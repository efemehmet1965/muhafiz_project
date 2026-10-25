using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Muhafiz.Agent.Analysis;
using Muhafiz.Agent.Ioc;
using Muhafiz.Agent.Monitoring;
using Muhafiz.Agent.Response;
using Muhafiz.Agent.Utils;
using Muhafiz.Agent.Pipelines;
using Muhafiz.Agent.Update;

namespace Muhafiz.Agent
{
    public sealed class Worker : BackgroundService
    {
        private readonly ILogger<Worker> _log;
        private readonly IConfiguration _cfg;
        private readonly SandboxOrchestrator _sandbox;
        private readonly CanaryWatcher _canary;
        private readonly EgressBlocker _egressBlocker;
        private readonly LlmAnalyser _llmAnalyser;
        private readonly YaraScanner _yaraScanner;

        private readonly List<FileSystemWatcher> _watchers = new();
        private readonly string _eventsRoot;
        private readonly int _eventsRetentionDays;
        private readonly string _quarantineRoot;
        private readonly string _iocRoot;

        private IocStore? _iocStore;
        private IocWatcher? _iocWatcher;
        private readonly bool _sandboxEnabled;
        private readonly bool _egressConditionalWebhookBlock;
        private string[] _egressHostsOnIncident = Array.Empty<string>();

        private readonly bool _yaraEnabled;
        private readonly bool _downloadAnalysisEnabled;

        // YARA/hash taramasının aynı dosya için tekrar tetiklenmesini önlemek için debounce
        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, DateTime> _recentScans
            = new(StringComparer.OrdinalIgnoreCase);

        public Worker(
            ILogger<Worker> log,
            IConfiguration cfg,
            SandboxOrchestrator sandbox,
            CanaryWatcher canary,
            EgressBlocker egressBlocker,
            LlmAnalyser llmAnalyser,
            YaraScanner yaraScanner)
        {
            _log = log;
            _cfg = cfg;
            _sandbox = sandbox;
            _canary = canary;
            _egressBlocker = egressBlocker;
            _llmAnalyser = llmAnalyser;
            _yaraScanner = yaraScanner;

            _eventsRoot = Expand(_cfg["Events:Root"] ?? @"%PROGRAMDATA%\Muhafiz\events");
            _eventsRetentionDays = _cfg.GetValue<int>("Events:RetentionDays", 30);
            _quarantineRoot = Expand(_cfg["Quarantine:Root"] ?? @"%PROGRAMDATA%\Muhafiz\Q");
            _iocRoot = Path.GetDirectoryName(Expand(_cfg["Ioc:HashesPath"] ?? @"%PROGRAMDATA%\Muhafiz\ioc\hashes.json"))
                        ?? @"%PROGRAMDATA%\Muhafiz\ioc";

            Directory.CreateDirectory(_eventsRoot);
            Directory.CreateDirectory(_quarantineRoot);
            Directory.CreateDirectory(_iocRoot);

            _yaraEnabled = _cfg.GetValue<bool>("Yara:Enabled");
            _downloadAnalysisEnabled = _cfg.GetValue<bool>("DownloadAnalysis:Enabled");
            _sandboxEnabled = _cfg.GetValue<bool>("Sandbox:Enabled");
            _egressConditionalWebhookBlock = _cfg.GetValue<bool>("Egress:ConditionalWebhookBlock");

            _egressHostsOnIncident = (_cfg.GetSection("Egress:Conditional:Hosts").Get<string[]>() ?? Array.Empty<string>())
                                     .Where(s => !string.IsNullOrWhiteSpace(s))
                                     .ToArray();
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            try
            {
                LogHeader();
                await LoadIocsAsync(stoppingToken);

                var watched = _cfg.GetSection("WatchedPaths").Get<string[]>() ?? Array.Empty<string>();
                foreach (var p in watched.Select(Expand).Where(Directory.Exists))
                    StartWatcher(p);

                // IOC hot-reload (debounce'lu dosya izleyici)
                _iocWatcher = new IocWatcher(_cfg, _log, _iocRoot, store => _iocStore = store);

                // IOC IP bloklarını firewall'a uygula (kalıcı kurallar)
                if (_iocStore is { } initialStore)
                    await _egressBlocker.InitializeAsync(initialStore, stoppingToken);

                // DNS anomali tespiti (DnsAnomaly:Enabled)
                if (_cfg.GetValue<bool>("DnsAnomaly:Enabled"))
                {
                    var dnsWatcher = new DnsAnomalyWatcher(_cfg, _log, () => _iocStore);
                    _ = dnsWatcher.RunAsync(stoppingToken);
                }

                // Güncelleme kanalı izleyicisi (UpdateChannel:Enabled)
                if (_cfg.GetValue<bool>("UpdateChannel:Enabled"))
                {
                    var updateWatcher = new UpdateWatcher(_cfg, _log);
                    _ = updateWatcher.RunAsync(stoppingToken);
                }

                await _canary.InitAsync(stoppingToken);
                _log.LogInformation("CanaryWatcher is starting.");
                _ = Task.Run(() => _canary.RunAsync(stoppingToken), stoppingToken);

                _log.LogInformation("File monitoring started for {count} directories.", _watchers.Count);
                _ = Task.Run(() => RunCleanupLoopAsync(stoppingToken), stoppingToken);

                await Task.Delay(Timeout.Infinite, stoppingToken);
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) { _log.LogError(ex, "Worker service critical failure."); }
            finally
            {
                foreach (var w in _watchers) { try { w.Dispose(); } catch { } }
                _iocWatcher?.Dispose();
            }
        }

        private async Task RunCleanupLoopAsync(CancellationToken stoppingToken)
        {
            await Task.Delay(TimeSpan.FromSeconds(15), stoppingToken);
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await _egressBlocker.CleanupAsync(stoppingToken);
                    CleanOldEvents();
                    CleanRecentScans();
                }
                catch (Exception ex) { _log.LogWarning(ex, "Error during periodic cleanup."); }
                await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken);
            }
        }

        public override Task StopAsync(CancellationToken cancellationToken)
        {
            foreach (var w in _watchers) { w.EnableRaisingEvents = false; }
            return base.StopAsync(cancellationToken);
        }

        private void LogHeader()
        {
            _log.LogInformation("Muhafiz Agent starting in mode: {mode}", _cfg["Mode"] ?? "Default");
        }

        private void StartWatcher(string dir)
        {
            var w = new FileSystemWatcher(dir)
            {
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.Size | NotifyFilters.LastWrite | NotifyFilters.CreationTime
            };
            w.Created += OnFsEvent;
            w.Changed += OnFsEvent;
            w.Renamed += OnRenamed;
            w.EnableRaisingEvents = true;
            _watchers.Add(w);
            _log.LogInformation("Now watching: {dir}", dir);
        }

        private void OnRenamed(object sender, RenamedEventArgs e) => OnFsEvent(sender, new FileSystemEventArgs(WatcherChangeTypes.Created, e.FullPath, e.Name));
        private void OnFsEvent(object sender, FileSystemEventArgs e) => _ = HandleFileEventAsync(e);

        /// <summary>
        /// Aynı dosya için Created+Changed+Renamed olaylarından doğan tekrarları
        /// engellemek amacıyla 5 saniyelik debounce uygular.
        /// </summary>
        private static bool ShouldScan(IDictionary<string, DateTime> recent, string fullPath)
        {
            var now = DateTime.UtcNow;
            if (recent.TryGetValue(fullPath, out var last) && (now - last).TotalSeconds < 5)
                return false;

            recent[fullPath] = now;
            return true;
        }

        private async Task HandleFileEventAsync(FileSystemEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(e.FullPath) || !File.Exists(e.FullPath)) return;

            await Task.Delay(250); // Wait for file write to complete
            var info = new FileInfo(e.FullPath);
            if (!info.Exists) return;

            // Aynı dosyaya gelen çoklu FS olaylarında tekrar taramayı engelle (debounce)
            if (!ShouldScan(_recentScans, e.FullPath)) return;

            var sha256 = await TrySha256Async(e.FullPath) ?? "<sha-fail>";
            _log.LogDebug("Handling file event {type} for {path}", e.ChangeType, e.FullPath);

            var reasons = new List<string>();
            if (_iocStore?.IsHashBlocked(sha256) == true) reasons.Add("IOC_HASH");

            if (_yaraEnabled)
            {
                var (hit, rules, _, _, _) = await _yaraScanner.ScanFileAsync(e.FullPath, CancellationToken.None);
                if (hit)
                {
                    var tags = string.Join(",", rules);
                    reasons.Add($"YARA:{tags}");
                    _log.LogWarning("YARA positive hit [{tags}] for file {path}", tags, e.FullPath);
                }
            }

            if (!reasons.Any()) return;

            string? hostUrl = _downloadAnalysisEnabled ? AdsReader.GetZoneIdentifierUrl(e.FullPath) : null;
            if (hostUrl != null) _log.LogInformation("File download source: {url}", hostUrl);

            // Koşullu egress bloğu: indirme kaynağı + olay anında bloklanacak ek host'lar (TTL'li)
            if (_egressConditionalWebhookBlock)
            {
                var hostsToBlock = new List<string>();
                if (!string.IsNullOrWhiteSpace(hostUrl)) hostsToBlock.Add(hostUrl);
                hostsToBlock.AddRange(_egressHostsOnIncident);

                foreach (var host in hostsToBlock.Distinct(StringComparer.OrdinalIgnoreCase))
                {
                    try { await _egressBlocker.BlockSuspiciousHostAsync(host, CancellationToken.None); }
                    catch (Exception ex) { _log.LogWarning(ex, "Egress conditional bloğu uygulanamadı: {host}", host); }
                }
            }

            var q = await TryQuarantineAsync(e.FullPath, sha256, reasons.ToArray());
            if (q.Success)
            {
                _log.LogInformation("File quarantined to {qpath}", q.QuarantinePath);
                var incident = new Incident
                {
                    Id = q.Id,
                    OriginalPath = e.FullPath,
                    QuarantinePath = q.QuarantinePath!,
                    Sha256 = sha256,
                    Size = info.Length,
                    Reasons = reasons.ToArray(),
                    HostUrl = hostUrl
                };
                _ = WriteAndEnrichEventAsync(incident);

                // Karantina sonrası sandbox analizini kuyruğa al (Sandbox:Enabled)
                if (_sandboxEnabled)
                {
                    _sandbox.Enqueue(new SandboxJob
                    {
                        Sha256 = sha256,
                        OriginalPath = e.FullPath,
                        QuarantinedPath = q.QuarantinePath,
                        Trigger = SandboxTrigger.OnQuarantine,
                        Reasons = reasons.ToArray()
                    });
                }
            }
            else
            {
                _log.LogWarning("Failed to quarantine file {path}", e.FullPath);
            }
        }

        private async Task LoadIocsAsync(CancellationToken ct)
        {
            try
            {
                await Task.Run(() => _iocStore = IocStore.Load(_cfg, _log), ct);
                _log.LogInformation("IOC store loaded. {h} hash, {hosts} host, {ips} IP.",
                    _iocStore?.Hashes.Count ?? 0,
                    _iocStore?.BlockedHosts.Count ?? 0,
                    _iocStore?.IocIps.Count ?? 0);
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "Failed to load IOC store.");
            }
        }

        private sealed class Incident
        {
            public string Id { get; set; } = Guid.NewGuid().ToString("N");
            public string OriginalPath { get; set; } = "";
            public string? QuarantinePath { get; set; }
            public string Sha256 { get; set; } = "";
            public long Size { get; set; }
            public string[] Reasons { get; set; } = Array.Empty<string>();
            public string? HostUrl { get; set; }

            [JsonPropertyName("llm_analysis")]
            public LlmAnalysisResult? LlmAnalysis { get; set; }
        }

        private async Task WriteAndEnrichEventAsync(Incident evt)
        {
            var dayDir = Path.Combine(_eventsRoot, DateTime.UtcNow.ToString("yyyyMMdd"));
            Directory.CreateDirectory(dayDir);
            var file = Path.Combine(dayDir, $"{evt.Id}.event.json");

            var opts = new JsonSerializerOptions { WriteIndented = true, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };

            try
            {
                var initialJson = JsonSerializer.Serialize(evt, opts);
                await File.WriteAllTextAsync(file, initialJson);
                _log.LogInformation("Incident event written: {file}", file);
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "Failed to write initial incident event.");
                return;
            }

            if (_llmAnalyser.IsEnabled)
            {
                _log.LogInformation("Starting LLM analysis for incident {id}", evt.Id);
                var llmResult = await _llmAnalyser.AnalyseIncidentAsync(evt);
                if (llmResult != null)
                {
                    evt.LlmAnalysis = llmResult;
                    try
                    {
                        var enrichedJson = JsonSerializer.Serialize(evt, opts);
                        await File.WriteAllTextAsync(file, enrichedJson);
                        _log.LogInformation("Incident event {id} enriched with LLM analysis.", evt.Id);
                    }
                    catch (Exception ex)
                    {
                        _log.LogError(ex, "Failed to write enriched incident event.");
                    }
                }
            }
        }
        
        private void CleanRecentScans()
        {
            var cutoff = DateTime.UtcNow.AddMinutes(-1);
            foreach (var kv in _recentScans)
            {
                if (kv.Value < cutoff)
                    _recentScans.TryRemove(kv.Key, out _);
            }
        }

        private void CleanOldEvents()
        {            if (_eventsRetentionDays <= 0) return;
            var cutoffDate = DateTime.UtcNow.AddDays(-_eventsRetentionDays);
            foreach (var dir in Directory.EnumerateDirectories(_eventsRoot))
            {
                if (DateTime.TryParseExact(Path.GetFileName(dir), "yyyyMMdd", null, System.Globalization.DateTimeStyles.None, out var dirDate) && dirDate < cutoffDate)
                {
                    try { Directory.Delete(dir, recursive: true); } catch (Exception ex) { _log.LogWarning(ex, "Failed to delete old event directory {dir}", dir); }
                }
            }
        }

        private sealed record QuarantineResult(bool Success, string Id, string? QuarantinePath);
        private async Task<QuarantineResult> TryQuarantineAsync(string path, string sha256, string[] reasons)
        {
            var id = Guid.NewGuid().ToString("N");
            var dayDir = Path.Combine(_quarantineRoot, DateTime.UtcNow.ToString("yyyyMMdd"));
            Directory.CreateDirectory(dayDir);
            var qPath = Path.Combine(dayDir, $"{id}.quar");

            for (int i = 0; i < 3; i++)
            {
                try { File.Move(path, qPath, false); return new QuarantineResult(true, id, qPath); }
                catch { await Task.Delay(100); }
            }
            return new QuarantineResult(false, id, null);
        }

        private static string Expand(string p) => Environment.ExpandEnvironmentVariables(p);

        private static async Task<string?> TrySha256Async(string file)
        {
            try
            {
                using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sha = SHA256.Create();
                var hash = await sha.ComputeHashAsync(fs);
                var sb = new StringBuilder(hash.Length * 2);
                foreach (byte b in hash) sb.Append(b.ToString("x2"));
                return sb.ToString();
            }
            catch { return null; }
        }
    }
}
