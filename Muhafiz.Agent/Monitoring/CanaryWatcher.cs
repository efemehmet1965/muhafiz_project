using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Muhafiz.Agent.Response; // EventWriter, ProcessKiller.GetLockingPids

namespace Muhafiz.Agent.Monitoring
{
    public sealed class CanaryWatcher
    {
        private const string BROWSER_TOKEN = "__BROWSER_PROFILES__";

        private readonly ILogger _log;
        private readonly IConfiguration _cfg;
        private readonly Func<EventWriter?> _eventsProvider;

        private readonly bool _enabled;
        private readonly bool _alertOnOpen;
        private readonly bool _quarantineOnHit;
        private readonly int _reseedHours;

        private readonly string[] _configuredDropPathsRaw;
        private readonly string[] _filenames;
        private readonly string[] _markers;

        private string[] _effectiveDropDirs = Array.Empty<string>();

        private readonly string _stateDir;
        private readonly string _stateFile;
        private readonly Dictionary<string, CanaryState> _state = new(StringComparer.OrdinalIgnoreCase);

        // Read-detect
        private readonly bool _readDetectEnabled;
        private readonly int _readIntervalMs;
        private readonly int _minEventIntervalSec;
        private readonly HashSet<string> _archiverHints;
        private readonly HashSet<string> _excludeProcs;
        private readonly bool _killSuspicious;

        private readonly Dictionary<string, DateTime> _lastReadEvent = new(StringComparer.OrdinalIgnoreCase);

        private sealed class CanaryState
        {
            public string Token { get; set; } = Guid.NewGuid().ToString("N");
            public DateTime LastAccessUtc { get; set; }
            public DateTime LastWriteUtc { get; set; }
        }

        public CanaryWatcher(IConfiguration cfg, ILogger log, Func<EventWriter?> eventsProvider)
        {
            _cfg = cfg;
            _log = log;
            _eventsProvider = eventsProvider;

            _enabled = string.Equals(cfg["Canary:Enabled"], "true", StringComparison.OrdinalIgnoreCase);
            _alertOnOpen = !string.Equals(cfg["Canary:AlertOnOpen"], "false", StringComparison.OrdinalIgnoreCase);
            _quarantineOnHit = string.Equals(cfg["Canary:QuarantineOnHit"], "true", StringComparison.OrdinalIgnoreCase);
            _reseedHours = Math.Max(1, int.TryParse(cfg["Canary:ReseedHours"], out var h) ? h : 24);

            _configuredDropPathsRaw = (cfg.GetSection("Canary:DropPaths").Get<string[]>() ?? Array.Empty<string>());
            _filenames = (cfg.GetSection("Canary:Filenames").Get<string[]>() ?? Array.Empty<string>());
            _markers = (cfg.GetSection("Canary:ContentMarkers").Get<string[]>() ?? Array.Empty<string>());

            _stateDir = Expand("%PROGRAMDATA%/Muhafiz/canary");
            _stateFile = Path.Combine(_stateDir, "state.json");

            _readDetectEnabled = string.Equals(cfg["Canary:ReadDetect:Enabled"], "true", StringComparison.OrdinalIgnoreCase);
            _readIntervalMs = Math.Max(250, int.TryParse(cfg["Canary:ReadDetect:IntervalMs"], out var r) ? r : 1000);
            _minEventIntervalSec = Math.Max(5, int.TryParse(cfg["Canary:ReadDetect:MinEventIntervalSeconds"], out var m) ? m : 30);

            _archiverHints = new HashSet<string>(
                (cfg.GetSection("Canary:ReadDetect:ArchiverHints").Get<string[]>() ?? Array.Empty<string>())
                .Select(s => s.Trim()).Where(s => !string.IsNullOrWhiteSpace(s)),
                StringComparer.OrdinalIgnoreCase);

            _excludeProcs = new HashSet<string>(
                (cfg.GetSection("Canary:ReadDetect:ExcludeProcesses").Get<string[]>() ?? Array.Empty<string>())
                .Select(s => s.Trim()).Where(s => !string.IsNullOrWhiteSpace(s)),
                StringComparer.OrdinalIgnoreCase);

            _killSuspicious = string.Equals(cfg["Canary:ReadDetect:KillSuspicious"], "true", StringComparison.OrdinalIgnoreCase);
        }

        public bool IsEnabled => _enabled;

        public async Task InitAsync(CancellationToken ct)
        {
            if (!_enabled) return;

            Directory.CreateDirectory(_stateDir);
            await LoadStateAsync(ct);

            _effectiveDropDirs = ResolveDropDirectories();
            foreach (var dir in _effectiveDropDirs) TryCreateDir(dir);

            await SeedIfNeededAsync(ct);

            _log.LogInformation("Canary izleme hazır: {count} hedef klasör", _effectiveDropDirs.Length);
            foreach (var d in _effectiveDropDirs.Take(10)) _log.LogInformation("  ↳ {dir}", d);
            if (_effectiveDropDirs.Length > 10) _log.LogInformation("  ↳ (+{n} daha...)", _effectiveDropDirs.Length - 10);
        }

        public Task RunAsync(CancellationToken ct)
        {
            if (!_enabled) return Task.CompletedTask;

            var openWriteLoop = RunOpenWriteLoop(ct);
            if (_readDetectEnabled)
            {
                var readLoop = RunReadDetectLoop(ct);
                return Task.WhenAll(openWriteLoop, readLoop);
            }
            return openWriteLoop;
        }

        private Task RunOpenWriteLoop(CancellationToken ct) => Task.Run(async () =>
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await TickOpenWriteAsync(ct);
                    await Task.Delay(TimeSpan.FromSeconds(15), ct);
                }
                catch (TaskCanceledException) { }
                catch (Exception ex) { _log.LogDebug(ex, "Canary (open/write) döngü hatası"); }
            }
        }, ct);

        private Task RunReadDetectLoop(CancellationToken ct) => Task.Run(async () =>
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await TickReadDetectAsync(ct);
                    await Task.Delay(_readIntervalMs, ct);
                }
                catch (TaskCanceledException) { }
                catch (Exception ex) { _log.LogDebug(ex, "Canary (read-detect) döngü hatası"); }
            }
        }, ct);

        private async Task TickOpenWriteAsync(CancellationToken ct)
        {
            foreach (var path in CandidatePaths())
            {
                try
                {
                    var fi = new FileInfo(path);
                    if (!fi.Exists) continue;

                    if (!_state.TryGetValue(path, out var st))
                    {
                        st = new CanaryState
                        {
                            Token = Guid.NewGuid().ToString("N"),
                            LastAccessUtc = fi.LastAccessTimeUtc,
                            LastWriteUtc = fi.LastWriteTimeUtc
                        };
                        _state[path] = st;
                        continue;
                    }

                    bool opened = _alertOnOpen && fi.LastAccessTimeUtc > st.LastAccessUtc.AddSeconds(1);
                    bool written = fi.LastWriteTimeUtc > st.LastWriteUtc.AddSeconds(1);

                    if (opened || written)
                    {
                        var browser = IsBrowserPath(path);
                        var reason = written
                                      ? (browser ? "CANARY_BROWSER_WRITE" : "CANARY_WRITE")
                                      : (browser ? "CANARY_BROWSER_OPEN" : "CANARY_OPEN");

                        await WriteEventAsync(reason, path, st.Token, fi.Exists ? fi.Length : 0, ct);
                    }

                    st.LastAccessUtc = fi.LastAccessTimeUtc;
                    st.LastWriteUtc = fi.LastWriteTimeUtc;
                }
                catch (Exception ex)
                {
                    _log.LogDebug(ex, "Canary kontrol edilemedi: {path}", path);
                }
            }

            await SeedIfNeededAsync(ct);
            await SaveStateAsync(ct);
        }

        private async Task TickReadDetectAsync(CancellationToken ct)
        {
            var now = DateTime.UtcNow;

            foreach (var path in CandidatePaths())
            {
                if (!File.Exists(path)) continue;

                List<int> pids;
                try { pids = ProcessKiller.GetLockingPids(path); }
                catch { continue; }

                foreach (var pid in pids.Distinct())
                {
                    Process? p = null;
                    try { p = Process.GetProcessById(pid); } catch { continue; }

                    var exe = SafeExe(p);
                    if (_excludeProcs.Contains(exe) || exe.Equals("Muhafiz.Agent.exe", StringComparison.OrdinalIgnoreCase))
                        continue;

                    var key = $"{path}|{pid}";
                    if (_lastReadEvent.TryGetValue(key, out var last) &&
                        (now - last).TotalSeconds < _minEventIntervalSec)
                        continue;

                    bool isArchiver = _archiverHints.Contains(exe) ||
                                      exe.Contains("7z", StringComparison.OrdinalIgnoreCase) ||
                                      exe.Contains("rar", StringComparison.OrdinalIgnoreCase) ||
                                      exe.Equals("zip.exe", StringComparison.OrdinalIgnoreCase) ||
                                      exe.Equals("tar.exe", StringComparison.OrdinalIgnoreCase);

                    var reason = isArchiver ? "CANARY_ARCHIVER_READ" : "CANARY_READ";

                    if (!_state.TryGetValue(path, out var st))
                    {
                        st = new CanaryState
                        {
                            Token = Guid.NewGuid().ToString("N"),
                            LastAccessUtc = DateTime.UtcNow,
                            LastWriteUtc = DateTime.UtcNow
                        };
                        _state[path] = st;
                    }

                    long size = 0;
                    try { size = new FileInfo(path).Length; } catch { }

                    await WriteEventAsync(reason, path, st.Token, size, ct, pid, exe);
                    _lastReadEvent[key] = now;

                    if (_killSuspicious && isArchiver)
                    {
                        try
                        {
                            p.Kill(entireProcessTree: true);
                            _log.LogWarning("CANARY: şüpheli arşivleyici sonlandırıldı → {exe} (PID {pid})", exe, pid);
                        }
                        catch (Exception ex)
                        {
                            _log.LogDebug(ex, "CANARY: arşivleyici sonlandırılamadı → {exe} (PID {pid})", exe, pid);
                        }
                    }
                }
            }
        }

        private async Task WriteEventAsync(string reason, string path, string token, long size, CancellationToken ct, int? pid = null, string? exe = null)
        {
            _log.LogWarning("CANARY tetiği: {reason} ␦ {path}{who}",
                reason, path, pid.HasValue ? $" (PID {pid}, {exe})" : string.Empty);

            var evt = new EventWriter.Incident
            {
                Reasons = new[] { reason },
                DetectionMode = _cfg["Mode"] ?? "Silent",
                OriginalPath = path,
                QuarantinePath = null,
                Size = size,
                Sha256 = "",
                EgressHostsTtlBlocked = null,
                ProcessActions = pid.HasValue
                    ? new[] { new EventWriter.ProcessAction { Pid = pid.Value, Exe = exe ?? "", Action = "read" } }
                    : null,
                CanaryToken = token
            };

            _ = await _eventsProvider()?.WriteIncidentAsync(evt, ct)!;
        }

        private IEnumerable<string> CandidatePaths()
        {
            foreach (var root in _effectiveDropDirs)
                foreach (var name in _filenames)
                    yield return Path.Combine(root, name);
        }

        private async Task SeedIfNeededAsync(CancellationToken ct)
        {
            foreach (var path in CandidatePaths())
            {
                try
                {
                    var fi = new FileInfo(path);
                    bool need = !fi.Exists || (DateTime.UtcNow - fi.CreationTimeUtc).TotalHours > _reseedHours;
                    if (!need) continue;

                    var dir = Path.GetDirectoryName(path)!;
                    TryCreateDir(dir);

                    var token = Guid.NewGuid().ToString("N");
                    _state[path] = new CanaryState
                    {
                        Token = token,
                        LastAccessUtc = DateTime.UtcNow,
                        LastWriteUtc = DateTime.UtcNow
                    };

                    var sb = new StringBuilder();
                    sb.AppendLine("==== MUHAFIZ CANARY FILE ====");
                    foreach (var m in _markers) sb.AppendLine(m);
                    sb.AppendLine($"TOKEN:{token}");
                    sb.AppendLine($"CREATED_UTC:{DateTime.UtcNow:o}");

                    await File.WriteAllTextAsync(path, sb.ToString(), ct);
                    try { File.SetAttributes(path, FileAttributes.ReadOnly | FileAttributes.Archive); } catch { }

                    _log.LogInformation("Canary dağıtıldı/yenilendi: {path}", path);
                }
                catch (Exception ex)
                {
                    _log.LogDebug(ex, "Canary oluşturulamadı: {path}", path);
                }
            }
        }

        private string[] ResolveDropDirectories()
        {
            var list = new List<string>();

            foreach (var raw in _configuredDropPathsRaw)
            {
                if (string.Equals(raw, BROWSER_TOKEN, StringComparison.OrdinalIgnoreCase))
                {
                    list.AddRange(DiscoverBrowserProfileDirs());
                    continue;
                }

                var expanded = Expand(raw);
                if (!string.IsNullOrWhiteSpace(expanded))
                    list.Add(expanded);
            }

            return list.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        }

        private IEnumerable<string> DiscoverBrowserProfileDirs()
        {
            var outDirs = new List<string>();

            var chromes = new[]
            {
                "%LOCALAPPDATA%/Google/Chrome/User Data",
                "%LOCALAPPDATA%/Microsoft/Edge/User Data",
                "%LOCALAPPDATA%/BraveSoftware/Brave-Browser/User Data"
            };

            foreach (var rootRaw in chromes)
            {
                var root = Expand(rootRaw);
                if (!Directory.Exists(root)) continue;

                foreach (var dir in Directory.GetDirectories(root))
                {
                    var name = Path.GetFileName(dir);
                    if (name.Equals("Default", StringComparison.OrdinalIgnoreCase) ||
                        name.StartsWith("Profile", StringComparison.OrdinalIgnoreCase) ||
                        name.StartsWith("Guest", StringComparison.OrdinalIgnoreCase))
                    {
                        outDirs.Add(dir);
                    }
                }
            }

            var opera = Expand("%APPDATA%/Opera Software/Opera Stable");
            if (Directory.Exists(opera)) outDirs.Add(opera);

            var ffRoot = Expand("%APPDATA%/Mozilla/Firefox/Profiles");
            if (Directory.Exists(ffRoot))
                outDirs.AddRange(Directory.GetDirectories(ffRoot));

            return outDirs.Distinct(StringComparer.OrdinalIgnoreCase);
        }

        private static bool IsBrowserPath(string path)
        {
            var p = path.ToLowerInvariant();
            return p.Contains("\\chrome\\user data\\") ||
                   p.Contains("\\microsoft\\edge\\user data\\") ||
                   p.Contains("\\bravesoftware\\brave-browser\\user data\\") ||
                   p.Contains("\\opera software\\opera stable\\") ||
                   p.Contains("\\mozilla\\firefox\\profiles\\");
        }

        private async Task LoadStateAsync(CancellationToken ct)
        {
            try
            {
                if (!File.Exists(_stateFile)) return;
                var json = await File.ReadAllTextAsync(_stateFile, ct);
                var tmp = JsonSerializer.Deserialize<Dictionary<string, CanaryState>>(json);
                if (tmp != null) foreach (var kv in tmp) _state[kv.Key] = kv.Value;
            }
            catch { }
        }

        private async Task SaveStateAsync(CancellationToken ct)
        {
            try
            {
                Directory.CreateDirectory(_stateDir);
                var json = JsonSerializer.Serialize(_state, new JsonSerializerOptions { WriteIndented = true });
                await File.WriteAllTextAsync(_stateFile, json, ct);
            }
            catch { }
        }

        private static void TryCreateDir(string dir)
        {
            try { Directory.CreateDirectory(dir); } catch { }
        }

        private static string Expand(string? p) =>
            Environment.ExpandEnvironmentVariables(p ?? string.Empty)
                .Replace('/', Path.DirectorySeparatorChar);

        private static string SafeExe(Process p)
        {
            try { return Path.GetFileName(p.MainModule?.FileName ?? p.ProcessName); }
            catch { return p.ProcessName; }
        }
    }
}
