using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Muhafiz.Agent.Analysis.Backends
{
    using Muhafiz.Agent.Analysis;

    public sealed class WindowsSandboxBackend : ISandboxBackend
    {
        private readonly IConfiguration _cfg;
        private readonly ILogger _log;

        private readonly bool _enabled;
        private readonly int _timeoutSec;
        private readonly int _memoryMb;
        private readonly bool _netEnable;

        private readonly string _root;
        private readonly string _inDir;
        private readonly string _wsbDir;
        private readonly string _outRoot;

        public WindowsSandboxBackend(IConfiguration cfg, ILogger<WindowsSandboxBackend> log)
        {
            _cfg = cfg;
            _log = log;

            _enabled = string.Equals(cfg["Sandbox:WindowsSandbox:Enabled"], "true", StringComparison.OrdinalIgnoreCase);
            _timeoutSec = Math.Max(30, int.TryParse(cfg["Sandbox:WindowsSandbox:TimeoutSeconds"], out var t) ? t : 120);
            _memoryMb = Math.Max(1024, int.TryParse(cfg["Sandbox:WindowsSandbox:MemoryMB"], out var m) ? m : 2048);
            _netEnable = string.Equals(cfg["Sandbox:WindowsSandbox:Networking"], "Enable", StringComparison.OrdinalIgnoreCase);

            _root = Expand("%PROGRAMDATA%/Muhafiz/sandbox");
            _inDir = Path.Combine(_root, "in");
            _wsbDir = Path.Combine(_root, "wsb");
            _outRoot = Path.Combine(_root, "out");

            Directory.CreateDirectory(_inDir);
            Directory.CreateDirectory(_wsbDir);
            Directory.CreateDirectory(_outRoot);
        }

        public string Name => "WindowsSandbox";
        public bool IsEnabled => _enabled;

        public bool CanAnalyze(SandboxJob job)
        {
            var ext = Path.GetExtension(job.QuarantinedPath ?? job.OriginalPath).ToLowerInvariant();
            var allowed = _cfg.GetSection("Sandbox:AllowedExtensions").Get<string[]>() ?? Array.Empty<string>();
            if (allowed.Length > 0 && Array.IndexOf(allowed, ext) < 0) return false;
            return true;
        }

        public async Task<ProviderResult> AnalyzeAsync(SandboxJob job, CancellationToken ct)
        {
            if (!IsEnabled) return new ProviderResult { Provider = Name, Ran = false, Success = false, Error = "Disabled" };

            var samplePath = job.QuarantinedPath ?? job.OriginalPath;
            if (!File.Exists(samplePath))
                return new ProviderResult { Provider = Name, Ran = true, Success = false, Error = "Sample not found" };

            var ext = Path.GetExtension(samplePath);
            var jid = $"{DateTime.UtcNow:yyyyMMdd_HHmmss}_{job.Sha256[..8]}";
            var outDir = Path.Combine(_outRoot, jid);
            Directory.CreateDirectory(outDir);

            var inSample = Path.Combine(_inDir, "sample" + ext);
            SafeDelete(inSample);
            File.Copy(samplePath, inSample, overwrite: true);

            var analyzePs1 = Path.Combine(_inDir, "analyze.ps1");
            await File.WriteAllTextAsync(analyzePs1, BuildAnalyzeScript(), ct);

            var wsbPath = Path.Combine(_wsbDir, $"run_{jid}.wsb");
            await File.WriteAllTextAsync(wsbPath, BuildWsb(outDir), ct);

            _log.LogInformation("WSB: başlatılıyor (timeout={sec}s): {sample}", _timeoutSec, samplePath);

            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "WindowsSandbox.exe",
                    Arguments = $"\"{wsbPath}\"",
                    UseShellExecute = true,
                    WindowStyle = ProcessWindowStyle.Normal
                };
                using var proc = Process.Start(psi);
                if (proc == null) throw new InvalidOperationException("WindowsSandbox.exe başlatılamadı");

                var report = Path.Combine(outDir, "report.json");
                var sw = Stopwatch.StartNew();
                while (sw.Elapsed.TotalSeconds < _timeoutSec && !ct.IsCancellationRequested)
                {
                    if (File.Exists(report)) break;
                    await Task.Delay(1000, ct);
                }

                try { if (!proc.HasExited) proc.Kill(entireProcessTree: true); } catch { }

                if (!File.Exists(Path.Combine(outDir, "report.json")))
                    return new ProviderResult { Provider = Name, Ran = true, Success = false, ReportPath = outDir, Error = "Timeout/no report" };

                return new ProviderResult
                {
                    Provider = Name,
                    Ran = true,
                    Success = true,
                    ReportPath = Path.Combine(outDir, "report.json"),
                    Data = new() { { "OutDir", outDir } }
                };
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "WSB çalıştırma hatası");
                return new ProviderResult { Provider = Name, Ran = true, Success = false, Error = ex.Message };
            }
        }

        // ---- helpers ----

        private string BuildWsb(string outDir)
        {
            var net = _netEnable ? "Enable" : "Disable";
            var inMap = Expand(_inDir);
            var outMap = Expand(outDir);

            var sb = new StringBuilder();
            sb.AppendLine("<Configuration>");
            sb.AppendLine("  <VGpu>Disable</VGpu>");
            sb.AppendLine($"  <Networking>{net}</Networking>");
            sb.AppendLine($"  <MemoryInMB>{_memoryMb}</MemoryInMB>");
            sb.AppendLine("  <MappedFolders>");
            sb.AppendLine("    <MappedFolder>");
            sb.AppendLine($"      <HostFolder>{inMap}</HostFolder>");
            sb.AppendLine("      <SandboxFolder>C:\\SandboxIn</SandboxFolder>");
            sb.AppendLine("      <ReadOnly>false</ReadOnly>");
            sb.AppendLine("    </MappedFolder>");
            sb.AppendLine("    <MappedFolder>");
            sb.AppendLine($"      <HostFolder>{outMap}</HostFolder>");
            sb.AppendLine("      <SandboxFolder>C:\\SandboxOut</SandboxFolder>");
            sb.AppendLine("      <ReadOnly>false</ReadOnly>");
            sb.AppendLine("    </MappedFolder>");
            sb.AppendLine("  </MappedFolders>");
            sb.AppendLine("  <LogonCommand>");
            sb.AppendLine("    <Command>powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\SandboxIn\\analyze.ps1</Command>");
            sb.AppendLine("  </LogonCommand>");
            sb.AppendLine("</Configuration>");
            return sb.ToString();
        }

        private static string BuildAnalyzeScript()
        {
            // Örnek: sample'ı başlat, kısa bekle, süreç/ağ/dosya artefaktlarını topla → C:\SandboxOut\report.json
            return @"
$ErrorActionPreference = 'SilentlyContinue'
$report = 'C:\SandboxOut\report.json'
$sample = Get-ChildItem 'C:\SandboxIn\sample*' | Select-Object -First 1

$procInfo = @()
$netInfo  = @()
$filesNew = @()

if ($sample) {
  try { Start-Process -FilePath $sample.FullName -WindowStyle Hidden } catch {}
  Start-Sleep -Seconds 8

  $procInfo = Get-Process | Select-Object Name, Id, Path -ErrorAction SilentlyContinue
  try { $netInfo = Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State } catch {}

  $filesNew = Get-ChildItem -Recurse -Force -ErrorAction SilentlyContinue C:\Users\WDAGUtilityAccount\AppData\Local\Temp |
              Select-Object FullName,Length,CreationTime -First 200
}

$doc = [ordered]@{
  TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
  Processes = $procInfo
  Net = $netInfo
  TempFiles = $filesNew
}
$doc | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 $report
";
        }

        private static void SafeDelete(string path)
        {
            try { if (File.Exists(path)) File.Delete(path); } catch { }
        }
        private static string Expand(string p) => Environment.ExpandEnvironmentVariables(p.Replace('/', '\\'));
    }
}
