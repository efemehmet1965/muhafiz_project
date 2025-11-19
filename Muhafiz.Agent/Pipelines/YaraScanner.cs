using System;
using System.IO;
using System.Linq;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Muhafiz.Agent.Pipelines
{
    public sealed class YaraScanner
    {
        private readonly string _cliPath;
        private readonly string _rulesPath;
        private readonly ILogger _log;

        public YaraScanner(IConfiguration cfg, ILogger log)
        {
            _cliPath = Expand(cfg["Yara:CliPath"] ?? "");
            _rulesPath = Expand(cfg["Yara:RulesPath"] ?? "");
            _log = log;

            if (!File.Exists(_cliPath))
                _log.LogWarning("YARA CLI bulunamadı: {path}", _cliPath);

            if (!(Directory.Exists(_rulesPath) || File.Exists(_rulesPath)))
                _log.LogWarning("YARA kural yolu bulunamadı: {path}", _rulesPath);
        }

        public async Task<(bool hit, List<string> rules, string stdout, string stderr, int exitCode)>
            ScanFileAsync(string filePath, CancellationToken ct)
        {
            var file = Expand(filePath);
            if (!File.Exists(_cliPath) || !File.Exists(file))
                return (false, new(), "", "Eksik CLI veya hedef dosya", -1);

            // Kural dosyalarını topla
            var ruleFiles = new List<string>();
            if (Directory.Exists(_rulesPath))
            {
                try
                {
                    ruleFiles.AddRange(
                        Directory.EnumerateFiles(_rulesPath, "*.yar", SearchOption.TopDirectoryOnly)
                    );
                }
                catch (Exception ex)
                {
                    _log.LogWarning(ex, "YARA kural klasörü okunamadı: {path}", _rulesPath);
                }
            }
            else if (File.Exists(_rulesPath))
            {
                ruleFiles.Add(_rulesPath);
            }

            if (ruleFiles.Count == 0)
                return (false, new(), "", "Kural dosyası bulunamadı (.yar)", -1);

            // Argümanları oluştur: tüm kural dosyaları + hedef dosya
            var args = string.Join(" ", ruleFiles.Select(r => $"\"{r}\"")) + " " + $"\"{file}\"";

            var psi = new ProcessStartInfo
            {
                FileName = _cliPath,
                Arguments = args,                 // -C/-r yok; .yar dosyalarını doğrudan veriyoruz
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };

            using var proc = new Process { StartInfo = psi };
            try { proc.Start(); }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "YARA başlatılamadı: {exe}", _cliPath);
                return (false, new(), "", "YARA başlatılamadı", -1);
            }

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(15));

            var outTask = proc.StandardOutput.ReadToEndAsync();
            var errTask = proc.StandardError.ReadToEndAsync();

            try { await Task.Run(() => proc.WaitForExit(), cts.Token); }
            catch (OperationCanceledException) { try { proc.Kill(true); } catch { } }

            var stdout = await outTask;
            var stderr = await errTask;
            var exit = proc.HasExited ? proc.ExitCode : -2;

            // stdout tipik: "RULE_NAME <fullpath>"
            var matchedRules = new List<string>();
            using (var sr = new StringReader(stdout))
            {
                string? line;
                while ((line = sr.ReadLine()) != null)
                {
                    var idx = line.IndexOf(' ');
                    if (idx > 0)
                    {
                        var rule = line[..idx].Trim();
                        if (!string.IsNullOrWhiteSpace(rule))
                            matchedRules.Add(rule);
                    }
                }
            }

            var hit = exit == 0 && matchedRules.Count > 0;

            if (!string.IsNullOrWhiteSpace(stderr))
                _log.LogDebug("YARA stderr: {err}", stderr.Trim());

            return (hit, matchedRules, stdout, stderr, exit);
        }

        private static string Expand(string p) =>
            Environment.ExpandEnvironmentVariables(p ?? string.Empty)
                       .Replace('/', Path.DirectorySeparatorChar);
    }
}
