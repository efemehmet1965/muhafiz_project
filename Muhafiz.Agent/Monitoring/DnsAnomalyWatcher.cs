using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Muhafiz.Agent.Ioc;

namespace Muhafiz.Agent.Monitoring
{
    /// <summary>
    /// DNS istemci önbelleğini periyodik okur; IOC'deki blocked_hosts ile eşleşen kayıtları "anomali" olarak loglar.
    /// Powershell "Get-DnsClientCache" varsa onu kullanır, yoksa "ipconfig /displaydns" ile kaba ayrıştırma dener.
    /// </summary>
    public sealed class DnsAnomalyWatcher
    {
        private readonly ILogger _log;
        private readonly int _intervalSec;
        private readonly Func<IocStore?> _iocProvider;
        private readonly HashSet<string> _recent = new(StringComparer.OrdinalIgnoreCase);

        public DnsAnomalyWatcher(IConfiguration cfg, ILogger log, Func<IocStore?> iocProvider)
        {
            _log = log;
            _intervalSec = Math.Max(10, int.TryParse(cfg["DnsAnomaly:IntervalSeconds"], out var s) ? s : 30);
            _iocProvider = iocProvider;
        }

        public Task RunAsync(CancellationToken ct) => Task.Run(async () =>
        {
            while (!ct.IsCancellationRequested)
            {
                try { await TickAsync(ct); }
                catch (Exception ex) { _log.LogDebug(ex, "DNS anomali döngü hatası"); }

                await Task.Delay(TimeSpan.FromSeconds(_intervalSec), ct);
            }
        }, ct);

        private async Task TickAsync(CancellationToken ct)
        {
            var ioc = _iocProvider();
            if (ioc == null || ioc.BlockedHosts.Count == 0) return;

            var names = await TryGetDnsNamesAsync(ct);
            if (names.Count == 0) return;

            foreach (var name in names)
            {
                foreach (var host in ioc.BlockedHosts)
                {
                    // Tam eşleşme veya alt-alan (example.com ↔ sub.example.com)
                    if (name.Equals(host, StringComparison.OrdinalIgnoreCase) ||
                        name.EndsWith("." + host, StringComparison.OrdinalIgnoreCase))
                    {
                        var key = $"{name}";
                        if (_recent.Add(key))
                        {
                            _log.LogWarning("DNS-ANOMALI: {name} adında çözümleme bulundu (IOC host eşleşmesi).", name);
                        }
                    }
                }
            }

            // pencereyi sınırlı tut (son ~500 kayıt)
            if (_recent.Count > 500)
            {
                foreach (var k in _recent.Take(_recent.Count - 400).ToList())
                    _recent.Remove(k);
            }
        }

        private static async Task<List<string>> TryGetDnsNamesAsync(CancellationToken ct)
        {
            // 1) Powershell varsa: Get-DnsClientCache
            var ps = await RunProcessAsync("powershell", "-NoProfile -Command \"Get-DnsClientCache | Select-Object -ExpandProperty Name | Sort-Object -Unique\"", ct);
            if (ps.ok)
            {
                var list = ps.stdout.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                                    .Select(s => s.Trim().TrimEnd('.'))
                                    .Where(s => s.Contains('.'))
                                    .Distinct(StringComparer.OrdinalIgnoreCase)
                                    .ToList();
                if (list.Count > 0) return list;
            }

            // 2) Yedek: ipconfig /displaydns (lokalize olabilir; kaba çıkarım)
            var ic = await RunProcessAsync("ipconfig", "/displaydns", ct);
            if (ic.ok)
            {
                var names = new List<string>();
                foreach (var line in ic.stdout.Split('\n'))
                {
                    var idx = line.IndexOf(':');
                    if (idx > 0)
                    {
                        var value = line[(idx + 1)..].Trim().TrimEnd('.');
                        if (value.Contains('.') && value.Length > 2 && value.Length < 256)
                            names.Add(value);
                    }
                }
                return names.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            }

            return new List<string>();
        }

        private static async Task<(bool ok, string stdout)> RunProcessAsync(string exe, string args, CancellationToken ct)
        {
            var psi = new ProcessStartInfo
            {
                FileName = exe,
                Arguments = args,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };

            try
            {
                using var p = Process.Start(psi)!;
                var read = p.StandardOutput.ReadToEndAsync();
                await Task.Run(() => p.WaitForExit(), ct);
                var stdout = await read;
                return (p.ExitCode == 0, stdout ?? "");
            }
            catch
            {
                return (false, "");
            }
        }
    }
}
