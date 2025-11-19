using System.Diagnostics;
using System.Net;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Muhafiz.Agent.Ioc;

namespace Muhafiz.Agent.Response;

public sealed class EgressBlocker
{
    private readonly ILogger _log;
    private readonly bool _applyFirewall;
    private readonly bool _iocBlockAlways;
    private readonly bool _globalWebhookBlock;
    private readonly int _ttlSeconds;
    private readonly int _maxIpsPerHost;
    private readonly int _dnsCacheSeconds;

    // Geçici/TTL'li kurallar (ruleName → bitiş)
    private readonly Dictionary<string, DateTimeOffset> _tempRules = new();

    // DNS önbellek (host → (zaman, IPv4 listesi))
    private readonly Dictionary<string, (DateTimeOffset fetchedAt, List<string> ips)> _dnsCache = new();
    private readonly object _lock = new();

    public EgressBlocker(IConfiguration cfg, ILogger log)
    {
        _log = log;
        _applyFirewall = string.Equals(cfg["Egress:ApplyFirewall"], "true", StringComparison.OrdinalIgnoreCase);
        _iocBlockAlways = string.Equals(cfg["Egress:IocBlockAlways"], "true", StringComparison.OrdinalIgnoreCase);
        _globalWebhookBlock = string.Equals(cfg["Egress:GlobalWebhookBlock"], "true", StringComparison.OrdinalIgnoreCase);

        _ttlSeconds = int.TryParse(cfg["Egress:RuleTtlSeconds"], out var sTtl) ? Math.Max(60, sTtl) : 1800;
        _maxIpsPerHost = int.TryParse(cfg["Egress:MaxIpsPerHost"], out var sMax) ? Math.Clamp(sMax, 1, 32) : 6;
        _dnsCacheSeconds = int.TryParse(cfg["Egress:DnsCacheSeconds"], out var sDns) ? Math.Clamp(sDns, 30, 3600) : 600;
    }

    public async Task InitializeAsync(IocStore ioc, CancellationToken ct)
    {
        // IOC IP'ler → daima blok (kalıcı, IP başına)
        if (_iocBlockAlways && ioc.IocIps.Count > 0)
        {
            foreach (var ip in ioc.IocIps)
                await AddFirewallBlockForIpAsync(ip, permanent: true, ct);
        }

        // Global host blok (isteğe bağlı, host başına tek kuralda toplu IP)
        if (_globalWebhookBlock && ioc.BlockedHosts.Count > 0)
        {
            foreach (var host in ioc.BlockedHosts)
                await AddFirewallBlockForHostAsync(host, permanent: true, ct);
        }
    }

    /// <summary>Koşullu (TTL'li) blok: host veya URL ver; DNS çözülür, tek kuralda IP'ler toplanır.</summary>
    public async Task BlockSuspiciousHostAsync(string hostOrUrl, CancellationToken ct)
    {
        string? host = hostOrUrl;
        if (Uri.TryCreate(hostOrUrl, UriKind.Absolute, out var uri))
            host = uri.Host;

        if (string.IsNullOrWhiteSpace(host)) return;

        await AddFirewallBlockForHostAsync(host!, permanent: false, ct);
    }

    public async Task CleanupAsync(CancellationToken ct)
    {
        if (_applyFirewall == false) { _tempRules.Clear(); return; }

        var now = DateTimeOffset.UtcNow;
        var expired = _tempRules.Where(kv => kv.Value <= now).Select(kv => kv.Key).ToList();

        foreach (var name in expired)
        {
            await DeleteFirewallRuleAsync(name, ct);
            _tempRules.Remove(name);
        }
    }

    // ---------------------- İç yardımcılar ----------------------

    private async Task AddFirewallBlockForHostAsync(string host, bool permanent, CancellationToken ct)
    {
        var ips = await ResolveHostAsync(host, ct);
        if (ips.Count == 0)
        {
            _log.LogWarning("Host çözümlenemedi (bloklama atlandı): {host}", host);
            return;
        }

        // IP'leri sınırla ve tek kuralda topla
        var chosen = ips.Take(_maxIpsPerHost).ToList();
        var ruleName = permanent ? $"Muhafiz_Block_host_{host}" : $"Muhafiz_Block_host_{host}_ttl";

        // TTL'li kural zaten varsa: sadece süresini uzat
        if (!permanent && _tempRules.TryGetValue(ruleName, out _))
        {
            _tempRules[ruleName] = DateTimeOffset.UtcNow.AddSeconds(_ttlSeconds);
            _log.LogInformation("Firewall TTL uzatıldı (host): {host} (+{ttl}s)", host, _ttlSeconds);
            return;
        }

        await AddFirewallBlockForIpListAsync(ruleName, chosen, permanent, ct);

        if (!permanent)
            _tempRules[ruleName] = DateTimeOffset.UtcNow.AddSeconds(_ttlSeconds);

        _log.LogInformation("Firewall: {count} IPv4 ile {host} için {scope} kural eklendi.",
            chosen.Count, host, permanent ? "kalıcı" : $"TTL({_ttlSeconds}s)");
    }

    private async Task<List<string>> ResolveHostAsync(string host, CancellationToken ct)
    {
        List<string> ips;
        lock (_lock)
        {
            if (_dnsCache.TryGetValue(host, out var item))
            {
                if ((DateTimeOffset.UtcNow - item.fetchedAt).TotalSeconds < _dnsCacheSeconds)
                    return new List<string>(item.ips);
            }
        }

        try
        {
            var addrs = await Dns.GetHostAddressesAsync(host);
            ips = addrs
                .Where(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                .Select(a => a.ToString())
                .Distinct()
                .ToList();
        }
        catch
        {
            ips = new List<string>();
        }

        lock (_lock)
            _dnsCache[host] = (DateTimeOffset.UtcNow, ips);

        if (ips.Count > 0)
            _log.LogDebug("DNS: {host} → {count} IPv4 (cache {sec}s)", host, ips.Count, _dnsCacheSeconds);

        return ips;
    }

    private async Task AddFirewallBlockForIpListAsync(string ruleName, List<string> ips, bool permanent, CancellationToken ct)
    {
        if (ips.Count == 0) return;

        var ipArg = string.Join(",", ips);
        var addCmd = $"advfirewall firewall add rule name=\"{ruleName}\" dir=out action=block remoteip={ipArg} enable=yes";

        if (_applyFirewall)
        {
            // Aynı isimde kural varsa sil → tekrar ekle (idempotent)
            await RunNetshAsync($"advfirewall firewall delete rule name=\"{ruleName}\"", ct);

            var ok = await RunNetshAsync(addCmd, ct);
            if (!ok)
                _log.LogWarning("Firewall kuralı eklenemedi: {name}", ruleName);
        }
        else
        {
            _log.LogInformation("[dry-run] Firewall kuralı eklenecek: netsh {cmd}", addCmd);
        }
    }

    private async Task AddFirewallBlockForIpAsync(string ip, bool permanent, CancellationToken ct)
    {
        var ruleName = permanent ? $"Muhafiz_Block_{ip}" : $"Muhafiz_Block_{ip}_ttl";
        var cmd = $"advfirewall firewall add rule name=\"{ruleName}\" dir=out action=block remoteip={ip} enable=yes";

        if (_applyFirewall)
        {
            await RunNetshAsync($"advfirewall firewall delete rule name=\"{ruleName}\"", ct);
            var ok = await RunNetshAsync(cmd, ct);
            if (ok)
            {
                if (!permanent)
                    _tempRules[ruleName] = DateTimeOffset.UtcNow.AddSeconds(_ttlSeconds);
            }
            else
            {
                _log.LogWarning("Firewall kuralı eklenemedi (IP): {ip}", ip);
            }
        }
        else
        {
            _log.LogInformation("[dry-run] Firewall kuralı eklenecek: netsh {cmd}", cmd);
            if (!permanent)
                _tempRules[ruleName] = DateTimeOffset.UtcNow.AddSeconds(_ttlSeconds);
        }
    }

    private async Task DeleteFirewallRuleAsync(string ruleName, CancellationToken ct)
    {
        var cmd = $"advfirewall firewall delete rule name=\"{ruleName}\"";
        if (_applyFirewall)
        {
            var ok = await RunNetshAsync(cmd, ct);
            if (ok) _log.LogInformation("Firewall: kural silindi → {name}", ruleName);
        }
        else
        {
            _log.LogInformation("[dry-run] Firewall kuralı silinecek: netsh {cmd}", cmd);
        }
    }

    private static async Task<bool> RunNetshAsync(string args, CancellationToken ct)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "netsh",
            Arguments = args,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            Verb = "runas" // admin gerekebilir
        };

        try
        {
            using var p = Process.Start(psi)!;
            await Task.Run(() => p.WaitForExit(), ct);
            return p.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }
}
