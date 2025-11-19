using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Muhafiz.Agent.Ioc;

public sealed class IocStore
{
    public HashSet<string> Hashes { get; } = new(StringComparer.OrdinalIgnoreCase);

    public HashSet<string> BlockedHosts { get; } = new(StringComparer.OrdinalIgnoreCase);
    public List<string> BlockedPaths { get; } = new(); // alt-dize eşleşmesi
    public HashSet<string> IocIps { get; } = new(StringComparer.OrdinalIgnoreCase);

    public static IocStore Load(IConfiguration cfg, ILogger? log = null)
    {
        var store = new IocStore();

        // ---- HASHES ----
        try
        {
            var path = Expand(cfg["Ioc:HashesPath"]);
            if (!string.IsNullOrWhiteSpace(path) && File.Exists(path))
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(path));
                if (doc.RootElement.TryGetProperty("malicious_hashes", out var arr) && arr.ValueKind == JsonValueKind.Array)
                    foreach (var el in arr.EnumerateArray())
                    {
                        var h = el.GetString()?.Trim();
                        if (!string.IsNullOrEmpty(h)) store.Hashes.Add(h.ToLowerInvariant());
                    }
                log?.LogInformation("IOC: {count} hash yüklendi ({file})", store.Hashes.Count, path);
            }
            else log?.LogWarning("IOC hashes dosyası bulunamadı: {path}", path);
        }
        catch (Exception ex) { log?.LogError(ex, "IOC hashes yüklenemedi"); }

        // ---- URLS/IP ----
        try
        {
            var path = Expand(cfg["Ioc:UrlsPath"]);
            if (!string.IsNullOrWhiteSpace(path) && File.Exists(path))
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(path));
                if (doc.RootElement.TryGetProperty("blocked_hosts", out var hosts) && hosts.ValueKind == JsonValueKind.Array)
                    foreach (var el in hosts.EnumerateArray())
                    {
                        var h = el.GetString()?.Trim();
                        if (!string.IsNullOrEmpty(h)) store.BlockedHosts.Add(h.ToLowerInvariant());
                    }

                if (doc.RootElement.TryGetProperty("blocked_paths", out var paths) && paths.ValueKind == JsonValueKind.Array)
                    foreach (var el in paths.EnumerateArray())
                    {
                        var p = el.GetString()?.Trim();
                        if (!string.IsNullOrEmpty(p)) store.BlockedPaths.Add(p);
                    }

                if (doc.RootElement.TryGetProperty("ioc_ips", out var ips) && ips.ValueKind == JsonValueKind.Array)
                    foreach (var el in ips.EnumerateArray())
                    {
                        var ip = el.GetString()?.Trim();
                        if (!string.IsNullOrEmpty(ip)) store.IocIps.Add(ip);
                    }

                log?.LogInformation("IOC: {h} host, {p} path, {i} IP yüklendi ({file})",
                    store.BlockedHosts.Count, store.BlockedPaths.Count, store.IocIps.Count, path);
            }
            else log?.LogWarning("IOC urls dosyası bulunamadı: {path}", path);
        }
        catch (Exception ex) { log?.LogError(ex, "IOC urls yüklenemedi"); }

        return store;
    }

    public bool IsHashBlocked(string sha256)
        => !string.IsNullOrWhiteSpace(sha256) && Hashes.Contains(sha256.ToLowerInvariant());

    public bool IsHostBlocked(string host)
        => !string.IsNullOrWhiteSpace(host) && BlockedHosts.Contains(host.ToLowerInvariant());

    public bool IsIpBlocked(string ip)
        => !string.IsNullOrWhiteSpace(ip) && IocIps.Contains(ip);

    public bool IsUrlSuspicious(Uri uri)
    {
        if (uri == null) return false;
        var host = uri.Host.ToLowerInvariant();
        if (BlockedHosts.Contains(host)) return true;
        var path = uri.AbsolutePath ?? "";
        return BlockedPaths.Any(p => path.Contains(p, StringComparison.OrdinalIgnoreCase));
    }

    private static string Expand(string? p)
        => (p ?? string.Empty)
            .Replace('/', Path.DirectorySeparatorChar)
            .Replace("\\\\", "\\")
            .Replace("\"", "")
            .Trim()
            .Replace("%PROGRAMDATA%", Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData))
            .Replace("%USERPROFILE%", Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
}
