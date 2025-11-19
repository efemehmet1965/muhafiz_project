using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Muhafiz.Agent.Update
{
    /// <summary>
    /// Basit güncelleme kanalı: WatchPath altındaki *.zip paketleri tespit eder,
    /// SHA-256 hesaplar ve staging'e açar. Uygulama/yeniden başlatma yapmaz.
    /// </summary>
    public sealed class UpdateWatcher
    {
        private readonly ILogger _log;
        private readonly string _watchPath;
        private readonly int _intervalSec;
        private readonly string _staging;

        public UpdateWatcher(IConfiguration cfg, ILogger log)
        {
            _log = log;
            _watchPath = Expand(cfg["UpdateChannel:WatchPath"] ?? "%PROGRAMDATA%/Muhafiz/update");
            _intervalSec = Math.Max(10, int.TryParse(cfg["UpdateChannel:IntervalSeconds"], out var s) ? s : 30);
            _staging = Path.Combine(_watchPath, "staging");

            Directory.CreateDirectory(_watchPath);
            Directory.CreateDirectory(_staging);
        }

        public Task RunAsync(CancellationToken ct) => Task.Run(async () =>
        {
            _log.LogInformation("Güncelleme kanalı izleme başladı: {dir} (interval: {sec}s)", _watchPath, _intervalSec);
            while (!ct.IsCancellationRequested)
            {
                try { await ScanOnceAsync(ct); }
                catch (Exception ex) { _log.LogDebug(ex, "UpdateWatcher döngü hatası"); }

                await Task.Delay(TimeSpan.FromSeconds(_intervalSec), ct);
            }
        }, ct);

        private async Task ScanOnceAsync(CancellationToken ct)
        {
            var zips = Directory.GetFiles(_watchPath, "*.zip", SearchOption.TopDirectoryOnly);
            foreach (var zip in zips)
            {
                try
                {
                    // Dosya yazımı bitmemiş olabilir, kısa bekle
                    await Task.Delay(200, ct);

                    var sha = await Sha256Async(zip, ct);
                    var id = Path.GetFileNameWithoutExtension(zip) + "_" + sha[..8];
                    var dest = Path.Combine(_staging, id);

                    if (Directory.Exists(dest))
                    {
                        _log.LogInformation("Güncelleme zaten açılmış: {id}", id);
                        continue;
                    }

                    Directory.CreateDirectory(dest);
                    ZipFile.ExtractToDirectory(zip, dest);
                    _log.LogInformation("Güncelleme paketi stage edildi: {id} → {dest}", id, dest);
                    _log.LogInformation("Not: Uygulama adımı manuel/onaylı olacaktır (şimdilik otomasyon yok).");
                }
                catch (Exception ex)
                {
                    _log.LogWarning(ex, "Güncelleme paketi işlenemedi: {zip}", zip);
                }
            }
        }

        private static async Task<string> Sha256Async(string file, CancellationToken ct)
        {
            using var fs = File.OpenRead(file);
            using var sha = SHA256.Create();
            var hash = await sha.ComputeHashAsync(fs, ct);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }

        private static string Expand(string? p) =>
            Environment.ExpandEnvironmentVariables(p ?? string.Empty)
                .Replace('/', Path.DirectorySeparatorChar);
    }
}
