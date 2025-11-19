using System;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Muhafiz.Agent.Response
{
    public sealed class QuarantineManager
    {
        private readonly ILogger _log;
        private readonly string _root;

        public QuarantineManager(IConfiguration cfg, ILogger log)
        {
            _log = log;
            _root = Expand(cfg["Quarantine:Root"] ?? "%PROGRAMDATA%/Muhafiz/Q");

            try { Directory.CreateDirectory(_root); }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "Karantina kökü oluşturulamadı: {root}", _root);
            }
        }

        public async Task<string?> QuarantineAsync(string sourcePath, string sha256, string[] reasons, CancellationToken ct)
        {
            try
            {
                if (!File.Exists(sourcePath))
                {
                    _log.LogWarning("Karantina: dosya bulunamadı → {path}", sourcePath);
                    return null;
                }

                var id = Guid.NewGuid().ToString("N");
                var day = DateTime.UtcNow.ToString("yyyyMMdd");
                var dir = Path.Combine(_root, day);

                Directory.CreateDirectory(dir);

                var targetPath = Path.Combine(dir, id + ".quar");
                var metaPath = targetPath + ".meta.json";

                // 1) Dosyayı karantina alanına taşı (kilitliyse kopyala + sil)
                if (!await TryMoveOrCopyAsync(sourcePath, targetPath, ct))
                {
                    _log.LogWarning("Karantina: dosya taşınamadı → {path}", sourcePath);
                    return null;
                }

                // 2) Koruma bayrakları (read-only + hidden); EFS şifreleme mümkünse dener
                try
                {
                    File.SetAttributes(targetPath, FileAttributes.ReadOnly | FileAttributes.Hidden);
                    try { File.Encrypt(targetPath); } catch { /* Bazı sürümlerde olmayabilir */ }
                }
                catch { /* önemsiz */ }

                // 3) Metadata yaz
                var fi = new FileInfo(targetPath);
                var meta = new QuarantineMeta
                {
                    Id = id,
                    QuarantinedAtUtc = DateTimeOffset.UtcNow,
                    OriginalPath = sourcePath,
                    QuarantinePath = targetPath,
                    Sha256 = sha256,
                    Size = fi.Length,
                    Reasons = reasons ?? Array.Empty<string>()
                };

                var json = JsonSerializer.Serialize(meta, new JsonSerializerOptions { WriteIndented = true });
                await File.WriteAllTextAsync(metaPath, json, ct);

                _log.LogInformation("Karantinaya alındı: {target} (neden: {reasons})", targetPath, string.Join(",", meta.Reasons));
                return targetPath;
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "Karantina hatası: {path}", sourcePath);
                return null;
            }
        }

        private static async Task<bool> TryMoveOrCopyAsync(string src, string dst, CancellationToken ct)
        {
            // Önce doğrudan Move dene
            try
            {
                File.Move(src, dst, overwrite: false);
                return true;
            }
            catch { /* kilitli olabilir, kopyaya geç */ }

            // Kopyala + sil (lock toleranslı)
            try
            {
                using var inFs = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var outFs = new FileStream(dst, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                await inFs.CopyToAsync(outFs, 1024 * 64, ct);
            }
            catch
            {
                // Son bir deneme: küçük gecikme ile tekrar
                try
                {
                    await Task.Delay(200, ct);
                    using var inFs2 = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var outFs2 = new FileStream(dst, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                    await inFs2.CopyToAsync(outFs2, 1024 * 64, ct);
                }
                catch { return false; }
            }

            // Kaynağı silmeye çalış (başaramazsa log atıp bırak)
            try { File.Delete(src); } catch { /* bazı durumlarda süreç kilitli olabilir */ }

            return true;
        }

        private static string Expand(string? p) =>
            Environment.ExpandEnvironmentVariables(p ?? string.Empty)
                .Replace('/', Path.DirectorySeparatorChar);

        private sealed class QuarantineMeta
        {
            public string Id { get; set; } = "";
            public DateTimeOffset QuarantinedAtUtc { get; set; }
            public string OriginalPath { get; set; } = "";
            public string QuarantinePath { get; set; } = "";
            public string Sha256 { get; set; } = "";
            public long Size { get; set; }
            public string[] Reasons { get; set; } = Array.Empty<string>();
        }
    }
}
