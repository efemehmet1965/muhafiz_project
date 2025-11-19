using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Muhafiz.Agent.Ioc
{
    /// <summary>
    /// hashes.json / urls.json değişince IOC'yi otomatik yeniden yükler.
    /// </summary>
    public sealed class IocWatcher : IDisposable
    {
        private readonly ILogger _log;
        private readonly IConfiguration _cfg;
        private readonly string _dir;
        private readonly Action<IocStore> _onReload;
        private readonly FileSystemWatcher _fsw;
        private readonly object _gate = new();
        private DateTime _last = DateTime.MinValue;
        private readonly TimeSpan _debounce = TimeSpan.FromMilliseconds(600);
        private bool _disposed;

        public IocWatcher(IConfiguration cfg, ILogger log, string directory, Action<IocStore> onReload)
        {
            _cfg = cfg;
            _log = log;
            _dir = directory;
            _onReload = onReload;

            Directory.CreateDirectory(_dir);

            _fsw = new FileSystemWatcher(_dir)
            {
                Filter = "*.json",
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size
            };
            _fsw.Changed += OnChanged;
            _fsw.Created += OnChanged;
            _fsw.Renamed += OnRenamed;
            _fsw.EnableRaisingEvents = true;

            _log.LogInformation("IOC watcher aktif: {dir}", _dir);
        }

        private void OnChanged(object sender, FileSystemEventArgs e) => TryReload(e.FullPath);
        private void OnRenamed(object sender, RenamedEventArgs e) => TryReload(e.FullPath);

        private void TryReload(string path)
        {
            if (_disposed) return;
            var name = Path.GetFileName(path).ToLowerInvariant();
            if (name != "hashes.json" && name != "urls.json") return;

            lock (_gate)
            {
                var now = DateTime.UtcNow;
                if (now - _last < _debounce) return;
                _last = now;
            }

            Task.Run(() =>
            {
                try
                {
                    // Küçük bir gecikme: yazım tamamlanmamış olabilir
                    Thread.Sleep(250);
                    var store = IocStore.Load(_cfg, _log);
                    _onReload(store);
                    _log.LogInformation("IOC yeniden yüklendi (hot-reload).");
                }
                catch (Exception ex)
                {
                    _log.LogWarning(ex, "IOC hot-reload hatası");
                }
            });
        }

        public void Dispose()
        {
            _disposed = true;
            _fsw.Dispose();
        }
    }
}
