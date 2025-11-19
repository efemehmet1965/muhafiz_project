using System.Collections.Concurrent;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Muhafiz.Agent.Analysis.Backends; // ISandboxBackend

namespace Muhafiz.Agent.Analysis
{
    /// <summary>
    /// Basit kuyruk + tüketici döngüsü. DI’dan IEnumerable<ISandboxBackend> alır.
    /// Her job’ı şimdilik sadece loglar (gerçek entegrasyonu sonra ekleyeceğiz).
    /// Bu haliyle hiçbir concrete backend’e doğrudan bağlı değildir.
    /// </summary>
    public sealed class SandboxOrchestrator : IDisposable
    {
        private readonly ILogger<SandboxOrchestrator> _log;
        private readonly IReadOnlyList<ISandboxBackend> _backends;
        private readonly ConcurrentQueue<SandboxJob> _queue = new();
        private readonly SemaphoreSlim _signal = new(0);
        private readonly CancellationTokenSource _cts = new();
        private Task? _loop;
        private int _started; // 0/1

        public SandboxOrchestrator(
            IEnumerable<ISandboxBackend>? backends,
            ILogger<SandboxOrchestrator> log,
            IConfiguration _ /* ileride ayar okunursa burada */)
        {
            _log = log;
            _backends = (backends ?? Enumerable.Empty<ISandboxBackend>()).ToList();
            _log.LogInformation("SandboxOrchestrator hazır (backends: {cnt})", _backends.Count);
        }

        /// <summary> Worker gibi yerlerden çağrılır. </summary>
        public void Enqueue(SandboxJob job)
        {
            _queue.Enqueue(job);
            _signal.Release();

            // tüketici döngüsünü bir kez başlat
            if (Interlocked.Exchange(ref _started, 1) == 0)
            {
                _loop = Task.Run(ProcessLoopAsync);
            }
        }

        private async Task ProcessLoopAsync()
        {
            _log.LogInformation("Sandbox kuyruğu döngüsü başladı.");
            try
            {
                while (!_cts.IsCancellationRequested)
                {
                    await _signal.WaitAsync(_cts.Token);

                    while (_queue.TryDequeue(out var job))
                    {
                        // Şimdilik yalnızca log. (Gerçek submit çağrılarını ekleyeceğiz.)
                        _log.LogInformation(
                            "Sandbox kuyruğu: sha={sha} trigger={trg} q={q} backends={cnt}",
                            job.Sha256,
                            job.Trigger.ToString(),
                            job.QuarantinedPath ?? "-",
                            _backends.Count);

                        // Örn. ileride:
                        // foreach (var be in _backends)
                        // {
                        //     try { await be.SubmitAsync(job, _cts.Token); }
                        //     catch (Exception ex) { _log.LogWarning(ex, "{name} submit hatası", be.Name); }
                        // }
                    }
                }
            }
            catch (OperationCanceledException) { /* normal */ }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "Sandbox döngüsü hata");
            }
            finally
            {
                _log.LogInformation("Sandbox döngüsü durdu.");
            }
        }

        public void Dispose()
        {
            try { _cts.Cancel(); } catch { }
            try { _signal.Dispose(); } catch { }
            try { _cts.Dispose(); } catch { }
        }
    }
}
