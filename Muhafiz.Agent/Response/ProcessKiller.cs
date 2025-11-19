using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Muhafiz.Agent.Response
{
    public sealed class ProcessKiller
    {
        private readonly ILogger _log;
        private readonly bool _enabled;
        private readonly int _softTimeoutMs;
        private readonly bool _hardKill;
        private readonly HashSet<string> _exclusions;
        private readonly int _selfPid;
        private readonly string _selfExe;

        public ProcessKiller(IConfiguration cfg, ILogger log)
        {
            _log = log;
            _enabled = string.Equals(cfg["ProcessKiller:Enabled"], "true", StringComparison.OrdinalIgnoreCase);
            _softTimeoutMs = Math.Max(300, int.TryParse(cfg["ProcessKiller:SoftKillTimeoutMs"], out var ms) ? ms : 1500);
            _hardKill = !string.Equals(cfg["ProcessKiller:HardKill"], "false", StringComparison.OrdinalIgnoreCase);

            _exclusions = new HashSet<string>(
                (cfg.GetSection("ProcessKiller:Exclusions").Get<string[]>() ?? Array.Empty<string>())
                .Select(s => s.Trim())
                .Where(s => !string.IsNullOrWhiteSpace(s)),
                StringComparer.OrdinalIgnoreCase);

            var self = Process.GetCurrentProcess();
            _selfPid = self.Id;
            _selfExe = SafeExe(self);

            // Dinamik dışlama: ajan kendi adını listeye ekle
            _exclusions.Add(_selfExe);
            _exclusions.Add(Path.GetFileNameWithoutExtension(_selfExe));
        }

        public bool IsEnabled => _enabled;

        public async Task<KillResult> KillLockingProcessesAsync(string targetPath, CancellationToken ct)
        {
            var res = new KillResult();
            if (!_enabled) return res;

            var locks = GetLockingPids(targetPath);
            if (locks.Count == 0) return res;

            foreach (var pid in locks.Distinct())
            {
                if (ct.IsCancellationRequested) break;
                if (pid == _selfPid) { _log.LogInformation("Killer: kendi PID atlandı ({pid})", pid); continue; }

                Process? p = null;
                try { p = Process.GetProcessById(pid); }
                catch { continue; }

                var name = SafeExe(p);
                if (_exclusions.Contains(name) || _exclusions.Contains(Path.GetFileNameWithoutExtension(name)))
                {
                    _log.LogInformation("Killer: dışlanan süreç atlandı → {name} (PID {pid})", name, pid);
                    res.Skipped.Add((pid, name));
                    continue;
                }

                bool exited = false;

                // 1) Yumuşak kapatma
                try
                {
                    if (p.CloseMainWindow())
                    {
                        _log.LogInformation("Killer: yumuşak kapatma denendi → {name} (PID {pid})", name, pid);
                        exited = await WaitExitAsync(p, _softTimeoutMs, ct);
                    }
                }
                catch { /* GUI olmayan proses olabilir */ }

                // 2) Sert kapatma
                if (!exited && _hardKill)
                {
                    try
                    {
                        p.Kill(entireProcessTree: true);
                        _log.LogWarning("Killer: SERT kapatma uygulandı → {name} (PID {pid})", name, pid);
                        exited = await WaitExitAsync(p, 2000, ct);
                        res.HardKilled.Add((pid, name));
                    }
                    catch (Exception ex)
                    {
                        _log.LogWarning(ex, "Killer: sert kapatma başarısız → {name} (PID {pid})", name, pid);
                        res.Errors.Add((pid, name, "KillFailed"));
                    }
                }

                if (exited) res.SoftKilled.Add((pid, name));
                else res.StillRunning.Add((pid, name));
            }

            return res;
        }

        // ---- Restart Manager ----
        public static List<int> GetLockingPids(string path)
        {
            var pids = new List<int>();
            int session = 0;
            var key = Guid.NewGuid().ToString();

            if (RmStartSession(out session, 0, key) != 0) return pids;

            try
            {
                var resources = new string[] { path };
                if (RmRegisterResources(session, (uint)resources.Length, resources, 0, null, 0, null) != 0)
                    return pids;

                uint needed = 0, count = 0, reason;
                var res = RmGetList(session, out needed, ref count, null, out reason);

                if (res == ERROR_MORE_DATA)
                {
                    var infos = new RM_PROCESS_INFO[needed];
                    count = needed;
                    res = RmGetList(session, out needed, ref count, infos, out reason);

                    if (res == 0)
                    {
                        for (int i = 0; i < count; i++)
                            pids.Add(infos[i].Process.dwProcessId);
                    }
                }
            }
            finally { RmEndSession(session); }

            return pids;
        }

        private static async Task<bool> WaitExitAsync(Process p, int timeoutMs, CancellationToken ct)
        {
            try
            {
                var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                p.EnableRaisingEvents = true;
                p.Exited += (_, __) => tcs.TrySetResult(true);

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(timeoutMs);

                var completed = await Task.WhenAny(tcs.Task, Task.Delay(Timeout.Infinite, cts.Token));
                return completed == tcs.Task || p.HasExited;
            }
            catch { return p.HasExited; }
        }

        private static string SafeExe(Process p)
        {
            try { return Path.GetFileName(p.MainModule?.FileName ?? p.ProcessName); }
            catch { return p.ProcessName; }
        }

        private const int ERROR_MORE_DATA = 234;

        [StructLayout(LayoutKind.Sequential)]
        private struct RM_UNIQUE_PROCESS
        {
            public int dwProcessId;
            public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct RM_PROCESS_INFO
        {
            public RM_UNIQUE_PROCESS Process;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string strAppName;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
            public string strServiceShortName;

            public RM_APP_TYPE ApplicationType;
            public uint AppStatus;
            public uint TSSessionId;
            [MarshalAs(UnmanagedType.Bool)]
            public bool bRestartable;
        }

        private enum RM_APP_TYPE { RmUnknownApp = 0, RmMainWindow = 1, RmOtherWindow = 2, RmService = 3, RmExplorer = 4, RmConsole = 5, RmCritical = 1000 }

        [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)] private static extern int RmStartSession(out int pSessionHandle, int dwSessionFlags, string strSessionKey);
        [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)] private static extern int RmRegisterResources(int pSessionHandle, uint nFiles, string[] rgsFilenames, uint nApplications, [In] RM_UNIQUE_PROCESS[]? rgApplications, uint nServices, string[]? rgsServiceNames);
        [DllImport("rstrtmgr.dll")] private static extern int RmGetList(int dwSessionHandle, out uint nProcInfoNeeded, ref uint nProcInfo, [In, Out] RM_PROCESS_INFO[]? rgAffectedApps, out uint lpdwRebootReasons);
        [DllImport("rstrtmgr.dll")] private static extern int RmEndSession(int pSessionHandle);
    }

    public sealed class KillResult
    {
        public List<(int pid, string exe)> SoftKilled { get; } = new();
        public List<(int pid, string exe)> HardKilled { get; } = new();
        public List<(int pid, string exe)> StillRunning { get; } = new();
        public List<(int pid, string exe)> Skipped { get; } = new();
        public List<(int pid, string exe, string reason)> Errors { get; } = new();
    }
}
