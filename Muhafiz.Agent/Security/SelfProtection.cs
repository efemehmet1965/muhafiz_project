using System;
using System.Diagnostics;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Muhafiz.Agent.Security
{
    public sealed class SelfProtection
    {
        private readonly ILogger _log;
        private readonly IConfiguration _cfg;
        private readonly string _svcName;

        public SelfProtection(IConfiguration cfg, ILogger log)
        {
            _cfg = cfg;
            _log = log;
            _svcName = (_cfg["Service:Name"] ?? "Muhafiz.Agent").Trim();
        }

        public void ApplyAll()
        {
            TryApplyServiceRecovery();
            TryHardenPaths();
        }

        private void TryApplyServiceRecovery()
        {
            try
            {
                var cmd1 = $"failure \"{_svcName}\" reset= 60 actions= restart/5000/restart/5000/none/0";
                var cmd2 = $"failureflag \"{_svcName}\" 1";
                if (!RunTool("sc", cmd1)) _log.LogDebug("Service recovery (1) uygulanamadı: {name}", _svcName);
                if (!RunTool("sc", cmd2)) _log.LogDebug("Service recovery (2) uygulanamadı: {name}", _svcName);
                else _log.LogInformation("Service recovery politikası ayarlandı: {name}", _svcName);
            }
            catch (Exception ex) { _log.LogDebug(ex, "Service recovery ayarı hatası"); }
        }

        private void TryHardenPaths()
        {
            try
            {
                var list = _cfg.GetSection("SelfProtection:HardenPaths").Get<string[]>() ?? Array.Empty<string>();
                foreach (var raw in list)
                {
                    var dir = Expand(raw);
                    if (string.IsNullOrWhiteSpace(dir)) continue;
                    Directory.CreateDirectory(dir);
                    RelaxDenyAndGrant(dir);
                    _log.LogInformation("ACL sertleştirildi: {dir}", dir);
                }
            }
            catch (Exception ex) { _log.LogDebug(ex, "ACL sertleştirme hatası"); }
        }

        /// <summary>
        /// Eski DENY kurallarını (Users/Authenticated Users) kaldırır, SYSTEM/Administrators'a Full,
        /// mevcut kullanıcıya Modify verir. DENY kullanmıyoruz.
        /// </summary>
        private static void RelaxDenyAndGrant(string path)
        {
            var di = new DirectoryInfo(path);
            var sec = di.GetAccessControl();

            var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
            var authUsers = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);
            var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var current = WindowsIdentity.GetCurrent().User ?? authUsers;

            // 1) Eski DENY (write/delete) kurallarını temizle
            var denyMask = FileSystemRights.CreateFiles | FileSystemRights.CreateDirectories |
                           FileSystemRights.Write | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles;

            foreach (var sid in new[] { users, authUsers })
            {
                var denyRule = new FileSystemAccessRule(
                    sid, denyMask,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Deny);
                try { sec.RemoveAccessRuleAll(denyRule); } catch { /* yok say */ }
            }

            // 2) Pozitif haklar: SYSTEM + Admins = Full, Current User = Modify
            var allowFlags = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;

            sec.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, allowFlags, PropagationFlags.None, AccessControlType.Allow));
            sec.AddAccessRule(new FileSystemAccessRule(admins, FileSystemRights.FullControl, allowFlags, PropagationFlags.None, AccessControlType.Allow));
            sec.AddAccessRule(new FileSystemAccessRule(current, FileSystemRights.Modify, allowFlags, PropagationFlags.None, AccessControlType.Allow));

            try { di.SetAccessControl(sec); } catch { /* bazı durumlarda admin gerekir */ }
        }

        private static string Expand(string? p) =>
            Environment.ExpandEnvironmentVariables(p ?? string.Empty)
                .Replace('/', Path.DirectorySeparatorChar);

        private static bool RunTool(string exe, string args)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = exe,
                    Arguments = args,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden,
                    Verb = "runas"
                };
                using var p = Process.Start(psi)!;
                p.WaitForExit();
                return p.ExitCode == 0;
            }
            catch { return false; }
        }
    }
}
