using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace Muhafiz.Agent.Setup
{
    public sealed class EnvironmentBootstrapper
    {
        private readonly string _appBaseDirectory;
        private readonly string _configDir;
        private readonly string _settingsPath;

        private EnvironmentBootstrapper(string appBaseDirectory)
        {
            _appBaseDirectory = appBaseDirectory;
            var programDataPath = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            _configDir = Path.Combine(programDataPath, "Muhafiz");
            _settingsPath = Path.Combine(_configDir, "settings.json");
        }

        public static BootstrapResult Bootstrap(string appBaseDirectory)
        {
            var bootstrapper = new EnvironmentBootstrapper(appBaseDirectory);
            return bootstrapper.Run();
        }

        private BootstrapResult Run()
        {
            Directory.CreateDirectory(_configDir);
            EnsureSettingsFile();

            using var configDocument = JsonDocument.Parse(File.ReadAllText(_settingsPath));
            var root = configDocument.RootElement;

            var iocDir = EnsureIocFiles();
            var eventsDir = EnsureDirectoryFromConfig(root, new[] { "Events", "Root" }, Path.Combine(_configDir, "events"));
            var quarantineDir = EnsureDirectoryFromConfig(root, new[] { "Quarantine", "Root" }, Path.Combine(_configDir, "Q"));
            var yaraDir = EnsureYaraAssets(root);

            return new BootstrapResult(
                _configDir,
                _settingsPath,
                iocDir,
                yaraDir,
                eventsDir,
                quarantineDir);
        }

        private void EnsureSettingsFile()
        {
            if (File.Exists(_settingsPath))
            {
                return;
            }

            var templatePath = Path.Combine(_appBaseDirectory, "appsettings.json");
            if (!File.Exists(templatePath))
            {
                File.WriteAllText(_settingsPath, "{}");
                return;
            }

            File.Copy(templatePath, _settingsPath, overwrite: false);
        }

        private string EnsureIocFiles()
        {
            var iocDir = Path.Combine(_configDir, "ioc");
            Directory.CreateDirectory(iocDir);

            var hashesPath = Path.Combine(iocDir, "hashes.json");
            if (!File.Exists(hashesPath))
            {
                var hashesPayload = JsonSerializer.Serialize(new { malicious_hashes = Array.Empty<string>() }, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(hashesPath, hashesPayload);
            }

            var urlsPath = Path.Combine(iocDir, "urls.json");
            if (!File.Exists(urlsPath))
            {
                var urlsPayload = JsonSerializer.Serialize(new
                {
                    blocked_hosts = Array.Empty<string>(),
                    blocked_paths = Array.Empty<string>(),
                    ioc_ips = Array.Empty<string>()
                }, new JsonSerializerOptions { WriteIndented = true });

                File.WriteAllText(urlsPath, urlsPayload);
            }

            return iocDir;
        }

        private string EnsureDirectoryFromConfig(JsonElement root, IReadOnlyList<string> jsonPath, string fallback)
        {
            var rawPath = GetString(root, jsonPath) ?? fallback;
            var normalized = NormalizePath(rawPath);
            Directory.CreateDirectory(normalized);
            return normalized;
        }

        private string EnsureYaraAssets(JsonElement root)
        {
            var configuredCliPath = GetString(root, new[] { "Yara", "CliPath" });
            var configuredRulesPath = GetString(root, new[] { "Yara", "RulesPath" });

            var yaraDir = NormalizePath(Path.Combine(_configDir, "yara"));
            Directory.CreateDirectory(yaraDir);

            var rulesDir = NormalizePath(configuredRulesPath ?? Path.Combine(yaraDir, "rules"));
            Directory.CreateDirectory(rulesDir);

            var cliTargetPath = NormalizePath(configuredCliPath ?? Path.Combine(yaraDir, "yara64.exe"));
            var cliTargetDirectory = Path.GetDirectoryName(cliTargetPath);
            if (!string.IsNullOrWhiteSpace(cliTargetDirectory))
            {
                Directory.CreateDirectory(cliTargetDirectory);
            }

            if (!File.Exists(cliTargetPath))
            {
                var packagedCli = Path.Combine(_appBaseDirectory, "Resources", Path.GetFileName(cliTargetPath));
                if (File.Exists(packagedCli))
                {
                    File.Copy(packagedCli, cliTargetPath, overwrite: false);
                }
                else
                {
                    Console.Error.WriteLine($"[Bootstrap] Unable to locate packaged YARA CLI at {packagedCli}. Please place the executable under Resources.");
                }
            }

            return yaraDir;
        }

        private static string? GetString(JsonElement root, IReadOnlyList<string> pathSegments)
        {
            var current = root;
            foreach (var segment in pathSegments)
            {
                if (current.ValueKind != JsonValueKind.Object || !current.TryGetProperty(segment, out var next))
                {
                    return null;
                }
                current = next;
            }

            return current.ValueKind == JsonValueKind.String ? current.GetString() : null;
        }

        private static string NormalizePath(string rawPath)
        {
            var expanded = Environment.ExpandEnvironmentVariables(rawPath ?? string.Empty);
            expanded = expanded.Replace('/', Path.DirectorySeparatorChar);
            if (string.IsNullOrWhiteSpace(expanded))
            {
                expanded = Directory.GetCurrentDirectory();
            }

            return Path.GetFullPath(expanded);
        }
    }

    public sealed record BootstrapResult(
        string ConfigDirectory,
        string SettingsPath,
        string IocDirectory,
        string YaraDirectory,
        string EventsDirectory,
        string QuarantineDirectory);
}
