using System.Collections.Generic;
using System.Diagnostics;
using System.Windows;
using System.Windows.Input;
using Muhafiz.Agent.WPF.UI.ViewModels;
using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Windows.Controls;
using Muhafiz.Agent.WPF.UI.Models;
using System.Threading.Tasks;

namespace Muhafiz.Agent.WPF.UI
{
    public partial class MainWindow : Window
    {
        private readonly string _settingsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Muhafiz", "settings.json");
        private string _eventsRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Muhafiz", "events");
        private readonly Dictionary<string, (string Endpoint, string Model)> _llmDefaults = new(StringComparer.OrdinalIgnoreCase)
        {
            ["Gemini"] = ("https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent", "gemini-pro"),
            ["OpenAI"] = ("https://api.openai.com/v1/chat/completions", "gpt-4o-mini")
        };
        private bool _isLoadingSettings;

        public MainWindow()
        {
            InitializeComponent();
            DataContext = new MainViewModel();

            Loaded += MainWindow_Loaded;
            BtnSave.Click += BtnSave_Click;
        }

        private void Border_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.LeftButton == MouseButtonState.Pressed)
            {
                DragMove();
            }
        }

        private void Minimize_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState.Minimized;
        }

        private void Close_Click(object sender, RoutedEventArgs e)
        {
            Application.Current.Shutdown();
        }

        private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            try
            {
                LoadSettingsIntoUi();
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "Ayarlar yüklenemedi: {ex.Message}", "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
            }

            if (DataContext is MainViewModel vm)
            {
                await vm.LoadIocDataAsync();
            }
        }

        private void LoadSettingsIntoUi()
        {
            _isLoadingSettings = true;
            try
            {
                if (!File.Exists(_settingsPath)) return;
                var json = File.ReadAllText(_settingsPath, Encoding.UTF8);
                var cfg = JsonSerializer.Deserialize<AppSettings>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? new AppSettings();

            // Genel
            ComboMode.SelectedIndex = string.Equals(cfg.Mode, "Silent", StringComparison.OrdinalIgnoreCase) ? 0 : 1;
            TxtWatchedPaths.Text = string.Join(Environment.NewLine, cfg.WatchedPaths ?? new());
            TxtProcessWhitelist.Text = string.Join(Environment.NewLine, cfg.ProcessWhitelist ?? new());

            // SelfProtection
            ChkSelfProtectionEnabled.IsChecked = cfg.SelfProtection?.Enabled ?? false;
            TxtHardenPaths.Text = string.Join(Environment.NewLine, cfg.SelfProtection?.HardenPaths ?? new());

            // Update Channel
            ChkUpdateChannelEnabled.IsChecked = cfg.UpdateChannel?.Enabled ?? false;
            TxtUpdateWatchPath.Text = cfg.UpdateChannel?.WatchPath ?? string.Empty;
            TxtUpdateInterval.Text = (cfg.UpdateChannel?.IntervalSeconds ?? 30).ToString();

            // Events
            var eventsRootFromSettings = cfg.Events?.Root;
            _eventsRoot = !string.IsNullOrWhiteSpace(eventsRootFromSettings) ? eventsRootFromSettings : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Muhafiz", "events");
            TxtEventsRoot.Text = _eventsRoot;

            // YARA
            ChkYaraEnabled.IsChecked = cfg.Yara?.Enabled ?? false;
            ChkYaraUseCli.IsChecked = cfg.Yara?.UseCli ?? false;
            TxtYaraCliPath.Text = cfg.Yara?.CliPath ?? string.Empty;
            TxtYaraRulesPath.Text = cfg.Yara?.RulesPath ?? string.Empty;

            // Egress / DNS
            TxtEgressHosts.Text = string.Join(Environment.NewLine, cfg.Egress?.Conditional?.Hosts ?? new());
            ChkDnsAnomalyEnabled.IsChecked = cfg.DnsAnomaly?.Enabled ?? false;
            TxtDnsAnomalyInterval.Text = (cfg.DnsAnomaly?.IntervalSeconds ?? 30).ToString();

            // Sandbox general
            ChkSandboxEnabled.IsChecked = cfg.Sandbox?.Enabled ?? false;
            // VirusTotal / HybridAnalysis API keys
            TxtVirusTotalApiKey.Text = cfg.Sandbox?.VirusTotal?.ApiKey ?? string.Empty;
            TxtHybridAnalysisApiKey.Text = cfg.Sandbox?.HybridAnalysis?.ApiKey ?? string.Empty;
            // Windows Sandbox
            ChkWinSandboxEnabled.IsChecked = cfg.Sandbox?.WindowsSandbox?.Enabled ?? false;
            TxtWinSandboxTimeout.Text = (cfg.Sandbox?.WindowsSandbox?.TimeoutSeconds ?? 120).ToString();
            TxtWinSandboxMemory.Text = (cfg.Sandbox?.WindowsSandbox?.MemoryMB ?? 2048).ToString();
            var net = cfg.Sandbox?.WindowsSandbox?.Networking ?? "Default";
            CmbWinSandboxNetworking.SelectedIndex = net.Equals("Enable", StringComparison.OrdinalIgnoreCase) || net.Equals("Enabled", StringComparison.OrdinalIgnoreCase) ? 2 :
                                                    net.Equals("Disable", StringComparison.OrdinalIgnoreCase) || net.Equals("Disabled", StringComparison.OrdinalIgnoreCase) ? 1 : 0;

            // Quarantine
            TxtQuarantineRoot.Text = cfg.Quarantine?.Root ?? string.Empty;
            ChkQuarantineEncrypt.IsChecked = cfg.Quarantine?.Encrypt ?? false;
            TxtQuarantineEncryptExtensions.Text = string.Join(Environment.NewLine, cfg.Quarantine?.EncryptExtensions ?? new());
            TxtQuarantineKeyPath.Text = cfg.Quarantine?.KeyPath ?? string.Empty;

            // ProcessKiller
            ChkProcessKillerEnabled.IsChecked = cfg.ProcessKiller?.Enabled ?? false;
            TxtProcessKillerTimeout.Text = (cfg.ProcessKiller?.SoftKillTimeoutMs ?? 1500).ToString();
            ChkProcessKillerHardKill.IsChecked = cfg.ProcessKiller?.HardKill ?? true;
            TxtProcessKillerExclusions.Text = string.Join(Environment.NewLine, cfg.ProcessKiller?.Exclusions ?? new());

            // Canary
            ChkCanaryEnabled.IsChecked = cfg.Canary?.Enabled ?? false;
            ChkCanaryAlertOnOpen.IsChecked = cfg.Canary?.AlertOnOpen ?? true;
            ChkCanaryQuarantineOnHit.IsChecked = cfg.Canary?.QuarantineOnHit ?? false;
            TxtCanaryReseedHours.Text = (cfg.Canary?.ReseedHours ?? 24).ToString();
            TxtCanaryDropPaths.Text = string.Join(Environment.NewLine, cfg.Canary?.DropPaths ?? new());
            TxtCanaryFilenames.Text = string.Join(Environment.NewLine, cfg.Canary?.Filenames ?? new());
            TxtCanaryContentMarkers.Text = string.Join(Environment.NewLine, cfg.Canary?.ContentMarkers ?? new());

            // Advanced - Clipboard
            ChkClipboardEnabled.IsChecked = cfg.Clipboard?.Enabled ?? false;
            TxtClipboardInterval.Text = (cfg.Clipboard?.PollingIntervalSeconds ?? 2).ToString();
            TxtClipboardPatterns.Text = string.Join(Environment.NewLine, cfg.Clipboard?.Patterns ?? new());

            // Advanced - Honeypot
            ChkHoneypotEnabled.IsChecked = cfg.Honeypot?.Enabled ?? false;
            TxtHoneypotPorts.Text = string.Join(", ", cfg.Honeypot?.Ports ?? new());

            // Advanced - Download Analysis
            ChkDownloadAnalysisEnabled.IsChecked = cfg.DownloadAnalysis?.Enabled ?? false;

            // Advanced - LLM
            ChkLlmAnalysisEnabled.IsChecked = cfg.LlmAnalysis?.Enabled ?? false;
            var providerCombo = GetLlmProviderCombo();
            var provider = cfg.LlmAnalysis?.Provider;
            if (providerCombo != null)
            {
                if (!string.IsNullOrWhiteSpace(provider))
                {
                    providerCombo.SelectedValue = provider;
                }
                else
                {
                    providerCombo.SelectedIndex = 0;
                }

                if (providerCombo.SelectedValue == null)
                {
                    providerCombo.SelectedIndex = 0;
                }
            }

            var modelBox = GetLlmModelTextBox();
            if (modelBox != null)
            {
                modelBox.Text = cfg.LlmAnalysis?.Model ?? string.Empty;
            }
            TxtLlmApiKey.Text = cfg.LlmAnalysis?.ApiKey ?? string.Empty;
            TxtLlmApiEndpoint.Text = cfg.LlmAnalysis?.ApiEndpoint ?? string.Empty;

            ApplyLlmDefaultsIfEmpty(ignoreLoadingGuard: true);
        }
        finally
        {
            _isLoadingSettings = false;
        }
        }

        private void BtnSave_Click(object? sender, RoutedEventArgs e)
        {
            try
            {
                var cfg = BuildSettingsFromUi();
                Directory.CreateDirectory(Path.GetDirectoryName(_settingsPath)!);
                var json = JsonSerializer.Serialize(cfg, new JsonSerializerOptions 
                {
                    WriteIndented = true,
                    DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
                });
                File.WriteAllText(_settingsPath, json, Encoding.UTF8);
                MessageBox.Show(this, "Ayarlar kaydedildi.", "Bilgi", MessageBoxButton.OK, MessageBoxImage.Information);

                // update events root
                _eventsRoot = !string.IsNullOrWhiteSpace(cfg.Events?.Root) ? cfg.Events.Root : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Muhafiz", "events");
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, $"Kaydetme hatası: {ex.Message}", "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private AppSettings BuildSettingsFromUi()
        {
            var cfg = new AppSettings();

            cfg.Mode = ComboMode.SelectedIndex == 0 ? "Silent" : "Normal";
            cfg.WatchedPaths = TxtWatchedPaths.Text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries).Select(s => s.Trim()).ToList();
            cfg.ProcessWhitelist = TxtProcessWhitelist.Text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries).Select(s => s.Trim()).ToList();

            cfg.SelfProtection ??= new SelfProtectionSettings();
            cfg.SelfProtection.Enabled = ChkSelfProtectionEnabled.IsChecked == true;
            cfg.SelfProtection.HardenPaths = TxtHardenPaths.Text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries).Select(s => s.Trim()).ToList();

            cfg.UpdateChannel ??= new UpdateChannelSettings();
            cfg.UpdateChannel.Enabled = ChkUpdateChannelEnabled.IsChecked == true;
            cfg.UpdateChannel.WatchPath = TxtUpdateWatchPath.Text.Trim();
            cfg.UpdateChannel.IntervalSeconds = int.TryParse(TxtUpdateInterval.Text, out var upd) ? upd : 30;

            cfg.Events ??= new EventSettings();
            cfg.Events.Root = TxtEventsRoot.Text.Trim();

            cfg.Yara ??= new YaraSettings();
            cfg.Yara.Enabled = ChkYaraEnabled.IsChecked == true;
            cfg.Yara.UseCli = ChkYaraUseCli.IsChecked == true;
            cfg.Yara.CliPath = TxtYaraCliPath.Text.Trim();
            cfg.Yara.RulesPath = TxtYaraRulesPath.Text.Trim();

            cfg.Egress ??= new EgressSettings();
            cfg.Egress.Conditional ??= new EgressConditionalSettings();
            cfg.Egress.Conditional.Hosts = TxtEgressHosts.Text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries).Select(s => s.Trim()).ToList();

            cfg.DnsAnomaly ??= new DnsAnomalySettings();
            cfg.DnsAnomaly.Enabled = ChkDnsAnomalyEnabled.IsChecked == true;
            cfg.DnsAnomaly.IntervalSeconds = int.TryParse(TxtDnsAnomalyInterval.Text, out var dnsInt) ? dnsInt : 30;

            cfg.Sandbox ??= new SandboxSettings();
            cfg.Sandbox.Enabled = ChkSandboxEnabled.IsChecked == true;
            cfg.Sandbox.VirusTotal ??= new VirusTotalSettings();
            cfg.Sandbox.VirusTotal.ApiKey = TxtVirusTotalApiKey.Text.Trim();
            cfg.Sandbox.HybridAnalysis ??= new HybridAnalysisSettings();
            cfg.Sandbox.HybridAnalysis.ApiKey = TxtHybridAnalysisApiKey.Text.Trim();
            cfg.Sandbox.WindowsSandbox ??= new WindowsSandboxSettings();
            cfg.Sandbox.WindowsSandbox.Enabled = ChkWinSandboxEnabled.IsChecked == true;
            cfg.Sandbox.WindowsSandbox.TimeoutSeconds = int.TryParse(TxtWinSandboxTimeout.Text, out var wsbT) ? wsbT : 120;
            cfg.Sandbox.WindowsSandbox.MemoryMB = int.TryParse(TxtWinSandboxMemory.Text, out var wsbM) ? wsbM : 2048;
            cfg.Sandbox.WindowsSandbox.Networking = (CmbWinSandboxNetworking.SelectedItem as ComboBoxItem)?.Content as string ?? "Default";

            cfg.Quarantine ??= new QuarantineSettings();
            cfg.Quarantine.Root = TxtQuarantineRoot.Text.Trim();
            cfg.Quarantine.Encrypt = ChkQuarantineEncrypt.IsChecked == true;
            cfg.Quarantine.EncryptExtensions = TxtQuarantineEncryptExtensions.Text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries).Select(s => s.Trim()).ToList();
            cfg.Quarantine.KeyPath = TxtQuarantineKeyPath.Text.Trim();

            cfg.ProcessKiller ??= new ProcessKillerSettings();
            cfg.ProcessKiller.Enabled = ChkProcessKillerEnabled.IsChecked == true;
            cfg.ProcessKiller.SoftKillTimeoutMs = int.TryParse(TxtProcessKillerTimeout.Text, out var pkT) ? pkT : 1500;
            cfg.ProcessKiller.HardKill = ChkProcessKillerHardKill.IsChecked != false;
            cfg.ProcessKiller.Exclusions = TxtProcessKillerExclusions.Text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries).Select(s => s.Trim()).ToList();

            cfg.Canary ??= new CanarySettings();
            cfg.Canary.Enabled = ChkCanaryEnabled.IsChecked == true;
            cfg.Canary.AlertOnOpen = ChkCanaryAlertOnOpen.IsChecked != false;
            cfg.Canary.ReseedHours = int.TryParse(TxtCanaryReseedHours.Text, out var rh) ? rh : 24;
            cfg.Canary.QuarantineOnHit = ChkCanaryQuarantineOnHit.IsChecked == true;
            cfg.Canary.DropPaths = TxtCanaryDropPaths.Text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries).Select(s => s.Trim()).ToList();
            cfg.Canary.Filenames = TxtCanaryFilenames.Text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries).Select(s => s.Trim()).ToList();
            cfg.Canary.ContentMarkers = TxtCanaryContentMarkers.Text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries).Select(s => s.Trim()).ToList();

            // Advanced - Clipboard
            cfg.Clipboard ??= new ClipboardSettings();
            cfg.Clipboard.Enabled = ChkClipboardEnabled.IsChecked == true;
            cfg.Clipboard.PollingIntervalSeconds = int.TryParse(TxtClipboardInterval.Text, out var cbInt) ? cbInt : 2;
            cfg.Clipboard.Patterns = TxtClipboardPatterns.Text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries).Select(s => s.Trim()).ToList();

            // Advanced - Honeypot
            cfg.Honeypot ??= new HoneypotSettings();
            cfg.Honeypot.Enabled = ChkHoneypotEnabled.IsChecked == true;
            cfg.Honeypot.Ports = TxtHoneypotPorts.Text.Split(',').Select(p => int.TryParse(p.Trim(), out var port) ? port : 0).Where(p => p > 0).ToList();

            // Advanced - Download Analysis
            cfg.DownloadAnalysis ??= new DownloadAnalysisSettings();
            cfg.DownloadAnalysis.Enabled = ChkDownloadAnalysisEnabled.IsChecked == true;

            // Advanced - LLM
            cfg.LlmAnalysis ??= new LlmAnalysisSettings();
            cfg.LlmAnalysis.Enabled = ChkLlmAnalysisEnabled.IsChecked == true;
            cfg.LlmAnalysis.Provider = GetSelectedLlmProvider();
            cfg.LlmAnalysis.ApiKey = TxtLlmApiKey.Text.Trim();
            cfg.LlmAnalysis.ApiEndpoint = TxtLlmApiEndpoint.Text.Trim();
            cfg.LlmAnalysis.Model = (GetLlmModelTextBox()?.Text ?? string.Empty).Trim();

            return cfg;
        }

        private string GetSelectedLlmProvider()
        {
            var combo = GetLlmProviderCombo();
            return combo?.SelectedValue as string ?? "Gemini";
        }

        private void CmbLlmProvider_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            ApplyLlmDefaultsIfEmpty();
        }

        private ComboBox? GetLlmProviderCombo() => FindName("CmbLlmProvider") as ComboBox;
        private TextBox? GetLlmModelTextBox() => FindName("TxtLlmModel") as TextBox;

        private void ApplyLlmDefaultsIfEmpty(bool ignoreLoadingGuard = false)
        {
            if (_isLoadingSettings && !ignoreLoadingGuard)
            {
                return;
            }

            var provider = GetSelectedLlmProvider();
            var modelBox = GetLlmModelTextBox();
            var endpointBox = TxtLlmApiEndpoint;
            if (_llmDefaults.TryGetValue(provider, out var defaults))
            {
                if (endpointBox != null && string.IsNullOrWhiteSpace(endpointBox.Text))
                {
                    endpointBox.Text = defaults.Endpoint;
                }

                if (modelBox != null && string.IsNullOrWhiteSpace(modelBox.Text))
                {
                    modelBox.Text = defaults.Model;
                }
            }
        }

        private void HostUrl_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if (sender is TextBlock textBlock && textBlock.Text is string url && Uri.IsWellFormedUriString(url, UriKind.Absolute))
            {
                try
                {
                    Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"URL açılamadı: {ex.Message}", "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }
    }
}
