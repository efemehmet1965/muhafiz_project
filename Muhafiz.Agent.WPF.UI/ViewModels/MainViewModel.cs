using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Media;
using System;
using System.Collections.ObjectModel;
using System.Text.Json;
using System.Text.Json.Serialization;
using Muhafiz.Agent.WPF.UI.Models;
using System.ComponentModel;
using System.Windows.Data;
using System.Text.Encodings.Web;
using System.Collections.Generic;
using System.Windows;

namespace Muhafiz.Agent.WPF.UI.ViewModels
{
    public class LlmAnalysisResult
    {
        [JsonPropertyName("risk_score")]
        public int RiskScore { get; set; }
        public string? Summary { get; set; }
        public string? Reasoning { get; set; }
    }

    public class EventEntry
    {
        public string Id { get; set; }
        public DateTimeOffset CreatedUtc { get; set; }
        public string[] Reasons { get; set; }
        public string DetectionMode { get; set; }
        public string OriginalPath { get; set; }
        public string FileName => Path.GetFileName(OriginalPath);
        public string? QuarantinePath { get; set; }
        public long Size { get; set; }
        public string Sha256 { get; set; }
        public string? CanaryToken { get; set; }
        public string? HostUrl { get; set; }

        [JsonPropertyName("llm_analysis")]
        public LlmAnalysisResult? LlmAnalysis { get; set; }
    }

    public partial class MainViewModel : ObservableObject
    {
        private const string AgentProcessName = "Muhafiz.Agent";
                private readonly string _agentExePath = Path.Combine(AppContext.BaseDirectory, "Muhafiz.Agent.exe");

        private readonly string _settingsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Muhafiz", "settings.json");
        private readonly string _iocRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Muhafiz", "ioc");

        [ObservableProperty]
        private string _agentStatusText = "Bilinmiyor";

        [ObservableProperty]
        private Brush _agentStatusColor = Brushes.Gray;

        [ObservableProperty]
        private bool _isStartEnabled = false;

        [ObservableProperty]
        private bool _isStopEnabled = false;

        [ObservableProperty]
        private bool _isRestartEnabled = false;

        [ObservableProperty]
        private bool _isIocLoading = false;

        [ObservableProperty]
        private string _currentPanelName = "Genel";

        public bool IsGenelPanelVisible => CurrentPanelName == "Genel";
        public bool IsAgentPanelVisible => CurrentPanelName == "Agent";
        public bool IsIocPanelVisible => CurrentPanelName == "Ioc";
        public bool IsYaraPanelVisible => CurrentPanelName == "Yara";
        public bool IsEgressPanelVisible => CurrentPanelName == "Egress";
        public bool IsSandboxPanelVisible => CurrentPanelName == "Sandbox";
        public bool IsQuarantinePanelVisible => CurrentPanelName == "Quarantine";
        public bool IsProcessKillerPanelVisible => CurrentPanelName == "ProcessKiller";
        public bool IsCanaryPanelVisible => CurrentPanelName == "Canary";
        public bool IsLogsPanelVisible => CurrentPanelName == "Logs";
        public bool IsAdvancedPanelVisible => CurrentPanelName == "Advanced";

        public ObservableCollection<IocEntry> Hashes { get; set; } = new();
        public ObservableCollection<IocEntry> Urls { get; set; } = new();
        public ObservableCollection<EventEntry> Logs { get; } = new();

        [ObservableProperty]
        private string _newHash = string.Empty;

        [ObservableProperty]
        private string _newUrl = string.Empty;

        [ObservableProperty]
        private string _searchHashesText = string.Empty;

        [ObservableProperty]
        private string _searchUrlsText = string.Empty;

        public ICollectionView HashesView { get; }
        public ICollectionView UrlsView { get; }

        public MainViewModel()
        {
            RefreshAgentStatusCommand.Execute(null);
            CurrentPanelName = "Genel"; // Set default panel

            HashesView = CollectionViewSource.GetDefaultView(Hashes);
            HashesView.Filter = FilterHashes;

            UrlsView = CollectionViewSource.GetDefaultView(Urls);
            UrlsView.Filter = FilterUrls;
        }

        partial void OnSearchHashesTextChanged(string value)
        {
            HashesView.Refresh();
        }

        partial void OnSearchUrlsTextChanged(string value)
        {
            UrlsView.Refresh();
        }

        private bool FilterHashes(object item)
        {
            if (string.IsNullOrWhiteSpace(SearchHashesText)) return true;
            return (item as IocEntry)?.Value.Contains(SearchHashesText, StringComparison.OrdinalIgnoreCase) == true;
        }

        private bool FilterUrls(object item)
        {
            if (string.IsNullOrWhiteSpace(SearchUrlsText)) return true;
            return (item as IocEntry)?.Value.Contains(SearchUrlsText, StringComparison.OrdinalIgnoreCase) == true;
        }

        [RelayCommand]
        private async void Navigate(string panelName)
        {
            CurrentPanelName = panelName;
            OnPropertyChanged(nameof(IsGenelPanelVisible));
            OnPropertyChanged(nameof(IsAgentPanelVisible));
            OnPropertyChanged(nameof(IsIocPanelVisible));
            OnPropertyChanged(nameof(IsYaraPanelVisible));
            OnPropertyChanged(nameof(IsEgressPanelVisible));
            OnPropertyChanged(nameof(IsSandboxPanelVisible));
            OnPropertyChanged(nameof(IsQuarantinePanelVisible));
            OnPropertyChanged(nameof(IsProcessKillerPanelVisible));
            OnPropertyChanged(nameof(IsCanaryPanelVisible));
            OnPropertyChanged(nameof(IsLogsPanelVisible));
            OnPropertyChanged(nameof(IsAdvancedPanelVisible));

            if (panelName == "Logs")
            {
                await LoadLogsAsync();
            }
        }

        private async Task LoadLogsAsync()
        {
            try
            {
                var eventsRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Muhafiz", "events");
                if (!Directory.Exists(eventsRoot))
                {
                    Logs.Clear();
                    return;
                }

                var eventFiles = Directory.EnumerateFiles(eventsRoot, "*.event.json", SearchOption.AllDirectories);

                var loadedLogs = new List<EventEntry>();
                var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };

                await Task.Run(async () =>
                {
                    foreach (var file in eventFiles)
                    {
                        try
                        {
                            var json = await File.ReadAllTextAsync(file);
                            var entry = JsonSerializer.Deserialize<EventEntry>(json, options);
                            if (entry != null)
                            {
                                loadedLogs.Add(entry);
                            }
                        }
                        catch (Exception ex)
                        {
                            Debug.WriteLine($"Failed to parse event file {file}: {ex.Message}");
                        }
                    }
                });

                // Update collection on UI thread
                Application.Current.Dispatcher.Invoke(() =>
                {
                    Logs.Clear();
                    foreach (var log in loadedLogs.OrderByDescending(l => l.CreatedUtc))
                    {
                        Logs.Add(log);
                    }
                });
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Olaylar yüklenirken bir hata oluştu: {ex.Message}", "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        [RelayCommand]
        private void RefreshAgentStatus()
        {
            var processes = Process.GetProcessesByName(AgentProcessName);
            if (processes.Any())
            {
                AgentStatusText = "Çalışıyor";
                AgentStatusColor = new SolidColorBrush(Color.FromRgb(0, 255, 0)); // Green
                IsStartEnabled = false;
                IsStopEnabled = true;
                IsRestartEnabled = true;
            }
            else
            {
                AgentStatusText = "Durduruldu";
                AgentStatusColor = Brushes.Gray;
                IsStartEnabled = true;
                IsStopEnabled = false;
                IsRestartEnabled = false;
            }
        }

        [RelayCommand]
        private void StartAgent()
        {
            try
            {
                if (Process.GetProcessesByName(AgentProcessName).Any()) return;

                var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                var flagDir = Path.Combine(programData, "Muhafiz");
                Directory.CreateDirectory(flagDir);
                var flagPath = Path.Combine(flagDir, "ui_start.token");
                var token = Guid.NewGuid().ToString("N");
                File.WriteAllText(flagPath, token);

                var startInfo = new ProcessStartInfo
                {
                    FileName = _agentExePath,
                    Arguments = $"--ui-token {token}",
                    WorkingDirectory = Path.GetDirectoryName(_agentExePath),
                    UseShellExecute = true,
                    CreateNoWindow = true
                };
                Process.Start(startInfo);
            }
            catch (Exception ex)
            {
                System.Windows.MessageBox.Show($"Agent başlatılamadı: {ex.Message}", "Hata", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
            }
            finally
            {
                RefreshAgentStatus();
            }
        }

        [RelayCommand]
        private void StopAgent()
        {
            try
            {
                var processes = Process.GetProcessesByName(AgentProcessName);
                foreach (var process in processes)
                {
                    process.Kill();
                    process.WaitForExit(5000);
                }
            }
            catch (Exception ex)
            {
                System.Windows.MessageBox.Show($"Agent durdurulamadı: {ex.Message}", "Hata", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
            }
            finally
            {
                RefreshAgentStatus();
            }
        }

        [RelayCommand]
        private async Task RestartAgent()
        {
            try
            {
                StopAgent();
                await Task.Delay(1000);
                StartAgent();
            }
            catch (Exception ex)
            {
                System.Windows.MessageBox.Show($"Agent yeniden başlatılamadı: {ex.Message}", "Hata", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
            }
            finally
            {
                RefreshAgentStatus();
            }
        }

        public async Task LoadIocDataAsync()
        {
            IsIocLoading = true;
            try
            {
                Directory.CreateDirectory(_iocRoot);
                var hashesPath = Path.Combine(_iocRoot, "hashes.json");
                var urlsPath = Path.Combine(_iocRoot, "urls.json");

                var (loadedHashes, loadedUrls) = await Task.Run(async () =>
                {
                    var tempHashes = new List<IocEntry>();
                    var tempUrls = new List<IocEntry>();

                    if (File.Exists(hashesPath))
                    {
                        try
                        {
                            var json = await File.ReadAllTextAsync(hashesPath);
                            using var doc = JsonDocument.Parse(json);
                            var root = doc.RootElement;

                            if (root.ValueKind == JsonValueKind.Object && root.TryGetProperty("malicious_hashes", out var arr) && arr.ValueKind == JsonValueKind.Array)
                            {
                                foreach (var el in arr.EnumerateArray())
                                {
                                    var h = el.GetString()?.Trim();
                                    if (!string.IsNullOrEmpty(h))
                                    {
                                        tempHashes.Add(new IocEntry { Value = h });
                                    }
                                }
                            }
                            else if (root.ValueKind == JsonValueKind.Array) // Fallback to old simple array format
                            {
                                foreach (var el in root.EnumerateArray())
                                {
                                    var h = el.GetString()?.Trim();
                                    if (!string.IsNullOrEmpty(h))
                                    {
                                        tempHashes.Add(new IocEntry { Value = h });
                                    }
                                }
                            }
                        }
                        catch (Exception)
                        {
                            // Ignore errors on background thread
                        }
                    }
                    else
                    {
                        try
                        {
                            await File.WriteAllTextAsync(hashesPath, JsonSerializer.Serialize(new HashesFileContent(), new JsonSerializerOptions { WriteIndented = true }));
                        }
                        catch (Exception) { /* Ignore */ }
                    }

                    // Load urls.json
                    if (File.Exists(urlsPath))
                    {
                        try
                        {
                            var json = await File.ReadAllTextAsync(urlsPath);
                            using var doc = JsonDocument.Parse(json);
                            var root = doc.RootElement;

                            if (root.ValueKind == JsonValueKind.Object && root.TryGetProperty("blocked_hosts", out var hosts) && hosts.ValueKind == JsonValueKind.Array)
                            {
                                foreach (var el in hosts.EnumerateArray())
                                {
                                    var h = el.GetString()?.Trim();
                                    if (!string.IsNullOrEmpty(h))
                                    {
                                        tempUrls.Add(new IocEntry { Value = h });
                                    }
                                }
                            }
                            else if (root.ValueKind == JsonValueKind.Array) // Fallback for old simple array format for URLs (blocked_hosts)
                            {
                                foreach (var el in root.EnumerateArray())
                                {
                                    var h = el.GetString()?.Trim();
                                    if (!string.IsNullOrEmpty(h))
                                    {
                                        tempUrls.Add(new IocEntry { Value = h });
                                    }
                                }
                            }
                        }
                        catch (Exception)
                        {
                            // Ignore errors on background thread
                        }
                    }
                    else
                    {
                        try
                        {
                            await File.WriteAllTextAsync(urlsPath, JsonSerializer.Serialize(new UrlsFileContent(), new JsonSerializerOptions { WriteIndented = true }));
                        }
                        catch (Exception) { /* Ignore */ }
                    }
                    return (tempHashes, tempUrls);
                });

                // Update collections on UI thread
                Hashes.Clear();
                foreach (var hash in loadedHashes) Hashes.Add(hash);

                Urls.Clear();
                foreach (var url in loadedUrls) Urls.Add(url);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"IOC verileri yüklenirken bir hata oluştu: {ex.Message}", "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                IsIocLoading = false;
            }
        }

        [RelayCommand]
        private void AddHash()
        {
            if (string.IsNullOrWhiteSpace(NewHash)) return;

            // Basic hash validation (MD5, SHA1, SHA256)
            if (!System.Text.RegularExpressions.Regex.IsMatch(NewHash, "^[a-fA-F0-9]{32}$") && // MD5
                !System.Text.RegularExpressions.Regex.IsMatch(NewHash, "^[a-fA-F0-9]{40}$") && // SHA1
                !System.Text.RegularExpressions.Regex.IsMatch(NewHash, "^[a-fA-F0-9]{64}$"))   // SHA256
            {
                // Show error message
                return;
            }

            Hashes.Add(new IocEntry { Value = NewHash });
            NewHash = string.Empty;
            SaveIocData();
        }

        [RelayCommand]
        private void DeleteHash(IocEntry hashToDelete)
        {
            if (hashToDelete == null) return;
            Hashes.Remove(hashToDelete);
            SaveIocData();
        }

        [RelayCommand]
        private void AddUrl()
        {
            if (string.IsNullOrWhiteSpace(NewUrl)) return;

            // Basic URL validation
            if (!Uri.TryCreate(NewUrl, UriKind.Absolute, out _))
            {
                // Show error message
                return;
            }

            Urls.Add(new IocEntry { Value = NewUrl });
            NewUrl = string.Empty;
            SaveIocData();
        }

        [RelayCommand]
        private void DeleteUrl(IocEntry urlToDelete)
        {
            if (urlToDelete == null) return;
            Urls.Remove(urlToDelete);
            SaveIocData();
        }

        private void SaveIocData()
        {
            try
            {
                var hashesPath = Path.Combine(_iocRoot, "hashes.json");
                var hashesContent = new HashesFileContent
                {
                    malicious_hashes = Hashes.Select(e => e.Value).ToList()
                };
                File.WriteAllText(hashesPath, JsonSerializer.Serialize(hashesContent, new JsonSerializerOptions { WriteIndented = true }));

                var urlsPath = Path.Combine(_iocRoot, "urls.json");
                var urlsContent = new UrlsFileContent
                {
                    blocked_hosts = Urls.Select(e => e.Value).ToList(),
                    blocked_paths = new List<string>(), // UI currently doesn't manage this
                    ioc_ips = new List<string>()             // UI currently doesn't manage this
                };
                File.WriteAllText(urlsPath, JsonSerializer.Serialize(urlsContent, new JsonSerializerOptions { WriteIndented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping }));
            }
            catch (Exception ex)
            {
                System.Windows.MessageBox.Show($"IOC kaydedilemedi: {ex.Message}", "Hata", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Warning);
            }
        }
    }
}
