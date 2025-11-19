using System.Collections.Generic;
using System.ComponentModel;

namespace Muhafiz.Agent.WPF.UI.Models
{
    public class AppSettings 
    {
        public string Mode { get; set; } = string.Empty;
        public List<string> WatchedPaths { get; set; } = new();
        public List<string> ProcessWhitelist { get; set; } = new();
        public IocSettings Ioc { get; set; } = new();
        public YaraSettings Yara { get; set; } = new();
        public EgressSettings Egress { get; set; } = new();
        public QuarantineSettings Quarantine { get; set; } = new();
        public EventSettings Events { get; set; } = new();
        public DnsAnomalySettings DnsAnomaly { get; set; } = new();
        public SelfProtectionSettings SelfProtection { get; set; } = new();
        public UpdateChannelSettings UpdateChannel { get; set; } = new();
        public ProcessKillerSettings ProcessKiller { get; set; } = new();
        public CanarySettings Canary { get; set; } = new();
        public SandboxSettings Sandbox { get; set; } = new();
        
        // New Features
        public ClipboardSettings Clipboard { get; set; } = new();
        public HoneypotSettings Honeypot { get; set; } = new();
        public DownloadAnalysisSettings DownloadAnalysis { get; set; } = new();
        public LlmAnalysisSettings LlmAnalysis { get; set; } = new();
    }

    public class ClipboardSettings
    {
        public bool Enabled { get; set; }
        public int PollingIntervalSeconds { get; set; } = 2;
        public List<string> Patterns { get; set; } = new();
    }

    public class HoneypotSettings
    {
        public bool Enabled { get; set; }
        public List<int> Ports { get; set; } = new();
    }

    public class DownloadAnalysisSettings
    {
        public bool Enabled { get; set; }
    }

    public class LlmAnalysisSettings
    {
        public bool Enabled { get; set; }
        public string Provider { get; set; } = "Gemini";
        public string ApiKey { get; set; } = string.Empty;
        public string ApiEndpoint { get; set; } = string.Empty;
        public string Model { get; set; } = string.Empty;
    }

    public class IocSettings
    {
        public string HashesPath { get; set; } = string.Empty;
        public string UrlsPath { get; set; } = string.Empty;
    }

    public class YaraSettings
    {
        public bool Enabled { get; set; }
        public bool UseCli { get; set; }
        public string CliPath { get; set; } = string.Empty;
        public string RulesPath { get; set; } = string.Empty;
    }

    public class EgressSettings
    {
        public EgressConditionalSettings Conditional { get; set; } = new();
        public bool ConditionalWebhookBlock { get; set; }
        public bool GlobalWebhookBlock { get; set; }
        public bool IocBlockAlways { get; set; }
        public int RuleTtlSeconds { get; set; }
        public bool ApplyFirewall { get; set; }
        public int MaxIpsPerHost { get; set; }
        public int DnsCacheSeconds { get; set; }
    }

    public class EgressConditionalSettings
    {
        public List<string> Hosts { get; set; } = new();
    }

    public class QuarantineSettings
    {
        public string Root { get; set; } = string.Empty;
        public bool Encrypt { get; set; }
        public List<string> EncryptExtensions { get; set; } = new();
        public string KeyPath { get; set; } = string.Empty;
    }

    public class EventSettings
    {
        public string Root { get; set; } = string.Empty;
    }

    public class DnsAnomalySettings
    {
        public bool Enabled { get; set; }
        public int IntervalSeconds { get; set; }
    }

    public class SelfProtectionSettings
    {
        public bool Enabled { get; set; }
        public List<string> HardenPaths { get; set; } = new();
    }

    public class UpdateChannelSettings
    {
        public bool Enabled { get; set; }
        public string WatchPath { get; set; } = string.Empty;
        public int IntervalSeconds { get; set; }
    }

    public class ProcessKillerSettings
    {
        public bool Enabled { get; set; }
        public int SoftKillTimeoutMs { get; set; }
        public bool HardKill { get; set; }
        public List<string> Exclusions { get; set; } = new();
    }

    public class CanarySettings
    {
        public bool Enabled { get; set; }
        public List<string> DropPaths { get; set; } = new();
        public List<string> Filenames { get; set; } = new();
        public List<string> ContentMarkers { get; set; } = new();
        public bool AlertOnOpen { get; set; }
        public int ReseedHours { get; set; }
        public bool QuarantineOnHit { get; set; }
    }

    public class SandboxSettings
    {
        public bool Enabled { get; set; }
        public string Trigger { get; set; } = string.Empty;
        public int MaxParallel { get; set; }
        public int CacheTtlMinutes { get; set; }
        public List<string> AllowedExtensions { get; set; } = new();
        public WindowsSandboxSettings WindowsSandbox { get; set; } = new();
        public VirusTotalSettings VirusTotal { get; set; } = new();
        public HybridAnalysisSettings HybridAnalysis { get; set; } = new();
        public PrivacySettings Privacy { get; set; } = new();
    }

    public class WindowsSandboxSettings
    {
        public bool Enabled { get; set; }
        public int TimeoutSeconds { get; set; }
        public int MemoryMB { get; set; }
        public string Networking { get; set; } = string.Empty;
    }

    public class VirusTotalSettings
    {
        public bool Enabled { get; set; }
        public string ApiKey { get; set; } = string.Empty;
        public string Mode { get; set; } = string.Empty;
        public int RateLimitPerMin { get; set; }
    }

    public class HybridAnalysisSettings
    {
        public bool Enabled { get; set; }
        public string ApiKey { get; set; } = string.Empty;
        public string Environment { get; set; } = string.Empty;
        public string Mode { get; set; } = string.Empty;
        public int RateLimitPerMin { get; set; }
    }

    public class PrivacySettings
    {
        public bool AskBeforeUpload { get; set; }
        public List<string> NeverUploadPaths { get; set; } = new();
        public List<string> AllowExtensions { get; set; } = new();
        public int MaxSampleSizeMB { get; set; }
    }
}
