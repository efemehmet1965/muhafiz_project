using System;
using System.Collections.Generic;

namespace Muhafiz.Agent.Analysis
{
    public enum SandboxTrigger { OnDetection, OnQuarantine }

    public sealed class SandboxJob
    {
        public required string Sha256 { get; init; }
        public required string OriginalPath { get; init; }
        public string? QuarantinedPath { get; init; }
        public SandboxTrigger Trigger { get; init; }
        public string[] Reasons { get; init; } = Array.Empty<string>();
    }

    public sealed class ProviderResult
    {
        public string Provider { get; init; } = "";
        public bool Ran { get; init; }
        public bool Success { get; init; }
        public string? ReportPath { get; init; }
        public Dictionary<string, object>? Data { get; init; }
        public string? Error { get; init; }
    }

    public sealed class OrchestratorResult
    {
        public string Sha256 { get; init; } = "";
        public string Summary { get; init; } = "";
        public List<ProviderResult> Providers { get; init; } = new();
        public DateTime TimestampUtc { get; init; } = DateTime.UtcNow;
    }

    public interface ISandboxBackend
    {
        string Name { get; }
        bool IsEnabled { get; }
        bool CanAnalyze(SandboxJob job);
        System.Threading.Tasks.Task<ProviderResult> AnalyzeAsync(SandboxJob job, System.Threading.CancellationToken ct);
    }
}
