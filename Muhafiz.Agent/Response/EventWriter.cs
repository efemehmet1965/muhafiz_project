using System;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Muhafiz.Agent.Response
{
    public sealed class EventWriter
    {
        private readonly ILogger _log;
        private readonly string _root;

        public EventWriter(IConfiguration cfg, ILogger log)
        {
            _log = log;
            _root = Expand(cfg["Events:Root"] ?? "%PROGRAMDATA%/Muhafiz/events");
            try { Directory.CreateDirectory(_root); } catch { }
        }

        public async Task<string?> WriteIncidentAsync(Incident evt, CancellationToken ct)
        {
            try
            {
                var day = DateTime.UtcNow.ToString("yyyyMMdd");
                var dir = Path.Combine(_root, day);
                Directory.CreateDirectory(dir);

                var file = Path.Combine(dir, $"{evt.Id}.event.json");
                var json = JsonSerializer.Serialize(evt, new JsonSerializerOptions { WriteIndented = true });
                await File.WriteAllTextAsync(file, json, ct);

                _log.LogInformation("Olay kartı yazıldı: {file}", file);
                return file;
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "Olay kartı yazılamadı");
                return null;
            }
        }

        private static string Expand(string? p) =>
            Environment.ExpandEnvironmentVariables(p ?? string.Empty)
                .Replace('/', Path.DirectorySeparatorChar);

        public sealed class Incident
        {
            public string Id { get; set; } = Guid.NewGuid().ToString("N");
            public DateTimeOffset CreatedUtc { get; set; } = DateTimeOffset.UtcNow;

            public string[] Reasons { get; set; } = Array.Empty<string>();
            public string DetectionMode { get; set; } = "Silent";
            public string? Payload { get; set; }

            public string OriginalPath { get; set; } = "";
            public string? QuarantinePath { get; set; }
            public long Size { get; set; }
            public string Sha256 { get; set; } = "";

            public string[]? EgressHostsTtlBlocked { get; set; }
            public ProcessAction[]? ProcessActions { get; set; }

            // *** CANARY alanı (HATAYI GİDERİR) ***
            public string? CanaryToken { get; set; }

            public string? AnalystNotes { get; set; }
            public string? LlmSummary { get; set; }
        }

        public sealed class ProcessAction
        {
            public int Pid { get; set; }
            public string Exe { get; set; } = "";
            public string Action { get; set; } = "";
        }
    }
}
