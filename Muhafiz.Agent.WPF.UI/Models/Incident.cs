using System;

namespace Muhafiz.Agent.WPF.UI.Models
{
    public sealed class Incident
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N");
        public string OriginalPath { get; set; } = "";
        public string? QuarantinePath { get; set; }
        public string Sha256 { get; set; } = "";
        public long Size { get; set; }
        public string[] Reasons { get; set; } = Array.Empty<string>();
        public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;
    }
}
