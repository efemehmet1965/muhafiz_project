using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Muhafiz.Agent.Analysis.Backends
{
    using Muhafiz.Agent.Analysis;

    public sealed class VirusTotalBackend : ISandboxBackend
    {
        private readonly IConfiguration _cfg;
        private readonly ILogger _log;
        private readonly HttpClient _http;
        private readonly bool _enabled;
        private readonly string _apiKey;

        public VirusTotalBackend(IConfiguration cfg, ILogger<VirusTotalBackend> log)
        {
            _cfg = cfg;
            _log = log;
            _http = new HttpClient { BaseAddress = new Uri("https://www.virustotal.com/api/v3/") };

            _enabled = string.Equals(cfg["Sandbox:VirusTotal:Enabled"], "true", StringComparison.OrdinalIgnoreCase);
            _apiKey = cfg["Sandbox:VirusTotal:ApiKey"] ?? "";

            if (!string.IsNullOrWhiteSpace(_apiKey))
                _http.DefaultRequestHeaders.Add("x-apikey", _apiKey);
        }

        public string Name => "VirusTotal";
        public bool IsEnabled => _enabled && !string.IsNullOrWhiteSpace(_apiKey);
        public bool CanAnalyze(SandboxJob job) => true;

        public async Task<ProviderResult> AnalyzeAsync(SandboxJob job, CancellationToken ct)
        {
            if (!IsEnabled) return new ProviderResult { Provider = Name, Ran = false, Success = false, Error = "Disabled or no API key" };

            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, $"files/{job.Sha256}");
                using var res = await _http.SendAsync(req, ct);
                if (res.StatusCode == System.Net.HttpStatusCode.NotFound)
                {
                    return new ProviderResult
                    {
                        Provider = Name,
                        Ran = true,
                        Success = true,
                        Data = new() { { "HashFound", false } }
                    };
                }
                res.EnsureSuccessStatusCode();
                var json = await res.Content.ReadAsStringAsync(ct);

                using var doc = JsonDocument.Parse(json);
                var data = doc.RootElement.GetProperty("data");
                var stats = data.GetProperty("attributes").GetProperty("last_analysis_stats");
                int mal = stats.TryGetProperty("malicious", out var m) ? m.GetInt32() : 0;
                int sus = stats.TryGetProperty("suspicious", out var s) ? s.GetInt32() : 0;

                string link = $"https://www.virustotal.com/gui/file/{job.Sha256}";
                return new ProviderResult
                {
                    Provider = Name,
                    Ran = true,
                    Success = true,
                    Data = new()
                    {
                        { "HashFound", true },
                        { "Malicious", mal },
                        { "Suspicious", sus },
                        { "Link", link }
                    }
                };
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "VirusTotal lookup hatası");
                return new ProviderResult { Provider = Name, Ran = true, Success = false, Error = ex.Message };
            }
        }
    }
}
