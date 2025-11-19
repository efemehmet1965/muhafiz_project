using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Muhafiz.Agent.Analysis.Backends
{
    using Muhafiz.Agent.Analysis;

    public sealed class HybridAnalysisBackend : ISandboxBackend
    {
        private readonly IConfiguration _cfg;
        private readonly ILogger _log;
        private readonly HttpClient _http;
        private readonly bool _enabled;
        private readonly string _apiKey;

        public HybridAnalysisBackend(IConfiguration cfg, ILogger<HybridAnalysisBackend> log)
        {
            _cfg = cfg; _log = log;
            _enabled = string.Equals(cfg["Sandbox:HybridAnalysis:Enabled"], "true", StringComparison.OrdinalIgnoreCase);
            _apiKey = cfg["Sandbox:HybridAnalysis:ApiKey"] ?? "";

            _http = new HttpClient { BaseAddress = new Uri("https://www.hybrid-analysis.com/api/v2/") };
            if (!string.IsNullOrWhiteSpace(_apiKey))
                _http.DefaultRequestHeaders.Add("api-key", _apiKey);
            _http.DefaultRequestHeaders.Add("User-Agent", "Muhafiz-Agent");
        }

        public string Name => "HybridAnalysis";
        public bool IsEnabled => _enabled && !string.IsNullOrWhiteSpace(_apiKey);
        public bool CanAnalyze(SandboxJob job) => true;

        public async Task<ProviderResult> AnalyzeAsync(SandboxJob job, CancellationToken ct)
        {
            if (!IsEnabled) return new ProviderResult { Provider = Name, Ran = false, Success = false, Error = "Disabled or no API key" };

            try
            {
                // Basit hash araması: POST /search/hash
                var content = new StringContent($"hash={job.Sha256}", Encoding.UTF8, "application/x-www-form-urlencoded");
                using var res = await _http.PostAsync("search/hash", content, ct);

                if (res.StatusCode == System.Net.HttpStatusCode.NotFound)
                    return new ProviderResult { Provider = Name, Ran = true, Success = true, Data = new() { { "HashFound", false } } };

                res.EnsureSuccessStatusCode();
                var json = await res.Content.ReadAsStringAsync(ct);
                using var doc = JsonDocument.Parse(json);
                bool found = doc.RootElement.ValueKind == JsonValueKind.Array && doc.RootElement.GetArrayLength() > 0;

                string? verdict = null;
                if (found)
                {
                    var first = doc.RootElement[0];
                    verdict = first.TryGetProperty("verdict", out var v) ? v.GetString() : null;
                }

                return new ProviderResult
                {
                    Provider = Name,
                    Ran = true,
                    Success = true,
                    Data = new()
                    {
                        { "HashFound", found },
                        { "Verdict", verdict }
                    }
                };
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "HybridAnalysis lookup hatası");
                return new ProviderResult { Provider = Name, Ran = true, Success = false, Error = ex.Message };
            }
        }
    }
}
