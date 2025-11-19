using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;

namespace Muhafiz.Agent.Analysis
{
    public class LlmAnalyser
    {
        private const string DefaultGeminiEndpoint = "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent";
        private const string DefaultOpenAiEndpoint = "https://api.openai.com/v1/chat/completions";

        private readonly ILogger<LlmAnalyser> _log;
        private readonly bool _enabled;
        private readonly string _provider;
        private readonly string _apiKey;
        private readonly string _apiEndpoint;
        private readonly string _model;
        private readonly HttpClient _httpClient;

        public LlmAnalyser(ILogger<LlmAnalyser> log, IConfiguration cfg)
        {
            _log = log;
            _enabled = cfg.GetValue<bool>("LlmAnalysis:Enabled", false);
            _provider = cfg.GetValue<string>("LlmAnalysis:Provider") ?? "Gemini";
            _apiKey = cfg.GetValue<string>("LlmAnalysis:ApiKey") ?? string.Empty;
            _apiEndpoint = cfg.GetValue<string>("LlmAnalysis:ApiEndpoint") ?? string.Empty;
            _model = cfg.GetValue<string>("LlmAnalysis:Model") ?? string.Empty;

            if (string.IsNullOrWhiteSpace(_apiEndpoint))
            {
                _apiEndpoint = IsOpenAiProvider() ? DefaultOpenAiEndpoint : DefaultGeminiEndpoint;
            }

            if (string.IsNullOrWhiteSpace(_model))
            {
                _model = IsOpenAiProvider() ? "gpt-4o-mini" : "gemini-pro";
            }

            _httpClient = new HttpClient();
        }

        public bool IsEnabled => _enabled && !string.IsNullOrEmpty(_apiKey) && !string.IsNullOrEmpty(_apiEndpoint);

        public async Task<LlmAnalysisResult?> AnalyseIncidentAsync(object incidentData)
        {
            if (!IsEnabled)
            {
                return null;
            }

            var prompt = BuildPrompt(incidentData);

            try
            {
                var response = await SendLlmRequestAsync(prompt);
                response.EnsureSuccessStatusCode();

                var analysisText = await ExtractResponseTextAsync(response);
                var result = ParseLlmResponse(analysisText);

                _log.LogInformation("LLM analysis completed. Risk score: {score}", result?.RiskScore);
                return result;
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "Failed to get LLM analysis.");
                return null;
            }
        }

        private Task<HttpResponseMessage> SendLlmRequestAsync(string prompt)
        {
            return IsOpenAiProvider()
                ? SendOpenAiRequestAsync(prompt)
                : SendGeminiRequestAsync(prompt);
        }

        private Task<HttpResponseMessage> SendGeminiRequestAsync(string prompt)
        {
            var requestUri = _apiEndpoint.Contains("?", StringComparison.OrdinalIgnoreCase)
                ? $"{_apiEndpoint}&key={_apiKey}"
                : $"{_apiEndpoint}?key={_apiKey}";

            var requestBody = new
            {
                contents = new[]
                {
                    new { parts = new[] { new { text = prompt } } }
                }
            };

            return _httpClient.PostAsJsonAsync(requestUri, requestBody);
        }

        private async Task<HttpResponseMessage> SendOpenAiRequestAsync(string prompt)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, _apiEndpoint);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _apiKey);

            var requestBody = new
            {
                model = _model,
                messages = new[]
                {
                    new { role = "system", content = "You are a senior cybersecurity analyst. Respond only with JSON." },
                    new { role = "user", content = prompt }
                },
                temperature = 0.1
            };

            request.Content = JsonContent.Create(requestBody);
            return await _httpClient.SendAsync(request);
        }

        private async Task<string> ExtractResponseTextAsync(HttpResponseMessage response)
        {
            var body = await response.Content.ReadAsStringAsync();

            if (IsOpenAiProvider())
            {
                try
                {
                    using var doc = JsonDocument.Parse(body);
                    if (doc.RootElement.TryGetProperty("choices", out var choices) &&
                        choices.ValueKind == JsonValueKind.Array &&
                        choices.GetArrayLength() > 0)
                    {
                        var message = choices[0].GetProperty("message");
                        if (message.TryGetProperty("content", out var contentElement))
                        {
                            if (contentElement.ValueKind == JsonValueKind.Array)
                            {
                                var combined = string.Join(Environment.NewLine,
                                    contentElement.EnumerateArray()
                                        .Select(part =>
                                        {
                                            if (part.ValueKind == JsonValueKind.Object && part.TryGetProperty("text", out var textElement))
                                            {
                                                return textElement.GetString();
                                            }
                                            return part.GetString();
                                        })
                                        .Where(s => !string.IsNullOrWhiteSpace(s)));

                                if (!string.IsNullOrWhiteSpace(combined))
                                {
                                    return combined;
                                }
                            }
                            else if (contentElement.ValueKind == JsonValueKind.String)
                            {
                                return contentElement.GetString() ?? body;
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _log.LogWarning(ex, "Failed to parse OpenAI response; falling back to raw payload.");
                }
            }

            return body;
        }

        private string BuildPrompt(object incidentData)
        {
            var incidentJson = JsonSerializer.Serialize(incidentData, new JsonSerializerOptions { WriteIndented = true });

            return $@"You are a senior cybersecurity analyst. Your task is to analyze a security alert from a host machine and provide a structured risk assessment. Do not include any preamble or explanation outside of the JSON structure.

Based on the following alert data, return a single JSON object with three fields:
1. 'risk_score': An integer from 1 (low) to 10 (critical).
2. 'summary': A concise, one-sentence summary of the threat in Turkish.
3. 'reasoning': A brief, step-by-step explanation of your analysis in Turkish.

Alert Data:
```json
{incidentJson}
```

Your JSON response:";
        }

        private LlmAnalysisResult? ParseLlmResponse(string llmOutput)
        {
            try
            {
                // The response from the LLM might be wrapped in markdown ```json ... ```
                var jsonStart = llmOutput.IndexOf('{');
                var jsonEnd = llmOutput.LastIndexOf('}');
                if (jsonStart == -1 || jsonEnd == -1)
                {
                    _log.LogWarning("LLM response did not contain a valid JSON object. Output: {output}", llmOutput);
                    return null;
                }

                var json = llmOutput.Substring(jsonStart, jsonEnd - jsonStart + 1);
                
                return JsonSerializer.Deserialize<LlmAnalysisResult>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "Failed to parse JSON response from LLM. Raw response: {response}", llmOutput);
                return null;
            }
        }

        private bool IsOpenAiProvider() =>
            string.Equals(_provider, "OpenAI", StringComparison.OrdinalIgnoreCase);
    }

    public class LlmAnalysisResult
    {
        public int RiskScore { get; set; }
        public string? Summary { get; set; }
        public string? Reasoning { get; set; }
    }
}
