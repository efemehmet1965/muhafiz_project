using System.Text.Json;
using Muhafiz.Agent.Analysis;
using Xunit;

namespace Muhafiz.Agent.Tests
{
    public class LlmAnalysisResultTests
    {
        [Fact]
        public void Deserialize_MapsSnakeCaseRiskScore()
        {
            const string json = """
                { "risk_score": 7, "summary": "Şüpheli dosya", "reasoning": "İmza eşleşmesi" }
                """;

            var result = JsonSerializer.Deserialize<LlmAnalysisResult>(
                json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

            Assert.NotNull(result);
            Assert.Equal(7, result!.RiskScore);
            Assert.Equal("Şüpheli dosya", result.Summary);
            Assert.Equal("İmza eşleşmesi", result.Reasoning);
        }

        [Fact]
        public void Serialize_UsesSnakeCaseRiskScore()
        {
            var json = JsonSerializer.Serialize(new LlmAnalysisResult { RiskScore = 9 });

            Assert.Contains("\"risk_score\":9", json);
        }
    }
}
