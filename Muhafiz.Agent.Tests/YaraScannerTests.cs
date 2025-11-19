using Xunit;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using System.IO;
using System.Threading.Tasks;
using System.Threading;

namespace Muhafiz.Agent.Pipelines.Tests
{
    public class YaraScannerTests
    {
        private const string YARA_CLI_PATH = @"C:\ProgramData\Muhafiz\yara\yara64.exe";
        private const string DUMMY_MALWARE_STRING = "MUHAFIZ_TEST_MALWARE";

        [Fact]
        public async Task ScanFileAsync_WhenFileContainsSignature_ReturnsHit()
        {
            // --- Arrange ---
            if (!File.Exists(YARA_CLI_PATH))
            {
                // If yara isn't installed in the expected path, skip the test.
                // This allows the test to pass in environments without a full setup.
                // An alternative would be to fail or use a dedicated message.
                return;
            }

            var tempDir = Path.Combine(Path.GetTempPath(), "MuhafizTests", Path.GetRandomFileName());
            var rulesDir = Path.Combine(tempDir, "rules");
            Directory.CreateDirectory(rulesDir);

            var infectedFilePath = Path.Combine(tempDir, "infected.txt");
            var cleanFilePath = Path.Combine(tempDir, "clean.txt");
            var ruleFilePath = Path.Combine(rulesDir, "test_rule.yar");

            // Create a dummy YARA rule
            await File.WriteAllTextAsync(ruleFilePath, $"rule IsInfected {{ strings: $a = \"{DUMMY_MALWARE_STRING}\" condition: $a }}");

            // Create an "infected" file and a clean file
            await File.WriteAllTextAsync(infectedFilePath, $"This is a test file containing the magic string: {DUMMY_MALWARE_STRING}");
            await File.WriteAllTextAsync(cleanFilePath, "This is a clean file with no magic strings.");

            var config = new ConfigurationBuilder()
                .AddInMemoryCollection(new[]
                {
                    new KeyValuePair<string, string?>("Yara:CliPath", YARA_CLI_PATH),
                    new KeyValuePair<string, string?>("Yara:RulesPath", rulesDir),
                })
                .Build();

            var logger = NullLogger.Instance;
            var scanner = new YaraScanner(config, logger);

            // --- Act ---
            var (infectedResult, _, _, _, _) = await scanner.ScanFileAsync(infectedFilePath, CancellationToken.None);
            var (cleanResult, _, _, _, _) = await scanner.ScanFileAsync(cleanFilePath, CancellationToken.None);


            // --- Assert ---
            Assert.True(infectedResult, "The infected file should be detected as a hit.");
            Assert.False(cleanResult, "The clean file should not be detected as a hit.");

            // --- Cleanup ---
            try
            {
                Directory.Delete(tempDir, true);
            }
            catch { /* Ignore cleanup errors in tests */ }
        }
    }
}
