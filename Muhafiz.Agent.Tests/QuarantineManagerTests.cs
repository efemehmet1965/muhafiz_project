using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Muhafiz.Agent.Response;
using Xunit;

namespace Muhafiz.Agent.Tests
{
    public class QuarantineManagerTests : IDisposable
    {
        private readonly string _root;
        private readonly string _sourceDir;

        public QuarantineManagerTests()
        {
            var baseDir = Path.Combine(Path.GetTempPath(), "MuhafizQuarantineTests", Guid.NewGuid().ToString("N"));
            _root = Path.Combine(baseDir, "Q");
            _sourceDir = Path.Combine(baseDir, "src");
            Directory.CreateDirectory(_sourceDir);
        }

        private QuarantineManager CreateManager() =>
            new(
                new ConfigurationBuilder()
                    .AddInMemoryCollection(new[]
                    {
                        new KeyValuePair<string, string?>("Quarantine:Root", _root)
                    })
                    .Build(),
                NullLogger.Instance);

        [Fact]
        public async Task QuarantineAsync_MovesFileAndWritesMetadata()
        {
            var source = Path.Combine(_sourceDir, "malware.exe");
            await File.WriteAllTextAsync(source, "MZ fake payload");

            var manager = CreateManager();
            var target = await manager.QuarantineAsync(source, "abc123", new[] { "IOC_HASH" }, CancellationToken.None);

            Assert.NotNull(target);
            Assert.False(File.Exists(source));
            Assert.True(File.Exists(target));

            var meta = target + ".meta.json";
            Assert.True(File.Exists(meta));

            using var doc = JsonDocument.Parse(await File.ReadAllTextAsync(meta));
            Assert.Equal("abc123", doc.RootElement.GetProperty("Sha256").GetString());
            Assert.Equal(source, doc.RootElement.GetProperty("OriginalPath").GetString());
        }

        [Fact]
        public async Task QuarantineAsync_MissingFile_ReturnsNull()
        {
            var manager = CreateManager();

            var target = await manager.QuarantineAsync(
                Path.Combine(_sourceDir, "yok.exe"), "abc", Array.Empty<string>(), CancellationToken.None);

            Assert.Null(target);
        }

        public void Dispose()
        {
            try { Directory.Delete(Path.GetDirectoryName(_root)!, true); } catch { }
        }
    }
}
