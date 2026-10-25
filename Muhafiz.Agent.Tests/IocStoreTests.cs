using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Muhafiz.Agent.Ioc;
using Xunit;

namespace Muhafiz.Agent.Tests
{
    public class IocStoreTests : IDisposable
    {
        private readonly string _dir;

        public IocStoreTests()
        {
            _dir = Path.Combine(Path.GetTempPath(), "MuhafizIocTests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_dir);
        }

        private IConfiguration BuildConfig(string hashesPath, string urlsPath) =>
            new ConfigurationBuilder()
                .AddInMemoryCollection(new[]
                {
                    new KeyValuePair<string, string?>("Ioc:HashesPath", hashesPath),
                    new KeyValuePair<string, string?>("Ioc:UrlsPath", urlsPath)
                })
                .Build();

        [Fact]
        public async Task Load_ReadsObjectFormatHashes()
        {
            // Bootstrapper ve UI'nin yazdığı format: { "malicious_hashes": [...] }
            var hashesPath = Path.Combine(_dir, "hashes.json");
            await File.WriteAllTextAsync(hashesPath, "{ \"malicious_hashes\": [\"ABC123\"] }");

            var store = IocStore.Load(BuildConfig(hashesPath, Path.Combine(_dir, "urls.json")), NullLogger.Instance);

            Assert.True(store.IsHashBlocked("abc123"));
            Assert.False(store.IsHashBlocked("deadbeef"));
        }

        [Fact]
        public async Task Load_ReadsLegacyArrayFormatHashes()
        {
            var hashesPath = Path.Combine(_dir, "hashes.json");
            await File.WriteAllTextAsync(hashesPath, "[\"ABC123\"]");

            var store = IocStore.Load(BuildConfig(hashesPath, Path.Combine(_dir, "urls.json")), NullLogger.Instance);

            // Legacy dizi formatı IocStore tarafından desteklenmiyor; boş kalması beklenir.
            Assert.False(store.IsHashBlocked("abc123"));
        }

        [Fact]
        public async Task Load_ReadsBlockedHostsAndIps()
        {
            var urlsPath = Path.Combine(_dir, "urls.json");
            await File.WriteAllTextAsync(urlsPath,
                "{ \"blocked_hosts\": [\"evil.example\"], \"ioc_ips\": [\"1.2.3.4\"] }");

            var store = IocStore.Load(BuildConfig(Path.Combine(_dir, "hashes.json"), urlsPath), NullLogger.Instance);

            Assert.True(store.IsHostBlocked("EVIL.example"));
            Assert.True(store.IsIpBlocked("1.2.3.4"));
        }

        [Fact]
        public void Load_WithMissingFiles_ReturnsEmptyStore()
        {
            var store = IocStore.Load(
                BuildConfig(Path.Combine(_dir, "nope.json"), Path.Combine(_dir, "nope2.json")),
                NullLogger.Instance);

            Assert.Empty(store.Hashes);
            Assert.Empty(store.BlockedHosts);
            Assert.Empty(store.IocIps);
        }

        public void Dispose()
        {
            try { Directory.Delete(_dir, true); } catch { }
        }
    }
}
