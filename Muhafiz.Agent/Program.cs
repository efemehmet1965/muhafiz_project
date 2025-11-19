using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System.IO;

using Muhafiz.Agent;               // Worker
using Muhafiz.Agent.Monitoring;    // CanaryWatcher
using Muhafiz.Agent.Analysis;      // SandboxOrchestrator
using Muhafiz.Agent.Response;      // EventWriter
using Muhafiz.Agent.Pipelines;     // YaraScanner
using Muhafiz.Agent.Setup;

// --- Enforce launch only via WPF UI ---
// UI writes a one-time token to %PROGRAMDATA%\Muhafiz\ui_start.token and starts the agent
// with "--ui-token <token>". If validation fails, exit immediately.
try
{
    var tokenArgIdx = Array.IndexOf(args, "--ui-token");
    if (tokenArgIdx < 0 || tokenArgIdx == args.Length - 1)
    {
        Console.Error.WriteLine("Muhafiz.Agent can only be started from the WPF UI.");
        return;
    }

    var tokenProvided = args[tokenArgIdx + 1];
    var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
    var flagDir = Path.Combine(programData, "Muhafiz");
    var flagPath = Path.Combine(flagDir, "ui_start.token");

    if (!File.Exists(flagPath)) { Console.Error.WriteLine("UI token not found."); return; }

    var fileText = File.ReadAllText(flagPath).Trim();
    var age = DateTime.UtcNow - File.GetLastWriteTimeUtc(flagPath);
    var ok = !string.IsNullOrWhiteSpace(fileText)
             && string.Equals(fileText, tokenProvided, StringComparison.OrdinalIgnoreCase)
             && age < TimeSpan.FromMinutes(2);

    try { File.Delete(flagPath); } catch { }
    if (!ok) { Console.Error.WriteLine("Invalid or expired UI token."); return; }
}
catch { return; }

var bootstrap = EnvironmentBootstrapper.Bootstrap(AppContext.BaseDirectory);

var builder = Host.CreateApplicationBuilder(args);

// --- Yapılandırma Kaynaklarını Temizle ve Sadece Merkezi Dosyayı Yükle ---
builder.Configuration.Sources.Clear();
builder.Configuration.AddJsonFile(bootstrap.SettingsPath, optional: false, reloadOnChange: true);
builder.Configuration.AddEnvironmentVariables();
builder.Configuration.AddCommandLine(args);


// --- Bitti ---

// Windows Service olarak isim
// builder.Services.AddWindowsService(o => o.ServiceName = "Muhafiz.Agent");

// EventWriter + factory (CanaryWatcher Func<EventWriter> istiyor)
builder.Services.AddSingleton<EventWriter>();
builder.Services.AddSingleton<Func<EventWriter>>(sp => () => sp.GetRequiredService<EventWriter>());

// Response modülleri
builder.Services.AddSingleton<EgressBlocker>();

// CanaryWatcher ctor'u düz ILogger alıyorsa köprü (ILogger<CanaryWatcher> -> ILogger)
builder.Services.AddSingleton<ILogger>(sp => sp.GetRequiredService<ILogger<CanaryWatcher>>());

// Orchestrator (artık concrete backend istemiyor)
builder.Services.AddSingleton<SandboxOrchestrator>();

// YARA scanner (CLI üzerinden)
builder.Services.AddSingleton<YaraScanner>();

// LLM Analyser
builder.Services.AddSingleton<LlmAnalyser>();

// Canary + Worker
builder.Services.AddSingleton<CanaryWatcher>();
builder.Services.AddHostedService<Worker>();
builder.Services.AddHostedService<ClipboardWatcher>();
builder.Services.AddHostedService<HoneypotWatcher>();

var app = builder.Build();
await app.RunAsync();

