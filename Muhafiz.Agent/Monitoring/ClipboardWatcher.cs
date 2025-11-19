using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Muhafiz.Agent.Response;

namespace Muhafiz.Agent.Monitoring
{
    public class ClipboardWatcher : BackgroundService
    {
        private readonly ILogger<ClipboardWatcher> _log;
        private readonly Func<EventWriter> _eventWriterFactory;
        private readonly bool _enabled;
        private readonly int _interval;
        private readonly List<Regex> _patterns = new();

        public ClipboardWatcher(ILogger<ClipboardWatcher> log, IConfiguration cfg, Func<EventWriter> eventWriterFactory)
        {
            _log = log;
            _eventWriterFactory = eventWriterFactory;

            _enabled = cfg.GetValue<bool>("Clipboard:Enabled", false);
            _interval = cfg.GetValue<int>("Clipboard:PollingIntervalSeconds", 2);
            var patternStrings = cfg.GetSection("Clipboard:Patterns").Get<string[]>() ?? Array.Empty<string>();

            foreach (var pattern in patternStrings)
            {
                try
                {
                    _patterns.Add(new Regex(pattern, RegexOptions.Compiled | RegexOptions.IgnoreCase));
                }
                catch (Exception ex)
                {
                    _log.LogWarning(ex, "Invalid regex pattern in clipboard configuration: {pattern}", pattern);
                }
            }
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            if (!_enabled || _patterns.Count == 0)
            {
                _log.LogInformation("ClipboardWatcher is disabled or has no patterns.");
                return;
            }

            _log.LogInformation("ClipboardWatcher started. Polling interval: {interval} seconds.", _interval);

            var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

            // The clipboard can only be reliably accessed from a thread in the Single-Threaded Apartment (STA) state.
            var staThread = new Thread(() =>
            {
                try
                {
                    STAThreadLoop(stoppingToken);
                    tcs.TrySetResult(true);
                }
                catch (OperationCanceledException)
                {
                    tcs.TrySetResult(true);
                }
                catch (Exception ex)
                {
                    _log.LogError(ex, "Unhandled exception in ClipboardWatcher STA thread.");
                    tcs.TrySetException(ex);
                }
            });

            staThread.SetApartmentState(ApartmentState.STA);
            staThread.Start();

            await tcs.Task;
            
            _log.LogInformation("ClipboardWatcher stopped.");
        }

        private void STAThreadLoop(CancellationToken stoppingToken)
        {
            string lastClipboardText = string.Empty;

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    var clipboardText = GetClipboardText();
                    if (!string.IsNullOrEmpty(clipboardText) && clipboardText != lastClipboardText)
                    {
                        lastClipboardText = clipboardText;
                        
                        foreach (var regex in _patterns)
                        {
                            if (regex.IsMatch(clipboardText))
                            {
                                _log.LogWarning("Malicious pattern detected in clipboard. Pattern: {regex}", regex.ToString());
                                
                                // Do not await this call in the STA thread to avoid blocking it.
                                // Fire and forget the event writing.
                                _ = WriteClipboardIncidentAsync(clipboardText, regex.ToString(), stoppingToken);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                     _log.LogDebug(ex, "Failed to check clipboard.");
                }

                // Wait for the interval or until cancellation is requested.
                stoppingToken.WaitHandle.WaitOne(_interval * 1000);
            }
        }

        private Task WriteClipboardIncidentAsync(string clipboardContent, string pattern, CancellationToken stoppingToken)
        {
            var incident = new EventWriter.Incident
            {
                Id = Guid.NewGuid().ToString("N"),
                OriginalPath = "clipboard",
                Sha256 = "N/A",
                Size = clipboardContent.Length,
                Reasons = new[] { $"CLIPBOARD_MATCH:{pattern}" }
            };

            var eventWriter = _eventWriterFactory();
            return eventWriter.WriteIncidentAsync(incident, stoppingToken);
        }

        private string GetClipboardText()
        {
            try
            {
                if (System.Windows.Forms.Clipboard.ContainsText())
                {
                    return System.Windows.Forms.Clipboard.GetText(System.Windows.Forms.TextDataFormat.UnicodeText);
                }
            }
            catch
            {
                // This can happen if the clipboard is busy or unavailable.
            }
            return string.Empty;
        }
    }
}
