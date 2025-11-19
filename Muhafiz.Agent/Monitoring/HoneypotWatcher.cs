using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Muhafiz.Agent.Response;

namespace Muhafiz.Agent.Monitoring
{
    public class HoneypotWatcher : BackgroundService
    {
        private readonly ILogger<HoneypotWatcher> _log;
        private readonly Func<EventWriter> _eventWriterFactory;
        private readonly bool _enabled;
        private readonly int[] _ports;

        public HoneypotWatcher(ILogger<HoneypotWatcher> log, IConfiguration cfg, Func<EventWriter> eventWriterFactory)
        {
            _log = log;
            _eventWriterFactory = eventWriterFactory;

            _enabled = cfg.GetValue<bool>("Honeypot:Enabled", false);
            _ports = cfg.GetSection("Honeypot:Ports").Get<int[]>() ?? Array.Empty<int>();
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            if (!_enabled || _ports.Length == 0)
            {
                _log.LogInformation("HoneypotWatcher is disabled or has no ports configured.");
                return;
            }

            var listeners = new List<TcpListener>();
            foreach (var port in _ports)
            {
                try
                {
                    var listener = new TcpListener(IPAddress.Any, port);
                    listener.Start();
                    listeners.Add(listener);
                    _log.LogInformation("Honeypot listening on port {port}", port);
                    _ = ListenForConnectionsAsync(listener, stoppingToken);
                }
                catch (Exception ex)
                {
                    _log.LogWarning(ex, "Failed to start honeypot listener on port {port}. It might be in use.", port);
                }
            }

            if (!listeners.Any())
            {
                _log.LogWarning("No honeypot listeners were started.");
                return;
            }

            await Task.Delay(Timeout.Infinite, stoppingToken);

            foreach (var listener in listeners)
            {
                listener.Stop();
            }
            _log.LogInformation("HoneypotWatcher stopped.");
        }

        private async Task ListenForConnectionsAsync(TcpListener listener, CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    var client = await listener.AcceptTcpClientAsync(stoppingToken);
                    var remoteEndpoint = client.Client.RemoteEndPoint as IPEndPoint;
                    var localEndpoint = client.Client.LocalEndPoint as IPEndPoint;
                    _log.LogWarning("Honeypot HIT on port {port} from {ip}", localEndpoint?.Port, remoteEndpoint?.Address);

                    // Find the offending process
                    var process = FindProcessForConnection(localEndpoint, remoteEndpoint);
                    if (process != null)
                    {
                        _log.LogCritical("Honeypot connection from process: {processName} (PID: {pid}) Path: {path}",
                            process.ProcessName, process.Id, process.MainModule?.FileName);

                        // Fire and forget the incident report
                        _ = WriteHoneypotIncidentAsync(process, localEndpoint?.Port ?? 0, remoteEndpoint, stoppingToken);
                    }
                    else
                    {
                        _log.LogError("Could not identify process for honeypot connection to port {port}", localEndpoint?.Port);
                    }

                    client.Close();
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _log.LogError(ex, "Error in honeypot listener loop.");
                    await Task.Delay(1000, stoppingToken); // Avoid tight loop on error
                }
            }
        }

        private Process? FindProcessForConnection(IPEndPoint? local, IPEndPoint? remote)
        {
            if (local == null || remote == null) return null;

            try
            {
                var tcpTable = ManagedIpHelper.GetExtendedTcpTable(true);
                foreach (var row in tcpTable)
                {
                    if (row.LocalEndPoint.Port == local.Port &&
                        row.RemoteEndPoint.Port == remote.Port &&
                        row.RemoteEndPoint.Address.Equals(remote.Address))
                    {
                        return Process.GetProcessById(row.ProcessId);
                    }
                }
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "Failed to find process for TCP connection.");
            }
            return null;
        }
        
        private Task WriteHoneypotIncidentAsync(Process process, int port, IPEndPoint? remote, CancellationToken stoppingToken)
        {
            var incident = new EventWriter.Incident
            {
                Id = Guid.NewGuid().ToString("N"),
                OriginalPath = process.MainModule?.FileName ?? process.ProcessName,
                Sha256 = "N/A", // We can try to hash the file later
                Size = 0,
                Reasons = new[] { $"HONEYPOT_HIT:PORT_{port}" },
                Payload = $"Connection from {remote?.Address}:{remote?.Port}"
            };

            var eventWriter = _eventWriterFactory();
            return eventWriter.WriteIncidentAsync(incident, stoppingToken);
        }
    }

    // Helper class for P/Invoke of GetExtendedTcpTable
    public static class ManagedIpHelper
    {
        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, TCP_TABLE_CLASS TableClass, uint Reserved);

        public static List<MIB_TCPROW_OWNER_PID> GetExtendedTcpTable(bool order)
        {
            var table = new List<MIB_TCPROW_OWNER_PID>();
            int AF_INET = 2; // IP v4
            int buffSize = 0;

            GetExtendedTcpTable(IntPtr.Zero, ref buffSize, order, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
            IntPtr buffTable = Marshal.AllocHGlobal(buffSize);

            try
            {
                if (GetExtendedTcpTable(buffTable, ref buffSize, order, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0) == 0)
                {
                    int rowCount = Marshal.ReadInt32(buffTable);
                    IntPtr rowPtr = IntPtr.Add(buffTable, sizeof(int));
                    for (int i = 0; i < rowCount; i++)
                    {
                        var tcpRow = (MIB_TCPROW_OWNER_PID)Marshal.PtrToStructure(rowPtr, typeof(MIB_TCPROW_OWNER_PID));
                        table.Add(tcpRow);
                        rowPtr = IntPtr.Add(rowPtr, Marshal.SizeOf(tcpRow));
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffTable);
            }
            return table;
        }
    }

    public enum TCP_TABLE_CLASS
    {
        TCP_TABLE_BASIC_LISTENER,
        TCP_TABLE_BASIC_CONNECTIONS,
        TCP_TABLE_BASIC_ALL,
        TCP_TABLE_OWNER_PID_LISTENER,
        TCP_TABLE_OWNER_PID_CONNECTIONS,
        TCP_TABLE_OWNER_PID_ALL,
        TCP_TABLE_OWNER_MODULE_LISTENER,
        TCP_TABLE_OWNER_MODULE_CONNECTIONS,
        TCP_TABLE_OWNER_MODULE_ALL
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] localPort;
        public uint remoteAddr;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] remotePort;
        public int owningPid;

        public IPEndPoint LocalEndPoint => new IPEndPoint(localAddr, (ushort)((localPort[0] << 8) + localPort[1]));
        public IPEndPoint RemoteEndPoint => new IPEndPoint(remoteAddr, (ushort)((remotePort[0] << 8) + remotePort[1]));
        public int ProcessId => owningPid;
    }
}
