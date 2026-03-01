// FILE: Networking/TcpProxy.cs - Enhanced version with better logging
using HyForce.Core;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace HyForce.Networking;

public class TcpProxy : IDisposable
{
    public bool IsRunning { get; private set; }
    public int TotalConnections { get; private set; }
    public int ActiveSessions => _sessions.Count;
    public int TcpSession { get; private set; }
    public string StatusMessage { get; private set; } = "Stopped";
    public string ServerIp { get; private set; } = "";
    public int ServerPort { get; private set; }
    public int ListenPort { get; private set; }

    public event PacketHandler? OnPacket;

    private readonly Data.TestLog _log;
    private TcpListener? _listener;
    private CancellationTokenSource? _cts;
    private readonly ConcurrentDictionary<string, TcpSession> _sessions = new();
    private uint _sequenceCounter;

    // NEW: Buffer for reassembling fragmented packets
    private readonly Dictionary<string, byte[]> _pendingData = new();

    public TcpProxy(Data.TestLog log)
    {
        _log = log;
    }

    public void Start(string listenIp, int listenPort, string serverIp, int serverPort)
    {
        if (IsRunning) return;

        try
        {
            _listener = new TcpListener(IPAddress.Parse(listenIp), listenPort);
            _listener.Start();
            _listener.Server.NoDelay = true; // Disable Nagle's algorithm for lower latency

            ServerIp = serverIp;
            ServerPort = serverPort;
            ListenPort = listenPort;
            IsRunning = true;
            StatusMessage = $"Listening {listenIp}:{listenPort} → {serverIp}:{serverPort}";

            _log.Info($"[TCP] Started on {listenIp}:{listenPort}", "TCP");
            _log.Info($"[TCP] Forwarding to {serverIp}:{serverPort}", "TCP");
            _log.Info($"[TCP] Waiting for Hytale connection...", "TCP");

            _cts = new CancellationTokenSource();
            Task.Run(() => AcceptLoop(_cts.Token));
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
            _log.Error($"[TCP] Start failed: {ex.Message}", "TCP");
        }
    }

    public void Stop()
    {
        if (!IsRunning) return;

        _cts?.Cancel();
        _listener?.Stop();

        foreach (var session in _sessions.Values)
        {
            try
            {
                session.Client.Close();
                session.Server?.Close();
            }
            catch { }
        }
        _sessions.Clear();
        _pendingData.Clear();

        IsRunning = false;
        StatusMessage = $"Stopped ({TotalConnections} total)";
        _log.Info("[TCP] Stopped", "TCP");
    }

    private async Task AcceptLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var client = await _listener!.AcceptTcpClientAsync(ct);
                var clientEp = client.Client.RemoteEndPoint?.ToString() ?? "unknown";

                // Configure client for better performance
                client.NoDelay = true;
                client.ReceiveBufferSize = 65536;
                client.SendBufferSize = 65536;

                TotalConnections++;
                _log.Info($"[TCP] Connection #{TotalConnections} from {clientEp}", "TCP");
                _log.Info($"[TCP] Hytale client connected - expecting RegistrySync", "TCP");

                var session = new TcpSession(client, ServerIp, ServerPort, _log);
                _sessions[clientEp] = session;

                _ = Task.Run(() => HandleSession(session, clientEp, ct), ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _log.Error($"[TCP] Accept error: {ex.Message}", "TCP");
            }
        }
    }

    private async Task HandleSession(TcpSession session, string key, CancellationToken ct)
    {
        try
        {
            await session.Run(async (data, direction) =>
            {
                // CRITICAL: Log ALL TCP traffic for debugging
                _log.Info($"[TCP] {direction} packet: {data.Length} bytes", "TCP");

                var packet = new CapturedPacket
                {
                    SequenceId = Interlocked.Increment(ref _sequenceCounter),
                    Timestamp = DateTime.Now,
                    Direction = direction,
                    RawBytes = data,
                    IsTcp = true,
                    Source = "TCP"
                };

                if (data.Length >= 2)
                {
                    packet.Opcode = (ushort)((data[0] << 8) | data[1]);
                    _log.Info($"[TCP] Opcode: 0x{packet.Opcode:X4}", "TCP");
                }

                // Special logging for RegistrySync range
                if (direction == PacketDirection.ServerToClient && packet.Opcode >= 0x18 && packet.Opcode <= 0x3F)
                {
                    _log.Success($"[TCP] REGISTRYSYNC DETECTED! Opcode: 0x{packet.Opcode:X2}, Size: {data.Length}", "Registry");
                }

                OnPacket?.Invoke(packet);
            }, ct);
        }
        finally
        {
            _sessions.TryRemove(key, out _);
            _log.Info($"[TCP] Session closed: {key}", "TCP");
        }
    }

    public void Dispose() => Stop();
}