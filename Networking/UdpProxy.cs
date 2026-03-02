// FILE: Networking/UdpProxy.cs - COMPLETELY TRANSPARENT PROXY
using HyForce.Core;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace HyForce.Networking;

public class UdpProxy : IDisposable
{
    public bool IsRunning { get; private set; }
    public int TotalClients { get; private set; }
    public int ActiveSessions => _sessions.Count;
    public string StatusMessage { get; private set; } = "Stopped";

    public string ServerIp { get; private set; } = "";
    public int ServerPort { get; private set; }
    public int ListenPort { get; private set; }

    public event PacketReceivedHandler? OnPacket;

    private readonly Data.TestLog _log;
    private UdpClient? _listener;
    private CancellationTokenSource? _cts;
    private readonly ConcurrentDictionary<string, UdpSession> _sessions = new();
    private IPEndPoint _serverEp = new(IPAddress.Loopback, 0);
    private uint _sequenceCounter;

    public UdpProxy(Data.TestLog log)
    {
        _log = log;
    }

    public void Start(string listenIp, int listenPort, string serverIp, int serverPort)
    {
        if (IsRunning) return;

        try
        {
            if (listenPort == serverPort && serverIp == "127.0.0.1")
            {
                _log.Error("[UDP] Port conflict on localhost!", "UDP");
                StatusMessage = "Config error: port conflict";
                return;
            }

            _serverEp = new IPEndPoint(IPAddress.Parse(serverIp), serverPort);

            // FIXED: Use dual-stack socket for better compatibility
            _listener = new UdpClient(AddressFamily.InterNetwork);
            _listener.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            _listener.Client.Bind(new IPEndPoint(IPAddress.Any, listenPort));

            ServerIp = serverIp;
            ServerPort = serverPort;
            ListenPort = listenPort;
            IsRunning = true;
            StatusMessage = $"Listening *:{listenPort} -> {serverIp}:{serverPort}";

            _log.Info($"[UDP] Transparent proxy started on port {listenPort}", "UDP");
            _log.Info($"[UDP] Forwarding to {serverIp}:{serverPort}", "UDP");

            _cts = new CancellationTokenSource();
            Task.Run(() => ReceiveLoop(_cts.Token));
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
            _log.Error($"[UDP] Start failed: {ex.Message}", "UDP");
        }
    }

    public void Stop()
    {
        if (!IsRunning) return;

        _cts?.Cancel();
        _listener?.Close();
        _listener = null;

        foreach (var session in _sessions.Values)
        {
            session.Dispose();
        }
        _sessions.Clear();

        IsRunning = false;
        StatusMessage = $"Stopped ({TotalClients} clients)";
        _log.Info("[UDP] Stopped", "UDP");
    }

    private async Task ReceiveLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            UdpReceiveResult result;
            try
            {
                result = await _listener!.ReceiveAsync(ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset)
            {
                continue;
            }
            catch (Exception ex)
            {
                if (!ct.IsCancellationRequested)
                    _log.Error($"[UDP] Receive error: {ex.Message}", "UDP");
                break;
            }

            var clientEp = result.RemoteEndPoint;
            var key = clientEp.ToString();
            var data = result.Buffer;

            if (data.Length == 0) continue;

            // Get or create session - COMPLETELY PASS-THROUGH
            if (!_sessions.TryGetValue(key, out var session))
            {
                TotalClients++;

                // Create server socket
                var serverSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                serverSocket.Connect(_serverEp);

                session = new UdpSession(clientEp, serverSocket);
                _sessions[key] = session;

                StatusMessage = $"Active: {_sessions.Count} sessions";
                _log.Info($"[UDP] New session #{TotalClients}: {clientEp} -> {_serverEp}", "UDP");

                _ = Task.Run(() => ServerReceiveLoop(session, ct), ct);
            }

            session.LastActivity = DateTimeOffset.UtcNow;

            // Log packet (copy for analysis, don't modify original)
            try
            {
                var packet = new CapturedPacket
                {
                    SequenceId = Interlocked.Increment(ref _sequenceCounter),
                    Timestamp = DateTime.Now,
                    Direction = PacketDirection.ClientToServer,
                    RawBytes = data.ToArray(), // COPY for logging
                    IsTcp = false,
                    Opcode = data.Length > 0 ? data[0] : (ushort)0,
                    Source = "UDP",
                    QuicInfo = TryParseQuicInfo(data)
                };
                OnPacket?.Invoke(packet);
            }
            catch (Exception ex)
            {
                _log.Error($"[UDP] Logging error: {ex.Message}", "UDP");
            }

            // FIXED: Send EXACT bytes without modification
            try
            {
                await session.ServerSocket.SendAsync(data, SocketFlags.None, ct);
            }
            catch (Exception ex)
            {
                _log.Error($"[UDP] Forward error: {ex.Message}", "UDP");
            }
        }
    }

    private async Task ServerReceiveLoop(UdpSession session, CancellationToken ct)
    {
        try
        {
            var buffer = new byte[65536];

            while (!ct.IsCancellationRequested)
            {
                int received;
                try
                {
                    received = await session.ServerSocket.ReceiveAsync(buffer, SocketFlags.None, ct);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch
                {
                    continue;
                }

                if (received == 0) continue;

                // Extract received data
                var serverData = new byte[received];
                Buffer.BlockCopy(buffer, 0, serverData, 0, received);

                // Log server response (copy for analysis)
                try
                {
                    var packet = new CapturedPacket
                    {
                        SequenceId = Interlocked.Increment(ref _sequenceCounter),
                        Timestamp = DateTime.Now,
                        Direction = PacketDirection.ServerToClient,
                        RawBytes = serverData.ToArray(),
                        IsTcp = false,
                        Opcode = serverData.Length > 0 ? serverData[0] : (ushort)0,
                        Source = "UDP",
                        QuicInfo = TryParseQuicInfo(serverData)
                    };
                    OnPacket?.Invoke(packet);
                }
                catch { }

                // FIXED: Send back to client EXACTLY as received
                try
                {
                    await _listener!.SendAsync(serverData, serverData.Length, session.ClientEndpoint);
                }
                catch (Exception ex)
                {
                    _log.Error($"[UDP] S->C error: {ex.Message}", "UDP");
                }
            }
        }
        catch (Exception ex)
        {
            _log.Error($"[UDP] Server loop error: {ex.Message}", "UDP");
        }
    }

    private QuicHeaderInfo? TryParseQuicInfo(byte[] data)
    {
        try
        {
            if (data.Length < 1) return null;

            var info = new QuicHeaderInfo();
            byte firstByte = data[0];
            bool isLongHeader = (firstByte & 0x80) != 0;
            info.IsLongHeader = isLongHeader;

            if (isLongHeader && data.Length >= 6)
            {
                info.Version = (uint)((data[1] << 24) | (data[2] << 16) | (data[3] << 8) | data[4]);
                byte dcidLen = data[5];
                if (data.Length >= 6 + dcidLen && dcidLen <= 20)
                {
                    info.ClientConnectionId = new byte[dcidLen];
                    Buffer.BlockCopy(data, 6, info.ClientConnectionId, 0, dcidLen);
                }
            }
            return info;
        }
        catch { return null; }
    }

    public void Dispose() => Stop();
}

// Simplified session - no CID translation
public class UdpSession : IDisposable
{
    public IPEndPoint ClientEndpoint { get; }
    public Socket ServerSocket { get; }
    public DateTimeOffset LastActivity { get; set; }

    private bool _disposed;

    public UdpSession(IPEndPoint clientEp, Socket serverSocket)
    {
        ClientEndpoint = clientEp;
        ServerSocket = serverSocket;
        LastActivity = DateTimeOffset.UtcNow;
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            try
            {
                ServerSocket?.Close();
                ServerSocket?.Dispose();
            }
            catch { }
            _disposed = true;
        }
    }
}