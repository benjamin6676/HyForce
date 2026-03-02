// FILE: Networking/UdpProxy.cs - FIXED: Proper QUIC transparent proxy without packet corruption
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

    // CRITICAL FIX: Separate socket for server communication per client
    // CRITICAL FIX: Don't modify packet contents - forward exactly as received

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

            // CRITICAL FIX: Create socket with proper configuration for transparent proxying
            _listener = new UdpClient(AddressFamily.InterNetwork);

            // Enable address reuse
            _listener.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);

            // CRITICAL FIX: Don't set exclusive address use (allows multiple clients)
            _listener.Client.ExclusiveAddressUse = false;

            // Increase buffer sizes
            _listener.Client.ReceiveBufferSize = 65536;
            _listener.Client.SendBufferSize = 65536;

            // CRITICAL FIX: Bind to specific endpoint
            _listener.Client.Bind(new IPEndPoint(IPAddress.Parse(listenIp), listenPort));

            ServerIp = serverIp;
            ServerPort = serverPort;
            ListenPort = listenPort;
            IsRunning = true;
            StatusMessage = $"Listening {listenIp}:{listenPort} -> {serverIp}:{serverPort}";

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
            catch (ObjectDisposedException)
            {
                break;
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

            // CRITICAL FIX: Get or create session for EVERY client - no filtering
            if (!_sessions.TryGetValue(key, out var session))
            {
                TotalClients++;

                // CRITICAL FIX: Create new socket for this client with proper settings
                var serverSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                serverSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                serverSocket.ReceiveBufferSize = 65536;
                serverSocket.SendBufferSize = 65536;

                // CRITICAL FIX: Bind to any available port for outbound
                serverSocket.Bind(new IPEndPoint(IPAddress.Any, 0));

                // Connect to target server
                serverSocket.Connect(_serverEp);

                session = new UdpSession(clientEp, serverSocket);
                _sessions[key] = session;

                StatusMessage = $"Active: {_sessions.Count} sessions";
                _log.Info($"[UDP] New session #{TotalClients}: {clientEp} -> {_serverEp}", "UDP");

                // Start server receive loop for this session
                _ = Task.Run(() => ServerReceiveLoop(session, ct), ct);
            }

            session.LastActivity = DateTimeOffset.UtcNow;

            // Log packet (non-blocking) - but DON'T modify the data
            try
            {
                var packet = new CapturedPacket
                {
                    SequenceId = Interlocked.Increment(ref _sequenceCounter),
                    Timestamp = DateTime.Now,
                    Direction = PacketDirection.ClientToServer,
                    RawBytes = data.ToArray(), // Make a copy for logging
                    IsTcp = false,
                    Opcode = 0, // QUIC doesn't have opcodes in traditional sense
                    Source = "UDP",
                    QuicInfo = TryParseQuicInfo(data)
                };

                OnPacket?.Invoke(packet);
            }
            catch (Exception ex)
            {
                _log.Error($"[UDP] Logging error: {ex.Message}", "UDP");
            }

            // CRITICAL FIX: Forward packet immediately WITHOUT ANY MODIFICATION
            try
            {
                // Use the connected socket for proper source address handling
                await session.ServerSocket.SendAsync(data, SocketFlags.None, ct);
            }
            catch (Exception ex)
            {
                _log.Error($"[UDP] Forward error: {ex.Message}", "UDP");
                // Remove dead session
                _sessions.TryRemove(key, out _);
                session.Dispose();
            }
        }
    }

    private async Task ServerReceiveLoop(UdpSession session, CancellationToken ct)
    {
        var buffer = new byte[65536];

        try
        {
            while (!ct.IsCancellationRequested)
            {
                int received;
                try
                {
                    received = await session.ServerSocket.ReceiveAsync(new ArraySegment<byte>(buffer), SocketFlags.None, ct);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
                catch
                {
                    // Socket error, session probably dead
                    break;
                }

                if (received == 0) continue;

                // CRITICAL FIX: Copy received data exactly as-is
                var serverData = new byte[received];
                Buffer.BlockCopy(buffer, 0, serverData, 0, received);

                // Log packet (non-blocking) - but DON'T modify the data
                try
                {
                    var packet = new CapturedPacket
                    {
                        SequenceId = Interlocked.Increment(ref _sequenceCounter),
                        Timestamp = DateTime.Now,
                        Direction = PacketDirection.ServerToClient,
                        RawBytes = serverData.ToArray(), // Make a copy for logging
                        IsTcp = false,
                        Opcode = 0,
                        Source = "UDP",
                        QuicInfo = TryParseQuicInfo(serverData)
                    };
                    OnPacket?.Invoke(packet);
                }
                catch { }

                // CRITICAL FIX: Send back to client WITHOUT ANY MODIFICATION
                try
                {
                    await _listener!.SendAsync(serverData, serverData.Length, session.ClientEndpoint);
                }
                catch (Exception ex)
                {
                    _log.Error($"[UDP] S->C error: {ex.Message}", "UDP");
                    break;
                }
            }
        }
        catch (Exception ex)
        {
            _log.Error($"[UDP] Server loop error: {ex.Message}", "UDP");
        }
        finally
        {
            // Clean up session when loop exits
            var key = session.ClientEndpoint.ToString();
            _sessions.TryRemove(key, out _);
            session.Dispose();
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
            else
            {
                // Short header
                int pnLen = (firstByte & 0x03) + 1;
                info.PacketNumberLength = pnLen;
            }

            return info;
        }
        catch { return null; }
    }

    public void Dispose() => Stop();
}

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