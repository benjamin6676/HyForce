// FILE: Networking/UdpProxy.cs - FIXED: Proper QUIC transparent proxy without handshake corruption
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

    // FIXED: Use ConcurrentDictionary for thread-safe session tracking
    private readonly ConcurrentDictionary<string, UdpSession> _sessions = new();
    private IPEndPoint _serverEp = new(IPAddress.Loopback, 0);
    private uint _sequenceCounter;

    // FIXED: Single shared server socket for all clients (preserves QUIC path)
    private UdpClient? _sharedServerSocket;

    // CRITICAL FIX: Batch logging to prevent thread pool exhaustion
    private readonly ConcurrentQueue<CapturedPacket> _logQueue = new();
    private System.Threading.Timer? _logBatchTimer;

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

            // FIXED: Create listener with proper configuration
            _listener = new UdpClient(AddressFamily.InterNetwork);
            _listener.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            _listener.Client.ExclusiveAddressUse = false;
            _listener.Client.ReceiveBufferSize = 65536;
            _listener.Client.SendBufferSize = 65536;
            _listener.Client.Bind(new IPEndPoint(IPAddress.Parse(listenIp), listenPort));

            // FIXED: Create single shared server socket
            _sharedServerSocket = new UdpClient(AddressFamily.InterNetwork);
            _sharedServerSocket.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            _sharedServerSocket.Client.ReceiveBufferSize = 65536;
            _sharedServerSocket.Client.SendBufferSize = 65536;
            _sharedServerSocket.Connect(_serverEp);

            ServerIp = serverIp;
            ServerPort = serverPort;
            ListenPort = listenPort;
            IsRunning = true;
            StatusMessage = $"Listening {listenIp}:{listenPort} -> {serverIp}:{serverPort}";

            _log.Info($"[UDP] QUIC-transparent proxy started on port {listenPort}", "UDP");
            _log.Info($"[UDP] Forwarding to {serverIp}:{serverPort}", "UDP");

            _cts = new CancellationTokenSource();

            // CRITICAL FIX: Start batch logging timer
            StartBatchLogging();

            // FIXED: Start separate loops for client->server and server->client
            Task.Run(() => ClientToServerLoop(_cts.Token));
            Task.Run(() => ServerToClientLoop(_cts.Token));
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

        _logBatchTimer?.Dispose();
        _cts?.Cancel();
        _listener?.Close();
        _sharedServerSocket?.Close();
        _listener = null;
        _sharedServerSocket = null;

        foreach (var session in _sessions.Values)
        {
            session.Dispose();
        }
        _sessions.Clear();
        _logQueue.Clear();

        IsRunning = false;
        StatusMessage = $"Stopped ({TotalClients} clients)";
        _log.Info("[UDP] Stopped", "UDP");
    }

    // CRITICAL FIX: Batch logging to prevent thread pool exhaustion
    private void StartBatchLogging()
    {
        _logBatchTimer = new System.Threading.Timer(_ =>
        {
            ProcessLogBatch();
        }, null, TimeSpan.FromMilliseconds(100), TimeSpan.FromMilliseconds(100));
    }

    private void ProcessLogBatch()
    {
        const int MAX_BATCH = 50;
        int count = 0;

        while (_logQueue.TryDequeue(out var packet) && count < MAX_BATCH)
        {
            try
            {
                OnPacket?.Invoke(packet);
            }
            catch (Exception ex)
            {
                _log.Error($"[UDP] Log error: {ex.Message}", "UDP");
            }
            count++;
        }
    }

    private void LogPacket(CapturedPacket packet)
    {
        // Just enqueue, don't process immediately - prevents UI freeze
        _logQueue.Enqueue(packet);
    }

    // FIXED: Dedicated client->server loop with immediate forwarding - NO Task.Run spam
    private async Task ClientToServerLoop(CancellationToken ct)
    {
        _log.Info("[UDP] Client->Server loop started", "UDP");

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

            // FIXED: Get or create session (lightweight, no socket creation)
            if (!_sessions.TryGetValue(key, out var session))
            {
                TotalClients++;
                session = new UdpSession(clientEp);
                _sessions[key] = session;
                StatusMessage = $"Active: {_sessions.Count} sessions";
                _log.Info($"[UDP] New session #{TotalClients}: {clientEp}", "UDP");
            }

            session.LastActivity = DateTimeOffset.UtcNow;

            // CRITICAL FIX: Forward IMMEDIATELY - no Task.Run, no blocking
            try
            {
                await _sharedServerSocket!.SendAsync(data, data.Length);
            }
            catch (Exception ex)
            {
                _log.Error($"[UDP] Forward C->S error: {ex.Message}", "UDP");
            }

            // CRITICAL FIX: Batch log instead of Task.Run
            LogPacket(new CapturedPacket
            {
                SequenceId = Interlocked.Increment(ref _sequenceCounter),
                Timestamp = DateTime.Now,
                Direction = PacketDirection.ClientToServer,
                RawBytes = data.ToArray(),
                IsTcp = false,
                Opcode = 0,
                Source = "UDP",
                QuicInfo = TryParseQuicInfo(data)
            });
        }
    }

    // FIXED: Dedicated server->client loop with immediate forwarding
    private async Task ServerToClientLoop(CancellationToken ct)
    {
        _log.Info("[UDP] Server->Client loop started", "UDP");
        var buffer = new byte[65536];

        while (!ct.IsCancellationRequested)
        {
            try
            {
                // FIXED: Use Socket.ReceiveFromAsync and get result properly
                var remoteEp = new IPEndPoint(IPAddress.Any, 0) as EndPoint;

                var result = await _sharedServerSocket!.Client.ReceiveFromAsync(
                    new ArraySegment<byte>(buffer),
                    SocketFlags.None,
                    remoteEp);

                int received = result.ReceivedBytes;

                if (received == 0) continue;

                // Copy data immediately
                var serverData = new byte[received];
                Buffer.BlockCopy(buffer, 0, serverData, 0, received);

                // CRITICAL FIX: Forward to ALL active clients (QUIC handles demux via CIDs)
                var clients = _sessions.Values.ToList();

                foreach (var session in clients)
                {
                    try
                    {
                        await _listener!.SendAsync(serverData, serverData.Length, session.ClientEndpoint);
                    }
                    catch { /* Ignore send errors to disconnected clients */ }
                }

                // CRITICAL FIX: Batch log instead of Task.Run
                LogPacket(new CapturedPacket
                {
                    SequenceId = Interlocked.Increment(ref _sequenceCounter),
                    Timestamp = DateTime.Now,
                    Direction = PacketDirection.ServerToClient,
                    RawBytes = serverData.ToArray(),
                    IsTcp = false,
                    Opcode = 0,
                    Source = "UDP",
                    QuicInfo = TryParseQuicInfo(serverData)
                });
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (Exception ex)
            {
                if (!ct.IsCancellationRequested)
                    _log.Error($"[UDP] S->C error: {ex.Message}", "UDP");
            }
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
    public DateTimeOffset LastActivity { get; set; }

    private bool _disposed;

    // FIXED: Lightweight session - no per-client sockets
    public UdpSession(IPEndPoint clientEp)
    {
        ClientEndpoint = clientEp;
        LastActivity = DateTimeOffset.UtcNow;
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _disposed = true;
        }
    }
}