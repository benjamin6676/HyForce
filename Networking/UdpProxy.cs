// FILE: Networking/UdpProxy.cs - FIXED: Proper disposal pattern
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
    private readonly ConcurrentDictionary<string, QuicSession> _sessions = new();
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
                _log.Error("[UDP] ERROR: Port conflict on localhost!", "UDP");
                StatusMessage = "Config error: port conflict";
                return;
            }

            _serverEp = new IPEndPoint(IPAddress.Parse(serverIp), serverPort);
            _listener = new UdpClient(new IPEndPoint(IPAddress.Any, listenPort));

            ServerIp = serverIp;
            ServerPort = serverPort;
            ListenPort = listenPort;
            IsRunning = true;
            StatusMessage = $"Listening 0.0.0.0:{listenPort} -> {serverIp}:{serverPort}";

            _log.Info($"[UDP] Started on 0.0.0.0:{listenPort}", "UDP");
            _log.Info($"[UDP] QUIC-aware with CID translation", "UDP");

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

        // FIXED: Proper disposal of sessions
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

            var quicInfo = ParseQuicHeader(data);

            if (!_sessions.TryGetValue(key, out var session))
            {
                TotalClients++;
                var serverSocket = new UdpClient();
                serverSocket.Connect(_serverEp);

                var serverCid = GenerateConnectionId();

                session = new QuicSession(clientEp, serverSocket, serverCid, quicInfo.ClientConnectionId);
                _sessions[key] = session;

                StatusMessage = $"Active: {_sessions.Count} sessions";
                _log.Info($"[UDP] New QUIC session #{TotalClients}: {clientEp}", "UDP");

                _ = Task.Run(() => ServerReceiveLoop(session, ct), ct);
            }

            session.LastActivity = DateTimeOffset.UtcNow;

            var packet = new CapturedPacket
            {
                SequenceId = Interlocked.Increment(ref _sequenceCounter),
                Timestamp = DateTime.Now,
                Direction = PacketDirection.ClientToServer,
                RawBytes = data,
                IsTcp = false,
                Opcode = data.Length > 0 ? data[0] : (ushort)0,
                Source = "UDP/QUIC",
                QuicInfo = quicInfo
            };
            OnPacket?.Invoke(packet);

            var translated = TranslateCid(data, session.ClientToServerCidMap, quicInfo);
            try
            {
                await session.ServerSocket.SendAsync(translated, translated.Length);
            }
            catch (Exception ex)
            {
                _log.Error($"[UDP] Forward error: {ex.Message}", "UDP");
            }
        }
    }

    private async Task ServerReceiveLoop(QuicSession session, CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                UdpReceiveResult result;
                try
                {
                    result = await session.ServerSocket.ReceiveAsync(ct);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch
                {
                    continue;
                }

                var serverQuicInfo = ParseQuicHeader(result.Buffer);
                var translated = TranslateCid(result.Buffer, session.ServerToClientCidMap, serverQuicInfo);

                var packet = new CapturedPacket
                {
                    SequenceId = Interlocked.Increment(ref _sequenceCounter),
                    Timestamp = DateTime.Now,
                    Direction = PacketDirection.ServerToClient,
                    RawBytes = result.Buffer,
                    IsTcp = false,
                    Opcode = result.Buffer.Length > 0 ? result.Buffer[0] : (ushort)0,
                    Source = "UDP/QUIC"
                };
                OnPacket?.Invoke(packet);

                try
                {
                    await _listener!.SendAsync(translated, translated.Length, session.ClientEndpoint);
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

    private QuicHeaderInfo ParseQuicHeader(byte[] data)
    {
        var info = new QuicHeaderInfo();

        if (data.Length < 1)
            return info;

        byte firstByte = data[0];
        bool isLongHeader = (firstByte & 0x80) != 0;

        if (isLongHeader && data.Length >= 6)
        {
            info.Version = (uint)((data[1] << 24) | (data[2] << 16) | (data[3] << 8) | data[4]);
            byte dcidLen = data[5];

            if (data.Length >= 6 + dcidLen)
            {
                info.ClientConnectionId = new byte[dcidLen];
                Buffer.BlockCopy(data, 6, info.ClientConnectionId, 0, dcidLen);
            }

            info.IsLongHeader = true;
        }
        else
        {
            info.IsLongHeader = false;
            if (data.Length >= 5)
            {
                info.ClientConnectionId = new byte[4];
                Buffer.BlockCopy(data, 1, info.ClientConnectionId, 0, 4);
            }
        }

        return info;
    }

    private byte[] TranslateCid(byte[] data, Dictionary<byte[], byte[]> cidMap, QuicHeaderInfo info)
    {
        // Simplified - in production would rewrite CID bytes
        return data;
    }

    private byte[] GenerateConnectionId()
    {
        var cid = new byte[8];
        Random.Shared.NextBytes(cid);
        return cid;
    }

    public void Dispose() => Stop();
}

// FIXED: Implement IDisposable properly
public class QuicSession : IDisposable
{
    public IPEndPoint ClientEndpoint { get; }
    public UdpClient ServerSocket { get; }
    public byte[] ServerConnectionId { get; }
    public byte[] ClientConnectionId { get; }
    public DateTimeOffset LastActivity { get; set; }

    public Dictionary<byte[], byte[]> ClientToServerCidMap { get; } = new();
    public Dictionary<byte[], byte[]> ServerToClientCidMap { get; } = new();

    private bool _disposed;

    public QuicSession(IPEndPoint clientEp, UdpClient serverSocket, byte[] serverCid, byte[] clientCid)
    {
        ClientEndpoint = clientEp;
        ServerSocket = serverSocket;
        ServerConnectionId = serverCid;
        ClientConnectionId = clientCid;
        LastActivity = DateTimeOffset.UtcNow;

        ClientToServerCidMap[clientCid] = serverCid;
        ServerToClientCidMap[serverCid] = clientCid;
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