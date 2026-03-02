// FILE: Networking/UdpProxy.cs - FIXED: Proper QUIC Handshake Handling
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

    // FIXED: Track handshake state per session
    private readonly ConcurrentDictionary<string, bool> _handshakeComplete = new();

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
            _log.Info($"[UDP] QUIC handshake-preserving proxy", "UDP");

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
        _handshakeComplete.Clear();

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
            bool isLongHeader = quicInfo.IsLongHeader;

            // FIXED: Create or get session
            if (!_sessions.TryGetValue(key, out var session))
            {
                TotalClients++;

                // FIXED: Create server socket but DON'T modify client CID during handshake
                var serverSocket = new UdpClient();
                serverSocket.Connect(_serverEp);

                // FIXED: Store original client CID, don't generate new one yet
                session = new QuicSession(clientEp, serverSocket, quicInfo.ClientConnectionId);
                _sessions[key] = session;
                _handshakeComplete[key] = false; // Track handshake state

                StatusMessage = $"Active: {_sessions.Count} sessions";
                _log.Info($"[UDP] New QUIC session #{TotalClients}: {clientEp}", "UDP");
                _log.Info($"[UDP] Client CID: {BitConverter.ToString(quicInfo.ClientConnectionId)}", "UDP");

                _ = Task.Run(() => ServerReceiveLoop(session, key, ct), ct);
            }

            session.LastActivity = DateTimeOffset.UtcNow;

            // Log the packet
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

            // FIXED: Determine if we should translate CIDs
            bool handshakeDone = _handshakeComplete.TryGetValue(key, out bool complete) && complete;

            byte[] dataToSend;
            if (isLongHeader && !handshakeDone)
            {
                // FIXED: During handshake, preserve original CIDs - only translate DCID for routing if needed
                // But keep the original client CID so server can respond correctly
                dataToSend = data; // Pass through unchanged during handshake!
            }
            else
            {
                // Post-handshake: can translate CIDs if needed
                dataToSend = data;
            }

            try
            {
                await session.ServerSocket.SendAsync(dataToSend, dataToSend.Length);
            }
            catch (Exception ex)
            {
                _log.Error($"[UDP] Forward error: {ex.Message}", "UDP");
            }
        }
    }

    private async Task ServerReceiveLoop(QuicSession session, string sessionKey, CancellationToken ct)
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

                var serverData = result.Buffer;
                if (serverData.Length == 0) continue;

                // Parse server response to detect handshake completion
                var serverQuicInfo = ParseQuicHeader(serverData);

                // FIXED: Detect handshake completion (server sends Handshake Done or 1-RTT packets)
                if (serverQuicInfo.IsLongHeader)
                {
                    // Check for handshake completion indicators
                    if (IsHandshakeCompletePacket(serverData))
                    {
                        _handshakeComplete[sessionKey] = true;
                        _log.Info($"[UDP] Handshake complete for {sessionKey}", "UDP");
                    }
                }
                else
                {
                    // Short header = 1-RTT data = handshake definitely complete
                    _handshakeComplete[sessionKey] = true;
                }

                // Log server-to-client packet
                var packet = new CapturedPacket
                {
                    SequenceId = Interlocked.Increment(ref _sequenceCounter),
                    Timestamp = DateTime.Now,
                    Direction = PacketDirection.ServerToClient,
                    RawBytes = serverData,
                    IsTcp = false,
                    Opcode = serverData.Length > 0 ? serverData[0] : (ushort)0,
                    Source = "UDP/QUIC",
                    QuicInfo = serverQuicInfo
                };
                OnPacket?.Invoke(packet);

                // FIXED: Send response back to client unchanged
                // The server has already set the correct Destination CID based on client's original CID
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

    private QuicHeaderInfo ParseQuicHeader(byte[] data)
    {
        var info = new QuicHeaderInfo();

        if (data.Length < 1)
            return info;

        byte firstByte = data[0];
        bool isLongHeader = (firstByte & 0x80) != 0;
        info.IsLongHeader = isLongHeader;

        if (isLongHeader && data.Length >= 6)
        {
            info.Version = (uint)((data[1] << 24) | (data[2] << 16) | (data[3] << 8) | data[4]);
            byte dcidLen = data[5];

            if (data.Length >= 6 + dcidLen)
            {
                info.ClientConnectionId = new byte[dcidLen];
                Buffer.BlockCopy(data, 6, info.ClientConnectionId, 0, dcidLen);
            }

            // Parse SCID if present
            int scidOffset = 6 + dcidLen;
            if (data.Length > scidOffset)
            {
                byte scidLen = data[scidOffset];
                if (data.Length >= scidOffset + 1 + scidLen)
                {
                    info.SourceConnectionId = new byte[scidLen];
                    Buffer.BlockCopy(data, scidOffset + 1, info.SourceConnectionId, 0, scidLen);
                }
            }
        }
        else if (!isLongHeader && data.Length >= 5)
        {
            // Short header: DCID follows immediately after first byte
            int dcidLen = Math.Min(4, data.Length - 1); // Typically 4 bytes for Hytale
            info.ClientConnectionId = new byte[dcidLen];
            Buffer.BlockCopy(data, 1, info.ClientConnectionId, 0, dcidLen);
        }

        return info;
    }

    private bool IsHandshakeCompletePacket(byte[] data)
    {
        // Look for Handshake Done frame (type 0x1e) or NST (0x07)
        // This is a simplified check - in production, you'd parse the crypto frames properly
        for (int i = 5; i < Math.Min(data.Length - 1, 100); i++)
        {
            if (data[i] == 0x1e) return true; // Handshake Done
            if (data[i] == 0x07) return true; // New Session Ticket (indicates handshake success)
        }
        return false;
    }

    public void Dispose() => Stop();
}

public class QuicSession : IDisposable
{
    public IPEndPoint ClientEndpoint { get; }
    public UdpClient ServerSocket { get; }
    public byte[] ClientConnectionId { get; }
    public DateTimeOffset LastActivity { get; set; }

    private bool _disposed;

    public QuicSession(IPEndPoint clientEp, UdpClient serverSocket, byte[] clientCid)
    {
        ClientEndpoint = clientEp;
        ServerSocket = serverSocket;
        ClientConnectionId = clientCid;
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