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

            ServerIp = serverIp;
            ServerPort = serverPort;
            ListenPort = listenPort;
            IsRunning = true;
            StatusMessage = $"Listening {listenIp}:{listenPort} → {serverIp}:{serverPort}";

            _log.Info($"[TCP] Started on {listenIp}:{listenPort}", "TCP");
            _log.Info($"[TCP] Forwarding to {serverIp}:{serverPort}", "TCP");

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
            session.Client.Close();
            session.Server?.Close();
        }
        _sessions.Clear();

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

                TotalConnections++;
                _log.Info($"[TCP] Connection #{TotalConnections} from {clientEp}", "TCP");

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

public class TcpSession
{
    public TcpClient Client { get; }
    public TcpClient? Server { get; private set; }
    public DateTime StartTime { get; } = DateTime.Now;

    private readonly Data.TestLog _log;
    private NetworkStream? _clientStream;
    private NetworkStream? _serverStream;

    public TcpSession(TcpClient client, string serverIp, int serverPort, Data.TestLog log)
    {
        Client = client;
        _log = log;

        Server = new TcpClient();
        Server.Connect(serverIp, serverPort);

        _clientStream = client.GetStream();
        _serverStream = Server.GetStream();
    }

    public async Task Run(Func<byte[], PacketDirection, Task> onData, CancellationToken ct)
    {
        var clientToServer = Forward(_clientStream!, _serverStream!, PacketDirection.ClientToServer, onData, ct);
        var serverToClient = Forward(_serverStream!, _clientStream!, PacketDirection.ServerToClient, onData, ct);

        await Task.WhenAny(clientToServer, serverToClient);
    }

    private async Task Forward(NetworkStream from, NetworkStream to, PacketDirection direction,
        Func<byte[], PacketDirection, Task> onData, CancellationToken ct)
    {
        var buffer = new byte[65536];

        while (!ct.IsCancellationRequested)
        {
            int read;
            try
            {
                read = await from.ReadAsync(buffer, 0, buffer.Length, ct);
            }
            catch
            {
                break;
            }

            if (read == 0) break;

            var data = new byte[read];
            Buffer.BlockCopy(buffer, 0, data, 0, read);

            await onData(data, direction);

            try
            {
                await to.WriteAsync(data, 0, data.Length, ct);
            }
            catch
            {
                break;
            }
        }
    }
}