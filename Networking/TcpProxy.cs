// FILE: Networking/TcpProxy.cs
using System.Net;
using System.Net.Sockets;
using HyForce.Data;

namespace HyForce.Networking;

public class TcpProxy
{
    private TcpListener? _listener;
    private readonly List<TcpSession> _sessions = new();
    private readonly object _lock = new();
    private CancellationTokenSource? _cts;
    private readonly TestLog _log;
    private readonly Action<byte[], PacketDirection> _onPacket;
    private int _listenPort;
    private string _listenHost = "";

    public bool IsRunning => _listener != null;
    public string StatusMessage { get; private set; } = "Stopped";
    public int ActiveSessions => _sessions.Count;
    public long TotalConnections { get; private set; }
    public int ListenPort => _listenPort;
    public string ListenHost => _listenHost;

    public TcpProxy(TestLog log)
    {
        _log = log;
        _onPacket = (data, dir) =>
        {
            var packet = new CapturedPacket
            {
                RawBytes = data,
                Direction = dir,
                IsTcp = true,
                Timestamp = DateTime.Now
            };
            OnPacket?.Invoke(packet);
        };
    }

    public event Action<CapturedPacket>? OnPacket;

    public void Start(string listenHost, int listenPort, string targetHost, int targetPort)
    {
        if (IsRunning) return;

        _listenHost = listenHost;
        _listenPort = listenPort;

        _cts = new CancellationTokenSource();
        _listener = new TcpListener(IPAddress.Parse(listenHost), listenPort);
        _listener.Start();

        StatusMessage = $"Listening {listenHost}:{listenPort} → {targetHost}:{targetPort}";
        _log.Info($"[TCP] {StatusMessage}", "TcpProxy");

        _ = AcceptLoopAsync(targetHost, targetPort);
    }

    private async Task AcceptLoopAsync(string targetHost, int targetPort)
    {
        while (_cts?.IsCancellationRequested == false)
        {
            try
            {
                var client = await _listener!.AcceptTcpClientAsync();
                TotalConnections++;

                _log.Info($"[TCP] New connection from {client.Client.RemoteEndPoint}", "TcpProxy");

                var session = new TcpSession(client, targetHost, targetPort, _onPacket);

                lock (_lock)
                    _sessions.Add(session);

                session.Start();
                CleanupSessions();
            }
            catch (Exception ex) when (!_cts!.IsCancellationRequested)
            {
                _log.Error($"[TCP] Accept error: {ex.Message}", "TcpProxy");
            }
        }
    }

    private void CleanupSessions()
    {
        lock (_lock)
        {
            _sessions.RemoveAll(s => !s.IsConnected);
        }
    }

    public void Stop()
    {
        _cts?.Cancel();

        lock (_lock)
        {
            foreach (var session in _sessions)
                session.Stop();
            _sessions.Clear();
        }

        _listener?.Stop();
        _listener = null;
        StatusMessage = "Stopped";
        _log.Info("[TCP] Proxy stopped", "TcpProxy");
    }
}