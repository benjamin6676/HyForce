// FILE: Networking/TcpSession.cs
using System.Net;
using System.Net.Sockets;

namespace HyForce.Networking;

public class TcpSession
{
    private readonly TcpClient _client;
    private TcpClient? _server;
    private NetworkStream? _clientStream;
    private NetworkStream? _serverStream;
    private readonly CancellationTokenSource _cts = new();
    private readonly Action<byte[], PacketDirection> _onData;
    private Task? _clientToServerTask;
    private Task? _serverToClientTask;

    public IPEndPoint? RemoteEndPoint => _client.Client.RemoteEndPoint as IPEndPoint;
    public bool IsConnected => _client.Connected && (_server?.Connected ?? false);

    public TcpSession(TcpClient client, string targetHost, int targetPort, Action<byte[], PacketDirection> onData)
    {
        _client = client;
        _onData = onData;

        try
        {
            _server = new TcpClient();
            _server.Connect(targetHost, targetPort);
            _clientStream = _client.GetStream();
            _serverStream = _server.GetStream();
        }
        catch (Exception ex)
        {
            _client.Close();
            throw;
        }
    }

    public void Start()
    {
        _clientToServerTask = RelayAsync(_clientStream!, _serverStream!, PacketDirection.ClientToServer);
        _serverToClientTask = RelayAsync(_serverStream!, _clientStream!, PacketDirection.ServerToClient);
    }

    private async Task RelayAsync(NetworkStream source, NetworkStream dest, PacketDirection direction)
    {
        byte[] buffer = new byte[65536];
        try
        {
            while (!_cts.Token.IsCancellationRequested)
            {
                int read = await source.ReadAsync(buffer, 0, buffer.Length, _cts.Token);
                if (read == 0) break;

                byte[] data = new byte[read];
                Buffer.BlockCopy(buffer, 0, data, 0, read);

                _onData(data, direction);

                await dest.WriteAsync(data, 0, read, _cts.Token);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception) { /* Connection closed */ }
    }

    public void Stop()
    {
        _cts.Cancel();
        _clientStream?.Close();
        _serverStream?.Close();
        _client?.Close();
        _server?.Close();
    }
}