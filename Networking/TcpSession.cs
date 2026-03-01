// FILE: Networking/TcpSession.cs
using System.Net;
using System.Net.Sockets;

namespace HyForce.Networking;

public class TcpSession
{
    public TcpClient Client { get; }      // ADDED public getter
    public TcpClient? Server { get; }     // ADDED public getter
    private readonly NetworkStream? _clientStream;
    private readonly NetworkStream? _serverStream;
    private readonly CancellationTokenSource _cts = new();
    private readonly string _targetHost;
    private readonly int _targetPort;
    private readonly Data.TestLog _log;

    public IPEndPoint? RemoteEndPoint => Client.Client.RemoteEndPoint as IPEndPoint;
    public bool IsConnected => Client.Connected && (Server?.Connected ?? false);

    public TcpSession(TcpClient client, string targetHost, int targetPort, Data.TestLog log)
    {
        Client = client;
        _targetHost = targetHost;
        _targetPort = targetPort;
        _log = log;

        try
        {
            var server = new TcpClient();
            server.Connect(targetHost, targetPort);
            Server = server;
            _clientStream = client.GetStream();
            _serverStream = server.GetStream();
        }
        catch (Exception ex)
        {
            client.Close();
            throw;
        }
    }

    // ADDED: New Run method with callback
    public async Task Run(Func<byte[], PacketDirection, Task> onPacket, CancellationToken ct)
    {
        var cts = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token, ct);

        var clientToServer = RelayAsync(_clientStream!, _serverStream!, PacketDirection.ClientToServer, onPacket, cts.Token);
        var serverToClient = RelayAsync(_serverStream!, _clientStream!, PacketDirection.ServerToClient, onPacket, cts.Token);

        await Task.WhenAny(clientToServer, serverToClient);

        _cts.Cancel();
        try { await Task.WhenAll(clientToServer, serverToClient); } catch { }
    }

    private async Task RelayAsync(NetworkStream source, NetworkStream dest, PacketDirection direction, Func<byte[], PacketDirection, Task> onPacket, CancellationToken ct)
    {
        byte[] buffer = new byte[65536];
        try
        {
            while (!ct.IsCancellationRequested)
            {
                int read = await source.ReadAsync(buffer, 0, buffer.Length, ct);
                if (read == 0) break;

                byte[] data = new byte[read];
                Buffer.BlockCopy(buffer, 0, data, 0, read);

                // Call the packet callback
                await onPacket(data, direction);

                await dest.WriteAsync(data, 0, read, ct);
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
        Client?.Close();
        Server?.Close();
    }
}