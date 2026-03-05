using HyForce.Core;
using HyForce.Data;
using HyForce.Networking;
using System;
using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace HyForce.Networking
{
    /// <summary>
    /// Listens on \\.\pipe\HyForcePipe for packets forwarded by HyForceHook.dll
    /// injected into the Hytale JVM process.
    ///
    /// Pipe message format (each message):
    ///   [1B  direction : 0 = Client→Server, 1 = Server→Client]
    ///   [4B  data_len  : uint32 LE]
    ///   [NB  raw QUIC packet bytes]
    ///   [4B  remote_ip  : IPv4 network order]
    ///   [2B  remote_port: uint16 network order]
    /// </summary>
    public class PipeCaptureServer : IDisposable
    {
        public const string PIPE_NAME = "HyForcePipe";

        private readonly AppState      _state;
        private CancellationTokenSource? _cts;
        private Thread?                 _serverThread;
        private volatile bool           _running;
        private int                     _packetsReceived;
        private DateTime                _startTime = DateTime.MinValue;

        public bool  IsRunning       => _running;
        public int   PacketsReceived => _packetsReceived;

        // Raised on the background thread — subscribe to forward packets into PacketLog
        public event Action<CapturedPacket>? OnPacketReceived;

        public PipeCaptureServer(AppState state) { _state = state; }

        // ─── Start ────────────────────────────────────────────────────
        public void Start()
        {
            if (_running) return;
            _cts        = new CancellationTokenSource();
            _running    = true;
            _startTime  = DateTime.Now;
            _packetsReceived = 0;
            _serverThread = new Thread(ServerLoop)
            {
                IsBackground = true,
                Name         = "HyForce-PipeServer"
            };
            _serverThread.Start();
            _state.AddInGameLog("[PIPE] Listening on \\\\.\\pipe\\" + PIPE_NAME);
        }

        // ─── Stop ─────────────────────────────────────────────────────
        public void Stop()
        {
            if (!_running) return;
            _running = false;
            _cts?.Cancel();
            _state.AddInGameLog($"[PIPE] Stopped — {_packetsReceived} packets received.");
        }

        public void Dispose() { Stop(); }

        // ─── Server loop (accepts one client at a time, loops on reconnect) ──
        private void ServerLoop()
        {
            var token = _cts!.Token;
            while (_running && !token.IsCancellationRequested)
            {
                try
                {
                    using var pipe = new NamedPipeServerStream(
                        PIPE_NAME,
                        PipeDirection.In,
                        1,
                        PipeTransmissionMode.Byte,
                        PipeOptions.Asynchronous,
                        0, 65536 + 11);  // inBuf = 0, outBuf = max packet + header

                    _state.AddInGameLog("[PIPE] Waiting for HyForceHook.dll to connect…");

                    // Wait for DLL to connect (with cancellation)
                    var connectTask = pipe.WaitForConnectionAsync(token);
                    connectTask.GetAwaiter().GetResult();

                    _state.AddInGameLog("[PIPE] HyForceHook.dll connected — live capture active.");

                    ReadPackets(pipe, token);

                    _state.AddInGameLog("[PIPE] Client disconnected — waiting for reconnect…");
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) when (!token.IsCancellationRequested)
                {
                    _state.AddInGameLog($"[PIPE] Error: {ex.Message} — retrying in 1s");
                    Thread.Sleep(1000);
                }
            }
        }

        // ─── Read messages from a connected pipe ──────────────────────
        private void ReadPackets(NamedPipeServerStream pipe, CancellationToken token)
        {
            byte[] header = new byte[5]; // direction(1) + len(4)

            while (_running && !token.IsCancellationRequested && pipe.IsConnected)
            {
                // Read header
                if (!ReadExact(pipe, header, 5)) return;

                byte direction   = header[0];
                int  dataLen     = (int)BitConverter.ToUInt32(header, 1);

                if (dataLen <= 0 || dataLen > 65535)
                {
                    _state.AddInGameLog($"[PIPE] Bad packet length {dataLen} — dropping");
                    return;
                }

                byte[] payload = new byte[dataLen];
                if (!ReadExact(pipe, payload, dataLen)) return;

                byte[] tail = new byte[6]; // ip(4) + port(2)
                if (!ReadExact(pipe, tail, 6)) return;

                uint   ipRaw  = BitConverter.ToUInt32(tail, 0);
                ushort portRaw= BitConverter.ToUInt16(tail, 4);

                // Build CapturedPacket
                string remoteIp   = new IPAddress(ipRaw).ToString();
                int    remotePort = IPAddress.NetworkToHostOrder((short)portRaw);

                var dir = (direction == 0)
                    ? PacketDirection.ClientToServer
                    : PacketDirection.ServerToClient;

                var pkt = new CapturedPacket
                {
                    RawBytes        = payload,
                    Direction       = dir,
                    EncryptionHint  = "encrypted",
                    Timestamp       = DateTime.Now,
                    SourceAddress   = direction == 0 ? "127.0.0.1" : remoteIp,
                    DestAddress     = direction == 0 ? remoteIp    : "127.0.0.1",
                    SourcePort      = direction == 0 ? 0           : remotePort,
                    DestPort        = direction == 0 ? remotePort  : 0,
                };

                Interlocked.Increment(ref _packetsReceived);
                OnPacketReceived?.Invoke(pkt);
            }
        }

        // ─── Read exactly N bytes, return false on disconnect ─────────
        private static bool ReadExact(NamedPipeServerStream pipe, byte[] buf, int count)
        {
            int read = 0;
            while (read < count)
            {
                int n = pipe.Read(buf, read, count - read);
                if (n <= 0) return false;
                read += n;
            }
            return true;
        }
    }
}
