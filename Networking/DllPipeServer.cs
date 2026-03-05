using HyForce.Core;
using HyForce.Data;
using HyForce.Protocol;
using System;
using System.IO;
using System.IO.Pipes;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace HyForce.Networking
{
    /// <summary>
    /// Named pipe server that receives captured UDP packets from HyForceHook.dll.
    /// The DLL runs inside Hytale.exe and hooks WSASendTo/WSARecvFrom, streaming
    /// raw UDP data here without any proxy overhead.
    ///
    /// Pipe name:  \\.\pipe\HyForceCapture
    /// Protocol (per message):
    ///   [1]  direction  0=ClientToServer  1=ServerToClient
    ///   [4]  data_len   uint32 LE
    ///   [4]  src_ip     IPv4 uint32 BE
    ///   [2]  src_port   uint16 BE
    ///   [4]  dst_ip     IPv4 uint32 BE
    ///   [2]  dst_port   uint16 BE
    ///   [N]  data       raw UDP payload bytes
    /// </summary>
    public class DllPipeServer
    {
        public const string PipeName = "HyForceCapture";

        private CancellationTokenSource? _cts;
        private Task? _serverTask;
        private readonly AppState _state;

        public bool IsRunning => _cts != null && !_cts.IsCancellationRequested;
        public int PacketsReceived { get; private set; }
        public int BytesReceived   { get; private set; }
        public DateTime LastPacket { get; private set; }
        public string LastError    { get; private set; } = "";

        public event Action<byte[], PacketDirection>? OnPacketReceived;

        public DllPipeServer(AppState state) { _state = state; }

        public void Start()
        {
            if (IsRunning) return;
            _cts = new CancellationTokenSource();
            _serverTask = Task.Run(() => ServerLoop(_cts.Token));
            _state.AddInGameLog("[PIPE] Named pipe server started — waiting for HyForceHook.dll");
        }

        public void Stop()
        {
            _cts?.Cancel();
            _serverTask = null;
            _cts = null;
            PacketDecryptor.DllInjectionActive = false;
            PacketDecryptor.SkipHPFilter = false;
            _state.AddInGameLog("[PIPE] Named pipe server stopped");
        }

        private async Task ServerLoop(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    using var pipe = new NamedPipeServerStream(
                        PipeName,
                        PipeDirection.In,
                        NamedPipeServerStream.MaxAllowedServerInstances,
                        PipeTransmissionMode.Byte,
                        PipeOptions.Asynchronous);

                    _state.AddInGameLog("[PIPE] Waiting for DLL connection...");
                    await pipe.WaitForConnectionAsync(ct);
                    _state.AddInGameLog("[PIPE] ✓ HyForceHook.dll connected!");

                    // Signal: DLL is active — skip proxy, enable DCID=0 fast path
                    PacketDecryptor.DllInjectionActive = true;
                    PacketDecryptor.SkipHPFilter = true;
                    PacketDecryptor.AutoDecryptEnabled = true;

                    await ReadPacketsAsync(pipe, ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    LastError = ex.Message;
                    _state.AddInGameLog($"[PIPE] Error: {ex.Message}");
                    PacketDecryptor.DllInjectionActive = false;
                    await Task.Delay(1000, ct).ContinueWith(_ => { }); // reconnect delay
                }
            }
            PacketDecryptor.DllInjectionActive = false;
        }

        private async Task ReadPacketsAsync(NamedPipeServerStream pipe, CancellationToken ct)
        {
            var hdr = new byte[13]; // 1+4+4+2+4+2 - but we pack as 1+4+4+2 = 11? Let me use 17
            // Header: dir(1) + len(4) + src_ip(4) + src_port(2) + dst_ip(4) + dst_port(2) = 17
            var hdrBuf = new byte[17];

            while (!ct.IsCancellationRequested && pipe.IsConnected)
            {
                try
                {
                    // Read fixed header
                    int read = 0;
                    while (read < hdrBuf.Length)
                    {
                        int n = await pipe.ReadAsync(hdrBuf, read, hdrBuf.Length - read, ct);
                        if (n == 0) return; // pipe closed
                        read += n;
                    }

                    byte dir   = hdrBuf[0];
                    uint dataLen = BitConverter.ToUInt32(hdrBuf, 1);
                    uint srcIp  = BitConverter.ToUInt32(hdrBuf, 5);  // network order
                    ushort srcPort = BitConverter.ToUInt16(hdrBuf, 9);
                    uint dstIp  = BitConverter.ToUInt32(hdrBuf, 11);
                    ushort dstPort = BitConverter.ToUInt16(hdrBuf, 15);

                    if (dataLen == 0 || dataLen > 65535) continue;

                    var data = new byte[dataLen];
                    read = 0;
                    while (read < data.Length)
                    {
                        int n = await pipe.ReadAsync(data, read, data.Length - read, ct);
                        if (n == 0) return;
                        read += n;
                    }

                    PacketsReceived++;
                    BytesReceived += data.Length;
                    LastPacket = DateTime.Now;

                    var direction = dir == 0 ? PacketDirection.ClientToServer : PacketDirection.ServerToClient;

                    // Enqueue for decryption (skip HP filter - DLL confirmed these are QUIC)
                    if (PacketDecryptor.AutoDecryptEnabled)
                    {
                        var result = PacketDecryptor.TryDecryptDirect(data, direction);
                        if (result != null)
                        {
                            _state.AddInGameLog($"[PIPE] ✓ Decrypted {result.Length}B ({direction})");
                        }
                    }

                    OnPacketReceived?.Invoke(data, direction);
                }
                catch (Exception ex) when (!ct.IsCancellationRequested)
                {
                    LastError = ex.Message;
                    break;
                }
            }
            _state.AddInGameLog("[PIPE] DLL disconnected");
            PacketDecryptor.DllInjectionActive = false;
        }
    }
}
