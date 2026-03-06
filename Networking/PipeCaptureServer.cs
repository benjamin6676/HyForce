using HyForce.Core;
using HyForce.Data;
using HyForce.Networking;
using System;
using System.Collections.Generic;
using System.IO.Pipes;
using System.Net;
using System.Threading;

namespace HyForce.Networking
{
    public class PipeCaptureServer : IDisposable
    {
        public const string PIPE_DATA = "HyForcePipe";
        public const string PIPE_CMD = "HyForceCmdPipe";

        private readonly AppState _state;
        private CancellationTokenSource? _cts;
        private Thread? _dataThread, _cmdThread;
        private NamedPipeServerStream? _cmdPipe;

        private volatile bool _running;
        private volatile bool _dllConnected;
        private int _packetCount;
        private string _dllStatus = "Not connected";
        private DateTime _lastPkt = DateTime.Now; // FIXED: Not DateTime.MinValue
        private DateTime _dllConnectedAt = DateTime.MinValue;

        private readonly object _memLock = new();
        private readonly object _timingLock = new();
        private readonly object _seqLock = new();

        public readonly List<MemScanHit> MemHits = new();
        public readonly List<TimingEntry> TimingLog = new();
        public const int MAX_TIMING = 2000;
        public readonly List<string> SeqAnomalies = new();

        public int LastRateLimitSent;
        public int LastRateLimitIntervalMs;

        public bool IsRunning => _running;
        public bool DllConnected => _dllConnected;
        public int PacketCount => _packetCount;
        public string DllStatus => _dllStatus;
        public DateTime LastPacket => _lastPkt;
        public DateTime DllConnectedAt => _dllConnectedAt;
        public TimeSpan TimeSinceConnected =>
            _dllConnectedAt != DateTime.MinValue ? DateTime.Now - _dllConnectedAt : TimeSpan.Zero;

        public event Action<CapturedPacket>? OnPacketReceived;

        public PipeCaptureServer(AppState state) { _state = state; }

        public void Start()
        {
            if (_running) return;
            _cts = new CancellationTokenSource();
            _running = true;
            _packetCount = 0;
            _dllConnected = false;
            _lastPkt = DateTime.Now;
            _dataThread = new Thread(DataLoop) { IsBackground = true, Name = "HyForce-PipeData" };
            _dataThread.Start();
            _cmdThread = new Thread(CmdLoop) { IsBackground = true, Name = "HyForce-PipeCmd" };
            _cmdThread.Start();
            _state.AddInGameLog("[PIPE] Servers started — waiting for DLL");
        }

        public void Stop()
        {
            if (!_running) return;
            _running = false;
            _cts?.Cancel();
            _dllConnected = false;
            try { _cmdPipe?.Close(); } catch { }
            _state.AddInGameLog($"[PIPE] Stopped. {_packetCount} packets captured.");
        }

        public void Dispose() => Stop();

        public void SendCommand(string cmd)
        {
            try
            {
                if (_cmdPipe?.IsConnected == true)
                {
                    byte[] b = System.Text.Encoding.ASCII.GetBytes(cmd + "\n");
                    _cmdPipe.Write(b, 0, b.Length);
                    _cmdPipe.Flush();
                }
            }
            catch { }
        }

        public void Fuzz(int bits) => SendCommand($"FUZZ {bits}");
        public void Replay() => SendCommand("REPLAY");
        public void ReplayHex(string hex) => SendCommand($"REPLAY {hex}");
        public void RateLimit(int count, int ms) => SendCommand($"RATELIMIT {count} {ms}");
        public void StartPcap(string path) => SendCommand($"PCAP_START {path}");
        public void StopPcap() => SendCommand("PCAP_STOP");
        public void MemScan() => SendCommand("MEMSCAN");
        public void SeqReset() => SendCommand("SEQRESET");
        public void Ping() => SendCommand("PING");

        public void ResetConnection()
        {
            _dllConnected = false;
            _dllConnectedAt = DateTime.MinValue;
            _packetCount = 0;
            try { _cmdPipe?.Close(); } catch { }
            _cmdPipe = null;
            _state.AddInGameLog("[PIPE] Connection reset");
        }

        private void DataLoop()
        {
            var token = _cts!.Token;
            while (_running && !token.IsCancellationRequested)
            {
                try
                {
                    using var pipe = new NamedPipeServerStream(PIPE_DATA,
                        PipeDirection.In, 1, PipeTransmissionMode.Byte,
                        PipeOptions.Asynchronous, 0, 131072);

                    _state.AddInGameLog("[PIPE] Waiting for DLL connection...");
                    pipe.WaitForConnectionAsync(token).GetAwaiter().GetResult();

                    _dllConnected = true;
                    _dllConnectedAt = DateTime.Now;
                    _lastPkt = DateTime.Now;
                    _state.AddInGameLog("[PIPE] DLL connected — capture live");

                    ReadMessages(pipe, token);

                    _dllConnected = false;
                    _dllConnectedAt = DateTime.MinValue;
                    _state.AddInGameLog("[PIPE] DLL disconnected");
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) when (!token.IsCancellationRequested)
                {
                    _state.AddInGameLog($"[PIPE] Error: {ex.Message}");
                    Thread.Sleep(1000);
                }
            }
        }

        private void CmdLoop()
        {
            var token = _cts!.Token;
            while (_running && !token.IsCancellationRequested)
            {
                try
                {
                    var pipe = new NamedPipeServerStream(PIPE_CMD,
                        PipeDirection.Out, 1, PipeTransmissionMode.Byte,
                        PipeOptions.None, 131072, 0);

                    pipe.WaitForConnectionAsync(token).GetAwaiter().GetResult();
                    _cmdPipe = pipe;

                    while (_running && pipe.IsConnected && !token.IsCancellationRequested)
                        Thread.Sleep(100);

                    _cmdPipe = null;
                    try { pipe.Close(); } catch { }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) when (!token.IsCancellationRequested)
                {
                    _state.AddInGameLog($"[PIPE/CMD] {ex.Message}");
                    Thread.Sleep(1000);
                }
            }
        }

        private void ReadMessages(NamedPipeServerStream pipe, CancellationToken token)
        {
            byte[] hdr = new byte[5];
            while (_running && !token.IsCancellationRequested && pipe.IsConnected)
            {
                if (!ReadExact(pipe, hdr, 5)) return;

                byte type = hdr[0];
                uint len = BitConverter.ToUInt32(hdr, 1);
                if (len > 131072) return;

                byte[] pay = len > 0 ? new byte[len] : Array.Empty<byte>();
                if (len > 0 && !ReadExact(pipe, pay, (int)len)) return;

                _lastPkt = DateTime.Now;

                switch (type)
                {
                    case 0x01: HandlePacket(pay); break;
                    case 0x02:
                        _dllStatus = System.Text.Encoding.ASCII.GetString(pay).TrimEnd('\0');
                        _state.AddInGameLog($"[PIPE] {_dllStatus}");
                        break;
                    case 0x03:
                        _state.AddInGameLog($"[DLL] {System.Text.Encoding.ASCII.GetString(pay).TrimEnd('\0')}");
                        break;
                    case 0x04: HandleTiming(pay); break;
                    case 0x05: HandleSeqAnomaly(pay); break;
                    case 0x06: HandleMemScan(pay); break;
                    case 0x07: HandleRateLimit(pay); break;
                }
            }
        }

        private void HandlePacket(byte[] pay)
        {
            if (pay.Length < 8) return;
            byte dir = pay[0];
            uint ipRaw = BitConverter.ToUInt32(pay, 1);
            ushort portRaw = BitConverter.ToUInt16(pay, 5);
            int dataLen = pay.Length - 7;
            if (dataLen <= 0) return;

            byte[] data = new byte[dataLen];
            Buffer.BlockCopy(pay, 7, data, 0, dataLen);
            string ip = new IPAddress(ipRaw).ToString();
            int port = IPAddress.NetworkToHostOrder((short)portRaw) & 0xFFFF;

            var pkt = new CapturedPacket
            {
                RawBytes = data,
                Direction = dir == 0 ? PacketDirection.ClientToServer : PacketDirection.ServerToClient,
                EncryptionHint = "encrypted",
                Timestamp = DateTime.Now,
                SourceAddress = dir == 0 ? "127.0.0.1" : ip,
                DestAddress = dir == 0 ? ip : "127.0.0.1",
                SourcePort = dir == 0 ? 0 : port,
                DestPort = dir == 0 ? port : 0,
            };

            Interlocked.Increment(ref _packetCount);
            _lastPkt = DateTime.Now;
            OnPacketReceived?.Invoke(pkt);
        }

        private void HandleTiming(byte[] pay)
        {
            if (pay.Length < 13) return;
            var e = new TimingEntry
            {
                TimestampUs = BitConverter.ToUInt64(pay, 0),
                Length = BitConverter.ToUInt32(pay, 8),
                Dir = pay[12],
            };
            lock (_timingLock)
            {
                TimingLog.Add(e);
                if (TimingLog.Count > MAX_TIMING)
                    TimingLog.RemoveAt(0);
            }
        }

        private void HandleSeqAnomaly(byte[] pay)
        {
            if (pay.Length < 17) return;
            ulong expected = BitConverter.ToUInt64(pay, 0);
            ulong got = BitConverter.ToUInt64(pay, 8);
            byte dir = pay[16];
            string msg = $"SEQ ANOMALY dir={dir} expected>{expected} got={got}";
            lock (_seqLock) { SeqAnomalies.Add($"{DateTime.Now:HH:mm:ss.fff}  {msg}"); }
            _state.AddInGameLog($"[SEQ] {msg}");
        }

        private void HandleMemScan(byte[] pay)
        {
            if (pay.Length < 12) return;
            ulong addr = BitConverter.ToUInt64(pay, 0);
            uint sz = BitConverter.ToUInt32(pay, 8);
            byte[] data = new byte[pay.Length - 12];
            if (data.Length > 0) Buffer.BlockCopy(pay, 12, data, 0, data.Length);

            var hit = new MemScanHit { Address = addr, StructBytes = data };
            if (data.Length >= 32)
            {
                hit.Health = BitConverter.ToSingle(data, 0);
                hit.MaxHealth = BitConverter.ToSingle(data, 4);
                hit.X = BitConverter.ToDouble(data, 8);
                hit.Y = BitConverter.ToDouble(data, 16);
                hit.Z = BitConverter.ToDouble(data, 24);
            }
            lock (_memLock) { MemHits.Add(hit); }
        }

        private void HandleRateLimit(byte[] pay)
        {
            if (pay.Length < 8) return;
            LastRateLimitSent = (int)BitConverter.ToUInt32(pay, 0);
            LastRateLimitIntervalMs = (int)BitConverter.ToUInt32(pay, 4);
        }

        private static bool ReadExact(System.IO.Stream s, byte[] buf, int count)
        {
            int read = 0;
            while (read < count)
            {
                int n = s.Read(buf, read, count - read);
                if (n <= 0) return false;
                read += n;
            }
            return true;
        }
    }

    public class TimingEntry
    {
        public ulong TimestampUs { get; set; }
        public uint Length { get; set; }
        public byte Dir { get; set; }
    }

    public class MemScanHit
    {
        public ulong Address { get; set; }
        public float Health { get; set; }
        public float MaxHealth { get; set; }
        public double X { get; set; }
        public double Y { get; set; }
        public double Z { get; set; }
        public byte[] StructBytes { get; set; } = Array.Empty<byte>();
        public DateTime FoundAt { get; set; } = DateTime.Now;
    }
}