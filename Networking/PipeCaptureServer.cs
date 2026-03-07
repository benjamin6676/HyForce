using HyForce.Core;
using HyForce.Data;
using HyForce.Networking;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO.Pipes;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace HyForce.Networking
{
    public class PipeCaptureServer : IDisposable
    {
        public const string PIPE_DATA = "HyForcePipe";
        public const string PIPE_CMD  = "HyForceCmdPipe";

        // ─────────────────────────────────────────────────────────────────────────
        // ROOT-CAUSE FIX FOR "DLL never connects":
        //   NamedPipeServerStream uses the process token DACL by default.
        //   When HyForce runs at medium integrity and the game runs elevated,
        //   the elevated DLL can't open a pipe owned by medium-IL process.
        //   Fix: call CreateNamedPipeW directly via P/Invoke with a NULL DACL
        //   security descriptor (bDaclPresent=true, pDacl=NULL = allow everyone).
        //   No extra NuGet package needed — advapi32 + kernel32 are always present.
        // ─────────────────────────────────────────────────────────────────────────

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES
        {
            public int    nLength;
            public IntPtr lpSecurityDescriptor;
            public int    bInheritHandle;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateNamedPipeW(
            string lpName,
            uint   dwOpenMode,
            uint   dwPipeMode,
            uint   nMaxInstances,
            uint   nOutBufferSize,
            uint   nInBufferSize,
            uint   nDefaultTimeOut,
            ref SECURITY_ATTRIBUTES lpSecurityAttributes);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool InitializeSecurityDescriptor(IntPtr pSD, uint dwRevision);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool SetSecurityDescriptorDacl(
            IntPtr pSD,
            bool   bDaclPresent,
            IntPtr pDacl,
            bool   bDaclDefaulted);

        private const uint PIPE_ACCESS_INBOUND  = 0x00000001u;
        private const uint PIPE_ACCESS_OUTBOUND = 0x00000002u;
        private const uint FILE_FLAG_OVERLAPPED = 0x40000000u;
        private const uint PIPE_TYPE_BYTE       = 0x00000000u;
        private const uint PIPE_READMODE_BYTE   = 0x00000000u;
        private const uint PIPE_WAIT            = 0x00000000u;
        private const int  SD_MIN_LENGTH        = 40;
        private static readonly IntPtr INVALID_PIPE_HANDLE = new IntPtr(-1);

        /// <summary>
        /// Creates a named pipe with NULL DACL — connectable from any integrity level.
        /// </summary>
        private static NamedPipeServerStream CreatePermissivePipe(
            string name, PipeDirection dir, bool isAsync, int bufSize = 131072)
        {
            IntPtr pSD = Marshal.AllocHGlobal(SD_MIN_LENGTH);
            try
            {
                // Zero the buffer; InitializeSecurityDescriptor will set the header
                for (int i = 0; i < SD_MIN_LENGTH; i++)
                    Marshal.WriteByte(pSD, i, 0);

                if (!InitializeSecurityDescriptor(pSD, 1))
                    throw new Win32Exception(Marshal.GetLastWin32Error(),
                        "InitializeSecurityDescriptor failed");

                // NULL DACL with bDaclPresent = true means "no restrictions — allow all"
                if (!SetSecurityDescriptorDacl(pSD, bDaclPresent: true, pDacl: IntPtr.Zero, bDaclDefaulted: false))
                    throw new Win32Exception(Marshal.GetLastWin32Error(),
                        "SetSecurityDescriptorDacl failed");

                var sa = new SECURITY_ATTRIBUTES
                {
                    nLength              = Marshal.SizeOf<SECURITY_ATTRIBUTES>(),
                    lpSecurityDescriptor = pSD,
                    bInheritHandle       = 0,
                };

                uint openMode = (dir == PipeDirection.In ? PIPE_ACCESS_INBOUND : PIPE_ACCESS_OUTBOUND)
                              | (isAsync ? FILE_FLAG_OVERLAPPED : 0u);

                IntPtr raw = CreateNamedPipeW(
                    $@"\\.\pipe\{name}",
                    openMode,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                    1,              // nMaxInstances — 1 client at a time; loop recreates after disconnect
                    (uint)bufSize,
                    (uint)bufSize,
                    0,              // nDefaultTimeOut — use system default (50 ms)
                    ref sa);

                if (raw == INVALID_PIPE_HANDLE)
                    throw new Win32Exception(Marshal.GetLastWin32Error(),
                        $"CreateNamedPipeW({name}) failed");

                var safeHandle = new SafePipeHandle(raw, ownsHandle: true);
                // isConnected = false: WaitForConnection hasn't been called yet
                return new NamedPipeServerStream(dir, isAsync, isConnected: false, safeHandle);
            }
            finally
            {
                Marshal.FreeHGlobal(pSD);
            }
        }

        // ── Fields ────────────────────────────────────────────────────────────────
        private readonly AppState _state;
        private CancellationTokenSource? _cts;
        private Thread? _dataThread, _cmdThread;
        private NamedPipeServerStream? _cmdPipe;

        private volatile bool _running;
        private volatile bool _dllConnected;
        private int      _packetCount;
        private string   _dllStatus       = "Not connected";
        private DateTime _lastPkt         = DateTime.Now;
        private DateTime _dllConnectedAt  = DateTime.MinValue;

        private readonly object _memLock    = new();
        private readonly object _timingLock = new();
        private readonly object _seqLock    = new();
        private readonly object _modLock    = new();
        private readonly object _gadgetLock = new();

        public readonly List<MemScanHit>    MemHits      = new();
        public readonly List<TimingEntry>   TimingLog    = new();
        public readonly List<string>        SeqAnomalies = new();
        public readonly List<MemWatchEntry> MemWatchLog  = new();
        public readonly List<ModuleInfo>    Modules      = new();
        public readonly List<GadgetHit>     Gadgets      = new();
        public readonly List<StringHit>     Strings      = new();
        public readonly object              StringLock   = new();

        public const int MAX_TIMING = 2000;
        public int LastRateLimitSent;
        public int LastRateLimitIntervalMs;

        // ── Public properties ─────────────────────────────────────────────────────
        public bool     IsRunning       => _running;
        public bool     DllConnected    => _dllConnected;
        public int      PacketCount     => _packetCount;
        public string   DllStatus       => _dllStatus;
        public DateTime LastPacket      => _lastPkt;
        public DateTime DllConnectedAt  => _dllConnectedAt;
        public TimeSpan TimeSinceConnected =>
            _dllConnectedAt != DateTime.MinValue
                ? DateTime.Now - _dllConnectedAt
                : TimeSpan.Zero;

        public event Action<CapturedPacket>? OnPacketReceived;

        public PipeCaptureServer(AppState state) { _state = state; }

        // ── Lifecycle ─────────────────────────────────────────────────────────────
        public void Start()
        {
            if (_running) return;
            _cts         = new CancellationTokenSource();
            _running     = true;
            _packetCount = 0;
            _dllConnected = false;
            _lastPkt     = DateTime.Now;

            _dataThread = new Thread(DataLoop) { IsBackground = true, Name = "HyForce-PipeData" };
            _dataThread.Start();
            _cmdThread = new Thread(CmdLoop) { IsBackground = true, Name = "HyForce-PipeCmd" };
            _cmdThread.Start();

            _state.AddInGameLog("[PIPE] Servers started (NULL-DACL) — waiting for DLL");
        }

        public void Stop()
        {
            if (!_running) return;
            _running     = false;
            _cts?.Cancel();
            _dllConnected = false;
            try { _cmdPipe?.Close(); } catch { }
            _state.AddInGameLog($"[PIPE] Stopped. {_packetCount} packets captured.");
        }

        public void Dispose() => Stop();

        // ── Commands ──────────────────────────────────────────────────────────────
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

        // ── Convenience wrappers ──────────────────────────────────────────────────
        public void Fuzz(int bits)               => SendCommand($"FUZZ {bits}");
        public void Replay()                     => SendCommand("REPLAY");
        public void RateLimit(int count, int ms) => SendCommand($"RATELIMIT {count} {ms}");
        public void StartPcap(string path)       => SendCommand($"PCAP_START {path}");
        public void StopPcap()                   => SendCommand("PCAP_STOP");
        public void MemScan()                    => SendCommand("MEMSCAN");
        public void SeqReset()                   => SendCommand("SEQRESET");
        public void Ping()                       => SendCommand("PING");
        public void GetStats()                   => SendCommand("STATS");
        public void KeylogFlush()                => SendCommand("KEYLOG_FLUSH");
        public void Eject()                      => SendCommand("EJECT");
        public void StringScan()                 => SendCommand("STRINGSCAN");
        public void ModList()                    => SendCommand("MODLIST");
        public void ThreadList()                 => SendCommand("THREADLIST");
        public void GadgetScan()                 => SendCommand("GADGETSCAN");
        public void ExploitProbe()               => SendCommand("EXPLOITPROBE");
        public void SockEnum()                   => SendCommand("SOCKENUM");
        public void PktForge(string hexPayload)  => SendCommand($"PKTFORGE {hexPayload}");
        public void ProcDump(ulong addr, int sz) => SendCommand($"PROCDUMP {addr:X} {sz}");
        public void PortScan(int lo, int hi)     => SendCommand($"PORTSCAN {lo} {hi}");

        public void MemWatch(ulong address, int pollMs = 250)
            => SendCommand($"MEMWATCH {address:X} {pollMs}");
        public void MemWatchStop()
            => SendCommand("MEMWATCH_STOP");

        public void RegisterInjectorPid()
            => SendCommand($"INJPID {System.Diagnostics.Process.GetCurrentProcess().Id}");

        public void ResetConnection()
        {
            _dllConnected   = false;
            _dllConnectedAt = DateTime.MinValue;
            _packetCount    = 0;
            try { _cmdPipe?.Close(); } catch { }
            _cmdPipe = null;
            _state.AddInGameLog("[PIPE] Connection reset");
        }

        // ── Pipe server loops ─────────────────────────────────────────────────────
        private void DataLoop()
        {
            var token = _cts!.Token;
            while (_running && !token.IsCancellationRequested)
            {
                NamedPipeServerStream? pipe = null;
                try
                {
                    pipe = CreatePermissivePipe(PIPE_DATA, PipeDirection.In, isAsync: true);
                    _state.AddInGameLog("[PIPE] Waiting for DLL connection...");
                    pipe.WaitForConnectionAsync(token).GetAwaiter().GetResult();

                    _dllConnected   = true;
                    _dllConnectedAt = DateTime.Now;
                    _lastPkt        = DateTime.Now;
                    _state.AddInGameLog("[PIPE] DLL connected — capture live");

                    // Send our PID to DLL monitor thread (delayed so cmd pipe connects first)
                    _ = System.Threading.Tasks.Task.Run(() =>
                    {
                        Thread.Sleep(1200);
                        RegisterInjectorPid();
                    });

                    ReadMessages(pipe, token);

                    _dllConnected   = false;
                    _dllConnectedAt = DateTime.MinValue;
                    _state.AddInGameLog("[PIPE] DLL disconnected");
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) when (!token.IsCancellationRequested)
                {
                    _state.AddInGameLog($"[PIPE] Error: {ex.Message}");
                    Thread.Sleep(1000);
                }
                finally
                {
                    try { pipe?.Dispose(); } catch { }
                }
            }
        }

        private void CmdLoop()
        {
            var token = _cts!.Token;
            while (_running && !token.IsCancellationRequested)
            {
                NamedPipeServerStream? pipe = null;
                try
                {
                    pipe = CreatePermissivePipe(PIPE_CMD, PipeDirection.Out, isAsync: false);
                    pipe.WaitForConnectionAsync(token).GetAwaiter().GetResult();
                    _cmdPipe = pipe;

                    while (_running && pipe.IsConnected && !token.IsCancellationRequested)
                        Thread.Sleep(100);

                    _cmdPipe = null;
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) when (!token.IsCancellationRequested)
                {
                    _state.AddInGameLog($"[PIPE/CMD] {ex.Message}");
                    Thread.Sleep(1000);
                }
                finally
                {
                    _cmdPipe = null;
                    try { pipe?.Dispose(); } catch { }
                }
            }
        }

        // ── Message dispatcher ────────────────────────────────────────────────────
        private void ReadMessages(NamedPipeServerStream pipe, CancellationToken token)
        {
            byte[] hdr = new byte[5];
            while (_running && !token.IsCancellationRequested && pipe.IsConnected)
            {
                if (!ReadExact(pipe, hdr, 5)) return;

                byte type = hdr[0];
                uint len  = BitConverter.ToUInt32(hdr, 1);
                if (len > 131072) return;

                byte[] pay = len > 0 ? new byte[len] : Array.Empty<byte>();
                if (len > 0 && !ReadExact(pipe, pay, (int)len)) return;

                _lastPkt = DateTime.Now;

                switch (type)
                {
                    case 0x01: HandlePacket(pay);        break;
                    case 0x02: HandleStatus(pay);        break;
                    case 0x03: HandleLog(pay);           break;
                    case 0x04: HandleTiming(pay);        break;
                    case 0x05: HandleSeqAnomaly(pay);    break;
                    case 0x06: HandleMemScan(pay);       break;
                    case 0x07: HandleRateLimit(pay);     break;
                    case 0x08: HandleEjected(); return;  // exit loop immediately
                    case 0x09: HandleKeylog(pay);        break;
                    case 0x0B: HandleMemWatch(pay);      break;
                    case 0x10: HandleStringScan(pay);    break;
                    case 0x11: HandleModInfo(pay);       break;
                    case 0x12: HandleGadget(pay);        break;
                    case 0x13: HandleExploitResult(pay); break;
                    case 0x14: HandleProcDump(pay);      break;
                    // Unknown types are silently skipped
                }
            }
        }

        // ── Message handlers ──────────────────────────────────────────────────────
        private void HandlePacket(byte[] pay)
        {
            if (pay.Length < 8) return;
            byte   dir     = pay[0];
            uint   ipRaw   = BitConverter.ToUInt32(pay, 1);
            ushort portRaw = BitConverter.ToUInt16(pay, 5);
            int    dataLen = pay.Length - 7;
            if (dataLen <= 0) return;

            byte[] data = new byte[dataLen];
            Buffer.BlockCopy(pay, 7, data, 0, dataLen);

            string ip   = new IPAddress(ipRaw).ToString();
            int    port = IPAddress.NetworkToHostOrder((short)portRaw) & 0xFFFF;

            var pkt = new CapturedPacket
            {
                RawBytes       = data,
                Direction      = dir == 0 ? PacketDirection.ClientToServer : PacketDirection.ServerToClient,
                EncryptionHint = "encrypted",
                Timestamp      = DateTime.Now,
                SourceAddress  = dir == 0 ? "127.0.0.1" : ip,
                DestAddress    = dir == 0 ? ip : "127.0.0.1",
                SourcePort     = dir == 0 ? 0 : port,
                DestPort       = dir == 0 ? port : 0,
            };

            Interlocked.Increment(ref _packetCount);
            _lastPkt = DateTime.Now;
            OnPacketReceived?.Invoke(pkt);
        }

        private void HandleStatus(byte[] pay)
        {
            _dllStatus = System.Text.Encoding.ASCII.GetString(pay).TrimEnd('\0');
            _state.AddInGameLog($"[DLL] {_dllStatus}");
        }

        private void HandleLog(byte[] pay)
        {
            _state.AddInGameLog(
                $"[DLL] {System.Text.Encoding.ASCII.GetString(pay).TrimEnd('\0')}");
        }

        private void HandleTiming(byte[] pay)
        {
            if (pay.Length < 13) return;
            var e = new TimingEntry
            {
                TimestampUs = BitConverter.ToUInt64(pay, 0),
                Length      = BitConverter.ToUInt32(pay, 8),
                Dir         = pay[12],
            };
            lock (_timingLock)
            {
                TimingLog.Add(e);
                if (TimingLog.Count > MAX_TIMING) TimingLog.RemoveAt(0);
            }
        }

        private void HandleSeqAnomaly(byte[] pay)
        {
            if (pay.Length < 17) return;
            ulong  expected = BitConverter.ToUInt64(pay, 0);
            ulong  got      = BitConverter.ToUInt64(pay, 8);
            byte   dir      = pay[16];
            string msg      = $"SEQ dir={dir} expected>{expected} got={got}";
            lock (_seqLock) { SeqAnomalies.Add($"{DateTime.Now:HH:mm:ss.fff}  {msg}"); }
            _state.AddInGameLog($"[SEQ] {msg}");
        }

        private void HandleMemScan(byte[] pay)
        {
            if (pay.Length < 12) return;
            ulong  addr = BitConverter.ToUInt64(pay, 0);
            byte[] data = new byte[pay.Length - 12];
            if (data.Length > 0) Buffer.BlockCopy(pay, 12, data, 0, data.Length);

            var hit = new MemScanHit { Address = addr, StructBytes = data, FoundAt = DateTime.Now };
            if (data.Length >= 44)
            {
                hit.Health    = BitConverter.ToSingle(data, 0);
                hit.MaxHealth = BitConverter.ToSingle(data, 4);
                hit.X         = BitConverter.ToDouble(data, 8);
                hit.Y         = BitConverter.ToDouble(data, 16);
                hit.Z         = BitConverter.ToDouble(data, 24);
                hit.VelX      = BitConverter.ToSingle(data, 32);
                hit.VelY      = BitConverter.ToSingle(data, 36);
                hit.VelZ      = BitConverter.ToSingle(data, 40);
            }
            lock (_memLock) { MemHits.Add(hit); }
        }

        private void HandleRateLimit(byte[] pay)
        {
            if (pay.Length < 8) return;
            LastRateLimitSent       = (int)BitConverter.ToUInt32(pay, 0);
            LastRateLimitIntervalMs = (int)BitConverter.ToUInt32(pay, 4);
        }

        private void HandleEjected()
        {
            _state.AddInGameLog("[PIPE] DLL ejected itself — pipe closed");
            _dllConnected = false;
        }

        private void HandleKeylog(byte[] pay)
        {
            string line = System.Text.Encoding.ASCII.GetString(pay).TrimEnd('\0', '\n', '\r');
            if (string.IsNullOrWhiteSpace(line)) return;
            _state.ImportKeylogLine(line);
            _state.AddInGameLog($"[KEYLOG] {line[..Math.Min(80, line.Length)]}");
        }

        private void HandleMemWatch(byte[] pay)
        {
            if (pay.Length < 72) return;
            ulong  addr = BitConverter.ToUInt64(pay, 0);
            byte[] data = new byte[64];
            Buffer.BlockCopy(pay, 8, data, 0, 64);

            var entry = new MemWatchEntry
            {
                Address   = addr,
                Snapshot  = data,
                Timestamp = DateTime.Now,
            };
            if (data.Length >= 44)
            {
                entry.Health    = BitConverter.ToSingle(data, 0);
                entry.MaxHealth = BitConverter.ToSingle(data, 4);
                entry.X         = BitConverter.ToDouble(data, 8);
                entry.Y         = BitConverter.ToDouble(data, 16);
                entry.Z         = BitConverter.ToDouble(data, 24);
            }
            lock (_memLock)
            {
                MemWatchLog.Add(entry);
                if (MemWatchLog.Count > 500) MemWatchLog.RemoveAt(0);
            }
            _state.TriggerMemoryScan();
        }

        private void HandleStringScan(byte[] pay)
        {
            // Format: [8B addr][4B slen][UTF-8 string bytes, no null]
            if (pay.Length < 13) return;
            ulong  addr = BitConverter.ToUInt64(pay, 0);
            int    slen = (int)BitConverter.ToUInt32(pay, 8);
            int    avail = pay.Length - 12;
            if (avail <= 0) return;
            string text = System.Text.Encoding.UTF8.GetString(pay, 12, Math.Min(slen, avail));

            var hit = new StringHit { Address = addr, Text = text, FoundAt = DateTime.Now };
            lock (StringLock)
            {
                Strings.Add(hit);
                if (Strings.Count > 5000) Strings.RemoveAt(0);
            }
        }

        private void HandleModInfo(byte[] pay)
        {
            // Format: [8B base][4B size][ASCII name, null-terminated]
            if (pay.Length < 13) return;
            ulong  baseAddr = BitConverter.ToUInt64(pay, 0);
            uint   size     = BitConverter.ToUInt32(pay, 8);
            string name     = System.Text.Encoding.ASCII.GetString(pay, 12, pay.Length - 12)
                                                        .TrimEnd('\0');
            var info = new ModuleInfo { BaseAddress = baseAddr, Size = size, Name = name };
            lock (_modLock)
            {
                Modules.RemoveAll(m => m.Name == name);
                Modules.Add(info);
            }
        }

        private void HandleGadget(byte[] pay)
        {
            // Format: [8B addr][1B type][ASCII desc, null-terminated]
            if (pay.Length < 10) return;
            ulong  addr  = BitConverter.ToUInt64(pay, 0);
            byte   gtype = pay[8];
            string desc  = System.Text.Encoding.ASCII.GetString(pay, 9, pay.Length - 9)
                                                      .TrimEnd('\0');
            var hit = new GadgetHit
            {
                Address     = addr,
                GadgetType  = gtype,
                Description = desc,
                FoundAt     = DateTime.Now,
            };
            lock (_gadgetLock)
            {
                Gadgets.Add(hit);
                if (Gadgets.Count > 2000) Gadgets.RemoveAt(0);
            }
            _state.AddInGameLog($"[GADGET] 0x{addr:X16}  {desc}");
        }

        private void HandleExploitResult(byte[] pay)
        {
            string result = System.Text.Encoding.ASCII.GetString(pay).TrimEnd('\0');
            _state.AddInGameLog($"[EXPLOIT] {result}");
        }

        private void HandleProcDump(byte[] pay)
        {
            if (pay.Length < 12) return;
            ulong  addr = BitConverter.ToUInt64(pay, 0);
            uint   sz   = BitConverter.ToUInt32(pay, 8);
            int    avail = pay.Length - 12;
            string hex  = avail > 0
                ? BitConverter.ToString(pay, 12, Math.Min((int)sz, avail)).Replace("-", "")
                : "";
            _state.AddInGameLog(
                $"[DUMP] @0x{addr:X16} {sz}B  {hex[..Math.Min(64, hex.Length)]}{(hex.Length > 64 ? "..." : "")}");
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

    // ── Supporting data types ─────────────────────────────────────────────────────
    public class TimingEntry
    {
        public ulong TimestampUs { get; set; }
        public uint  Length      { get; set; }
        public byte  Dir         { get; set; }
    }

    public class MemScanHit
    {
        public ulong    Address     { get; set; }
        public float    Health      { get; set; }
        public float    MaxHealth   { get; set; }
        public double   X           { get; set; }
        public double   Y           { get; set; }
        public double   Z           { get; set; }
        public float    VelX        { get; set; }
        public float    VelY        { get; set; }
        public float    VelZ        { get; set; }
        public byte[]   StructBytes { get; set; } = Array.Empty<byte>();
        public DateTime FoundAt     { get; set; } = DateTime.Now;
        public string   Label       { get; set; } = "";
    }

    public class MemWatchEntry
    {
        public ulong    Address    { get; set; }
        public float    Health     { get; set; }
        public float    MaxHealth  { get; set; }
        public double   X          { get; set; }
        public double   Y          { get; set; }
        public double   Z          { get; set; }
        public byte[]   Snapshot   { get; set; } = Array.Empty<byte>();
        public DateTime Timestamp  { get; set; } = DateTime.Now;
    }

    public class ModuleInfo
    {
        public ulong  BaseAddress { get; set; }
        public uint   Size        { get; set; }
        public string Name        { get; set; } = "";
    }

    public class GadgetHit
    {
        public ulong    Address     { get; set; }
        public byte     GadgetType  { get; set; }
        public string   Description { get; set; } = "";
        public DateTime FoundAt     { get; set; } = DateTime.Now;
    }

    public class StringHit
    {
        public ulong    Address { get; set; }
        public string   Text    { get; set; } = "";
        public DateTime FoundAt { get; set; } = DateTime.Now;
    }
}
