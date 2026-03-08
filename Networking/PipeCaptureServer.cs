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
        public readonly List<MemReadResult>  MemReadResults = new();
        public readonly List<TimingEntry>   TimingLog    = new();
        public readonly List<string>        SeqAnomalies = new();
        public readonly List<MemWatchEntry> MemWatchLog  = new();
        public readonly List<ModuleInfo>    Modules      = new();
        public readonly List<GadgetHit>     Gadgets      = new();
        public readonly List<StringHit>     Strings      = new();
        public readonly List<PlaintextEntry> PlaintextPackets = new();
        public readonly object              StringLock   = new();
        public readonly object              PlaintextLock = new();

        public const int MAX_TIMING = 2000;
        public int LastRateLimitSent;
        public int LastRateLimitIntervalMs;

        // ── Diagnostics properties (for DiagnosticsCollector) ────────────────
        public DateTime StartedAt       { get; private set; } = DateTime.Now;
        public DateTime LastMessageAt   { get; private set; } = DateTime.MinValue;
        public int  S2cCount            { get; private set; }
        public int  C2sCount            { get; private set; }
        public int  TcpCount            { get; private set; }
        // Hook fire counts from DLL STATS reply
        public long StatWSASendTo       { get; private set; }
        public long StatSendTo          { get; private set; }
        public long StatWSARecvFrom     { get; private set; }
        public long StatRecvFrom        { get; private set; }

        // ── MemoryToggleSystem hookup ─────────────────────────────────────────
        // Set this after construction so HandleMemRead can forward read-backs
        public HyForce.Core.MemoryToggleSystem? ToggleSystem { get; set; }

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

        // ── Freeze / write helpers ────────────────────────────────
        public void FreezeHp(ulong address, float hp, float maxHp)
            => SendCommand($"FREEZE_HP {address:X} {hp:G6} {maxHp:G6}");
        public void FreezeHpStop()
            => SendCommand("FREEZE_HP_STOP");
        public void FreezePos(ulong address, double x, double y, double z)
            => SendCommand($"FREEZE_POS {address:X} {x:G10} {y:G10} {z:G10}");
        public void FreezePosStop()
            => SendCommand("FREEZE_POS_STOP");
        public void MemWriteF32(ulong address, float value)
            => SendCommand($"MEMWRITE_F32 {address:X} {value:G6}");


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
                    case 0x15: HandlePlaintext(pay);     break;
                    case 0x16: HandleQuicStream(pay);    break;  // v16 msquic plaintext
                    case 0x17: HandleQuicEvent(pay);     break;  // v16 stream lifecycle
                    case 0x1C: HandleMemRead(pay);       break;
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

            if (pkt.Direction == PacketDirection.ServerToClient) S2cCount++;
            else C2sCount++;
            if (pkt.IsTcp) TcpCount++;

            Interlocked.Increment(ref _packetCount);
            LastMessageAt = _lastPkt = DateTime.Now;
            OnPacketReceived?.Invoke(pkt);
        }

        private void HandleStatus(byte[] pay)
        {
            _dllStatus = System.Text.Encoding.ASCII.GetString(pay).TrimEnd('\0');
            _state.AddInGameLog($"[DLL] {_dllStatus}");
            LastMessageAt = DateTime.Now;
        }

        private void HandleLog(byte[] pay)
        {
            string msg = System.Text.Encoding.ASCII.GetString(pay).TrimEnd('\0');
            _state.AddInGameLog($"[DLL] {msg}");
            LastMessageAt = DateTime.Now;

            // Parse STATS line from DLL: "[STATS] WSASendTo:N sendto:N WSARecvFrom:N recvfrom:N pkts:N"
            if (msg.Contains("[STATS]"))
            {
                try
                {
                    long Parse(string key)
                    {
                        int i = msg.IndexOf(key + ":");
                        if (i < 0) return 0;
                        i += key.Length + 1;
                        int end = i;
                        while (end < msg.Length && (char.IsDigit(msg[end]) || msg[end] == '-')) end++;
                        return long.TryParse(msg[i..end], out long v) ? v : 0;
                    }
                    StatWSASendTo  = Parse("WSASendTo");
                    StatSendTo     = Parse("sendto");
                    StatWSARecvFrom= Parse("WSARecvFrom");
                    StatRecvFrom   = Parse("recvfrom");
                }
                catch { }
            }
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

        private readonly object _memReadLock = new();
        private void HandleMemRead(byte[] pay)
        {
            if (pay.Length < 8) return;
            ulong addr = BitConverter.ToUInt64(pay, 0);
            byte[] data = new byte[pay.Length - 8];
            if (data.Length > 0) Buffer.BlockCopy(pay, 8, data, 0, data.Length);
            var result = new MemReadResult { Address = addr, Data = data, ReadAt = DateTime.Now };
            lock (_memReadLock) { MemReadResults.Add(result); if (MemReadResults.Count > 200) MemReadResults.RemoveAt(0); }
            _state.AddInGameLog($"[MEMREAD] 0x{addr:X14}: {data.Length}B → {BitConverter.ToString(data.Take(16).ToArray()).Replace("-"," ")}");
            // Forward to ToggleSystem for write confirmation
            ToggleSystem?.OnMemReadResult(addr, data);
            LastMessageAt = DateTime.Now;
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

        private void HandlePlaintext(byte[] pay)
        {
            // MSG_PLAINTEXT layout: 1B direction, 4B IP, 2B port, rest = plaintext app data
            if (pay.Length < 7) return;
            byte   dir   = pay[0];
            uint   ipRaw = BitConverter.ToUInt32(pay, 1);
            ushort port  = BitConverter.ToUInt16(pay, 5);
            int    dLen  = pay.Length - 7;
            if (dLen <= 0) return;

            byte[] data = new byte[dLen];
            Array.Copy(pay, 7, data, 0, dLen);

            var ip = new System.Net.IPAddress(ipRaw).ToString();
            var entry = new PlaintextEntry
            {
                Timestamp  = DateTime.UtcNow,
                Direction  = dir == 0 ? "C→S" : "S→C",
                RemoteAddr = $"{ip}:{port}",
                Data       = data,
                HexPreview = BitConverter.ToString(data, 0, Math.Min(32, data.Length)).Replace("-", " ")
            };

            lock (PlaintextLock)
            {
                PlaintextPackets.Add(entry);
                if (PlaintextPackets.Count > 2000)
                    PlaintextPackets.RemoveAt(0);
            }
            _state.AddInGameLog($"[PLAIN] {entry.Direction} {entry.RemoteAddr}  {dLen}B  {entry.HexPreview[..Math.Min(32, entry.HexPreview.Length)]}");
        }

        public readonly List<QuicStreamEntry> QuicStreamPackets = new();
        public readonly object                QuicStreamLock    = new();
        public event Action<QuicStreamEntry>? OnQuicStream;

        private void HandleQuicStream(byte[] pay)
        {
            // [u8 dir][u64 stream_handle][u32 data_len][data]
            if (pay.Length < 13) return;
            byte   dir    = pay[0];
            ulong  handle = BitConverter.ToUInt64(pay, 1);
            uint   dLen   = BitConverter.ToUInt32(pay, 9);
            if (pay.Length < 13 + (int)dLen) return;
            byte[] data = new byte[dLen];
            Array.Copy(pay, 13, data, 0, (int)dLen);

            string dirStr = dir == 0xC2 ? "C→S" : dir >= 0xD0 ? $"DUP-{dir & 0x0F}" : "S→C"; // 0x52=S2C, 0xC2=C2S
            var entry = new QuicStreamEntry
            {
                Timestamp   = DateTime.UtcNow,
                StreamHandle = handle,
                Direction   = dirStr,
                Data        = data,
                HexPreview  = BitConverter.ToString(data, 0, Math.Min(32, data.Length)).Replace("-", " ")
            };

            lock (QuicStreamLock)
            {
                QuicStreamPackets.Add(entry);
                if (QuicStreamPackets.Count > 5000) QuicStreamPackets.RemoveAt(0);
            }
            OnQuicStream?.Invoke(entry);
            _state.AddInGameLog($"[QUIC-PLAIN] {dirStr} stream=0x{handle:X}  {dLen}B  {entry.HexPreview[..Math.Min(48, entry.HexPreview.Length)]}");
        }

        private void HandleQuicEvent(byte[] pay)
        {
            if (pay.Length < 9) return;
            byte  evType = pay[0];
            ulong handle = BitConverter.ToUInt64(pay, 1);
            _state.AddInGameLog($"[QUIC-EV] stream=0x{handle:X}  ev={evType}");
        }

        // v16 msquic command helpers
        public void QuicProbe()                          => SendCommand("QUIC_PROBE");
        public void QuicListStreams()                    => SendCommand("QUIC_STREAMS");
        public void QuicSetRaceDelay(int ms)             => SendCommand($"QUIC_RACE {ms}");
        public void QuicFuzzStream(int bits)             => SendCommand($"QUIC_FUZZ_STREAM {bits}");
        public void QuicDuplicate(int count)             => SendCommand($"QUIC_DUP {count}");
        public void QuicDropNext()                       => SendCommand("QUIC_DROP");
        public void QuicReplayStream()                   => SendCommand("QUIC_REPLAY_STREAM");
        public void QuicInject(byte[] data)              => SendCommand($"QUIC_INJECT {BitConverter.ToString(data).Replace("-", "").ToLower()}");

        // v16 C2S filter helpers
        public void QuicDropC2S(uint opcode)             => SendCommand(opcode == 0 ? "QUIC_DROP_C2S 0" : $"QUIC_DROP_C2S {opcode:X4}");
        public void QuicDupC2S(uint opcode, int count)   => SendCommand(opcode == 0 ? "QUIC_DUP_C2S 0 0" : $"QUIC_DUP_C2S {opcode:X4} {count}");
        public void QuicC2SLogOn()                       => SendCommand("QUIC_C2S_LOG_ON");
        public void QuicC2SLogOff()                      => SendCommand("QUIC_C2S_LOG_OFF");
        public void QuicC2SStats()                       => SendCommand("QUIC_C2S_STATS");

        // v16 position / teleport / interaction forge
        public void Teleport(float x, float y, float z)      => SendCommand($"TELEPORT {x:G6} {y:G6} {z:G6}");
        public void PosOverride(float x, float y, float z)   => SendCommand($"POS_OVERRIDE {x:G6} {y:G6} {z:G6}");
        public void PosOverrideOff()                          => SendCommand("POS_OVERRIDE_OFF");
        public void SpeedMultiplier(float mul)                => SendCommand($"SPEED_MUL {mul:G6}");
        public void SpeedMultiplierOff()                      => SendCommand("SPEED_MUL_OFF");
        public void ForgeStream(byte[] payload)               => SendCommand($"FORGE_STREAM {BitConverter.ToString(payload).Replace("-","").ToLower()}");

        // v17 chat / permission / admin / S2C filter
        public void SendChat(byte[] utf8Payload)               => SendCommand($"SEND_CHAT {BitConverter.ToString(utf8Payload).Replace("-","").ToLower()}");
        public void SetGameMode(uint mode)                     => SendCommand($"SET_GAMEMODE {mode}");
        public void ReplaySetup(byte[] patchedPayload)         => SendCommand($"REPLAY_SETUP {BitConverter.ToString(patchedPayload).Replace("-","").ToLower()}");
        public void KickEntity(ulong entityId)                 => SendCommand($"KICK_ENTITY {entityId:X16}");
        public void AdminCmd(ushort opcode, byte[] payload)    => SendCommand($"ADMIN_CMD {opcode:X4} {BitConverter.ToString(payload).Replace("-","").ToLower()}");
        public void S2CDropOpcode(uint opcode)                 => SendCommand($"S2C_DROP_OPCODE {opcode:X4}");

        // v18
        public void AutoPongOn()                               => SendCommand("AUTO_PONG_ON");
        public void AutoPongOff()                              => SendCommand("AUTO_PONG_OFF");
        public void BlockPlace(int x, int y, int z, uint typeId, uint face = 0) => SendCommand($"BLOCK_PLACE {x} {y} {z} {typeId:X} {face}");
        public void BlockBreak(int x, int y, int z)            => SendCommand($"BLOCK_BREAK {x} {y} {z}");
        public void SetEntityProp(ulong eid, uint prop, byte[] val) => SendCommand($"SET_ENTITY_PROP {eid:X16} {prop} {BitConverter.ToString(val).Replace("-","").ToLower()}");
        public void RecordOn()                                 => SendCommand("RECORD_ON");
        public void RecordOff()                                => SendCommand("RECORD_OFF");
        public void RecordClear()                              => SendCommand("RECORD_CLEAR");
        public void RecordStats()                              => SendCommand("RECORD_STATS");
        public void SpoofS2C(byte[] payload)                   => SendCommand($"SPOOF_S2C {BitConverter.ToString(payload).Replace("-","").ToLower()}");
        public void TradeCaptureOn()                           => SendCommand("TRADE_CAPTURE_ON");
        public void TradeCaptureOff()                          => SendCommand("TRADE_CAPTURE_OFF");

        // v19
        public void VelocityLaunch(float vx, float vy, float vz) => SendCommand($"VELOCITY_LAUNCH {vx:G6} {vy:G6} {vz:G6}");
        public void VelocityLaunchOff()                           => SendCommand("VELOCITY_LAUNCH_OFF");
        public void TimeSet(uint ticks)                            => SendCommand($"TIME_SET {ticks}");
        public void WeatherSet(uint type)                          => SendCommand($"WEATHER_SET {type}");
        public void RespawnForce()                                 => SendCommand("RESPAWN_FORCE");
        public void EntityScan(ulong eid)                          => SendCommand($"ENTITY_SCAN {eid:X16}");
        public void EntityScanStop()                               => SendCommand("ENTITY_SCAN_STOP");
        public void SpectateOn()                                   => SendCommand("SPECTATE_ON");
        public void SpectateOff()                                  => SendCommand("SPECTATE_OFF");
        public void NoclipOn()                                     => SendCommand("NOCLIP_ON");
        public void NoclipOff()                                    => SendCommand("NOCLIP_OFF");
        public void InfiniteReachOn()                              => SendCommand("INF_REACH_ON");
        public void InfiniteReachOff()                             => SendCommand("INF_REACH_OFF");

        // v20
        public void InvSnapshot()                                  => SendCommand("INV_SNAPSHOT");
        public void InvLockOn()                                    => SendCommand("INV_LOCK_ON");
        public void InvLockOff()                                   => SendCommand("INV_LOCK_OFF");
        public void InvCacheSet(byte[] payload)                    => SendCommand($"INV_CACHE_SET {BitConverter.ToString(payload).Replace("-","").ToLower()}");
        public void DupeSlot(uint src, uint dst, uint count, uint repeat) => SendCommand($"DUPE_SLOT {src} {dst} {count} {repeat}");
        public void WindowSteal(uint windowId, uint containerSlot, uint playerSlot) => SendCommand($"WINDOW_STEAL {windowId} {containerSlot} {playerSlot}");
        public void ItemSpamStart(uint typeId, uint slot, uint count, uint delayMs) => SendCommand($"ITEM_SPAM_START {typeId:X} {slot} {count} {delayMs}");
        public void ItemSpamStop()                                 => SendCommand("ITEM_SPAM_STOP");
        public void PermTestBit(int bit)                           => SendCommand($"PERM_TEST_BIT {bit}");
        public void PermInjectMask(uint mask)                      => SendCommand($"PERM_INJECT_MASK {mask:X8}");
        public void OpcodeFuzzStart(uint start, uint end, uint delayMs) => SendCommand($"OPCODE_FUZZ_START {start:X} {end:X} {delayMs}");
        public void OpcodeFuzzStop()                               => SendCommand("OPCODE_FUZZ_STOP");
        public void OpcodeFuzzStatus()                             => SendCommand("OPCODE_FUZZ_STATUS");
        public void WaypointAdd(float x, float y, float z)        => SendCommand($"WAYPOINT_ADD {x:G6} {y:G6} {z:G6}");
        public void WaypointClear()                                => SendCommand("WAYPOINT_CLEAR");
        public void WaypointRun(uint delayMs)                      => SendCommand($"WAYPOINT_RUN {delayMs}");
        public void WaypointStop()                                 => SendCommand("WAYPOINT_STOP");
        public void WaypointStatus()                               => SendCommand("WAYPOINT_STATUS");
        public void ScriptExec(string script)                      => SendCommand($"SCRIPT_EXEC {BitConverter.ToString(System.Text.Encoding.UTF8.GetBytes(script)).Replace("-","").ToLower()}");
        public void ScriptStop()                                   => SendCommand("SCRIPT_STOP");

        public void QuicheProbe() => SendCommand("QUICHEPROBE");
        public void MemScanBroad()                           => SendCommand("MEMSCAN_BROAD");
        public void MemRead(ulong address, uint size = 64)   => SendCommand($"MEMREAD {address:X} {size}");
        public void MemWriteF64(ulong address, double value) => SendCommand($"MEMWRITE_F64 {address:X} {value:G15}");
        public void MemWriteI32(ulong address, int value)    => SendCommand($"MEMWRITE_I32 {address:X} {value}");
        public void MemWriteU8(ulong address, byte value)    => SendCommand($"MEMWRITE_U8 {address:X} {value}");
        public void FreezeGeneric(int slot, ulong address, string dtype, string value, int intervalMs = 50)
            => SendCommand($"FREEZE_GENERIC {slot} {address:X} {dtype} {value} {intervalMs}");
        public void FreezeGenericStop(int slot) => SendCommand($"FREEZE_GENERIC_STOP {slot}");
        public void FreezeAllStop() => SendCommand("FREEZE_ALL_STOP");

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
    public class QuicStreamEntry
    {
        public DateTime Timestamp    { get; set; }
        public ulong    StreamHandle { get; set; }
        public string   Direction    { get; set; } = "";
        public byte[]   Data         { get; set; } = Array.Empty<byte>();
        public string   HexPreview   { get; set; } = "";
        public string   AsciiPreview => System.Text.Encoding.ASCII.GetString(
            Array.ConvertAll(Data, b => b is >= 32 and < 127 ? b : (byte)'.'));
    }

    public class PlaintextEntry
    {
        public DateTime Timestamp  { get; set; }
        public string   Direction  { get; set; } = "";
        public string   RemoteAddr { get; set; } = "";
        public byte[]   Data       { get; set; } = Array.Empty<byte>();
        public string   HexPreview { get; set; } = "";
    }

    public class TimingEntry
    {
        public ulong TimestampUs { get; set; }
        public uint  Length      { get; set; }
        public byte  Dir         { get; set; }
    }

    public class MemReadResult
    {
        public ulong    Address { get; set; }
        public byte[]   Data    { get; set; } = Array.Empty<byte>();
        public DateTime ReadAt  { get; set; } = DateTime.Now;
        public float    AsF32(int offset = 0) => offset + 4 <= Data.Length ? BitConverter.ToSingle(Data, offset) : float.NaN;
        public double   AsF64(int offset = 0) => offset + 8 <= Data.Length ? BitConverter.ToDouble(Data, offset) : double.NaN;
        public int      AsI32(int offset = 0) => offset + 4 <= Data.Length ? BitConverter.ToInt32(Data, offset) : 0;
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
