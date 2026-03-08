// Core/OpcodeScanner.cs  v20
// Brute-forces C2S opcode space 0x0001..0x01FF with empty frames.
// Tracks for each opcode:
//   - Whether the server disconnected (strong: opcode exists, server rejected)
//   - Whether new S2C opcodes arrived within a window (server processed it)
//   - Round-trip latency delta (compares S2C rate before vs after send)
//
// Results feed OpcodeScannerTab heatmap.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace HyForce.Core;

public enum OpcodeResponse
{
    Pending,
    Silent,         // no new S2C, no disconnect
    S2CTriggered,   // new S2C opcode observed shortly after
    Disconnected,   // pipe dropped (server rejected and closed)
    RateBlocked,    // repeated sends got rate-limited response
}

public class OpcodeResult
{
    public ushort        Opcode       { get; set; }
    public OpcodeResponse Response   { get; set; } = OpcodeResponse.Pending;
    public List<ushort>  TriggeredS2C { get; } = new();
    public double        LatencyDeltaMs { get; set; }   // S2C rate change
    public DateTime      SentAt       { get; set; }
    public string        Notes        { get; set; } = "";
}

public class OpcodeScanner
{
    private readonly ConcurrentDictionary<ushort, OpcodeResult> _results = new();
    private readonly List<string>   _log     = new();
    private readonly object         _logLock = new();
    private CancellationTokenSource? _cts;

    // Rolling S2C opcode window for response detection
    private readonly Queue<(DateTime t, ushort op)> _recentS2C = new();
    private readonly object _s2cLock = new();
    private ushort _lastTestedOpcode;
    private DateTime _lastSendTime;

    public bool   IsScanning    { get; private set; }
    public int    Progress      { get; private set; }
    public int    Total         { get; private set; }
    public ushort CurrentOpcode { get; private set; }

    // Callbacks
    public Action<byte[]>? SendRaw { get; set; }   // sends raw frame bytes via pipe

    public IReadOnlyDictionary<ushort, OpcodeResult> Results => _results;
    public IReadOnlyList<string> Log { get { lock (_logLock) return _log.ToList(); } }
    public event Action<string>? OnLog;

    // Called from AppState routing for every S2C packet
    public void ObserveS2C(ushort opcode)
    {
        lock (_s2cLock) _recentS2C.Enqueue((DateTime.UtcNow, opcode));
        // Check if this arrived shortly after a probe send
        if (_lastSendTime != default && (DateTime.UtcNow - _lastSendTime).TotalMilliseconds < 800)
        {
            if (_results.TryGetValue(_lastTestedOpcode, out var r) && r.Response == OpcodeResponse.Pending)
            {
                if (!r.TriggeredS2C.Contains(opcode))
                {
                    r.TriggeredS2C.Add(opcode);
                    r.Response = OpcodeResponse.S2CTriggered;
                    AddLog($"[SCAN] 0x{_lastTestedOpcode:X4} → triggered S2C 0x{opcode:X4}");
                }
            }
        }
    }

    public void StartScan(ushort start = 0x0001, ushort end = 0x01FF, int delayMs = 250)
    {
        if (IsScanning) return;
        _cts      = new CancellationTokenSource();
        var tok   = _cts.Token;
        Total     = end - start + 1;
        Progress  = 0;
        IsScanning = true;
        AddLog($"[SCAN] Starting opcode scan 0x{start:X4}..0x{end:X4}  delay={delayMs}ms");

        Task.Run(async () =>
        {
            try
            {
                for (ushort op = start; op <= end && !tok.IsCancellationRequested; op++)
                {
                    CurrentOpcode = op;
                    var r = _results.GetOrAdd(op, id => new OpcodeResult { Opcode = id });
                    r.SentAt  = DateTime.UtcNow;
                    r.Response = OpcodeResponse.Pending;

                    // Build empty frame: [4B flen=4][2B op][2B pad]
                    byte[] frame = new byte[8];
                    BitConverter.GetBytes((uint)4).CopyTo(frame, 0);
                    BitConverter.GetBytes(op).CopyTo(frame, 4);
                    _lastTestedOpcode = op;
                    _lastSendTime     = DateTime.UtcNow;
                    SendRaw?.Invoke(frame);

                    await Task.Delay(delayMs, tok);

                    if (r.Response == OpcodeResponse.Pending)
                        r.Response = OpcodeResponse.Silent;

                    Progress++;
                    if (Progress % 32 == 0)
                        AddLog($"[SCAN] Progress {Progress}/{Total}  last=0x{op:X4}");
                }
                AddLog($"[SCAN] Done — {_results.Values.Count(r => r.Response == OpcodeResponse.S2CTriggered)} responsive opcodes");
            }
            catch (OperationCanceledException) { AddLog("[SCAN] Cancelled"); }
            finally { IsScanning = false; }
        }, tok);
    }

    public void StopScan() { _cts?.Cancel(); IsScanning = false; }

    public List<OpcodeResult> GetResponsive() =>
        _results.Values.Where(r => r.Response == OpcodeResponse.S2CTriggered).OrderBy(r => r.Opcode).ToList();

    public List<OpcodeResult> GetAll() =>
        _results.Values.OrderBy(r => r.Opcode).ToList();

    public void Clear() { _results.Clear(); AddLog("[SCAN] Cleared"); }

    private void AddLog(string msg)
    {
        var line = $"[{DateTime.Now:HH:mm:ss.fff}] {msg}";
        lock (_logLock) { _log.Add(line); if (_log.Count > 1000) _log.RemoveAt(0); }
        OnLog?.Invoke(line);
    }
}
