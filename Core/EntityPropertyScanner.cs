// Core/EntityPropertyScanner.cs  v19
// Probes entity property IDs by forging 0xA6 SetEntityProperty and watching
// for server rejection (disconnect) vs acceptance (no response = silently applied).
// Also parses property deltas from 0xA1 EntityUpdates extended component data.
//
// Scan flow:
//   1. C# starts scan: calls pipe.EntityScan(eid) → C hook iterates propId 0..N
//   2. For each propId, hook forges a null-valued SetEntityProperty
//   3. Server either ignores, applies, or drops the connection
//   4. C# monitors: if connection stays alive after N ms → property accepted
//   5. Results stored with propId + status + any observed entity delta

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace HyForce.Core;

public enum PropScanStatus { Pending, Sent, Accepted, Rejected, Unknown }

public class EntityPropResult
{
    public uint            PropId     { get; set; }
    public PropScanStatus  Status     { get; set; } = PropScanStatus.Unknown;
    public byte[]          LastValue  { get; set; } = Array.Empty<byte>();
    public string          Notes      { get; set; } = "";
    public DateTime        TriedAt    { get; set; } = DateTime.UtcNow;
}

public class KnownProp
{
    public uint   PropId      { get; set; }
    public string Name        { get; set; } = "";
    public string ValueType   { get; set; } = "uint32"; // uint32, float, bool, string
    public string Description { get; set; } = "";
}

public class EntityPropertyScanner
{
    // Known property definitions discovered via scan + manual research
    private readonly List<KnownProp> _knownProps = new()
    {
        new() { PropId=0x01, Name="MaxHealth",    ValueType="float",  Description="Entity max HP" },
        new() { PropId=0x02, Name="MoveSpeed",    ValueType="float",  Description="Movement speed multiplier" },
        new() { PropId=0x03, Name="Scale",        ValueType="float",  Description="Entity scale" },
        new() { PropId=0x04, Name="Gravity",      ValueType="float",  Description="Gravity scale (0=no fall)" },
        new() { PropId=0x05, Name="IsInvincible", ValueType="bool",   Description="Damage immunity flag" },
        new() { PropId=0x06, Name="IsVisible",    ValueType="bool",   Description="Visibility flag" },
        new() { PropId=0x07, Name="AttackDamage", ValueType="float",  Description="Melee damage output" },
        new() { PropId=0x08, Name="AttackRange",  ValueType="float",  Description="Melee reach range" },
        new() { PropId=0x09, Name="FollowTarget", ValueType="uint32", Description="Entity ID to follow" },
        new() { PropId=0x0A, Name="AIBehavior",   ValueType="uint32", Description="Behavior state flags" },
    };

    private readonly ConcurrentDictionary<uint, EntityPropResult> _results = new();
    private readonly List<string> _log    = new();
    private readonly object       _logLock= new();

    private CancellationTokenSource? _scanCts;
    public  bool  IsScanning   { get; private set; }
    public  int   ScanProgress { get; private set; }
    public  int   ScanTotal    { get; private set; }
    public  ulong ScanTargetEid{ get; private set; }

    // Callback wired from tab to send via pipe
    public Action<ulong, uint, byte[]>? SendPropForge { get; set; }

    public IReadOnlyList<KnownProp>                  KnownProps => _knownProps;
    public IReadOnlyDictionary<uint,EntityPropResult> Results   => _results;
    public IReadOnlyList<string> Log { get { lock (_logLock) return _log.ToList(); } }
    public event Action<string>? OnLog;

    // ── Manual single set ────────────────────────────────────────────────
    public void SetProp(ulong eid, uint propId, byte[] value)
    {
        SendPropForge?.Invoke(eid, propId, value);
        var r = _results.GetOrAdd(propId, id => new EntityPropResult { PropId=id });
        r.LastValue = value;
        r.Status    = PropScanStatus.Sent;
        r.TriedAt   = DateTime.UtcNow;
        string name = _knownProps.FirstOrDefault(p => p.PropId == propId)?.Name ?? $"Prop_0x{propId:X2}";
        AddLog($"[PROP] Set {name} (0x{propId:X2}) on 0x{eid:X}  val=[{BitConverter.ToString(value).Replace("-"," ")}]");
    }

    public void SetPropFloat(ulong eid, uint propId, float value)    => SetProp(eid, propId, BitConverter.GetBytes(value));
    public void SetPropUint(ulong eid, uint propId, uint value)       => SetProp(eid, propId, BitConverter.GetBytes(value));
    public void SetPropBool(ulong eid, uint propId, bool value)       => SetProp(eid, propId, new[]{ value ? (byte)1 : (byte)0 });

    // ── Scan loop ────────────────────────────────────────────────────────
    public void StartScan(ulong eid, uint startId = 0, uint endId = 255, int delayMs = 300)
    {
        if (IsScanning) { AddLog("[SCAN] Already scanning"); return; }
        _scanCts = new CancellationTokenSource();
        var tok  = _scanCts.Token;
        ScanTargetEid = eid;
        ScanTotal     = (int)(endId - startId + 1);
        ScanProgress  = 0;
        _results.Clear();
        IsScanning = true;
        AddLog($"[SCAN] Starting prop scan  eid=0x{eid:X}  range=0x{startId:X2}..0x{endId:X2}  delay={delayMs}ms");

        Task.Run(async () =>
        {
            try
            {
                byte[] zeroVal = new byte[4];
                for (uint pid = startId; pid <= endId; pid++)
                {
                    if (tok.IsCancellationRequested) break;
                    var r = _results.GetOrAdd(pid, id => new EntityPropResult { PropId=id, Status=PropScanStatus.Pending });
                    SendPropForge?.Invoke(eid, pid, zeroVal);
                    r.Status = PropScanStatus.Sent;
                    r.TriedAt = DateTime.UtcNow;
                    ScanProgress++;
                    if (ScanProgress % 16 == 0)
                        AddLog($"[SCAN] Progress {ScanProgress}/{ScanTotal}  last=0x{pid:X2}");
                    await Task.Delay(delayMs, tok);
                }
                AddLog($"[SCAN] Done — {ScanProgress} props probed");
            }
            catch (OperationCanceledException) { AddLog("[SCAN] Cancelled"); }
            finally { IsScanning = false; }
        }, tok);
    }

    public void StopScan() { _scanCts?.Cancel(); IsScanning = false; }

    public void AddKnownProp(KnownProp p) { _knownProps.Add(p); }

    public void Clear() { _results.Clear(); AddLog("[SCAN] Results cleared"); }

    private void AddLog(string msg)
    {
        var line = $"[{DateTime.Now:HH:mm:ss.fff}] {msg}";
        lock (_logLock) { _log.Add(line); if (_log.Count > 1000) _log.RemoveAt(0); }
        OnLog?.Invoke(line);
    }
}
