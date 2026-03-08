// Core/ItemDuplicator.cs  v20
// Manages item duplication and theft exploits.
//
// Techniques:
//   Slot dupe     — rapid-fire 0xAF MoveItemStack(src→dst) sends before server
//                   can verify. Server may apply first N moves without checking.
//   Drop dupe     — send DropItemStack then immediately SetCreativeItem on same slot.
//   Window steal  — forge 0xCB SendWindowAction to pull items from any open window
//                   without matching the real trade flow.
//   Item spam     — continuously inject SetCreativeItem for a target type ID.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using HyForce.Networking;

namespace HyForce.Core;

public class DupeJob
{
    public Guid     Id          { get; } = Guid.NewGuid();
    public string   Label       { get; set; } = "";
    public string   Technique   { get; set; } = "SlotDupe";
    public uint     SrcSlot     { get; set; }
    public uint     DstSlot     { get; set; }
    public uint     ItemTypeId  { get; set; }
    public uint     Count       { get; set; } = 1;
    public uint     Repeat      { get; set; } = 8;
    public uint     DelayMs     { get; set; } = 0;
    public int      Sent        { get; set; }
    public DateTime StartedAt   { get; set; } = DateTime.UtcNow;
    public bool     IsRunning   { get; set; }
    public string   Result      { get; set; } = "";
}

public class WindowStealConfig
{
    public uint WindowId       { get; set; }
    public uint ContainerSlot  { get; set; }
    public uint PlayerSlot     { get; set; }
    public int  RepeatCount    { get; set; } = 1;
    public int  DelayMs        { get; set; } = 50;
}

public class ItemDuplicator
{
    private readonly List<DupeJob>   _history  = new();
    private readonly List<string>    _log      = new();
    private readonly object          _logLock  = new();
    private CancellationTokenSource? _spamCts;

    public bool    IsSpamming     { get; private set; }
    public uint    SpamTypeId     { get; private set; }
    public long    TotalSent      { get; private set; }

    public IReadOnlyList<DupeJob> History => _history;
    public IReadOnlyList<string>  Log { get { lock (_logLock) return _log.ToList(); } }
    public event Action<string>?  OnLog;

    // Pipe callbacks wired from AppState
    public Action<uint,uint,uint,uint>?              DupeSlotCmd     { get; set; }  // src,dst,count,repeat
    public Action<uint,uint,uint>?                   WindowStealCmd  { get; set; }  // wid,cslot,pslot
    public Action<uint,uint,uint,uint>?              ItemSpamStartCmd{ get; set; }  // typeId,slot,count,delayMs
    public Action?                                   ItemSpamStopCmd { get; set; }
    public Func<ushort,byte[],System.IO.Stream>?     ForgeRaw        { get; set; }

    // ── Slot dupe ────────────────────────────────────────────────────────
    public DupeJob SlotDupe(uint src, uint dst, uint count, uint repeat, uint delayMs = 0)
    {
        var job = new DupeJob { Label=$"SlotDupe {src}→{dst}", Technique="SlotDupe",
            SrcSlot=src, DstSlot=dst, Count=count, Repeat=repeat, DelayMs=delayMs, IsRunning=true };
        _history.Add(job);
        if (_history.Count > 100) _history.RemoveAt(0);

        DupeSlotCmd?.Invoke(src, dst, count, repeat);
        job.Sent    = (int)repeat;
        job.Result  = $"Sent {repeat} × MoveItemStack";
        job.IsRunning = false;
        AddLog($"[DUPE] SlotDupe {src}→{dst} count={count} ×{repeat}  {(delayMs>0?$"delay={delayMs}ms":"")}");
        TotalSent += repeat;
        return job;
    }

    // ── Drop dupe: DropItemStack then immediate SetCreativeItem ──────────
    public async Task<DupeJob> DropDupe(uint slot, uint typeId, uint count, uint repeat,
        PipeCaptureServer pipe)
    {
        var job = new DupeJob { Label=$"DropDupe slot={slot} type=0x{typeId:X}", Technique="DropDupe",
            SrcSlot=slot, ItemTypeId=typeId, Count=count, Repeat=repeat, IsRunning=true };
        _history.Add(job);

        AddLog($"[DUPE] DropDupe slot={slot} typeId=0x{typeId:X} ×{repeat}");
        for (int i = 0; i < repeat; i++)
        {
            pipe.ForgeStream(BuildDropItemStack(slot, count));
            await Task.Delay(1);
            pipe.ForgeStream(BuildSetCreativeItem(slot, typeId, count));
            job.Sent++;
            TotalSent++;
        }
        job.IsRunning = false;
        job.Result = $"Sent {repeat} DropItem+SetCreative pairs";
        return job;
    }

    // ── Window steal ─────────────────────────────────────────────────────
    public DupeJob WindowSteal(WindowStealConfig cfg)
    {
        var job = new DupeJob { Label=$"WindowSteal wid={cfg.WindowId} c[{cfg.ContainerSlot}]→p[{cfg.PlayerSlot}]",
            Technique="WindowSteal", IsRunning=true };
        _history.Add(job);

        for (int i = 0; i < cfg.RepeatCount; i++)
        {
            WindowStealCmd?.Invoke(cfg.WindowId, cfg.ContainerSlot, cfg.PlayerSlot);
            job.Sent++;
            TotalSent++;
            if (cfg.DelayMs > 0) Thread.Sleep(cfg.DelayMs);
        }
        job.IsRunning = false;
        job.Result = $"Sent {cfg.RepeatCount} WindowAction(steal) frames";
        AddLog($"[STEAL] wid={cfg.WindowId} container[{cfg.ContainerSlot}]→player[{cfg.PlayerSlot}] ×{cfg.RepeatCount}");
        return job;
    }

    // ── Full window drain: steal all container slots ─────────────────────
    public DupeJob DrainWindow(uint windowId, uint containerSlots, uint playerSlotStart, int delayMs=30)
    {
        var job = new DupeJob { Label=$"DrainWindow wid={windowId} {containerSlots} slots", Technique="DrainWindow" };
        _history.Add(job);
        for (uint s = 0; s < containerSlots; s++)
        {
            WindowStealCmd?.Invoke(windowId, s, playerSlotStart + s);
            job.Sent++;
            TotalSent++;
            if (delayMs > 0) Thread.Sleep(delayMs);
        }
        job.Result = $"Drained {containerSlots} slots from window {windowId}";
        AddLog($"[DRAIN] Window {windowId}: {containerSlots} slots → player inventory");
        return job;
    }

    // ── Item spam ────────────────────────────────────────────────────────
    public void StartItemSpam(uint typeId, uint slot, uint count, uint delayMs)
    {
        IsSpamming  = true;
        SpamTypeId  = typeId;
        ItemSpamStartCmd?.Invoke(typeId, slot, count, delayMs);
        AddLog($"[SPAM] Item spam ON typeId=0x{typeId:X} slot={slot} count={count} delay={delayMs}ms");
    }

    public void StopItemSpam()
    {
        IsSpamming = false;
        ItemSpamStopCmd?.Invoke();
        AddLog("[SPAM] Item spam OFF");
    }

    // ── Batch give: give all registry items in sequence ──────────────────
    public async Task BatchGiveAll(IEnumerable<(uint typeId, string name)> items,
        PipeCaptureServer pipe, int startSlot = 0, int delayMs = 50,
        CancellationToken tok = default)
    {
        int slot = startSlot;
        int n = 0;
        foreach (var (tid, name) in items)
        {
            if (tok.IsCancellationRequested) break;
            pipe.ForgeStream(BuildSetCreativeItem((uint)(slot % 36), tid, 64));
            slot++;
            n++;
            TotalSent++;
            if (delayMs > 0) await Task.Delay(delayMs, tok);
        }
        AddLog($"[BATCH] Gave {n} item types");
    }

    // ── Export history ────────────────────────────────────────────────────
    public string ExportJson() =>
        JsonSerializer.Serialize(_history.Select(j => new {
            j.Label, j.Technique, j.SrcSlot, j.DstSlot,
            TypeId = $"0x{j.ItemTypeId:X}", j.Count, j.Repeat, j.Sent,
            j.Result, Started = j.StartedAt.ToString("HH:mm:ss")
        }), new JsonSerializerOptions { WriteIndented = true });

    public void Clear() { _history.Clear(); AddLog("[DUPE] History cleared"); }

    // ── Frame builders ───────────────────────────────────────────────────
    public static byte[] BuildSetCreativeItem(uint slot, uint typeId, uint count)
    {
        // [4B flen=16][2B 0xAB][2B pad][4B slot][4B typeId][4B count]
        using var ms = new MemoryStream(20);
        using var bw = new BinaryWriter(ms);
        bw.Write((uint)16); bw.Write((ushort)0xAB); bw.Write((ushort)0);
        bw.Write(slot); bw.Write(typeId); bw.Write(count);
        return ms.ToArray();
    }

    public static byte[] BuildDropItemStack(uint slot, uint count)
    {
        // [4B flen=12][2B 0xAC][2B pad][4B slot][4B count]
        using var ms = new MemoryStream(16);
        using var bw = new BinaryWriter(ms);
        bw.Write((uint)12); bw.Write((ushort)0xAC); bw.Write((ushort)0);
        bw.Write(slot); bw.Write(count);
        return ms.ToArray();
    }

    public static byte[] BuildMoveItemStack(uint src, uint dst, uint count)
    {
        // [4B flen=16][2B 0xAF][2B pad][4B from][4B to][4B count]
        using var ms = new MemoryStream(20);
        using var bw = new BinaryWriter(ms);
        bw.Write((uint)16); bw.Write((ushort)0xAF); bw.Write((ushort)0);
        bw.Write(src); bw.Write(dst); bw.Write(count);
        return ms.ToArray();
    }

    public static byte[] BuildWindowAction(uint windowId, uint actionType, uint srcSlot, uint dstSlot)
    {
        // [4B flen=20][2B 0xCB][2B pad][4B wid][4B action][4B src][4B dst]
        using var ms = new MemoryStream(28);
        using var bw = new BinaryWriter(ms);
        bw.Write((uint)20); bw.Write((ushort)0xCB); bw.Write((ushort)0);
        bw.Write(windowId); bw.Write(actionType); bw.Write(srcSlot); bw.Write(dstSlot);
        return ms.ToArray();
    }

    private void AddLog(string msg)
    {
        var line = $"[{DateTime.Now:HH:mm:ss.fff}] {msg}";
        lock (_logLock) { _log.Add(line); if (_log.Count > 1000) _log.RemoveAt(0); }
        OnLog?.Invoke(line);
    }
}
