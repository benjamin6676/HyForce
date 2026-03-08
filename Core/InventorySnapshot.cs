// Core/InventorySnapshot.cs  v20
// Takes named snapshots of InventoryTracker state and computes slot diffs.
// Used by InventorySnapshotTab and TradeTab to show what changed after an action.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace HyForce.Core;

public class SlotSnapshot
{
    public int    SlotIndex  { get; set; }
    public uint   TypeId     { get; set; }
    public int    StackCount { get; set; }
    public int    Durability { get; set; }
    public string ItemName   { get; set; } = "";
}

public class InventorySnap
{
    public string              Name      { get; set; } = "";
    public DateTime            TakenAt   { get; set; } = DateTime.UtcNow;
    public List<SlotSnapshot>  Slots     { get; set; } = new();
    public int                 SlotCount => Slots.Count;
}

public enum SlotDiffKind { Unchanged, Added, Removed, Changed }

public class SlotDiff
{
    public int          SlotIndex { get; set; }
    public SlotDiffKind Kind      { get; set; }
    public SlotSnapshot? Before  { get; set; }
    public SlotSnapshot? After   { get; set; }
    public string Summary { get; set; } = "";
}

public class InventorySnapshot
{
    private readonly List<InventorySnap> _snaps   = new();
    private readonly List<string>        _log     = new();
    private readonly object              _logLock = new();

    public IReadOnlyList<InventorySnap> Snaps => _snaps;
    public IReadOnlyList<string> Log { get { lock (_logLock) return _log.ToList(); } }
    public event Action<string>? OnLog;

    // Called by AppState / UI to take a snapshot of current inventory state
    public InventorySnap Take(InventoryTracker tracker, string name = "")
    {
        var snap = new InventorySnap
        {
            Name    = string.IsNullOrEmpty(name) ? $"Snap #{_snaps.Count + 1}" : name,
            TakenAt = DateTime.UtcNow,
            Slots   = tracker.Slots.Values.Select(s => new SlotSnapshot
            {
                SlotIndex  = s.SlotIndex,
                TypeId     = s.ItemTypeId,
                StackCount = (int)s.StackCount,
                Durability = (int)s.Durability,
                ItemName   = s.ItemName
            }).OrderBy(s => s.SlotIndex).ToList()
        };
        _snaps.Add(snap);
        if (_snaps.Count > 50) _snaps.RemoveAt(0);
        AddLog($"[INV-SNAP] '{snap.Name}'  {snap.SlotCount} slots  @ {snap.TakenAt:HH:mm:ss.fff}");
        return snap;
    }

    // Diff two snapshots
    public List<SlotDiff> Diff(InventorySnap before, InventorySnap after)
    {
        var result = new List<SlotDiff>();
        var beforeMap = before.Slots.ToDictionary(s => s.SlotIndex);
        var afterMap  = after.Slots.ToDictionary(s => s.SlotIndex);

        var allSlots = beforeMap.Keys.Union(afterMap.Keys).OrderBy(x => x);
        foreach (var slot in allSlots)
        {
            beforeMap.TryGetValue(slot, out var b);
            afterMap.TryGetValue(slot, out var a);

            SlotDiffKind kind;
            string summary;

            if (b == null && a != null)
            {
                kind    = SlotDiffKind.Added;
                summary = $"+ [{slot}] {a.ItemName} ×{a.StackCount}";
            }
            else if (b != null && a == null)
            {
                kind    = SlotDiffKind.Removed;
                summary = $"- [{slot}] {b.ItemName} ×{b.StackCount}";
            }
            else if (b != null && a != null && (b.TypeId != a.TypeId || b.StackCount != a.StackCount || b.Durability != a.Durability))
            {
                kind = SlotDiffKind.Changed;
                if (b.TypeId != a.TypeId)
                    summary = $"~ [{slot}] {b.ItemName} → {a.ItemName}";
                else if (b.StackCount != a.StackCount)
                    summary = $"~ [{slot}] {a.ItemName} ×{b.StackCount} → ×{a.StackCount}";
                else
                    summary = $"~ [{slot}] {a.ItemName} dur {b.Durability} → {a.Durability}";
            }
            else continue;

            result.Add(new SlotDiff { SlotIndex=slot, Kind=kind, Before=b, After=a, Summary=summary });
        }
        return result;
    }

    // Take two consecutive snapshots for easy before/after comparison
    private InventorySnap? _pendingBefore;
    public void MarkBefore(InventoryTracker t) { _pendingBefore = Take(t, $"Before #{_snaps.Count}"); }
    public (InventorySnap? Before, InventorySnap After, List<SlotDiff> Diffs) MarkAfter(InventoryTracker t)
    {
        var after = Take(t, $"After #{_snaps.Count}");
        var diffs = _pendingBefore != null ? Diff(_pendingBefore, after) : new List<SlotDiff>();
        int gains  = diffs.Count(d => d.Kind == SlotDiffKind.Added || (d.Kind==SlotDiffKind.Changed && (d.After?.StackCount??0) > (d.Before?.StackCount??0)));
        int losses = diffs.Count(d => d.Kind == SlotDiffKind.Removed);
        AddLog($"[INV-DIFF] {diffs.Count} changes  +{gains} gained  -{losses} removed");
        return (_pendingBefore, after, diffs);
    }

    // Export
    public string ExportJson(InventorySnap snap) =>
        JsonSerializer.Serialize(snap, new JsonSerializerOptions { WriteIndented = true });

    public string ExportDiffJson(List<SlotDiff> diffs) =>
        JsonSerializer.Serialize(diffs.Select(d => new {
            d.SlotIndex, Kind = d.Kind.ToString(), d.Summary,
            Before = d.Before == null ? null : new { d.Before.TypeId, d.Before.StackCount, d.Before.ItemName },
            After  = d.After  == null ? null : new { d.After.TypeId,  d.After.StackCount,  d.After.ItemName }
        }), new JsonSerializerOptions { WriteIndented = true });

    public void Delete(InventorySnap snap) => _snaps.Remove(snap);
    public void Clear() { _snaps.Clear(); AddLog("[INV-SNAP] Cleared"); }

    private void AddLog(string msg)
    {
        var line = $"[{DateTime.Now:HH:mm:ss.fff}] {msg}";
        lock (_logLock) { _log.Add(line); if (_log.Count > 500) _log.RemoveAt(0); }
        OnLog?.Invoke(line);
    }
}
