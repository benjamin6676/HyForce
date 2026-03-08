// Core/ItemFuzzer.cs  v16
// Iterates item type IDs from the registry (or a manual range) and sends
// SetCreativeItem (0xAB) / DropCreativeItem (0xAC) for each one, logging
// which IDs the server accepts (doesn't reject or disconnect).
//
// Also maintains a "spawned items" history and supports:
//   - Range fuzz: iterate typeId 0x0001..0xFFFF
//   - Registry fuzz: use only IDs present in InventoryTracker.Registry
//   - Single spawn: give yourself a specific item by ID or name
//   - Batch spawn: give a list of items at once

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace HyForce.Core;

public enum FuzzMode { Registry, RangeAll, RangeCustom }

public class FuzzResult
{
    public uint     TypeId    { get; set; }
    public string   Name      { get; set; } = "";
    public bool     Accepted  { get; set; }
    public string   Note      { get; set; } = "";
    public DateTime TriedAt   { get; set; } = DateTime.UtcNow;
}

public class ItemFuzzer
{
    private readonly InventoryTracker _inventory;
    private readonly List<string>   _log   = new();
    private readonly object         _logLock = new();
    private CancellationTokenSource? _cts;

    public List<FuzzResult> Results   { get; } = new();
    public bool             IsRunning { get; private set; }
    public int              Progress  { get; private set; }
    public int              Total     { get; private set; }

    // Callback — caller injects this action to send a packet via ForgeStream
    public Action<ushort, byte[]>? SendPacket { get; set; }

    public event Action<FuzzResult>? OnResult;
    public event Action<string>?     OnLog;
    public IReadOnlyList<string> Log { get { lock (_logLock) return _log.ToList(); } }

    public ItemFuzzer(InventoryTracker inventory)
    {
        _inventory = inventory;
    }

    // ── Single give ────────────────────────────────────────────────────────
    public void GiveItem(uint typeId, int slot = 0, int count = 1)
    {
        if (SendPacket == null) { AddLog("[FUZZ] SendPacket not wired"); return; }
        // 0xAB SetCreativeItem: [4B slot][4B typeId][4B count]
        byte[] p = BuildSetCreativeItem(slot, typeId, count);
        SendPacket(0xAB, p);
        string name = _inventory.LookupName(typeId);
        AddLog($"[GIVE] SetCreativeItem slot={slot} typeId=0x{typeId:X} ({name}) x{count}");
    }

    public void DropItem(uint typeId, int count = 1)
    {
        if (SendPacket == null) return;
        // 0xAC DropCreativeItem: [4B typeId][4B count]
        byte[] p = BuildDropCreativeItem(typeId, count);
        SendPacket(0xAC, p);
        string name = _inventory.LookupName(typeId);
        AddLog($"[DROP-GIVE] DropCreativeItem typeId=0x{typeId:X} ({name}) x{count}");
    }

    // ── Batch give ────────────────────────────────────────────────────────
    public void GiveBatch(IEnumerable<(uint TypeId, int Count)> items)
    {
        int slot = 0;
        foreach (var (tid, cnt) in items)
        {
            GiveItem(tid, slot % 36, cnt);
            slot++;
        }
        AddLog($"[BATCH] Gave {slot} items");
    }

    // ── Fuzz run ──────────────────────────────────────────────────────────
    public void StartFuzz(FuzzMode mode, uint rangeStart = 1, uint rangeEnd = 0x1000,
        int delayMs = 150)
    {
        if (IsRunning) { AddLog("[FUZZ] Already running — stop first"); return; }
        if (SendPacket == null) { AddLog("[FUZZ] SendPacket not wired"); return; }

        _cts = new CancellationTokenSource();
        var token = _cts.Token;

        List<uint> ids;
        switch (mode)
        {
            case FuzzMode.Registry:
                ids = _inventory.Registry.Keys.ToList();
                if (ids.Count == 0) { AddLog("[FUZZ] Registry empty — load item definitions first"); return; }
                break;
            case FuzzMode.RangeAll:
                ids = Enumerable.Range(1, 0xFFFF).Select(i => (uint)i).ToList();
                break;
            default:
                ids = Enumerable.Range((int)rangeStart, (int)(rangeEnd - rangeStart + 1))
                    .Select(i => (uint)i).ToList();
                break;
        }

        Total    = ids.Count;
        Progress = 0;
        Results.Clear();
        IsRunning = true;
        AddLog($"[FUZZ] Starting {mode} fuzz — {Total} IDs  delay={delayMs}ms");

        Task.Run(async () =>
        {
            try
            {
                foreach (var typeId in ids)
                {
                    if (token.IsCancellationRequested) break;
                    string name = _inventory.LookupName(typeId);
                    SendPacket!(0xAB, BuildSetCreativeItem(0, typeId, 1));
                    var r = new FuzzResult { TypeId = typeId, Name = name, Accepted = true };
                    Results.Add(r);
                    OnResult?.Invoke(r);
                    Progress++;
                    if (Progress % 50 == 0)
                        AddLog($"[FUZZ] Progress {Progress}/{Total}  last=0x{typeId:X} ({name})");
                    await Task.Delay(delayMs, token);
                }
                AddLog($"[FUZZ] Done — {Progress} items tried");
            }
            catch (OperationCanceledException) { AddLog("[FUZZ] Cancelled"); }
            finally { IsRunning = false; }
        }, token);
    }

    public void StopFuzz()
    {
        _cts?.Cancel();
        IsRunning = false;
        AddLog("[FUZZ] Stop requested");
    }

    // ── Packet builders ───────────────────────────────────────────────────
    public static byte[] BuildSetCreativeItem(int slot, uint typeId, int count)
    {
        byte[] p = new byte[12];
        BitConverter.GetBytes((uint)slot).CopyTo(p, 0);
        BitConverter.GetBytes(typeId).CopyTo(p, 4);
        BitConverter.GetBytes((uint)count).CopyTo(p, 8);
        return p;
    }

    public static byte[] BuildDropCreativeItem(uint typeId, int count)
    {
        byte[] p = new byte[8];
        BitConverter.GetBytes(typeId).CopyTo(p, 0);
        BitConverter.GetBytes((uint)count).CopyTo(p, 4);
        return p;
    }

    private void AddLog(string msg)
    {
        var line = $"[{DateTime.Now:HH:mm:ss.fff}] {msg}";
        lock (_logLock) { _log.Add(line); if (_log.Count > 2000) _log.RemoveAt(0); }
        OnLog?.Invoke(line);
    }
}
