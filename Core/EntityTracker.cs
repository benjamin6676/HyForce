// Core/EntityTracker.cs  v16
// Parses 0xA1 EntityUpdates S2C packets and maintains a live entity table.
//
// EntityUpdates wire format (post-Zstd-decompress):
//   [4B LE uint32 -- entity count]
//   For each entity:
//     [8B LE uint64 -- entity ID]
//     [4B LE uint32 -- component flags bitmask]
//     IF flag 0x01 (HasPosition):  [4B float X][4B float Y][4B float Z]
//     IF flag 0x02 (HasHealth):    [4B float HP][4B float MaxHP]
//     IF flag 0x04 (HasVelocity):  [4B float VX][4B float VY][4B float VZ]
//     IF flag 0x08 (HasEntityType):[4B LE uint32 typeId]
//     IF flag 0x10 (HasRotation):  [4B float Yaw][4B float Pitch]
//
// NOTE: The exact layout is reverse-engineered from stream captures.
// Fields are best-effort — some entities may parse partially.
// All parsing is exception-safe; bad data is logged and skipped.

using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace HyForce.Core;

public class EntityEntry
{
    public ulong    EntityId    { get; set; }
    public float    X           { get; set; }
    public float    Y           { get; set; }
    public float    Z           { get; set; }
    public float    HP          { get; set; }
    public float    MaxHP       { get; set; }
    public float    VelX        { get; set; }
    public float    VelY        { get; set; }
    public float    VelZ        { get; set; }
    public float    Yaw         { get; set; }
    public float    Pitch       { get; set; }
    public uint     TypeId      { get; set; }
    public uint     Flags       { get; set; }
    public bool     HasPosition => (Flags & 0x01) != 0;
    public bool     HasHealth   => (Flags & 0x02) != 0;
    public bool     HasVelocity => (Flags & 0x04) != 0;
    public bool     HasType     => (Flags & 0x08) != 0;
    public bool     HasRotation => (Flags & 0x10) != 0;
    public DateTime LastSeen    { get; set; } = DateTime.UtcNow;
    public int      UpdateCount { get; set; }
    public string   Label       { get; set; } = "";

    public string PositionStr => HasPosition ? $"({X:F1}, {Y:F1}, {Z:F1})" : "-";
    public string HealthStr   => HasHealth   ? $"{HP:F0}/{MaxHP:F0}" : "-";
    public string VelocityStr => HasVelocity ? $"({VelX:F2},{VelY:F2},{VelZ:F2})" : "-";
    public float  DistanceTo(float ox, float oy, float oz) =>
        MathF.Sqrt((X-ox)*(X-ox) + (Y-oy)*(Y-oy) + (Z-oz)*(Z-oz));
}

public class EntityTracker
{
    private readonly ConcurrentDictionary<ulong, EntityEntry> _entities = new();
    private readonly List<string> _log = new();
    private readonly object _logLock = new();
    private int _parseErrors;
    private int _totalUpdates;

    public event Action<EntityEntry>? OnEntityUpdated;
    public event Action<string>? OnLog;

    public IReadOnlyDictionary<ulong, EntityEntry> Entities => _entities;
    public int ParseErrors   => _parseErrors;
    public int TotalUpdates  => _totalUpdates;
    public int EntityCount   => _entities.Count;

    public IReadOnlyList<string> Log { get { lock (_logLock) return _log.ToList(); } }

    public void ProcessPacket(byte[] payload)
    {
        if (payload == null || payload.Length < 4) return;
        try
        {
            int pos = 0;
            uint count = BinaryPrimitives.ReadUInt32LittleEndian(payload.AsSpan(pos)); pos += 4;
            if (count > 10000) { AddLog($"[ENTITY] Suspicious entity count {count}, skipping"); return; }

            int parsed = 0;
            for (uint i = 0; i < count && pos + 12 <= payload.Length; i++)
            {
                ulong eid   = BinaryPrimitives.ReadUInt64LittleEndian(payload.AsSpan(pos)); pos += 8;
                uint  flags = BinaryPrimitives.ReadUInt32LittleEndian(payload.AsSpan(pos)); pos += 4;

                var e = _entities.GetOrAdd(eid, id => new EntityEntry { EntityId = id });
                e.Flags = flags;
                e.LastSeen = DateTime.UtcNow;
                e.UpdateCount++;

                if ((flags & 0x01) != 0 && pos + 12 <= payload.Length)
                {
                    e.X = BitConverter.ToSingle(payload, pos);
                    e.Y = BitConverter.ToSingle(payload, pos+4);
                    e.Z = BitConverter.ToSingle(payload, pos+8);
                    pos += 12;
                }
                if ((flags & 0x02) != 0 && pos + 8 <= payload.Length)
                {
                    e.HP    = BitConverter.ToSingle(payload, pos);
                    e.MaxHP = BitConverter.ToSingle(payload, pos+4);
                    pos += 8;
                }
                if ((flags & 0x04) != 0 && pos + 12 <= payload.Length)
                {
                    e.VelX = BitConverter.ToSingle(payload, pos);
                    e.VelY = BitConverter.ToSingle(payload, pos+4);
                    e.VelZ = BitConverter.ToSingle(payload, pos+8);
                    pos += 12;
                }
                if ((flags & 0x08) != 0 && pos + 4 <= payload.Length)
                {
                    e.TypeId = BinaryPrimitives.ReadUInt32LittleEndian(payload.AsSpan(pos)); pos += 4;
                }
                if ((flags & 0x10) != 0 && pos + 8 <= payload.Length)
                {
                    e.Yaw   = BitConverter.ToSingle(payload, pos);
                    e.Pitch = BitConverter.ToSingle(payload, pos+4);
                    pos += 8;
                }

                OnEntityUpdated?.Invoke(e);
                parsed++;
            }

            _totalUpdates++;
            if (parsed > 0)
                AddLog($"[ENTITY] Batch: {parsed}/{count} entities parsed  total-tracked={_entities.Count}");
        }
        catch (Exception ex)
        {
            _parseErrors++;
            AddLog($"[ENTITY-ERR] {ex.Message}  (errors so far: {_parseErrors})");
        }
    }

    public void PruneStale(TimeSpan maxAge)
    {
        var cutoff = DateTime.UtcNow - maxAge;
        int removed = 0;
        foreach (var kv in _entities.ToArray())
            if (kv.Value.LastSeen < cutoff && _entities.TryRemove(kv.Key, out _)) removed++;
        if (removed > 0) AddLog($"[ENTITY] Pruned {removed} stale entities");
    }

    public void Clear()
    {
        _entities.Clear();
        AddLog("[ENTITY] Tracker cleared");
    }

    public void SetLabel(ulong eid, string label)
    {
        if (_entities.TryGetValue(eid, out var e)) e.Label = label;
    }

    private void AddLog(string msg)
    {
        var line = $"[{DateTime.Now:HH:mm:ss.fff}] {msg}";
        lock (_logLock)
        {
            _log.Add(line);
            if (_log.Count > 2000) _log.RemoveAt(0);
        }
        OnLog?.Invoke(line);
    }
}
