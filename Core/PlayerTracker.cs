// Core/PlayerTracker.cs  v16
// Sits on top of EntityTracker — filters by known player TypeIDs and
// maintains a separate "confirmed players" dictionary.
//
// Player type ID discovery:
//   On first connection, EntityUpdates (0xA1) contains every entity.
//   PlayerSetup (0x12) S2C tells us our own entity ID.
//   By finding our own entity in the batch we learn the player TypeID.
//   All other entities with that TypeID are other players.
//
// Once the player TypeID is known:
//   - Live player list updates every EntityUpdates batch
//   - Per-player: position, HP, distance from self, entity ID, last seen
//   - OnPlayerJoined / OnPlayerLeft events for UI notifications

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace HyForce.Core;

public class PlayerEntry
{
    public ulong    EntityId    { get; set; }
    public float    X           { get; set; }
    public float    Y           { get; set; }
    public float    Z           { get; set; }
    public float    HP          { get; set; }
    public float    MaxHP       { get; set; }
    public uint     TypeId      { get; set; }
    public bool     IsSelf      { get; set; }
    public string   Label       { get; set; } = "";
    public DateTime FirstSeen   { get; set; } = DateTime.UtcNow;
    public DateTime LastSeen    { get; set; } = DateTime.UtcNow;
    public int      UpdateCount { get; set; }

    public string PositionStr => $"({X:F1}, {Y:F1}, {Z:F1})";
    public string HealthStr   => MaxHP > 0 ? $"{HP:F0}/{MaxHP:F0}" : $"{HP:F0}";
    public float  DistanceTo(float ox, float oy, float oz) =>
        MathF.Sqrt((X-ox)*(X-ox)+(Y-oy)*(Y-oy)+(Z-oz)*(Z-oz));
}

public class PlayerTracker
{
    private readonly ConcurrentDictionary<ulong, PlayerEntry> _players = new();
    private readonly HashSet<uint>  _playerTypeIds  = new();
    private readonly object         _typeIdLock     = new();
    private readonly List<string>   _log            = new();
    private readonly object         _logLock        = new();

    private ulong   _selfEntityId   = 0;
    private float   _selfX, _selfY, _selfZ;

    public event Action<PlayerEntry>? OnPlayerUpdated;
    public event Action<PlayerEntry>? OnPlayerJoined;
    public event Action<ulong>?       OnPlayerLeft;
    public event Action<string>?      OnLog;

    public IReadOnlyDictionary<ulong, PlayerEntry> Players => _players;
    public ulong   SelfEntityId => _selfEntityId;
    public float   SelfX => _selfX;
    public float   SelfY => _selfY;
    public float   SelfZ => _selfZ;
    public IReadOnlyList<string> Log { get { lock (_logLock) return _log.ToList(); } }

    /// <summary>Called when PlayerSetup (0x12) is received — tells us our own entity ID.</summary>
    public void SetSelfEntityId(ulong eid)
    {
        _selfEntityId = eid;
        AddLog($"[PLAYER] Self entity ID set: 0x{eid:X}");
    }

    /// <summary>Manually register a TypeID as a player type.</summary>
    public void RegisterPlayerTypeId(uint typeId)
    {
        lock (_typeIdLock) _playerTypeIds.Add(typeId);
        AddLog($"[PLAYER] Registered player TypeID: 0x{typeId:X4}");
    }

    /// <summary>
    /// Feed an EntityEntry from EntityTracker.
    /// Auto-detects player TypeID when our own entity is first seen.
    /// </summary>
    public void Feed(EntityEntry e)
    {
        // Auto-learn player TypeID from self entity
        if (_selfEntityId != 0 && e.EntityId == _selfEntityId && e.HasType)
        {
            lock (_typeIdLock)
            {
                if (_playerTypeIds.Add(e.TypeId))
                    AddLog($"[PLAYER] Auto-learned player TypeID 0x{e.TypeId:X4} from self entity 0x{_selfEntityId:X}");
            }
        }

        // Only track known player type IDs
        bool isPlayerType;
        lock (_typeIdLock) isPlayerType = e.HasType && _playerTypeIds.Contains(e.TypeId);
        if (!isPlayerType && e.EntityId != _selfEntityId) return;

        bool isNew = !_players.ContainsKey(e.EntityId);
        var p = _players.GetOrAdd(e.EntityId, id => new PlayerEntry
        {
            EntityId  = id,
            TypeId    = e.TypeId,
            FirstSeen = DateTime.UtcNow
        });

        p.TypeId    = e.TypeId;
        p.IsSelf    = e.EntityId == _selfEntityId;
        p.LastSeen  = DateTime.UtcNow;
        p.UpdateCount++;

        if (e.HasPosition) { p.X = e.X; p.Y = e.Y; p.Z = e.Z; }
        if (e.HasHealth)   { p.HP = e.HP; p.MaxHP = e.MaxHP; }

        // Track self position for distance calculations
        if (p.IsSelf && e.HasPosition) { _selfX = e.X; _selfY = e.Y; _selfZ = e.Z; }

        if (isNew)
        {
            AddLog($"[PLAYER] New player seen: 0x{e.EntityId:X}  pos={p.PositionStr}  hp={p.HealthStr}");
            OnPlayerJoined?.Invoke(p);
        }
        OnPlayerUpdated?.Invoke(p);
    }

    public void PruneStale(TimeSpan maxAge)
    {
        var cutoff = DateTime.UtcNow - maxAge;
        foreach (var kv in _players.ToArray())
        {
            if (kv.Value.LastSeen < cutoff && _players.TryRemove(kv.Key, out _))
            {
                AddLog($"[PLAYER] Player 0x{kv.Key:X} pruned (stale)");
                OnPlayerLeft?.Invoke(kv.Key);
            }
        }
    }

    public void Clear()
    {
        _players.Clear();
        AddLog("[PLAYER] Tracker cleared");
    }

    public void SetLabel(ulong eid, string label)
    {
        if (_players.TryGetValue(eid, out var p)) p.Label = label;
    }

    private void AddLog(string msg)
    {
        var line = $"[{DateTime.Now:HH:mm:ss.fff}] {msg}";
        lock (_logLock) { _log.Add(line); if (_log.Count > 1000) _log.RemoveAt(0); }
        OnLog?.Invoke(line);
    }
}
