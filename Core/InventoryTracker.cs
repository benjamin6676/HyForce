// Core/InventoryTracker.cs  v16
// Parses 0xAA UpdatePlayerInventory and registry packets (0x28, 0x2E) to
// maintain a live named inventory + item definition database.
//
// Inventory wire format (post-Zstd):
//   [4B LE uint32 -- slot count]
//   For each slot:
//     [4B LE uint32 -- slot index]
//     [4B LE uint32 -- item type ID (0 = empty)]
//     [4B LE uint32 -- stack count]
//     [4B LE uint32 -- durability / metadata]
//
// Registry (UpdateBlockTypes 0x28, UpdateBlockSets 0x2E) format:
//   [4B LE uint32 -- entry count]
//   For each entry:
//     [4B LE uint32 -- type ID]
//     [2B LE uint16 -- name length]
//     [N bytes UTF-8 name]
//     [...additional fields we skip]

using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace HyForce.Core;

public class InventorySlot
{
    public int    SlotIndex  { get; set; }
    public uint   ItemTypeId { get; set; }
    public uint   StackCount { get; set; }
    public uint   Durability { get; set; }
    public bool   IsEmpty    => ItemTypeId == 0;
    public string ItemName   { get; set; } = "";
    public DateTime LastSeen { get; set; } = DateTime.UtcNow;
}

public class ItemDefinition
{
    public uint   TypeId { get; set; }
    public string Name   { get; set; } = "";
}

public class InventoryTracker
{
    private readonly ConcurrentDictionary<int, InventorySlot>  _slots    = new();
    private readonly ConcurrentDictionary<uint, ItemDefinition> _registry = new();
    private readonly List<string> _log = new();
    private readonly object _logLock = new();

    private int _parseErrors;
    private int _registryEntries;
    private DateTime _lastInventoryUpdate = DateTime.MinValue;

    public event Action? OnInventoryChanged;
    public event Action<string>? OnLog;

    public IReadOnlyDictionary<int, InventorySlot>   Slots         => _slots;
    public IReadOnlyDictionary<uint, ItemDefinition> Registry      => _registry;
    public int   ParseErrors      => _parseErrors;
    public int   RegistryEntries  => _registryEntries;
    public DateTime LastUpdate    => _lastInventoryUpdate;
    public IReadOnlyList<string> Log { get { lock (_logLock) return _log.ToList(); } }

    // ── Inventory packet (0xAA) ─────────────────────────────────────────────
    public void ProcessInventoryPacket(byte[] payload)
    {
        if (payload == null || payload.Length < 4) return;
        try
        {
            int pos = 0;
            uint slotCount = BinaryPrimitives.ReadUInt32LittleEndian(payload.AsSpan(pos)); pos += 4;
            if (slotCount > 1000) { AddLog($"[INV] Suspicious slot count {slotCount}"); return; }

            _slots.Clear();
            int filled = 0;
            for (uint i = 0; i < slotCount && pos + 16 <= payload.Length; i++)
            {
                uint slotIdx  = BinaryPrimitives.ReadUInt32LittleEndian(payload.AsSpan(pos)); pos += 4;
                uint typeId   = BinaryPrimitives.ReadUInt32LittleEndian(payload.AsSpan(pos)); pos += 4;
                uint stack    = BinaryPrimitives.ReadUInt32LittleEndian(payload.AsSpan(pos)); pos += 4;
                uint dura     = BinaryPrimitives.ReadUInt32LittleEndian(payload.AsSpan(pos)); pos += 4;

                string name = _registry.TryGetValue(typeId, out var def) ? def.Name : $"ID:{typeId:X}";
                var slot = new InventorySlot
                {
                    SlotIndex  = (int)slotIdx,
                    ItemTypeId = typeId,
                    StackCount = stack,
                    Durability = dura,
                    ItemName   = name
                };
                _slots[(int)slotIdx] = slot;
                if (typeId != 0) filled++;
            }

            _lastInventoryUpdate = DateTime.UtcNow;
            AddLog($"[INV] Synced {slotCount} slots — {filled} filled. Payload={payload.Length}B");
            OnInventoryChanged?.Invoke();
        }
        catch (Exception ex)
        {
            _parseErrors++;
            AddLog($"[INV-ERR] {ex.Message}  (total errors: {_parseErrors})");
        }
    }

    // ── Registry packet (0x28 UpdateBlockTypes / 0x2E UpdateBlockSets) ─────
    public void ProcessRegistryPacket(byte[] payload, ushort opcode)
    {
        if (payload == null || payload.Length < 4) return;
        try
        {
            int pos = 0;
            uint entryCount = BinaryPrimitives.ReadUInt32LittleEndian(payload.AsSpan(pos)); pos += 4;
            if (entryCount > 100_000) { AddLog($"[REG] Suspicious entry count {entryCount}"); return; }

            int loaded = 0;
            for (uint i = 0; i < entryCount && pos + 6 <= payload.Length; i++)
            {
                uint typeId = BinaryPrimitives.ReadUInt32LittleEndian(payload.AsSpan(pos)); pos += 4;
                ushort nameLen = BinaryPrimitives.ReadUInt16LittleEndian(payload.AsSpan(pos)); pos += 2;
                if (nameLen > 512 || pos + nameLen > payload.Length) break;

                string name = Encoding.UTF8.GetString(payload, pos, nameLen); pos += nameLen;
                _registry[typeId] = new ItemDefinition { TypeId = typeId, Name = name };

                // Skip remaining fields in this entry (variable — advance past any trailing data
                // by looking for next typeId-like pattern; best effort only)
                loaded++;
            }

            _registryEntries = _registry.Count;
            AddLog($"[REG] 0x{opcode:X4}: loaded {loaded} definitions  total={_registryEntries}");
        }
        catch (Exception ex)
        {
            _parseErrors++;
            AddLog($"[REG-ERR] 0x{opcode:X4}: {ex.Message}");
        }
    }

    public class InventoryLoadout
    {
        public string Name { get; set; } = "";
        public List<(uint TypeId, int Count, int Slot)> Items { get; set; } = new();
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }

    public void Clear()
    {
        _slots.Clear();
        AddLog("[INV] Inventory cleared");
    }

    public void ClearRegistry()
    {
        _registry.Clear();
        _registryEntries = 0;
        AddLog("[REG] Registry cleared");
    }

    public string LookupName(uint typeId) =>
        _registry.TryGetValue(typeId, out var d) ? d.Name : $"TypeID:{typeId:X}";

    // Re-label all slots using current registry (call after registry loaded)
    public void RelabelSlots()
    {
        foreach (var kv in _slots)
            kv.Value.ItemName = LookupName(kv.Value.ItemTypeId);
        OnInventoryChanged?.Invoke();
    }

    private void AddLog(string msg)
    {
        var line = $"[{DateTime.Now:HH:mm:ss.fff}] {msg}";
        lock (_logLock) { _log.Add(line); if (_log.Count > 2000) _log.RemoveAt(0); }
        OnLog?.Invoke(line);
    }
}
