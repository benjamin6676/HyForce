using HyForce.Core;
using HyForce.Data;
using HyForce.Networking;
using System.Buffers.Binary;
using System.Text;
using static HyForce.Protocol.PacketDecryptor;

namespace HyForce.Protocol;

public class PacketHandler
{
    private readonly AppState _state;
    private readonly Dictionary<uint, DateTime> _lastPacketTimes = new();
    private readonly HashSet<ushort> _interestingOpcodes = new()
    {
        0x6C, // ClientMovement
        0x6F, // MouseInteraction
        0x70, // DamageInfo
        0xAA, // UpdatePlayerInventory
        0xC8, // OpenWindow
        0xCA, // CloseWindow
        0xCB, // SendWindowAction
        0xAE, // DropItemStack
        0xAC, // DropCreativeItem
        0xAF, // MoveItemStack
        0xA1, // EntityUpdates
        0x83  // SetChunk
    };

    public PacketHandler(AppState state)
    {
        _state = state;
        // PacketDecryptor.OnKeyDiscovered += OnEncryptionKeyFound;
    }

    public void ProcessPacket(CapturedPacket packet)
    {
        // Track packet timing for rate analysis
        _lastPacketTimes[packet.SequenceId] = DateTime.Now;

        // Try to decrypt if encrypted
        byte[] dataToProcess = packet.RawBytes;
        bool wasDecrypted = false;
        DecryptionResult? decryptResult = null;

        if (PacketDecryptor.IsLikelyEncrypted(packet.RawBytes))
        {
            decryptResult = PacketDecryptor.TryDecrypt(packet.RawBytes);

            // CRITICAL FIX: Check for null before accessing Success property
            if (decryptResult?.Success == true && decryptResult.DecryptedData != null)
            {
                dataToProcess = decryptResult.DecryptedData;
                wasDecrypted = true;

                _state.AddInGameLog($"[DECRYPT] {packet.Opcode:X4} decrypted ({dataToProcess.Length} bytes)");
            }
        }

        // Process based on opcode
        AnalyzePacketContent(packet, dataToProcess, wasDecrypted);

        // Log interesting packets
        if (_interestingOpcodes.Contains(packet.Opcode))
        {
            string prefix = wasDecrypted ? "[DECRYPTED] " : "";
            _state.AddInGameLog($"{prefix}[{packet.Opcode:X4}] {GetOpcodeName(packet.Opcode)} ({packet.RawBytes.Length} bytes)");
        }
    }

    private void AnalyzePacketContent(CapturedPacket packet, byte[] data, bool wasDecrypted)
    {
        // Registry sync (always check)
        if (packet.IsTcp && packet.Direction == PacketDirection.ServerToClient)
        {
            if (packet.Opcode >= 0x28 && packet.Opcode <= 0x3F)
            {
                RegistrySyncParser.TryParse(packet.Opcode, data);
            }
        }

        // Specific handlers
        switch (packet.Opcode)
        {
            case 0xAA when packet.Direction == PacketDirection.ServerToClient:
                HandleInventoryUpdate(packet, data);
                break;
            case 0xC8 when packet.Direction == PacketDirection.ServerToClient:
                HandleWindowOpen(packet, data);
                break;
            case 0xCA when packet.Direction == PacketDirection.ServerToClient:
                HandleWindowClose(packet, data);
                break;
            case 0xCB when packet.Direction == PacketDirection.ClientToServer:
                HandleWindowAction(packet, data);
                break;
            case 0xAE when packet.Direction == PacketDirection.ClientToServer:
                HandleItemDrop(packet, data);
                break;
            case 0x6C when packet.Direction == PacketDirection.ClientToServer:
                HandleMovement(packet, data);
                break;
            case 0x6F when packet.Direction == PacketDirection.ClientToServer:
                HandleMouseInteraction(packet, data);
                break;
        }
    }

    private void HandleInventoryUpdate(CapturedPacket packet, byte[] data)
    {
        try
        {
            var items = ParseInventoryData(data);

            _state.AddInGameLog($"[INVENTORY] Update with {items.Count} items");

            foreach (var item in items.Take(5)) // Log first 5
            {
                string name = GetItemName(item.ItemId);
                _state.AddInGameLog($"  Slot {item.Slot}: {name} x{item.Count}");
            }

            // Security check: Too many items = possible exploit
            if (items.Count > 100)
            {
                _state.LogSecurityEvent("Inventory", $"Suspicious: {items.Count} items in update",
                    new Dictionary<string, object> { ["count"] = items.Count });
            }
        }
        catch (Exception ex)
        {
            _state.AddInGameLog($"[INVENTORY] Parse error: {ex.Message}");
        }
    }

    private void HandleWindowOpen(CapturedPacket packet, byte[] data)
    {
        string windowType = "Unknown";

        // Try to extract window type from packet
        var strings = ExtractStrings(data);
        var typeString = strings.FirstOrDefault(s =>
            s.Contains("chest", StringComparison.OrdinalIgnoreCase) ||
            s.Contains("inventory", StringComparison.OrdinalIgnoreCase) ||
            s.Contains("container", StringComparison.OrdinalIgnoreCase));

        if (typeString != null)
            windowType = typeString;

        _state.AddInGameLog($"[WINDOW] Opened: {windowType}");

        // Try to extract window ID for tracking
        if (data.Length >= 4)
        {
            byte windowId = data[2];
            _state.AddInGameLog($"  Window ID: {windowId}");
        }
    }

    private void HandleWindowClose(CapturedPacket packet, byte[] data)
    {
        _state.AddInGameLog("[WINDOW] Closed");
    }

    private void HandleWindowAction(CapturedPacket packet, byte[] data)
    {
        // Window action = click/drag in inventory/chest
        if (data.Length >= 6)
        {
            byte windowId = data[2];
            short slot = BinaryPrimitives.ReadInt16BigEndian(data.AsSpan(3));
            byte action = data[5];

            string actionName = action switch
            {
                0 => "LEFT_CLICK",
                1 => "RIGHT_CLICK",
                2 => "SHIFT_CLICK",
                _ => $"UNKNOWN({action})"
            };

            _state.AddInGameLog($"[ACTION] {actionName} in window {windowId}, slot {slot}");
        }
    }

    private void HandleItemDrop(CapturedPacket packet, byte[] data)
    {
        _state.AddInGameLog("[DROP] Player dropped item");

        // Try to extract dropped item info
        if (data.Length >= 6)
        {
            short slot = BinaryPrimitives.ReadInt16BigEndian(data.AsSpan(2));
            byte count = data[4];

            _state.AddInGameLog($"  From slot {slot}, count: {count}");
        }

        // Security: Rapid dropping = possible dupe check
        var recentDrops = _lastPacketTimes.Count(kvp =>
            (DateTime.Now - kvp.Value).TotalSeconds < 1);

        if (recentDrops > 10)
        {
            _state.LogSecurityEvent("Drop", "Rapid item dropping detected",
                new Dictionary<string, object> { ["rate"] = recentDrops });
        }
    }

    private void HandleMovement(CapturedPacket packet, byte[] data)
    {
        // Extract position if possible
        if (data.Length >= 26)
        {
            try
            {
                float x = BinaryPrimitives.ReadSingleBigEndian(data.AsSpan(6));
                float y = BinaryPrimitives.ReadSingleBigEndian(data.AsSpan(10));
                float z = BinaryPrimitives.ReadSingleBigEndian(data.AsSpan(14));

                // Only log significant position changes (every 5 seconds max)
                // Store in state for comparison
            }
            catch { }
        }
    }

    private void HandleMouseInteraction(CapturedPacket packet, byte[] data)
    {
        _state.AddInGameLog("[INTERACTION] Mouse click/attack");
    }

    private List<InventoryItem> ParseInventoryData(byte[] data)
    {
        var items = new List<InventoryItem>();

        try
        {
            // Skip opcode (2 bytes)
            int offset = 2;

            // Read item count
            if (offset + 2 > data.Length) return items;
            short count = BinaryPrimitives.ReadInt16BigEndian(data.AsSpan(offset));
            offset += 2;

            for (int i = 0; i < count && offset < data.Length - 8; i++)
            {
                short slot = BinaryPrimitives.ReadInt16BigEndian(data.AsSpan(offset));
                offset += 2;

                int itemId = BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(offset));
                offset += 4;

                short itemCount = BinaryPrimitives.ReadInt16BigEndian(data.AsSpan(offset));
                offset += 2;

                items.Add(new InventoryItem
                {
                    Slot = slot,
                    ItemId = itemId,
                    Count = itemCount
                });

                // Skip metadata if present (simplified)
                if (offset < data.Length && data[offset] == 0x01) // Has metadata flag
                {
                    offset += 1 + data[offset + 1]; // Skip metadata block
                }
            }
        }
        catch { }

        return items;
    }

    private List<string> ExtractStrings(byte[] data, int minLength = 3)
    {
        var results = new List<string>();
        var sb = new StringBuilder();

        foreach (var b in data)
        {
            if (b >= 32 && b <= 126)
            {
                sb.Append((char)b);
            }
            else
            {
                if (sb.Length >= minLength)
                    results.Add(sb.ToString());
                sb.Clear();
            }
        }

        if (sb.Length >= minLength)
            results.Add(sb.ToString());

        return results;
    }

    private string GetItemName(int itemId)
    {
        // Check registry first
        if (RegistrySyncParser.NumericIdToName.TryGetValue((uint)itemId, out var name))
            return name;

        return $"Unknown(0x{itemId:X8})";
    }

    private string GetOpcodeName(ushort opcode)
    {
        var info = OpcodeRegistry.GetInfo(opcode, PacketDirection.ServerToClient)
                ?? OpcodeRegistry.GetInfo(opcode, PacketDirection.ClientToServer);
        return info?.Name ?? $"Unknown_0x{opcode:X4}";
    }

    private void OnEncryptionKeyFound(PacketDecryptor.EncryptionKey key)
    {
        //_state.AddInGameLog($"[KEY] Found {key.Type} key from {key.Source}");

        if (key.MemoryAddress.HasValue)
        {
            _state.AddInGameLog($"  Address: 0x{(ulong)key.MemoryAddress.Value:X}");
        }

        _state.LogSecurityEvent("Encryption", $"Key discovered: {key.Type}",
            new Dictionary<string, object>
            {
                ["type"] = key.Type.ToString(),
                ["source"] = key.Source,
                ["key_length"] = key.Key.Length
            });
    }

    private class InventoryItem
    {
        public short Slot { get; set; }
        public int ItemId { get; set; }
        public short Count { get; set; }
    }
}