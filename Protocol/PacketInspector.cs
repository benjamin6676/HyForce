// FILE: Protocol/PacketInspector.cs (ENHANCED)
using HyForce.Data;
using HyForce.Networking;
using HyForce.Utils;
using System;
using System.Collections.Generic;
using System.Linq;

namespace HyForce.Protocol;

public class PacketInspector
{
    public static PacketAnalysis Analyze(CapturedPacket packet)
    {
        var analysis = new PacketAnalysis();
        var data = packet.RawBytes;

        if (data.Length < 2) return analysis;

        // Read opcode (first 2 bytes, big-endian as shown in your hex dumps)
        ushort opcode = (ushort)((data[0] << 8) | data[1]);
        analysis.Opcode = opcode;
        analysis.OpcodeHex = $"0x{opcode:X4}";

        // Determine direction-based info
        var info = OpcodeRegistry.GetInfo(opcode, packet.Direction);
        if (info != null)
        {
            analysis.PacketName = info.Name;
            analysis.Category = info.Category;
            analysis.Description = info.Description;
            analysis.IsCritical = info.IsCritical;
        }
        else
        {
            analysis.PacketName = "Unknown";
            analysis.Category = PacketCategory.Unknown;
            analysis.Description = "Unrecognized packet type";
            analysis.IsCritical = false;
        }

        // Analyze payload structure
        if (data.Length > 2)
        {
            analysis.PayloadOffset = 2;
            analysis.PayloadLength = data.Length - 2;

            // Try to parse specific packet types
            switch (opcode)
            {
                case 0x6C when packet.Direction == PacketDirection.ClientToServer: // ClientMovement
                    ParseClientMovement(data, analysis);
                    break;
                case 0x6F when packet.Direction == PacketDirection.ClientToServer: // MouseInteraction
                    ParseMouseInteraction(data, analysis);
                    break;
                case 0xA1 when packet.Direction == PacketDirection.ServerToClient: // EntityUpdates
                    ParseEntityUpdates(data, analysis);
                    break;
                case 0x83 when packet.Direction == PacketDirection.ServerToClient: // SetChunk
                    ParseSetChunk(data, analysis);
                    break;
                case 0xAA when packet.Direction == PacketDirection.ServerToClient: // UpdatePlayerInventory
                    ParseInventoryUpdate(data, analysis);
                    break;
                case >= 0x28 and <= 0x42 when packet.Direction == PacketDirection.ServerToClient:
                    analysis.IsRegistrySync = true;
                    analysis.CompressionHint = "Likely Zstd compressed";
                    break;
            }
        }

        // Entropy analysis for encryption detection
        analysis.Entropy = ByteUtils.CalculateEntropy(data);
        analysis.EncryptionLikely = analysis.Entropy > 7.8;

        // QUIC-specific analysis
        if (!packet.IsTcp && packet.QuicInfo != null)
        {
            analysis.QuicHeaderType = packet.QuicInfo.HeaderType;
            analysis.QuicVersion = packet.QuicInfo.Version;
        }

        return analysis;
    }

    private static void ParseClientMovement(byte[] data, PacketAnalysis analysis)
    {
        // ClientMovement packet structure (0x6C)
        // Based on documentation: movementStates, relativePosition, absolutePosition, etc.
        if (data.Length < 10) return;

        analysis.Fields["MovementStates"] = data[2].ToString("X2");

        // Try to extract position if available
        if (data.Length >= 14)
        {
            try
            {
                float x = BitConverter.ToSingle(data, 4);
                float y = BitConverter.ToSingle(data, 8);
                float z = BitConverter.ToSingle(data, 12);
                analysis.Fields["Position"] = $"({x:F2}, {y:F2}, {z:F2})";
            }
            catch { }
        }
    }

    private static void ParseMouseInteraction(byte[] data, PacketAnalysis analysis)
    {
        // MouseInteraction (0x6F)
        if (data.Length < 6) return;

        analysis.Fields["Timestamp"] = BitConverter.ToUInt32(data, 2).ToString();
        if (data.Length >= 7)
            analysis.Fields["ActiveSlot"] = data[6].ToString();
    }

    private static void ParseEntityUpdates(byte[] data, PacketAnalysis analysis)
    {
        // EntityUpdates (0xA1) - Batch update, usually compressed
        analysis.Fields["UpdateType"] = "Batch Entity Update";
        analysis.Fields["Note"] = "Payload likely Zstd compressed";
    }

    private static void ParseSetChunk(byte[] data, PacketAnalysis analysis)
    {
        // SetChunk (0x83)
        if (data.Length < 10) return;

        try
        {
            int chunkX = BitConverter.ToInt32(data, 2);
            int chunkY = BitConverter.ToInt32(data, 6);
            analysis.Fields["ChunkPos"] = $"({chunkX}, {chunkY})";
            analysis.Fields["Compressed"] = "Yes (Zstd)";
        }
        catch { }
    }

    private static void ParseInventoryUpdate(byte[] data, PacketAnalysis analysis)
    {
        analysis.Fields["Type"] = "Full Inventory Sync";
        analysis.Fields["Compressed"] = "Yes (Zstd)";
    }

    public static List<PacketPattern> DetectPatterns(List<PacketLogEntry> packets)
    {
        var patterns = new List<PacketPattern>();

        // Group by opcode
        var grouped = packets.GroupBy(p => p.OpcodeDecimal);

        foreach (var group in grouped)
        {
            var list = group.ToList();
            if (list.Count < 5) continue; // Need at least 5 packets for pattern

            var pattern = new PacketPattern
            {
                Opcode = group.Key,
                PacketName = list[0].OpcodeName,
                Count = list.Count,
                AvgSize = (int)list.Average(p => p.ByteLength),
                Direction = list[0].Direction
            };

            // Detect periodic patterns
            if (list.Count >= 10)
            {
                var intervals = new List<double>();
                for (int i = 1; i < list.Count; i++)
                {
                    intervals.Add((list[i].Timestamp - list[i - 1].Timestamp).TotalMilliseconds);
                }

                var avgInterval = intervals.Average();
                var variance = intervals.Select(i => Math.Abs(i - avgInterval)).Average();

                if (variance < avgInterval * 0.1) // Less than 10% variance
                {
                    pattern.IsPeriodic = true;
                    pattern.PeriodMs = avgInterval;
                }
            }

            // Detect burst patterns
            var timeSpan = list.Last().Timestamp - list.First().Timestamp;
            if (timeSpan.TotalSeconds > 0)
            {
                var rate = list.Count / timeSpan.TotalSeconds;
                if (rate > 50) // More than 50 packets per second
                {
                    pattern.IsBurst = true;
                    pattern.RatePerSecond = rate;
                }
            }

            patterns.Add(pattern);
        }

        return patterns.OrderByDescending(p => p.Count).ToList();
    }
}

public class PacketAnalysis
{
    public ushort Opcode { get; set; }
    public string OpcodeHex { get; set; } = "";
    public string PacketName { get; set; } = "Unknown";
    public PacketCategory Category { get; set; }
    public string Description { get; set; } = "";
    public bool IsCritical { get; set; }
    public int PayloadOffset { get; set; }
    public int PayloadLength { get; set; }
    public Dictionary<string, string> Fields { get; set; } = new();
    public double Entropy { get; set; }
    public bool EncryptionLikely { get; set; }
    public bool IsRegistrySync { get; set; }
    public string CompressionHint { get; set; } = "";
    public string QuicHeaderType { get; set; } = "";
    public string QuicVersion { get; set; } = "";
}

public class PacketPattern
{
    public ushort Opcode { get; set; }
    public string PacketName { get; set; } = "";
    public int Count { get; set; }
    public int AvgSize { get; set; }
    public PacketDirection Direction { get; set; }
    public bool IsPeriodic { get; set; }
    public double PeriodMs { get; set; }
    public bool IsBurst { get; set; }
    public double RatePerSecond { get; set; }
}