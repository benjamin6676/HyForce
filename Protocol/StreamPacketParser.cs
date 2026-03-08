// Protocol/StreamPacketParser.cs  v16
// Parses raw QUIC stream bytes into typed HytaleStreamPackets.
//
// Hytale wire format inside each QUIC stream:
//   [4B LE uint32 -- frame payload length NOT including these 4 bytes]
//   [2B LE uint16 -- opcode]
//   [2B padding/flags]
//   [...payload -- may be Zstd compressed (magic 0x28 B5 2F FD)]
//
// A single QUIC stream receive event may contain multiple back-to-back frames.
// The parser maintains a byte buffer per stream and slices frames out of it.

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;

namespace HyForce.Protocol;

public enum HytaleOpcode : ushort
{
    // S2C
    EntityUpdates         = 0xA1,
    UpdatePlayerInventory = 0xAA,
    ChatMessage           = 0xD2,
    SetChunk              = 0x83,
    UpdateBlockTypes      = 0x28,
    SetEntitySeed         = 0xA0,
    PlayAnimation         = 0xA2,
    ChangeVelocity        = 0xA3,
    ApplyKnockback        = 0xA4,
    SpawnParticleSystem   = 0x98,
    UpdateTime            = 0x92,
    UpdateWeather         = 0x95,
    PlayerSetup           = 0x12,
    WorldSettings         = 0x10,
    // C2S
    ClientMovement        = 0x6C,
    MouseInteraction      = 0x6F,
    DamageInfo            = 0x70,
    MoveItemStack         = 0xAF,
    SetActiveSlot         = 0xB1,
    ClientReady           = 0x69,
    JoinWorld             = 0x68,
}

public record HytaleStreamPacket(
    ushort  Opcode,
    string  OpcodeName,
    bool    IsS2C,
    byte[]  Payload,
    bool    WasCompressed,
    DateTime ReceivedAt,
    ulong   StreamHandle
);

public static class StreamPacketParser
{
    // Per-stream reassembly buffers (handle → leftover bytes)
    private static readonly Dictionary<ulong, byte[]> _streamBufs = new();
    private static readonly object _lock = new();

    /// <summary>
    /// Feed raw stream bytes for a given stream handle.
    /// Returns zero or more complete framed packets.
    /// </summary>
    public static List<HytaleStreamPacket> Feed(ulong streamHandle, byte[] data, bool isS2C)
    {
        var results = new List<HytaleStreamPacket>();
        if (data == null || data.Length == 0) return results;

        byte[] buf;
        lock (_lock)
        {
            if (_streamBufs.TryGetValue(streamHandle, out var leftover) && leftover.Length > 0)
            {
                buf = new byte[leftover.Length + data.Length];
                leftover.CopyTo(buf, 0);
                data.CopyTo(buf, leftover.Length);
            }
            else buf = data;
        }

        int pos = 0;
        while (pos < buf.Length)
        {
            // Need at least 8 bytes for header
            if (pos + 8 > buf.Length) break;

            uint frameLen = BinaryPrimitives.ReadUInt32LittleEndian(buf.AsSpan(pos));
            ushort opcode = BinaryPrimitives.ReadUInt16LittleEndian(buf.AsSpan(pos + 4));

            // Sanity check — reject absurd frame sizes (> 4 MB)
            if (frameLen > 4 * 1024 * 1024 || frameLen < 4)
            {
                // Try to resync by advancing one byte
                pos++;
                continue;
            }

            int totalFrame = 4 + (int)frameLen; // length field + payload
            if (pos + totalFrame > buf.Length) break; // incomplete — wait for more data

            byte[] payload = new byte[frameLen - 4]; // strip opcode+flags (4B) from payload
            if (payload.Length > 0)
                Array.Copy(buf, pos + 8, payload, 0, payload.Length);

            bool wasCompressed = false;
            byte[] decoded = payload;

            // Zstd magic: 28 B5 2F FD
            if (payload.Length >= 4 &&
                payload[0] == 0x28 && payload[1] == 0xB5 &&
                payload[2] == 0x2F && payload[3] == 0xFD)
            {
                try
                {
                    using var d = new ZstdSharp.Decompressor();
                    decoded = d.Unwrap(payload).ToArray();
                    wasCompressed = true;
                }
                catch { decoded = payload; }
            }

            results.Add(new HytaleStreamPacket(
                Opcode:        opcode,
                OpcodeName:    OpcodeToName(opcode, isS2C),
                IsS2C:         isS2C,
                Payload:       decoded,
                WasCompressed: wasCompressed,
                ReceivedAt:    DateTime.UtcNow,
                StreamHandle:  streamHandle
            ));

            pos += totalFrame;
        }

        // Save leftover bytes for next call
        lock (_lock)
        {
            if (pos < buf.Length)
            {
                var leftover = new byte[buf.Length - pos];
                Array.Copy(buf, pos, leftover, 0, leftover.Length);
                _streamBufs[streamHandle] = leftover;
            }
            else _streamBufs.Remove(streamHandle);
        }

        return results;
    }

    public static void ResetStream(ulong handle)
    {
        lock (_lock) _streamBufs.Remove(handle);
    }

    public static void ResetAll()
    {
        lock (_lock) _streamBufs.Clear();
    }

    private static string OpcodeToName(ushort op, bool isS2C) => op switch
    {
        0xA1 => "EntityUpdates",
        0xAA => "UpdatePlayerInventory",
        0xD2 => "ChatMessage",
        0x83 => "SetChunk",
        0x28 => "UpdateBlockTypes",
        0x2E => "UpdateBlockSets",
        0xA0 => "SetEntitySeed",
        0xA2 => "PlayAnimation",
        0xA3 => "ChangeVelocity",
        0xA4 => "ApplyKnockback",
        0x98 => "SpawnParticleSystem",
        0x92 => "UpdateTime",
        0x95 => "UpdateWeather",
        0x10 => "WorldSettings",
        0x12 => "PlayerSetup",
        0x02 => "AuthToken",
        0x03 => "ConnectAccept",
        0x6C => "ClientMovement",
        0x6F => "MouseInteraction",
        0x70 => "DamageInfo",
        0xAF => "MoveItemStack",
        0xB1 => "SetActiveSlot",
        0x69 => "ClientReady",
        0x68 => "JoinWorld",
        0xAB => "SetCreativeItem",
        0xAC => "DropCreativeItem",
        0xAE => "DropItemStack",
        0xB0 => "SmartMoveItemStack",
        _    => $"0x{op:X4}"
    };
}
