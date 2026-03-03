// FILE: Protocol/WireFormatParser.cs
// Parses decrypted Hytale QUIC packet payloads.
//
// Hytale wire format (post-QUIC decrypt):
//   [4B LE uint32 — payload length]
//   [4B LE uint32 — packet ID / opcode]
//   [...payload — may be Zstd-compressed]
//
// This parser:
//   1. Strips the 8-byte header and (optionally) decompresses the payload.
//   2. Runs a field detector to auto-label common data types.
//   3. Returns a structured result usable in the UI.

using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;

namespace HyForce.Protocol;

public static class WireFormatParser
{
    // ── Public entry point ────────────────────────────────────────────────

    /// <summary>Parse a raw decrypted byte array from QUIC into a structured packet.</summary>
    public static ParsedHytalePacket? Parse(byte[] decrypted)
    {
        if (decrypted == null || decrypted.Length < 8) return null;

        try
        {
            uint payloadLength = BinaryPrimitives.ReadUInt32LittleEndian(decrypted);
            uint packetId      = BinaryPrimitives.ReadUInt32LittleEndian(decrypted.AsSpan(4));

            var rawPayload = decrypted.Length > 8
                ? decrypted.AsSpan(8).ToArray()
                : Array.Empty<byte>();

            // Decompress if Zstd
            bool wasCompressed = false;
            byte[] payload = rawPayload;
            if (rawPayload.Length >= 4 &&
                rawPayload[0] == 0x28 && rawPayload[1] == 0xB5 &&
                rawPayload[2] == 0x2F && rawPayload[3] == 0xFD)
            {
                try
                {
                    using var d = new ZstdSharp.Decompressor();
                    payload = d.Unwrap(rawPayload).ToArray();
                    wasCompressed = true;
                }
                catch { /* Keep raw on decompress failure */ }
            }

            var fields = DetectFields(payload);

            return new ParsedHytalePacket
            {
                PacketId      = packetId,
                HeaderLength  = payloadLength,
                RawPayload    = rawPayload,
                Payload       = payload,
                WasCompressed = wasCompressed,
                Fields        = fields,
            };
        }
        catch
        {
            return null;
        }
    }

    // ── Field auto-detection ──────────────────────────────────────────────

    /// <summary>
    /// Heuristic scan of payload bytes — detect floats, ints, strings, pointers.
    /// Returns up to 64 high-confidence fields.
    /// </summary>
    public static List<Data.ParsedField> DetectFields(byte[] data)
    {
        var results = new List<Data.ParsedField>();
        if (data.Length < 4) return results;

        int i = 0;
        while (i < data.Length - 3 && results.Count < 64)
        {
            // ── Vec3 detection: 3 plausible floats in a row ───────────────
            if (i + 11 < data.Length)
            {
                float fx = BitConverter.ToSingle(data, i);
                float fy = BitConverter.ToSingle(data, i + 4);
                float fz = BitConverter.ToSingle(data, i + 8);

                if (IsPlausibleFloat(fx) && IsPlausibleFloat(fy) && IsPlausibleFloat(fz) &&
                    !IsAllZero(data, i, 12))
                {
                    // Distinguish position (large range) from rotation (−π to π)
                    bool isRot = Math.Abs(fx) <= 7f && Math.Abs(fy) <= 7f && Math.Abs(fz) <= 7f;
                    results.Add(new Data.ParsedField
                    {
                        Name       = isRot ? "Rotation" : "Position",
                        Offset     = i,
                        Length     = 12,
                        Type       = Data.FieldType.Vec3,
                        Value      = new float[] { fx, fy, fz },
                        HexPreview = Hex(data, i, 12),
                        Confidence = 0.75
                    });
                    i += 12;
                    continue;
                }
            }

            // ── Float detection ───────────────────────────────────────────
            if (i + 3 < data.Length)
            {
                float f = BitConverter.ToSingle(data, i);
                if (IsPlausibleFloat(f) && !IsAllZero(data, i, 4))
                {
                    string name = GuessFloatFieldName(f, i, data);
                    results.Add(new Data.ParsedField
                    {
                        Name       = name,
                        Offset     = i,
                        Length     = 4,
                        Type       = Data.FieldType.Float,
                        Value      = f,
                        HexPreview = Hex(data, i, 4),
                        Confidence = 0.6
                    });
                    i += 4;
                    continue;
                }
            }

            // ── Length-prefixed UTF-8 string (2B prefix) ──────────────────
            if (i + 3 < data.Length)
            {
                ushort strLen = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(i));
                if (strLen >= 2 && strLen <= 128 && i + 2 + strLen <= data.Length)
                {
                    var strBytes = data.AsSpan(i + 2, strLen);
                    if (strBytes.ToArray().All(b => b >= 32 && b <= 126))
                    {
                        string s = Encoding.UTF8.GetString(strBytes);
                        results.Add(new Data.ParsedField
                        {
                            Name       = "String",
                            Offset     = i,
                            Length     = 2 + strLen,
                            Type       = Data.FieldType.String8,
                            Value      = s,
                            HexPreview = Hex(data, i, Math.Min(2 + strLen, 24)),
                            Confidence = 0.8
                        });
                        i += 2 + strLen;
                        continue;
                    }
                }
            }

            // ── Int32 detection ────────────────────────────────────────────
            if (i + 3 < data.Length)
            {
                int iv = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(i));
                if (iv > 0 && iv < 100_000 && !IsAllZero(data, i, 4))
                {
                    results.Add(new Data.ParsedField
                    {
                        Name       = "Int32",
                        Offset     = i,
                        Length     = 4,
                        Type       = Data.FieldType.Int32,
                        Value      = iv,
                        HexPreview = Hex(data, i, 4),
                        Confidence = 0.4
                    });
                    i += 4;
                    continue;
                }
            }

            // ── 8-byte pointer (JVM compressed OOP range) ─────────────────
            if (i + 7 < data.Length)
            {
                long ptr = BitConverter.ToInt64(data, i);
                if (IsLikelyJvmPointer(ptr))
                {
                    results.Add(new Data.ParsedField
                    {
                        Name       = "Pointer",
                        Offset     = i,
                        Length     = 8,
                        Type       = Data.FieldType.Pointer,
                        Value      = (ulong)ptr,
                        HexPreview = Hex(data, i, 8),
                        Confidence = 0.5
                    });
                    i += 8;
                    continue;
                }
            }

            i++;
        }

        // Deduplicate overlapping ranges — keep higher-confidence entry
        return DeduplicateFields(results);
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private static bool IsPlausibleFloat(float f) =>
        !float.IsNaN(f) && !float.IsInfinity(f) &&
        Math.Abs(f) < 1_000_000f &&
        Math.Abs(f) > 0.0001f || f == 0f;

    private static bool IsAllZero(byte[] data, int offset, int len)
    {
        for (int k = 0; k < len && offset + k < data.Length; k++)
            if (data[offset + k] != 0) return false;
        return true;
    }

    private static bool IsLikelyJvmPointer(long p)
    {
        ulong u = (ulong)p;
        return u > 0x10000 && u < 0x7FFFFFFF_0000 && (u & 0x7) == 0;
    }

    private static string GuessFloatFieldName(float f, int offset, byte[] data)
    {
        // Health heuristic: 0 < f <= 40 (Hytale-like health range)
        if (f > 0 && f <= 40f && f == MathF.Floor(f * 2) / 2)
            return $"Health?({f:F1})";
        // Speed heuristic: 0 < f <= 30
        if (f > 0 && f <= 30f)
            return $"Speed?({f:F2})";
        return $"Float@{offset:X}";
    }

    private static string Hex(byte[] data, int offset, int len)
    {
        int actual = Math.Min(len, data.Length - offset);
        return actual <= 0 ? "" : BitConverter.ToString(data, offset, actual).Replace("-", " ");
    }

    private static List<Data.ParsedField> DeduplicateFields(List<Data.ParsedField> fields)
    {
        var result = new List<Data.ParsedField>();
        foreach (var f in fields.OrderByDescending(x => x.Confidence))
        {
            bool overlaps = result.Any(existing =>
                f.Offset < existing.Offset + existing.Length &&
                f.Offset + f.Length > existing.Offset);

            if (!overlaps) result.Add(f);
        }
        return result.OrderBy(f => f.Offset).ToList();
    }
}

// ── Return type ──────────────────────────────────────────────────────────────
public class ParsedHytalePacket
{
    public uint   PacketId      { get; init; }
    public uint   HeaderLength  { get; init; }
    public byte[] RawPayload    { get; init; } = Array.Empty<byte>();
    public byte[] Payload       { get; init; } = Array.Empty<byte>();
    public bool   WasCompressed { get; init; }
    public List<Data.ParsedField> Fields { get; init; } = new();

    public string PacketIdHex   => $"0x{PacketId:X8}";
    public string SizeStr       => WasCompressed
        ? $"{RawPayload.Length}B → {Payload.Length}B (Zstd)"
        : $"{Payload.Length}B";
}
