// FILE: Protocol/RegistrySyncParser.cs
// FIXES:
//   BUG-CRITICAL: ALL Zstd-compressed packets were silently dropped with early return.
//     ZstdSharp.Port NuGet must be added to HyForce.csproj:
//     <PackageReference Include="ZstdSharp.Port" Version="0.8.1" />
//   ADDED: Full Zstd decompression before parsing, so Items/Registry tabs actually populate.
//   ADDED: Length-prefixed string parsing (Hytale registry format).

using System.Buffers.Binary;
using System.Text;

namespace HyForce.Protocol;

public static class RegistrySyncParser
{
    public const ushort ScanOpcodeMin = 0x00;
    public const ushort ScanOpcodeMax = 0x3F;

    public static bool   RegistrySyncReceived { get; private set; }
    public static ushort FoundAtOpcode        { get; private set; } = 0xFFFF;

    public static Dictionary<ushort, int>    OpcodeSeen       { get; } = new();
    public static Dictionary<ushort, int>    OpcodeEntryCount { get; } = new();
    public static Dictionary<ushort, string> ParseLog         { get; } = new();

    public static Dictionary<uint, string>   NumericIdToName  { get; } = new();
    public static Dictionary<string, string> StringIdToName   { get; } = new();
    public static HashSet<string>            PlayerNamesSeen  { get; } = new();
    public static int                        TotalParsed      { get; private set; }

    // -------------------------------------------------------------------
    public static void TryParse(ushort opcode, byte[] raw)
    {
        if (raw.Length < 4) return;

        OpcodeSeen[opcode] = OpcodeSeen.TryGetValue(opcode, out var c) ? c + 1 : 1;

        try
        {
            // FIX: Actually decompress instead of silently returning
            byte[] data = TryDecompress(raw, out bool wasCompressed);
            if (wasCompressed)
                ParseLog[opcode] = $"Zstd decompressed: {raw.Length} -> {data.Length} bytes";

            int entryCount = 0;

            // Strategy 1: length-prefixed strings (most reliable for registry packets)
            entryCount += ParseLengthPrefixedStrings(opcode, data);

            // Strategy 2: raw string scan fallback
            if (entryCount == 0)
                entryCount += ParseRawStrings(opcode, data);

            if (entryCount > 0)
            {
                OpcodeEntryCount[opcode] = entryCount;
                TotalParsed += entryCount;
                RegistrySyncReceived = true;

                if (FoundAtOpcode == 0xFFFF)
                    FoundAtOpcode = opcode;

                ParseLog[opcode] = $"Parsed {entryCount} entries" +
                                   (wasCompressed ? " (Zstd)" : " (raw)");
            }
            else
            {
                ParseLog[opcode] = wasCompressed
                    ? $"Decompressed but no entries found ({data.Length} bytes)"
                    : $"No entries found ({raw.Length} bytes)";
            }
        }
        catch (Exception ex)
        {
            ParseLog[opcode] = $"Parse error: {ex.Message}";
        }
    }

    // -------------------------------------------------------------------
    // Hytale registry uses length-prefixed UTF-8 strings.
    // Format: [2B LE length][...UTF-8 bytes]  OR  [4B LE length][...UTF-8 bytes]
    // We try both.
    private static int ParseLengthPrefixedStrings(ushort opcode, byte[] data)
    {
        int count = 0;

        // Try 2-byte length prefix
        count += ScanLengthPrefixed(data, 2);

        // Try 4-byte length prefix if 2-byte found nothing
        if (count == 0)
            count += ScanLengthPrefixed(data, 4);

        return count;
    }

    private static int ScanLengthPrefixed(byte[] data, int prefixSize)
    {
        int count = 0;
        int i = 0;
        while (i < data.Length - prefixSize - 2)
        {
            int len = prefixSize == 2
                ? BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(i))
                : (int)BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(i));

            if (len < 3 || len > 256 || i + prefixSize + len > data.Length)
            {
                i++;
                continue;
            }

            var strSpan = data.AsSpan(i + prefixSize, len);
            if (!strSpan.ToArray().All(b => b >= 32 && b <= 126))
            {
                i++;
                continue;
            }

            string str = Encoding.UTF8.GetString(strSpan);
            if (IsItemIdPattern(str))
            {
                StringIdToName[str] = str;
                NumericIdToName[ComputeHash(str)] = str;
                count++;
                i += prefixSize + len;
                continue;
            }
            if (IsPlayerNamePattern(str))
            {
                PlayerNamesSeen.Add(str);
            }

            i++;
        }
        return count;
    }

    private static int ParseRawStrings(ushort opcode, byte[] data)
    {
        int count = 0;
        foreach (var str in ExtractStrings(data))
        {
            if (IsItemIdPattern(str))
            {
                count++;
                StringIdToName[str] = str;
                NumericIdToName[ComputeHash(str)] = str;
            }
            if (IsPlayerNamePattern(str))
                PlayerNamesSeen.Add(str);
        }
        return count;
    }

    // -------------------------------------------------------------------
    private static byte[] TryDecompress(byte[] raw, out bool wasCompressed)
    {
        wasCompressed = false;
        // Zstd magic: bytes 28 B5 2F FD (LE 0xFD2FB528)
        if (raw.Length >= 4 &&
            raw[0] == 0x28 && raw[1] == 0xB5 &&
            raw[2] == 0x2F && raw[3] == 0xFD)
        {
            try
            {
                using var decomp = new ZstdSharp.Decompressor();
                var result = decomp.Unwrap(raw).ToArray();
                wasCompressed = true;
                return result;
            }
            catch
            {
                // Fall through to raw
            }
        }
        return raw;
    }

    // -------------------------------------------------------------------
    public static void Clear()
    {
        NumericIdToName.Clear();
        StringIdToName.Clear();
        PlayerNamesSeen.Clear();
        OpcodeSeen.Clear();
        OpcodeEntryCount.Clear();
        ParseLog.Clear();
        TotalParsed = 0;
        RegistrySyncReceived = false;
        FoundAtOpcode = 0xFFFF;
    }

    // -------------------------------------------------------------------
    private static bool IsItemIdPattern(string s) =>
        s.Length >= 3 && s.Length <= 64 &&
        (s.Contains('_') || s.Contains(':')) &&
        s.All(c => char.IsLetterOrDigit(c) || c == '_' || c == ':' || c == '.' || c == '-') &&
        !s.All(char.IsDigit);

    private static bool IsPlayerNamePattern(string s) =>
        s.Length >= 3 && s.Length <= 32 &&
        s.All(c => char.IsLetterOrDigit(c) || c == '_');

    private static List<string> ExtractStrings(byte[] data, int minLen = 4)
    {
        var results = new List<string>();
        var sb      = new StringBuilder();
        foreach (var b in data)
        {
            if (b >= 32 && b <= 126) sb.Append((char)b);
            else
            {
                if (sb.Length >= minLen) results.Add(sb.ToString());
                sb.Clear();
            }
        }
        if (sb.Length >= minLen) results.Add(sb.ToString());
        return results;
    }

    // FNV-1a 32-bit hash (consistent with original)
    private static uint ComputeHash(string s)
    {
        const uint FNV_OFFSET = 2166136261u;
        const uint FNV_PRIME  = 16777619u;
        uint hash = FNV_OFFSET;
        foreach (char c in s)
        {
            hash ^= c;
            hash *= FNV_PRIME;
        }
        return hash;
    }
}
