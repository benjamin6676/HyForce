namespace HyForce.Protocol;

public static class RegistrySyncParser
{
    public const ushort ScanOpcodeMin = 0x00;
    public const ushort ScanOpcodeMax = 0x3F;

    public static bool RegistrySyncReceived { get; private set; }
    public static ushort FoundAtOpcode { get; private set; } = 0xFFFF;

    public static Dictionary<ushort, int> OpcodeSeen { get; } = new();
    public static Dictionary<ushort, int> OpcodeEntryCount { get; private set; } = new(); // Public getter, private setter
    public static Dictionary<ushort, string> ParseLog { get; } = new();

    public static Dictionary<uint, string> NumericIdToName { get; } = new();
    public static Dictionary<string, string> StringIdToName { get; } = new();
    public static HashSet<string> PlayerNamesSeen { get; } = new();
    public static int TotalParsed { get; private set; }

    public static void TryParse(ushort opcode, byte[] raw)
    {
        if (raw.Length < 4) return;

        OpcodeSeen[opcode] = OpcodeSeen.TryGetValue(opcode, out var c) ? c + 1 : 1;

        try
        {
            bool isZstd = raw.Length >= 4 &&
                raw[0] == 0x28 && raw[1] == 0xB5 && raw[2] == 0x2F && raw[3] == 0xFD;

            if (isZstd)
            {
                ParseLog[opcode] = "Zstd compressed - needs decompression";
                return;
            }

            var strings = ExtractStrings(raw);
            int entryCount = 0;

            foreach (var str in strings)
            {
                if (IsItemIdPattern(str))
                {
                    entryCount++;
                    StringIdToName[str] = str;
                    uint numericId = ComputeHash(str);
                    NumericIdToName[numericId] = str;
                }

                if (IsPlayerNamePattern(str))
                {
                    PlayerNamesSeen.Add(str);
                }
            }

            if (entryCount > 0)
            {
                OpcodeEntryCount[opcode] = entryCount;
                TotalParsed += entryCount;
                RegistrySyncReceived = true;
                FoundAtOpcode = opcode;
                ParseLog[opcode] = $"Parsed {entryCount} entries";
            }
            else
            {
                ParseLog[opcode] = $"No entries found ({strings.Count} strings)";
            }
        }
        catch (Exception ex)
        {
            ParseLog[opcode] = $"Parse error: {ex.Message}";
        }
    }

    private static List<string> ExtractStrings(byte[] data)
    {
        var strings = new List<string>();
        var sb = new System.Text.StringBuilder();

        for (int i = 0; i < data.Length; i++)
        {
            if (data[i] >= 32 && data[i] <= 126)
            {
                sb.Append((char)data[i]);
            }
            else
            {
                if (sb.Length >= 4)
                    strings.Add(sb.ToString());
                sb.Clear();
            }
        }

        if (sb.Length >= 4)
            strings.Add(sb.ToString());

        return strings;
    }

    private static bool IsItemIdPattern(string str)
    {
        return str.Contains('_') &&
               (str.StartsWith("Armor_") ||
                str.StartsWith("Ingredient_") ||
                str.StartsWith("Weapon_") ||
                str.StartsWith("Tool_") ||
                str.StartsWith("Block_") ||
                str.StartsWith("Ore_") ||
                str.StartsWith("Wood_") ||
                str.StartsWith("Plant_") ||
                str.StartsWith("Soil_") ||
                str.StartsWith("Utility_"));
    }

    private static bool IsPlayerNamePattern(string str)
    {
        return str.Length >= 3 && str.Length <= 16 &&
               str.All(c => char.IsLetterOrDigit(c) || c == '_') &&
               !str.Contains("__");
    }

    private static uint ComputeHash(string str)
    {
        const uint FNV_PRIME = 16777619;
        const uint FNV_OFFSET_BASIS = 2166136261;

        uint hash = FNV_OFFSET_BASIS;
        foreach (var c in str)
        {
            hash ^= c;
            hash *= FNV_PRIME;
        }
        return hash;
    }

    public static void Clear()
    {
        RegistrySyncReceived = false;
        FoundAtOpcode = 0xFFFF;
        OpcodeSeen.Clear();
        OpcodeEntryCount.Clear();
        ParseLog.Clear();
        NumericIdToName.Clear();
        StringIdToName.Clear();
        PlayerNamesSeen.Clear();
        TotalParsed = 0;
    }

    public static string GetSummary()
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"RegistrySync Received: {RegistrySyncReceived}");
        sb.AppendLine($"Found at Opcode: 0x{FoundAtOpcode:X2}");
        sb.AppendLine($"Numeric IDs: {NumericIdToName.Count}");
        sb.AppendLine($"String IDs: {StringIdToName.Count}");
        sb.AppendLine($"Player Names: {PlayerNamesSeen.Count}");
        sb.AppendLine($"Total Parsed: {TotalParsed}");
        return sb.ToString();
    }
}