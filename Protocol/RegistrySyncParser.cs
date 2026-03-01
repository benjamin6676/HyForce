// FILE: Protocol/RegistrySyncParser.cs
using HyForce.Utils;

namespace HyForce.Protocol;

public static class RegistrySyncParser
{
    public static bool RegistrySyncReceived { get; private set; }
    public static ushort FoundAtOpcode { get; private set; } = 0xFFFF;
    public static int TotalParsed { get; private set; }
    public static HashSet<ushort> OpcodeSeen { get; } = new();

    public static Dictionary<uint, string> NumericIdToName { get; } = new();
    public static Dictionary<string, string> StringIdToName { get; } = new();
    public static HashSet<string> PlayerNamesSeen { get; } = new();
    public static Dictionary<ushort, int> OpcodeEntryCount { get; } = new();
    public static Dictionary<ushort, string> ParseLog { get; } = new();

    public static void Reset()
    {
        RegistrySyncReceived = false;
        FoundAtOpcode = 0xFFFF;
        TotalParsed = 0;
        OpcodeSeen.Clear();
        NumericIdToName.Clear();
        StringIdToName.Clear();
        PlayerNamesSeen.Clear();
        OpcodeEntryCount.Clear();
        ParseLog.Clear();
    }

    public static bool TryParse(ushort opcode, byte[] data)
    {
        OpcodeSeen.Add(opcode);

        if (RegistrySyncReceived) return true;

        if (opcode < 0x18 || opcode > 0x3F)
            return false;

        try
        {
            int offset = (data.Length > 2 && (data[0] << 8 | data[1]) == opcode) ? 2 : 0;
            var payload = data.Skip(offset).ToArray();

            var strings = ByteUtils.ExtractStrings(payload);

            int itemCount = 0;
            int playerCount = 0;

            foreach (var str in strings)
            {
                if (IsItemId(str))
                {
                    itemCount++;
                    StringIdToName[str] = str;
                    uint hash = Fnv1aHash(str);
                    NumericIdToName[hash] = str;
                }
                else if (IsPlayerName(str))
                {
                    playerCount++;
                    PlayerNamesSeen.Add(str);
                }
            }

            if (itemCount > 0 || playerCount > 0)
            {
                RegistrySyncReceived = true;
                FoundAtOpcode = opcode;
                TotalParsed = itemCount + playerCount;
                OpcodeEntryCount[opcode] = itemCount + playerCount;
                ParseLog[opcode] = $"Parsed {itemCount} items, {playerCount} players";
                return true;
            }
        }
        catch (Exception ex)
        {
            ParseLog[opcode] = $"Error: {ex.Message}";
        }

        return false;
    }

    private static bool IsItemId(string str)
    {
        if (string.IsNullOrEmpty(str) || str.Length < 3) return false;
        if (!str.Contains('_')) return false;

        string[] prefixes = new[]
        {
            "Armor_", "Ingredient_", "Weapon_", "Tool_", "Block_", "Ore_",
            "Wood_", "Plant_", "Soil_", "Utility_", "Item_", "Entity_",
            "Effect_", "Particle_", "Sound_", "Music_", "Biome_", "Structure_"
        };

        return prefixes.Any(p => str.StartsWith(p, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsPlayerName(string str)
    {
        if (str.Length < 3 || str.Length > 16) return false;
        if (!str.All(c => char.IsLetterOrDigit(c) || c == '_')) return false;
        if (str.Contains("__")) return false;
        if (str.StartsWith("_") || str.EndsWith("_")) return false;
        return true;
    }

    private static uint Fnv1aHash(string str)
    {
        const uint FNV_PRIME = 16777619;
        const uint FNV_OFFSET_BASIS = 2166136261;

        uint hash = FNV_OFFSET_BASIS;
        foreach (char c in str)
        {
            hash ^= c;
            hash *= FNV_PRIME;
        }
        return hash;
    }
}