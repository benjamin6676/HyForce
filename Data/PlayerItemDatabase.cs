using HyForce.Networking;
using System.Collections.Concurrent;

namespace HyForce.Data;

public class PlayerItemDatabase
{
    public ConcurrentDictionary<uint, ItemInfo> Items { get; } = new();
    public ConcurrentDictionary<string, PlayerInfo> Players { get; } = new();
    public HashSet<string> ItemNames { get; } = new();
    public HashSet<string> PlayerNames { get; } = new();

    public void ProcessPacket(CapturedPacket packet)
    {
        // Extract strings from packet data
        var strings = ExtractStrings(packet.RawBytes);

        foreach (var str in strings)
        {
            // Detect item IDs
            if (IsItemId(str))
            {
                ItemNames.Add(str);
                var hash = ComputeHash(str);
                Items[hash] = new ItemInfo
                {
                    Id = hash,
                    StringId = str,
                    Name = str,
                    FirstSeen = DateTime.Now
                };
            }

            // Detect player names
            if (IsPlayerName(str))
            {
                PlayerNames.Add(str);
                Players[str] = new PlayerInfo
                {
                    Name = str,
                    FirstSeen = DateTime.Now,
                    LastSeen = DateTime.Now
                };
            }
        }
    }

    private List<string> ExtractStrings(byte[] data)
    {
        var result = new List<string>();
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
                    result.Add(sb.ToString());
                sb.Clear();
            }
        }

        if (sb.Length >= 4)
            result.Add(sb.ToString());

        return result;
    }

    private bool IsItemId(string str)
    {
        return str.Contains('_') && (
            str.StartsWith("Armor_") ||
            str.StartsWith("Ingredient_") ||
            str.StartsWith("Weapon_") ||
            str.StartsWith("Tool_") ||
            str.StartsWith("Block_") ||
            str.StartsWith("Ore_") ||
            str.StartsWith("Wood_") ||
            str.StartsWith("Plant_") ||
            str.StartsWith("Soil_") ||
            str.StartsWith("Utility_") ||
            str.StartsWith("Item_")
        );
    }

    private bool IsPlayerName(string str)
    {
        return str.Length >= 3 && str.Length <= 16 &&
               str.All(c => char.IsLetterOrDigit(c) || c == '_') &&
               !str.Contains("__") &&
               !str.Contains('_');
    }

    private uint ComputeHash(string str)
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

    public void Clear()
    {
        Items.Clear();
        Players.Clear();
        ItemNames.Clear();
        PlayerNames.Clear();
    }
}

public class ItemInfo
{
    public uint Id { get; set; }
    public string StringId { get; set; } = "";
    public string Name { get; set; } = "";
    public DateTime FirstSeen { get; set; }
    public int SeenCount { get; set; }
}

public class PlayerInfo
{
    public string Name { get; set; } = "";
    public string? UUID { get; set; }
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
    public List<string> IPs { get; set; } = new();
}