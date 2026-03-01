// FILE: Data/PacketLog.cs
using System.Collections.Concurrent;
using HyForce.Networking;
using HyForce.Protocol;
using HyForce.Utils;

namespace HyForce.Data;

public class PacketLog
{
    private readonly Queue<PacketLogEntry> _entries = new();
    private readonly object _lock = new();
    private readonly int _maxSize;

    private readonly ConcurrentDictionary<ushort, int> _opcodeCounts = new();
    private readonly ConcurrentDictionary<ushort, PacketLogEntry> _opcodeLatest = new();

    private long _bytesScTotal, _bytesCsTotal, _countSc, _countCs;
    private long _bytesTcpTotal, _countTcp;
    private long _bytesUdpTotal, _countUdp;

    public PacketLog(int maxSize = 5000)
    {
        _maxSize = maxSize;
    }

    public long TotalPackets => _countSc + _countCs;
    public long PacketsSc => _countSc;
    public long PacketsCs => _countCs;
    public long BytesSc => _bytesScTotal;
    public long BytesCs => _bytesCsTotal;
    public long PacketsTcp => _countTcp;
    public long PacketsUdp => _countUdp;
    public long BytesTcp => _bytesTcpTotal;
    public long BytesUdp => _bytesUdpTotal;
    public int UniqueOpcodes => _opcodeCounts.Count;

    public void Add(CapturedPacket pkt)
    {
        byte[] raw = pkt.RawBytes;
        if (raw.Length == 0) return;

        ushort opcode = ReadOpcode(raw);
        string name = OpcodeRegistry.Label(opcode, pkt.Direction);
        string encHint = ByteUtils.CalculateEntropy(raw) > 7.8 ? "encrypted" : "readable";

        byte[]? decompressed = TryDecompress(raw, out string compr);
        bool compressed = compr != "none" && decompressed != null;

        var entry = new PacketLogEntry
        {
            Timestamp = pkt.Timestamp,
            Direction = pkt.Direction,
            ByteLength = raw.Length,
            OpcodeDecimal = opcode,
            OpcodeName = name,
            IsTcp = pkt.IsTcp,
            RawBytes = raw,
            CompressionMethod = compr,
            CompressedSize = raw.Length,
            DecompressedSize = compressed ? decompressed!.Length : raw.Length,
            EncryptionHint = encHint,
            RawHexPreview = ByteUtils.ToHex(raw, 24),
            DecompHexPreview = compressed ? ByteUtils.ToHex(decompressed!, 32) : ByteUtils.ToHex(raw, 32),
            Injected = pkt.Injected,
            QuicInfo = pkt.QuicInfo
        };

        lock (_lock)
        {
            _entries.Enqueue(entry);
            while (_entries.Count > _maxSize)
                _entries.Dequeue();
        }

        _opcodeCounts.AddOrUpdate(opcode, 1, (_, v) => v + 1);
        _opcodeLatest[opcode] = entry;

        if (pkt.Direction == PacketDirection.ServerToClient)
        {
            Interlocked.Add(ref _bytesScTotal, raw.Length);
            Interlocked.Increment(ref _countSc);
        }
        else
        {
            Interlocked.Add(ref _bytesCsTotal, raw.Length);
            Interlocked.Increment(ref _countCs);
        }

        if (pkt.IsTcp)
        {
            Interlocked.Add(ref _bytesTcpTotal, raw.Length);
            Interlocked.Increment(ref _countTcp);
        }
        else
        {
            Interlocked.Add(ref _bytesUdpTotal, raw.Length);
            Interlocked.Increment(ref _countUdp);
        }

        // Registry parsing with proper checks
        if (pkt.IsTcp && pkt.Direction == PacketDirection.ServerToClient)
        {
            RegistrySyncParser.TryParse(opcode, raw);

            // Force parse for known registry opcodes
            if (opcode >= 0x18 && opcode <= 0x3F && !RegistrySyncParser.RegistrySyncReceived)
            {
                ForceRegistryParse(opcode, raw);
            }
        }
    }

    private static ushort ReadOpcode(byte[] data)
    {
        if (data.Length >= 2)
            return (ushort)((data[0] << 8) | data[1]);
        return data.Length > 0 ? data[0] : (ushort)0;
    }

    private static byte[]? TryDecompress(byte[] data, out string method)
    {
        if (data.Length >= 4 && data[0] == 0x28 && data[1] == 0xB5 && data[2] == 0x2F && data[3] == 0xFD)
        {
            method = "zstd";
            return null;
        }

        if (data.Length >= 2 && data[0] == 0x1F && data[1] == 0x8B)
        {
            method = "gzip";
            try
            {
                using var ms = new MemoryStream(data);
                using var gzip = new System.IO.Compression.GZipStream(ms, System.IO.Compression.CompressionMode.Decompress);
                using var outMs = new MemoryStream();
                gzip.CopyTo(outMs);
                return outMs.ToArray();
            }
            catch { return null; }
        }

        method = "none";
        return null;
    }

    // Force registry parse - uses reflection to access private setters
    private static void ForceRegistryParse(ushort opcode, byte[] raw)
    {
        try
        {
            int offset = raw.Length > 2 ? 2 : 0;
            var data = raw.Skip(offset).ToArray();
            var strings = ByteUtils.ExtractStrings(data, 3);

            int itemCount = 0;
            foreach (var str in strings)
            {
                if (IsLikelyItemId(str))
                {
                    itemCount++;
                    RegistrySyncParser.StringIdToName[str] = str;
                    uint numericId = Fnv1aHash(str);
                    RegistrySyncParser.NumericIdToName[numericId] = str;
                }
            }

            if (itemCount > 0)
            {
                RegistrySyncParser.OpcodeEntryCount[opcode] = itemCount;

                // Use reflection to set private properties
                var type = typeof(RegistrySyncParser);

                var registryReceivedField = type.GetField("<RegistrySyncReceived>k__BackingField",
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
                registryReceivedField?.SetValue(null, true);

                var foundAtOpcodeField = type.GetField("<FoundAtOpcode>k__BackingField",
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
                foundAtOpcodeField?.SetValue(null, opcode);

                var totalParsedField = type.GetField("<TotalParsed>k__BackingField",
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
                var currentTotal = (int?)totalParsedField?.GetValue(null) ?? 0;
                totalParsedField?.SetValue(null, currentTotal + itemCount);

                RegistrySyncParser.ParseLog[opcode] = $"Force-parsed {itemCount} entries";
            }
        }
        catch { }
    }

    private static bool IsLikelyItemId(string str)
    {
        return str.Contains('_') && (
            str.StartsWith("Armor_", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("Ingredient_", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("Weapon_", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("Tool_", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("Block_", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("Ore_", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("Wood_", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("Plant_", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("Soil_", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("Utility_", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("Item_", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("Entity_", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("Effect_", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("Particle_", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("Sound_", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("Music_", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("Biome_", StringComparison.OrdinalIgnoreCase) ||
            str.StartsWith("Structure_", StringComparison.OrdinalIgnoreCase)
        );
    }

    private static uint Fnv1aHash(string str)
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

    public List<PacketLogEntry> GetAll()
    {
        lock (_lock) return new List<PacketLogEntry>(_entries);
    }

    public List<PacketLogEntry> GetLast(int n)
    {
        lock (_lock)
        {
            var list = _entries.ToList();
            return list.Skip(Math.Max(0, list.Count - n)).ToList();
        }
    }

    public List<PacketLogEntry> GetTcpPackets() => GetAll().Where(p => p.IsTcp).ToList();
    public List<PacketLogEntry> GetUdpPackets() => GetAll().Where(p => !p.IsTcp).ToList();
    public IReadOnlyDictionary<ushort, int> GetOpcodeCounts() => _opcodeCounts;
    public int CountForOpcode(ushort opcode) => _opcodeCounts.TryGetValue(opcode, out int c) ? c : 0;
    public List<PacketLogEntry> GetByOpcode(ushort opcode) => GetAll().Where(e => e.OpcodeDecimal == opcode).ToList();
    public List<PacketLogEntry> GetOnePerOpcode() => _opcodeLatest.Values.OrderBy(e => e.OpcodeDecimal).ToList();

    public void Clear()
    {
        lock (_lock) _entries.Clear();
        _opcodeCounts.Clear();
        _opcodeLatest.Clear();
        Interlocked.Exchange(ref _bytesScTotal, 0);
        Interlocked.Exchange(ref _bytesCsTotal, 0);
        Interlocked.Exchange(ref _countSc, 0);
        Interlocked.Exchange(ref _countCs, 0);
        Interlocked.Exchange(ref _bytesTcpTotal, 0);
        Interlocked.Exchange(ref _countTcp, 0);
        Interlocked.Exchange(ref _bytesUdpTotal, 0);
        Interlocked.Exchange(ref _countUdp, 0);
    }

    public string GenerateReport()
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("=== PACKET LOG REPORT ===");
        sb.AppendLine($"Total Packets: {TotalPackets}");
        sb.AppendLine($"  TCP: {PacketsTcp} ({BytesTcp} bytes) - Registry/Login");
        sb.AppendLine($"  UDP: {PacketsUdp} ({BytesUdp} bytes) - Gameplay");
        sb.AppendLine();
        sb.AppendLine("Top Opcodes:");
        foreach (var kv in _opcodeCounts.OrderByDescending(x => x.Value).Take(10))
        {
            var name = _opcodeLatest.TryGetValue(kv.Key, out var e) ? e.OpcodeName : "?";
            sb.AppendLine($"  0x{kv.Key:X2} ({name}): {kv.Value}");
        }
        return sb.ToString();
    }
}