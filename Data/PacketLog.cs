using System.Collections.Concurrent;

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

    public void Add(Networking.CapturedPacket pkt)
    {
        byte[] raw = pkt.RawBytes;
        if (raw.Length == 0) return;

        ushort opcode = ReadOpcode(raw);
        string name = Protocol.OpcodeRegistry.Label(opcode, pkt.Direction);
        string encHint = Utils.ByteUtils.CalculateEntropy(raw) > 7.8 ? "encrypted" : "readable";

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
            CompressionMethod = compr,
            CompressedSize = raw.Length,
            DecompressedSize = compressed ? decompressed!.Length : raw.Length,
            EncryptionHint = encHint,
            RawHexPreview = Utils.ByteUtils.ToHex(raw, 24),
            DecompHexPreview = compressed ? Utils.ByteUtils.ToHex(decompressed!, 32) : Utils.ByteUtils.ToHex(raw, 32),
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

        if (pkt.Direction == Networking.PacketDirection.ServerToClient)
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

        if (pkt.IsTcp && pkt.Direction == Networking.PacketDirection.ServerToClient && opcode <= 0x3F)
        {
            Protocol.RegistrySyncParser.TryParse(opcode, raw);
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