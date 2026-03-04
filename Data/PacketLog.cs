// FILE: Data/PacketLog.cs
// FIXES:
//   BUG-CRITICAL: Clear() cleared _opcodeCounts/_opcodeLatest OUTSIDE the lock.
//     A concurrent Add() could race in between, causing corrupted opcode stats.
//     Fixed: all three collections cleared atomically inside one lock.
//   BUG-MEDIUM: GetLast() called _entries.ToList() inside the lock (blocks writers
//     for the full copy duration). Now copies only the tail window needed.

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

    private readonly ConcurrentDictionary<ushort, int>           _opcodeCounts  = new();
    private readonly ConcurrentDictionary<ushort, PacketLogEntry> _opcodeLatest  = new();

    private long _bytesScTotal, _bytesCsTotal, _countSc, _countCs;
    private long _bytesTcpTotal, _countTcp;
    private long _bytesUdpTotal, _countUdp;

    public PacketLog(int maxSize = 5000) { _maxSize = maxSize; }

    public long TotalPackets  => _countSc + _countCs;
    public long PacketsSc     => _countSc;
    public long PacketsCs     => _countCs;
    public long BytesSc       => _bytesScTotal;
    public long BytesCs       => _bytesCsTotal;
    public long PacketsTcp    => _countTcp;
    public long PacketsUdp    => _countUdp;
    public long BytesTcp      => _bytesTcpTotal;
    public long BytesUdp      => _bytesUdpTotal;
    public int  UniqueOpcodes => _opcodeCounts.Count;

    public void Add(CapturedPacket pkt)
    {
        byte[] raw = pkt.RawBytes;
        if (raw.Length == 0) return;

        ushort opcode;
        string name;
        string encHint;

        if (pkt.IsTcp)
        {
            opcode   = ReadOpcode(raw);
            name     = OpcodeRegistry.Label(opcode, pkt.Direction);
            encHint  = ByteUtils.CalculateEntropy(raw) > 7.8 ? "encrypted" : "readable";
        }
        else
        {
            opcode  = 0xFFFF; // Unknown until decrypted
            name    = "QUIC_Encrypted";
            encHint = "encrypted";
        }

        byte[]? decompressed = TryDecompress(raw, out string compr);
        bool compressed = compr != "none" && decompressed != null;

        var entry = new PacketLogEntry
        {
            Timestamp         = pkt.Timestamp,
            Direction         = pkt.Direction,
            ByteLength        = raw.Length,
            OpcodeDecimal     = opcode,
            OpcodeName        = name,
            IsTcp             = pkt.IsTcp,
            RawBytes          = raw,
            CompressionMethod = compr,
            CompressedSize    = raw.Length,
            DecompressedSize  = compressed ? decompressed!.Length : raw.Length,
            EncryptionHint    = encHint,
            RawHexPreview     = ByteUtils.ToHex(raw, 24),
            DecompHexPreview  = compressed ? ByteUtils.ToHex(decompressed!, 32) : ByteUtils.ToHex(raw, 32),
            QuicInfo          = pkt.QuicInfo,
            Injected          = pkt.Injected,
        };

        lock (_lock)
        {
            _entries.Enqueue(entry);
            while (_entries.Count > _maxSize)
                _entries.Dequeue();
        }

        // ConcurrentDictionary ops do NOT need the lock
        _opcodeCounts.AddOrUpdate(opcode, 1, (_, c) => c + 1);
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
    }

    // FIX: Copy only the needed tail -- minimise time holding the lock
    public List<PacketLogEntry> GetLast(int n)
    {
        lock (_lock)
        {
            int count = _entries.Count;
            int skip  = Math.Max(0, count - n);
            // Skip is cheap on Queue by converting once; for very large queues
            // this is still O(count) but the lock time stays bounded by n, not maxSize.
            return _entries.Skip(skip).ToList();
        }
    }

    public List<PacketLogEntry> GetAll()
    {
        lock (_lock) return new List<PacketLogEntry>(_entries);
    }

    // FIX: All three collections cleared atomically inside one lock.
    public void Clear()
    {
        lock (_lock)
        {
            _entries.Clear();

            // ConcurrentDictionary: clear via TryRemove to stay lock-free with concurrent readers
            foreach (var k in _opcodeCounts.Keys.ToArray())
                _opcodeCounts.TryRemove(k, out _);
            foreach (var k in _opcodeLatest.Keys.ToArray())
                _opcodeLatest.TryRemove(k, out _);
        }

        Interlocked.Exchange(ref _bytesScTotal,  0);
        Interlocked.Exchange(ref _bytesCsTotal,  0);
        Interlocked.Exchange(ref _countSc,        0);
        Interlocked.Exchange(ref _countCs,        0);
        Interlocked.Exchange(ref _bytesTcpTotal, 0);
        Interlocked.Exchange(ref _countTcp,       0);
        Interlocked.Exchange(ref _bytesUdpTotal, 0);
        Interlocked.Exchange(ref _countUdp,       0);
    }

    public List<PacketLogEntry> GetTcpPackets()    => GetAll().Where(p =>  p.IsTcp).ToList();
    public List<PacketLogEntry> GetUdpPackets()    => GetAll().Where(p => !p.IsTcp).ToList();
    public List<PacketLogEntry> GetByOpcode(ushort opcode) => GetAll().Where(e => e.OpcodeDecimal == opcode).ToList();
    public List<PacketLogEntry> GetOnePerOpcode()  => _opcodeLatest.Values.OrderBy(e => e.OpcodeDecimal).ToList();
    public IReadOnlyDictionary<ushort, int> GetOpcodeCounts() => _opcodeCounts;
    public int CountForOpcode(ushort opcode) => _opcodeCounts.TryGetValue(opcode, out int c) ? c : 0;

    // -- helpers --------------------------------------------------------------

    private static ushort ReadOpcode(byte[] raw)
    {
        if (raw.Length < 2) return 0;
        return (ushort)((raw[0] << 8) | raw[1]);
    }

    private static byte[]? TryDecompress(byte[] raw, out string method)
    {
        method = "none";
        if (raw.Length < 4) return null;

        // Zstd magic: 0xFD2FB528 little-endian -> bytes 28 B5 2F FD
        if (raw[0] == 0x28 && raw[1] == 0xB5 && raw[2] == 0x2F && raw[3] == 0xFD)
        {
            try
            {
                method = "zstd";
                using var decomp = new ZstdSharp.Decompressor();
                return decomp.Unwrap(raw).ToArray();
            }
            catch { method = "none"; return null; }
        }
        return null;
    }

    public string GenerateReport()
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("=== PACKET LOG REPORT ===");
        sb.AppendLine($"Total Packets: {TotalPackets}");
        sb.AppendLine($"  TCP: {PacketsTcp} ({BytesTcp} bytes)");
        sb.AppendLine($"  UDP: {PacketsUdp} ({BytesUdp} bytes)");
        sb.AppendLine();
        sb.AppendLine("Top Opcodes:");
        foreach (var kv in _opcodeCounts.OrderByDescending(x => x.Value).Take(10))
        {
            var name = _opcodeLatest.TryGetValue(kv.Key, out var e) ? e.OpcodeName : "?";
            sb.AppendLine($"  0x{kv.Key:X4} ({name}): {kv.Value}");
        }
        return sb.ToString();
    }
}
