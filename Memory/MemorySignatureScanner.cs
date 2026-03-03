// FILE: Memory/MemorySignatureScanner.cs
// ============================================================
// Core memory analysis engine for HyForce.
//
// Components in this file:
//   • Signature          — byte pattern with wildcards
//   • SignatureScanner   — multi-region parallel pattern scan
//   • PointerWalker      — validated multi-level pointer chain traversal
//   • StructureValidator — heuristic object layout checks
//   • MemoryRegionCache  — cached readable-region enumeration
//
// Design notes:
//   Hytale is a 64-bit JVM process (HotSpot/OpenJDK).
//   – Object header:  8 bytes (mark word) + 4 bytes (compressed klass ptr)
//     padded to 16 bytes → first real field at offset 16.
//   – References (OOPs): 4 bytes with UseCompressedOops (default), or 8 bytes.
//   – Floats/ints:    4 bytes, doubles: 8 bytes.
//   – Java String:    char[] (UTF-16LE), length as int32 at char[]-8.
//
// Usage (from MemoryAnalysisTab or anywhere else):
//   var scanner = new SignatureScanner(processHandle, log);
//   var sig = Signature.FromAob("?? ?? ?? 3F 00 00 80 3F", "HealthFloat");
//   var results = scanner.Scan(sig);

using System.Buffers;
using System.Runtime.InteropServices;

namespace HyForce.Memory;

// ════════════════════════════════════════════════════════════════════════════
// 1.  SIGNATURE DEFINITION
// ════════════════════════════════════════════════════════════════════════════

/// <summary>
/// A byte-pattern + wildcard definition.
/// Example: "48 8B 05 ?? ?? ?? ?? 48 8B 48 10" scans for a MOV instruction
/// with unknown 4-byte displacement.
/// </summary>
public sealed class Signature
{
    public string    Name           { get; init; } = "Unnamed";
    public byte?[]   Pattern        { get; init; } = Array.Empty<byte?>();
    public int       ResultOffset   { get; init; } // Bytes from match start to the pointer-of-interest
    public bool      Dereference    { get; init; } // True = read 4/8 bytes at result to get final address
    public int       DerefSize      { get; init; } = 8;
    public string    Description    { get; init; } = "";

    // ── Factories ────────────────────────────────────────────────────────

    /// <summary>
    /// Parse an IDA-style AOB string:
    ///   "48 8B 05 ?? ?? ?? ??"
    ///   '??' and '?' are wildcards.
    /// </summary>
    public static Signature FromAob(string aob, string name, int offset = 0, bool deref = false)
    {
        var parts   = aob.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var pattern = new byte?[parts.Length];
        for (int i = 0; i < parts.Length; i++)
            pattern[i] = (parts[i] == "??" || parts[i] == "?")
                ? null
                : Convert.ToByte(parts[i], 16);

        return new Signature { Name = name, Pattern = pattern, ResultOffset = offset, Dereference = deref };
    }

    /// <summary>Exact byte array match, no wildcards.</summary>
    public static Signature FromBytes(byte[] bytes, string name, int offset = 0) =>
        new() { Name = name, Pattern = bytes.Select(b => (byte?)b).ToArray(), ResultOffset = offset };

    /// <summary>UTF-16LE string pattern (for JVM class/field names in heap).</summary>
    public static Signature FromUtf16String(string text, string name) =>
        FromBytes(System.Text.Encoding.Unicode.GetBytes(text), name);

    /// <summary>UTF-8 string pattern (for JVM class metadata / modified UTF-8).</summary>
    public static Signature FromUtf8String(string text, string name) =>
        FromBytes(System.Text.Encoding.UTF8.GetBytes(text), name);
}

// ════════════════════════════════════════════════════════════════════════════
// 2.  SCAN RESULT
// ════════════════════════════════════════════════════════════════════════════

public sealed class ScanResult
{
    public IntPtr    MatchAddress   { get; init; }  // Address of first matching byte
    public IntPtr    ResultAddress  { get; init; }  // MatchAddress + Signature.ResultOffset (+ optional deref)
    public string    SignatureName  { get; init; } = "";
    public byte[]    MatchBytes     { get; init; } = Array.Empty<byte>();
    public double    Confidence     { get; set; }  = 1.0;
    public string    Notes          { get; set; }  = "";

    public string AddressHex => $"0x{(ulong)ResultAddress:X16}";
    public override string ToString() =>
        $"[{SignatureName}] match@0x{(ulong)MatchAddress:X} → result@0x{(ulong)ResultAddress:X} conf={Confidence:F2}";
}

// ════════════════════════════════════════════════════════════════════════════
// 3.  SIGNATURE SCANNER
// ════════════════════════════════════════════════════════════════════════════

public sealed class SignatureScanner
{
    [DllImport("kernel32.dll")] static extern bool  ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, int size, out int read);
    [DllImport("kernel32.dll")] static extern IntPtr VirtualQueryEx(IntPtr h, IntPtr addr, out MEMORY_BASIC_INFORMATION mbi, uint size);

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress; public IntPtr AllocationBase;
        public uint   AllocationProtect; public ushort PartitionId; public ushort _pad;
        public IntPtr RegionSize;
        public uint   State; public uint Protect; public uint Type;
    }

    private const uint MEM_COMMIT       = 0x1000;
    private const uint PAGE_GUARD       = 0x100;
    private const uint READABLE_MASK    = 0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80;
    private const int  CHUNK_SIZE       = 256 * 1024;
    private const int  MAX_RESULTS      = 1024;

    private readonly IntPtr              _handle;
    private readonly MemoryLogger        _log;
    private          MemoryRegionCache?  _regionCache;
    private          DateTime            _cacheExpiry = DateTime.MinValue;

    public SignatureScanner(IntPtr processHandle, MemoryLogger log)
    {
        _handle = processHandle;
        _log    = log;
    }

    // ── Public API ────────────────────────────────────────────────────────

    public List<ScanResult> Scan(Signature sig, int maxResults = MAX_RESULTS) =>
        Scan(new[] { sig }, maxResults);

    public List<ScanResult> Scan(IEnumerable<Signature> signatures, int maxResults = MAX_RESULTS)
    {
        var results  = new List<ScanResult>();
        var sigs     = signatures.ToArray();
        var regions  = GetCachedRegions();

        _log.Info($"[SCAN] Scanning {regions.Count} regions for {sigs.Length} signature(s)");

        // Process regions in parallel (read-only, each region is independent)
        var bag = new System.Collections.Concurrent.ConcurrentBag<ScanResult>();

        Parallel.ForEach(regions, new ParallelOptions { MaxDegreeOfParallelism = 4 }, region =>
        {
            if (bag.Count >= maxResults) return;
            try
            {
                int chunkSize = (int)Math.Min(region.Size, (long)CHUNK_SIZE);
                byte[] buf    = ArrayPool<byte>.Shared.Rent(chunkSize);
                try
                {
                    if (!ReadProcessMemory(_handle, region.BaseAddress, buf, chunkSize, out int read) || read == 0)
                        return;

                    foreach (var sig in sigs)
                    {
                        var hits = ScanBuffer(buf, read, region.BaseAddress, sig);
                        foreach (var hit in hits)
                            bag.Add(hit);
                        if (bag.Count >= maxResults) break;
                    }
                }
                finally { ArrayPool<byte>.Shared.Return(buf); }
            }
            catch { }
        });

        results.AddRange(bag.Take(maxResults));
        _log.Info($"[SCAN] Found {results.Count} result(s)");
        return results;
    }

    /// <summary>Convenience: scan one AOB string and return the first match or null.</summary>
    public ScanResult? ScanFirst(string aob, string name, int offset = 0, bool deref = false) =>
        Scan(Signature.FromAob(aob, name, offset, deref), 1).FirstOrDefault();

    // ── Read helpers ──────────────────────────────────────────────────────

    public byte[]? ReadBytes(IntPtr address, int count)
    {
        if (_handle == IntPtr.Zero || address == IntPtr.Zero || count <= 0) return null;
        var buf = new byte[count];
        return ReadProcessMemory(_handle, address, buf, count, out int r) && r == count ? buf : null;
    }

    public T? Read<T>(IntPtr address) where T : unmanaged
    {
        int size = Marshal.SizeOf<T>();
        var bytes = ReadBytes(address, size);
        if (bytes == null) return null;
        return MemoryMarshal.Read<T>(bytes);
    }

    public IntPtr ReadPointer(IntPtr address)
    {
        var v = Read<long>(address);
        return v.HasValue ? (IntPtr)v.Value : IntPtr.Zero;
    }

    // ── Internal scan ─────────────────────────────────────────────────────

    private List<ScanResult> ScanBuffer(byte[] buf, int len, IntPtr baseAddr, Signature sig)
    {
        var results = new List<ScanResult>();
        var pattern = sig.Pattern;
        int pLen    = pattern.Length;
        if (pLen == 0 || len < pLen) return results;

        for (int i = 0; i <= len - pLen; i++)
        {
            if (!MatchAt(buf, i, pattern)) continue;

            var matchAddr  = baseAddr + i;
            var resultAddr = matchAddr + sig.ResultOffset;

            if (sig.Dereference)
            {
                var derefBytes = ReadBytes(resultAddr, sig.DerefSize);
                if (derefBytes == null) continue;
                resultAddr = sig.DerefSize == 4
                    ? (IntPtr)BitConverter.ToInt32(derefBytes)
                    : (IntPtr)BitConverter.ToInt64(derefBytes);
            }

            var matchBytes = new byte[Math.Min(pLen, 32)];
            Array.Copy(buf, i, matchBytes, 0, matchBytes.Length);

            results.Add(new ScanResult
            {
                MatchAddress   = matchAddr,
                ResultAddress  = resultAddr,
                SignatureName  = sig.Name,
                MatchBytes     = matchBytes,
            });
        }
        return results;
    }

    private static bool MatchAt(byte[] buf, int offset, byte?[] pattern)
    {
        for (int j = 0; j < pattern.Length; j++)
            if (pattern[j].HasValue && buf[offset + j] != pattern[j].Value)
                return false;
        return true;
    }

    // ── Region enumeration ────────────────────────────────────────────────

    private List<MemoryRegion> GetCachedRegions()
    {
        if (_regionCache != null && DateTime.UtcNow < _cacheExpiry)
            return _regionCache.Regions;

        _regionCache = new MemoryRegionCache(EnumerateRegions());
        _cacheExpiry = DateTime.UtcNow.AddSeconds(10);
        _log.Info($"[REGIONS] Enumerated {_regionCache.Regions.Count} readable regions");
        return _regionCache.Regions;
    }

    private List<MemoryRegion> EnumerateRegions()
    {
        var list  = new List<MemoryRegion>();
        nint addr = 0;
        while (true)
        {
            var r = VirtualQueryEx(_handle, (IntPtr)addr, out var mbi, (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>());
            if (r == IntPtr.Zero) break;

            nint size = (nint)(ulong)(nuint)(nint)mbi.RegionSize;
            if (size <= 0) break;

            if (mbi.State == MEM_COMMIT &&
                (mbi.Protect & READABLE_MASK) != 0 &&
                (mbi.Protect & PAGE_GUARD) == 0 &&
                size > 0x1000 && size < 0x40000000)
            {
                list.Add(new MemoryRegion(mbi.BaseAddress, (long)size));
            }

            addr = (nint)mbi.BaseAddress + size;
        }
        return list;
    }
}

// ════════════════════════════════════════════════════════════════════════════
// 4.  POINTER WALKER
// ════════════════════════════════════════════════════════════════════════════

/// <summary>
/// Walk a multi-level pointer chain with bounds checking at each step.
/// Example: playerBase → +0x10 → +0x3C  reads *(*(base+0x10)+0x3C)
/// </summary>
public sealed class PointerWalker
{
    private readonly SignatureScanner _scanner;
    private readonly MemoryLogger     _log;

    public PointerWalker(SignatureScanner scanner, MemoryLogger log)
    {
        _scanner = scanner;
        _log     = log;
    }

    /// <summary>
    /// Walk <paramref name="offsets"/> levels of pointers starting from <paramref name="base"/>.
    /// Returns IntPtr.Zero on any bad dereference or out-of-range pointer.
    /// </summary>
    public IntPtr Walk(IntPtr @base, params int[] offsets)
    {
        var current = @base;
        for (int i = 0; i < offsets.Length; i++)
        {
            current += offsets[i];
            if (!IsValidHeapPointer(current))
            {
                _log.Warn($"[PTR] Invalid address 0x{(ulong)current:X} at step {i}");
                return IntPtr.Zero;
            }
            current = _scanner.ReadPointer(current);
            if (current == IntPtr.Zero || !IsValidHeapPointer(current))
            {
                _log.Warn($"[PTR] Null/invalid after deref at step {i}, offset +0x{offsets[i]:X}");
                return IntPtr.Zero;
            }
        }
        return current;
    }

    /// <summary>
    /// Walk a chain, reading the final value as T (not as a pointer).
    /// Walks all but the last offset as pointers, then reads T at (finalPtr + lastOffset).
    /// </summary>
    public T? WalkRead<T>(IntPtr @base, params int[] offsets) where T : unmanaged
    {
        if (offsets.Length == 0) return _scanner.Read<T>(@base);

        int[] chain    = offsets[..^1];
        int   lastOff  = offsets[^1];
        var   ptr      = Walk(@base, chain);
        if (ptr == IntPtr.Zero) return null;
        return _scanner.Read<T>(ptr + lastOff);
    }

    public static bool IsValidHeapPointer(IntPtr p)
    {
        ulong u = (ulong)p;
        return u > 0x10000 && u < 0x7FFF_FFFF_0000 && (u & 0x3) == 0;
    }
}

// ════════════════════════════════════════════════════════════════════════════
// 5.  STRUCTURE VALIDATOR
// ════════════════════════════════════════════════════════════════════════════

/// <summary>
/// Validates that a candidate address looks like a specific JVM object or structure.
/// Each check returns a confidence score 0.0–1.0.
/// </summary>
public sealed class StructureValidator
{
    private readonly SignatureScanner _scanner;

    public StructureValidator(SignatureScanner scanner) { _scanner = scanner; }

    // ── JVM object header validation ──────────────────────────────────────

    /// <summary>
    /// A valid JVM object header (HotSpot 64-bit) looks like:
    ///   bytes 0–7   : mark word (often 0x0000000000000001 for unlocked objects)
    ///   bytes 8–11  : compressed klass pointer — nonzero, points to metaspace
    ///   bytes 12–15 : padding (may be 0 or first field)
    /// Score approaches 1.0 as more checks pass.
    /// </summary>
    public double ValidateJvmObjectHeader(IntPtr addr)
    {
        var data = _scanner.ReadBytes(addr, 32);
        if (data == null) return 0;

        double score = 0;

        // Mark word: low bits 0x01 (unlocked) or 0x05 (biased-locking)
        ulong markWord = BitConverter.ToUInt64(data, 0);
        if ((markWord & 0x03) == 0x01) score += 0.3; // unlocked state
        if ((markWord & 0x07) == 0x05) score += 0.3; // biased-locking

        // Klass pointer (compressed, 32 bits) should be nonzero and < 2GB
        uint klass = BitConverter.ToUInt32(data, 8);
        if (klass > 0 && klass < 0x7FFF_FFFF) score += 0.4;

        return Math.Min(score, 1.0);
    }

    // ── Float-triple (Vec3) validation ───────────────────────────────────

    /// <summary>Three consecutive plausible floats that form a world coordinate.</summary>
    public double ValidateVec3(byte[] data, int offset)
    {
        if (offset + 11 >= data.Length) return 0;
        float x = BitConverter.ToSingle(data, offset);
        float y = BitConverter.ToSingle(data, offset + 4);
        float z = BitConverter.ToSingle(data, offset + 8);

        if (float.IsNaN(x) || float.IsNaN(y) || float.IsNaN(z)) return 0;
        if (float.IsInfinity(x) || float.IsInfinity(y) || float.IsInfinity(z)) return 0;

        double score = 0;
        // World coords: reasonable magnitude
        if (Math.Abs(x) < 100_000 && Math.Abs(y) < 10_000 && Math.Abs(z) < 100_000) score += 0.5;
        // At least one component is non-zero
        if (Math.Abs(x) > 0.01f || Math.Abs(y) > 0.01f || Math.Abs(z) > 0.01f) score += 0.3;
        // Y is vertical in Hytale — unlikely to be 0 unless on exact ground
        if (y != 0) score += 0.2;

        return score;
    }

    // ── Health-like float ─────────────────────────────────────────────────

    public double ValidateHealthFloat(float value)
    {
        if (float.IsNaN(value) || float.IsInfinity(value)) return 0;
        if (value < 0 || value > 40) return 0;        // Hytale heart system: 0–20 hearts
        return value > 0 && value <= 40 ? 0.8 : 0.3;
    }

    // ── Pointer array (entity list) ───────────────────────────────────────

    /// <summary>
    /// A contiguous array of N valid heap pointers = likely entity/object list.
    /// Returns ratio of valid pointers found.
    /// </summary>
    public double ValidatePointerArray(byte[] data, int offset, int count)
    {
        int valid = 0;
        for (int i = 0; i < count; i++)
        {
            int off = offset + i * 8;
            if (off + 7 >= data.Length) break;
            long ptr = BitConverter.ToInt64(data, off);
            if (PointerWalker.IsValidHeapPointer((IntPtr)ptr)) valid++;
        }
        return count > 0 ? (double)valid / count : 0;
    }
}

// ════════════════════════════════════════════════════════════════════════════
// 6.  MEMORY REGION CACHE
// ════════════════════════════════════════════════════════════════════════════

public sealed class MemoryRegionCache
{
    public List<MemoryRegion> Regions   { get; }
    public long               TotalSize => Regions.Sum(r => r.Size);

    public MemoryRegionCache(List<MemoryRegion> regions) { Regions = regions; }
}

public readonly struct MemoryRegion
{
    public IntPtr BaseAddress { get; }
    public long   Size        { get; }

    public MemoryRegion(IntPtr baseAddress, long size)
    {
        BaseAddress = baseAddress;
        Size        = size;
    }

    public override string ToString() =>
        $"[0x{(ulong)BaseAddress:X} size={Size / 1024}KB]";
}
