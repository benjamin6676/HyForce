// FILE: Memory/MemoryField.cs + EntityScanner.cs
// ============================================================
// MemoryField:   Generic "live read + diff + UI binding" primitive.
// EntityScanner: Heuristic scan for entity arrays, ECS tables, id-indexed maps.

using System.Runtime.InteropServices;
using System.Text;

namespace HyForce.Memory;

// ============================================================================
// MEMORY FIELD -- the core UI data-binding primitive
// ============================================================================
//
// Design:
//   * Each MemoryField owns its address, type, and value history.
//   * Refresh() reads memory once and records the diff.
//   * The UI reads `DisplayValue`, `Changed`, and `RawBytes` -- it never
//     touches Win32 directly.
//   * Throttling: a shared MemoryFieldBatch calls Refresh() at most
//     `RefreshHz` times per second for its entire field list.
//
// Why a class, not a struct?
//   Fields need a mutable `Previous` value and optional child expansions,
//   so reference semantics avoid repeated boxing.

public sealed class MemoryField
{
    // -- Identity ----------------------------------------------------------
    public string   Name         { get; set; } = "";
    public IntPtr   Address      { get; set; }
    public int      Size         { get; set; }       // bytes to read
    public FieldKind Kind        { get; set; } = FieldKind.Unknown;
    public string   Group        { get; set; } = ""; // for collapsing in UI
    public bool     IsBookmarked { get; set; }

    // -- Current value -----------------------------------------------------
    public byte[]   RawBytes     { get; private set; } = Array.Empty<byte>();
    public byte[]   PrevBytes    { get; private set; } = Array.Empty<byte>();
    public bool     Changed      { get; private set; }
    public DateTime LastChanged  { get; private set; }
    public double   Confidence   { get; set; } = 1.0;

    // -- Interpreted display -----------------------------------------------
    public string DisplayValue
    {
        get
        {
            if (RawBytes.Length == 0) return "--";
            try
            {
                return Kind switch
                {
                    FieldKind.Float   => BitConverter.ToSingle(RawBytes, 0).ToString("F4"),
                    FieldKind.Vec3    => FormatVec3(),
                    FieldKind.Int32   => BitConverter.ToInt32(RawBytes, 0).ToString(),
                    FieldKind.UInt32  => BitConverter.ToUInt32(RawBytes, 0).ToString("X8"),
                    FieldKind.Int64   => BitConverter.ToInt64(RawBytes, 0).ToString(),
                    FieldKind.UInt64  => BitConverter.ToUInt64(RawBytes, 0).ToString("X16"),
                    FieldKind.Bool    => RawBytes[0] != 0 ? "true" : "false",
                    FieldKind.Pointer => $"0x{BitConverter.ToUInt64(RawBytes, 0):X16}",
                    FieldKind.String8 => ReadString8(),
                    FieldKind.String16=> ReadString16(),
                    _                 => BitConverter.ToString(RawBytes).Replace("-", " ")
                };
            }
            catch { return "error"; }
        }
    }

    public string HexPreview =>
        RawBytes.Length == 0 ? ""
        : BitConverter.ToString(RawBytes.Take(16).ToArray()).Replace("-", " ");

    // -- Child fields (for pointer expansion in UI) -------------------------
    public List<MemoryField> Children { get; } = new();
    public bool IsExpanded { get; set; }

    // -- Refresh -----------------------------------------------------------

    /// <summary>
    /// Read current bytes from <paramref name="scanner"/>.
    /// Returns true if value changed since last read.
    /// </summary>
    public bool Refresh(SignatureScanner scanner)
    {
        var fresh = scanner.ReadBytes(Address, Size);
        if (fresh == null) return false;

        PrevBytes = RawBytes;
        Changed   = !RawBytes.SequenceEqual(fresh);
        RawBytes  = fresh;

        if (Changed) LastChanged = DateTime.Now;

        // Refresh children too
        foreach (var child in Children)
            child.Refresh(scanner);

        return Changed;
    }

    // -- Child pointer expansion --------------------------------------------

    /// <summary>
    /// If this field is a Pointer kind, expand it by reading <paramref name="childCount"/>
    /// fields of <paramref name="childSize"/> bytes starting at the pointed-to address.
    /// </summary>
    public void ExpandPointer(SignatureScanner scanner, int childCount = 16, int childSize = 4)
    {
        if (Kind != FieldKind.Pointer || RawBytes.Length < 8) return;
        ulong ptr = BitConverter.ToUInt64(RawBytes, 0);
        if (ptr == 0 || ptr > 0x7FFF_FFFF_0000) return;

        Children.Clear();
        for (int i = 0; i < childCount; i++)
        {
            var child = new MemoryField
            {
                Name    = $"+0x{i * childSize:X3}",
                Address = (IntPtr)(ptr + (ulong)(i * childSize)),
                Size    = childSize,
                Kind    = childSize == 4 ? FieldKind.UInt32 : FieldKind.UInt64,
                Group   = Name
            };
            child.Refresh(scanner);
            Children.Add(child);
        }
    }

    // -- Factory helpers ---------------------------------------------------

    public static MemoryField Float(string name, IntPtr addr)     => new() { Name = name, Address = addr, Size = 4,  Kind = FieldKind.Float };
    public static MemoryField Vec3(string name, IntPtr addr)      => new() { Name = name, Address = addr, Size = 12, Kind = FieldKind.Vec3 };
    public static MemoryField Int32(string name, IntPtr addr)     => new() { Name = name, Address = addr, Size = 4,  Kind = FieldKind.Int32 };
    public static MemoryField Ptr64(string name, IntPtr addr)     => new() { Name = name, Address = addr, Size = 8,  Kind = FieldKind.Pointer };
    public static MemoryField Bool8(string name, IntPtr addr)     => new() { Name = name, Address = addr, Size = 1,  Kind = FieldKind.Bool };
    public static MemoryField Bytes(string name, IntPtr addr, int size) => new() { Name = name, Address = addr, Size = size, Kind = FieldKind.Bytes };

    // -- Private helpers ---------------------------------------------------

    private string FormatVec3()
    {
        float x = BitConverter.ToSingle(RawBytes, 0);
        float y = BitConverter.ToSingle(RawBytes, 4);
        float z = BitConverter.ToSingle(RawBytes, 8);
        return $"({x:F3}, {y:F3}, {z:F3})";
    }

    private string ReadString8()
    {
        int end = Array.IndexOf(RawBytes, (byte)0);
        return Encoding.UTF8.GetString(RawBytes, 0, end < 0 ? RawBytes.Length : end);
    }

    private string ReadString16()
    {
        int end = -1;
        for (int i = 0; i < RawBytes.Length - 1; i += 2)
            if (RawBytes[i] == 0 && RawBytes[i + 1] == 0) { end = i; break; }
        return Encoding.Unicode.GetString(RawBytes, 0, end < 0 ? RawBytes.Length : end);
    }
}

// -- Field kinds --------------------------------------------------------------
public enum FieldKind
{
    Unknown, Float, Vec3, Int32, UInt32, Int64, UInt64,
    Bool, Pointer, String8, String16, Bytes
}

// ============================================================================
// MEMORY FIELD BATCH -- throttled group refresh
// ============================================================================

public sealed class MemoryFieldBatch
{
    private readonly SignatureScanner _scanner;
    private          DateTime         _lastRefresh = DateTime.MinValue;

    public List<MemoryField> Fields       { get; } = new();
    public float             RefreshHz    { get; set; } = 10f;
    public int               ChangedCount { get; private set; }

    public MemoryFieldBatch(SignatureScanner scanner) { _scanner = scanner; }

    /// <summary>Refresh all fields if the interval has elapsed. Call from render loop.</summary>
    public void TryRefresh()
    {
        double intervalMs = 1000.0 / RefreshHz;
        if ((DateTime.Now - _lastRefresh).TotalMilliseconds < intervalMs) return;
        _lastRefresh  = DateTime.Now;
        ChangedCount  = 0;
        foreach (var f in Fields)
            if (f.Refresh(_scanner)) ChangedCount++;
    }

    public void Add(MemoryField f)    { Fields.Add(f); }
    public void Clear()               { Fields.Clear(); }

    /// <summary>Build fields from a discovered LocalPlayerState.</summary>
    public void PopulateFromPlayerState(LocalPlayerState player)
    {
        Fields.Clear();
        if (!player.IsValid) return;

        IntPtr b = player.BaseAddress;

        // Use scan-discovered addresses when available; fall back to hardcoded offsets.
        // Hardcoded offsets (+16, +28, etc.) are ONLY a last resort — the scanner
        // found more accurate addresses dynamically.
        IntPtr posAddr       = player.PosAddr       != IntPtr.Zero ? player.PosAddr       : b + 16;
        IntPtr rotAddr       = player.RotAddr        != IntPtr.Zero ? player.RotAddr       : b + 28;
        IntPtr healthAddr    = player.HealthAddr     != IntPtr.Zero ? player.HealthAddr    : b + 36;
        IntPtr maxHealthAddr = player.MaxHealthAddr  != IntPtr.Zero ? player.MaxHealthAddr : healthAddr + 4;

        Fields.Add(MemoryField.Vec3 ("Position",     posAddr));
        Fields.Add(MemoryField.Float("RotYaw",        rotAddr));
        Fields.Add(MemoryField.Float("RotPitch",      rotAddr + 4));
        Fields.Add(MemoryField.Float("Health",        healthAddr));
        Fields.Add(MemoryField.Float("MaxHealth",     maxHealthAddr));
        Fields.Add(MemoryField.Float("MoveSpeed",     b + 44));
        Fields.Add(MemoryField.Bool8("OnGround",      b + 48));
        Fields.Add(MemoryField.Ptr64("InventoryPtr",  b + 56));
        Fields.Add(MemoryField.Ptr64("NamePtr",       b + 64));

        // Raw dump for manual inspection
        Fields.Add(MemoryField.Bytes("RawDump[0..63]",   b,      64));
        Fields.Add(MemoryField.Bytes("RawDump[64..127]", b + 64, 64));

        // Refresh once immediately
        foreach (var f in Fields) f.Refresh(_scanner);
    }
}

// ============================================================================
// ENTITY SCANNER -- finds entity arrays / ECS tables / pointer lists
// ============================================================================
//
// Entity structure heuristics:
//   1. POINTER ARRAY:    N consecutive 8-byte values all passing IsValidHeapPointer.
//                        N >= 8 is a strong signal. Each pointed-to object should
//                        pass JVM header validation.
//   2. ECS COMPONENT TABLE: A region starting with a 4-byte int (count), followed
//                        by count * stride bytes where every stride-th slot
//                        has a valid pointer.
//   3. REPEATED STRUCT: A run of identical-sized blocks where block[0] and block[1]
//                        have the same non-zero bytes at the same sub-offsets.
//   4. ID TABLE:         Dense int32 sequence [0, 1, 2, ... N-1] followed by N pointers.

public sealed class EntityScanner
{
    private readonly SignatureScanner   _scanner;
    private readonly StructureValidator _validator;
    private readonly MemoryLogger       _log;

    public EntityScanner(SignatureScanner scanner, StructureValidator validator, MemoryLogger log)
    {
        _scanner   = scanner;
        _validator = validator;
        _log       = log;
    }

    // -- Main scan ---------------------------------------------------------

    public List<EntityRegionCandidate> Scan(int maxRegions = 200)
    {
        var results = new List<EntityRegionCandidate>();
        _log.Info($"[ENTITY] Starting entity structure scan...");

        // We do the actual region enumeration via a raw scan of
        // "regions containing many valid pointers".
        // Use the SignatureScanner's region cache indirectly via a targeted read loop.

        // Signature: 4 consecutive 8-byte aligned valid heap pointers
        // (this is a very common prefix for entity lists)
        // We scan for it using our generic AOB engine, then validate further.
        var arraySig = new Signature
        {
            Name    = "PointerArrayStart",
            // 8 bytes that all have bit patterns consistent with heap pointers:
            // just use a raw parallel scan below instead of an AOB for flexibility
            Pattern = Array.Empty<byte?>()
        };

        // Scan all memory in 1MB windows, looking for pointer density clusters
        var ptrArrayCandidates = FindPointerArrays(maxRegions * 4);
        foreach (var ca in ptrArrayCandidates.Take(maxRegions))
        {
            var candidate = AnalyzeCandidate(ca);
            if (candidate.Score > 0.2)
                results.Add(candidate);
        }

        results = results.OrderByDescending(r => r.Score).ToList();
        _log.Info($"[ENTITY] Found {results.Count} candidate entity regions");
        return results;
    }

    // -- Pointer array finder ----------------------------------------------

    private List<(IntPtr baseAddr, int length, byte[] data)> FindPointerArrays(int maxCandidates)
    {
        var results = new List<(IntPtr, int, byte[])>();

        // We can't enumerate regions directly here without the handle -- so we use
        // the scanner's ReadBytes in 1MB blocks across the expected heap range.
        // In practice a JVM heap lives between ~0x0000_0001_0000_0000 and ~0x0000_0010_0000_0000.
        long start   = 0x100000000;
        long end     = 0x1000000000;
        int  chunkSz = 1024 * 1024; // 1MB

        for (long addr = start; addr < end && results.Count < maxCandidates; addr += chunkSz)
        {
            var data = _scanner.ReadBytes((IntPtr)addr, chunkSz);
            if (data == null) continue;

            // Find runs of >= 8 valid pointers
            int runStart = -1, runLen = 0;
            for (int i = 0; i <= data.Length - 8; i += 8)
            {
                long raw = BitConverter.ToInt64(data, i);
                bool valid = PointerWalker.IsValidHeapPointer((IntPtr)raw);

                if (valid)
                {
                    if (runStart < 0) { runStart = i; runLen = 0; }
                    runLen++;
                }
                else if (runStart >= 0)
                {
                    if (runLen >= 8)
                    {
                        var chunk = new byte[runLen * 8];
                        Array.Copy(data, runStart, chunk, 0, chunk.Length);
                        results.Add(((IntPtr)(addr + runStart), runLen, chunk));
                    }
                    runStart = -1; runLen = 0;
                }
            }
        }
        return results;
    }

    // -- Candidate analysis ------------------------------------------------

    private EntityRegionCandidate AnalyzeCandidate((IntPtr addr, int ptrCount, byte[] data) ca)
    {
        var c = new EntityRegionCandidate
        {
            BaseAddress  = ca.addr,
            PointerCount = ca.ptrCount,
        };

        // Check how many pointed-to objects have valid JVM headers
        int validObjects = 0;
        int sampledCount = Math.Min(ca.ptrCount, 32);

        for (int i = 0; i < sampledCount; i++)
        {
            long raw = BitConverter.ToInt64(ca.data, i * 8);
            var  ptr = (IntPtr)raw;
            if (_validator.ValidateJvmObjectHeader(ptr) > 0.4) validObjects++;
        }

        double ptrValidRatio = (double)validObjects / sampledCount;
        c.ValidObjectRatio   = ptrValidRatio;

        // Stride detection: are all objects the same size?
        var sizes = new List<int>();
        for (int i = 0; i < Math.Min(sampledCount, 8); i++)
        {
            long raw  = BitConverter.ToInt64(ca.data, i * 8);
            var  ptr  = (IntPtr)raw;
            var  hdr  = _scanner.ReadBytes(ptr, 32);
            if (hdr == null) continue;
            // Estimate object size from the klass (not reliable without JVM internals,
            // so we just note that the header was readable)
            sizes.Add(hdr.Length);
        }

        bool sameSize = sizes.Distinct().Count() == 1;

        // Score
        c.Score  = ptrValidRatio * 0.6;
        c.Score += (ca.ptrCount >= 16 ? 0.2 : ca.ptrCount / 80.0);
        if (sameSize) c.Score += 0.1;
        c.Score = Math.Min(c.Score, 1.0);

        // Classify
        c.Kind = ca.ptrCount >= 64 ? EntityArrayKind.LargeArray
               : ca.ptrCount >= 16 ? EntityArrayKind.SmallArray
               : EntityArrayKind.PointerCluster;

        return c;
    }
}

// -- Entity candidate result ---------------------------------------------------
public sealed class EntityRegionCandidate
{
    public IntPtr          BaseAddress       { get; set; }
    public int             PointerCount      { get; set; }
    public double          ValidObjectRatio  { get; set; }
    public double          Score             { get; set; }
    public EntityArrayKind Kind              { get; set; }
    public string          Notes             { get; set; } = "";

    public string AddrHex    => $"0x{(ulong)BaseAddress:X}";
    public string ScoreStr   => $"{Score:F2}";
    public string Summary    => $"[{Kind}] {PointerCount} ptrs, {ValidObjectRatio:P0} valid, score={ScoreStr}";
}

public enum EntityArrayKind { Unknown, PointerCluster, SmallArray, LargeArray, EcsTable }
