// FILE: Memory/MemoryLogger.cs + MemoryDumper.cs + SnapshotSystem.cs
// ============================================================
// Structured logging, memory-region dumping, snapshots & diff,
// and a pointer-graph for visualizing chains in the UI.

using System.Text;

namespace HyForce.Memory;

// ============================================================================
// 1.  STRUCTURED MEMORY LOGGER
// ============================================================================

public enum LogLevel { Debug, Info, Warn, Error }

public sealed class MemoryLogEntry
{
    public DateTime  Time     { get; init; } = DateTime.Now;
    public LogLevel  Level    { get; init; }
    public string    Category { get; init; } = "";
    public string    Message  { get; init; } = "";

    public string Prefix => Level switch
    {
        LogLevel.Debug => "[DBG]",
        LogLevel.Info  => "[INF]",
        LogLevel.Warn  => "[WRN]",
        LogLevel.Error => "[ERR]",
        _              => "[???]"
    };

    public System.Numerics.Vector4 Color => Level switch
    {
        LogLevel.Debug => new(0.6f, 0.6f, 0.6f, 1f),
        LogLevel.Info  => new(0.9f, 0.9f, 0.9f, 1f),
        LogLevel.Warn  => new(1f,   0.8f, 0.2f, 1f),
        LogLevel.Error => new(1f,   0.3f, 0.3f, 1f),
        _              => new(1f,   1f,   1f,   1f)
    };

    public override string ToString() =>
        $"{Time:HH:mm:ss.fff} {Prefix} {(string.IsNullOrEmpty(Category) ? "" : $"[{Category}] ")}{Message}";
}

/// <summary>Thread-safe, capped ring-buffer logger for the memory subsystem.</summary>
public sealed class MemoryLogger
{
    private readonly object                 _lock    = new();
    private readonly Queue<MemoryLogEntry>  _entries = new();
    private readonly int                    _cap;

    public int                  Count    => _entries.Count;
    public LogLevel             MinLevel { get; set; } = LogLevel.Info;

    public event Action<MemoryLogEntry>? OnEntry;

    public MemoryLogger(int capacity = 2000) { _cap = capacity; }

    public void Log(LogLevel level, string msg, string cat = "")
    {
        if (level < MinLevel) return;
        var entry = new MemoryLogEntry { Level = level, Message = msg, Category = cat };
        lock (_lock)
        {
            _entries.Enqueue(entry);
            while (_entries.Count > _cap) _entries.Dequeue();
        }
        OnEntry?.Invoke(entry);
    }

    public void Debug(string msg, string cat = "") => Log(LogLevel.Debug, msg, cat);
    public void Info (string msg, string cat = "") => Log(LogLevel.Info,  msg, cat);
    public void Warn (string msg, string cat = "") => Log(LogLevel.Warn,  msg, cat);
    public void Error(string msg, string cat = "") => Log(LogLevel.Error, msg, cat);

    public List<MemoryLogEntry> GetAll()
    {
        lock (_lock) return new List<MemoryLogEntry>(_entries);
    }

    public List<MemoryLogEntry> GetLast(int n)
    {
        lock (_lock)
        {
            int skip = Math.Max(0, _entries.Count - n);
            return _entries.Skip(skip).ToList();
        }
    }

    public void Clear() { lock (_lock) _entries.Clear(); }

    public void ExportToFile(string path)
    {
        var lines = GetAll().Select(e => e.ToString());
        File.WriteAllLines(path, lines, Encoding.UTF8);
    }
}

// ============================================================================
// 2.  MEMORY REGION DUMPER
// ============================================================================

public sealed class MemoryDumper
{
    private readonly SignatureScanner _scanner;
    private readonly MemoryLogger     _log;

    public MemoryDumper(SignatureScanner scanner, MemoryLogger log)
    {
        _scanner = scanner;
        _log     = log;
    }

    // -- Formatted hex dump ------------------------------------------------

    /// <summary>
    /// Read <paramref name="length"/> bytes from <paramref name="address"/> and
    /// return an annotated hex + ASCII dump string (like xxd/Cheat Engine view).
    /// </summary>
    public string HexDump(IntPtr address, int length, int bytesPerRow = 16)
    {
        var data = _scanner.ReadBytes(address, length);
        if (data == null)
        {
            _log.Warn($"[DUMP] Could not read {length} bytes @ 0x{(ulong)address:X}");
            return $"<read failed @ 0x{(ulong)address:X}>";
        }

        var sb = new StringBuilder();
        sb.AppendLine($"-- Memory Dump: 0x{(ulong)address:X16} (+{length} bytes) --");

        for (int row = 0; row < data.Length; row += bytesPerRow)
        {
            // Address column
            ulong rowAddr = (ulong)address + (ulong)row;
            sb.Append($"{rowAddr:X16}  ");

            // Hex bytes
            for (int col = 0; col < bytesPerRow; col++)
            {
                if (row + col < data.Length)
                    sb.Append($"{data[row + col]:X2} ");
                else
                    sb.Append("   ");
                if (col == bytesPerRow / 2 - 1) sb.Append(' ');
            }

            // ASCII column
            sb.Append(" |");
            for (int col = 0; col < bytesPerRow && row + col < data.Length; col++)
            {
                byte b = data[row + col];
                sb.Append(b >= 32 && b <= 126 ? (char)b : '.');
            }
            sb.AppendLine("|");
        }
        return sb.ToString();
    }

    // -- Struct dump (4-byte grid with type guesses) -----------------------

    public string StructDump(IntPtr address, int length = 256)
    {
        var data = _scanner.ReadBytes(address, length);
        if (data == null) return "<read failed>";

        var sb = new StringBuilder();
        sb.AppendLine($"-- Struct Dump: 0x{(ulong)address:X16} --");
        sb.AppendLine($"{"Offset",-8} {"Hex",-12} {"Int32",-12} {"Float",-14} {"Pointer?",-20} {"Guess"}");
        sb.AppendLine(new string('-', 80));

        for (int i = 0; i < data.Length - 3; i += 4)
        {
            int    iv  = BitConverter.ToInt32(data,  i);
            uint   uv  = BitConverter.ToUInt32(data, i);
            float  fv  = BitConverter.ToSingle(data, i);
            string hex = BitConverter.ToString(data, i, 4).Replace("-", " ");

            string ptrStr = "";
            if (i + 7 < data.Length)
            {
                long raw = BitConverter.ToInt64(data, i);
                if (PointerWalker.IsValidHeapPointer((IntPtr)raw))
                    ptrStr = $"0x{(ulong)raw:X}";
            }

            string guess = GuessFieldType(fv, iv, ptrStr != "");
            sb.AppendLine($"+0x{i:X3}    {hex,-12} {iv,-12} {fv,-14:F4} {ptrStr,-20} {guess}");
        }
        return sb.ToString();
    }

    // -- Save dump to disk -------------------------------------------------

    public void DumpToFile(IntPtr address, int length, string outputDir)
    {
        string filename = Path.Combine(outputDir,
            $"dump_0x{(ulong)address:X}_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
        Directory.CreateDirectory(outputDir);

        var hexDump    = HexDump(address, length);
        var structDump = StructDump(address, Math.Min(length, 256));
        File.WriteAllText(filename, hexDump + "\n\n" + structDump, Encoding.UTF8);

        _log.Info($"[DUMP] Saved to {Path.GetFileName(filename)}");
    }

    private static string GuessFieldType(float f, int iv, bool isPtr)
    {
        if (isPtr) return "Pointer";
        if (!float.IsNaN(f) && !float.IsInfinity(f) && Math.Abs(f) < 1e6 && Math.Abs(f) > 1e-4) return $"Float ~{f:F2}";
        if (iv > 0 && iv < 1_000_000) return $"Int ~{iv}";
        if (iv == 0) return "Zero";
        return "Unknown";
    }
}

// ============================================================================
// 3.  SNAPSHOT SYSTEM -- compare memory states over time
// ============================================================================

public sealed class MemorySnapshot
{
    public string   Name      { get; set; } = "";
    public DateTime Timestamp { get; init; } = DateTime.Now;
    public IntPtr   Address   { get; init; }
    public int      Length    { get; init; }
    public byte[]   Data      { get; init; } = Array.Empty<byte>();

    public string AddrHex => $"0x{(ulong)Address:X}";
}

public sealed class SnapshotDiff
{
    public MemorySnapshot  A       { get; init; } = null!;
    public MemorySnapshot  B       { get; init; } = null!;
    public List<DiffRange> Ranges  { get; init; } = new();
    public int             Changed { get; init; }

    public string Summary =>
        $"{Changed} bytes changed across {Ranges.Count} ranges";
}

public readonly struct DiffRange
{
    public int    Offset  { get; init; }
    public int    Length  { get; init; }
    public byte[] OldData { get; init; }
    public byte[] NewData { get; init; }

    public string OffsetHex => $"+0x{Offset:X3}";
    public string OldHex    => BitConverter.ToString(OldData).Replace("-", " ");
    public string NewHex    => BitConverter.ToString(NewData).Replace("-", " ");
}

public sealed class SnapshotSystem
{
    private readonly SignatureScanner    _scanner;
    private readonly MemoryLogger        _log;
    private readonly List<MemorySnapshot> _snapshots = new();

    public IReadOnlyList<MemorySnapshot> Snapshots => _snapshots;

    public SnapshotSystem(SignatureScanner scanner, MemoryLogger log)
    {
        _scanner = scanner;
        _log     = log;
    }

    public MemorySnapshot? Take(IntPtr address, int length, string name = "")
    {
        var data = _scanner.ReadBytes(address, length);
        if (data == null)
        {
            _log.Warn($"[SNAP] Could not read {length}B @ 0x{(ulong)address:X}");
            return null;
        }

        var snap = new MemorySnapshot
        {
            Name    = string.IsNullOrEmpty(name) ? $"snap_{_snapshots.Count}" : name,
            Address = address,
            Length  = length,
            Data    = data
        };
        _snapshots.Add(snap);
        _log.Info($"[SNAP] Saved '{snap.Name}' ({length}B @ {snap.AddrHex})");
        return snap;
    }

    /// <summary>Byte-diff two snapshots (must be same address and length).</summary>
    public SnapshotDiff Diff(MemorySnapshot a, MemorySnapshot b)
    {
        int minLen  = Math.Min(a.Data.Length, b.Data.Length);
        var ranges  = new List<DiffRange>();
        int changed = 0;

        int i = 0;
        while (i < minLen)
        {
            if (a.Data[i] == b.Data[i]) { i++; continue; }

            // Start of changed range
            int start = i;
            while (i < minLen && a.Data[i] != b.Data[i]) { changed++; i++; }

            int len    = i - start;
            var oldD   = a.Data[start..(start + len)];
            var newD   = b.Data[start..(start + len)];
            ranges.Add(new DiffRange { Offset = start, Length = len, OldData = oldD, NewData = newD });
        }

        _log.Info($"[SNAP] Diff '{a.Name}' vs '{b.Name}': {changed}B changed");
        return new SnapshotDiff { A = a, B = b, Ranges = ranges, Changed = changed };
    }

    /// <summary>Export diff as readable text.</summary>
    public string FormatDiff(SnapshotDiff diff)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"-- DIFF: '{diff.A.Name}' @ {diff.A.Timestamp:HH:mm:ss} vs '{diff.B.Name}' @ {diff.B.Timestamp:HH:mm:ss} --");
        sb.AppendLine(diff.Summary);
        sb.AppendLine();

        foreach (var r in diff.Ranges)
        {
            sb.AppendLine($"{r.OffsetHex} ({r.Length}B):");
            sb.AppendLine($"  OLD: {r.OldHex}");
            sb.AppendLine($"  NEW: {r.NewHex}");

            // Attempt float interpretation of changed bytes
            if (r.NewData.Length >= 4)
            {
                float fNew = BitConverter.ToSingle(r.NewData, 0);
                float fOld = BitConverter.ToSingle(r.OldData, 0);
                if (!float.IsNaN(fNew) && !float.IsNaN(fOld))
                    sb.AppendLine($"  As Float: {fOld:F4} -> {fNew:F4}  (D {fNew - fOld:+F4;-F4})");
            }
        }
        return sb.ToString();
    }

    public void Remove(MemorySnapshot s)  { _snapshots.Remove(s); }
    public void ClearAll()                { _snapshots.Clear(); }

    public void ExportAllDiffs(string outputDir)
    {
        if (_snapshots.Count < 2) return;
        Directory.CreateDirectory(outputDir);
        for (int i = 1; i < _snapshots.Count; i++)
        {
            if (_snapshots[i].Address != _snapshots[i - 1].Address) continue;
            var diff = Diff(_snapshots[i - 1], _snapshots[i]);
            string path = Path.Combine(outputDir, $"diff_{i:D3}_{DateTime.Now:HHmmss}.txt");
            File.WriteAllText(path, FormatDiff(diff), Encoding.UTF8);
        }
        _log.Info($"[SNAP] Exported diffs to {outputDir}");
    }
}

// ============================================================================
// 4.  POINTER GRAPH -- visualize pointer chains in ImGui
// ============================================================================

public sealed class PointerGraphNode
{
    public IntPtr              Address  { get; set; }
    public string              Label    { get; set; } = "";
    public byte[]              Preview  { get; set; } = Array.Empty<byte>();
    public List<PointerGraphNode> Children { get; } = new();
    public int                 Depth    { get; set; }
    public bool                IsExpanded { get; set; } = true;

    public string AddrHex    => $"0x{(ulong)Address:X}";
    public string PreviewHex => BitConverter.ToString(Preview.Take(8).ToArray()).Replace("-", " ");
}

public sealed class PointerGraph
{
    private readonly SignatureScanner _scanner;
    private readonly MemoryLogger     _log;

    public List<PointerGraphNode> Roots { get; } = new();

    public PointerGraph(SignatureScanner scanner, MemoryLogger log)
    {
        _scanner = scanner;
        _log     = log;
    }

    /// <summary>
    /// Build a pointer graph rooted at <paramref name="rootAddr"/>,
    /// walking up to <paramref name="maxDepth"/> levels deep.
    /// At each node, scan the first 64 bytes for valid heap pointers and follow them.
    /// </summary>
    public PointerGraphNode? Build(IntPtr rootAddr, int maxDepth = 3, int maxChildrenPerNode = 4)
    {
        if (!PointerWalker.IsValidHeapPointer(rootAddr)) return null;
        Roots.Clear();
        var root = BuildNode(rootAddr, 0, maxDepth, maxChildrenPerNode, new HashSet<IntPtr>());
        if (root != null) Roots.Add(root);
        return root;
    }

    private PointerGraphNode? BuildNode(IntPtr addr, int depth, int maxDepth,
        int maxChildren, HashSet<IntPtr> visited)
    {
        if (depth > maxDepth || !PointerWalker.IsValidHeapPointer(addr)) return null;
        if (!visited.Add(addr)) return null;  // cycle guard

        var preview = _scanner.ReadBytes(addr, 32) ?? Array.Empty<byte>();
        var node = new PointerGraphNode
        {
            Address = addr,
            Label   = $"0x{(ulong)addr:X}",
            Preview = preview,
            Depth   = depth
        };

        if (depth < maxDepth)
        {
            // Find child pointers in first 64 bytes
            int childCount = 0;
            for (int i = 0; i < preview.Length - 7 && childCount < maxChildren; i += 8)
            {
                long raw  = BitConverter.ToInt64(preview, i);
                var  ptr  = (IntPtr)raw;
                if (!PointerWalker.IsValidHeapPointer(ptr)) continue;

                var child = BuildNode(ptr, depth + 1, maxDepth, maxChildren, visited);
                if (child != null)
                {
                    child.Label = $"+0x{i:X2} -> 0x{(ulong)ptr:X}";
                    node.Children.Add(child);
                    childCount++;
                }
            }
        }
        return node;
    }

    /// <summary>Render the graph as indented text (for the log panel).</summary>
    public string FormatAsText(PointerGraphNode? root = null)
    {
        var sb   = new StringBuilder();
        var r    = root ?? Roots.FirstOrDefault();
        if (r == null) return "<empty>";
        FormatNode(r, sb, "");
        return sb.ToString();
    }

    private static void FormatNode(PointerGraphNode node, StringBuilder sb, string indent)
    {
        sb.AppendLine($"{indent}[{node.Label}]  {node.PreviewHex}");
        foreach (var child in node.Children)
            FormatNode(child, sb, indent + "  ");
    }
}
