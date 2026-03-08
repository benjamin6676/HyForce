// Core/ChunkAccumulator.cs  v18
// Parses 0x83 SetChunk S2C frames and builds a 2D loaded-chunk map.
//
// SetChunk wire format (post-Zstd):
//   [4B LE int32 chunk_x]
//   [4B LE int32 chunk_z]
//   [4B LE uint32 chunk_size_y]  (height of chunk in blocks)
//   [...block data — we skip for now, just record the coords]
//
// Result: a dictionary of (chunkX, chunkZ) → ChunkInfo
// Used by ChunkMapTab to render a 2D radar/map.

using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace HyForce.Core;

public class ChunkInfo
{
    public int       ChunkX     { get; set; }
    public int       ChunkZ     { get; set; }
    public uint      HeightY    { get; set; }
    public DateTime  ReceivedAt { get; set; } = DateTime.UtcNow;
    public int       UpdateCount{ get; set; }
    // Highest non-empty Y (for color-coding elevation)
    public float     SurfaceY   { get; set; }
}

public class ChunkAccumulator
{
    private readonly ConcurrentDictionary<(int,int), ChunkInfo> _chunks = new();
    private readonly List<string> _log    = new();
    private readonly object       _logLock= new();

    private int _parseErrors;
    private int _totalReceived;

    // Bounds of known world
    public int MinX { get; private set; } = int.MaxValue;
    public int MaxX { get; private set; } = int.MinValue;
    public int MinZ { get; private set; } = int.MaxValue;
    public int MaxZ { get; private set; } = int.MinValue;

    public IReadOnlyDictionary<(int,int),ChunkInfo> Chunks => _chunks;
    public int ChunkCount    => _chunks.Count;
    public int ParseErrors   => _parseErrors;
    public int TotalReceived => _totalReceived;

    public event Action<ChunkInfo>? OnChunkAdded;
    public event Action<string>?    OnLog;
    public IReadOnlyList<string> Log { get { lock (_logLock) return _log.ToList(); } }

    public void ProcessChunkPacket(byte[] payload, ushort opcode)
    {
        if (payload == null || payload.Length < 12) return;
        try
        {
            int cx = BinaryPrimitives.ReadInt32LittleEndian(payload.AsSpan(0));
            int cz = BinaryPrimitives.ReadInt32LittleEndian(payload.AsSpan(4));
            uint hy = BinaryPrimitives.ReadUInt32LittleEndian(payload.AsSpan(8));

            var key = (cx, cz);
            bool isNew = !_chunks.ContainsKey(key);
            var ci = _chunks.GetOrAdd(key, _ => new ChunkInfo { ChunkX = cx, ChunkZ = cz });
            ci.HeightY     = hy;
            ci.SurfaceY    = hy;
            ci.ReceivedAt  = DateTime.UtcNow;
            ci.UpdateCount++;

            // Update bounds
            if (cx < MinX) MinX = cx; if (cx > MaxX) MaxX = cx;
            if (cz < MinZ) MinZ = cz; if (cz > MaxZ) MaxZ = cz;

            _totalReceived++;
            if (isNew)
            {
                OnChunkAdded?.Invoke(ci);
                if (_totalReceived % 25 == 0)
                    AddLog($"[CHUNK] {_chunks.Count} chunks loaded  bounds X:[{MinX},{MaxX}] Z:[{MinZ},{MaxZ}]");
            }
        }
        catch (Exception ex)
        {
            _parseErrors++;
            AddLog($"[CHUNK-ERR] {ex.Message}");
        }
    }

    public void Clear()
    {
        _chunks.Clear();
        MinX = MaxX = MinZ = MaxZ = 0;
        AddLog("[CHUNK] Cleared");
    }

    private void AddLog(string msg)
    {
        var line = $"[{DateTime.Now:HH:mm:ss.fff}] {msg}";
        lock (_logLock) { _log.Add(line); if (_log.Count > 500) _log.RemoveAt(0); }
        OnLog?.Invoke(line);
    }
}
