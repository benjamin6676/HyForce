// Core/PacketRecorder.cs  v18
// Receives piped S2C stream frames and stores them in memory.
// Supports: record, stop, save to .hfrec binary file, load & replay.
//
// .hfrec format:
//   [4B magic = 0x48465243 "HFRC"]
//   [4B version = 1]
//   [8B session timestamp (UTC ticks)]
//   [4B frame count]
//   For each frame:
//     [8B UTC ticks timestamp]
//     [2B opcode]
//     [4B payload length]
//     [N bytes payload]

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace HyForce.Core;

public record RecordedFrame(
    DateTime Timestamp,
    ushort   Opcode,
    byte[]   Payload,
    bool     IsS2C
);

public class PacketRecorder
{
    private readonly List<RecordedFrame> _frames  = new();
    private readonly object              _lock    = new();
    private readonly List<string>        _log     = new();
    private readonly object              _logLock = new();

    private const int MaxFrames = 50_000;
    private const uint Magic    = 0x48465243;

    public bool IsRecording  { get; private set; }
    public int  FrameCount   { get { lock(_lock) return _frames.Count; } }
    public long TotalBytes   { get { lock(_lock) return _frames.Sum(f => (long)f.Payload.Length); } }

    public event Action<string>? OnLog;
    public IReadOnlyList<string> Log { get { lock (_logLock) return _log.ToList(); } }

    // ── Recording ──────────────────────────────────────────────────────────
    public void Start()
    {
        lock (_lock) _frames.Clear();
        IsRecording = true;
        AddLog("[REC] Recording started");
    }

    public void Stop()
    {
        IsRecording = false;
        AddLog($"[REC] Stopped — {FrameCount} frames  {TotalBytes / 1024.0:F1} KB");
    }

    public void Clear()
    {
        lock (_lock) _frames.Clear();
        AddLog("[REC] Cleared");
    }

    /// <summary>Called from AppState stream routing for every parsed packet.</summary>
    public void Feed(RecordedFrame frame)
    {
        if (!IsRecording) return;
        lock (_lock)
        {
            _frames.Add(frame);
            if (_frames.Count > MaxFrames) _frames.RemoveAt(0);
        }
    }

    public List<RecordedFrame> GetFrames()
    {
        lock (_lock) return _frames.ToList();
    }

    // ── Disk I/O ────────────────────────────────────────────────────────────
    public void SaveTo(string path)
    {
        List<RecordedFrame> snap;
        lock (_lock) snap = _frames.ToList();

        using var bw = new BinaryWriter(File.Open(path, FileMode.Create));
        bw.Write(Magic);
        bw.Write((uint)1);                                    // version
        bw.Write(DateTime.UtcNow.Ticks);
        bw.Write((uint)snap.Count);

        foreach (var f in snap)
        {
            bw.Write(f.Timestamp.Ticks);
            bw.Write(f.Opcode);
            bw.Write((uint)f.Payload.Length);
            bw.Write(f.Payload);
        }

        AddLog($"[REC] Saved {snap.Count} frames → {path}  ({new FileInfo(path).Length / 1024.0:F1} KB)");
    }

    public List<RecordedFrame> LoadFrom(string path)
    {
        var frames = new List<RecordedFrame>();
        using var br = new BinaryReader(File.OpenRead(path));

        uint magic = br.ReadUInt32();
        if (magic != Magic) throw new InvalidDataException("Not a .hfrec file");
        uint version = br.ReadUInt32();
        long sessionTicks = br.ReadInt64();
        uint count = br.ReadUInt32();

        for (uint i = 0; i < count; i++)
        {
            long ticks   = br.ReadInt64();
            ushort opcode = br.ReadUInt16();
            uint len     = br.ReadUInt32();
            byte[] payload = br.ReadBytes((int)len);
            frames.Add(new RecordedFrame(new DateTime(ticks, DateTimeKind.Utc), opcode, payload, true));
        }

        AddLog($"[REC] Loaded {frames.Count} frames from {Path.GetFileName(path)}  (session: {new DateTime(sessionTicks,DateTimeKind.Utc):HH:mm:ss})");
        return frames;
    }

    private void AddLog(string msg)
    {
        var line = $"[{DateTime.Now:HH:mm:ss.fff}] {msg}";
        lock (_logLock) { _log.Add(line); if (_log.Count > 1000) _log.RemoveAt(0); }
        OnLog?.Invoke(line);
    }
}
