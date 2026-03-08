// Core/TradeCapture.cs  v18
// Records 0xCB SendWindowAction C2S frames during merchant interactions.
// Allows replaying captured transactions with modified item output slots.
//
// Transaction record:
//   - Window ID from the open window context
//   - List of 0xCB C2S frames in order
//   - Timestamps for timing-accurate replay

using System;
using System.Collections.Generic;
using System.Linq;

namespace HyForce.Core;

public class TradeTransaction
{
    public Guid   Id          { get; } = Guid.NewGuid();
    public string Label       { get; set; } = "";
    public DateTime StartedAt { get; set; } = DateTime.UtcNow;
    public List<(DateTime Time, byte[] Data)> Frames { get; } = new();
    public int  FrameCount => Frames.Count;
    public bool IsComplete  { get; set; }

    public string Summary => $"{Label}  {FrameCount} actions @ {StartedAt:HH:mm:ss}";
}

public class TradeCapture
{
    private readonly List<TradeTransaction> _transactions = new();
    private TradeTransaction?               _current;
    private readonly List<string>           _log     = new();
    private readonly object                 _logLock = new();

    public bool IsCapturing => _current != null;
    public IReadOnlyList<TradeTransaction> Transactions => _transactions;
    public IReadOnlyList<string> Log { get { lock (_logLock) return _log.ToList(); } }

    public event Action<string>? OnLog;

    // Called when pipe sends 0xC3 (trade C2S) or MSG_QUIC_STREAM direction=C→S with 0xCB
    public void FeedWindowAction(byte[] data)
    {
        if (_current == null) return;
        _current.Frames.Add((DateTime.UtcNow, (byte[])data.Clone()));
        AddLog($"[TRADE] Frame #{_current.FrameCount}  {data.Length}B  " +
               $"hex={BitConverter.ToString(data, 0, Math.Min(16, data.Length)).Replace("-", " ")}");
    }

    public void StartCapture(string label = "")
    {
        _current = new TradeTransaction { Label = string.IsNullOrEmpty(label) ? $"Trade #{_transactions.Count+1}" : label };
        AddLog($"[TRADE] Capture started: {_current.Label}");
    }

    public TradeTransaction? StopCapture()
    {
        if (_current == null) return null;
        _current.IsComplete = true;
        _transactions.Add(_current);
        var t = _current;
        _current = null;
        AddLog($"[TRADE] Captured: {t.Label}  {t.FrameCount} frames");
        if (_transactions.Count > 50) _transactions.RemoveAt(0);
        return t;
    }

    public void CancelCapture()
    {
        _current = null;
        AddLog("[TRADE] Capture cancelled");
    }

    /// <summary>
    /// Build a modified version of a captured transaction's N-th frame,
    /// replacing the item slot bytes at offset 8 with a different slot index.
    /// Returns null if index out of range.
    /// </summary>
    public byte[]? BuildModifiedFrame(TradeTransaction tx, int frameIndex, int newSlot)
    {
        if (frameIndex < 0 || frameIndex >= tx.Frames.Count) return null;
        var (_, data) = tx.Frames[frameIndex];
        byte[] copy = (byte[])data.Clone();
        // SendWindowAction payload offset 4+4=8 from frame start: [4B actionType][4B slot]
        // Our frame has 8B header [4B flen][2B op][2B pad], then the payload
        // So slot is at byte offset 8+4 = 12 in the full frame
        if (copy.Length >= 16)
        {
            BitConverter.GetBytes((uint)newSlot).CopyTo(copy, 12);
            AddLog($"[TRADE] Modified frame {frameIndex}: slot → {newSlot}");
        }
        return copy;
    }

    public void Clear()
    {
        _transactions.Clear();
        _current = null;
        AddLog("[TRADE] All transactions cleared");
    }

    private void AddLog(string msg)
    {
        var line = $"[{DateTime.Now:HH:mm:ss.fff}] {msg}";
        lock (_logLock) { _log.Add(line); if (_log.Count > 500) _log.RemoveAt(0); }
        OnLog?.Invoke(line);
    }
}
