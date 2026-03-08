// Core/PermissionEscalator.cs  v20
// Systematically tests every permission bit in the 32-bit PlayerSetup mask.
// For each bit, injects a modified PlayerSetup and watches for behavioural
// changes (new opcodes arriving, UI unlocks, or disconnects).
//
// Escalation modes:
//   Single bit probe   — inject one bit at a time, delay, watch S2C response
//   All-bits sweep     — iterate all 32 bits sequentially
//   Mask brute-force   — try known admin/creative/mod mask values
//   Custom mask inject — direct mask write

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace HyForce.Core;

public enum PermBitResult { Unknown, NoEffect, GameplayChange, NewOpcode, Disconnected,
    S2CTriggered
}

public class PermBitInfo
{
    public int             Bit         { get; set; }
    public uint            Mask        => (uint)(1 << Bit);
    public PermBitResult   Result      { get; set; } = PermBitResult.Unknown;
    public string          Notes       { get; set; } = "";
    public DateTime        TestedAt    { get; set; }
    public List<ushort>    NewOpcodes  { get; } = new();   // S2C opcodes seen after inject
}

public class KnownMaskPreset
{
    public string Name        { get; set; } = "";
    public uint   Mask        { get; set; }
    public string Description { get; set; } = "";
}

public class PermissionEscalator
{
    // Known mask presets to try
    public static readonly List<KnownMaskPreset> Presets = new()
    {
        new() { Name="All Zero",       Mask=0x00000000, Description="Baseline — no permissions" },
        new() { Name="All Ones",       Mask=0xFFFFFFFF, Description="All bits set — maximum escalation attempt" },
        new() { Name="Creative",       Mask=0x00000001, Description="Bit 0 — likely creative/god mode flag" },
        new() { Name="Build",          Mask=0x00000002, Description="Bit 1 — build permission hypothesis" },
        new() { Name="Mod",            Mask=0x00000004, Description="Bit 2 — moderator flag hypothesis" },
        new() { Name="Admin",          Mask=0x00000008, Description="Bit 3 — admin flag hypothesis" },
        new() { Name="Fly",            Mask=0x00000010, Description="Bit 4 — flight permission hypothesis" },
        new() { Name="No Clip",        Mask=0x00000020, Description="Bit 5 — noclip server-side hypothesis" },
        new() { Name="Dev",            Mask=0x00000100, Description="Bit 8 — dev/internal flag hypothesis" },
        new() { Name="Spectator",      Mask=0x00000200, Description="Bit 9 — spectate mode flag hypothesis" },
        new() { Name="Creative+Build", Mask=0x00000003, Description="Bits 0+1 combined" },
        new() { Name="Admin+Creative", Mask=0x00000009, Description="Bits 0+3 combined" },
        new() { Name="All Lower",      Mask=0x0000FFFF, Description="Lower 16 bits set" },
        new() { Name="All Upper",      Mask=0xFFFF0000, Description="Upper 16 bits set" },
        new() { Name="Original",       Mask=0x00000000, Description="Restored from captured PlayerSetup" },
    };

    private readonly PermBitInfo[] _bits = Enumerable.Range(0, 32)
        .Select(i => new PermBitInfo { Bit = i }).ToArray();

    private CancellationTokenSource? _cts;
    private readonly List<string>    _log     = new();
    private readonly object          _logLock = new();

    public bool   IsScanning    { get; private set; }
    public int    ScanProgress  { get; private set; }
    public uint   CurrentMask   { get; private set; }
    public uint   OriginalMask  { get; private set; }

    // Callbacks — wired from AppState after pipe is connected
    public Action<int>?  InjectBit  { get; set; }  // calls pipe.PermTestBit
    public Action<uint>? InjectMask { get; set; }  // calls pipe.PermInjectMask

    // Called from AppState stream routing when a new S2C opcode arrives post-inject
    public void ObserveS2COpcode(ushort opcode)
    {
        if (!IsScanning) return;
        var bit = _bits.FirstOrDefault(b => b.Result == PermBitResult.Unknown && b.TestedAt != default);
        if (bit != null && !bit.NewOpcodes.Contains(opcode))
        {
            bit.NewOpcodes.Add(opcode);
            AddLog($"[PERM] Bit {bit.Bit}: new S2C opcode 0x{opcode:X4} observed after inject");
        }
    }

    public IReadOnlyList<PermBitInfo> Bits => _bits;
    public IReadOnlyList<string> Log { get { lock (_logLock) return _log.ToList(); } }
    public event Action<string>? OnLog;

    public void SetOriginalMask(uint mask)
    {
        OriginalMask = mask;
        // Update "Original" preset
        var orig = Presets.FirstOrDefault(p => p.Name == "Original");
        if (orig != null) orig.Mask = mask;
        AddLog($"[PERM] Original mask captured: 0x{mask:X8}");
    }

    public void InjectPreset(KnownMaskPreset preset)
    {
        CurrentMask = preset.Mask;
        InjectMask?.Invoke(preset.Mask);
        AddLog($"[PERM] Injecting preset '{preset.Name}' mask=0x{preset.Mask:X8}");
    }

    public void InjectCustom(uint mask)
    {
        CurrentMask = mask;
        InjectMask?.Invoke(mask);
        AddLog($"[PERM] Injecting custom mask=0x{mask:X8}");
    }

    public void RestoreOriginal()
    {
        InjectMask?.Invoke(OriginalMask);
        AddLog($"[PERM] Restored original mask=0x{OriginalMask:X8}");
    }

    public void StartBitSweep(int delayMs = 1500)
    {
        if (IsScanning) return;
        _cts     = new CancellationTokenSource();
        var tok  = _cts.Token;
        IsScanning   = true;
        ScanProgress = 0;
        foreach (var b in _bits) { b.Result = PermBitResult.Unknown; b.Notes = ""; b.NewOpcodes.Clear(); b.TestedAt = default; }
        AddLog($"[PERM] Starting 32-bit sweep  delay={delayMs}ms per bit");

        Task.Run(async () =>
        {
            try
            {
                for (int i = 0; i < 32 && !tok.IsCancellationRequested; i++)
                {
                    _bits[i].TestedAt = DateTime.UtcNow;
                    InjectBit?.Invoke(i);
                    AddLog($"[PERM] Testing bit {i:D2} (0x{1u << i:X8})…");
                    await Task.Delay(delayMs, tok);
                    // Mark unknown bits as NoEffect if no new opcodes arrived
                    if (_bits[i].NewOpcodes.Count == 0 && _bits[i].Result == PermBitResult.Unknown)
                        _bits[i].Result = PermBitResult.NoEffect;
                    ScanProgress = i + 1;
                }
                RestoreOriginal();
                AddLog($"[PERM] Sweep done — {_bits.Count(b => b.NewOpcodes.Count > 0)} bits triggered new opcodes");
            }
            catch (OperationCanceledException) { AddLog("[PERM] Sweep cancelled"); RestoreOriginal(); }
            finally { IsScanning = false; }
        }, tok);
    }

    public void StopSweep() { _cts?.Cancel(); IsScanning = false; }

    public void MarkBit(int bit, PermBitResult result, string notes = "")
    {
        if (bit < 0 || bit >= 32) return;
        _bits[bit].Result = result;
        _bits[bit].Notes  = notes;
        AddLog($"[PERM] Bit {bit} marked: {result}  {notes}");
    }

    public void Clear()
    {
        foreach (var b in _bits) { b.Result = PermBitResult.Unknown; b.Notes = ""; b.NewOpcodes.Clear(); }
        AddLog("[PERM] Cleared");
    }

    private void AddLog(string msg)
    {
        var line = $"[{DateTime.Now:HH:mm:ss.fff}] {msg}";
        lock (_logLock) { _log.Add(line); if (_log.Count > 1000) _log.RemoveAt(0); }
        OnLog?.Invoke(line);
    }
}
