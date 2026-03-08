// Core/SessionCapture.cs  v16
// Captures session-establishment packets:
//   0x02 AuthToken, 0x03 ConnectAccept, 0x12 PlayerSetup
//
// These arrive once per session at connect time.  Storing them lets us:
//   1. Extract our own entity ID (PlayerSetup usually has it at byte 8)
//   2. Inspect permission/role bytes for analysis
//   3. Patch and re-inject ConnectAccept/PlayerSetup with modified flags
//      (works best on locally-hosted or modded servers that don't re-validate)
//
// Wire format assumption (best-effort reverse-engineering):
//   PlayerSetup (0x12):
//     [4B LE frame_len][2B opcode][2B pad]
//     [8B LE uint64 entity_id]          -- offset 0 in payload
//     [4B LE uint32 gamemode_flags]     -- offset 8
//     [4B LE uint32 permission_mask]    -- offset 12
//     [...rest: world name, etc.]
//
//   ConnectAccept (0x03):
//     [4B LE session_token_len]
//     [N bytes session token]

using System;
using System.Collections.Generic;
using System.Buffers.Binary;
using System.Text;

namespace HyForce.Core;

public enum GameMode : uint
{
    Survival  = 0,
    Creative  = 1,
    Adventure = 2,
    Spectator = 3,
}

public class SessionSnapshot
{
    public byte[]   RawPlayerSetup   { get; set; } = Array.Empty<byte>();
    public byte[]   RawConnectAccept { get; set; } = Array.Empty<byte>();
    public byte[]   RawAuthToken     { get; set; } = Array.Empty<byte>();
    public DateTime CapturedAt       { get; set; } = DateTime.UtcNow;

    // Parsed fields from PlayerSetup
    public ulong    SelfEntityId     { get; set; }
    public uint     GameModeFlags    { get; set; }
    public uint     PermissionMask   { get; set; }
    public string   WorldName        { get; set; } = "";
    public string   GameModeStr      => ((GameMode)(GameModeFlags & 0xFF)).ToString();

    public bool     HasPlayerSetup   => RawPlayerSetup.Length > 0;
    public bool     HasConnectAccept => RawConnectAccept.Length > 0;
}

public class SessionCapture
{
    private readonly List<string> _log = new();
    private readonly object _logLock = new();

    public SessionSnapshot? Current { get; private set; }
    public List<SessionSnapshot> History { get; } = new();

    public event Action<SessionSnapshot>? OnSessionCaptured;
    public event Action<string>?          OnLog;

    public IReadOnlyList<string> Log { get { lock (_logLock) return _log.ToList(); } }

    // ── Ingest raw session packets ─────────────────────────────────────────
    public void ProcessPacket(ushort opcode, byte[] payload)
    {
        switch (opcode)
        {
            case 0x02: // AuthToken
                AddLog($"[SESSION] AuthToken captured  {payload.Length}B");
                EnsureCurrent().RawAuthToken = payload;
                break;

            case 0x03: // ConnectAccept
                AddLog($"[SESSION] ConnectAccept captured  {payload.Length}B");
                EnsureCurrent().RawConnectAccept = payload;
                break;

            case 0x12: // PlayerSetup
                AddLog($"[SESSION] PlayerSetup captured  {payload.Length}B");
                var snap = EnsureCurrent();
                snap.RawPlayerSetup = payload;
                ParsePlayerSetup(snap, payload);
                History.Add(snap);
                if (History.Count > 20) History.RemoveAt(0);
                Current = snap;
                OnSessionCaptured?.Invoke(snap);
                AddLog($"[SESSION] Parsed: EntityID=0x{snap.SelfEntityId:X}  GameMode={snap.GameModeStr}  Perms=0x{snap.PermissionMask:X8}  World='{snap.WorldName}'");
                break;
        }
    }

    // ── Build modified PlayerSetup payload ────────────────────────────────
    /// <summary>
    /// Returns a copy of the last PlayerSetup payload with GameMode and PermissionMask
    /// replaced.  Inject via ForgeStream (opcode 0x12).
    /// </summary>
    public byte[]? BuildModifiedPlayerSetup(GameMode gameMode, uint permMask)
    {
        if (Current?.RawPlayerSetup == null || Current.RawPlayerSetup.Length < 16) return null;

        byte[] patched = (byte[])Current.RawPlayerSetup.Clone();
        // Offset 8: gameModeFlags (4B LE)
        BitConverter.GetBytes((uint)gameMode).CopyTo(patched, 8);
        // Offset 12: permissionMask (4B LE)
        BitConverter.GetBytes(permMask).CopyTo(patched, 12);
        AddLog($"[SESSION] Built modified PlayerSetup: mode={gameMode} perms=0x{permMask:X8}");
        return patched;
    }

    // ── Build a SetGameMode (0x65) packet payload ──────────────────────────
    public static byte[] BuildSetGameMode(GameMode mode)
    {
        var b = new byte[4];
        BitConverter.GetBytes((uint)mode).CopyTo(b, 0);
        return b;
    }

    // ── Helpers ─────────────────────────────────────────────────────────────
    private SessionSnapshot EnsureCurrent()
    {
        if (Current == null || (DateTime.UtcNow - Current.CapturedAt).TotalMinutes > 30)
            Current = new SessionSnapshot { CapturedAt = DateTime.UtcNow };
        return Current;
    }

    private static void ParsePlayerSetup(SessionSnapshot snap, byte[] p)
    {
        try
        {
            if (p.Length >= 8)  snap.SelfEntityId   = BinaryPrimitives.ReadUInt64LittleEndian(p.AsSpan(0));
            if (p.Length >= 12) snap.GameModeFlags   = BinaryPrimitives.ReadUInt32LittleEndian(p.AsSpan(8));
            if (p.Length >= 16) snap.PermissionMask  = BinaryPrimitives.ReadUInt32LittleEndian(p.AsSpan(12));
            // Try to extract a length-prefixed world name starting at offset 16
            if (p.Length >= 18)
            {
                ushort nameLen = BinaryPrimitives.ReadUInt16LittleEndian(p.AsSpan(16));
                if (nameLen > 0 && nameLen <= 128 && 18 + nameLen <= p.Length)
                    snap.WorldName = Encoding.UTF8.GetString(p, 18, nameLen);
            }
        }
        catch { /* best-effort parse */ }
    }

    private void AddLog(string msg)
    {
        var line = $"[{DateTime.Now:HH:mm:ss.fff}] {msg}";
        lock (_logLock) { _log.Add(line); if (_log.Count > 500) _log.RemoveAt(0); }
        OnLog?.Invoke(line);
    }
}
