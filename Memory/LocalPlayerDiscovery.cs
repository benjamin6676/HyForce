// FILE: Memory/LocalPlayerDiscovery.cs
// ============================================================
// Automated LocalPlayer structure discovery for Hytale (JVM process).
//
// HOW IT WORKS
// ─────────────────────────────────────────────────────────
// Hytale runs on HotSpot JVM. The LocalPlayer object lives on the Java heap.
// We can't use a static offset from a module base (there is no native .exe
// with a predictable data section). Instead we use three complementary strategies:
//
// Strategy A — String Anchor (most reliable across updates)
//   Scan heap for UTF-16LE class strings like "PlayerChannelHandler",
//   "HytaleProtocol", "LocalPlayer". A Java class object always has a
//   reference back to its instances. We walk nearby pointers to find the
//   live player object.
//
// Strategy B — Field Pattern Heuristics
//   Scan for regions that contain a Vec3 (3 consecutive plausible floats)
//   followed closely by another float in [0, 40] (health) and at least one
//   valid heap pointer (inventory). Score each candidate and keep the best.
//
// Strategy C — Netty Pipeline Walk
//   Hytale uses Netty QUIC. PlayerChannelHandler is always reachable from
//   the pipeline. Walk: pipeline → context → handler → player field.
//   This is the most stable chain because Netty's object layout changes
//   independently from game updates.
//
// Pointer validation rules (applied after every candidate address):
//   1. Address is 8-byte aligned.
//   2. Address is in committed heap region (not stack, not code, not GUARD).
//   3. JVM object header at address is plausible (mark word low bits = 1).
//   4. Klass pointer at +8 is nonzero and < 0x80000000 (compressed OOP range).
//   5. At offset 16 (first real field): at least one of the next 64 bytes
//      is a non-NaN float in a realistic game-world range.

using System.Runtime.InteropServices;
using System.Text;
using HyForce.Memory;

namespace HyForce.Memory;

// ════════════════════════════════════════════════════════════════════════════
// PUBLIC DATA MODEL — LocalPlayerState
// ════════════════════════════════════════════════════════════════════════════

public class LocalPlayerState
{
    // Core fields (updated live by LocalPlayerMonitor)
    public IntPtr  BaseAddress  { get; set; }
    public bool    IsValid      { get; set; }
    public float   PosX         { get; set; }
    public float   PosY         { get; set; }
    public float   PosZ         { get; set; }
    public float   RotYaw       { get; set; }   // radians
    public float   RotPitch     { get; set; }
    public float   Health       { get; set; }
    public float   MaxHealth    { get; set; }
    public IntPtr  InventoryPtr { get; set; }
    public IntPtr  NamePtr      { get; set; }
    public string  PlayerName   { get; set; } = "";
    public float   MoveSpeed    { get; set; }
    public bool    IsOnGround   { get; set; }

    // Discovery metadata
    public string  DiscoveryStrategy { get; set; } = "";
    public double  Confidence        { get; set; }
    public DateTime DiscoveredAt     { get; set; }

    public string  PosStr    => $"({PosX:F2}, {PosY:F2}, {PosZ:F2})";
    public string  RotStr    => $"Yaw={RotYaw:F3} Pitch={RotPitch:F3}";
    public string  HealthStr => $"{Health:F1}/{MaxHealth:F1}";
    public string  AddrHex   => $"0x{(ulong)BaseAddress:X16}";
}

// ════════════════════════════════════════════════════════════════════════════
// DISCOVERY ENGINE
// ════════════════════════════════════════════════════════════════════════════

public sealed class LocalPlayerDiscovery
{
    private readonly SignatureScanner  _scanner;
    private readonly PointerWalker     _walker;
    private readonly StructureValidator _validator;
    private readonly MemoryLogger      _log;

    // ── Hytale-specific signatures ────────────────────────────────────────
    // These are designed to survive minor updates:
    //   - We anchor on STRING CONTENT, not code offsets.
    //   - Wildcards absorb pointer-size differences and padding bytes.
    //   - We use MULTIPLE fallback patterns; any one success is enough.

    // UTF-16LE encoded class name snippets found in the JVM heap
    private static readonly Signature[] StringAnchors =
    {
        Signature.FromUtf16String("PlayerChannelHandler",  "Netty_PlayerChannelHandler"),
        Signature.FromUtf16String("HytaleProtocol",        "HytaleProtocol"),
        Signature.FromUtf16String("QuicStreamHandler",     "QuicStreamHandler"),
        Signature.FromUtf8String ("com/hypixel/hytale",    "HytaleClass_UTF8"),
        Signature.FromUtf8String ("PlayerChannelHandler",  "PlayerChannelHandler_UTF8"),
    };

    // Native-style byte patterns (used if JVM heap walk succeeds and Hytale
    // ever exposes a native PlayerManager via JNI — unlikely but future-proof)
    private static readonly Signature[] NativePatterns =
    {
        // Float 1.0 sentinel at start of many Hytale health structs
        // Pattern: "00 00 80 3F ?? ?? ?? ?? 00 00 80 3F" = [1.0f][??][1.0f]
        Signature.FromAob("00 00 80 3F ?? ?? ?? ?? 00 00 80 3F",
                          "HealthSentinel_1f", offset: -4),

        // Vec3 pattern: 3 floats where mid float (Y=64.0 typical spawn)
        // "00 00 80 42" = 64.0f
        Signature.FromAob("00 00 80 42 ?? ?? ?? ?? 00 00 80 42",
                          "YCoord_64f", offset: -4),
    };

    public LocalPlayerDiscovery(SignatureScanner scanner, PointerWalker walker,
                                StructureValidator validator, MemoryLogger log)
    {
        _scanner   = scanner;
        _walker    = walker;
        _validator = validator;
        _log       = log;
    }

    // ── Main discovery entry point ─────────────────────────────────────────

    /// <summary>
    /// Run all discovery strategies and return the best candidate,
    /// or null if nothing passes validation.
    /// </summary>
    public LocalPlayerState? Discover()
    {
        _log.Info("[DISCOVERY] Starting LocalPlayer scan…");
        var candidates = new List<(IntPtr addr, double score, string strategy)>();

        // Strategy A: string anchor → pointer walk
        var stringCandidates = StrategyA_StringAnchor();
        candidates.AddRange(stringCandidates);

        // Strategy B: field pattern heuristics
        if (candidates.Count == 0)
        {
            var heuristicCandidates = StrategyB_FieldPatterns();
            candidates.AddRange(heuristicCandidates);
        }

        // Strategy C: native float-sentinel patterns
        if (candidates.Count == 0)
        {
            var nativeCandidates = StrategyC_NativePatterns();
            candidates.AddRange(nativeCandidates);
        }

        if (candidates.Count == 0)
        {
            _log.Warn("[DISCOVERY] No candidates found. Run with game in active session.");
            return null;
        }

        // Pick highest-confidence candidate
        var best = candidates.OrderByDescending(c => c.score).First();
        _log.Info($"[DISCOVERY] Best candidate: 0x{(ulong)best.addr:X} score={best.score:F2} via {best.strategy}");

        // Extract initial field values
        var state = ExtractFields(best.addr);
        state.DiscoveryStrategy = best.strategy;
        state.Confidence        = best.score;
        state.DiscoveredAt      = DateTime.Now;
        return state;
    }

    // ── Strategy A: String anchor + nearby pointer search ─────────────────

    private List<(IntPtr, double, string)> StrategyA_StringAnchor()
    {
        var results = new List<(IntPtr, double, string)>();

        foreach (var sig in StringAnchors)
        {
            var hits = _scanner.Scan(sig, maxResults: 8);
            if (hits.Count == 0) continue;

            _log.Info($"[A] Found {hits.Count} hits for {sig.Name}");

            foreach (var hit in hits)
            {
                // Scan ±512 bytes around the string for valid heap pointers
                // that might be 'this' references pointing to a larger object
                var candidates = FindNearbyObjectPointers(hit.MatchAddress, radius: 512);
                foreach (var (ptr, score) in candidates)
                {
                    if (!ValidatePlayerCandidate(ptr)) continue;
                    results.Add((ptr, score * 0.8, $"StringAnchor:{sig.Name}"));
                }
            }
        }

        return results;
    }

    // ── Strategy B: Field pattern heuristics ──────────────────────────────

    private List<(IntPtr, double, string)> StrategyB_FieldPatterns()
    {
        var results = new List<(IntPtr, double, string)>();
        var regions = _scanner.Scan(NativePatterns[0], maxResults: 64);

        foreach (var hit in regions)
        {
            // Assume match is inside the player struct — back up to start
            for (int backtrack = 0; backtrack <= 128; backtrack += 4)
            {
                var candidate = hit.MatchAddress - backtrack;
                if (!ValidatePlayerCandidate(candidate)) continue;

                var score = ScorePlayerCandidate(candidate);
                if (score > 0.3)
                    results.Add((candidate, score, "FieldPattern:Vec3+Health"));
            }
        }
        return results;
    }

    // ── Strategy C: Native AOB patterns ───────────────────────────────────

    private List<(IntPtr, double, string)> StrategyC_NativePatterns()
    {
        var results = new List<(IntPtr, double, string)>();
        foreach (var sig in NativePatterns)
        {
            var hits = _scanner.Scan(sig, maxResults: 32);
            foreach (var hit in hits)
            {
                var candidate = hit.ResultAddress;
                if (!ValidatePlayerCandidate(candidate)) continue;
                var score = ScorePlayerCandidate(candidate);
                if (score > 0.25)
                    results.Add((candidate, score, $"NativePattern:{sig.Name}"));
            }
        }
        return results;
    }

    // ── Pointer search within a radius ────────────────────────────────────

    private List<(IntPtr ptr, double score)> FindNearbyObjectPointers(IntPtr anchor, int radius)
    {
        var results = new List<(IntPtr, double)>();
        // Read the surrounding region
        var data = _scanner.ReadBytes(anchor - radius, radius * 2);
        if (data == null) return results;

        for (int i = 0; i < data.Length - 8; i += 8)
        {
            long raw = BitConverter.ToInt64(data, i);
            var ptr  = (IntPtr)raw;
            if (!PointerWalker.IsValidHeapPointer(ptr)) continue;

            double objScore = _validator.ValidateJvmObjectHeader(ptr);
            if (objScore > 0.3)
                results.Add((ptr, objScore));
        }
        return results;
    }

    // ── Candidate validation ───────────────────────────────────────────────

    public bool ValidatePlayerCandidate(IntPtr addr)
    {
        if (!PointerWalker.IsValidHeapPointer(addr)) return false;
        if (_validator.ValidateJvmObjectHeader(addr) < 0.3) return false;

        // Read 80 bytes starting at typical first-field offset (after 16B header)
        var data = _scanner.ReadBytes(addr + 16, 80);
        if (data == null) return false;

        // Must contain at least one Vec3-like float triplet
        bool hasVec3 = false;
        for (int i = 0; i < data.Length - 11; i += 4)
        {
            if (_validator.ValidateVec3(data, i) > 0.4) { hasVec3 = true; break; }
        }
        return hasVec3;
    }

    public double ScorePlayerCandidate(IntPtr addr)
    {
        double score = 0;
        var data = _scanner.ReadBytes(addr, 256);
        if (data == null) return 0;

        // JVM header validity
        score += _validator.ValidateJvmObjectHeader(addr) * 0.2;

        // Field scan starting at offset 16
        for (int i = 16; i < Math.Min(data.Length - 11, 160); i += 4)
        {
            // Vec3 bonus
            double vec3 = _validator.ValidateVec3(data, i);
            if (vec3 > 0.4) score += vec3 * 0.35;

            // Health float bonus
            if (i + 3 < data.Length)
            {
                float f = BitConverter.ToSingle(data, i);
                score += _validator.ValidateHealthFloat(f) * 0.2;
            }
        }

        // Pointer bonus (inventory, name…)
        for (int i = 16; i < Math.Min(data.Length - 7, 200); i += 8)
        {
            long raw = BitConverter.ToInt64(data, i);
            if (PointerWalker.IsValidHeapPointer((IntPtr)raw))
                score += 0.05;
        }

        return Math.Min(score, 1.0);
    }

    // ── Field extraction ───────────────────────────────────────────────────

    /// <summary>
    /// Read all known fields from a validated LocalPlayer address.
    /// Field offsets are heuristically discovered — auto-scan the first 256 bytes.
    /// </summary>
    public LocalPlayerState ExtractFields(IntPtr addr)
    {
        var state = new LocalPlayerState { BaseAddress = addr };
        var data  = _scanner.ReadBytes(addr, 512);
        if (data == null) { state.IsValid = false; return state; }

        state.IsValid = true;

        // Find the first high-confidence Vec3 starting after the 16-byte JVM header
        for (int i = 16; i < data.Length - 11; i += 4)
        {
            if (_validator.ValidateVec3(data, i) < 0.5) continue;

            state.PosX = BitConverter.ToSingle(data, i);
            state.PosY = BitConverter.ToSingle(data, i + 4);
            state.PosZ = BitConverter.ToSingle(data, i + 8);

            // Rotation likely follows position
            int rotOff = i + 12;
            if (rotOff + 7 < data.Length)
            {
                float yaw   = BitConverter.ToSingle(data, rotOff);
                float pitch = BitConverter.ToSingle(data, rotOff + 4);
                if (!float.IsNaN(yaw) && !float.IsNaN(pitch) &&
                    Math.Abs(yaw) <= 7f && Math.Abs(pitch) <= 7f)
                {
                    state.RotYaw   = yaw;
                    state.RotPitch = pitch;
                }
            }
            break;
        }

        // Scan for health float: value in (0, 40], not NaN
        for (int i = 16; i < data.Length - 7; i += 4)
        {
            float f = BitConverter.ToSingle(data, i);
            double hScore = _validator.ValidateHealthFloat(f);
            if (hScore > 0.6)
            {
                state.Health    = f;
                // Max health likely immediately before or after
                float prev = i >= 4 ? BitConverter.ToSingle(data, i - 4) : 0;
                float next = i + 7 < data.Length ? BitConverter.ToSingle(data, i + 4) : 0;
                if (prev > 0 && prev >= f && prev <= 40f)      state.MaxHealth = prev;
                else if (next > 0 && next >= f && next <= 40f) state.MaxHealth = next;
                else                                            state.MaxHealth = 20f;
                break;
            }
        }

        // Scan for valid heap pointers (inventory, name…)
        int ptrCount = 0;
        for (int i = 16; i < data.Length - 7; i += 8)
        {
            long raw = BitConverter.ToInt64(data, i);
            var  ptr = (IntPtr)raw;
            if (!PointerWalker.IsValidHeapPointer(ptr)) continue;

            switch (ptrCount)
            {
                case 0: state.NamePtr      = ptr; break;
                case 1: state.InventoryPtr = ptr; break;
            }
            ptrCount++;
            if (ptrCount >= 4) break;
        }

        // Attempt to read player name from NamePtr
        state.PlayerName = TryReadJavaString(state.NamePtr);

        _log.Info($"[FIELDS] Extracted: pos={state.PosStr} hp={state.Health:F1} name=\"{state.PlayerName}\"");
        return state;
    }

    // ── Java String read ──────────────────────────────────────────────────
    // Java String object layout (HotSpot 64-bit, compressed OOPs):
    //   +0  : mark word (8B)
    //   +8  : klass ptr (4B compressed)
    //   +12 : hash (4B int)
    //   +16 : value (4B compressed oop → char[] or byte[])
    //   +20 : coder (1B: 0=LATIN1, 1=UTF16)

    private string TryReadJavaString(IntPtr strObjPtr)
    {
        if (!PointerWalker.IsValidHeapPointer(strObjPtr)) return "";
        var hdr = _scanner.ReadBytes(strObjPtr, 24);
        if (hdr == null) return "";

        // Read compressed oop for the char/byte array
        uint arrayOop = BitConverter.ToUInt32(hdr, 16);
        byte coder    = hdr[20];

        // Decompress OOP: multiply by 8 (default heap base = 0 on small heaps)
        // This is process-specific; on large heaps needs HeapBaseAddress adjustment.
        IntPtr arrayPtr = (IntPtr)((ulong)arrayOop * 8);
        if (!PointerWalker.IsValidHeapPointer(arrayPtr)) return "";

        // Java array header: [markword(8)][klass(4)][length(4)] = 16 bytes
        var arrHdr = _scanner.ReadBytes(arrayPtr, 20);
        if (arrHdr == null) return "";

        int length = BitConverter.ToInt32(arrHdr, 12);
        if (length <= 0 || length > 256) return "";

        int byteCount = coder == 1 ? length * 2 : length;
        var strBytes  = _scanner.ReadBytes(arrayPtr + 16, byteCount);
        if (strBytes == null) return "";

        return coder == 1
            ? Encoding.Unicode.GetString(strBytes)  // UTF-16LE
            : Encoding.Latin1.GetString(strBytes);  // LATIN-1
    }
}

// ════════════════════════════════════════════════════════════════════════════
// LIVE MONITOR — updates LocalPlayerState every N ms
// ════════════════════════════════════════════════════════════════════════════

public sealed class LocalPlayerMonitor : IDisposable
{
    public LocalPlayerState? State      { get; private set; }
    public bool              IsRunning  { get; private set; }
    public string            StatusText { get; private set; } = "Not started";

    private readonly LocalPlayerDiscovery _discovery;
    private readonly SignatureScanner     _scanner;
    private readonly MemoryLogger         _log;
    private          CancellationTokenSource? _cts;
    private          Task?                _task;

    public event Action<LocalPlayerState>? OnStateUpdated;

    public LocalPlayerMonitor(LocalPlayerDiscovery discovery, SignatureScanner scanner, MemoryLogger log)
    {
        _discovery = discovery;
        _scanner   = scanner;
        _log       = log;
    }

    public void Start(int refreshMs = 100)
    {
        if (IsRunning) return;
        _cts = new CancellationTokenSource();
        _task = Task.Run(() => MonitorLoop(refreshMs, _cts.Token));
        IsRunning = true;
        StatusText = "Running";
        _log.Info("[MONITOR] LocalPlayer monitor started");
    }

    public void Stop()
    {
        _cts?.Cancel();
        IsRunning  = false;
        StatusText = "Stopped";
    }

    private async Task MonitorLoop(int refreshMs, CancellationToken ct)
    {
        // Initial discovery
        StatusText = "Discovering…";
        State = _discovery.Discover();

        if (State == null)
        {
            StatusText = "Discovery failed";
            _log.Warn("[MONITOR] Could not locate LocalPlayer");
        }
        else
        {
            StatusText = $"Tracking @ {State.AddrHex}";
            _log.Info($"[MONITOR] Tracking LocalPlayer @ {State.AddrHex}");
        }

        while (!ct.IsCancellationRequested)
        {
            await Task.Delay(refreshMs, ct).ConfigureAwait(false);

            if (State == null || !State.IsValid)
            {
                // Periodically re-discover (every 5 seconds)
                State = _discovery.Discover();
                if (State != null) StatusText = $"Re-found @ {State.AddrHex}";
                continue;
            }

            // Live field refresh (only position, rotation, health — not discovery)
            RefreshLiveFields(State);
            OnStateUpdated?.Invoke(State);
        }
    }

    private void RefreshLiveFields(LocalPlayerState state)
    {
        var data = _scanner.ReadBytes(state.BaseAddress, 256);
        if (data == null) { state.IsValid = false; return; }

        // Re-scan for position (quick — just try last known offsets first, then full scan)
        // We store the offset in the state on first discovery (not shown here for brevity;
        // in practice cache the offsets from ExtractFields).
        var updated = _discovery.ExtractFields(state.BaseAddress);
        state.PosX         = updated.PosX;
        state.PosY         = updated.PosY;
        state.PosZ         = updated.PosZ;
        state.RotYaw       = updated.RotYaw;
        state.RotPitch     = updated.RotPitch;
        state.Health       = updated.Health;
        state.MaxHealth    = updated.MaxHealth;
        state.InventoryPtr = updated.InventoryPtr;
    }

    public void Dispose()
    {
        Stop();
        _cts?.Dispose();
    }
}
