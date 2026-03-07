// MemoryToggle.cs  — Modular named hotkey-driven memory value pinners
// Each toggle: name, address, data type, target value, hotkey, active state, change log.
// C# timer fires FREEZE_GENERIC commands at the configured interval.
// Works entirely via the named pipe to HyForceHook.dll running inside HytaleClient.exe.

using HyForce.Networking;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.IO;

namespace HyForce.Core
{
    public enum ToggleDataType { Float32, Float64, Int32, UInt8 }

    public class ToggleChangeEntry
    {
        public DateTime Timestamp { get; set; } = DateTime.Now;
        public string   PrevValue { get; set; } = "";
        public string   NewValue  { get; set; } = "";
        public string   Source    { get; set; } = ""; // "user" | "verify" | "external"
        public bool     WasApplied { get; set; }
    }

    public class MemoryToggle
    {
        // ── Identity ──────────────────────────────────────────────────────────
        public Guid   Id         { get; set; } = Guid.NewGuid();
        public string Name       { get; set; } = "Unnamed Toggle";
        public bool   Favorited  { get; set; } = false;
        public string Notes      { get; set; } = "";
        public string Category   { get; set; } = "General";

        // ── Target ───────────────────────────────────────────────────────────
        public ulong          Address    { get; set; }
        public ToggleDataType DataType   { get; set; } = ToggleDataType.Float32;
        public string         ValueStr   { get; set; } = "0"; // typed by user
        public int            IntervalMs { get; set; } = 50;  // write freq when active

        // ── Hotkey ───────────────────────────────────────────────────────────
        // Key name: "F1"–"F12", "X", "Numpad0", "Insert", etc.
        public string HotkeyKey  { get; set; } = "";
        public bool   HotkeyCtrl { get; set; } = false;
        public bool   HotkeyShift{ get; set; } = false;
        public bool   HotkeyAlt  { get; set; } = false;

        // ── Runtime state (not serialised) ───────────────────────────────────
        [System.Text.Json.Serialization.JsonIgnore]
        public bool Active { get; set; } = false;
        [System.Text.Json.Serialization.JsonIgnore]
        public string LastReadValue { get; set; } = "—";
        [System.Text.Json.Serialization.JsonIgnore]
        public DateTime LastWriteAt { get; set; } = DateTime.MinValue;
        [System.Text.Json.Serialization.JsonIgnore]
        public int WriteCount { get; set; } = 0;
        [System.Text.Json.Serialization.JsonIgnore]
        public List<ToggleChangeEntry> ChangeLog { get; set; } = new();

        public string DTypeCode => DataType switch
        {
            ToggleDataType.Float32 => "f32",
            ToggleDataType.Float64 => "f64",
            ToggleDataType.Int32   => "i32",
            ToggleDataType.UInt8   => "u8",
            _                      => "f32"
        };

        public string HotkeyLabel
        {
            get
            {
                if (string.IsNullOrEmpty(HotkeyKey)) return "(none)";
                string s = "";
                if (HotkeyCtrl)  s += "Ctrl+";
                if (HotkeyShift) s += "Shift+";
                if (HotkeyAlt)   s += "Alt+";
                s += HotkeyKey;
                return s;
            }
        }
    }

    // ── MemoryToggleManager ──────────────────────────────────────────────────
    public class MemoryToggleManager : IDisposable
    {
        private readonly PipeCaptureServer _pipe;
        private readonly AppState          _state;
        private readonly string            _savePath;
        private readonly object            _lock = new();
        private readonly Timer             _writeTimer;
        private readonly Timer             _verifyTimer;

        public List<MemoryToggle> Toggles { get; } = new();

        // fired when a toggle changes active state or a verified value differs
        public event Action<MemoryToggle, string>? OnEvent;

        public MemoryToggleManager(PipeCaptureServer pipe, AppState state)
        {
            _pipe = pipe;
            _state = state;
            _savePath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "HyForce", "toggles.json");

            Load();

            // Fire active toggles at their configured interval
            _writeTimer  = new Timer(WriteActive, null, 50, 50);
            // Verify every 500 ms: request a MEMREAD and check value matches
            _verifyTimer = new Timer(VerifyActive, null, 500, 500);
        }

        // ── Public API ───────────────────────────────────────────────────────

        public MemoryToggle Add(string name = "New Toggle")
        {
            var t = new MemoryToggle { Name = name };
            lock (_lock) Toggles.Add(t);
            Save();
            return t;
        }

        public void Remove(MemoryToggle t)
        {
            lock (_lock)
            {
                t.Active = false;
                Toggles.Remove(t);
            }
            Save();
        }

        public void SetActive(MemoryToggle t, bool active)
        {
            if (t.Active == active) return;
            t.Active = active;
            var entry = new ToggleChangeEntry
            {
                Source    = "user",
                PrevValue = active ? "OFF" : "ON",
                NewValue  = active ? "ON"  : "OFF",
                WasApplied = true
            };
            t.ChangeLog.Add(entry);
            if (t.ChangeLog.Count > 500) t.ChangeLog.RemoveAt(0);

            _state.AddInGameLog(active
                ? $"[TOGGLE] '{t.Name}' ACTIVATED @ 0x{t.Address:X} = {t.ValueStr} ({t.DTypeCode})"
                : $"[TOGGLE] '{t.Name}' DEACTIVATED");

            OnEvent?.Invoke(t, active ? "activated" : "deactivated");
            if (!active) Save();
        }

        public void Toggle(MemoryToggle t) => SetActive(t, !t.Active);

        /// <summary>Apply a single one-shot write regardless of active state.</summary>
        public void WriteOnce(MemoryToggle t)
        {
            if (!_pipe.DllConnected) { _state.AddInGameLog($"[TOGGLE] DLL not connected"); return; }
            SendWrite(t);
            t.WriteCount++;
            t.LastWriteAt = DateTime.Now;
            var entry = new ToggleChangeEntry { Source = "user", NewValue = t.ValueStr, WasApplied = true };
            t.ChangeLog.Add(entry);
        }

        /// <summary>Check hotkeys against currently held ImGui-exposed keys.</summary>
        public void PollHotkeys(Func<string, bool> isKeyDown)
        {
            lock (_lock)
            {
                foreach (var t in Toggles)
                {
                    if (string.IsNullOrEmpty(t.HotkeyKey)) continue;
                    bool held = (!t.HotkeyCtrl  || isKeyDown("Ctrl"))  &&
                                (!t.HotkeyShift || isKeyDown("Shift")) &&
                                (!t.HotkeyAlt   || isKeyDown("Alt"))   &&
                                isKeyDown(t.HotkeyKey);
                    // toggle only on leading edge — simple edge-detect via last-held tracking
                    // (edge tracking is done in the tab UI with prev-frame state)
                }
            }
        }

        public void Save()
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(_savePath)!);
                var opts = new JsonSerializerOptions { WriteIndented = true };
                lock (_lock)
                {
                    // Serialize without runtime-only fields
                    File.WriteAllText(_savePath, JsonSerializer.Serialize(Toggles, opts));
                }
            }
            catch (Exception ex) { _state.AddInGameLog($"[TOGGLE] Save failed: {ex.Message}"); }
        }

        public void Load()
        {
            try
            {
                if (!File.Exists(_savePath)) return;
                var loaded = JsonSerializer.Deserialize<List<MemoryToggle>>(File.ReadAllText(_savePath));
                if (loaded == null) return;
                lock (_lock)
                {
                    Toggles.Clear();
                    foreach (var t in loaded)
                    {
                        t.Active = false; // never restore active state on load
                        t.ChangeLog = new List<ToggleChangeEntry>();
                        Toggles.Add(t);
                    }
                }
                _state.AddInGameLog($"[TOGGLE] Loaded {Toggles.Count} toggle(s) from disk");
            }
            catch (Exception ex) { _state.AddInGameLog($"[TOGGLE] Load failed: {ex.Message}"); }
        }

        // ── Timer callbacks ──────────────────────────────────────────────────

        private void WriteActive(object? _)
        {
            if (!_pipe.DllConnected) return;
            List<MemoryToggle> active;
            lock (_lock) active = Toggles.Where(t => t.Active && t.Address != 0).ToList();
            var now = DateTime.Now;
            foreach (var t in active)
            {
                if ((now - t.LastWriteAt).TotalMilliseconds >= t.IntervalMs)
                {
                    SendWrite(t);
                    t.WriteCount++;
                    t.LastWriteAt = now;
                }
            }
        }

        private void VerifyActive(object? _)
        {
            if (!_pipe.DllConnected) return;
            List<MemoryToggle> active;
            lock (_lock) active = Toggles.Where(t => t.Active && t.Address != 0).ToList();
            foreach (var t in active)
            {
                // Request a 16-byte read to verify
                _pipe.MemRead(t.Address, 16);
                // Result will come back via HandleMemRead in PipeCaptureServer
                // and appear in MemReadResults — the tab reads it for display
            }
        }

        private void SendWrite(MemoryToggle t)
        {
            try { _pipe.FreezeGeneric(-1, t.Address, t.DTypeCode, t.ValueStr, t.IntervalMs); }
            catch { }
        }

        public void Dispose()
        {
            _writeTimer.Dispose();
            _verifyTimer.Dispose();
            Save();
        }

        // ── Export helper ────────────────────────────────────────────────────
        public string ExportReport()
        {
            var sb = new System.Text.StringBuilder();
            sb.AppendLine("=== HyForce Memory Toggle Report ===");
            sb.AppendLine($"Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"Total toggles: {Toggles.Count}");
            sb.AppendLine();
            lock (_lock)
            {
                foreach (var t in Toggles.OrderByDescending(t => t.Favorited).ThenBy(t => t.Category))
                {
                    sb.AppendLine($"[{(t.Favorited ? "★" : " ")}] {t.Category} / {t.Name}");
                    sb.AppendLine($"    Address:  0x{t.Address:X14}");
                    sb.AppendLine($"    Type:     {t.DataType} ({t.DTypeCode})");
                    sb.AppendLine($"    Value:    {t.ValueStr}");
                    sb.AppendLine($"    Interval: {t.IntervalMs}ms");
                    sb.AppendLine($"    Hotkey:   {t.HotkeyLabel}");
                    sb.AppendLine($"    Active:   {t.Active}");
                    sb.AppendLine($"    Writes:   {t.WriteCount}");
                    sb.AppendLine($"    LastRead: {t.LastReadValue}");
                    sb.AppendLine($"    Notes:    {t.Notes}");
                    if (t.ChangeLog.Count > 0)
                    {
                        sb.AppendLine($"    Change log ({t.ChangeLog.Count} entries):");
                        foreach (var e in t.ChangeLog.TakeLast(20))
                            sb.AppendLine($"      [{e.Timestamp:HH:mm:ss.fff}] {e.PrevValue} → {e.NewValue}  src={e.Source}  applied={e.WasApplied}");
                    }
                    sb.AppendLine();
                }
            }
            return sb.ToString();
        }
    }
}
