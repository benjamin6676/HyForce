// ValueToggleTab.cs  v1
// Modular value freeze/toggle system.
// Each entry has:
//   • User-chosen name
//   • Memory address (paste from Entity Finder or type hex)
//   • Value type  (f32 | f64 | i32 | u8)
//   • Target value to write/freeze
//   • Hotkey (any VK, e.g. F8, X, NumPad0 …)
//   • Toggle mode: Freeze (continuous write) or OneShot (single write on press)
//   • Favorite star
//   • Change log: every confirmed write timestamped
// Keybind poll runs on a background thread — no ImGui required for hotkey to fire.

using HyForce.Core;
using HyForce.Networking;
using ImGuiNET;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading;

namespace HyForce.Tabs
{
    public class ValueToggleTab : ITab
    {
        public string Name => "Value Toggles";

        // ── Public for DiagnosticsCollector ───────────────────────
        public IReadOnlyList<ToggleEntry> Entries
        {
            get { lock (_entries) return _entries.ToList(); }
        }

        // ── data ─────────────────────────────────────────────────
        private readonly AppState          _state;
        private readonly PipeCaptureServer _pipe;
        private readonly List<ToggleEntry> _entries = new();
        private readonly string            _saveFile;

        // UI state
        private int    _editIdx   = -1;   // which entry is being edited
        private bool   _binding   = false; // waiting for key press
        private int    _bindTarget = -1;
        private string _newName   = "";
        private string _newAddr   = "";
        private string _newVal    = "";
        private int    _newType   = 0;   // 0=f32 1=f64 2=i32 3=u8
        private int    _newMode   = 0;   // 0=Freeze 1=OneShot
        private string _filterStr = "";
        private bool   _showLog   = false;

        // slot counter for DLL generic freeze (0..31)
        private int    _nextSlot  = 0;

        // Background hotkey poll
        private Thread?   _hkThread;
        private bool      _hkRunning;

        [DllImport("user32.dll")] private static extern short GetAsyncKeyState(int vk);

        // ── VK name table (subset) ────────────────────────────────
        private static readonly Dictionary<int, string> _vkNames = BuildVkNames();
        private static Dictionary<int, string> BuildVkNames()
        {
            var d = new Dictionary<int, string>();
            for (int i = (int)'A'; i <= (int)'Z'; i++) d[i] = ((char)i).ToString();
            for (int i = (int)'0'; i <= (int)'9'; i++) d[i] = ((char)i).ToString();
            for (int i = 0x70; i <= 0x7B; i++) d[i] = $"F{i - 0x6F}";       // F1-F12
            for (int i = 0x60; i <= 0x69; i++) d[i] = $"Num{i - 0x60}";     // Numpad 0-9
            d[0x20] = "Space"; d[0x0D] = "Enter"; d[0x08] = "Back";
            d[0x09] = "Tab";   d[0x1B] = "Esc";   d[0xBC] = "Comma";
            d[0xBE] = "Period";d[0xDB] = "[";      d[0xDD] = "]";
            d[0xBF] = "/";     d[0xDC] = "\\";     d[0xBA] = ";";
            d[0x2D] = "Insert";d[0x2E] = "Delete"; d[0x24] = "Home";
            d[0x23] = "End";   d[0x21] = "PgUp";   d[0x22] = "PgDn";
            return d;
        }
        private static string VkToName(int vk) =>
            _vkNames.TryGetValue(vk, out var n) ? n : $"VK{vk:X2}";

        static readonly string[] TypeNames = { "float32", "float64", "int32", "uint8" };
        static readonly string[] ModeNames = { "Freeze (loop)", "OneShot" };

        static readonly Vector4 Accent  = new(0.65f, 0.40f, 1.00f, 1f);
        static readonly Vector4 Green   = new(0.25f, 1.00f, 0.45f, 1f);
        static readonly Vector4 Yellow  = new(1.00f, 0.85f, 0.20f, 1f);
        static readonly Vector4 Red     = new(1.00f, 0.30f, 0.30f, 1f);
        static readonly Vector4 Muted   = new(0.55f, 0.55f, 0.55f, 1f);

        // ── constructor ───────────────────────────────────────────
        public ValueToggleTab(AppState state, PipeCaptureServer pipe)
        {
            _state = state;
            _pipe  = pipe;
            _saveFile = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "HyForce", "value_toggles.json");
            Load();
            StartHotkeyThread();
        }

        // ── hotkey background thread ──────────────────────────────
        private void StartHotkeyThread()
        {
            _hkRunning = true;
            _hkThread  = new Thread(HotkeyLoop) { IsBackground = true, Name = "HyForce-HK" };
            _hkThread.Start();
        }
        public void Shutdown() { _hkRunning = false; }

        private void HotkeyLoop()
        {
            // track key-was-down to detect edges
            var prev = new Dictionary<int, bool>();
            while (_hkRunning)
            {
                // capture key while binding
                if (_binding && _bindTarget >= 0)
                {
                    foreach (var kv in _vkNames)
                    {
                        if ((GetAsyncKeyState(kv.Key) & 0x8000) != 0 && kv.Key != 0x1B)
                        {
                            lock (_entries)
                                if (_bindTarget < _entries.Count)
                                    _entries[_bindTarget].HotkeyVk = kv.Key;
                            _binding = false; _bindTarget = -1;
                            Save();
                            break;
                        }
                    }
                    Thread.Sleep(50); continue;
                }

                lock (_entries)
                {
                    foreach (var e in _entries)
                    {
                        if (e.HotkeyVk == 0) continue;
                        bool down = (GetAsyncKeyState(e.HotkeyVk) & 0x8000) != 0;
                        prev.TryGetValue(e.HotkeyVk, out bool wasDn);

                        if (down && !wasDn) // rising edge
                        {
                            if (e.Mode == ToggleMode.OneShot)
                            {
                                FireEntry(e);
                            }
                            else // Freeze toggle
                            {
                                e.Active = !e.Active;
                                if (e.Active) ActivateFreeze(e);
                                else          DeactivateFreeze(e);
                            }
                        }
                        prev[e.HotkeyVk] = down;
                    }
                }
                Thread.Sleep(16);
            }
        }

        // ── fire logic ────────────────────────────────────────────
        private string EntryDtype(ToggleEntry e) => e.ValueType switch
        {
            ValueType.Float32 => "f32",
            ValueType.Float64 => "f64",
            ValueType.Int32   => "i32",
            _                 => "u8"
        };

        private void FireEntry(ToggleEntry e)
        {
            if (e.Address == 0) return;
            string dtype = EntryDtype(e);
            string val   = e.TargetValue;

            switch (e.ValueType)
            {
                case ValueType.Float32:
                    if (float.TryParse(val, out float fv))
                        _pipe.MemWriteF32(e.Address, fv);
                    break;
                case ValueType.Float64:
                    if (double.TryParse(val, out double dv))
                        _pipe.MemWriteF64(e.Address, dv);
                    break;
                case ValueType.Int32:
                    if (int.TryParse(val, out int iv))
                        _pipe.MemWriteI32(e.Address, iv);
                    break;
                case ValueType.UInt8:
                    if (byte.TryParse(val, out byte bv))
                        _pipe.MemWriteU8(e.Address, bv);
                    break;
            }
            string logLine = $"[{DateTime.Now:HH:mm:ss.fff}] WRITE {e.Name}  addr=0x{e.Address:X}  type={dtype}  val={val}";
            e.ChangeLog.Add(logLine);
            if (e.ChangeLog.Count > 500) e.ChangeLog.RemoveAt(0);
            _state.AddInGameLog(logLine);
        }

        private void ActivateFreeze(ToggleEntry e)
        {
            if (e.Address == 0) return;
            if (e.FreezeSlot < 0) { e.FreezeSlot = _nextSlot++ % 32; }
            _pipe.FreezeGeneric(e.FreezeSlot, e.Address, EntryDtype(e), e.TargetValue, 50);
            string log = $"[{DateTime.Now:HH:mm:ss.fff}] FREEZE ON  {e.Name}  addr=0x{e.Address:X}  val={e.TargetValue}";
            e.ChangeLog.Add(log); _state.AddInGameLog(log);
        }

        private void DeactivateFreeze(ToggleEntry e)
        {
            if (e.FreezeSlot >= 0) _pipe.FreezeGenericStop(e.FreezeSlot);
            string log = $"[{DateTime.Now:HH:mm:ss.fff}] FREEZE OFF {e.Name}";
            e.ChangeLog.Add(log); _state.AddInGameLog(log);
        }

        // ── render ────────────────────────────────────────────────
        public void Render()
        {
            ImGui.TextColored(Accent, "Value Toggles");
            ImGui.SameLine();
            ImGui.TextColored(Muted, "— hotkey-bound memory writes/freezes for research");
            ImGui.Separator();

            // Global controls
            if (ImGui.SmallButton("+ New Toggle")) AddNew();
            ImGui.SameLine();
            if (ImGui.SmallButton("Stop All Freezes")) { StopAll(); }
            ImGui.SameLine();
            ImGui.SetNextItemWidth(160);
            ImGui.InputText("Filter##vtf", ref _filterStr, 64);
            ImGui.SameLine();
            ImGui.Checkbox("Show Log##vtsl", ref _showLog);
            ImGui.Separator();
            ImGui.Spacing();

            // Help text
            ImGui.TextColored(Muted,
                "Paste any address from Entity Finder. Set value + type. Bind a hotkey. " +
                "Freeze = continuously re-writes (holds value). OneShot = writes once per key press.");
            ImGui.Spacing();

            // Favorites first
            List<ToggleEntry> sorted;
            lock (_entries)
                sorted = _entries.Where(e => string.IsNullOrEmpty(_filterStr) ||
                    e.Name.Contains(_filterStr, StringComparison.OrdinalIgnoreCase))
                    .OrderByDescending(e => e.Favorite)
                    .ThenBy(e => _entries.IndexOf(e))
                    .ToList();

            if (sorted.Count == 0)
            {
                ImGui.TextColored(Muted, "No toggles yet. Click '+ New Toggle' to add one.");
                return;
            }

            // Table
            if (ImGui.BeginTable("##vt", 9,
                ImGuiTableFlags.Borders | ImGuiTableFlags.RowBg |
                ImGuiTableFlags.ScrollY | ImGuiTableFlags.Resizable,
                new Vector2(-1, _showLog ? ImGui.GetContentRegionAvail().Y * 0.55f : ImGui.GetContentRegionAvail().Y - 4)))
            {
                ImGui.TableSetupScrollFreeze(0, 1);
                ImGui.TableSetupColumn("★",       ImGuiTableColumnFlags.WidthFixed, 24);
                ImGui.TableSetupColumn("Name",    ImGuiTableColumnFlags.WidthFixed, 150);
                ImGui.TableSetupColumn("Address", ImGuiTableColumnFlags.WidthFixed, 150);
                ImGui.TableSetupColumn("Type",    ImGuiTableColumnFlags.WidthFixed, 70);
                ImGui.TableSetupColumn("Value",   ImGuiTableColumnFlags.WidthFixed, 100);
                ImGui.TableSetupColumn("Mode",    ImGuiTableColumnFlags.WidthFixed, 90);
                ImGui.TableSetupColumn("Hotkey",  ImGuiTableColumnFlags.WidthFixed, 90);
                ImGui.TableSetupColumn("State",   ImGuiTableColumnFlags.WidthFixed, 80);
                ImGui.TableSetupColumn("Actions", ImGuiTableColumnFlags.WidthStretch);
                ImGui.TableHeadersRow();

                foreach (var e in sorted)
                {
                    ImGui.PushID(e.Id.GetHashCode());
                    ImGui.TableNextRow();

                    // ★
                    ImGui.TableSetColumnIndex(0);
                    if (e.Favorite) ImGui.TextColored(Yellow, "★");
                    else if (ImGui.SmallButton("☆")) { e.Favorite = true; Save(); }

                    // Name
                    ImGui.TableSetColumnIndex(1);
                    bool editing = _editIdx == sorted.IndexOf(e);
                    if (editing)
                    {
                        ImGui.SetNextItemWidth(-1);
                        if (ImGui.InputText("##en", ref _newName, 64))
                            e.Name = _newName;
                    }
                    else
                    {
                        ImGui.TextUnformatted(e.Name);
                    }

                    // Address
                    ImGui.TableSetColumnIndex(2);
                    if (editing)
                    {
                        ImGui.SetNextItemWidth(-1);
                        if (ImGui.InputText("##ea", ref _newAddr, 32))
                        {
                            if (ulong.TryParse(_newAddr.Replace("0x","").Replace("0X",""),
                                System.Globalization.NumberStyles.HexNumber, null, out ulong a))
                                e.Address = a;
                        }
                    }
                    else ImGui.Text($"0x{e.Address:X}");

                    // Type
                    ImGui.TableSetColumnIndex(3);
                    if (editing)
                    {
                        ImGui.SetNextItemWidth(-1);
                        if (ImGui.Combo("##et", ref _newType, TypeNames, TypeNames.Length))
                            e.ValueType = (ValueType)_newType;
                    }
                    else ImGui.Text(TypeNames[(int)e.ValueType]);

                    // Value
                    ImGui.TableSetColumnIndex(4);
                    if (editing)
                    {
                        ImGui.SetNextItemWidth(-1);
                        if (ImGui.InputText("##ev", ref _newVal, 32))
                            e.TargetValue = _newVal;
                    }
                    else ImGui.Text(e.TargetValue);

                    // Mode
                    ImGui.TableSetColumnIndex(5);
                    if (editing)
                    {
                        ImGui.SetNextItemWidth(-1);
                        if (ImGui.Combo("##em", ref _newMode, ModeNames, ModeNames.Length))
                            e.Mode = (ToggleMode)_newMode;
                    }
                    else ImGui.Text(ModeNames[(int)e.Mode]);

                    // Hotkey
                    ImGui.TableSetColumnIndex(6);
                    bool isBinding = _binding && _bindTarget == sorted.IndexOf(e);
                    if (isBinding)
                    {
                        ImGui.TextColored(Yellow, "Press key…");
                        if (ImGui.IsKeyPressed(ImGuiKey.Escape)) { _binding = false; _bindTarget = -1; }
                    }
                    else
                    {
                        string hkLabel = e.HotkeyVk != 0 ? VkToName(e.HotkeyVk) : "(none)";
                        if (ImGui.SmallButton($"{hkLabel}##hk"))
                        {
                            _binding = true; _bindTarget = sorted.IndexOf(e);
                        }
                        if (e.HotkeyVk != 0)
                        {
                            ImGui.SameLine();
                            if (ImGui.SmallButton("✕##hkc")) { e.HotkeyVk = 0; Save(); }
                        }
                    }

                    // State
                    ImGui.TableSetColumnIndex(7);
                    if (e.Mode == ToggleMode.Freeze)
                    {
                        if (e.Active)
                        {
                            ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.6f, 0.1f, 0.1f, 1f));
                            if (ImGui.SmallButton("🔒 ON##st")) { e.Active = false; DeactivateFreeze(e); }
                            ImGui.PopStyleColor();
                        }
                        else
                        {
                            if (ImGui.SmallButton("🔓 OFF##st")) { e.Active = true; ActivateFreeze(e); }
                        }
                    }
                    else
                    {
                        if (ImGui.SmallButton("▶ Fire##st")) FireEntry(e);
                    }

                    // Actions
                    ImGui.TableSetColumnIndex(8);
                    if (editing)
                    {
                        if (ImGui.SmallButton("✓ Done##ed")) { _editIdx = -1; Save(); }
                    }
                    else
                    {
                        if (ImGui.SmallButton("Edit##ed"))
                        {
                            _editIdx  = sorted.IndexOf(e);
                            _newName  = e.Name;
                            _newAddr  = $"{e.Address:X}";
                            _newVal   = e.TargetValue;
                            _newType  = (int)e.ValueType;
                            _newMode  = (int)e.Mode;
                        }
                    }
                    ImGui.SameLine();
                    if (e.Favorite)
                    {
                        if (ImGui.SmallButton("★→☆##unf")) { e.Favorite = false; Save(); }
                        ImGui.SameLine();
                    }
                    if (ImGui.SmallButton("Log##lg"))
                        e.ShowLog = !e.ShowLog;
                    ImGui.SameLine();
                    if (ImGui.SmallButton("✕##del"))
                    {
                        lock (_entries) { if (e.Active) DeactivateFreeze(e); _entries.Remove(e); }
                        Save(); ImGui.PopID(); break;
                    }

                    // Per-entry inline log
                    if (e.ShowLog && e.ChangeLog.Count > 0)
                    {
                        ImGui.TableNextRow();
                        ImGui.TableSetColumnIndex(1);
                        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.1f,0.1f,0.1f,0.9f));
                        ImGui.BeginChild($"##log{e.Id}", new Vector2(-1, 80), ImGuiChildFlags.Borders);
                        foreach (var line in e.ChangeLog.TakeLast(30))
                            ImGui.TextUnformatted(line);
                        ImGui.SetScrollHereY(1f);
                        ImGui.EndChild();
                        ImGui.PopStyleColor();
                    }

                    ImGui.PopID();
                }
                ImGui.EndTable();
            }

            // Global log panel
            if (_showLog)
            {
                ImGui.Separator();
                ImGui.TextColored(Accent, "Combined Change Log (all toggles)");
                ImGui.SameLine();
                if (ImGui.SmallButton("Export##glog")) ExportLog();
                ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.08f,0.08f,0.08f,0.95f));
                ImGui.BeginChild("##glogChild", new Vector2(-1, -1), ImGuiChildFlags.Borders);
                lock (_entries)
                {
                    var allLines = _entries
                        .SelectMany(e => e.ChangeLog.Select(l => l))
                        .OrderBy(l => l)
                        .TakeLast(200);
                    foreach (var l in allLines) ImGui.TextUnformatted(l);
                }
                ImGui.SetScrollHereY(1f);
                ImGui.EndChild();
                ImGui.PopStyleColor();
            }
        }

        // ── helpers ───────────────────────────────────────────────
        private void AddNew()
        {
            var e = new ToggleEntry
            {
                Id          = Guid.NewGuid().ToString("N")[..8],
                Name        = $"Toggle {_entries.Count + 1}",
                Address     = 0,
                TargetValue = "100",
                ValueType   = ValueType.Float32,
                Mode        = ToggleMode.Freeze,
                HotkeyVk    = 0,
                FreezeSlot  = -1,
            };
            lock (_entries) _entries.Add(e);
            _editIdx = _entries.Count - 1;
            _newName = e.Name; _newAddr = ""; _newVal = e.TargetValue;
            _newType = 0; _newMode = 0;
        }

        private void StopAll()
        {
            _pipe.FreezeAllStop();
            lock (_entries)
                foreach (var e in _entries)
                    e.Active = false;
            _state.AddInGameLog("[TOGGLE] All freezes stopped");
        }

        private void ExportLog()
        {
            try
            {
                string dir  = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "HyForce", "Exports");
                Directory.CreateDirectory(dir);
                string path = Path.Combine(dir, $"value_toggle_log_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
                var sb = new StringBuilder();
                sb.AppendLine($"HyForce Value Toggle Log — {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                sb.AppendLine(new string('=', 70));
                lock (_entries)
                {
                    foreach (var e in _entries)
                    {
                        sb.AppendLine($"\n[{e.Name}]  addr=0x{e.Address:X}  type={TypeNames[(int)e.ValueType]}  val={e.TargetValue}  mode={ModeNames[(int)e.Mode]}  hotkey={VkToName(e.HotkeyVk)}");
                        foreach (var l in e.ChangeLog) sb.AppendLine("  " + l);
                    }
                }
                File.WriteAllText(path, sb.ToString());
                _state.AddInGameLog($"[TOGGLE] Log exported → {path}");
            }
            catch (Exception ex) { _state.AddInGameLog($"[TOGGLE] Export error: {ex.Message}"); }
        }

        // ── persistence ───────────────────────────────────────────
        private void Save()
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(_saveFile)!);
                string json = JsonSerializer.Serialize(_entries,
                    new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_saveFile, json);
            }
            catch { /* non-critical */ }
        }

        private void Load()
        {
            try
            {
                if (!File.Exists(_saveFile)) return;
                var loaded = JsonSerializer.Deserialize<List<ToggleEntry>>(File.ReadAllText(_saveFile));
                if (loaded != null) { _entries.AddRange(loaded); foreach (var e in _entries) { e.Active = false; e.ChangeLog.Clear(); } }
            }
            catch { /* corrupt file — start fresh */ }
        }
    }

    // ── Models ───────────────────────────────────────────────────
    public enum ValueType  { Float32, Float64, Int32, UInt8 }
    public enum ToggleMode { Freeze, OneShot }

    public class ToggleEntry
    {
        public string          Id           { get; set; } = Guid.NewGuid().ToString("N")[..8];
        public string          Name         { get; set; } = "Toggle";
        public ulong           Address      { get; set; }
        public string          TargetValue  { get; set; } = "100";
        public ValueType       ValueType    { get; set; } = ValueType.Float32;
        public ToggleMode      Mode         { get; set; } = ToggleMode.Freeze;
        public int             HotkeyVk     { get; set; } = 0;
        public bool            Favorite     { get; set; } = false;

        // runtime only
        [System.Text.Json.Serialization.JsonIgnore] public bool              Active      { get; set; } = false;
        [System.Text.Json.Serialization.JsonIgnore] public int               FreezeSlot  { get; set; } = -1;
        [System.Text.Json.Serialization.JsonIgnore] public List<string>      ChangeLog   { get; set; } = new();
        [System.Text.Json.Serialization.JsonIgnore] public bool              ShowLog     { get; set; } = false;
    }
}
