// MemoryTogglesTab.cs — Modular named hotkey-driven memory value toggles

using HyForce.Core;
using HyForce.Networking;
using ImGuiNET;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;

namespace HyForce.Tabs
{
    public class MemoryTogglesTab : ITab
    {
        public string Name => "Mem Toggles";

        private readonly AppState            _state;
        private readonly PipeCaptureServer   _pipe;
        public  readonly MemoryToggleManager Manager;

        private MemoryToggle? _selected;
        private string _filterText  = "";
        private bool   _showFavOnly = false;
        private string _newName     = "New Toggle";

        // Edit mirrors
        private string _editName       = "";
        private string _editCategory   = "";
        private string _editNotes      = "";
        private string _editAddrStr    = "";
        private string _editValue      = "";
        private int    _editTypeIdx    = 0;
        private int    _editIntervalMs = 50;
        private string _editHotkey     = "";
        private bool   _editHkCtrl     = false;
        private bool   _editHkShift    = false;
        private bool   _editHkAlt      = false;
        private bool   _capturingHotkey = false;
        private string _logSearch      = "";

        private readonly HashSet<string> _prevHeld = new();

        private static readonly string[] KeyNames = {
            "F1","F2","F3","F4","F5","F6","F7","F8","F9","F10","F11","F12",
            "Insert","Delete","Home","End","PageUp","PageDown",
            "Numpad0","Numpad1","Numpad2","Numpad3","Numpad4",
            "Numpad5","Numpad6","Numpad7","Numpad8","Numpad9",
            "A","B","C","D","E","F","G","H","I","J","K","L","M",
            "N","O","P","Q","R","S","T","U","V","W","X","Y","Z",
            "D0","D1","D2","D3","D4","D5","D6","D7","D8","D9",
        };
        private static readonly string[] TypeLabels = { "float32", "float64", "int32", "uint8" };

        static readonly Vector4 Accent = new(0.75f, 0.45f, 1f, 1f);
        static readonly Vector4 Yellow = new(1f, 0.85f, 0.1f, 1f);
        static readonly Vector4 Green  = new(0.2f, 1f, 0.4f, 1f);
        static readonly Vector4 Red    = new(1f, 0.3f, 0.2f, 1f);
        static readonly Vector4 Muted  = new(0.55f, 0.55f, 0.55f, 1f);

        public MemoryTogglesTab(AppState state, PipeCaptureServer pipe, MemoryToggleManager mgr)
        {
            _state   = state;
            _pipe    = pipe;
            Manager  = mgr;
        }

        public void Render()
        {
            PollHotkeys();

            bool dll = _pipe.DllConnected;
            ImGui.TextColored(dll ? Green : Red, dll ? "● DLL Live" : "○ DLL offline");
            ImGui.SameLine();
            ImGui.TextColored(Muted, $"  {Manager.Toggles.Count} toggles  {Manager.Toggles.Count(t=>t.Active)} active");
            ImGui.SameLine(ImGui.GetContentRegionAvail().X - 300);
            ImGui.SetNextItemWidth(140);
            ImGui.InputText("##filt", ref _filterText, 64);
            ImGui.SameLine();
            ImGui.Checkbox("★", ref _showFavOnly);
            ImGui.SameLine();
            if (ImGui.Button("Export All")) ExportAll();
            ImGui.Separator();

            ImGui.BeginChild("##tlist", new Vector2(270, -1), ImGuiChildFlags.Borders);
            RenderList();
            ImGui.EndChild();
            ImGui.SameLine();
            ImGui.BeginChild("##tedit", new Vector2(-1, -1));
            if (_selected != null) RenderEditor(_selected);
            else ImGui.TextColored(Muted, "Select a toggle on the left, or add one.");
            ImGui.EndChild();
        }

        private void RenderList()
        {
            ImGui.SetNextItemWidth(130);
            ImGui.InputText("##nn", ref _newName, 64);
            ImGui.SameLine();
            if (ImGui.SmallButton("+ Add"))
            {
                var t = Manager.Add(_newName);
                _selected = t;
                CopyToEdit(t);
            }
            ImGui.Separator();

            var list = Manager.Toggles
                .Where(t => !_showFavOnly || t.Favorited)
                .Where(t => string.IsNullOrEmpty(_filterText) ||
                            t.Name.Contains(_filterText, StringComparison.OrdinalIgnoreCase) ||
                            t.Category.Contains(_filterText, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(t => t.Favorited).ThenBy(t => t.Category).ThenBy(t => t.Name)
                .ToList();

            string curCat = "";
            foreach (var t in list)
            {
                if (t.Category != curCat)
                {
                    if (curCat != "") ImGui.Spacing();
                    ImGui.TextColored(Accent, $"── {t.Category}");
                    curCat = t.Category;
                }
                ImGui.PushID(t.Id.ToString());
                // Star
                ImGui.TextColored(t.Favorited ? Yellow : Muted, t.Favorited ? "★" : "☆");
                if (ImGui.IsItemClicked()) { t.Favorited = !t.Favorited; Manager.Save(); }
                ImGui.SameLine();
                // Active checkbox
                bool active = t.Active;
                if (ImGui.Checkbox($"##a{t.Id}", ref active)) Manager.SetActive(t, active);
                ImGui.SameLine();
                bool sel = _selected == t;
                if (ImGui.Selectable($"{t.Name} ({t.HotkeyLabel})##s", sel))
                { _selected = t; CopyToEdit(t); }
                if (ImGui.IsItemHovered())
                {
                    ImGui.BeginTooltip();
                    ImGui.Text($"0x{t.Address:X14}  {t.DataType}  val={t.ValueStr}");
                    ImGui.Text($"Writes: {t.WriteCount}   Read: {t.LastReadValue}");
                    ImGui.EndTooltip();
                }
                ImGui.PopID();
            }
            if (list.Count == 0) ImGui.TextColored(Muted, "(empty)");
        }

        private void RenderEditor(MemoryToggle t)
        {
            // Big activate button
            bool active = t.Active;
            ImGui.PushStyleColor(ImGuiCol.Button, active
                ? new Vector4(0.6f,0.1f,0.1f,1f) : new Vector4(0.1f,0.5f,0.1f,1f));
            if (ImGui.Button(active ? "■  STOP" : "▶  ACTIVATE", new Vector2(120, 28)))
                Manager.SetActive(t, !active);
            ImGui.PopStyleColor();
            ImGui.SameLine();
            if (ImGui.Button("Write Once", new Vector2(90,28))) Manager.WriteOnce(t);
            ImGui.SameLine();
            bool fav = t.Favorited;
            if (ImGui.Checkbox("★##fav", ref fav)) { t.Favorited = fav; Manager.Save(); }
            ImGui.SameLine(ImGui.GetContentRegionAvail().X - 60);
            ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.5f,0.1f,0.1f,1f));
            if (ImGui.Button("Delete##del"))
            { Manager.Remove(t); _selected = null; ImGui.PopStyleColor(); return; }
            ImGui.PopStyleColor();

            // Status
            ImGui.Separator();
            if (active)
                ImGui.TextColored(Green, $"● ACTIVE | Writes: {t.WriteCount} | Last: {t.LastWriteAt:HH:mm:ss.fff} | Read: {t.LastReadValue}");
            else
                ImGui.TextColored(Muted, $"● Idle   | Writes: {t.WriteCount} | Read: {t.LastReadValue}");
            ImGui.Spacing();

            if (!ImGui.BeginTabBar("##etabs")) return;

            // ── Config ────────────────────────────────────────────────────────
            if (ImGui.BeginTabItem("Config"))
            {
                ImGui.SetNextItemWidth(230);
                if (ImGui.InputText("Name##en", ref _editName, 64))     { t.Name = _editName;           Manager.Save(); }
                ImGui.SetNextItemWidth(140);
                if (ImGui.InputText("Category##ec", ref _editCategory, 32)) { t.Category = _editCategory; Manager.Save(); }

                ImGui.Separator();
                ImGui.TextColored(Accent, "Target");
                ImGui.SetNextItemWidth(200);
                if (ImGui.InputText("Address (hex)##addr", ref _editAddrStr, 20))
                {
                    string clean = _editAddrStr.TrimStart().TrimStart('0').TrimStart('x','X');
                    if (ulong.TryParse(clean, System.Globalization.NumberStyles.HexNumber, null, out ulong a))
                    { t.Address = a; Manager.Save(); }
                }
                ImGui.SameLine();
                if (ImGui.SmallButton("Read##rn") && _pipe.DllConnected) _pipe.MemRead(t.Address, 16);

                ImGui.SetNextItemWidth(120);
                if (ImGui.Combo("Type##dt", ref _editTypeIdx, TypeLabels, TypeLabels.Length))
                { t.DataType = (ToggleDataType)_editTypeIdx; Manager.Save(); }
                ImGui.SameLine();
                ImGui.TextColored(Muted, t.DataType switch {
                    ToggleDataType.Float32 => "float 4B",
                    ToggleDataType.Float64 => "double 8B",
                    ToggleDataType.Int32   => "int32 4B",
                    ToggleDataType.UInt8   => "uint8 1B",
                    _ => "" });

                ImGui.SetNextItemWidth(160);
                if (ImGui.InputText("Value##ev", ref _editValue, 40)) { t.ValueStr = _editValue; Manager.Save(); }
                ImGui.SameLine(); ImGui.TextColored(Muted, "← forced to address while active");

                ImGui.SetNextItemWidth(100);
                if (ImGui.InputInt("Interval ms##ei", ref _editIntervalMs))
                { _editIntervalMs = Math.Max(20, _editIntervalMs); t.IntervalMs = _editIntervalMs; Manager.Save(); }

                // Presets
                ImGui.Separator();
                ImGui.TextColored(Muted, "Quick presets:");
                void Preset(string label, string val, ToggleDataType dtype) {
                    if (ImGui.SmallButton(label)) {
                        _editValue = val; t.ValueStr = val;
                        _editTypeIdx = (int)dtype; t.DataType = dtype;
                        Manager.Save();
                    }
                    ImGui.SameLine();
                }
                Preset("Godmode HP",  "9999",  ToggleDataType.Float32);
                Preset("Max HP 1000", "1000",  ToggleDataType.Float32);
                Preset("Fly Y=200",   "200",   ToggleDataType.Float64);
                Preset("Speed X=50",  "50",    ToggleDataType.Float32);
                Preset("Speed X=0",   "0",     ToggleDataType.Float32);
                ImGui.NewLine();
                Preset("No gravity",  "0",     ToggleDataType.Float32);
                Preset("i32=0",       "0",     ToggleDataType.Int32);
                Preset("i32=1",       "1",     ToggleDataType.Int32);
                ImGui.NewLine();

                // Hotkey
                ImGui.Separator();
                ImGui.TextColored(Accent, "Hotkey");
                bool ck = _editHkCtrl, sk = _editHkShift, ak = _editHkAlt;
                if (ImGui.Checkbox("Ctrl##hc",  ref ck)) { _editHkCtrl  = ck; t.HotkeyCtrl  = ck; Manager.Save(); }
                ImGui.SameLine();
                if (ImGui.Checkbox("Shift##hs", ref sk)) { _editHkShift = sk; t.HotkeyShift = sk; Manager.Save(); }
                ImGui.SameLine();
                if (ImGui.Checkbox("Alt##ha",   ref ak)) { _editHkAlt   = ak; t.HotkeyAlt   = ak; Manager.Save(); }
                ImGui.SameLine();
                int ki = Array.IndexOf(KeyNames, _editHotkey); if (ki < 0) ki = 0;
                ImGui.SetNextItemWidth(100);
                if (ImGui.Combo("Key##hk", ref ki, KeyNames, KeyNames.Length))
                { _editHotkey = KeyNames[ki]; t.HotkeyKey = _editHotkey; Manager.Save(); }
                ImGui.SameLine();
                if (_capturingHotkey)
                    ImGui.TextColored(Yellow, "▶ Press any key...");
                else if (ImGui.SmallButton("Capture"))
                    _capturingHotkey = true;
                ImGui.SameLine();
                ImGui.TextColored(Yellow, t.HotkeyLabel);

                ImGui.Separator();
                ImGui.SetNextItemWidth(-1);
                if (ImGui.InputTextMultiline("##notes", ref _editNotes, 512, new Vector2(-1, 55)))
                { t.Notes = _editNotes; Manager.Save(); }

                ImGui.EndTabItem();
            }

            // ── Change Log ────────────────────────────────────────────────────
            if (ImGui.BeginTabItem($"Log ({t.ChangeLog.Count})##cl"))
            {
                ImGui.SetNextItemWidth(180); ImGui.InputText("##cls", ref _logSearch, 64);
                ImGui.SameLine();
                if (ImGui.SmallButton("Clear##clr")) t.ChangeLog.Clear();
                ImGui.SameLine();
                if (ImGui.SmallButton("Export##cle")) ExportToggleLog(t);
                ImGui.Separator();
                ImGui.BeginChild("##clscroll", new Vector2(-1,-1), ImGuiChildFlags.Borders);
                var entries = t.ChangeLog
                    .Where(e => string.IsNullOrEmpty(_logSearch) ||
                                e.NewValue.Contains(_logSearch) || e.Source.Contains(_logSearch))
                    .Reverse().Take(300).ToList();
                if (entries.Count == 0)
                    ImGui.TextColored(Muted, "No changes yet. Activate toggle to start.");
                foreach (var e in entries)
                {
                    var col = e.WasApplied ? (e.Source == "verify" ? Yellow : Green) : Red;
                    ImGui.TextColored(col, $"[{e.Timestamp:HH:mm:ss.fff}]");
                    ImGui.SameLine();
                    ImGui.Text($"{e.PrevValue,-14} → {e.NewValue,-14}  src={e.Source}");
                }
                ImGui.EndChild();
                ImGui.EndTabItem();
            }

            // ── Raw Bytes ─────────────────────────────────────────────────────
            if (ImGui.BeginTabItem("Raw Bytes##rb"))
            {
                if (ImGui.Button("Read 64B##r64") && _pipe.DllConnected) _pipe.MemRead(t.Address, 64);
                ImGui.SameLine();
                if (ImGui.Button("Read 256B##r256") && _pipe.DllConnected) _pipe.MemRead(t.Address, 256);
                ImGui.SameLine();
                ImGui.TextColored(Muted, $"Addr: 0x{t.Address:X14}");

                var recent = _pipe.MemReadResults
                    .Where(r => r.Address == t.Address)
                    .OrderByDescending(r => r.ReadAt)
                    .FirstOrDefault();

                if (recent != null)
                {
                    t.LastReadValue = recent.Data.Length >= 4 ? recent.AsF32().ToString("G6") : "—";
                    ImGui.TextColored(Green, $"Read at {recent.ReadAt:HH:mm:ss.fff}  {recent.Data.Length}B");
                    ImGui.Text($"f32[0]={recent.AsF32():G6}  f64[0]={recent.AsF64():G10}  i32[0]={recent.AsI32()}");
                    ImGui.Separator();

                    var hex = new System.Text.StringBuilder();
                    var d = recent.Data;
                    for (int row = 0; row < d.Length; row += 16)
                    {
                        hex.Append($"+{row:X4}  ");
                        for (int c = 0; c < 16; c++)
                        {
                            if (row+c < d.Length) hex.Append($"{d[row+c]:X2} ");
                            else hex.Append("   ");
                            if (c == 7) hex.Append(' ');
                        }
                        hex.Append("  ");
                        for (int c = 0; c < 16 && row+c < d.Length; c++)
                        { char ch = (char)d[row+c]; hex.Append(ch >= 0x20 && ch < 0x7F ? ch : '.'); }
                        hex.AppendLine();
                    }
                    var hexStr = hex.ToString();
                    ImGui.InputTextMultiline("##rbhex", ref hexStr, 16384, new Vector2(-1,-1), ImGuiInputTextFlags.ReadOnly);
                }
                else
                    ImGui.TextColored(Muted, "No data. Click Read with DLL connected.");

                ImGui.EndTabItem();
            }

            ImGui.EndTabBar();
        }

        // ── Hotkey edge detection ─────────────────────────────────────────────
        private void PollHotkeys()
        {
            if (!_pipe.DllConnected) return;
            foreach (var t in Manager.Toggles)
            {
                if (string.IsNullOrEmpty(t.HotkeyKey)) continue;
                bool held = CheckKey(t.HotkeyKey) &&
                    (!t.HotkeyCtrl  || ImGui.IsKeyDown(ImGuiKey.ModCtrl))  &&
                    (!t.HotkeyShift || ImGui.IsKeyDown(ImGuiKey.ModShift)) &&
                    (!t.HotkeyAlt   || ImGui.IsKeyDown(ImGuiKey.ModAlt));
                bool was = _prevHeld.Contains(t.Id.ToString());
                if (held && !was) Manager.Toggle(t);
                if (held) _prevHeld.Add(t.Id.ToString()); else _prevHeld.Remove(t.Id.ToString());
            }
            // Capture mode
            if (_capturingHotkey && _selected != null)
                foreach (var k in KeyNames)
                    if (CheckKey(k)) { _selected.HotkeyKey = k; _editHotkey = k; _capturingHotkey = false; Manager.Save(); break; }
        }

        private static bool CheckKey(string name)
        {
            if (!Enum.TryParse<ImGuiKey>(name, true, out var key)) return false;
            try { return ImGui.IsKeyDown(key); } catch { return false; }
        }

        private void CopyToEdit(MemoryToggle t)
        {
            _editName       = t.Name;
            _editCategory   = t.Category;
            _editNotes      = t.Notes;
            _editAddrStr    = t.Address == 0 ? "" : t.Address.ToString("X");
            _editValue      = t.ValueStr;
            _editTypeIdx    = (int)t.DataType;
            _editIntervalMs = t.IntervalMs;
            _editHotkey     = t.HotkeyKey;
            _editHkCtrl     = t.HotkeyCtrl;
            _editHkShift    = t.HotkeyShift;
            _editHkAlt      = t.HotkeyAlt;
        }

        private void ExportAll()
        {
            try
            {
                Directory.CreateDirectory(_state.ExportDirectory);
                string path = Path.Combine(_state.ExportDirectory, $"toggles_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
                File.WriteAllText(path, Manager.ExportReport());
                _state.AddInGameLog($"[TOGGLE] Exported → {Path.GetFileName(path)}");
                try { System.Diagnostics.Process.Start("notepad.exe", path); } catch { }
            }
            catch (Exception ex) { _state.AddInGameLog($"[TOGGLE] Export error: {ex.Message}"); }
        }

        private void ExportToggleLog(MemoryToggle t)
        {
            var sb = new System.Text.StringBuilder();
            sb.AppendLine($"=== Toggle Change Log: {t.Name} ===");
            sb.AppendLine($"Address  : 0x{t.Address:X14}  Type: {t.DataType}  Value: {t.ValueStr}");
            sb.AppendLine($"Hotkey   : {t.HotkeyLabel}  Total writes: {t.WriteCount}");
            sb.AppendLine($"Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine();
            foreach (var e in t.ChangeLog)
                sb.AppendLine($"[{e.Timestamp:HH:mm:ss.fff}] {e.PrevValue,-14} → {e.NewValue,-14}  src={e.Source}  applied={e.WasApplied}");

            try
            {
                Directory.CreateDirectory(_state.ExportDirectory);
                string path = Path.Combine(_state.ExportDirectory, $"toggle_log_{t.Name.Replace(' ','_')}_{DateTime.Now:HHmmss}.txt");
                File.WriteAllText(path, sb.ToString());
                _state.AddInGameLog($"[TOGGLE] Log → {Path.GetFileName(path)}");
                try { System.Diagnostics.Process.Start("notepad.exe", path); } catch { }
            }
            catch (Exception ex) { _state.AddInGameLog($"[TOGGLE] Log error: {ex.Message}"); }
        }
    }
}
