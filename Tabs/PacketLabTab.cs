// Tabs/PacketLabTab.cs  v16
// Unified C2S packet manipulation lab:
//   - Damage Suppressor: drop DamageInfo (0x70) → effective god-mode via server bypass
//   - Dupe Assist: duplicate MoveItemStack (0xAF) → server processes move twice
//   - Custom opcode drop/dup with live counters
//   - Live C2S stream logger

using HyForce.Core;
using HyForce.Networking;
using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;

namespace HyForce.Tabs;

public class PacketLabTab : ITab
{
    public string Name => "Packet Lab";

    private readonly AppState          _state;
    private readonly PipeCaptureServer _pipe;

    // ── God mode / damage suppressor ────────────────────────────────────────
    private bool   _godMode        = false;
    private long   _dropsTotal     = 0;
    private long   _dupsTotal      = 0;

    // ── Dupe assist ─────────────────────────────────────────────────────────
    private bool   _dupeActive     = false;
    private int    _dupeCount      = 1;
    private string _dupeStatus     = "";

    // ── Custom opcode filter ─────────────────────────────────────────────────
    private string _customDropHex  = "0070";
    private string _customDupHex   = "00AF";
    private int    _customDupCount = 1;
    private bool   _customDropArmed = false;
    private bool   _customDupArmed  = false;

    // ── C2S log ─────────────────────────────────────────────────────────────
    private bool   _c2sLogOn       = false;
    private readonly List<string> _c2sLog = new();
    private bool   _c2sLogScroll   = true;
    private string _c2sFilter      = "";

    // ── General log ─────────────────────────────────────────────────────────
    private readonly List<string> _log = new();
    private bool _logScroll = true;

    public PacketLabTab(AppState state, PipeCaptureServer pipe)
    {
        _state = state;
        _pipe  = pipe;

        // Listen for C2S stream events from the bypass shim
        _pipe.OnQuicStream += entry => {
            if (entry.Direction != "C→S") return;
            if (!_c2sLogOn) return;
            string line = $"[{entry.Timestamp:HH:mm:ss.fff}] C→S 0x{entry.StreamHandle:X}  {entry.Data.Length}B  {entry.HexPreview[..Math.Min(60, entry.HexPreview.Length)]}";
            lock (_c2sLog) {
                _c2sLog.Add(line);
                if (_c2sLog.Count > 1000) _c2sLog.RemoveAt(0);
            }
        };
    }

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();

        // ── Top status bar ──────────────────────────────────────────────────
        ImGui.TextColored(new Vector4(0.4f, 0.9f, 0.4f, 1f),
            $"Drops: {_dropsTotal}   Dups: {_dupsTotal}");
        ImGui.SameLine(0, 30);
        bool connected = _pipe.DllConnected;
        ImGui.TextColored(connected ? new Vector4(0.3f,1f,0.4f,1f) : new Vector4(1f,0.4f,0.3f,1f),
            connected ? "● DLL Connected" : "○ DLL Not Connected");

        ImGui.Separator();

        float leftW  = 320f;
        float rightW = avail.X - leftW - 8;

        // ── Left: controls ──────────────────────────────────────────────────
        ImGui.BeginChild("lab_left", new Vector2(leftW, avail.Y - 4), ImGuiChildFlags.Borders);
        {
            // ── God Mode ─────────────────────────────────────────────────────
            ImGui.TextColored(new Vector4(0.3f, 1f, 0.5f, 1f), "GOD MODE (Damage Suppressor)");
            ImGui.TextDisabled("Drops DamageInfo (0x70) C→S\nServer never registers hits on you.");
            ImGui.Spacing();

            var godCol = _godMode ? new Vector4(0.3f, 1f, 0.3f, 1f) : new Vector4(0.6f, 0.6f, 0.6f, 1f);
            ImGui.PushStyleColor(ImGuiCol.Button, _godMode ? new Vector4(0.1f,0.5f,0.1f,1f) : new Vector4(0.25f,0.25f,0.25f,1f));
            if (ImGui.Button(_godMode ? "GOD MODE: ON  [click to disable]" : "GOD MODE: OFF [click to enable]",
                new Vector2(-1, 32)))
            {
                _godMode = !_godMode;
                if (_godMode)
                {
                    _pipe.QuicDropC2S(0x70);
                    AddLog("[GOD] DamageInfo (0x70) drop ARMED — server will not see damage reports");
                }
                else
                {
                    _pipe.QuicDropC2S(0);
                    AddLog("[GOD] DamageInfo drop CLEARED");
                }
            }
            ImGui.PopStyleColor();

            if (_godMode)
                ImGui.TextColored(new Vector4(0.3f, 1f, 0.3f, 1f), $"  Active — {_dropsTotal} drops suppressed");

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

            // ── Dupe Assist ───────────────────────────────────────────────────
            ImGui.TextColored(new Vector4(1f, 0.65f, 0.2f, 1f), "ITEM DUPE ASSIST");
            ImGui.TextDisabled("Duplicates MoveItemStack (0xAF) C→S\nServer processes the move N+1 times in same tick.");
            ImGui.Spacing();
            ImGui.SetNextItemWidth(-1);
            ImGui.SliderInt("Extra copies##dc", ref _dupeCount, 1, 4);

            ImGui.PushStyleColor(ImGuiCol.Button, _dupeActive
                ? new Vector4(0.55f, 0.3f, 0.05f, 1f)
                : new Vector4(0.25f, 0.25f, 0.25f, 1f));
            if (ImGui.Button(_dupeActive ? "DUPE: ON  [click to disable]" : "DUPE: OFF [click to enable]",
                new Vector2(-1, 32)))
            {
                _dupeActive = !_dupeActive;
                if (_dupeActive)
                {
                    _pipe.QuicDupC2S(0xAF, _dupeCount);
                    _dupeStatus = $"Armed: 0xAF x{_dupeCount}";
                    AddLog($"[DUPE] MoveItemStack (0xAF) dup ARMED x{_dupeCount}  — each move C→S resent {_dupeCount} extra times");
                }
                else
                {
                    _pipe.QuicDupC2S(0, 0);
                    _dupeStatus = "Cleared";
                    AddLog("[DUPE] MoveItemStack dup CLEARED");
                }
            }
            ImGui.PopStyleColor();
            if (!string.IsNullOrEmpty(_dupeStatus))
                ImGui.TextColored(new Vector4(1f, 0.7f, 0.2f, 1f), $"  {_dupeStatus}");

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

            // ── Custom opcode filter ──────────────────────────────────────────
            ImGui.TextColored(new Vector4(0.7f, 0.5f, 1f, 1f), "CUSTOM OPCODE FILTER");
            ImGui.TextDisabled("Any C→S opcode (LE hex, e.g. 00AF)");
            ImGui.Spacing();

            ImGui.Text("Drop opcode:"); ImGui.SameLine();
            ImGui.SetNextItemWidth(90); ImGui.InputText("##cdh", ref _customDropHex, 8);
            ImGui.SameLine();
            ImGui.PushStyleColor(ImGuiCol.Button, _customDropArmed
                ? new Vector4(0.5f,0.1f,0.1f,1f) : new Vector4(0.25f,0.25f,0.25f,1f));
            if (ImGui.Button(_customDropArmed ? "Armed##cda" : "Arm Drop##cda"))
            {
                _customDropArmed = !_customDropArmed;
                if (_customDropArmed && uint.TryParse(_customDropHex, System.Globalization.NumberStyles.HexNumber, null, out uint dop))
                {
                    _pipe.QuicDropC2S(dop);
                    AddLog($"[CUSTOM-DROP] Armed opcode 0x{dop:X4}");
                }
                else { _pipe.QuicDropC2S(0); AddLog("[CUSTOM-DROP] Cleared"); }
            }
            ImGui.PopStyleColor();

            ImGui.Spacing();
            ImGui.Text("Dup opcode: "); ImGui.SameLine();
            ImGui.SetNextItemWidth(90); ImGui.InputText("##cduh", ref _customDupHex, 8);
            ImGui.SameLine();
            ImGui.SetNextItemWidth(40); ImGui.InputInt("x##cduc", ref _customDupCount, 0);
            ImGui.SameLine();
            ImGui.PushStyleColor(ImGuiCol.Button, _customDupArmed
                ? new Vector4(0.4f,0.2f,0.6f,1f) : new Vector4(0.25f,0.25f,0.25f,1f));
            if (ImGui.Button(_customDupArmed ? "Armed##cua" : "Arm Dup##cua"))
            {
                _customDupArmed = !_customDupArmed;
                if (_customDupArmed && uint.TryParse(_customDupHex, System.Globalization.NumberStyles.HexNumber, null, out uint duop))
                {
                    _pipe.QuicDupC2S(duop, _customDupCount);
                    AddLog($"[CUSTOM-DUP] Armed opcode 0x{duop:X4} x{_customDupCount}");
                }
                else { _pipe.QuicDupC2S(0, 0); AddLog("[CUSTOM-DUP] Cleared"); }
            }
            ImGui.PopStyleColor();

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

            // ── C2S logging ───────────────────────────────────────────────────
            ImGui.TextColored(new Vector4(0.5f, 0.8f, 1f, 1f), "C2S STREAM LOG");
            ImGui.TextDisabled("Logs all C→S sends to this panel.\nHigh-traffic — use only for capture.");
            ImGui.Spacing();
            if (ImGui.Button(_c2sLogOn ? "C2S Log: ON  [click off]" : "C2S Log: OFF [click on]",
                new Vector2(-1, 0)))
            {
                _c2sLogOn = !_c2sLogOn;
                if (_c2sLogOn) _pipe.QuicC2SLogOn();
                else           _pipe.QuicC2SLogOff();
                AddLog($"[C2S-LOG] {(_c2sLogOn ? "Enabled" : "Disabled")}");
            }

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

            // ── Counters ──────────────────────────────────────────────────────
            if (ImGui.Button("Fetch C2S Stats", new Vector2(-1, 0)))
                _pipe.QuicC2SStats();
            if (ImGui.Button("Clear All Filters", new Vector2(-1, 0)))
            {
                _godMode = false; _dupeActive = false; _customDropArmed = false; _customDupArmed = false;
                _pipe.QuicDropC2S(0); _pipe.QuicDupC2S(0, 0);
                AddLog("[LAB] All C2S filters cleared");
            }
        }
        ImGui.EndChild();

        ImGui.SameLine();

        // ── Right: logs ──────────────────────────────────────────────────────
        ImGui.BeginChild("lab_right", new Vector2(rightW, avail.Y - 4), ImGuiChildFlags.None);
        {
            if (ImGui.BeginTabBar("lab_right_tabs"))
            {
                if (ImGui.BeginTabItem("Activity Log##lal"))
                {
                    RenderActivityLog(rightW, avail.Y - 50);
                    ImGui.EndTabItem();
                }
                if (ImGui.BeginTabItem("C2S Stream##lc2s"))
                {
                    RenderC2SLog(rightW, avail.Y - 50);
                    ImGui.EndTabItem();
                }
                ImGui.EndTabBar();
            }
        }
        ImGui.EndChild();
    }

    private void RenderActivityLog(float w, float h)
    {
        ImGui.Checkbox("Auto-scroll##alsc", ref _logScroll);
        ImGui.SameLine();
        if (ImGui.Button("Clear##alc")) lock (_log) _log.Clear();
        ImGui.Separator();
        ImGui.BeginChild("act_log", new Vector2(-1, h - 60), ImGuiChildFlags.Borders);
        List<string> snap; lock (_log) snap = _log.ToList();
        foreach (var line in snap)
        {
            Vector4 col = line.Contains("[GOD]")    ? new Vector4(0.3f,1f,0.4f,1f)
                        : line.Contains("[DUPE]")   ? new Vector4(1f,0.7f,0.2f,1f)
                        : line.Contains("[ERR]")    ? new Vector4(1f,0.3f,0.3f,1f)
                        : line.Contains("[CUSTOM]") ? new Vector4(0.7f,0.5f,1f,1f)
                        :                             new Vector4(0.85f,0.85f,0.85f,1f);
            ImGui.TextColored(col, line);
        }
        if (_logScroll && ImGui.GetScrollY() >= ImGui.GetScrollMaxY() - 5)
            ImGui.SetScrollHereY(1f);
        ImGui.EndChild();
    }

    private void RenderC2SLog(float w, float h)
    {
        ImGui.Checkbox("Auto-scroll##c2ssc", ref _c2sLogScroll);
        ImGui.SameLine();
        ImGui.SetNextItemWidth(200); ImGui.InputText("Filter##c2sf", ref _c2sFilter, 64);
        ImGui.SameLine();
        if (ImGui.Button("Clear##c2scl")) lock (_c2sLog) _c2sLog.Clear();
        ImGui.Separator();
        ImGui.BeginChild("c2s_log_panel", new Vector2(-1, h - 60), ImGuiChildFlags.Borders);
        List<string> snap; lock (_c2sLog) snap = _c2sLog.ToList();
        if (!string.IsNullOrEmpty(_c2sFilter))
            snap = snap.Where(l => l.ToLower().Contains(_c2sFilter.ToLower())).ToList();
        foreach (var line in snap)
            ImGui.TextColored(new Vector4(1f, 0.65f, 0.3f, 1f), line);
        if (_c2sLogScroll && ImGui.GetScrollY() >= ImGui.GetScrollMaxY() - 5)
            ImGui.SetScrollHereY(1f);
        ImGui.EndChild();
    }

    private void AddLog(string msg)
    {
        var line = $"[{DateTime.Now:HH:mm:ss.fff}] {msg}";
        lock (_log) { _log.Add(line); if (_log.Count > 1000) _log.RemoveAt(0); }
    }
}
