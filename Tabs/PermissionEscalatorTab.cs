// Tabs/PermissionEscalatorTab.cs  v20
using HyForce.Core;
using HyForce.Networking;
using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;

namespace HyForce.Tabs;

public class PermissionEscalatorTab : ITab
{
    public string Name => "Perm Escalate";

    private readonly AppState            _state;
    private readonly PipeCaptureServer   _pipe;
    private readonly PermissionEscalator _perm;

    private int    _sweepDelay   = 1500;
    private int    _customMaskHex= 0;
    private string _customHexStr = "00000000";
    private int    _presetIdx    = 0;
    private bool   _logScroll    = true;
    private readonly List<string> _log = new();

    // 32-bit grid state
    private bool[] _bitToggles = new bool[32];

    public PermissionEscalatorTab(AppState state, PipeCaptureServer pipe)
    {
        _state = state; _pipe = pipe; _perm = state.PermissionEscalator;
        _perm.OnLog += line => { lock(_log) { _log.Add(line); if(_log.Count>500) _log.RemoveAt(0); } };
    }

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();
        float leftW = 310f;

        ImGui.TextColored(new Vector4(1f,0.65f,0.2f,1f),
            $"Original mask: 0x{_perm.OriginalMask:X8}    Current: 0x{_perm.CurrentMask:X8}");
        ImGui.SameLine();
        if (ImGui.SmallButton("Restore##permres")) _perm.RestoreOriginal();
        ImGui.Separator();

        ImGui.BeginChild("pe_left", new Vector2(leftW, avail.Y-4), ImGuiChildFlags.Borders);
        {
            // Sweep
            ImGui.TextColored(new Vector4(0.4f,0.85f,1f,1f), "BIT SWEEP");
            ImGui.TextDisabled("Injects one bit at a time into PlayerSetup.\nWatches for new S2C opcodes after each inject.");
            ImGui.SetNextItemWidth(-1); ImGui.SliderInt("Delay ms##pesd", ref _sweepDelay, 200, 5000);
            ImGui.Spacing();
            if (_perm.IsScanning)
            {
                float pct = _perm.ScanProgress / 32f;
                ImGui.ProgressBar(pct, new Vector2(-1,0), $"Bit {_perm.ScanProgress}/32");
                if (ImGui.Button("Stop Sweep##pesws", new Vector2(-1,28))) _perm.StopSweep();
            }
            else
            {
                if (ImGui.Button("Start 32-Bit Sweep##pesws2", new Vector2(-1,28)))
                    _perm.StartBitSweep(_sweepDelay);
            }

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

            // Presets
            ImGui.TextColored(new Vector4(0.3f,1f,0.5f,1f), "MASK PRESETS");
            var presets = PermissionEscalator.Presets;
            ImGui.SetNextItemWidth(-1);
            ImGui.Combo("##pepre", ref _presetIdx, presets.Select(p => p.Name).ToArray(), presets.Count);
            if (_presetIdx < presets.Count)
            {
                var sel = presets[_presetIdx];
                ImGui.TextDisabled($"  0x{sel.Mask:X8}  {sel.Description}");
                if (ImGui.Button("Inject Preset##pepri", new Vector2(-1,0)))
                    _perm.InjectPreset(sel);
            }

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

            // Custom mask
            ImGui.TextColored(new Vector4(0.7f,0.4f,1f,1f), "CUSTOM MASK");
            ImGui.SetNextItemWidth(-1);
            if (ImGui.InputText("Hex Mask##pecm", ref _customHexStr, 8,
                ImGuiInputTextFlags.CharsHexadecimal))
            {
                if (uint.TryParse(_customHexStr, System.Globalization.NumberStyles.HexNumber, null, out uint m))
                {
                    _customMaskHex = (int)m;
                    // Sync toggle grid
                    for (int b=0; b<32; b++) _bitToggles[b] = ((m>>b)&1) == 1;
                }
            }
            // Bit grid — 8×4
            ImGui.Text("Bit editor:");
            for (int row=0; row<4; row++)
            {
                for (int col=0; col<8; col++)
                {
                    int bit = row*8 + col;
                    if (col > 0) ImGui.SameLine();
                    bool v = _bitToggles[bit];
                    ImGui.PushStyleColor(ImGuiCol.Button, v ? new Vector4(0.2f,0.6f,0.2f,1f) : new Vector4(0.18f,0.18f,0.18f,1f));
                    if (ImGui.Button($"{bit:D2}##peb{bit}", new Vector2(28,22)))
                    {
                        _bitToggles[bit] = !_bitToggles[bit];
                        // Rebuild hex
                        uint nm = 0;
                        for (int b=0; b<32; b++) if (_bitToggles[b]) nm |= (1u<<b);
                        _customHexStr = nm.ToString("X8");
                        _customMaskHex = (int)nm;
                    }
                    ImGui.PopStyleColor();
                }
            }
            ImGui.Spacing();
            if (ImGui.Button("Inject Custom Mask##pecmi", new Vector2(-1,0)))
                _perm.InjectCustom((uint)_customMaskHex);

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

            // Single bit quick inject
            ImGui.TextColored(new Vector4(1f,0.4f,0.4f,1f), "SINGLE BIT TEST");
            ImGui.TextDisabled("Injects a PlayerSetup with ONE bit set.\nWatch in-game for immediate effect.");
            for (int b=0; b<32; b++)
            {
                if (b % 8 != 0) ImGui.SameLine();
                var bi = _perm.Bits[b];
                Vector4 bc = bi.Result == PermBitResult.S2CTriggered ? new(0.2f,1f,0.3f,1f)
                           : bi.Result == PermBitResult.NoEffect      ? new(0.35f,0.35f,0.35f,1f)
                           : bi.Result == PermBitResult.Disconnected  ? new(1f,0.2f,0.2f,1f)
                           : new(0.5f,0.5f,0.5f,1f);
                ImGui.PushStyleColor(ImGuiCol.Button, bc);
                if (ImGui.Button($"{b}##pesb{b}", new Vector2(28,22)))
                    _pipe.PermTestBit(b);
                ImGui.PopStyleColor();
                if (ImGui.IsItemHovered())
                    ImGui.SetTooltip($"Bit {b} (0x{1u<<b:X8})\nResult: {bi.Result}\nNew S2C: [{string.Join(",", bi.NewOpcodes.Select(o=>$"0x{o:X4}"))}]\n{bi.Notes}");
            }
        }
        ImGui.EndChild();

        ImGui.SameLine();

        float rightW = avail.X - leftW - 8;
        ImGui.BeginChild("pe_right", new Vector2(rightW, avail.Y-4), ImGuiChildFlags.None);
        {
            if (ImGui.BeginTabBar("pe_right_tabs"))
            {
                if (ImGui.BeginTabItem("Sweep Results##pesr")) { RenderSweepResults(avail.Y-50); ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Log##pelog"))          { RenderLog(avail.Y-50);           ImGui.EndTabItem(); }
                ImGui.EndTabBar();
            }
        }
        ImGui.EndChild();
    }

    private void RenderSweepResults(float h)
    {
        ImGui.TextDisabled($"Bits with new S2C activity: {_perm.Bits.Count(b => b.NewOpcodes.Count > 0)}");
        ImGui.Separator();
        ImGui.BeginChild("pe_sr_tbl", new Vector2(-1, h-60), ImGuiChildFlags.None);
        if (ImGui.BeginTable("pesrtbl", 5, ImGuiTableFlags.Borders|ImGuiTableFlags.RowBg|ImGuiTableFlags.ScrollY))
        {
            ImGui.TableSetupColumn("Bit",    ImGuiTableColumnFlags.WidthFixed, 35);
            ImGui.TableSetupColumn("Mask",   ImGuiTableColumnFlags.WidthFixed, 90);
            ImGui.TableSetupColumn("Result", ImGuiTableColumnFlags.WidthFixed, 90);
            ImGui.TableSetupColumn("S2C triggered", ImGuiTableColumnFlags.WidthStretch);
            ImGui.TableSetupColumn("Action", ImGuiTableColumnFlags.WidthFixed, 60);
            ImGui.TableSetupScrollFreeze(0,1); ImGui.TableHeadersRow();

            foreach (var bi in _perm.Bits)
            {
                ImGui.TableNextRow();
                ImGui.TableSetColumnIndex(0); ImGui.TextDisabled($"{bi.Bit:D2}");
                ImGui.TableSetColumnIndex(1); ImGui.TextDisabled($"0x{bi.Mask:X8}");
                ImGui.TableSetColumnIndex(2);
                Vector4 rc = bi.Result == PermBitResult.S2CTriggered ? new(0.2f,1f,0.3f,1f)
                           : bi.Result == PermBitResult.NoEffect      ? new(0.4f,0.4f,0.4f,1f)
                           : bi.Result == PermBitResult.Disconnected  ? new(1f,0.2f,0.2f,1f)
                           : new(0.6f,0.6f,0.6f,1f);
                ImGui.TextColored(rc, bi.Result.ToString());
                ImGui.TableSetColumnIndex(3);
                if (bi.NewOpcodes.Count > 0)
                    ImGui.TextUnformatted(string.Join(" ", bi.NewOpcodes.Select(o=>$"0x{o:X4}")));
                else
                    ImGui.TextDisabled("—");
                ImGui.TableSetColumnIndex(4);
                if (ImGui.SmallButton($"Inject##peinj{bi.Bit}"))
                    _pipe.PermTestBit(bi.Bit);
            }
            ImGui.EndTable();
        }
        ImGui.EndChild();
    }

    private void RenderLog(float h)
    {
        ImGui.Checkbox("Auto-scroll##pelsc", ref _logScroll);
        ImGui.SameLine(); if (ImGui.SmallButton("Clear##pelcl")) lock(_log) _log.Clear();
        ImGui.Separator();
        ImGui.BeginChild("pe_log_ch", new Vector2(-1, h-60), ImGuiChildFlags.Borders);
        List<string> snap; lock(_log) snap = _log.ToList();
        foreach(var line in snap) ImGui.TextUnformatted(line);
        if(_logScroll && ImGui.GetScrollY() >= ImGui.GetScrollMaxY()-5) ImGui.SetScrollHereY(1f);
        ImGui.EndChild();
    }
}
