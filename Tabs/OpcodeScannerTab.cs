// Tabs/OpcodeScannerTab.cs  v20
using HyForce.Core;
using HyForce.Networking;
using ImGuiNET;
using System;
using System.Linq;
using System.Numerics;

namespace HyForce.Tabs;

public class OpcodeScannerTab : ITab
{
    public string Name => "Opcode Scanner";

    private readonly AppState          _state;
    private readonly PipeCaptureServer _pipe;
    private readonly OpcodeScanner     _scanner;

    private int _scanStart = 0x0001, _scanEnd = 0x01FF, _scanDelay = 250;
    private bool _showAll = false;
    private bool _logScroll = true;
    private readonly System.Collections.Generic.List<string> _log = new();

    public OpcodeScannerTab(AppState state, PipeCaptureServer pipe)
    {
        _state = state; _pipe = pipe; _scanner = state.OpcodeScanner;
        _scanner.OnLog += line => { lock(_log) { _log.Add(line); if(_log.Count>500) _log.RemoveAt(0); } };
    }

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();

        // Status bar
        if (_scanner.IsScanning)
        {
            float pct = (float)_scanner.Progress / Math.Max(1, _scanner.Total);
            ImGui.ProgressBar(pct, new Vector2(300,0), $"0x{_scanner.CurrentOpcode:X4}  {_scanner.Progress}/{_scanner.Total}");
            ImGui.SameLine();
            if (ImGui.Button("Stop##osstp")) _scanner.StopScan();
        }
        else
        {
            ImGui.TextDisabled($"■ IDLE   {_scanner.Results.Count} opcodes scanned   {_scanner.GetResponsive().Count} responsive");
        }
        ImGui.Separator();

        float leftW = 270f;
        ImGui.BeginChild("os_left", new Vector2(leftW, avail.Y-4), ImGuiChildFlags.Borders);
        {
            ImGui.TextColored(new Vector4(0.4f,0.85f,1f,1f), "SCAN CONFIG");
            ImGui.SetNextItemWidth(-1); ImGui.InputInt("Start (hex)##osss", ref _scanStart, 1);
            ImGui.SetNextItemWidth(-1); ImGui.InputInt("End (hex)##osse",   ref _scanEnd,   1);
            ImGui.SetNextItemWidth(-1); ImGui.SliderInt("Delay ms##ossd",   ref _scanDelay, 50, 2000);
            _scanStart = Math.Clamp(_scanStart, 1, 0x1FF);
            _scanEnd   = Math.Clamp(_scanEnd, _scanStart, 0x1FF);
            ImGui.Spacing();
            if (!_scanner.IsScanning)
            {
                if (ImGui.Button("Start Scan##ossst", new Vector2(-1,28)))
                    _scanner.StartScan((ushort)_scanStart, (ushort)_scanEnd, _scanDelay);
            }
            else
            {
                ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.5f,0.1f,0.1f,1f));
                if (ImGui.Button("Stop Scan##ossstp", new Vector2(-1,28))) _scanner.StopScan();
                ImGui.PopStyleColor();
            }
            if (ImGui.SmallButton("Clear##osclr")) _scanner.Clear();

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

            // Quick scan presets
            ImGui.TextColored(new Vector4(0.3f,1f,0.5f,1f), "QUICK PRESETS");
            if (ImGui.SmallButton("Full (1..1FF)##osqf"))   { _scanStart=1; _scanEnd=0x1FF; }
            if (ImGui.SmallButton("Low  (1..7F)##osql"))    { _scanStart=1; _scanEnd=0x7F; }
            if (ImGui.SmallButton("Admin range##osqa"))     { _scanStart=0x100; _scanEnd=0x13F; }
            if (ImGui.SmallButton("Item range##osqi"))      { _scanStart=0xA0; _scanEnd=0xBF; }
            if (ImGui.SmallButton("Perm range##osqp"))      { _scanStart=0x60; _scanEnd=0x7F; }

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();
            ImGui.Checkbox("Show all (not just responsive)##osall", ref _showAll);
        }
        ImGui.EndChild();

        ImGui.SameLine();

        float rightW = avail.X - leftW - 8;
        ImGui.BeginChild("os_right", new Vector2(rightW, avail.Y-4), ImGuiChildFlags.None);
        {
            if (ImGui.BeginTabBar("os_right_tabs"))
            {
                if (ImGui.BeginTabItem("Heatmap##oshm"))  { RenderHeatmap(avail.Y-50); ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Results##osr"))   { RenderResults(avail.Y-50); ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Log##osl"))       { RenderLog(avail.Y-50); ImGui.EndTabItem(); }
                ImGui.EndTabBar();
            }
        }
        ImGui.EndChild();
    }

    private void RenderHeatmap(float h)
    {
        ImGui.TextDisabled("Each cell = one opcode. Color: grey=silent, green=responsive, red=disconnected, dark=untested.");
        ImGui.Separator();
        var dl   = ImGui.GetWindowDrawList();
        var cpos = ImGui.GetCursorScreenPos();
        float cellW = 18, cellH = 14;
        int cols = (int)((ImGui.GetContentRegionAvail().X - 8) / cellW);
        if (cols < 1) cols = 1;

        var all = _scanner.GetAll();
        var byOp = all.ToDictionary(r => r.Opcode);

        for (int op = 0x0001; op <= 0x01FF; op++)
        {
            int row = (op-1) / cols, col = (op-1) % cols;
            var tl = cpos + new Vector2(col * cellW, row * cellH);
            var br = tl + new Vector2(cellW-1, cellH-1);

            uint fill;
            if (byOp.TryGetValue((ushort)op, out var r))
            {
                fill = r.Response switch
                {
                    OpcodeResponse.S2CTriggered => 0xFF44BB44,
                    OpcodeResponse.Disconnected => 0xFF4444BB,
                    OpcodeResponse.RateBlocked  => 0xFF88AA22,
                    OpcodeResponse.Silent       => 0xFF333333,
                    _                           => 0xFF222222,
                };
            }
            else fill = 0xFF111111;

            dl.AddRectFilled(tl, br, fill);
            if (ImGui.IsMouseHoveringRect(tl, br))
                ImGui.SetTooltip($"0x{op:X4}  {(byOp.TryGetValue((ushort)op, out var hr) ? hr.Response.ToString() : "untested")}");
        }
        // advance cursor past heatmap
        int rows = (0x1FF / cols) + 1;
        ImGui.Dummy(new Vector2(cols * cellW, rows * cellH));
    }

    private void RenderResults(float h)
    {
        var results = _showAll ? _scanner.GetAll() : _scanner.GetResponsive();
        ImGui.TextDisabled($"Showing {results.Count} opcodes");
        ImGui.Separator();
        ImGui.BeginChild("os_rtbl", new Vector2(-1, h-60), ImGuiChildFlags.None);
        if (ImGui.BeginTable("osrtbl", 5, ImGuiTableFlags.Borders|ImGuiTableFlags.RowBg|ImGuiTableFlags.ScrollY))
        {
            ImGui.TableSetupColumn("Opcode",    ImGuiTableColumnFlags.WidthFixed, 70);
            ImGui.TableSetupColumn("Response",  ImGuiTableColumnFlags.WidthFixed, 110);
            ImGui.TableSetupColumn("S2C seen",  ImGuiTableColumnFlags.WidthStretch);
            ImGui.TableSetupColumn("Sent",      ImGuiTableColumnFlags.WidthFixed, 80);
            ImGui.TableSetupColumn("Probe",     ImGuiTableColumnFlags.WidthFixed, 50);
            ImGui.TableSetupScrollFreeze(0,1); ImGui.TableHeadersRow();
            foreach (var r in results)
            {
                ImGui.TableNextRow();
                ImGui.TableSetColumnIndex(0); ImGui.TextDisabled($"0x{r.Opcode:X4}");
                ImGui.TableSetColumnIndex(1);
                Vector4 rc = r.Response == OpcodeResponse.S2CTriggered ? new(0.3f,1f,0.4f,1f)
                           : r.Response == OpcodeResponse.Silent       ? new(0.4f,0.4f,0.4f,1f)
                           : r.Response == OpcodeResponse.Disconnected ? new(1f,0.3f,0.3f,1f)
                           : new(0.6f,0.6f,0.6f,1f);
                ImGui.TextColored(rc, r.Response.ToString());
                ImGui.TableSetColumnIndex(2);
                if (r.TriggeredS2C.Count > 0)
                    ImGui.TextUnformatted(string.Join(" ", r.TriggeredS2C.Select(o=>$"0x{o:X4}")));
                else ImGui.TextDisabled("—");
                ImGui.TableSetColumnIndex(3); ImGui.TextDisabled(r.SentAt.ToString("HH:mm:ss"));
                ImGui.TableSetColumnIndex(4);
                if (ImGui.SmallButton($"Re-send##osrs{r.Opcode}"))
                {
                    byte[] frame = new byte[8];
                    BitConverter.GetBytes((uint)4).CopyTo(frame,0);
                    BitConverter.GetBytes(r.Opcode).CopyTo(frame,4);
                    _pipe.ForgeStream(frame);
                }
            }
            ImGui.EndTable();
        }
        ImGui.EndChild();
    }

    private void RenderLog(float h)
    {
        ImGui.Checkbox("Auto-scroll##oslsc", ref _logScroll);
        ImGui.SameLine(); if (ImGui.SmallButton("Clear##oslcl")) lock(_log) _log.Clear();
        ImGui.Separator();
        ImGui.BeginChild("os_log_ch", new Vector2(-1, h-60), ImGuiChildFlags.Borders);
        System.Collections.Generic.List<string> snap; lock(_log) snap=_log.ToList();
        foreach(var line in snap) ImGui.TextUnformatted(line);
        if(_logScroll && ImGui.GetScrollY()>=ImGui.GetScrollMaxY()-5) ImGui.SetScrollHereY(1f);
        ImGui.EndChild();
    }
}
