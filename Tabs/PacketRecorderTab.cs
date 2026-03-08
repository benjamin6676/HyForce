// Tabs/PacketRecorderTab.cs  v19
using HyForce.Core;
using HyForce.Networking;
using ImGuiNET;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;

namespace HyForce.Tabs;

public class PacketRecorderTab : ITab
{
    public string Name => "Recorder";

    private readonly AppState          _state;
    private readonly PipeCaptureServer _pipe;
    private readonly PacketRecorder    _rec;

    private bool   _autoSave       = false;
    private string _saveDir        = "";
    private string _loadPath       = "";
    private List<RecordedFrame>? _loaded;
    private int    _selectedFrame  = -1;
    private string _filterOpcode   = "";
    private bool   _filterS2C      = true;
    private bool   _filterC2S      = true;
    private bool   _logScroll      = true;
    private readonly List<string> _log = new();

    public PacketRecorderTab(AppState state, PipeCaptureServer pipe)
    {
        _state   = state;
        _pipe    = pipe;
        _rec     = state.PacketRecorder;
        _saveDir = state.ExportDirectory;
        _rec.OnLog += line => { lock(_log) { _log.Add(line); if(_log.Count>500) _log.RemoveAt(0); } };
    }

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();
        float leftW = 280f;

        // Status bar
        string recState = _rec.IsRecording ? "● REC" : "■ STOP";
        Vector4 stateCol = _rec.IsRecording ? new(1f,0.2f,0.2f,1f) : new(0.5f,0.5f,0.5f,1f);
        ImGui.TextColored(stateCol, recState);
        ImGui.SameLine(0,12);
        ImGui.TextDisabled($"{_rec.FrameCount} frames  {_rec.TotalBytes/1024.0:F1} KB");
        ImGui.Separator();

        ImGui.BeginChild("rec_left", new Vector2(leftW, avail.Y-4), ImGuiChildFlags.Borders);
        {
            // Controls
            ImGui.TextColored(new Vector4(0.4f,0.85f,1f,1f), "RECORDING");
            if (!_rec.IsRecording)
            {
                if (ImGui.Button("Start Recording##recstart", new Vector2(-1,28)))
                { _rec.Start(); _pipe.RecordOn(); }
            }
            else
            {
                ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.6f,0.1f,0.1f,1f));
                if (ImGui.Button("Stop Recording##recstop", new Vector2(-1,28)))
                { _rec.Stop(); _pipe.RecordOff(); }
                ImGui.PopStyleColor();
            }
            if (ImGui.Button("Clear##reccl", new Vector2(-1,0)))
            { _rec.Clear(); _pipe.RecordClear(); _loaded = null; }

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

            // Save
            ImGui.TextColored(new Vector4(0.3f,1f,0.5f,1f), "SAVE / LOAD");
            ImGui.SetNextItemWidth(-1); ImGui.InputText("Save dir##recsd", ref _saveDir, 256);
            if (ImGui.Button("Save .hfrec##recsv", new Vector2(-1,0)) && _rec.FrameCount > 0)
            {
                try
                {
                    string path = Path.Combine(_saveDir, $"session_{DateTime.Now:yyyyMMdd_HHmmss}.hfrec");
                    _rec.SaveTo(path);
                }
                catch (Exception ex) { AddLog($"[ERR] {ex.Message}"); }
            }
            ImGui.Checkbox("Auto-save on stop##recas", ref _autoSave);

            ImGui.Spacing();
            ImGui.SetNextItemWidth(-1); ImGui.InputText("Load path##reclp", ref _loadPath, 512);
            if (ImGui.Button("Load .hfrec##recld", new Vector2(-1,0)) && File.Exists(_loadPath))
            {
                try { _loaded = _rec.LoadFrom(_loadPath); }
                catch (Exception ex) { AddLog($"[ERR] {ex.Message}"); }
            }

            // Browse exports
            ImGui.Spacing(); ImGui.Separator();
            ImGui.TextDisabled("Recent recordings:");
            if (Directory.Exists(_saveDir))
            {
                foreach (var f in Directory.GetFiles(_saveDir, "*.hfrec")
                    .OrderByDescending(File.GetLastWriteTime).Take(6))
                {
                    string fname = Path.GetFileName(f);
                    if (ImGui.SmallButton($"Load {fname}##recbr{fname}"))
                    {
                        try { _loaded = _rec.LoadFrom(f); _loadPath = f; }
                        catch (Exception ex) { AddLog($"[ERR] {ex.Message}"); }
                    }
                }
            }

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

            // Replay loaded
            ImGui.TextColored(new Vector4(1f,0.75f,0.3f,1f), "REPLAY");
            if (_loaded != null)
            {
                ImGui.TextDisabled($"Loaded: {_loaded.Count} frames");
                if (ImGui.Button("Replay All (S2C spoof)##recreplay", new Vector2(-1,0)))
                {
                    foreach (var f in _loaded.Where(x => x.IsS2C))
                        _pipe.SpoofS2C(f.Payload);
                    AddLog($"[REPLAY] Spoofed {_loaded.Count(x=>x.IsS2C)} S2C frames");
                }
                if (_selectedFrame >= 0 && _selectedFrame < (_loaded?.Count ?? 0))
                {
                    if (ImGui.Button("Replay Selected##recrsel", new Vector2(-1,0)))
                    {
                        _pipe.SpoofS2C(_loaded![_selectedFrame].Payload);
                        AddLog($"[REPLAY] Spoofed frame #{_selectedFrame}");
                    }
                }
            }
            else ImGui.TextDisabled("  Load a recording first.");
        }
        ImGui.EndChild();

        ImGui.SameLine();

        float rightW = avail.X - leftW - 8;
        ImGui.BeginChild("rec_right", new Vector2(rightW, avail.Y-4), ImGuiChildFlags.None);
        {
            if (ImGui.BeginTabBar("rec_right_tabs"))
            {
                if (ImGui.BeginTabItem("Live Frames##recl")) { RenderFrameTable(_rec.GetFrames(), avail.Y-50, ref _selectedFrame); ImGui.EndTabItem(); }
                if (_loaded != null && ImGui.BeginTabItem("Loaded##recld2")) { RenderFrameTable(_loaded, avail.Y-50, ref _selectedFrame); ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Log##reclog")) { RenderLog(avail.Y-50); ImGui.EndTabItem(); }
                ImGui.EndTabBar();
            }
        }
        ImGui.EndChild();
    }

    private void RenderFrameTable(List<RecordedFrame> frames, float h, ref int selIdx)
    {
        ImGui.SetNextItemWidth(100); ImGui.InputText("Opcode##recflt", ref _filterOpcode, 8); ImGui.SameLine();
        ImGui.Checkbox("S2C##recfs2c", ref _filterS2C); ImGui.SameLine();
        ImGui.Checkbox("C2S##recfc2s", ref _filterC2S);
        ImGui.Separator();

        var visible = frames.AsEnumerable();
        if (_filterS2C && !_filterC2S) visible = visible.Where(f => f.IsS2C);
        if (!_filterS2C && _filterC2S) visible = visible.Where(f => !f.IsS2C);
        if (!string.IsNullOrEmpty(_filterOpcode) && ushort.TryParse(_filterOpcode, System.Globalization.NumberStyles.HexNumber, null, out ushort fOp))
            visible = visible.Where(f => f.Opcode == fOp);

        var list = visible.ToList();
        ImGui.TextDisabled($"{list.Count} frames shown");

        ImGui.BeginChild("rec_tbl", new Vector2(-1, h-80), ImGuiChildFlags.None);
        if (ImGui.BeginTable("recframetbl", 5, ImGuiTableFlags.Borders|ImGuiTableFlags.RowBg|ImGuiTableFlags.ScrollY))
        {
            ImGui.TableSetupColumn("#",       ImGuiTableColumnFlags.WidthFixed, 40);
            ImGui.TableSetupColumn("Time",    ImGuiTableColumnFlags.WidthFixed, 90);
            ImGui.TableSetupColumn("Dir",     ImGuiTableColumnFlags.WidthFixed, 40);
            ImGui.TableSetupColumn("Opcode",  ImGuiTableColumnFlags.WidthFixed, 70);
            ImGui.TableSetupColumn("Len",     ImGuiTableColumnFlags.WidthFixed, 55);
            ImGui.TableSetupScrollFreeze(0,1); ImGui.TableHeadersRow();

            int idx = 0;
            foreach (var f in list.TakeLast(5000))
            {
                ImGui.TableNextRow();
                ImGui.TableSetColumnIndex(0);
                if (ImGui.Selectable($"{idx}##recf{idx}", selIdx==idx, ImGuiSelectableFlags.SpanAllColumns))
                    selIdx = idx;
                ImGui.TableSetColumnIndex(1); ImGui.TextDisabled(f.Timestamp.ToString("HH:mm:ss.fff"));
                ImGui.TableSetColumnIndex(2);
                ImGui.TextColored(f.IsS2C ? new Vector4(0.4f,0.85f,1f,1f) : new Vector4(1f,0.75f,0.3f,1f),
                    f.IsS2C ? "S2C" : "C2S");
                ImGui.TableSetColumnIndex(3); ImGui.TextDisabled($"0x{f.Opcode:X4}");
                ImGui.TableSetColumnIndex(4); ImGui.TextDisabled($"{f.Payload.Length}");
                idx++;
            }
            ImGui.EndTable();
        }

        // Detail of selected
        if (selIdx >= 0 && selIdx < list.Count)
        {
            var sf = list[selIdx];
            ImGui.Separator();
            ImGui.TextColored(new Vector4(1f,0.85f,0.3f,1f), $"Frame #{selIdx}  opcode=0x{sf.Opcode:X4}  {sf.Payload.Length}B");
            string hex = BitConverter.ToString(sf.Payload, 0, Math.Min(sf.Payload.Length, 128)).Replace("-"," ");
            ImGui.TextWrapped(hex);
        }
        ImGui.EndChild();
    }

    private void RenderLog(float h)
    {
        ImGui.Checkbox("Auto-scroll##reclsc", ref _logScroll);
        ImGui.SameLine(); if (ImGui.SmallButton("Clear##reclcl")) lock(_log) _log.Clear();
        ImGui.Separator();
        ImGui.BeginChild("rec_log_child", new Vector2(-1, h-60), ImGuiChildFlags.Borders);
        List<string> snap; lock(_log) snap=_log.ToList();
        foreach(var line in snap) ImGui.TextUnformatted(line);
        if(_logScroll && ImGui.GetScrollY()>=ImGui.GetScrollMaxY()-5) ImGui.SetScrollHereY(1f);
        ImGui.EndChild();
    }

    private void AddLog(string msg)
    {
        var line = $"[{DateTime.Now:HH:mm:ss.fff}] {msg}";
        lock(_log) { _log.Add(line); if(_log.Count>500) _log.RemoveAt(0); }
    }
}
