// Tabs/InventorySnapshotTab.cs  v20
using HyForce.Core;
using HyForce.Networking;
using ImGuiNET;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;

namespace HyForce.Tabs;

public class InventorySnapshotTab : ITab
{
    public string Name => "Inv Snapshot";

    private readonly AppState          _state;
    private readonly PipeCaptureServer _pipe;
    private readonly InventorySnapshot _snaps;

    private int   _selSnap1 = -1, _selSnap2 = -1;
    private List<SlotDiff>? _currentDiff;
    private string _exportPath = "";
    private bool   _logScroll  = true;
    private readonly List<string> _log = new();

    public InventorySnapshotTab(AppState state, PipeCaptureServer pipe)
    {
        _state = state; _pipe = pipe; _snaps = state.InventorySnapshot;
        _snaps.OnLog += line => { lock(_log) { _log.Add(line); if(_log.Count>500) _log.RemoveAt(0); } };
    }

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();
        float leftW = 280f;

        ImGui.TextDisabled($"{_snaps.Snaps.Count} snapshots stored");
        ImGui.SameLine();
        ImGui.TextColored(new Vector4(0.5f,1f,0.5f,1f), $"Slots tracked: {_state.InventoryTracker.Slots.Count}");
        ImGui.Separator();

        ImGui.BeginChild("is_left", new Vector2(leftW, avail.Y-4), ImGuiChildFlags.Borders);
        {
            ImGui.TextColored(new Vector4(0.4f,0.85f,1f,1f), "CAPTURE");
            ImGui.TextDisabled("Snapshot the current InventoryTracker state.");
            ImGui.Spacing();

            if (ImGui.Button("Snapshot Now##issn", new Vector2(-1,28)))
            {
                var s = _snaps.Take(_state.InventoryTracker);
                _selSnap1 = _snaps.Snaps.Count - 1;
            }

            if (ImGui.Button("Mark BEFORE##ismb", new Vector2(-1,0)))
                _snaps.MarkBefore(_state.InventoryTracker);

            if (ImGui.Button("Mark AFTER + Diff##isma", new Vector2(-1,0)))
            {
                var (_, after, diffs) = _snaps.MarkAfter(_state.InventoryTracker);
                _currentDiff = diffs;
                _selSnap2 = _snaps.Snaps.Count - 1;
                _selSnap1 = Math.Max(0, _selSnap2 - 1);
            }

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();
            ImGui.TextColored(new Vector4(1f,0.75f,0.3f,1f), "SNAPSHOT LIST");
            ImGui.TextDisabled("Click to select for diff.  A = Before, B = After.");

            ImGui.BeginChild("is_slist", new Vector2(-1,200), ImGuiChildFlags.Borders);
            for (int i=0; i<_snaps.Snaps.Count; i++)
            {
                var s = _snaps.Snaps[i];
                bool isSel1 = _selSnap1 == i, isSel2 = _selSnap2 == i;
                string marker = isSel1 ? "[A]" : isSel2 ? "[B]" : "   ";
                Vector4 col = isSel1 ? new(0.3f,0.7f,1f,1f) : isSel2 ? new(1f,0.7f,0.3f,1f) : new(0.75f,0.75f,0.75f,1f);
                ImGui.TextColored(col, marker);
                ImGui.SameLine();
                if (ImGui.Selectable($"{s.Name}  [{s.SlotCount}]  {s.TakenAt:HH:mm:ss}##isssl{i}", isSel1||isSel2))
                {
                    if (isSel1) _selSnap1 = -1;
                    else if (isSel2) _selSnap2 = -1;
                    else if (_selSnap1 < 0) _selSnap1 = i;
                    else if (_selSnap2 < 0) _selSnap2 = i;
                    else { _selSnap1 = i; _selSnap2 = -1; }
                }
            }
            ImGui.EndChild();

            if (ImGui.Button("Diff A vs B##isdiab", new Vector2(-1,0)) &&
                _selSnap1 >= 0 && _selSnap2 >= 0 && _selSnap1 < _snaps.Snaps.Count && _selSnap2 < _snaps.Snaps.Count)
            {
                _currentDiff = _snaps.Diff(_snaps.Snaps[_selSnap1], _snaps.Snaps[_selSnap2]);
                AddLog($"[DIFF] {_currentDiff.Count} changes");
            }

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();
            ImGui.TextColored(new Vector4(0.3f,1f,0.5f,1f), "EXPORT");
            ImGui.SetNextItemWidth(-1); ImGui.InputText("Path##isep", ref _exportPath, 256);
            if (ImGui.Button("Export Snapshot JSON##isexsn", new Vector2(-1,0)) && _selSnap1 >= 0 && _selSnap1 < _snaps.Snaps.Count && !string.IsNullOrEmpty(_exportPath))
                try { File.WriteAllText(_exportPath, _snaps.ExportJson(_snaps.Snaps[_selSnap1])); AddLog($"[INV] Exported to {_exportPath}"); } catch(Exception ex) { AddLog($"[ERR] {ex.Message}"); }

            if (ImGui.Button("Export Diff JSON##isexdf", new Vector2(-1,0)) && _currentDiff != null && !string.IsNullOrEmpty(_exportPath))
                try { File.WriteAllText(_exportPath, _snaps.ExportDiffJson(_currentDiff)); AddLog($"[DIFF] Exported {_currentDiff.Count} diffs to {_exportPath}"); } catch(Exception ex) { AddLog($"[ERR] {ex.Message}"); }

            if (ImGui.SmallButton("Clear All##iscl")) { _snaps.Clear(); _selSnap1=_selSnap2=-1; _currentDiff=null; }
        }
        ImGui.EndChild();

        ImGui.SameLine();

        float rightW = avail.X - leftW - 8;
        ImGui.BeginChild("is_right", new Vector2(rightW, avail.Y-4), ImGuiChildFlags.None);
        {
            if (ImGui.BeginTabBar("is_right_tabs"))
            {
                if (ImGui.BeginTabItem("Diff##isdt"))      { RenderDiff(avail.Y-50); ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Snapshot A##issa")){ RenderSnapView(_selSnap1, avail.Y-50); ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Snapshot B##issb")){ RenderSnapView(_selSnap2, avail.Y-50); ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Log##isl"))        { RenderLog(avail.Y-50); ImGui.EndTabItem(); }
                ImGui.EndTabBar();
            }
        }
        ImGui.EndChild();
    }

    private void RenderDiff(float h)
    {
        if (_currentDiff == null) { ImGui.TextDisabled("Click 'Diff A vs B' to compute differences."); return; }

        int added   = _currentDiff.Count(d => d.Kind == SlotDiffKind.Added);
        int removed = _currentDiff.Count(d => d.Kind == SlotDiffKind.Removed);
        int changed = _currentDiff.Count(d => d.Kind == SlotDiffKind.Changed);
        ImGui.TextColored(new Vector4(0.3f,1f,0.4f,1f),$"+{added} added");
        ImGui.SameLine(); ImGui.TextColored(new Vector4(1f,0.3f,0.3f,1f),$"  -{removed} removed");
        ImGui.SameLine(); ImGui.TextColored(new Vector4(1f,0.85f,0.3f,1f),$"  ~{changed} changed");
        ImGui.Separator();

        ImGui.BeginChild("is_difftbl", new Vector2(-1, h-70), ImGuiChildFlags.None);
        if (ImGui.BeginTable("isdifftbl", 3, ImGuiTableFlags.Borders|ImGuiTableFlags.RowBg|ImGuiTableFlags.ScrollY))
        {
            ImGui.TableSetupColumn("Slot",    ImGuiTableColumnFlags.WidthFixed, 45);
            ImGui.TableSetupColumn("Kind",    ImGuiTableColumnFlags.WidthFixed, 70);
            ImGui.TableSetupColumn("Summary", ImGuiTableColumnFlags.WidthStretch);
            ImGui.TableSetupScrollFreeze(0,1); ImGui.TableHeadersRow();

            foreach (var d in _currentDiff)
            {
                ImGui.TableNextRow();
                ImGui.TableSetColumnIndex(0); ImGui.TextDisabled($"[{d.SlotIndex}]");
                ImGui.TableSetColumnIndex(1);
                Vector4 kc = d.Kind switch {
                    SlotDiffKind.Added   => new(0.3f,1f,0.4f,1f),
                    SlotDiffKind.Removed => new(1f,0.35f,0.35f,1f),
                    SlotDiffKind.Changed => new(1f,0.85f,0.3f,1f),
                    _                   => new(0.5f,0.5f,0.5f,1f)
                };
                ImGui.TextColored(kc, d.Kind.ToString());
                ImGui.TableSetColumnIndex(2); ImGui.TextUnformatted(d.Summary);
            }
            ImGui.EndTable();
        }
        ImGui.EndChild();
    }

    private void RenderSnapView(int idx, float h)
    {
        if (idx < 0 || idx >= _snaps.Snaps.Count) { ImGui.TextDisabled("No snapshot selected."); return; }
        var snap = _snaps.Snaps[idx];
        ImGui.TextColored(new Vector4(0.4f,0.85f,1f,1f), $"{snap.Name}  {snap.SlotCount} slots @ {snap.TakenAt:HH:mm:ss}");
        ImGui.Separator();
        ImGui.BeginChild("is_sv", new Vector2(-1, h-70), ImGuiChildFlags.None);
        if (ImGui.BeginTable("issntbl", 4, ImGuiTableFlags.Borders|ImGuiTableFlags.RowBg|ImGuiTableFlags.ScrollY))
        {
            ImGui.TableSetupColumn("Slot",  ImGuiTableColumnFlags.WidthFixed, 45);
            ImGui.TableSetupColumn("TypeID",ImGuiTableColumnFlags.WidthFixed, 80);
            ImGui.TableSetupColumn("Name",  ImGuiTableColumnFlags.WidthStretch);
            ImGui.TableSetupColumn("Count", ImGuiTableColumnFlags.WidthFixed, 50);
            ImGui.TableSetupScrollFreeze(0,1); ImGui.TableHeadersRow();
            foreach (var s in snap.Slots)
            {
                ImGui.TableNextRow();
                ImGui.TableSetColumnIndex(0); ImGui.TextDisabled($"[{s.SlotIndex}]");
                ImGui.TableSetColumnIndex(1); ImGui.TextDisabled($"0x{s.TypeId:X6}");
                ImGui.TableSetColumnIndex(2); ImGui.TextUnformatted(s.ItemName);
                ImGui.TableSetColumnIndex(3); ImGui.TextDisabled($"×{s.StackCount}");
            }
            ImGui.EndTable();
        }
        ImGui.EndChild();
    }

    private void RenderLog(float h)
    {
        ImGui.Checkbox("Auto-scroll##islsc", ref _logScroll);
        ImGui.SameLine(); if (ImGui.SmallButton("Clear##islcl")) lock(_log) _log.Clear();
        ImGui.Separator();
        ImGui.BeginChild("is_log_ch", new Vector2(-1, h-60), ImGuiChildFlags.Borders);
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
