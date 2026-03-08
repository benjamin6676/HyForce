// Tabs/PlayerListTab.cs  v17
using HyForce.Core;
using HyForce.Networking;
using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;

namespace HyForce.Tabs;

public class PlayerListTab : ITab
{
    public string Name => "Players";

    private readonly AppState          _state;
    private readonly PipeCaptureServer _pipe;
    private readonly PlayerTracker     _tracker;

    private string  _filter         = "";
    private bool    _showSelf       = true;
    private bool    _autoProune     = true;
    private int     _pruneAgeSec    = 45;
    private bool    _logScroll      = true;
    private string  _typeIdHex      = "";
    private string  _labelEid       = "";
    private string  _labelText      = "";
    private ulong   _selectedEid    = 0;
    private float   _tpOffsetY      = 2f;

    private readonly List<string> _logDisplay = new();

    public PlayerListTab(AppState state, PipeCaptureServer pipe)
    {
        _state   = state;
        _pipe    = pipe;
        _tracker = state.PlayerTracker;
        _tracker.OnLog += line => { lock (_logDisplay) { _logDisplay.Add(line); if (_logDisplay.Count > 500) _logDisplay.RemoveAt(0); } };
        _tracker.OnPlayerJoined += p => { lock (_logDisplay) _logDisplay.Add($"[{DateTime.Now:HH:mm:ss}] ► Player joined  0x{p.EntityId:X}  @ {p.PositionStr}"); };
        _tracker.OnPlayerLeft   += id => { lock (_logDisplay) _logDisplay.Add($"[{DateTime.Now:HH:mm:ss}] ◄ Player left   0x{id:X}"); };
    }

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();

        // ── Stats bar ────────────────────────────────────────────────────────
        int total   = _tracker.Players.Count;
        int others  = _tracker.Players.Values.Count(p => !p.IsSelf);
        ulong selfId = _tracker.SelfEntityId;

        ImGui.TextColored(new Vector4(0.4f, 0.9f, 1f, 1f),
            $"● Players visible: {others}   Self: {(selfId != 0 ? $"0x{selfId:X}" : "unknown")}");
        ImGui.SameLine(0, 20);
        ImGui.TextDisabled($"TypeIDs known: {_tracker.Players.Values.Select(p => p.TypeId).Distinct().Count()}");

        ImGui.Separator();

        // ── Toolbar ──────────────────────────────────────────────────────────
        ImGui.Checkbox("Show self", ref _showSelf); ImGui.SameLine();
        ImGui.Checkbox("Auto-prune", ref _autoProune); ImGui.SameLine();
        ImGui.SetNextItemWidth(50); ImGui.InputInt("s##pps", ref _pruneAgeSec, 0); ImGui.SameLine(0, 16);
        ImGui.SetNextItemWidth(160); ImGui.InputText("Filter##plf", ref _filter, 64); ImGui.SameLine(0, 16);
        ImGui.TextDisabled("Register TypeID:"); ImGui.SameLine();
        ImGui.SetNextItemWidth(90); ImGui.InputText("##ptid", ref _typeIdHex, 8); ImGui.SameLine();
        if (ImGui.SmallButton("Register"))
        {
            if (uint.TryParse(_typeIdHex, System.Globalization.NumberStyles.HexNumber, null, out uint tid))
                _tracker.RegisterPlayerTypeId(tid);
        }
        ImGui.SameLine(0, 16);
        if (ImGui.SmallButton("Clear All")) _tracker.Clear();

        ImGui.Separator();

        float tableH  = avail.Y * 0.62f;
        float bottomH = avail.Y - tableH - 80f;

        // ── Player table ─────────────────────────────────────────────────────
        ImGui.BeginChild("pl_table", new Vector2(-1, tableH), ImGuiChildFlags.None);
        if (ImGui.BeginTable("players", 7,
            ImGuiTableFlags.Borders | ImGuiTableFlags.RowBg |
            ImGuiTableFlags.ScrollY | ImGuiTableFlags.Resizable))
        {
            ImGui.TableSetupColumn("Entity ID",  ImGuiTableColumnFlags.WidthFixed, 140);
            ImGui.TableSetupColumn("Label",      ImGuiTableColumnFlags.WidthFixed, 100);
            ImGui.TableSetupColumn("TypeID",     ImGuiTableColumnFlags.WidthFixed, 70);
            ImGui.TableSetupColumn("Position",   ImGuiTableColumnFlags.WidthStretch);
            ImGui.TableSetupColumn("HP",         ImGuiTableColumnFlags.WidthFixed, 85);
            ImGui.TableSetupColumn("Dist",       ImGuiTableColumnFlags.WidthFixed, 55);
            ImGui.TableSetupColumn("Actions",    ImGuiTableColumnFlags.WidthFixed, 90);
            ImGui.TableSetupScrollFreeze(0, 1);
            ImGui.TableHeadersRow();

            if (_autoProune) _tracker.PruneStale(TimeSpan.FromSeconds(_pruneAgeSec));

            var players = _tracker.Players.Values.ToList();
            if (!_showSelf) players = players.Where(p => !p.IsSelf).ToList();
            if (!string.IsNullOrEmpty(_filter))
            {
                var fl = _filter.ToLower();
                players = players.Where(p =>
                    p.EntityId.ToString("X").ToLower().Contains(fl) ||
                    p.Label.ToLower().Contains(fl)).ToList();
            }
            players = players.OrderBy(p => p.IsSelf ? 0 : 1)
                             .ThenBy(p => p.DistanceTo(_tracker.SelfX, _tracker.SelfY, _tracker.SelfZ))
                             .ToList();

            foreach (var p in players)
            {
                ImGui.TableNextRow();
                bool isSelected = _selectedEid == p.EntityId;

                Vector4 nameCol = p.IsSelf ? new Vector4(0.4f, 1f, 0.5f, 1f) : new Vector4(0.9f, 0.85f, 1f, 1f);

                ImGui.TableSetColumnIndex(0);
                ImGui.PushStyleColor(ImGuiCol.Text, nameCol);
                if (ImGui.Selectable($"0x{p.EntityId:X}##pls{p.EntityId}",
                    isSelected, ImGuiSelectableFlags.SpanAllColumns, new Vector2(0, 0)))
                    _selectedEid = isSelected ? 0 : p.EntityId;
                ImGui.PopStyleColor();

                ImGui.TableSetColumnIndex(1);
                string lbl = p.IsSelf ? "★ SELF" : (string.IsNullOrEmpty(p.Label) ? "-" : p.Label);
                ImGui.TextUnformatted(lbl);

                ImGui.TableSetColumnIndex(2);
                ImGui.TextDisabled($"0x{p.TypeId:X4}");

                ImGui.TableSetColumnIndex(3);
                ImGui.TextColored(new Vector4(0.4f, 0.85f, 1f, 1f), p.PositionStr);

                ImGui.TableSetColumnIndex(4);
                if (p.MaxHP > 0)
                {
                    float pct = p.HP / p.MaxHP;
                    Vector4 hcol = pct > 0.6f ? new Vector4(0.2f,0.9f,0.3f,1f)
                                 : pct > 0.25f ? new Vector4(1f,0.85f,0.1f,1f)
                                 :               new Vector4(1f,0.2f,0.2f,1f);
                    ImGui.TextColored(hcol, p.HealthStr);
                }
                else ImGui.TextDisabled("-");

                ImGui.TableSetColumnIndex(5);
                float dist = p.DistanceTo(_tracker.SelfX, _tracker.SelfY, _tracker.SelfZ);
                ImGui.TextDisabled(p.IsSelf ? "-" : $"{dist:F0}m");

                ImGui.TableSetColumnIndex(6);
                if (!p.IsSelf)
                {
                    if (ImGui.SmallButton($"TP##ptp{p.EntityId}"))
                    {
                        _pipe.Teleport(p.X, p.Y + _tpOffsetY, p.Z);
                    }
                    ImGui.SameLine();
                    if (ImGui.SmallButton($"Kick##pkk{p.EntityId}"))
                        _pipe.KickEntity(p.EntityId);
                }
            }
            ImGui.EndTable();
        }
        ImGui.EndChild();

        // ── Detail / actions ─────────────────────────────────────────────────
        ImGui.Separator();
        ImGui.SetNextItemWidth(60); ImGui.InputFloat("TP Y+##tpyo2", ref _tpOffsetY, 0, 0, "%.1f");
        ImGui.SameLine(0, 16);
        ImGui.SetNextItemWidth(160); ImGui.InputText("EID hex##leid2", ref _labelEid, 32);
        ImGui.SameLine();
        ImGui.SetNextItemWidth(140); ImGui.InputText("Label##ltxt2", ref _labelText, 32);
        ImGui.SameLine();
        if (ImGui.SmallButton("Set Label##sl2"))
        {
            if (ulong.TryParse(_labelEid.TrimStart('0','x','X').Replace("0x",""), System.Globalization.NumberStyles.HexNumber, null, out ulong eid2))
                _tracker.SetLabel(eid2, _labelText);
        }

        if (_selectedEid != 0 && _tracker.Players.TryGetValue(_selectedEid, out var sel))
        {
            ImGui.SameLine(0, 16);
            ImGui.TextColored(new Vector4(0.9f,0.85f,1f,1f), $"Selected: 0x{sel.EntityId:X}  {sel.PositionStr}  HP:{sel.HealthStr}");
            ImGui.SameLine();
            if (ImGui.SmallButton("TP to##ptp2"))
                _pipe.Teleport(sel.X, sel.Y + _tpOffsetY, sel.Z);
        }

        // ── Log ──────────────────────────────────────────────────────────────
        ImGui.Separator();
        ImGui.Checkbox("Auto-scroll##plsc", ref _logScroll); ImGui.SameLine();
        if (ImGui.SmallButton("Clear log")) lock (_logDisplay) _logDisplay.Clear();
        ImGui.BeginChild("pl_log", new Vector2(-1, bottomH), ImGuiChildFlags.Borders);
        List<string> snap; lock (_logDisplay) snap = _logDisplay.ToList();
        foreach (var line in snap)
        {
            Vector4 col = line.Contains("► Player")  ? new Vector4(0.3f,1f,0.5f,1f)
                        : line.Contains("◄ Player")  ? new Vector4(1f,0.5f,0.3f,1f)
                        :                              new Vector4(0.7f,0.7f,0.7f,1f);
            ImGui.TextColored(col, line);
        }
        if (_logScroll && ImGui.GetScrollY() >= ImGui.GetScrollMaxY() - 5)
            ImGui.SetScrollHereY(1f);
        ImGui.EndChild();
    }
}
