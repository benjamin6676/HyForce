// Tabs/EntityTrackerTab.cs  v16
using HyForce.Core;
using HyForce.Networking;
using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;

namespace HyForce.Tabs;

public class EntityTrackerTab : ITab
{
    public string Name => "Entity Tracker";

    private readonly EntityTracker _tracker;
    private readonly PipeCaptureServer _pipe;

    private string  _filter      = "";
    private bool    _autoProune  = true;
    private int     _pruneAgeSec = 30;
    private bool    _showLog     = true;
    private bool    _logScroll   = true;
    private bool    _sortByDist  = false;
    private float   _refX, _refY, _refZ;
    private string  _refStr      = "0,0,0";
    private string  _labelEid    = "";
    private string  _labelText   = "";
    private ulong   _selectedEid = 0;

    // Log display buffer
    private readonly List<string> _logDisplay = new();
    private int _logVersion = 0;

    public EntityTrackerTab(EntityTracker tracker, PipeCaptureServer pipe)
    {
        _tracker = tracker;
        _pipe    = pipe;

        _tracker.OnLog += line => {
            lock (_logDisplay) {
                _logDisplay.Add(line);
                if (_logDisplay.Count > 500) _logDisplay.RemoveAt(0);
            }
            _logVersion++;
        };
    }

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();

        // ── Header stats ────────────────────────────────────────────────────
        ImGui.TextColored(new Vector4(0.3f, 0.9f, 0.6f, 1f),
            $"● Entities tracked: {_tracker.EntityCount}   Updates: {_tracker.TotalUpdates}   Errors: {_tracker.ParseErrors}");
        ImGui.SameLine(0, 20);
        if (ImGui.Button("Clear All")) _tracker.Clear();
        ImGui.SameLine();
        if (ImGui.Button("Prune Stale"))
            _tracker.PruneStale(TimeSpan.FromSeconds(_pruneAgeSec));

        ImGui.Separator();

        // ── Toolbar ─────────────────────────────────────────────────────────
        ImGui.Checkbox("Auto-prune", ref _autoProune); ImGui.SameLine();
        ImGui.SetNextItemWidth(60); ImGui.InputInt("sec##ps", ref _pruneAgeSec, 0); ImGui.SameLine(0, 16);
        ImGui.Checkbox("Sort by distance", ref _sortByDist); ImGui.SameLine();
        if (_sortByDist)
        {
            ImGui.SetNextItemWidth(200);
            if (ImGui.InputText("Ref XYZ##ref", ref _refStr, 64))
                ParseRef(_refStr, out _refX, out _refY, out _refZ);
        }
        ImGui.SetNextItemWidth(200);
        ImGui.InputText("Filter##ef", ref _filter, 128);
        ImGui.SameLine();
        ImGui.Checkbox("Show log", ref _showLog);

        ImGui.Separator();

        float tableH = _showLog ? avail.Y * 0.60f : avail.Y - 40f;

        // ── Entity table ────────────────────────────────────────────────────
        ImGui.BeginChild("entity_table", new Vector2(-1, tableH - 30), ImGuiChildFlags.None);
        if (ImGui.BeginTable("entities", 8,
            ImGuiTableFlags.Borders | ImGuiTableFlags.RowBg |
            ImGuiTableFlags.ScrollY | ImGuiTableFlags.Sortable |
            ImGuiTableFlags.Resizable))
        {
            ImGui.TableSetupColumn("EntityID",   ImGuiTableColumnFlags.WidthFixed, 120);
            ImGui.TableSetupColumn("Label",      ImGuiTableColumnFlags.WidthFixed, 100);
            ImGui.TableSetupColumn("Type",       ImGuiTableColumnFlags.WidthFixed, 70);
            ImGui.TableSetupColumn("Position",   ImGuiTableColumnFlags.WidthStretch);
            ImGui.TableSetupColumn("Health",     ImGuiTableColumnFlags.WidthFixed, 90);
            ImGui.TableSetupColumn("Velocity",   ImGuiTableColumnFlags.WidthFixed, 130);
            ImGui.TableSetupColumn("Updates",    ImGuiTableColumnFlags.WidthFixed, 65);
            ImGui.TableSetupColumn("Last Seen",  ImGuiTableColumnFlags.WidthFixed, 90);
            ImGui.TableSetupScrollFreeze(0, 1);
            ImGui.TableHeadersRow();

            var entities = _tracker.Entities.Values.ToList();
            if (!string.IsNullOrEmpty(_filter))
            {
                string fl = _filter.ToLower();
                entities = entities.Where(e =>
                    e.EntityId.ToString("X").ToLower().Contains(fl) ||
                    e.Label.ToLower().Contains(fl) ||
                    e.TypeId.ToString("X").Contains(fl) ||
                    e.PositionStr.Contains(fl)).ToList();
            }
            if (_sortByDist && _autoProune)
                entities = entities.OrderBy(e => e.DistanceTo(_refX, _refY, _refZ)).ToList();
            else
                entities = entities.OrderByDescending(e => e.UpdateCount).ToList();

            // Auto-prune stale
            if (_autoProune) _tracker.PruneStale(TimeSpan.FromSeconds(_pruneAgeSec));

            foreach (var e in entities)
            {
                ImGui.TableNextRow();

                bool sel = _selectedEid == e.EntityId;
                Vector4 rowCol = e.HasHealth
                    ? new Vector4(0.4f + (e.HP / Math.Max(1, e.MaxHP)) * 0.5f, 0.9f, 0.5f, 1f)
                    : new Vector4(0.8f, 0.8f, 0.8f, 1f);

                ImGui.TableSetColumnIndex(0);
                ImGui.PushStyleColor(ImGuiCol.Text, rowCol);
                if (ImGui.Selectable($"0x{e.EntityId:X16}##e{e.EntityId}",
                    sel, ImGuiSelectableFlags.SpanAllColumns, new Vector2(0, 0)))
                    _selectedEid = sel ? 0 : e.EntityId;
                ImGui.PopStyleColor();

                ImGui.TableSetColumnIndex(1);
                ImGui.TextUnformatted(string.IsNullOrEmpty(e.Label) ? "-" : e.Label);

                ImGui.TableSetColumnIndex(2);
                ImGui.Text(e.HasType ? $"0x{e.TypeId:X4}" : "-");

                ImGui.TableSetColumnIndex(3);
                if (e.HasPosition)
                    ImGui.TextColored(new Vector4(0.4f, 0.85f, 1f, 1f), e.PositionStr);
                else
                    ImGui.TextDisabled("-");

                ImGui.TableSetColumnIndex(4);
                if (e.HasHealth)
                {
                    float pct = e.HP / Math.Max(1, e.MaxHP);
                    var hcol = pct > 0.5f ? new Vector4(0.2f, 0.9f, 0.3f, 1f)
                             : pct > 0.2f ? new Vector4(1f, 0.85f, 0.1f, 1f)
                             :              new Vector4(1f, 0.2f, 0.2f, 1f);
                    ImGui.TextColored(hcol, e.HealthStr);
                }
                else ImGui.TextDisabled("-");

                ImGui.TableSetColumnIndex(5);
                ImGui.TextDisabled(e.HasVelocity ? e.VelocityStr : "-");

                ImGui.TableSetColumnIndex(6);
                ImGui.Text(e.UpdateCount.ToString());

                ImGui.TableSetColumnIndex(7);
                ImGui.TextDisabled($"{(DateTime.UtcNow - e.LastSeen).TotalSeconds:F1}s");
            }
            ImGui.EndTable();
        }
        ImGui.EndChild();

        // ── Detail / label pane ─────────────────────────────────────────────
        if (_selectedEid != 0 && _tracker.Entities.TryGetValue(_selectedEid, out var sel2))
        {
            ImGui.Separator();
            ImGui.Text($"Selected: 0x{sel2.EntityId:X16}   TypeID: 0x{sel2.TypeId:X4}   Updates: {sel2.UpdateCount}");
            ImGui.SetNextItemWidth(200); ImGui.InputText("EID##leid", ref _labelEid, 64);
            ImGui.SameLine();
            ImGui.SetNextItemWidth(200); ImGui.InputText("Label##ltxt", ref _labelText, 64);
            ImGui.SameLine();
            if (ImGui.Button("Set Label") && ulong.TryParse(_labelEid.Replace("0x","").Replace("0X",""), System.Globalization.NumberStyles.HexNumber, null, out ulong leid))
                _tracker.SetLabel(leid, _labelText);
        }

        // ── Log panel ───────────────────────────────────────────────────────
        if (_showLog)
        {
            ImGui.Separator();
            ImGui.TextColored(new Vector4(0.7f, 0.7f, 0.7f, 1f), "Parse Log");
            ImGui.SameLine(); ImGui.Checkbox("Auto-scroll##esc", ref _logScroll);
            ImGui.BeginChild("elog", new Vector2(-1, avail.Y - tableH - 60), ImGuiChildFlags.Borders);
            List<string> snap;
            lock (_logDisplay) snap = _logDisplay.ToList();
            foreach (var line in snap)
                ImGui.TextUnformatted(line);
            if (_logScroll && ImGui.GetScrollY() >= ImGui.GetScrollMaxY() - 5)
                ImGui.SetScrollHereY(1f);
            ImGui.EndChild();
        }
    }

    private static void ParseRef(string s, out float x, out float y, out float z)
    {
        x = y = z = 0;
        var parts = s.Split(',');
        if (parts.Length >= 3)
        {
            float.TryParse(parts[0].Trim(), out x);
            float.TryParse(parts[1].Trim(), out y);
            float.TryParse(parts[2].Trim(), out z);
        }
    }
}
