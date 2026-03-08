// Tabs/TeleportTab.cs  v16
// Position override, one-shot teleport, teleport-to-entity, speed multiplier.
// Uses the QUIC stream shim — position is patched inside ClientMovement (0x6C)
// before the server receives it.  No memory writes, no anticheat-visible patches.

using HyForce.Core;
using HyForce.Networking;
using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;

namespace HyForce.Tabs;

public class TeleportTab : ITab
{
    public string Name => "Teleport";

    private readonly AppState          _state;
    private readonly PipeCaptureServer _pipe;
    private readonly EntityTracker     _entities;

    // ── Coords input ────────────────────────────────────────────────────────
    private float _x, _y, _z;
    private bool  _stickyOn   = false;
    private float _speedMul   = 1f;
    private bool  _speedOn    = false;

    // ── Entity selection ────────────────────────────────────────────────────
    private string  _entityFilter = "";
    private ulong   _selectedEid  = 0;
    private float   _offsetY      = 2f; // land on top of entity, not inside it

    // ── History ring ────────────────────────────────────────────────────────
    private readonly List<(string Label, float X, float Y, float Z)> _bookmarks = new();
    private string _bookmarkName = "";

    // ── Activity log ────────────────────────────────────────────────────────
    private readonly List<string> _log = new();
    private bool _logScroll = true;

    public TeleportTab(AppState state, PipeCaptureServer pipe)
    {
        _state    = state;
        _pipe     = pipe;
        _entities = state.EntityTracker;
    }

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();

        bool connected = _pipe.DllConnected;
        ImGui.TextColored(connected ? new Vector4(0.3f,1f,0.4f,1f) : new Vector4(1f,0.4f,0.3f,1f),
            connected ? "● DLL Connected — stream shim active" : "○ DLL Not Connected");
        ImGui.SameLine(0, 20);
        ImGui.TextDisabled("All teleports are C2S 0x6C patches — server-authoritative, no memory writes.");
        ImGui.Separator();

        float leftW = 310f;

        // ── Left controls ────────────────────────────────────────────────────
        ImGui.BeginChild("tp_left", new Vector2(leftW, avail.Y - 4), ImGuiChildFlags.Borders);
        {
            // One-shot teleport
            ImGui.TextColored(new Vector4(0.4f, 0.85f, 1f, 1f), "ONE-SHOT TELEPORT");
            ImGui.TextDisabled("Injects a single ClientMovement with these coords.");
            ImGui.Spacing();
            ImGui.SetNextItemWidth(-1); ImGui.InputFloat("X##tpx", ref _x, 0.5f, 5f, "%.3f");
            ImGui.SetNextItemWidth(-1); ImGui.InputFloat("Y##tpy", ref _y, 0.5f, 5f, "%.3f");
            ImGui.SetNextItemWidth(-1); ImGui.InputFloat("Z##tpz", ref _z, 0.5f, 5f, "%.3f");
            if (ImGui.Button("Teleport Now", new Vector2(-1, 32)))
            {
                _pipe.Teleport(_x, _y, _z);
                AddLog($"[TP] One-shot → ({_x:F2}, {_y:F2}, {_z:F2})");
            }

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

            // Sticky override
            ImGui.TextColored(new Vector4(1f, 0.65f, 0.2f, 1f), "STICKY POSITION LOCK");
            ImGui.TextDisabled("Patches EVERY 0x6C until disabled.\nServer thinks you never moved.");
            ImGui.Spacing();
            var stickyCol = _stickyOn ? new Vector4(0.1f,0.5f,0.1f,1f) : new Vector4(0.25f,0.25f,0.25f,1f);
            ImGui.PushStyleColor(ImGuiCol.Button, stickyCol);
            if (ImGui.Button(_stickyOn ? "LOCK: ON  [click off]" : "LOCK: OFF [click on]", new Vector2(-1, 28)))
            {
                _stickyOn = !_stickyOn;
                if (_stickyOn) { _pipe.PosOverride(_x, _y, _z); AddLog($"[LOCK] Sticky ON @ ({_x:F2},{_y:F2},{_z:F2})"); }
                else           { _pipe.PosOverrideOff();         AddLog("[LOCK] Sticky OFF"); }
            }
            ImGui.PopStyleColor();
            if (_stickyOn)
            {
                ImGui.TextColored(new Vector4(1f,0.85f,0.2f,1f), $"  Locked: ({_x:F2}, {_y:F2}, {_z:F2})");
                if (ImGui.Button("Update Lock Position", new Vector2(-1,0)))
                { _pipe.PosOverride(_x, _y, _z); AddLog($"[LOCK] Updated → ({_x:F2},{_y:F2},{_z:F2})"); }
            }

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

            // Speed
            ImGui.TextColored(new Vector4(0.8f, 0.4f, 1f, 1f), "SPEED MULTIPLIER");
            ImGui.TextDisabled("Scales velocity vector in 0x6C before server sees it.");
            ImGui.SetNextItemWidth(-1);
            ImGui.SliderFloat("Multiplier##spm", ref _speedMul, 0.1f, 20f, "%.1fx");
            var speedCol = _speedOn ? new Vector4(0.3f,0.1f,0.5f,1f) : new Vector4(0.25f,0.25f,0.25f,1f);
            ImGui.PushStyleColor(ImGuiCol.Button, speedCol);
            if (ImGui.Button(_speedOn ? "SPEED: ON  [click off]" : "SPEED: OFF [click on]", new Vector2(-1, 28)))
            {
                _speedOn = !_speedOn;
                if (_speedOn) { _pipe.SpeedMultiplier(_speedMul); AddLog($"[SPEED] {_speedMul:F1}x enabled"); }
                else          { _pipe.SpeedMultiplierOff();       AddLog("[SPEED] Cleared"); }
            }
            ImGui.PopStyleColor();

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

            // Bookmarks
            ImGui.TextColored(new Vector4(0.7f, 0.9f, 0.5f, 1f), "BOOKMARKS");
            ImGui.SetNextItemWidth(140); ImGui.InputText("Name##bkn", ref _bookmarkName, 32); ImGui.SameLine();
            if (ImGui.Button("Save##bks"))
            {
                string label = string.IsNullOrWhiteSpace(_bookmarkName) ? $"{_x:F0},{_y:F0},{_z:F0}" : _bookmarkName;
                _bookmarks.Add((label, _x, _y, _z));
                _bookmarkName = "";
                AddLog($"[BK] Saved '{label}' @ ({_x:F2},{_y:F2},{_z:F2})");
            }
            for (int i = 0; i < _bookmarks.Count; i++)
            {
                var (lbl, bx, by, bz) = _bookmarks[i];
                ImGui.Bullet(); ImGui.SameLine();
                ImGui.TextUnformatted($"{lbl}  ({bx:F1},{by:F1},{bz:F1})");
                ImGui.SameLine();
                if (ImGui.SmallButton($"Go##bkg{i}"))
                {
                    _x = bx; _y = by; _z = bz;
                    _pipe.Teleport(_x, _y, _z);
                    AddLog($"[TP] Bookmark '{lbl}'");
                }
                ImGui.SameLine();
                if (ImGui.SmallButton($"X##bkd{i}")) { _bookmarks.RemoveAt(i); break; }
            }
        }
        ImGui.EndChild();

        ImGui.SameLine();

        // ── Right: entity list + log ─────────────────────────────────────────
        float rightW = avail.X - leftW - 8;
        ImGui.BeginChild("tp_right", new Vector2(rightW, avail.Y - 4), ImGuiChildFlags.None);
        {
            if (ImGui.BeginTabBar("tp_right_tabs"))
            {
                if (ImGui.BeginTabItem("Teleport to Entity##tte"))
                {
                    RenderEntityList(rightW, avail.Y - 50);
                    ImGui.EndTabItem();
                }
                if (ImGui.BeginTabItem("Activity Log##tpal"))
                {
                    RenderLog(rightW, avail.Y - 50);
                    ImGui.EndTabItem();
                }
                ImGui.EndTabBar();
            }
        }
        ImGui.EndChild();
    }

    private void RenderEntityList(float w, float h)
    {
        ImGui.TextDisabled("Select entity → teleport to its last known position.");
        ImGui.SetNextItemWidth(200);
        ImGui.InputText("Filter##etpf", ref _entityFilter, 64); ImGui.SameLine();
        ImGui.SetNextItemWidth(80);
        ImGui.InputFloat("Y+offset##yo", ref _offsetY, 0.5f, 0f, "%.1f");
        ImGui.SameLine();
        ImGui.TextDisabled("(land height above entity)");
        ImGui.Separator();

        ImGui.BeginChild("tp_entity_list", new Vector2(-1, h - 100), ImGuiChildFlags.None);
        if (ImGui.BeginTable("tp_etbl", 6,
            ImGuiTableFlags.Borders | ImGuiTableFlags.RowBg |
            ImGuiTableFlags.ScrollY | ImGuiTableFlags.Resizable))
        {
            ImGui.TableSetupColumn("Entity ID",  ImGuiTableColumnFlags.WidthFixed, 130);
            ImGui.TableSetupColumn("Label",      ImGuiTableColumnFlags.WidthFixed, 90);
            ImGui.TableSetupColumn("Type",       ImGuiTableColumnFlags.WidthFixed, 70);
            ImGui.TableSetupColumn("Position",   ImGuiTableColumnFlags.WidthStretch);
            ImGui.TableSetupColumn("HP",         ImGuiTableColumnFlags.WidthFixed, 80);
            ImGui.TableSetupColumn("Action",     ImGuiTableColumnFlags.WidthFixed, 75);
            ImGui.TableSetupScrollFreeze(0, 1);
            ImGui.TableHeadersRow();

            var entities = _entities.Entities.Values
                .Where(e => e.HasPosition)
                .OrderByDescending(e => e.UpdateCount)
                .ToList();

            if (!string.IsNullOrEmpty(_entityFilter))
            {
                var f = _entityFilter.ToLower();
                entities = entities.Where(e =>
                    e.EntityId.ToString("X").ToLower().Contains(f) ||
                    e.Label.ToLower().Contains(f) ||
                    e.TypeId.ToString("X").Contains(f)).ToList();
            }

            foreach (var e in entities)
            {
                ImGui.TableNextRow();
                bool p = _selectedEid == e.EntityId;

                ImGui.TableSetColumnIndex(0);
                if (ImGui.Selectable($"0x{e.EntityId:X}##tpsel{e.EntityId}", p,
                    ImGuiSelectableFlags.SpanAllColumns, new Vector2(0,0)))
                {
                    _selectedEid = p ? 0 : e.EntityId;
                    if (!p) { _x = e.X; _y = e.Y + _offsetY; _z = e.Z; }
                }

                ImGui.TableSetColumnIndex(1);
                ImGui.TextUnformatted(string.IsNullOrEmpty(e.Label) ? "-" : e.Label);

                ImGui.TableSetColumnIndex(2);
                ImGui.TextDisabled(e.HasType ? $"0x{e.TypeId:X4}" : "-");

                ImGui.TableSetColumnIndex(3);
                ImGui.TextColored(new Vector4(0.4f,0.85f,1f,1f), e.PositionStr);

                ImGui.TableSetColumnIndex(4);
                if (e.HasHealth)
                {
                    float pct = e.HP / Math.Max(1, e.MaxHP);
                    var hcol = pct > 0.5f ? new Vector4(0.2f,0.9f,0.3f,1f)
                             : pct > 0.2f ? new Vector4(1f,0.85f,0.1f,1f)
                             :              new Vector4(1f,0.2f,0.2f,1f);
                    ImGui.TextColored(hcol, e.HealthStr);
                }
                else ImGui.TextDisabled("-");

                ImGui.TableSetColumnIndex(4);
                if (ImGui.SmallButton($"Go##tpgo{e.EntityId}"))
                {
                    float tx = e.X, ty = e.Y + _offsetY, tz = e.Z;
                    _x = tx; _y = ty; _z = tz;
                    _pipe.Teleport(tx, ty, tz);
                    AddLog($"[TP→ENTITY] 0x{e.EntityId:X}  @ ({tx:F2},{ty:F2},{tz:F2})");
                }
            }
            ImGui.EndTable();
        }
        ImGui.EndChild();

        // Selected entity summary
        if (_selectedEid != 0 && _entities.Entities.TryGetValue(_selectedEid, out var sel))
        {
            ImGui.Separator();
            ImGui.Text($"Selected: 0x{sel.EntityId:X}  Pos: {sel.PositionStr}  HP: {sel.HealthStr}");
            ImGui.SameLine();
            if (ImGui.Button("Teleport to Selected"))
            {
                _x = sel.X; _y = sel.Y + _offsetY; _z = sel.Z;
                _pipe.Teleport(_x, _y, _z);
                AddLog($"[TP→ENTITY] Teleported to 0x{sel.EntityId:X}  ({_x:F2},{_y:F2},{_z:F2})");
            }
            ImGui.SameLine();
            if (ImGui.Button("Lock Here"))
            {
                _x = sel.X; _y = sel.Y + _offsetY; _z = sel.Z;
                _stickyOn = true;
                _pipe.PosOverride(_x, _y, _z);
                AddLog($"[LOCK] Locked to entity 0x{sel.EntityId:X}");
            }
        }
    }

    private void RenderLog(float w, float h)
    {
        ImGui.Checkbox("Auto-scroll##tplsc", ref _logScroll);
        ImGui.SameLine();
        if (ImGui.Button("Clear##tplcl")) lock (_log) _log.Clear();
        ImGui.Separator();
        ImGui.BeginChild("tp_log", new Vector2(-1, h - 60), ImGuiChildFlags.Borders);
        List<string> snap; lock (_log) snap = _log.ToList();
        foreach (var line in snap)
        {
            Vector4 col = line.Contains("[TP]")    ? new Vector4(0.4f,0.85f,1f,1f)
                        : line.Contains("[LOCK]")  ? new Vector4(1f,0.75f,0.2f,1f)
                        : line.Contains("[SPEED]") ? new Vector4(0.8f,0.4f,1f,1f)
                        : line.Contains("[BK]")    ? new Vector4(0.6f,0.9f,0.4f,1f)
                        :                            new Vector4(0.8f,0.8f,0.8f,1f);
            ImGui.TextColored(col, line);
        }
        if (_logScroll && ImGui.GetScrollY() >= ImGui.GetScrollMaxY() - 5)
            ImGui.SetScrollHereY(1f);
        ImGui.EndChild();
    }

    private void AddLog(string msg)
    {
        var line = $"[{DateTime.Now:HH:mm:ss.fff}] {msg}";
        lock (_log) { _log.Add(line); if (_log.Count > 500) _log.RemoveAt(0); }
    }
}
