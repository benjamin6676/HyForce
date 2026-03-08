// Tabs/WaypointTab.cs  v20
using HyForce.Core;
using HyForce.Networking;
using ImGuiNET;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;

namespace HyForce.Tabs;

public class WaypointTab : ITab
{
    public string Name => "Waypoints";

    private readonly AppState          _state;
    private readonly PipeCaptureServer _pipe;
    private readonly WaypointSystem    _wp;

    private string _bmName = "", _bmNotes = "";
    private float  _bmX, _bmY, _bmZ;
    private int    _selBm = -1, _selRoute = -1, _selRoutePoint = -1;

    private string _routeName = "Route 1";
    private int    _routeDelay = 1000;
    private bool   _routeLoop = false;

    private string _savePath = "", _loadPath = "";
    private bool   _logScroll = true;
    private int i;
    private readonly List<string> _log = new();



    public WaypointTab(AppState state, PipeCaptureServer pipe)
    {
        _state = state; _pipe = pipe; _wp = state.WaypointSystem;
        _wp.OnLog += line => { lock(_log) { _log.Add(line); if(_log.Count>500) _log.RemoveAt(0); } };
    }

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();
        float leftW = 300f;

        if (_wp.IsRunning)
            ImGui.TextColored(new Vector4(0.3f,1f,0.4f,1f),
                $"● RUNNING '{_wp.RunningRoute}'  point {_wp.CurrentPoint}");
        else
            ImGui.TextDisabled($"■ IDLE   {_wp.Bookmarks.Count} bookmarks  {_wp.Routes.Count} routes");
        ImGui.Separator();

        ImGui.BeginChild("wp_left", new Vector2(leftW, avail.Y-4), ImGuiChildFlags.Borders);
        {
            if (ImGui.BeginTabBar("wp_left_tabs"))
            {
                if (ImGui.BeginTabItem("Bookmarks##wpbm")) { RenderBookmarks(avail.Y-50); ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Routes##wpr"))     { RenderRoutes(avail.Y-50);    ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Save/Load##wpsl")) { RenderSaveLoad();            ImGui.EndTabItem(); }
                ImGui.EndTabBar();
            }
        }
        ImGui.EndChild();

        ImGui.SameLine();

        float rightW = avail.X - leftW - 8;
        ImGui.BeginChild("wp_right", new Vector2(rightW, avail.Y-4), ImGuiChildFlags.None);
        {
            if (ImGui.BeginTabBar("wp_right_tabs"))
            {
                if (ImGui.BeginTabItem("Route Editor##wpre")) { RenderRouteEditor(avail.Y-50); ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Log##wpl"))            { RenderLog(avail.Y-50);         ImGui.EndTabItem(); }
                ImGui.EndTabBar();
            }
        }
        ImGui.EndChild();
    }

    private void RenderBookmarks(float h)
    {
        ImGui.TextColored(new Vector4(0.4f,0.85f,1f,1f), "ADD BOOKMARK");
        ImGui.SetNextItemWidth(-1); ImGui.InputText("Name##wpbmn", ref _bmName, 64);
        ImGui.SetNextItemWidth(75); ImGui.InputFloat("X##wpbmx",ref _bmX,1f,.1f); ImGui.SameLine();
        ImGui.SetNextItemWidth(75); ImGui.InputFloat("Y##wpbmy",ref _bmY,1f,.1f); ImGui.SameLine();
        ImGui.SetNextItemWidth(75); ImGui.InputFloat("Z##wpbmz",ref _bmZ,1f,.1f);

        // Copy self position
        if (ImGui.SmallButton("Self Pos##wpbmsp"))
        { _bmX=_state.PlayerTracker.SelfX; _bmY=_state.PlayerTracker.SelfY; _bmZ=_state.PlayerTracker.SelfZ; }

        if (ImGui.Button("Add Bookmark##wpbmadd", new Vector2(-1,0)) && !string.IsNullOrWhiteSpace(_bmName))
        {
            _wp.AddBookmark(_bmName, _bmX, _bmY, _bmZ, _bmNotes);
            _bmName = "";
        }

        ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();
        ImGui.TextDisabled($"{_wp.Bookmarks.Count} bookmarks:");

        ImGui.BeginChild("wp_bmlist", new Vector2(-1, h-180), ImGuiChildFlags.Borders);
        {
            var b = _wp.Bookmarks[i];
            bool sel = _selBm == i;
            if (ImGui.Selectable($"{b.Name}  ({b.X:F0},{b.Y:F0},{b.Z:F0})##wpbml{i}", sel))
                _selBm = sel ? -1 : i;
            if (ImGui.IsItemHovered() && ImGui.IsMouseDoubleClicked(0))
            { _wp.TeleportToBookmark(b.Name); _pipe.Teleport(b.X,b.Y,b.Z); }
        }
        ImGui.EndChild();

        if (_selBm >= 0 && _selBm < _wp.Bookmarks.Count)
        {
            var b = _wp.Bookmarks[_selBm];
            if (ImGui.SmallButton("Teleport##wpbmtp")) { _pipe.Teleport(b.X,b.Y,b.Z); }
            ImGui.SameLine();
            if (ImGui.SmallButton("Delete##wpbmdel"))  { _wp.DeleteBookmark(b.Name); _selBm=-1; }
            ImGui.SameLine();
            if (ImGui.SmallButton("Add to Route##wpbmar") && _selRoute >= 0 && _selRoute < _wp.Routes.Count)
            {
                _wp.Routes[_selRoute].Points.Add(new Waypoint{Name=b.Name,X=b.X,Y=b.Y,Z=b.Z});
                AddLog($"[WP] Added '{b.Name}' to route '{_wp.Routes[_selRoute].Name}'");
            }
        }
    }

    private void RenderRoutes(float h)
    {
        ImGui.TextColored(new Vector4(0.3f,1f,0.5f,1f), "ROUTES");
        ImGui.SetNextItemWidth(-1); ImGui.InputText("New route name##wprn", ref _routeName, 64);
        if (ImGui.Button("Create Route##wprcreat", new Vector2(-1,0)) && !string.IsNullOrWhiteSpace(_routeName))
        {
            _wp.CreateRoute(_routeName);
            AddLog($"[WP] Created route '{_routeName}'");
        }
        ImGui.Spacing();
        ImGui.BeginChild("wp_rlist", new Vector2(-1, h/2), ImGuiChildFlags.Borders);
        for (int i=0; i<_wp.Routes.Count; i++)
        {
            var r = _wp.Routes[i];
            bool sel = _selRoute == i;
            if (ImGui.Selectable($"{r.Name}  [{r.Points.Count} pts]##wprrl{i}", sel))
                _selRoute = sel ? -1 : i;
        }
        ImGui.EndChild();

        if (_selRoute >= 0 && _selRoute < _wp.Routes.Count)
        {
            var r = _wp.Routes[_selRoute];
            int delayMs = r.DelayMs;
            bool loop = r.Loop;
            ImGui.SetNextItemWidth(80);
            if (ImGui.InputInt("Delay ms##wpprdl", ref delayMs, 100))
                r.DelayMs = delayMs;
            ImGui.SameLine();
            if (ImGui.Checkbox("Loop##wprlp", ref loop))
                r.Loop = loop;

            if (!_wp.IsRunning)
            {
                if (ImGui.Button("Run Route##wprrun", new Vector2(-1,28))) _wp.StartRoute(r);
            }
            else
            {
                ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.5f,0.1f,0.1f,1f));
                if (ImGui.Button("Stop Route##wprstop", new Vector2(-1,28))) _wp.StopRoute();
                ImGui.PopStyleColor();
            }
            if (ImGui.SmallButton("Delete Route##wprrdel")) { _wp.DeleteRoute(r.Name); _selRoute=-1; }
        }
    }

    private void RenderSaveLoad()
    {
        ImGui.TextColored(new Vector4(1f,0.75f,0.3f,1f), "SAVE / LOAD");
        ImGui.SetNextItemWidth(-1); ImGui.InputText("Save path##wpslsp", ref _savePath, 256);
        if (ImGui.Button("Save JSON##wpslsv", new Vector2(-1,0)) && !string.IsNullOrEmpty(_savePath))
            try { _wp.SaveToJson(_savePath); } catch(Exception ex) { AddLog($"[ERR] {ex.Message}"); }

        ImGui.Spacing();
        ImGui.SetNextItemWidth(-1); ImGui.InputText("Load path##wpsllp", ref _loadPath, 256);
        if (ImGui.Button("Load JSON##wpslld", new Vector2(-1,0)) && File.Exists(_loadPath))
            try { _wp.LoadFromJson(_loadPath); } catch(Exception ex) { AddLog($"[ERR] {ex.Message}"); }

        ImGui.Spacing(); ImGui.Separator();
        if (ImGui.SmallButton("Clear All##wpslcl")) _wp.Clear();
    }

    private void RenderRouteEditor(float h)
    {
        if (_selRoute < 0 || _selRoute >= _wp.Routes.Count)
        { ImGui.TextDisabled("Select a route on the left."); return; }

        var r = _wp.Routes[_selRoute];
        ImGui.TextColored(new Vector4(0.4f,0.85f,1f,1f), $"Route: {r.Name}  {r.Points.Count} points");
        ImGui.Separator();

        ImGui.BeginChild("wp_rped", new Vector2(-1, h-80), ImGuiChildFlags.None);
        if (ImGui.BeginTable("wprptbl", 5, ImGuiTableFlags.Borders|ImGuiTableFlags.RowBg|ImGuiTableFlags.ScrollY))
        {
            ImGui.TableSetupColumn("#",    ImGuiTableColumnFlags.WidthFixed, 30);
            ImGui.TableSetupColumn("Name", ImGuiTableColumnFlags.WidthStretch);
            ImGui.TableSetupColumn("X",    ImGuiTableColumnFlags.WidthFixed, 70);
            ImGui.TableSetupColumn("Z",    ImGuiTableColumnFlags.WidthFixed, 70);
            ImGui.TableSetupColumn("Act",  ImGuiTableColumnFlags.WidthFixed, 80);
            ImGui.TableSetupScrollFreeze(0,1); ImGui.TableHeadersRow();

            for (int i=0; i<r.Points.Count; i++)
            {
                var p = r.Points[i];
                ImGui.TableNextRow();
                bool sel = _selRoutePoint == i;
                ImGui.TableSetColumnIndex(0);
                if (ImGui.Selectable($"{i+1}##wprps{i}", sel, ImGuiSelectableFlags.SpanAllColumns))
                    _selRoutePoint = sel ? -1 : i;
                ImGui.TableSetColumnIndex(1); ImGui.TextUnformatted(p.Name);
                ImGui.TableSetColumnIndex(2); ImGui.TextDisabled($"{p.X:F0}");
                ImGui.TableSetColumnIndex(3); ImGui.TextDisabled($"{p.Z:F0}");
                ImGui.TableSetColumnIndex(4);
                if (ImGui.SmallButton($"TP##wpptp{i}")) _pipe.Teleport(p.X,p.Y,p.Z);
                ImGui.SameLine();
                if (ImGui.SmallButton($"X##wppdel{i}")) { r.Points.RemoveAt(i); _selRoutePoint=-1; break; }
            }
            ImGui.EndTable();
        }
        ImGui.EndChild();
    }

    private void RenderLog(float h)
    {
        ImGui.Checkbox("Auto-scroll##wplsc", ref _logScroll);
        ImGui.SameLine(); if (ImGui.SmallButton("Clear##wplcl")) lock(_log) _log.Clear();
        ImGui.Separator();
        ImGui.BeginChild("wp_log_ch", new Vector2(-1, h-60), ImGuiChildFlags.Borders);
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
