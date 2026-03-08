// Tabs/ChunkMapTab.cs  v19
using HyForce.Core;
using HyForce.Networking;
using ImGuiNET;
using System;
using System.Linq;
using System.Numerics;

namespace HyForce.Tabs;

public class ChunkMapTab : ITab
{
    public string Name => "Chunk Map";

    private readonly AppState          _state;
    private readonly ChunkAccumulator  _chunks;

    private float  _zoom    = 4f;  // pixels per chunk
    private Vector2 _pan    = Vector2.Zero;
    private bool   _showEnts= true;
    private bool   _showSelf= true;
    private bool   _colorElev = true;
    private string _gotoX  = "0", _gotoZ = "0";

    public ChunkMapTab(AppState state, PipeCaptureServer pipe)
    {
        _state  = state;
        _chunks = state.ChunkAccumulator;
    }

    public void Render()
    {
        var avail   = ImGui.GetContentRegionAvail();
        float sideW = 200f;
        float canW  = avail.X - sideW - 8;
        float canH  = avail.Y - 4;

        // Sidebar
        ImGui.BeginChild("cm_side", new Vector2(sideW, canH), ImGuiChildFlags.Borders);
        {
            ImGui.TextColored(new Vector4(0.4f,0.9f,1f,1f), "CHUNK MAP");
            ImGui.TextDisabled($"Chunks loaded: {_chunks.ChunkCount}");
            ImGui.TextDisabled($"Errors: {_chunks.ParseErrors}");
            ImGui.TextDisabled($"X: [{_chunks.MinX}, {_chunks.MaxX}]");
            ImGui.TextDisabled($"Z: [{_chunks.MinZ}, {_chunks.MaxZ}]");
            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

            ImGui.Text("Zoom (px/chunk):"); ImGui.SetNextItemWidth(-1);
            ImGui.SliderFloat("##cmzoom", ref _zoom, 1f, 32f, "%.0f");
            ImGui.Checkbox("Show entities", ref _showEnts);
            ImGui.Checkbox("Show self",     ref _showSelf);
            ImGui.Checkbox("Color by height",ref _colorElev);

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();
            ImGui.Text("Go to:");
            ImGui.SetNextItemWidth(70); ImGui.InputText("X##cmgx",ref _gotoX,16); ImGui.SameLine();
            ImGui.SetNextItemWidth(70); ImGui.InputText("Z##cmgz",ref _gotoZ,16);
            if (ImGui.SmallButton("Jump##cmjump"))
            {
                if (int.TryParse(_gotoX,out int gx) && int.TryParse(_gotoZ,out int gz))
                    _pan = new Vector2(-gx * _zoom, -gz * _zoom);
            }

            ImGui.Spacing(); ImGui.Separator();
            if (ImGui.SmallButton("Reset View##cmrv")) _pan = Vector2.Zero;
            if (ImGui.SmallButton("Fit All##cmfit"))
            {
                if (_chunks.ChunkCount > 0)
                {
                    float midX = (_chunks.MinX + _chunks.MaxX) / 2f;
                    float midZ = (_chunks.MinZ + _chunks.MaxZ) / 2f;
                    _pan = new Vector2(-midX * _zoom, -midZ * _zoom);
                }
            }
            if (ImGui.SmallButton("Clear Chunks##cmcl")) _chunks.Clear();
        }
        ImGui.EndChild();

        ImGui.SameLine();

        ImGui.BeginChild("cm_canvas", new Vector2(canW, canH), ImGuiChildFlags.None,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        var dl   = ImGui.GetWindowDrawList();
        var cpos = ImGui.GetCursorScreenPos();
        var csize= new Vector2(canW-4, canH-4);

        // Background
        dl.AddRectFilled(cpos, cpos+csize, 0xFF0A0A10);
        dl.AddRect(cpos, cpos+csize, 0xFF303040);

        Vector2 origin = cpos + csize/2 + _pan;

        // Chunks
        foreach (var ci in _chunks.Chunks.Values)
        {
            var tl = origin + new Vector2(ci.ChunkX * _zoom, ci.ChunkZ * _zoom);
            var br = tl + new Vector2(_zoom, _zoom);
            if (br.X < cpos.X || tl.X > cpos.X+csize.X ||
                br.Y < cpos.Y || tl.Y > cpos.Y+csize.Y) continue;

            uint fill;
            if (_colorElev)
            {
                // Heat-map by surface height: blue=low, green=mid, white=high
                float t = Math.Clamp(ci.SurfaceY / 256f, 0f, 1f);
                byte r = (byte)(t * 220);
                byte g = (byte)(Math.Min(t * 2, 1f) * 180);
                byte b = (byte)((1f - t) * 200 + 30);
                fill = (uint)(0xFF000000 | ((uint)r<<16) | ((uint)g<<8) | b);
            }
            else
                fill = 0xFF2A3A2A;

            dl.AddRectFilled(tl, br, fill);
            if (_zoom > 6)
                dl.AddRect(tl, br, 0x40FFFFFF, 0f, ImDrawFlags.None, 0.5f);
        }

        // Entities
        if (_showEnts)
        {
            const int CS = 16;
            foreach (var e in _state.EntityTracker.Entities.Values.Where(e => e.HasPosition).Take(500))
            {
                float cx = e.X / CS, cz = e.Z / CS;
                var dot = origin + new Vector2(cx * _zoom, cz * _zoom);
                if (dot.X < cpos.X || dot.X > cpos.X+csize.X ||
                    dot.Y < cpos.Y || dot.Y > cpos.Y+csize.Y) continue;
                bool isPlayer = _state.PlayerTracker.Players.ContainsKey(e.EntityId);
                uint col = isPlayer ? 0xFF88DDFF : 0xFFFF7755;
                dl.AddCircleFilled(dot, isPlayer ? 3f : 2f, col);
            }
        }

        // Self
        if (_showSelf && _state.PlayerTracker.SelfEntityId != 0)
        {
            const int CS = 16;
            float sx = _state.PlayerTracker.SelfX / CS;
            float sz = _state.PlayerTracker.SelfZ / CS;
            var sdot = origin + new Vector2(sx*_zoom, sz*_zoom);
            dl.AddCircleFilled(sdot, 5f, 0xFF44FF66);
            dl.AddCircle(sdot, 7f, 0xFF88FFAA, 12, 1.5f);
            dl.AddText(sdot + new Vector2(8,-7), 0xFF88FFAA, "YOU");
        }

        // Scroll-to-zoom + pan
        ImGui.InvisibleButton("cm_hit", csize);
        if (ImGui.IsItemActive() && ImGui.IsMouseDragging(ImGuiMouseButton.Left))
            _pan += ImGui.GetIO().MouseDelta;
        if (ImGui.IsItemHovered())
        {
            float wheel = ImGui.GetIO().MouseWheel;
            if (wheel != 0) _zoom = Math.Clamp(_zoom * (wheel > 0 ? 1.15f : 0.87f), 1f, 64f);
        }

        // Coordinate tooltip
        if (ImGui.IsItemHovered())
        {
            const int CS = 16;
            var mp = ImGui.GetMousePos();
            float wx = ((mp.X - origin.X) / _zoom) * CS;
            float wz = ((mp.Y - origin.Y) / _zoom) * CS;
            ImGui.SetTooltip($"World ({wx:F0}, {wz:F0})  Chunk ({(int)(wx/CS)}, {(int)(wz/CS)})");
        }

        ImGui.EndChild();
    }
}
