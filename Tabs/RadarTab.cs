// Tabs/RadarTab.cs  v18
// 2D top-down radar canvas using ImGui DrawList.
// Data source: EntityTracker + PlayerTracker (no memory reads).
// Features: zoom, pan, entity type filter, distance rings, labels.

using HyForce.Core;
using HyForce.Networking;
using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;

namespace HyForce.Tabs;

public class RadarTab : ITab
{
    public string Name => "Radar";

    private readonly AppState       _state;
    private readonly EntityTracker  _entities;
    private readonly PlayerTracker  _players;

    // Canvas state
    private float   _zoom       = 1.0f;   // world units per pixel
    private float   _range      = 200f;   // world units visible radius
    private bool    _showPlayers  = true;
    private bool    _showEntities = true;
    private bool    _showChunks   = false;
    private bool    _showLabels   = true;
    private bool    _showRings    = true;
    private bool    _lockOnSelf   = true;
    private Vector2 _panOffset    = Vector2.Zero;
    private bool    _isPanning    = false;
    private Vector2 _panStart     = Vector2.Zero;

    private ulong   _hoveredEid   = 0;

    // Colors
    private static readonly Vector4 ColSelf    = new(0.3f, 1f, 0.4f, 1f);
    private static readonly Vector4 ColPlayer  = new(0.4f, 0.7f, 1f, 1f);
    private static readonly Vector4 ColEntity  = new(1f, 0.5f, 0.3f, 1f);
    private static readonly Vector4 ColChunk   = new(0.3f, 0.3f, 0.4f, 0.5f);
    private static readonly Vector4 ColRing    = new(0.3f, 0.3f, 0.3f, 0.7f);

    public RadarTab(AppState state, PipeCaptureServer pipe)
    {
        _state    = state;
        _entities = state.EntityTracker;
        _players  = state.PlayerTracker;
    }

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();
        float sideW = 220f;
        float canvasW = avail.X - sideW - 8;
        float canvasH = avail.Y - 4;

        // ── Controls sidebar ──────────────────────────────────────────────
        ImGui.BeginChild("radar_side", new Vector2(sideW, canvasH), ImGuiChildFlags.Borders);
        {
            ImGui.TextColored(new Vector4(0.4f, 1f, 0.6f, 1f), "RADAR");
            ImGui.Separator();

            ImGui.TextDisabled($"Entities: {_entities.EntityCount}");
            ImGui.TextDisabled($"Players:  {_players.Players.Count}");
            ImGui.TextDisabled($"Self:     {(_players.SelfEntityId != 0 ? $"0x{_players.SelfEntityId:X}" : "?")}");
            ImGui.TextDisabled($"Self pos: ({_players.SelfX:F0},{_players.SelfY:F0},{_players.SelfZ:F0})");

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

            ImGui.Text("View range:");
            ImGui.SetNextItemWidth(-1);
            ImGui.SliderFloat("##range", ref _range, 20f, 2000f, "%.0f units");
            ImGui.Checkbox("Lock on self", ref _lockOnSelf);
            ImGui.Checkbox("Show players",  ref _showPlayers);
            ImGui.Checkbox("Show entities", ref _showEntities);
            ImGui.Checkbox("Show chunks",   ref _showChunks);
            ImGui.Checkbox("Show labels",   ref _showLabels);
            ImGui.Checkbox("Distance rings",ref _showRings);

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

            // Legend
            ImGui.TextColored(ColSelf,   "● Self");
            ImGui.TextColored(ColPlayer, "● Player");
            ImGui.TextColored(ColEntity, "● Entity");

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

            // Hovered entity info
            if (_hoveredEid != 0 && _entities.Entities.TryGetValue(_hoveredEid, out var hov))
            {
                ImGui.TextColored(new Vector4(1f, 0.9f, 0.3f, 1f), "Hovered:");
                ImGui.TextDisabled($"0x{hov.EntityId:X}");
                ImGui.TextDisabled(hov.PositionStr);
                if (hov.HasHealth) ImGui.TextDisabled($"HP: {hov.HealthStr}");
            }

            ImGui.Spacing();
            if (ImGui.SmallButton("Reset Pan")) _panOffset = Vector2.Zero;
            ImGui.SameLine();
            if (ImGui.SmallButton("Fit World"))
            {
                // Fit all entities in view
                var allE = _entities.Entities.Values.Where(e => e.HasPosition).ToList();
                if (allE.Count > 0)
                {
                    float minX = allE.Min(e => e.X), maxX = allE.Max(e => e.X);
                    float minZ = allE.Min(e => e.Z), maxZ = allE.Max(e => e.Z);
                    _range = Math.Max(maxX - minX, maxZ - minZ) / 2f * 1.2f;
                    _panOffset = Vector2.Zero;
                }
            }
        }
        ImGui.EndChild();

        ImGui.SameLine();

        // ── Canvas ────────────────────────────────────────────────────────
        ImGui.BeginChild("radar_canvas", new Vector2(canvasW, canvasH), ImGuiChildFlags.None,
            ImGuiWindowFlags.NoScrollbar | ImGuiWindowFlags.NoScrollWithMouse);

        var dl   = ImGui.GetWindowDrawList();
        var cpos = ImGui.GetCursorScreenPos();
        var csize = new Vector2(canvasW - 4, canvasH - 4);

        // Background
        dl.AddRectFilled(cpos, cpos + csize, ImGui.ColorConvertFloat4ToU32(new Vector4(0.05f, 0.05f, 0.08f, 1f)));
        dl.AddRect(cpos, cpos + csize, ImGui.ColorConvertFloat4ToU32(new Vector4(0.2f, 0.2f, 0.3f, 1f)));

        Vector2 center = cpos + csize / 2;
        if (!_lockOnSelf) center += _panOffset;

        // World center is self position
        float selfX = _players.SelfX, selfZ = _players.SelfZ;
        float scale = (csize.X / 2) / _range;

        // ── Distance rings ────────────────────────────────────────────────
        if (_showRings)
        {
            uint ringCol = ImGui.ColorConvertFloat4ToU32(ColRing);
            for (float r = _range / 4; r <= _range; r += _range / 4)
            {
                float pxR = r * scale;
                dl.AddCircle(center, pxR, ringCol, 64, 1f);
                dl.AddText(center + new Vector2(pxR + 2, -8),
                    ImGui.ColorConvertFloat4ToU32(new Vector4(0.4f,0.4f,0.4f,0.7f)),
                    $"{r:F0}u");
            }
        }

        // North indicator
        dl.AddLine(center, center + new Vector2(0, -30),
            ImGui.ColorConvertFloat4ToU32(new Vector4(0.9f, 0.3f, 0.3f, 0.8f)), 2f);
        dl.AddText(center + new Vector2(-4, -44),
            ImGui.ColorConvertFloat4ToU32(new Vector4(0.9f,0.3f,0.3f,1f)), "N");

        // ── Chunks ────────────────────────────────────────────────────────
        if (_showChunks)
        {
            uint chunkCol = ImGui.ColorConvertFloat4ToU32(ColChunk);
            const int ChunkSize = 16;
            foreach (var ci in _state.ChunkAccumulator.Chunks.Values)
            {
                float wx = ci.ChunkX * ChunkSize - selfX;
                float wz = ci.ChunkZ * ChunkSize - selfZ;
                var p1 = center + new Vector2(wx * scale, wz * scale);
                var p2 = p1 + new Vector2(ChunkSize * scale, ChunkSize * scale);
                if (p1.X > cpos.X && p1.X < cpos.X + csize.X &&
                    p1.Y > cpos.Y && p1.Y < cpos.Y + csize.Y)
                    dl.AddRect(p1, p2, chunkCol);
            }
        }

        // ── Entities ──────────────────────────────────────────────────────
        _hoveredEid = 0;
        var mousePos = ImGui.GetMousePos();
        float closestDist = 12f;

        if (_showEntities)
        {
            foreach (var e in _entities.Entities.Values.Where(e => e.HasPosition))
            {
                bool isPlayer = _players.Players.ContainsKey(e.EntityId);
                if (isPlayer && !_showPlayers) continue;

                float wx = e.X - selfX, wz = e.Z - selfZ;
                if (Math.Abs(wx) > _range || Math.Abs(wz) > _range) continue;
                var dot = center + new Vector2(wx * scale, wz * scale);

                // Clamp to canvas
                if (dot.X < cpos.X || dot.X > cpos.X + csize.X ||
                    dot.Y < cpos.Y || dot.Y > cpos.Y + csize.Y) continue;

                bool isSelf = e.EntityId == _players.SelfEntityId;
                Vector4 col = isSelf ? ColSelf : isPlayer ? ColPlayer : ColEntity;
                uint colU = ImGui.ColorConvertFloat4ToU32(col);

                float dotSize = isSelf ? 6f : isPlayer ? 5f : 3.5f;
                dl.AddCircleFilled(dot, dotSize, colU);

                // HP ring
                if (e.HasHealth && e.MaxHP > 0)
                {
                    float pct = e.HP / e.MaxHP;
                    Vector4 hpCol = pct > 0.5f ? new Vector4(0.2f, 0.9f, 0.3f, 0.7f)
                        : pct > 0.2f ? new Vector4(1f, 0.85f, 0.1f, 0.7f)
                        : new Vector4(1f, 0.2f, 0.2f, 0.7f);
                    uint hpColor = ImGui.ColorConvertFloat4ToU32(hpCol);
                    float startAngle = -MathF.PI / 2;
                    float endAngle = -MathF.PI / 2 + pct * 2 * MathF.PI;
                    int segments = 24;
                    float radius = dotSize + 2;
                    for (int i = 0; i < segments; i++)
                    {
                        float a1 = startAngle + (endAngle - startAngle) * (i / (float)segments);
                        float a2 = startAngle + (endAngle - startAngle) * ((i + 1) / (float)segments);
                        Vector2 p1 = dot + new Vector2(MathF.Cos(a1), MathF.Sin(a1)) * radius;
                        Vector2 p2 = dot + new Vector2(MathF.Cos(a2), MathF.Sin(a2)) * radius;
                        dl.AddLine(p1, p2, hpColor, 1.5f);
                    }
                }

                // Labels
                if (_showLabels && (isPlayer || isSelf))
                {
                    string lbl = isSelf ? "YOU" : (string.IsNullOrEmpty(e.Label) ? $"0x{e.EntityId:X8}" : e.Label);
                    dl.AddText(dot + new Vector2(7, -7), colU, lbl);
                }

                // Hover detection
                float d = Vector2.Distance(mousePos, dot);
                if (d < closestDist) { closestDist = d; _hoveredEid = e.EntityId; }
            }
        }

        // Self crosshair
        uint selfCol = ImGui.ColorConvertFloat4ToU32(ColSelf);
        dl.AddLine(center + new Vector2(-8, 0), center + new Vector2(8, 0), selfCol, 1.5f);
        dl.AddLine(center + new Vector2(0, -8), center + new Vector2(0, 8), selfCol, 1.5f);

        // ── Mouse interaction ─────────────────────────────────────────────
        ImGui.InvisibleButton("radar_hit", csize);
        if (ImGui.IsItemActive() && ImGui.IsMouseDragging(ImGuiMouseButton.Left) && !_lockOnSelf)
        {
            _panOffset += ImGui.GetIO().MouseDelta;
        }
        // Scroll to zoom
        if (ImGui.IsItemHovered())
        {
            float wheel = ImGui.GetIO().MouseWheel;
            if (wheel != 0) _range = Math.Clamp(_range * (wheel > 0 ? 0.85f : 1.15f), 10f, 5000f);
        }

        ImGui.EndChild();
    }
}
