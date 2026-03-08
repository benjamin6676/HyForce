// Tabs/BlockForgeTab.cs  v18
// Forge PlaceBlock (0x80) and BreakBlock (0x81) C2S packets.
// Supports: single block, paint line, fill region, entity-relative placement.

using HyForce.Core;
using HyForce.Networking;
using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;

namespace HyForce.Tabs;

public class BlockForgeTab : ITab
{
    public string Name => "Block Forge";

    private readonly AppState          _state;
    private readonly PipeCaptureServer _pipe;

    // Single block
    private int    _x, _y, _z;
    private string _typeIdHex  = "00000001";
    private string _typeName   = "";
    private int    _face       = 0;
    private string _searchQ    = "";
    private static readonly string[] FaceNames = { "Bottom", "Top", "North", "South", "West", "East" };

    // Fill region
    private int    _x1, _y1, _z1, _x2, _y2, _z2;
    private string _fillTypeHex = "00000001";
    private int    _fillDelayMs = 100;
    private bool   _fillRunning = false;
    private System.Threading.CancellationTokenSource? _fillCts;

    // Entity-relative
    private ulong  _relEntityId  = 0;
    private string _relEntityHex = "";
    private int    _relOffX, _relOffY = 1, _relOffZ;

    // Log
    private readonly List<string> _log = new();
    private bool _logScroll = true;
    private int _totalSent = 0;

    public BlockForgeTab(AppState state, PipeCaptureServer pipe)
    {
        _state = state;
        _pipe  = pipe;
    }

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();
        float leftW = 320f;

        ImGui.TextColored(new Vector4(0.5f, 0.85f, 1f, 1f),
            $"Total blocks forged: {_totalSent}");
        ImGui.SameLine(0, 20);
        ImGui.TextDisabled("Forge C2S 0x80 PlaceBlock / 0x81 BreakBlock");
        ImGui.Separator();

        ImGui.BeginChild("bf_left", new Vector2(leftW, avail.Y - 4), ImGuiChildFlags.Borders);
        {
            if (ImGui.BeginTabBar("bf_tabs"))
            {
                if (ImGui.BeginTabItem("Single##bfs"))    { RenderSingle();    ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Fill Region##bff")){ RenderFill();    ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Entity Rel##bfe")) { RenderEntityRel(); ImGui.EndTabItem(); }
                ImGui.EndTabBar();
            }
        }
        ImGui.EndChild();

        ImGui.SameLine();

        float rightW = avail.X - leftW - 8;
        ImGui.BeginChild("bf_right", new Vector2(rightW, avail.Y - 4), ImGuiChildFlags.None);
        {
            if (ImGui.BeginTabBar("bf_right_tabs"))
            {
                if (ImGui.BeginTabItem("Registry##bfreg")) { RenderRegistry(avail.Y - 50); ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Log##bflog"))      { RenderLog(avail.Y - 50);      ImGui.EndTabItem(); }
                ImGui.EndTabBar();
            }
        }
        ImGui.EndChild();
    }

    private void RenderSingle()
    {
        ImGui.TextColored(new Vector4(0.5f, 0.85f, 1f, 1f), "SINGLE BLOCK");
        ImGui.Spacing();

        ImGui.SetNextItemWidth(-1); ImGui.InputInt("X##bsx", ref _x, 1);
        ImGui.SetNextItemWidth(-1); ImGui.InputInt("Y##bsy", ref _y, 1);
        ImGui.SetNextItemWidth(-1); ImGui.InputInt("Z##bsz", ref _z, 1);

        // Use self position
        if (ImGui.SmallButton("Self XZ")) { _x = (int)_state.PlayerTracker.SelfX; _z = (int)_state.PlayerTracker.SelfZ; }
        ImGui.SameLine();
        if (ImGui.SmallButton("+1Y")) _y++;  ImGui.SameLine();
        if (ImGui.SmallButton("-1Y")) _y--;

        ImGui.Spacing();
        ImGui.SetNextItemWidth(-1); ImGui.InputText("Block TypeID (hex)##bstid", ref _typeIdHex, 16);
        if (!string.IsNullOrEmpty(_typeName)) ImGui.TextColored(new Vector4(0.5f,1f,0.5f,1f), $"  {_typeName}");

        ImGui.SetNextItemWidth(-1);
        ImGui.Combo("Face##bsface", ref _face, FaceNames, FaceNames.Length);
        ImGui.Spacing();

        if (ImGui.Button("Place Block##bspb", new Vector2(-1, 28)))
        {
            if (uint.TryParse(_typeIdHex, System.Globalization.NumberStyles.HexNumber, null, out uint tid))
            {
                _pipe.BlockPlace(_x, _y, _z, tid, (uint)_face);
                _totalSent++;
                AddLog($"[PLACE] ({_x},{_y},{_z}) type=0x{tid:X} face={FaceNames[_face]}");
            }
        }
        if (ImGui.Button("Break Block##bsbb", new Vector2(-1, 28)))
        {
            _pipe.BlockBreak(_x, _y, _z);
            _totalSent++;
            AddLog($"[BREAK] ({_x},{_y},{_z})");
        }
    }

    private void RenderFill()
    {
        ImGui.TextColored(new Vector4(1f, 0.75f, 0.3f, 1f), "FILL REGION");
        ImGui.TextDisabled("Iterates all blocks in [X1..X2, Y1..Y2, Z1..Z2] and places them.\nUse small regions — large fills take time.");
        ImGui.Spacing();

        ImGui.Text("Corner 1:");
        ImGui.SetNextItemWidth(80); ImGui.InputInt("X1##fx1",ref _x1,1); ImGui.SameLine();
        ImGui.SetNextItemWidth(80); ImGui.InputInt("Y1##fy1",ref _y1,1); ImGui.SameLine();
        ImGui.SetNextItemWidth(80); ImGui.InputInt("Z1##fz1",ref _z1,1);
        ImGui.Text("Corner 2:");
        ImGui.SetNextItemWidth(80); ImGui.InputInt("X2##fx2",ref _x2,1); ImGui.SameLine();
        ImGui.SetNextItemWidth(80); ImGui.InputInt("Y2##fy2",ref _y2,1); ImGui.SameLine();
        ImGui.SetNextItemWidth(80); ImGui.InputInt("Z2##fz2",ref _z2,1);

        int vol = Math.Abs((_x2-_x1+1)*(_y2-_y1+1)*(_z2-_z1+1));
        ImGui.TextDisabled($"Volume: {vol} blocks");
        if (vol > 10000) ImGui.TextColored(new Vector4(1f,0.4f,0.4f,1f), "⚠ Large fill — may take a long time");

        ImGui.SetNextItemWidth(-1); ImGui.InputText("Block TypeID##ftid", ref _fillTypeHex, 16);
        ImGui.SetNextItemWidth(-1); ImGui.SliderInt("Delay ms##fdl", ref _fillDelayMs, 0, 500);
        ImGui.Spacing();

        if (_fillRunning)
        {
            if (ImGui.Button("Stop Fill##fstop", new Vector2(-1, 28))) { _fillCts?.Cancel(); _fillRunning = false; }
        }
        else
        {
            if (ImGui.Button("Start Fill##fstart", new Vector2(-1, 28)) && vol > 0 && vol <= 100000)
            {
                if (uint.TryParse(_fillTypeHex, System.Globalization.NumberStyles.HexNumber, null, out uint ftid))
                {
                    _fillCts = new System.Threading.CancellationTokenSource();
                    var tok = _fillCts.Token;
                    _fillRunning = true;
                    int fx1=_x1,fy1=_y1,fz1=_z1,fx2=_x2,fy2=_y2,fz2=_z2;
                    int fdl = _fillDelayMs;
                    System.Threading.Tasks.Task.Run(async () =>
                    {
                        int n=0;
                        for(int fx=Math.Min(fx1,fx2);fx<=Math.Max(fx1,fx2)&&!tok.IsCancellationRequested;fx++)
                        for(int fy=Math.Min(fy1,fy2);fy<=Math.Max(fy1,fy2)&&!tok.IsCancellationRequested;fy++)
                        for(int fz=Math.Min(fz1,fz2);fz<=Math.Max(fz1,fz2)&&!tok.IsCancellationRequested;fz++)
                        {
                            _pipe.BlockPlace(fx,fy,fz,ftid,1); n++; _totalSent++;
                            if(fdl>0) await System.Threading.Tasks.Task.Delay(fdl,tok);
                        }
                        _fillRunning=false;
                        AddLog($"[FILL] Done — {n} blocks placed");
                    }, tok);
                    AddLog($"[FILL] Started: {vol} blocks type=0x{ftid:X} delay={fdl}ms");
                }
            }
        }
    }

    private void RenderEntityRel()
    {
        ImGui.TextColored(new Vector4(0.8f, 0.5f, 1f, 1f), "ENTITY-RELATIVE");
        ImGui.TextDisabled("Place block relative to an entity's current position.");
        ImGui.Spacing();

        ImGui.SetNextItemWidth(-1);
        if (ImGui.InputText("Entity ID (hex)##bere", ref _relEntityHex, 32))
            ulong.TryParse(_relEntityHex.TrimStart('0','x'), System.Globalization.NumberStyles.HexNumber, null, out _relEntityId);

        if (_relEntityId != 0 && _state.EntityTracker.Entities.TryGetValue(_relEntityId, out var re))
            ImGui.TextColored(new Vector4(0.5f,1f,0.5f,1f), $"  {re.PositionStr}");

        ImGui.SetNextItemWidth(80); ImGui.InputInt("OffX##beoX",ref _relOffX,1); ImGui.SameLine();
        ImGui.SetNextItemWidth(80); ImGui.InputInt("OffY##beoY",ref _relOffY,1); ImGui.SameLine();
        ImGui.SetNextItemWidth(80); ImGui.InputInt("OffZ##beoZ",ref _relOffZ,1);
        ImGui.SetNextItemWidth(-1); ImGui.InputText("Block Type##bebt", ref _typeIdHex, 16);

        if (ImGui.Button("Place at Entity##beplace", new Vector2(-1, 0)))
        {
            if (_relEntityId != 0 && _state.EntityTracker.Entities.TryGetValue(_relEntityId, out var pe)
                && uint.TryParse(_typeIdHex, System.Globalization.NumberStyles.HexNumber, null, out uint tid))
            {
                int bx=(int)pe.X+_relOffX, by=(int)pe.Y+_relOffY, bz=(int)pe.Z+_relOffZ;
                _pipe.BlockPlace(bx,by,bz,tid,1); _totalSent++;
                AddLog($"[PLACE-ENT] entity=0x{_relEntityId:X}  ({bx},{by},{bz}) type=0x{tid:X}");
            }
        }
        if (ImGui.Button("Break at Entity##bebreak", new Vector2(-1, 0)))
        {
            if (_relEntityId != 0 && _state.EntityTracker.Entities.TryGetValue(_relEntityId, out var pe2))
            {
                int bx=(int)pe2.X+_relOffX, by=(int)pe2.Y+_relOffY, bz=(int)pe2.Z+_relOffZ;
                _pipe.BlockBreak(bx,by,bz); _totalSent++;
                AddLog($"[BREAK-ENT] entity=0x{_relEntityId:X}  ({bx},{by},{bz})");
            }
        }
    }

    private void RenderRegistry(float h)
    {
        ImGui.SetNextItemWidth(-1); ImGui.InputText("Search block##bfrsq", ref _searchQ, 64);
        ImGui.Separator();
        var defs = _state.InventoryTracker.Registry.Values.OrderBy(d => d.TypeId)
            .Where(d => string.IsNullOrEmpty(_searchQ) || d.Name.ToLower().Contains(_searchQ.ToLower())
                     || d.TypeId.ToString("X").ToLower().Contains(_searchQ.ToLower())).ToList();
        ImGui.BeginChild("bf_reg", new Vector2(-1, h-60), ImGuiChildFlags.None);
        if (ImGui.BeginTable("bfregtbl", 3, ImGuiTableFlags.Borders|ImGuiTableFlags.RowBg|ImGuiTableFlags.ScrollY))
        {
            ImGui.TableSetupColumn("TypeID", ImGuiTableColumnFlags.WidthFixed, 90);
            ImGui.TableSetupColumn("Name",   ImGuiTableColumnFlags.WidthStretch);
            ImGui.TableSetupColumn("Use",    ImGuiTableColumnFlags.WidthFixed, 45);
            ImGui.TableSetupScrollFreeze(0,1); ImGui.TableHeadersRow();
            foreach (var d in defs.Take(2000))
            {
                ImGui.TableNextRow();
                ImGui.TableSetColumnIndex(0); ImGui.TextDisabled($"0x{d.TypeId:X6}");
                ImGui.TableSetColumnIndex(1); ImGui.TextUnformatted(d.Name);
                ImGui.TableSetColumnIndex(2);
                if (ImGui.SmallButton($"Use##bru{d.TypeId}"))
                { _typeIdHex = d.TypeId.ToString("X"); _fillTypeHex = _typeIdHex; _typeName = d.Name; }
            }
            ImGui.EndTable();
        }
        ImGui.EndChild();
    }

    private void RenderLog(float h)
    {
        ImGui.Checkbox("Auto-scroll##bflsc", ref _logScroll);
        ImGui.SameLine(); if (ImGui.SmallButton("Clear##bflcl")) lock(_log) _log.Clear();
        ImGui.Separator();
        ImGui.BeginChild("bf_log", new Vector2(-1, h-60), ImGuiChildFlags.Borders);
        List<string> snap; lock(_log) snap=_log.ToList();
        foreach (var line in snap) ImGui.TextUnformatted(line);
        if (_logScroll && ImGui.GetScrollY()>=ImGui.GetScrollMaxY()-5) ImGui.SetScrollHereY(1f);
        ImGui.EndChild();
    }

    private void AddLog(string msg)
    {
        var line = $"[{DateTime.Now:HH:mm:ss.fff}] {msg}";
        lock(_log) { _log.Add(line); if(_log.Count>500) _log.RemoveAt(0); }
    }
}
