// Tabs/EntityPropertyTab.cs  v19
using HyForce.Core;
using HyForce.Networking;
using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;

namespace HyForce.Tabs;

public class EntityPropertyTab : ITab
{
    public string Name => "Entity Props";

    private readonly AppState               _state;
    private readonly PipeCaptureServer      _pipe;
    private readonly EntityPropertyScanner  _scanner;

    // Target entity
    private string  _eidHex     = "";
    private ulong   _targetEid  = 0;

    // Scan range
    private int     _scanStart  = 0;
    private int     _scanEnd    = 255;
    private int     _scanDelay  = 300;

    // Quick-set
    private int     _quickPropId= 0;
    private string  _quickType  = "float";
    private float   _quickFloat = 1.0f;
    private uint    _quickUint  = 1;
    private bool    _quickBool  = true;
    private static readonly string[] PropTypes = { "float", "uint32", "bool" };
    private int _quickTypeIdx = 0;

    // Known props quick-edit
    private float[] _knownVals;

    private bool _logScroll = true;
    private readonly List<string> _log = new();

    public EntityPropertyTab(AppState state, PipeCaptureServer pipe)
    {
        _state   = state;
        _pipe    = pipe;
        _scanner = state.EntityPropertyScanner;
        _scanner.OnLog += line => { lock(_log) { _log.Add(line); if(_log.Count>500) _log.RemoveAt(0); } };
        _knownVals = new float[_scanner.KnownProps.Count];
        for(int i=0;i<_knownVals.Length;i++) _knownVals[i] = 1f;
    }

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();
        float leftW = 300f;

        // Status
        if (_scanner.IsScanning)
            ImGui.TextColored(new Vector4(0.3f,1f,0.3f,1f),
                $"● SCANNING 0x{_scanner.ScanTargetEid:X}  {_scanner.ScanProgress}/{_scanner.ScanTotal}");
        else
            ImGui.TextDisabled($"■ IDLE  {_scanner.Results.Count} results");
        ImGui.Separator();

        ImGui.BeginChild("ep_left", new Vector2(leftW, avail.Y-4), ImGuiChildFlags.Borders);
        {
            // Target entity
            ImGui.TextColored(new Vector4(0.4f,0.85f,1f,1f), "TARGET ENTITY");
            ImGui.SetNextItemWidth(-1);
            if (ImGui.InputText("Entity ID (hex)##epeid", ref _eidHex, 32))
                ulong.TryParse(_eidHex.TrimStart('0','x'), System.Globalization.NumberStyles.HexNumber, null, out _targetEid);

            // Pick from tracker
            ImGui.TextDisabled("Or pick from entity list:");
            ImGui.BeginChild("ep_elist", new Vector2(-1,100), ImGuiChildFlags.Borders);
            foreach (var e in _state.EntityTracker.Entities.Values.Where(e=>e.HasPosition).Take(30))
            {
                bool sel = e.EntityId == _targetEid;
                string lbl = string.IsNullOrEmpty(e.Label) ? $"0x{e.EntityId:X}" : e.Label;
                if (ImGui.Selectable($"{lbl}  T=0x{e.TypeId:X4}##epel{e.EntityId}", sel))
                { _targetEid=e.EntityId; _eidHex=$"{e.EntityId:X}"; }
            }
            ImGui.EndChild();

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

            // Scanner
            ImGui.TextColored(new Vector4(1f,0.75f,0.3f,1f), "PROP SCANNER");
            ImGui.SetNextItemWidth(80); ImGui.InputInt("From##epsf",ref _scanStart,1); ImGui.SameLine();
            ImGui.SetNextItemWidth(80); ImGui.InputInt("To##epst",ref _scanEnd,1); ImGui.SameLine();
            ImGui.SetNextItemWidth(60); ImGui.InputInt("ms##epsms",ref _scanDelay,0);
            _scanStart = Math.Max(0,_scanStart); _scanEnd = Math.Clamp(_scanEnd,_scanStart,511);
            ImGui.Spacing();

            if (_scanner.IsScanning)
            {
                float pct = (float)_scanner.ScanProgress / Math.Max(1,_scanner.ScanTotal);
                ImGui.ProgressBar(pct, new Vector2(-1,0), $"{_scanner.ScanProgress}/{_scanner.ScanTotal}");
                if (ImGui.Button("Stop Scan##epss", new Vector2(-1,0))) _scanner.StopScan();
            }
            else
            {
                if (ImGui.Button("Start Scan##epss2", new Vector2(-1,28)) && _targetEid != 0)
                    _scanner.StartScan(_targetEid, (uint)_scanStart, (uint)_scanEnd, _scanDelay);
                if (_targetEid == 0) ImGui.TextColored(new Vector4(1f,0.4f,0.4f,1f), "Set target entity first");
            }

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

            // Quick-set
            ImGui.TextColored(new Vector4(0.7f,0.4f,1f,1f), "QUICK SET");
            ImGui.SetNextItemWidth(80); ImGui.InputInt("PropID##epqp", ref _quickPropId, 1);
            ImGui.SetNextItemWidth(-1);
            if (ImGui.Combo("Type##epqt", ref _quickTypeIdx, PropTypes, PropTypes.Length))
                _quickType = PropTypes[_quickTypeIdx];

            ImGui.SetNextItemWidth(-1);
            if (_quickType == "float") ImGui.InputFloat("Value##epqv", ref _quickFloat, 0.1f);
            else if (_quickType == "uint32") { int vi=(int)_quickUint; ImGui.InputInt("Value##epqv", ref vi,1); _quickUint=(uint)vi; }
            else ImGui.Checkbox("Value##epqv", ref _quickBool);

            ImGui.Spacing();
            if (ImGui.Button("Send SetEntityProperty##epqsend", new Vector2(-1,0)) && _targetEid!=0)
            {
                byte[] val = _quickType == "float"  ? BitConverter.GetBytes(_quickFloat)
                           : _quickType == "uint32" ? BitConverter.GetBytes(_quickUint)
                           : new[]{ _quickBool ? (byte)1 : (byte)0 };
                _scanner.SetProp(_targetEid, (uint)_quickPropId, val);
            }
        }
        ImGui.EndChild();

        ImGui.SameLine();

        float rightW = avail.X - leftW - 8;
        ImGui.BeginChild("ep_right", new Vector2(rightW, avail.Y-4), ImGuiChildFlags.None);
        {
            if (ImGui.BeginTabBar("ep_right_tabs"))
            {
                if (ImGui.BeginTabItem("Known Props##epkp"))  { RenderKnownProps(avail.Y-50); ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Scan Results##epsr")) { RenderScanResults(avail.Y-50); ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Log##eplog"))         { RenderLog(avail.Y-50);         ImGui.EndTabItem(); }
                ImGui.EndTabBar();
            }
        }
        ImGui.EndChild();
    }

    private void RenderKnownProps(float h)
    {
        ImGui.TextDisabled("Pre-mapped properties. Edit value and click Set.");
        ImGui.Separator();
        ImGui.BeginChild("ep_kp", new Vector2(-1, h-60), ImGuiChildFlags.None);
        var props = _scanner.KnownProps.ToList();
        while (_knownVals.Length < props.Count) Array.Resize(ref _knownVals, props.Count);
        for (int i = 0; i < props.Count; i++)
        {
            var p = props[i];
            ImGui.TextColored(new Vector4(0.6f,0.8f,1f,1f), $"0x{p.PropId:X2}  {p.Name}");
            ImGui.SameLine(); ImGui.TextDisabled($"({p.ValueType})");
            if (ImGui.IsItemHovered()) ImGui.SetTooltip(p.Description);
            ImGui.SetNextItemWidth(120); ImGui.InputFloat($"##epkv{i}", ref _knownVals[i], 0.1f);
            ImGui.SameLine();
            if (ImGui.SmallButton($"Set##epks{i}") && _targetEid != 0)
            {
                byte[] val = p.ValueType switch
                {
                    "float"  => BitConverter.GetBytes(_knownVals[i]),
                    "bool"   => new[]{ _knownVals[i] > 0.5f ? (byte)1 : (byte)0 },
                    _        => BitConverter.GetBytes((uint)_knownVals[i]),
                };
                _scanner.SetProp(_targetEid, p.PropId, val);
            }
        }
        ImGui.EndChild();
    }

    private void RenderScanResults(float h)
    {
        ImGui.TextDisabled($"{_scanner.Results.Count} results");
        ImGui.Separator();
        ImGui.BeginChild("ep_sr", new Vector2(-1, h-60), ImGuiChildFlags.None);
        if (ImGui.BeginTable("epsrtbl", 4, ImGuiTableFlags.Borders|ImGuiTableFlags.RowBg|ImGuiTableFlags.ScrollY))
        {
            ImGui.TableSetupColumn("PropID",  ImGuiTableColumnFlags.WidthFixed, 70);
            ImGui.TableSetupColumn("Name",    ImGuiTableColumnFlags.WidthFixed, 120);
            ImGui.TableSetupColumn("Status",  ImGuiTableColumnFlags.WidthFixed, 75);
            ImGui.TableSetupColumn("Tried",   ImGuiTableColumnFlags.WidthFixed, 85);
            ImGui.TableSetupScrollFreeze(0,1); ImGui.TableHeadersRow();
            foreach(var r in _scanner.Results.Values.OrderBy(r=>r.PropId))
            {
                ImGui.TableNextRow();
                ImGui.TableSetColumnIndex(0); ImGui.TextDisabled($"0x{r.PropId:X2}");
                ImGui.TableSetColumnIndex(1);
                string name = _scanner.KnownProps.FirstOrDefault(p=>p.PropId==r.PropId)?.Name ?? "-";
                ImGui.TextUnformatted(name);
                ImGui.TableSetColumnIndex(2);
                Vector4 sc = r.Status==PropScanStatus.Sent     ? new(0.5f,0.8f,1f,1f)
                           : r.Status==PropScanStatus.Accepted ? new(0.3f,1f,0.4f,1f)
                           : r.Status==PropScanStatus.Rejected ? new(1f,0.4f,0.4f,1f)
                           : new(0.5f,0.5f,0.5f,1f);
                ImGui.TextColored(sc, r.Status.ToString());
                ImGui.TableSetColumnIndex(3); ImGui.TextDisabled(r.TriedAt.ToString("HH:mm:ss"));
            }
            ImGui.EndTable();
        }
        ImGui.EndChild();
    }

    private void RenderLog(float h)
    {
        ImGui.Checkbox("Auto-scroll##eplsc", ref _logScroll);
        ImGui.SameLine(); if (ImGui.SmallButton("Clear##eplcl")) lock(_log) _log.Clear();
        ImGui.Separator();
        ImGui.BeginChild("ep_log_ch", new Vector2(-1, h-60), ImGuiChildFlags.Borders);
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
