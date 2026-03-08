// Tabs/ScriptTab.cs  v20
using HyForce.Core;
using HyForce.Networking;
using ImGuiNET;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;

namespace HyForce.Tabs;

public class ScriptTab : ITab
{
    public string Name => "Script";

    private readonly AppState          _state;
    private readonly PipeCaptureServer _pipe;
    private readonly ScriptEngine      _engine;

    private string _scriptText = _defaultScript;
    private string _loadPath   = "";
    private string _savePath   = "";
    private bool   _logScroll  = true;
    private int    _templateIdx = 0;
    private readonly List<string> _log = new();

    private static readonly string _defaultScript =
@"# HyForce .hfscript example
# Lines starting with # are comments
# All pipe commands are supported + SLEEP, LOOP, ENDLOOP, VAR, IF/ENDIF, PRINT

PRINT Script started
SLEEP 500

# Teleport to a fixed coordinate
TELEPORT 0 64 0
SLEEP 1000

# Give yourself a starter item
FORGE_STREAM 10000000AB000000000000000100000001000000

SLEEP 500
PRINT Done!
";

    private static readonly (string Name, string Script)[] _templates = {
        ("Empty",        "# HyForce script\n"),
        ("Item Give Loop",
@"# Give item type 0x1 every 2 seconds, 5 times
LOOP 5
  FORGE_STREAM 10000000AB000000000000000100000001000000
  SLEEP 2000
ENDLOOP
PRINT Done giving items
"),
        ("Perm Bit Sweep (manual)",
@"# Test each permission bit with a pause
VAR BIT 0
PRINT Testing bit 0
PERM_TEST_BIT 0
SLEEP 2000
PERM_TEST_BIT 1
SLEEP 2000
PERM_TEST_BIT 2
SLEEP 2000
PERM_TEST_BIT 3
SLEEP 2000
PRINT Sweep done — check PermEscalate tab
PERM_INJECT_MASK 00000000
"),
        ("Waypoint Route",
@"# Teleport through 3 points
TELEPORT 0 64 0
SLEEP 1500
TELEPORT 100 64 0
SLEEP 1500
TELEPORT 100 64 100
SLEEP 1500
TELEPORT 0 64 100
SLEEP 1500
PRINT Route complete
"),
        ("Item Spam + Stop",
@"ITEM_SPAM_START 1 0 64 500
SLEEP 5000
ITEM_SPAM_STOP
PRINT Spam done
"),
        ("Admin Command Probe",
@"# Probe admin opcodes with empty frames
OPCODE_FUZZ_START 100 13F 300
SLEEP 30000
OPCODE_FUZZ_STOP
PRINT Fuzz done — check OpcodeScannerTab
"),
    };

    public ScriptTab(AppState state, PipeCaptureServer pipe)
    {
        _state = state; _pipe = pipe; _engine = state.ScriptEngine;
        _engine.OnLog += line => { lock(_log) { _log.Add(line); if(_log.Count>2000) _log.RemoveAt(0); } };
    }

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();
        float rightW = 310f;
        float editorW = avail.X - rightW - 8;

        // Status bar
        if (_engine.IsRunning)
        {
            ImGui.TextColored(new Vector4(0.3f,1f,0.3f,1f),
                $"● RUNNING  L{_engine.LineNumber}: {_engine.CurrentLine[..Math.Min(60,_engine.CurrentLine.Length)]}");
            ImGui.SameLine();
            ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.5f,0.1f,0.1f,1f));
            if (ImGui.Button("Stop##scst")) _engine.Stop();
            ImGui.PopStyleColor();
        }
        else
        {
            ImGui.TextDisabled($"■ IDLE   {_engine.CommandsSent} commands sent   script: {_engine.ScriptName}");
            ImGui.SameLine();
            if (ImGui.Button("Run##scrun", new Vector2(50,0)))
                _engine.RunText(_scriptText, "editor");
        }
        ImGui.Separator();

        // Editor
        ImGui.BeginChild("sc_editor", new Vector2(editorW, avail.Y-4), ImGuiChildFlags.None);
        {
            ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.06f,0.06f,0.09f,1f));
            float eh = avail.Y - 70;
            ImGui.InputTextMultiline("##sced", ref _scriptText, 131072,
                new Vector2(-1, eh), ImGuiInputTextFlags.AllowTabInput);
            ImGui.PopStyleColor();
            ImGui.Spacing();
            if (ImGui.Button("Run##scrun2", new Vector2(60,0)) && !_engine.IsRunning)
                _engine.RunText(_scriptText, "editor");
            ImGui.SameLine();
            if (ImGui.SmallButton("Clear##scedcl")) _scriptText = "";
            ImGui.SameLine();
            if (ImGui.SmallButton("Default##scedef")) _scriptText = _defaultScript;
        }
        ImGui.EndChild();

        ImGui.SameLine();

        ImGui.BeginChild("sc_right", new Vector2(rightW, avail.Y-4), ImGuiChildFlags.None);
        {
            if (ImGui.BeginTabBar("sc_right_tabs"))
            {
                if (ImGui.BeginTabItem("Templates##sct"))   { RenderTemplates(); ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("File##scf"))        { RenderFileOps();   ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Reference##scref")) { RenderReference(); ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Log##scl"))         { RenderLog(avail.Y-50); ImGui.EndTabItem(); }
                ImGui.EndTabBar();
            }
        }
        ImGui.EndChild();
    }

    private void RenderTemplates()
    {
        ImGui.TextColored(new Vector4(0.4f,0.85f,1f,1f), "TEMPLATES");
        ImGui.Separator();
        for (int i=0; i<_templates.Length; i++)
        {
            bool sel = _templateIdx == i;
            if (ImGui.Selectable($"{_templates[i].Name}##sctmpl{i}", sel))
                _templateIdx = i;
        }
        ImGui.Spacing();
        if (ImGui.Button("Load Template##scltmpl", new Vector2(-1,0)))
            _scriptText = _templates[_templateIdx].Script;
        ImGui.SameLine();
        if (ImGui.Button("Append##scatmpl", new Vector2(-1,0)))
            _scriptText += "\n" + _templates[_templateIdx].Script;
    }

    private void RenderFileOps()
    {
        ImGui.TextColored(new Vector4(0.3f,1f,0.5f,1f), "LOAD / SAVE");
        ImGui.SetNextItemWidth(-1); ImGui.InputText("Path##scfp", ref _loadPath, 256);
        if (ImGui.Button("Load .hfscript##scfld", new Vector2(-1,0)) && File.Exists(_loadPath))
            try { _scriptText = File.ReadAllText(_loadPath); } catch(Exception ex) { AddLog($"[ERR] {ex.Message}"); }
        ImGui.Spacing();
        ImGui.SetNextItemWidth(-1); ImGui.InputText("Save path##scfsp", ref _savePath, 256);
        if (ImGui.Button("Save .hfscript##scfsv", new Vector2(-1,0)) && !string.IsNullOrEmpty(_savePath))
            try { File.WriteAllText(_savePath, _scriptText); AddLog($"[SCRIPT] Saved to {_savePath}"); }
            catch(Exception ex) { AddLog($"[ERR] {ex.Message}"); }
        ImGui.Spacing(); ImGui.Separator();
        ImGui.TextDisabled("Run file directly:");
        if (ImGui.Button("Run File##scfrf", new Vector2(-1,0)) && File.Exists(_loadPath))
            _engine.RunFile(_loadPath);
    }

    private void RenderReference()
    {
        ImGui.TextColored(new Vector4(1f,0.85f,0.3f,1f), "SCRIPT REFERENCE");
        ImGui.Separator();
        var cmds = new (string Cmd, string Desc)[] {
            ("# comment",        "Ignored line"),
            ("SLEEP <ms>",       "Wait N milliseconds"),
            ("PRINT <msg>",      "Log a message"),
            ("VAR <n> <val>",    "Set variable (use ${n})"),
            ("LOOP <n>",         "Repeat block N times (0=infinite)"),
            ("ENDLOOP",          "End loop block"),
            ("IF <a> == <b>",    "Conditional block"),
            ("ENDIF",            "End conditional"),
            ("LABEL <n>",        "Define jump target"),
            ("GOTO <n>",         "Jump to label"),
            ("TELEPORT x y z",   "Teleport to position"),
            ("SEND_CHAT <hex>",  "Send chat message (UTF-8 hex)"),
            ("FORGE_STREAM <hex>","Inject raw C2S stream frame"),
            ("BLOCK_PLACE x y z type face","Place block"),
            ("BLOCK_BREAK x y z","Break block"),
            ("ITEM_SPAM_START type slot count delay","Start item spam"),
            ("ITEM_SPAM_STOP",   "Stop item spam"),
            ("PERM_TEST_BIT <n>","Inject single perm bit"),
            ("PERM_INJECT_MASK <hex>","Inject permission mask"),
            ("OPCODE_FUZZ_START s e d","Start opcode fuzz"),
            ("OPCODE_FUZZ_STOP", "Stop opcode fuzz"),
            ("VELOCITY_LAUNCH vx vy vz","Launch velocity"),
            ("RESPAWN_FORCE",    "Force respawn"),
            ("TIME_SET <ticks>", "Set world time"),
            ("WEATHER_SET <n>",  "Set weather (0=clear,1=rain,2=thunder)"),
            ("AUTO_PONG_ON",     "Enable heartbeat"),
            ("NOCLIP_ON/OFF",    "Noclip toggle"),
            ("INF_REACH_ON/OFF", "Infinite reach toggle"),
        };
        ImGui.BeginChild("sc_reflist", new Vector2(-1,-1), ImGuiChildFlags.None);
        foreach (var (cmd, desc) in cmds)
        {
            ImGui.TextColored(new Vector4(0.5f,0.85f,1f,1f), cmd);
            ImGui.SameLine(0,6); ImGui.TextDisabled(desc);
            if (ImGui.IsItemClicked()) _scriptText += "\n" + cmd;
        }
        ImGui.EndChild();
    }

    private void RenderLog(float h)
    {
        ImGui.Checkbox("Auto-scroll##sclsc", ref _logScroll);
        ImGui.SameLine(); if (ImGui.SmallButton("Clear##sclcl")) lock(_log) _log.Clear();
        ImGui.Separator();
        ImGui.BeginChild("sc_log_ch", new Vector2(-1, h-60), ImGuiChildFlags.Borders);
        List<string> snap; lock(_log) snap=_log.ToList();
        foreach(var line in snap) ImGui.TextUnformatted(line);
        if(_logScroll && ImGui.GetScrollY()>=ImGui.GetScrollMaxY()-5) ImGui.SetScrollHereY(1f);
        ImGui.EndChild();
    }

    private void AddLog(string msg)
    {
        var line = $"[{DateTime.Now:HH:mm:ss.fff}] {msg}";
        lock(_log) { _log.Add(line); if(_log.Count>2000) _log.RemoveAt(0); }
    }
}
