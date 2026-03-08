// Tabs/ChatTab.cs  v17
// Chat intercept, injection, and macro system.
// Captured messages arrive via AppState.ChatHistory (fed from 0xD2 S2C stream).
// Outgoing messages are injected as 0xD2 C2S via SEND_CHAT pipe command.

using HyForce.Core;
using HyForce.Networking;
using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;

namespace HyForce.Tabs;

public class ChatTab : ITab
{
    public string Name => "Chat";

    private readonly AppState          _state;
    private readonly PipeCaptureServer _pipe;

    // Compose
    private string  _composeBuf    = "";
    private bool    _scrollToBottom = true;
    private string  _filterBuf     = "";

    // Macros
    private readonly List<(string Name, string Command)> _macros = new()
    {
        ("Creative Mode",   "/gamemode creative"),
        ("Survival Mode",   "/gamemode survival"),
        ("Give Diamond",    "/give @s diamond 64"),
        ("Give All Items",  "/give @s *"),
        ("Op Self",         "/op @s"),
        ("Clear Inventory", "/clear @s"),
        ("Kill All Mobs",   "/kill @e[type=!player]"),
        ("Day",             "/time set day"),
        ("Night",           "/time set night"),
        ("Clear Weather",   "/weather clear"),
    };
    private string _macroName  = "";
    private string _macroCmd   = "";

    // Spam / repeat
    private bool   _repeatOn   = false;
    private int    _repeatMs   = 3000;
    private string _repeatMsg  = "";
    private DateTime _lastRepeat = DateTime.MinValue;

    // Stats
    private int _injectedCount = 0;

    private readonly List<string> _activityLog = new();
    private bool _logScroll = true;

    public ChatTab(AppState state, PipeCaptureServer pipe)
    {
        _state = state;
        _pipe  = pipe;
    }

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();

        // Auto-repeat tick
        if (_repeatOn && !string.IsNullOrEmpty(_repeatMsg) &&
            (DateTime.UtcNow - _lastRepeat).TotalMilliseconds >= _repeatMs)
        {
            SendChat(_repeatMsg);
            _lastRepeat = DateTime.UtcNow;
        }

        float leftW = 320f;

        // ── Left: compose + macros + tools ───────────────────────────────────
        ImGui.BeginChild("chat_left", new Vector2(leftW, avail.Y - 4), ImGuiChildFlags.Borders);
        {
            ImGui.TextColored(new Vector4(0.4f, 0.9f, 1f, 1f), "CHAT INJECT");
            ImGui.TextDisabled($"Injected total: {_injectedCount}");
            ImGui.TextDisabled("Sends raw UTF-8 as 0xD2 ChatMessage C2S.\nServer-side commands work if you have permission.");
            ImGui.Spacing();

            ImGui.SetNextItemWidth(-1);
            bool enter = ImGui.InputText("##cmsg", ref _composeBuf, 512,
                ImGuiInputTextFlags.EnterReturnsTrue);
            if ((enter || ImGui.Button("Send##csend", new Vector2(-1, 0))) && !string.IsNullOrWhiteSpace(_composeBuf))
            {
                SendChat(_composeBuf);
                _composeBuf = "";
            }

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

            // ── Macros ────────────────────────────────────────────────────────
            ImGui.TextColored(new Vector4(0.3f, 1f, 0.5f, 1f), "MACROS");
            foreach (var (name, cmd) in _macros.ToList())
            {
                if (ImGui.Button($"{name}##m_{name}", new Vector2(-1, 0)))
                    SendChat(cmd);
                if (ImGui.IsItemHovered()) ImGui.SetTooltip(cmd);
            }

            ImGui.Spacing();
            ImGui.TextDisabled("Add macro:");
            ImGui.SetNextItemWidth(-1); ImGui.InputText("Name##mname", ref _macroName, 32);
            ImGui.SetNextItemWidth(-1); ImGui.InputText("Cmd##mcmd",   ref _macroCmd,  256);
            if (ImGui.Button("Add##madd", new Vector2(-1, 0)) && !string.IsNullOrWhiteSpace(_macroName))
            {
                _macros.Add((_macroName, _macroCmd));
                _macroName = ""; _macroCmd = "";
            }

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

            // ── Repeat / spam ─────────────────────────────────────────────────
            ImGui.TextColored(new Vector4(1f, 0.5f, 0.3f, 1f), "AUTO-REPEAT");
            ImGui.TextDisabled("Sends a message on a timer. Use carefully.");
            ImGui.SetNextItemWidth(-1); ImGui.InputText("Message##rptmsg", ref _repeatMsg, 256);
            ImGui.SetNextItemWidth(-1); ImGui.SliderInt("Interval ms##rptms", ref _repeatMs, 500, 30000);
            ImGui.PushStyleColor(ImGuiCol.Button, _repeatOn ? new Vector4(0.55f,0.1f,0.1f,1f) : new Vector4(0.25f,0.25f,0.25f,1f));
            if (ImGui.Button(_repeatOn ? "REPEAT: ON  [click off]" : "REPEAT: OFF [click on]", new Vector2(-1, 28)))
            {
                _repeatOn = !_repeatOn;
                AddLog(_repeatOn ? $"[REPEAT] Started: \"{_repeatMsg}\"  every {_repeatMs}ms" : "[REPEAT] Stopped");
            }
            ImGui.PopStyleColor();
        }
        ImGui.EndChild();

        ImGui.SameLine();

        // ── Right: chat feed + activity log ──────────────────────────────────
        float rightW = avail.X - leftW - 8;
        ImGui.BeginChild("chat_right", new Vector2(rightW, avail.Y - 4), ImGuiChildFlags.None);
        {
            if (ImGui.BeginTabBar("chat_right_tabs"))
            {
                if (ImGui.BeginTabItem("Chat Feed##cf"))
                {
                    RenderChatFeed(avail.Y - 50);
                    ImGui.EndTabItem();
                }
                if (ImGui.BeginTabItem("Activity Log##cal"))
                {
                    RenderActivityLog(avail.Y - 50);
                    ImGui.EndTabItem();
                }
                ImGui.EndTabBar();
            }
        }
        ImGui.EndChild();
    }

    private void RenderChatFeed(float h)
    {
        ImGui.Checkbox("Auto-scroll##cfs", ref _scrollToBottom); ImGui.SameLine();
        ImGui.SetNextItemWidth(200); ImGui.InputText("Filter##cff", ref _filterBuf, 64);
        ImGui.SameLine();
        if (ImGui.SmallButton("Clear##cfcl")) _state.ChatHistory.Clear();
        ImGui.Separator();

        ImGui.BeginChild("chat_feed", new Vector2(-1, h - 60), ImGuiChildFlags.Borders);
        var history = _state.ChatHistory.ToList();
        if (!string.IsNullOrEmpty(_filterBuf))
        {
            var f = _filterBuf.ToLower();
            history = history.Where(e => e.Text.ToLower().Contains(f)).ToList();
        }

        foreach (var (time, isServer, text) in history)
        {
            Vector4 col = isServer
                ? new Vector4(0.85f, 0.95f, 1f, 1f)
                : new Vector4(1f, 0.85f, 0.5f, 1f);
            string prefix = isServer ? "◄" : "►";
            ImGui.TextColored(new Vector4(0.5f, 0.5f, 0.5f, 1f), $"[{time:HH:mm:ss}]");
            ImGui.SameLine();
            ImGui.TextColored(col, $"{prefix} {text}");
        }
        if (_scrollToBottom && ImGui.GetScrollY() >= ImGui.GetScrollMaxY() - 5)
            ImGui.SetScrollHereY(1f);
        ImGui.EndChild();
    }

    private void RenderActivityLog(float h)
    {
        ImGui.Checkbox("Auto-scroll##alsc2", ref _logScroll);
        ImGui.SameLine(); if (ImGui.SmallButton("Clear##calcl")) lock (_activityLog) _activityLog.Clear();
        ImGui.Separator();
        ImGui.BeginChild("chat_actlog", new Vector2(-1, h - 60), ImGuiChildFlags.Borders);
        List<string> snap; lock (_activityLog) snap = _activityLog.ToList();
        foreach (var line in snap)
            ImGui.TextUnformatted(line);
        if (_logScroll && ImGui.GetScrollY() >= ImGui.GetScrollMaxY() - 5)
            ImGui.SetScrollHereY(1f);
        ImGui.EndChild();
    }

    private void SendChat(string message)
    {
        byte[] utf8 = Encoding.UTF8.GetBytes(message);
        _pipe.SendChat(utf8);
        _injectedCount++;
        _state.ChatHistory.Add((DateTime.UtcNow, false, message));
        if (_state.ChatHistory.Count > 2000) _state.ChatHistory.RemoveAt(0);
        AddLog($"[INJECT] \"{message}\"");
    }

    private void AddLog(string msg)
    {
        var line = $"[{DateTime.Now:HH:mm:ss.fff}] {msg}";
        lock (_activityLog) { _activityLog.Add(line); if (_activityLog.Count > 500) _activityLog.RemoveAt(0); }
    }
}
