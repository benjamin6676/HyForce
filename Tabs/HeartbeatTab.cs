// Tabs/HeartbeatTab.cs  v19
using HyForce.Core;
using HyForce.Networking;
using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Numerics;

namespace HyForce.Tabs;

public class HeartbeatTab : ITab
{
    public string Name => "Heartbeat";

    private readonly AppState          _state;
    private readonly PipeCaptureServer _pipe;

    private bool   _autoPong        = false;
    private bool   _spectateMode    = false;
    private bool   _noclip          = false;
    private bool   _infiniteReach   = false;
    private bool   _godMode         = false;  // PacketLab god mode (0x70 drop)
    private float  _launchVx, _launchVy = 20f, _launchVz;
    private bool   _logScroll       = true;
    private readonly List<string> _log = new();

    // Respawn
    private int  _respawnCount      = 1;

    // Time / weather  (delegates to TimeWeatherController)
    private int   _timeModeIdx      = 0;
    private int   _timePresetIdx    = 0;
    private uint  _customTick       = 6000;
    private int   _weatherIdx       = 0;
    private bool  _timeLocked       = false;
    private bool  _timeRunning      = false;
    private static readonly string[] TimeModes    = { "One-shot", "Lock (resend loop)", "Advance (time-lapse)" };
    private static readonly string[] WeatherNames = { "Clear", "Rain", "Thunder" };

    public HeartbeatTab(AppState state, PipeCaptureServer pipe)
    {
        _state = state;
        _pipe  = pipe;
        _state.TimeWeatherController.OnLog += line =>
        { lock(_log) { _log.Add(line); if(_log.Count>500) _log.RemoveAt(0); } };
    }

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();
        float colW = (avail.X - 12) / 2;

        // ── Left column ───────────────────────────────────────────────────
        ImGui.BeginChild("hb_left", new Vector2(colW, avail.Y-4), ImGuiChildFlags.Borders);
        {
            // Auto-pong
            ImGui.TextColored(new Vector4(0.4f,0.85f,1f,1f), "HEARTBEAT / AUTO-PONG");
            ImGui.TextDisabled("Auto-replies to 0x01 Ping S2C frames.\nKeeps session alive when game is frozen/tabbed.");
            ImGui.Spacing();
            ImGui.PushStyleColor(ImGuiCol.Button, _autoPong ? new Vector4(0.1f,0.5f,0.1f,1f) : new Vector4(0.25f,0.25f,0.25f,1f));
            if (ImGui.Button(_autoPong ? "Auto-Pong: ON##hbap" : "Auto-Pong: OFF##hbap", new Vector2(-1,28)))
            {
                _autoPong = !_autoPong;
                if (_autoPong) _pipe.AutoPongOn(); else _pipe.AutoPongOff();
                AddLog($"[PONG] {(_autoPong ? "Enabled" : "Disabled")}");
            }
            ImGui.PopStyleColor();

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

            // Movement / damage toggles
            ImGui.TextColored(new Vector4(1f,0.75f,0.3f,1f), "CLIENT TOGGLES");
            ImGui.TextDisabled("These suppress specific C2S packet types.");
            ImGui.Spacing();

            ToggleButton("Spectate Mode##hbspec", ref _spectateMode,
                () => _pipe.SpectateOn(), () => _pipe.SpectateOff(),
                "DROP 0x6C ClientMovement — server thinks you're stationary.");

            ToggleButton("Noclip (god pos)##hbnc", ref _noclip,
                () => _pipe.NoclipOn(), () => _pipe.NoclipOff(),
                "DROP 0x70 DamageInfo — server can't register damage.");

            ToggleButton("Infinite Reach##hbir", ref _infiniteReach,
                () => _pipe.InfiniteReachOn(), () => _pipe.InfiniteReachOff(),
                "DROP 0x71 RangeCheckFailed — interact/mine at any distance.");

            ToggleButton("God Mode (C2S drop)##hbgod", ref _godMode,
                () => _pipe.QuicDropC2S(0x70), () => _pipe.QuicDropC2S(0),
                "Identical to noclip but via PacketLab C2S drop path.");

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

            // Velocity launcher
            ImGui.TextColored(new Vector4(0.7f,0.4f,1f,1f), "VELOCITY LAUNCHER");
            ImGui.TextDisabled("Patches velocity bytes in next 0x6C movement send.");
            ImGui.SetNextItemWidth(-1); ImGui.SliderFloat("Vx##hvx", ref _launchVx,-100f,100f,"%.1f");
            ImGui.SetNextItemWidth(-1); ImGui.SliderFloat("Vy##hvy", ref _launchVy,-100f,100f,"%.1f");
            ImGui.SetNextItemWidth(-1); ImGui.SliderFloat("Vz##hvz", ref _launchVz,-100f,100f,"%.1f");
            ImGui.Spacing();
            if (ImGui.Button("Launch!##hblnch", new Vector2(-1,28)))
            {
                _pipe.VelocityLaunch(_launchVx, _launchVy, _launchVz);
                AddLog($"[LAUNCH] vx={_launchVx:F1} vy={_launchVy:F1} vz={_launchVz:F1}");
            }
            if (ImGui.SmallButton("Up##hbup"))   { _launchVx=0; _launchVy=30; _launchVz=0; }
            ImGui.SameLine();
            if (ImGui.SmallButton("Blast##hbbl")) { _launchVx=0; _launchVy=50; _launchVz=0; }
            ImGui.SameLine();
            if (ImGui.SmallButton("Zero##hbzr"))  { _launchVx=0; _launchVy=0;  _launchVz=0; }

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

            // Respawn
            ImGui.TextColored(new Vector4(1f,0.4f,0.4f,1f), "FORCE RESPAWN");
            ImGui.TextDisabled("Forges 0x6A ClientRespawn C2S.");
            ImGui.SetNextItemWidth(80); ImGui.InputInt("x##hrsc", ref _respawnCount, 0);
            _respawnCount = Math.Max(1, _respawnCount);
            ImGui.SameLine();
            if (ImGui.Button("Respawn##hbrsp", new Vector2(-1,0)))
            {
                for (int i=0; i<_respawnCount; i++) _pipe.RespawnForce();
                AddLog($"[RESPAWN] Sent x{_respawnCount}");
            }
        }
            ImGui.EndChild();

            ImGui.SameLine();

            // ── Right column: time + weather + log ───────────────────────────
            ImGui.BeginChild("hb_right", new Vector2(colW, avail.Y-4), ImGuiChildFlags.Borders);
            var twc = _state.TimeWeatherController;
            ImGui.TextColored(new Vector4(0.4f,1f,0.7f,1f), "TIME CONTROL");
            ImGui.TextDisabled("Spoofs 0x92 UpdateTime into the game app.");
            ImGui.Spacing();

            // Presets
            ImGui.Text("Presets:");
            for (int i=0; i<TimeWeatherController.TimePresets.Length; i++)
            {
                var (name, ticks) = TimeWeatherController.TimePresets[i];
                if (ImGui.SmallButton($"{name}##hbtp{i}")) { _customTick=ticks; twc.SetTime(ticks); }
                if (i < TimeWeatherController.TimePresets.Length-1) ImGui.SameLine();
            }
            ImGui.Spacing();
            ImGui.SetNextItemWidth(-1);
            ImGui.SliderInt("Ticks (0-24000)##hbtk", ref _dummy, 0, 24000);
            // Use SliderInt workaround
            uint tempTick = _customTick;
            int tickInt = (int)tempTick;
            ImGui.SetNextItemWidth(-1);
            if (ImGui.SliderInt("##hbticks", ref tickInt, 0, 24000, $"{tickInt}"))
                _customTick = (uint)tickInt;

            ImGui.SetNextItemWidth(-1);
            ImGui.Combo("Mode##hbtm", ref _timeModeIdx, TimeModes, TimeModes.Length);
            ImGui.Spacing();

            if (ImGui.Button("Apply##hbta", new Vector2(-1,0)))
            {
                switch (_timeModeIdx)
                {
                    case 0: twc.SetTime(_customTick); break;
                    case 1: twc.LockTime(_customTick); _timeLocked=true; break;
                    case 2: twc.StartTimeAdvance(20f); _timeRunning=true; break;
                }
            }
            if (_timeLocked || _timeRunning)
            {
                if (ImGui.Button("Stop Time Control##hbtstop", new Vector2(-1,0)))
                { twc.StopTimeAdvance(); _timeLocked=false; _timeRunning=false; }
            }
            ImGui.TextDisabled($"Status: {(twc.IsTimeLocked?"LOCKED":twc.IsTimeRunning?"ADVANCING":"IDLE")}  tick={twc.CurrentTick}");

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

            ImGui.TextColored(new Vector4(0.6f,0.8f,1f,1f), "WEATHER CONTROL");
            ImGui.TextDisabled("Spoofs 0x95 UpdateWeather into the game app.");
            ImGui.Spacing();
            ImGui.SetNextItemWidth(-1);
            ImGui.Combo("Weather##hbw", ref _weatherIdx, WeatherNames, WeatherNames.Length);
            if (ImGui.Button("Apply Weather##hbwa", new Vector2(-1,0)))
            {
                var wt = (WeatherType)_weatherIdx;
                twc.SetWeather(wt);
                AddLog($"[WEATHER] Set to {wt}");
            }

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

            // Log
            ImGui.TextColored(new Vector4(0.5f,0.5f,0.5f,1f), "LOG");
            ImGui.Checkbox("Auto-scroll##hblsc", ref _logScroll);
            ImGui.SameLine(); if (ImGui.SmallButton("Clear##hblcl")) lock(_log) _log.Clear();
            float logH = avail.Y - ImGui.GetCursorPosY() - 20;
            ImGui.BeginChild("hb_log", new Vector2(-1, logH), ImGuiChildFlags.Borders);
        List<string> snap; lock(_log) snap = _log.ToList();
            foreach(var line in snap) ImGui.TextUnformatted(line);
            if(_logScroll && ImGui.GetScrollY()>=ImGui.GetScrollMaxY()-5) ImGui.SetScrollHereY(1f);
            ImGui.EndChild();
            }
        

    private int _dummy = 6000;

    private void ToggleButton(string label, ref bool state, Action onEnable, Action onDisable, string tooltip)
    {
        ImGui.PushStyleColor(ImGuiCol.Button, state ? new Vector4(0.2f,0.55f,0.2f,1f) : new Vector4(0.22f,0.22f,0.22f,1f));
        if (ImGui.Button(label, new Vector2(-1, 24)))
        {
            state = !state;
            if (state) onEnable(); else onDisable();
            AddLog($"{label.Split('#')[0].Trim()}: {(state?"ON":"OFF")}");
        }
        ImGui.PopStyleColor();
        if (ImGui.IsItemHovered()) ImGui.SetTooltip(tooltip);
    }

    private void AddLog(string msg)
    {
        var line = $"[{DateTime.Now:HH:mm:ss.fff}] {msg}";
        lock(_log) { _log.Add(line); if(_log.Count>500) _log.RemoveAt(0); }
    }
}
