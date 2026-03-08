// Tabs/PermissionTab.cs  v17
// Session capture viewer, permission bit inspector, GameMode forger,
// modified PlayerSetup (0x12) replay with patched fields.
// Also controls the S2C opcode drop filter (time freeze, weather freeze, etc.)

using HyForce.Core;
using HyForce.Networking;
using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;

namespace HyForce.Tabs;

public class PermissionTab : ITab
{
    public string Name => "Permissions";

    private readonly AppState          _state;
    private readonly PipeCaptureServer _pipe;
    private readonly SessionCapture    _session;

    // GameMode forge
    private int    _gameModeIdx    = 0;
    private static readonly string[] GameModeNames = { "Survival (0)", "Creative (1)", "Adventure (2)", "Spectator (3)" };

    // Permission bit editor
    private uint   _permMask        = 0xFFFFFFFF;
    private bool[] _permBits        = new bool[32];
    private bool   _permBitsLoaded  = false;

    // S2C drop opcode
    private string _s2cDropHex      = "0000";
    private bool   _s2cDropArmed    = false;
    private string _s2cDropPreset   = "";
    private static readonly (string Label, string Hex, string Desc)[] DropPresets =
    {
        ("Time Freeze",    "0092", "Blocks UpdateTime — clock stops"),
        ("Weather Freeze", "0095", "Blocks UpdateWeather — weather locks"),
        ("No Animations",  "00A2", "Blocks PlayAnimation — entities freeze"),
        ("No Knockback",   "00A4", "Blocks ApplyKnockback — immune to knockback"),
        ("No Velocity",    "00A3", "Blocks ChangeVelocity — no forced movement"),
    };

    // Activity log
    private readonly List<string> _log = new();
    private bool _logScroll = true;

    public PermissionTab(AppState state, PipeCaptureServer pipe)
    {
        _state   = state;
        _pipe    = pipe;
        _session = state.SessionCapture;
        _session.OnLog += line => AddLog(line);
        _session.OnSessionCaptured += snap => {
            _permMask = snap.PermissionMask;
            LoadPermBits(snap.PermissionMask);
            AddLog($"[PERM] Session captured — GameMode={snap.GameModeStr}  Perms=0x{snap.PermissionMask:X8}");
        };
    }

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();
        float leftW = 350f;

        // ── Left panel ───────────────────────────────────────────────────────
        ImGui.BeginChild("perm_left", new Vector2(leftW, avail.Y - 4), ImGuiChildFlags.Borders);
        {
            // Session info
            ImGui.TextColored(new Vector4(0.4f, 0.85f, 1f, 1f), "SESSION CAPTURE");
            var snap = _session.Current;
            if (snap == null)
            {
                ImGui.TextDisabled("  No session captured yet.");
                ImGui.TextDisabled("  Connect to server — PlayerSetup (0x12)");
                ImGui.TextDisabled("  will be auto-captured on join.");
            }
            else
            {
                ImGui.Text($"  Entity ID:  0x{snap.SelfEntityId:X16}");
                ImGui.Text($"  Game Mode:  {snap.GameModeStr}  (raw: {snap.GameModeFlags})");
                ImGui.Text($"  Perm Mask:  0x{snap.PermissionMask:X8}");
                if (!string.IsNullOrEmpty(snap.WorldName))
                    ImGui.Text($"  World:      {snap.WorldName}");
                ImGui.TextDisabled($"  Captured:   {snap.CapturedAt:HH:mm:ss}");
                ImGui.TextDisabled($"  History:    {_session.History.Count} snapshots");
            }

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

            // ── GameMode forge ────────────────────────────────────────────────
            ImGui.TextColored(new Vector4(0.3f, 1f, 0.5f, 1f), "FORGE GAME MODE");
            ImGui.TextDisabled("Sends 0x65 SetGameMode C2S.\nServer enforces this or ignores — test both.");
            ImGui.SetNextItemWidth(-1);
            ImGui.Combo("Mode##gmc", ref _gameModeIdx, GameModeNames, GameModeNames.Length);
            if (ImGui.Button("Send SetGameMode (0x65)##sgm", new Vector2(-1, 28)))
            {
                _pipe.SetGameMode((uint)_gameModeIdx);
                AddLog($"[GAMEMODE] Sent 0x65 SetGameMode mode={GameModeNames[_gameModeIdx]}");
            }

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

            // ── Permission bit editor ─────────────────────────────────────────
            ImGui.TextColored(new Vector4(1f, 0.65f, 0.2f, 1f), "PERMISSION MASK EDITOR");
            ImGui.TextDisabled("Edit bits then replay PlayerSetup (0x12)\nwith modified mask. Locally-hosted servers only.");
            if (!_permBitsLoaded) LoadPermBits(_permMask);

            // Show as hex
            string maskHex = $"{_permMask:X8}";
            ImGui.SetNextItemWidth(-1);
            if (ImGui.InputText("Mask (hex)##pmh", ref maskHex, 8, ImGuiInputTextFlags.CharsHexadecimal))
            {
                if (uint.TryParse(maskHex, System.Globalization.NumberStyles.HexNumber, null, out uint m))
                { _permMask = m; LoadPermBits(m); }
            }

            // Bit toggles in 4 columns
            ImGui.Text("Bits:");
            if (ImGui.BeginTable("bitgrid", 8, ImGuiTableFlags.None))
            {
                for (int i = 0; i < 32; i++)
                {
                    ImGui.TableNextColumn();
                    if (ImGui.Checkbox($"##b{i}", ref _permBits[i]))
                        _permMask = BuildPermMask();
                    if (ImGui.IsItemHovered()) ImGui.SetTooltip($"Bit {i} (0x{(1u<<i):X8})");
                }
                ImGui.EndTable();
            }

            if (ImGui.Button("All ON##pall",  new Vector2(80, 0))) { for (int i=0;i<32;i++) _permBits[i]=true;  _permMask=0xFFFFFFFF; }
            ImGui.SameLine();
            if (ImGui.Button("All OFF##pnone",new Vector2(80, 0))) { for (int i=0;i<32;i++) _permBits[i]=false; _permMask=0; }
            ImGui.SameLine();
            ImGui.TextDisabled($"= 0x{_permMask:X8}");

            ImGui.Spacing();
            bool hasSnap = snap?.HasPlayerSetup == true;
            if (!hasSnap) { ImGui.BeginDisabled(); }
            if (ImGui.Button("Replay PlayerSetup with this mask##rps", new Vector2(-1, 28)))
            {
                byte[]? patched = _session.BuildModifiedPlayerSetup((GameMode)_gameModeIdx, _permMask);
                if (patched != null)
                {
                    _pipe.ReplaySetup(patched);
                    AddLog($"[PERM] Re-injected PlayerSetup  mode={_gameModeIdx}  mask=0x{_permMask:X8}  {patched.Length}B");
                }
            }
            if (!hasSnap) { ImGui.EndDisabled(); ImGui.TextDisabled("  (need captured session first)"); }

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

            // ── S2C drop presets ─────────────────────────────────────────────
            ImGui.TextColored(new Vector4(0.75f, 0.4f, 1f, 1f), "S2C OPCODE FILTER");
            ImGui.TextDisabled("Drop specific S2C packet types before the\ngame app processes them.");
            ImGui.Spacing();

            foreach (var (label, hex, desc) in DropPresets)
            {
                if (ImGui.Button($"{label}##dpreset{hex}", new Vector2(-1, 0)))
                {
                    _s2cDropHex = hex;
                    _s2cDropArmed = true;
                    if (uint.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out uint dropOp))
                    {
                        _pipe.S2CDropOpcode(dropOp);
                        AddLog($"[S2C-DROP] {label} (0x{dropOp:X4}) armed");
                    }
                }
                if (ImGui.IsItemHovered()) ImGui.SetTooltip(desc);
            }

            ImGui.Spacing();
            ImGui.SetNextItemWidth(90); ImGui.InputText("Custom##s2cdh", ref _s2cDropHex, 8); ImGui.SameLine();
            ImGui.PushStyleColor(ImGuiCol.Button, _s2cDropArmed ? new Vector4(0.4f,0.1f,0.6f,1f) : new Vector4(0.25f,0.25f,0.25f,1f));
            if (ImGui.Button(_s2cDropArmed ? "Armed##s2da" : "Arm##s2da"))
            {
                _s2cDropArmed = !_s2cDropArmed;
                if (_s2cDropArmed && uint.TryParse(_s2cDropHex, System.Globalization.NumberStyles.HexNumber, null, out uint dop))
                { _pipe.S2CDropOpcode(dop); AddLog($"[S2C-DROP] Custom 0x{dop:X4} armed"); }
                else { _pipe.S2CDropOpcode(0); AddLog("[S2C-DROP] Cleared"); }
            }
            ImGui.PopStyleColor();
            ImGui.SameLine();
            if (ImGui.Button("Clear All##s2dcl")) { _s2cDropArmed = false; _pipe.S2CDropOpcode(0); AddLog("[S2C-DROP] Cleared"); }
        }
        ImGui.EndChild();

        ImGui.SameLine();

        // ── Right panel: history + log ────────────────────────────────────────
        float rightW = avail.X - leftW - 8;
        ImGui.BeginChild("perm_right", new Vector2(rightW, avail.Y - 4), ImGuiChildFlags.None);
        {
            if (ImGui.BeginTabBar("perm_right_tabs"))
            {
                if (ImGui.BeginTabItem("Session History##sh"))
                {
                    RenderHistory(avail.Y - 50);
                    ImGui.EndTabItem();
                }
                if (ImGui.BeginTabItem("Activity Log##pal"))
                {
                    RenderLog(avail.Y - 50);
                    ImGui.EndTabItem();
                }
                ImGui.EndTabBar();
            }
        }
        ImGui.EndChild();
    }

    private void RenderHistory(float h)
    {
        ImGui.TextDisabled("All captured PlayerSetup snapshots this session.");
        ImGui.Separator();
        ImGui.BeginChild("perm_hist", new Vector2(-1, h - 60), ImGuiChildFlags.None);
        foreach (var snap in _session.History.AsEnumerable().Reverse().Take(10))
        {
            ImGui.TextColored(new Vector4(0.5f, 0.9f, 0.5f, 1f), $"[{snap.CapturedAt:HH:mm:ss}]");
            ImGui.SameLine();
            ImGui.TextUnformatted($"EntityID=0x{snap.SelfEntityId:X}  Mode={snap.GameModeStr}  Perms=0x{snap.PermissionMask:X8}");
            if (!string.IsNullOrEmpty(snap.WorldName)) { ImGui.SameLine(); ImGui.TextDisabled($"  World: {snap.WorldName}"); }
            ImGui.TextDisabled($"  PlayerSetup: {snap.RawPlayerSetup.Length}B   ConnectAccept: {snap.RawConnectAccept.Length}B   Auth: {snap.RawAuthToken.Length}B");
            ImGui.Separator();
        }
        if (_session.History.Count == 0) ImGui.TextDisabled("  (no snapshots yet)");
        ImGui.EndChild();
    }

    private void RenderLog(float h)
    {
        ImGui.Checkbox("Auto-scroll##permlogsc", ref _logScroll);
        ImGui.SameLine(); if (ImGui.SmallButton("Clear##permlogcl")) lock (_log) _log.Clear();
        ImGui.Separator();
        ImGui.BeginChild("perm_log", new Vector2(-1, h - 60), ImGuiChildFlags.Borders);
        List<string> snap; lock (_log) snap = _log.ToList();
        foreach (var line in snap)
        {
            Vector4 col = line.Contains("[PERM]")      ? new Vector4(1f,0.75f,0.2f,1f)
                        : line.Contains("[GAMEMODE]")  ? new Vector4(0.3f,1f,0.5f,1f)
                        : line.Contains("[S2C-DROP]")  ? new Vector4(0.75f,0.4f,1f,1f)
                        : line.Contains("[SESSION]")   ? new Vector4(0.4f,0.85f,1f,1f)
                        :                               new Vector4(0.8f,0.8f,0.8f,1f);
            ImGui.TextColored(col, line);
        }
        if (_logScroll && ImGui.GetScrollY() >= ImGui.GetScrollMaxY() - 5)
            ImGui.SetScrollHereY(1f);
        ImGui.EndChild();
    }

    private void LoadPermBits(uint mask)
    {
        for (int i = 0; i < 32; i++) _permBits[i] = (mask & (1u << i)) != 0;
        _permBitsLoaded = true;
    }

    private uint BuildPermMask()
    {
        uint m = 0;
        for (int i = 0; i < 32; i++) if (_permBits[i]) m |= (1u << i);
        return m;
    }

    private void AddLog(string msg)
    {
        var line = $"[{DateTime.Now:HH:mm:ss.fff}] {msg}";
        lock (_log) { _log.Add(line); if (_log.Count > 500) _log.RemoveAt(0); }
    }
}
