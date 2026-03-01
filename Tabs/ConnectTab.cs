// FILE: Tabs/ConnectTab.cs
using HyForce.Core;
using HyForce.UI;
using ImGuiNET;
using System.Numerics;

namespace HyForce.Tabs;

public class ConnectTab : ITab
{
    public string Name => "Connect";

    private readonly AppState _state;
    private readonly byte[] _bufServerIp = new byte[64];
    private readonly byte[] _bufServerPort = new byte[8];
    private readonly byte[] _bufUnifiedPort = new byte[8];
    private bool _showAdvanced = false;

    private int _selectedPresetIndex = 3; // Default to "Blank"

    public ConnectTab(AppState state)
    {
        _state = state;
        System.Text.Encoding.ASCII.GetBytes(state.TargetHost).CopyTo(_bufServerIp, 0);
        System.Text.Encoding.ASCII.GetBytes(state.TargetPort.ToString()).CopyTo(_bufServerPort, 0);
        System.Text.Encoding.ASCII.GetBytes(state.UnifiedPort.ToString()).CopyTo(_bufUnifiedPort, 0);
    }

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();

        ImGui.Spacing();
        ImGui.Text("  PROXY CONTROL  —  V22-Enhanced");
        ImGui.Separator();
        ImGui.Spacing();

        if (!_state.IsRunning)
        {
            ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(0.95f, 0.28f, 0.22f, 1));
            ImGui.TextWrapped("⚠  START PROXY FIRST: Then connect Hytale to 127.0.0.1:5521");
            ImGui.PopStyleColor();
        }
        else
        {
            ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(0.2f, 0.8f, 0.3f, 1));
            ImGui.TextWrapped("✓ Proxy is RUNNING - Connect Hytale to 127.0.0.1:5521 now!");
            ImGui.PopStyleColor();
        }

        float leftW = avail.X * 0.45f - 8;
        float rightW = avail.X * 0.55f - 8;

        ImGui.BeginChild("##conn_left", new Vector2(leftW, avail.Y - 140), ImGuiChildFlags.Borders);
        RenderLeftPanel(leftW);
        ImGui.EndChild();

        ImGui.SameLine(0, 8);

        ImGui.BeginChild("##conn_right", new Vector2(rightW, avail.Y - 140), ImGuiChildFlags.Borders);
        RenderRightPanel(rightW);
        ImGui.EndChild();
    }

    private void RenderLeftPanel(float leftW)
    {
        ImGui.Spacing();
        ImGui.Text("Configuration");
        ImGui.Separator();
        ImGui.Spacing();

        // SERVER PRESET SELECTOR - FIXED AND VISIBLE
        ImGui.TextColored(Theme.ColAccent, "Server Preset:");

        var presets = _state.Config.GetAllPresets();
        string[] presetNames = presets.Select(p => p.Name).ToArray();

        ImGui.SetNextItemWidth(leftW - 32);
        if (ImGui.Combo("##presetSelector", ref _selectedPresetIndex, presetNames, presetNames.Length))
        {
            var selected = presets[_selectedPresetIndex];

            if (selected.Name != "Blank" && !string.IsNullOrEmpty(selected.IpAddress))
            {
                System.Text.Encoding.ASCII.GetBytes(selected.IpAddress).CopyTo(_bufServerIp, 0);
                System.Text.Encoding.ASCII.GetBytes(selected.Port.ToString()).CopyTo(_bufServerPort, 0);
                _state.TargetHost = selected.IpAddress;
                _state.TargetPort = selected.Port;

                _state.AddInGameLog($"[PRESET] Loaded {selected.Name}: {selected.IpAddress}:{selected.Port}");
            }
            else
            {
                Array.Clear(_bufServerIp, 0, _bufServerIp.Length);
                Array.Clear(_bufServerPort, 0, _bufServerPort.Length);
                System.Text.Encoding.ASCII.GetBytes("5520").CopyTo(_bufServerPort, 0);
                _state.TargetHost = "";
                _state.TargetPort = 5520;
            }
        }

        if (_selectedPresetIndex < presets.Count)
        {
            var current = presets[_selectedPresetIndex];
            if (!string.IsNullOrEmpty(current.Description))
            {
                ImGui.TextColored(Theme.ColTextMuted, $"  {current.Description}");
            }
            if (!string.IsNullOrEmpty(current.IpAddress))
            {
                ImGui.TextColored(Theme.ColTextMuted, $"  {current.IpAddress}:{current.Port}");
            }
        }

        ImGui.Spacing();
        ImGui.Separator();
        ImGui.Spacing();

        // MANUAL SERVER CONFIGURATION WITH COPY-PASTE

        ImGui.Text("Target Server IP:");
        RenderInputWithPaste("##srvIp", _bufServerIp, (val) => _state.TargetHost = val, leftW - 32);

        ImGui.Spacing();

        ImGui.Text("Server Port:");
        RenderPortInputWithPaste("##srvPort", _bufServerPort, (val) => { if (int.TryParse(val, out int p)) _state.TargetPort = p; }, 120);

        ImGui.Spacing();
        ImGui.Separator();
        ImGui.Spacing();

        ImGui.Text("Proxy Mode:");
        bool unified = _state.UseUnifiedPort;

        if (ImGui.Button("  UNIFIED PORT  ", new Vector2(140, 28)))
            _state.UseUnifiedPort = true;
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("TCP + UDP on same port (like real Hytale server)");

        ImGui.SameLine();

        if (ImGui.Button("  SEPARATE PORTS  ", new Vector2(140, 28)))
            _state.UseUnifiedPort = false;
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("TCP and UDP on different ports");

        ImGui.Spacing();
        ImGui.Separator();
        ImGui.Spacing();

        if (_state.UseUnifiedPort)
        {
            ImGui.Text("Unified Port (TCP + UDP):");
            RenderPortInputWithPaste("##unifiedPort", _bufUnifiedPort, (val) => { if (int.TryParse(val, out int p)) _state.UnifiedPort = p; }, 120);

            ImGui.Spacing();
            ImGui.TextColored(new Vector4(0.2f, 0.8f, 0.2f, 1),
                $"Connect to: 127.0.0.1:{_state.UnifiedPort}");
            ImGui.TextWrapped("Both registry (TCP) and gameplay (UDP) on this single port");
        }
        else
        {
            ImGui.Text("TCP Port (Registry):");
            ImGui.TextColored(Theme.ColAccent, $"127.0.0.1:{_state.TcpListenPort}");
            ImGui.Spacing();
            ImGui.Text("UDP Port (Gameplay):");
            ImGui.TextColored(Theme.ColAccent, $"127.0.0.1:{_state.UdpListenPort}");
        }

        ImGui.Spacing();

        if (!_state.IsRunning)
        {
            ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.2f, 0.7f, 0.3f, 1f));
            if (ImGui.Button("  START PROXIES  ", new Vector2(leftW - 24, 40)))
                _state.Start();
            ImGui.PopStyleColor();
        }
        else
        {
            ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.9f, 0.3f, 0.2f, 1f));
            if (ImGui.Button("  STOP PROXIES  ", new Vector2(leftW - 24, 40)))
                _state.Stop();
            ImGui.PopStyleColor();
        }

        ImGui.Spacing();
        if (ImGui.Button("Clear All Data", new Vector2(leftW - 24, 28)))
            _state.ClearAll();

        ImGui.Spacing();
        ImGui.Checkbox("Show Advanced/Debug", ref _showAdvanced);

        if (_showAdvanced)
        {
            ImGui.Spacing();
            ImGui.TextColored(Theme.ColWarn, "Advanced Options:");
            if (ImGui.Button("Force TCP Bind to 127.0.0.1", new Vector2(leftW - 24, 28)))
            {
                _state.TcpListenPort = 5521;
                _state.AddInGameLog("[DEBUG] Forced TCP to 127.0.0.1:5521");
            }
            if (ImGui.IsItemHovered())
                ImGui.SetTooltip("Some systems require explicit localhost binding");

            if (ImGui.Button("Test Local Connection", new Vector2(leftW - 24, 28)))
            {
                TestLocalConnection();
            }

            if (ImGui.Button("Copy Config to Clipboard", new Vector2(leftW - 24, 28)))
            {
                var configText = $"Server: {_state.TargetHost}:{_state.TargetPort}\n" +
                               $"Mode: {(_state.UseUnifiedPort ? "Unified" : "Separate")}\n" +
                               $"Listen: 127.0.0.1:{_state.UnifiedPort}";
                CopyToClipboard(configText);
                _state.AddInGameLog("[DEBUG] Config copied to clipboard");
            }
        }
    }

    private void RenderInputWithPaste(string id, byte[] buffer, Action<string> onChange, float width)
    {
        float inputWidth = width - 70;

        ImGui.SetNextItemWidth(inputWidth);
        ImGui.PushID(id);

        if (ImGui.InputText("", buffer, (uint)buffer.Length, ImGuiInputTextFlags.AutoSelectAll))
        {
            string val = System.Text.Encoding.ASCII.GetString(buffer).TrimEnd('\0');
            onChange(val);
        }

        ImGui.PopID();

        ImGui.SameLine();

        ImGui.PushID(id + "_paste");
        if (ImGui.Button("Paste", new Vector2(60, 0)))
        {
            string? clipboard = GetClipboardText();
            if (!string.IsNullOrEmpty(clipboard))
            {
                Array.Clear(buffer, 0, buffer.Length);
                var bytes = System.Text.Encoding.ASCII.GetBytes(clipboard);
                int copyLength = Math.Min(bytes.Length, buffer.Length - 1);
                Array.Copy(bytes, buffer, copyLength);

                string val = System.Text.Encoding.ASCII.GetString(buffer).TrimEnd('\0');
                onChange(val);

                _state.AddInGameLog($"[PASTE] Pasted into {id}");
            }
        }
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("Paste from clipboard");
        ImGui.PopID();
    }

    private void RenderPortInputWithPaste(string id, byte[] buffer, Action<string> onChange, float width)
    {
        float inputWidth = width - 70;

        ImGui.SetNextItemWidth(inputWidth);
        ImGui.PushID(id);

        if (ImGui.InputText("", buffer, (uint)buffer.Length,
            ImGuiInputTextFlags.CharsDecimal | ImGuiInputTextFlags.AutoSelectAll))
        {
            string val = System.Text.Encoding.ASCII.GetString(buffer).TrimEnd('\0');
            onChange(val);
        }

        ImGui.PopID();

        ImGui.SameLine();

        ImGui.PushID(id + "_paste");
        if (ImGui.Button("Paste", new Vector2(60, 0)))
        {
            string? clipboard = GetClipboardText();
            if (!string.IsNullOrEmpty(clipboard))
            {
                var digits = new string(clipboard.Where(char.IsDigit).ToArray());
                if (!string.IsNullOrEmpty(digits))
                {
                    Array.Clear(buffer, 0, buffer.Length);
                    var bytes = System.Text.Encoding.ASCII.GetBytes(digits);
                    int copyLength = Math.Min(bytes.Length, buffer.Length - 1);
                    Array.Copy(bytes, buffer, copyLength);

                    string val = System.Text.Encoding.ASCII.GetString(buffer).TrimEnd('\0');
                    onChange(val);

                    _state.AddInGameLog($"[PASTE] Pasted port: {val}");
                }
            }
        }
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("Paste from clipboard");
        ImGui.PopID();
    }

    private void RenderRightPanel(float rightW)
    {
        ImGui.Spacing();
        ImGui.Text("Status & Diagnostics");
        ImGui.Separator();
        ImGui.Spacing();

        RenderStatusIndicator("TCP Proxy", _state.TcpProxy.IsRunning,
            _state.TcpProxy.IsRunning ? $"Port {_state.TcpProxy.ListenPort}" : "Stopped",
            _state.TcpProxy.ActiveSessions);

        ImGui.Spacing();

        RenderStatusIndicator("UDP Proxy", _state.UdpProxy.IsRunning,
            _state.UdpProxy.IsRunning ? $"Port {_state.UdpProxy.ListenPort}" : "Stopped",
            _state.UdpProxy.ActiveSessions);

        ImGui.Spacing();
        ImGui.Separator();
        ImGui.Spacing();

        ImGui.Text("Traffic Statistics");
        ImGui.Separator();
        ImGui.Spacing();

        ImGui.TextColored(Theme.ColAccent, $"{_state.TotalPackets:N0}");
        ImGui.SameLine();
        ImGui.Text("total packets");

        ImGui.Columns(2, "##traffic", false);
        ImGui.Text($"TCP: {_state.TcpPackets:N0}");
        ImGui.NextColumn();
        ImGui.Text($"UDP: {_state.UdpPackets:N0}");
        ImGui.NextColumn();
        ImGui.Columns(1);

        ImGui.Spacing();
        ImGui.Text($"Unique Opcodes: {_state.PacketLog.UniqueOpcodes}");

        ImGui.Spacing();
        ImGui.Separator();
        ImGui.Spacing();

        ImGui.Text("Registry Status");
        ImGui.Separator();
        ImGui.Spacing();

        bool regRx = Protocol.RegistrySyncParser.RegistrySyncReceived;

        var regColor = regRx ? Theme.ColSuccess : Theme.ColWarn;
        var drawList = ImGui.GetWindowDrawList();
        var pos = ImGui.GetCursorScreenPos();
        drawList.AddRectFilled(pos, pos + new Vector2(20, 20),
            ImGui.ColorConvertFloat4ToU32(regColor), 4);
        ImGui.Dummy(new Vector2(25, 20));
        ImGui.SameLine();
        ImGui.TextColored(regColor, regRx ? "RegistrySync RECEIVED ✓" : "Waiting for RegistrySync...");

        if (regRx)
        {
            ImGui.Text($"Items Parsed: {Protocol.RegistrySyncParser.NumericIdToName.Count:N0}");
            ImGui.Text($"Players Seen: {Protocol.RegistrySyncParser.PlayerNamesSeen.Count:N0}");

            if (ImGui.Button("Copy Item List", new Vector2(120, 0)))
            {
                var items = string.Join("\n", Protocol.RegistrySyncParser.NumericIdToName.Select(x => $"{x.Key:X8}: {x.Value}"));
                CopyToClipboard(items);
                _state.AddInGameLog("[COPY] Item list copied to clipboard");
            }
        }
        else
        {
            int port = _state.UseUnifiedPort ? _state.UnifiedPort : _state.TcpListenPort;
            ImGui.TextColored(new Vector4(0.9f, 0.3f, 0.2f, 1),
                $"Connect Hytale to 127.0.0.1:{port}");

            ImGui.Spacing();
            ImGui.TextColored(Theme.ColTextMuted, "Troubleshooting:");
            ImGui.TextWrapped("1. Make sure proxy is STARTED (green button)");
            ImGui.TextWrapped("2. Close Hytale completely");
            ImGui.TextWrapped("3. Launch Hytale, connect to 127.0.0.1:" + port);
            ImGui.TextWrapped("4. Check Windows Firewall isn't blocking");
        }

        if (_showAdvanced)
        {
            ImGui.Spacing();
            ImGui.Separator();
            ImGui.TextColored(Theme.ColWarn, "Debug Info:");
            ImGui.Text($"Target: {_state.TargetHost}:{_state.TargetPort}");
            ImGui.Text($"Listen: 127.0.0.1:{_state.UnifiedPort}");
            ImGui.Text($"TCP Status: {_state.TcpProxy.StatusMessage}");
            ImGui.Text($"UDP Status: {_state.UdpProxy.StatusMessage}");

            if (ImGui.Button("Copy Debug Info", new Vector2(120, 0)))
            {
                CopyToClipboard($"Target: {_state.TargetHost}:{_state.TargetPort}\n" +
                              $"TCP: {_state.TcpProxy.StatusMessage}\n" +
                              $"UDP: {_state.UdpProxy.StatusMessage}");
            }
        }
    }

    private void RenderStatusIndicator(string name, bool isRunning, string status, int sessions)
    {
        var color = isRunning ? Theme.ColSuccess : Theme.ColDanger;
        var drawList = ImGui.GetWindowDrawList();
        var pos = ImGui.GetCursorScreenPos();
        drawList.AddCircleFilled(pos + new Vector2(10, 10), 8,
            ImGui.ColorConvertFloat4ToU32(color));
        ImGui.Dummy(new Vector2(25, 20));

        ImGui.SameLine();
        ImGui.BeginGroup();
        ImGui.TextColored(color, name);
        ImGui.TextColored(Theme.ColTextMuted, status);
        if (isRunning)
        {
            ImGui.SameLine();
            ImGui.TextColored(Theme.ColTextMuted, $"• {sessions} sessions");
        }
        ImGui.EndGroup();
    }

    private void TestLocalConnection()
    {
        try
        {
            using var client = new System.Net.Sockets.TcpClient();
            client.Connect("127.0.0.1", _state.UnifiedPort);
            _state.AddInGameLog($"[TEST] Successfully connected to 127.0.0.1:{_state.UnifiedPort}");
            client.Close();
        }
        catch (Exception ex)
        {
            _state.AddInGameLog($"[TEST] Connection failed: {ex.Message}");
        }
    }

    // CROSS-PLATFORM CLIPBOARD HELPERS using TextCopy
    private string? GetClipboardText()
    {
        try
        {
            return TextCopy.ClipboardService.GetText();
        }
        catch
        {
            return null;
        }
    }

    private void CopyToClipboard(string text)
    {
        try
        {
            TextCopy.ClipboardService.SetText(text);
        }
        catch (Exception ex)
        {
            _state.AddInGameLog($"[ERROR] Failed to copy: {ex.Message}");
        }
    }
}