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
    private bool _showAdvanced = false;
    private double _copyFeedbackTime = 0;
    private int _selectedPresetIndex = -1;
    public ConnectTab(AppState state)
    {
        _state = state;
        System.Text.Encoding.ASCII.GetBytes(state.TargetHost).CopyTo(_bufServerIp, 0);
        System.Text.Encoding.ASCII.GetBytes(state.TargetPort.ToString()).CopyTo(_bufServerPort, 0);
    }

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();

        ImGui.Spacing();
        ImGui.Text("  PROXY CONTROL  -  V22-Enhanced (UDP-ONLY MODE)");
        ImGui.Separator();
        ImGui.Spacing();

        if (!_state.IsRunning)
        {
            ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(0.95f, 0.28f, 0.22f, 1));
            ImGui.TextWrapped("⚠  START PROXY FIRST: Then connect Hytale to 127.0.0.1:5521 (auto-copied to clipboard)");
            ImGui.PopStyleColor();
        }
        else
        {
            ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(0.2f, 0.8f, 0.3f, 1));
            ImGui.TextWrapped("✓ Proxy is RUNNING - Connect Hytale to 127.0.0.1:5521 (copied to clipboard!)");
            ImGui.PopStyleColor();

            // Show copy feedback
            if (ImGui.GetTime() - _copyFeedbackTime < 3.0)
            {
                ImGui.TextColored(new Vector4(0.2f, 0.9f, 0.2f, 1),
                    "✓ 127.0.0.1:5521 copied to clipboard!");
            }
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

        // Server preset selector - ADD THIS SECTION
        var presets = _state.Config.GetAllPresets();
        string[] displayNames = presets.Select(p =>
            string.IsNullOrEmpty(p.IpAddress) ? $"{p.Name} (Custom)" : $"{p.Name} ({p.IpAddress})"
        ).ToArray();

        ImGui.Text("Server Preset:");
        ImGui.SetNextItemWidth(leftW - 24);

        if (ImGui.Combo("##preset", ref _selectedPresetIndex, displayNames, displayNames.Length))
        {
            if (_selectedPresetIndex >= 0 && _selectedPresetIndex < presets.Count)
            {
                var selected = presets[_selectedPresetIndex];
                _state.TargetHost = selected.IpAddress;
                _state.TargetPort = selected.Port;

                // Update the input buffers
                Array.Clear(_bufServerIp, 0, _bufServerIp.Length);
                Array.Clear(_bufServerPort, 0, _bufServerPort.Length);
                System.Text.Encoding.ASCII.GetBytes(selected.IpAddress).CopyTo(_bufServerIp, 0);
                System.Text.Encoding.ASCII.GetBytes(selected.Port.ToString()).CopyTo(_bufServerPort, 0);

                _state.AddInGameLog($"[CONFIG] Selected preset: {selected.Name} ({selected.IpAddress}:{selected.Port})");
            }
        }

        // Show current selection info
        if (_selectedPresetIndex >= 0 && _selectedPresetIndex < presets.Count)
        {
            var current = presets[_selectedPresetIndex];
            ImGui.TextColored(Theme.ColTextMuted, $"Selected: {current.Name}");
            if (!string.IsNullOrEmpty(current.Description))
            {
                ImGui.TextColored(Theme.ColTextMuted, current.Description);
            }
        }

        ImGui.Spacing();

        ImGui.Text("Target Server IP:");
        RenderInputWithPaste("##srvIp", _bufServerIp, (val) => _state.TargetHost = val, leftW - 32);

        ImGui.Spacing();

        ImGui.Text("Server Port:");
        RenderPortInputWithPaste("##srvPort", _bufServerPort, (val) => {
            if (int.TryParse(val, out int p)) _state.TargetPort = p;
        }, 120);

        ImGui.Spacing();
        ImGui.Separator();
        ImGui.Spacing();

        // REMOVED: UDP-ONLY INFO - Now supports both TCP and UDP properly
        ImGui.TextColored(Theme.ColAccent, "Mode: TCP + UDP (Full Proxy)");
        ImGui.TextWrapped("Hytale uses QUIC over UDP for gameplay and TCP for registry sync.");
        ImGui.Spacing();

        ImGui.Text("Listen Ports:");
        ImGui.TextColored(new Vector4(0.2f, 0.8f, 0.2f, 1), $"UDP (Gameplay): 127.0.0.1:{_state.ListenPort}");
        ImGui.TextColored(new Vector4(0.2f, 0.8f, 0.2f, 1), $"TCP (Registry): 127.0.0.1:{_state.ListenPort + 1}");
        ImGui.TextWrapped("Connect Hytale to the UDP port (auto-copied when starting)");

        if (!_state.IsRunning)
        {
            ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.2f, 0.7f, 0.3f, 1f));
            if (ImGui.Button("  START PROXY  ", new Vector2(leftW - 24, 40)))
            {
                _state.Start();
                _copyFeedbackTime = ImGui.GetTime();
            }
            ImGui.PopStyleColor();
        }
        else
        {
            ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.9f, 0.3f, 0.2f, 1f));
            if (ImGui.Button("  STOP PROXY  ", new Vector2(leftW - 24, 40)))
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

            if (ImGui.Button("Force Rebind UDP Port", new Vector2(leftW - 24, 28)))
            {
                _state.ListenPort = 5521;
                _state.AddInGameLog("[DEBUG] Forced UDP to 0.0.0.0:5521");
            }

            if (ImGui.Button("Test Local Connection", new Vector2(leftW - 24, 28)))
            {
                TestLocalConnection();
            }

            if (ImGui.Button("Copy Config to Clipboard", new Vector2(leftW - 24, 28)))
            {
                var configText = $"Server: {_state.TargetHost}:{_state.TargetPort}\\n" +
                               $"Mode: UDP-ONLY\\n" +
                               $"Listen: 127.0.0.1:{_state.ListenPort}";
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

            // CRITICAL FIX: Validate port range
            if (int.TryParse(val, out int port))
            {
                if (port < 1 || port > 65535)
                {
                    _state.AddInGameLog("[ERROR] Port must be between 1-65535");
                    return;
                }
            }

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
                    // CRITICAL FIX: Validate pasted port
                    if (int.TryParse(digits, out int port))
                    {
                        if (port < 1 || port > 65535)
                        {
                            _state.AddInGameLog("[ERROR] Pasted port must be between 1-65535");
                            return;
                        }
                    }

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

        // REMOVED: TCP status - UDP only
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

        ImGui.Text($"UDP: {_state.UdpPackets:N0} (Gameplay only)");

        ImGui.Spacing();
        ImGui.Text($"Unique Opcodes: {_state.PacketLog.UniqueOpcodes}");

        ImGui.Spacing();
        ImGui.Separator();
        ImGui.Spacing();

        ImGui.TextColored(Theme.ColAccent, "Auto-Copy Feature");
        ImGui.TextWrapped("When you click 'START PROXY', the connect address");
        ImGui.TextColored(new Vector4(0.2f, 0.9f, 0.2f, 1), "127.0.0.1:5521");
        ImGui.TextWrapped("is automatically copied to your clipboard. Just paste it into Hytale!");

        if (_showAdvanced)
        {
            ImGui.Spacing();
            ImGui.Separator();
            ImGui.TextColored(Theme.ColWarn, "Debug Info:");
            ImGui.Text($"Target: {_state.TargetHost}:{_state.TargetPort}");
            ImGui.Text($"Listen: 0.0.0.0:{_state.ListenPort}");
            ImGui.Text($"UDP Status: {_state.UdpProxy.StatusMessage}");

            if (ImGui.Button("Copy Debug Info", new Vector2(120, 0)))
            {
                CopyToClipboard($"Target: {_state.TargetHost}:{_state.TargetPort}\\n" +
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
            ImGui.TextColored(Theme.ColTextMuted, $"● {sessions} sessions");
        }
        ImGui.EndGroup();
    }

    private void TestLocalConnection()
    {
        try
        {
            using var client = new System.Net.Sockets.UdpClient();
            client.Connect("127.0.0.1", _state.ListenPort);
            _state.AddInGameLog($"[TEST] UDP port {_state.ListenPort} is reachable");
            client.Close();
        }
        catch (Exception ex)
        {
            _state.AddInGameLog($"[TEST] Connection test: {ex.Message}");
        }
    }

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
        try { TextCopy.ClipboardService.SetText(text); } catch { }
    }
}