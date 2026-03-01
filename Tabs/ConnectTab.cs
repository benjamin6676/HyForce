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

        // CRITICAL WARNING
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

        // Mode selector
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

        // Server IP
        ImGui.Text("Target Server IP:");
        ImGui.SetNextItemWidth(leftW - 32);
        if (ImGui.InputText("##srvIp", _bufServerIp, (uint)_bufServerIp.Length))
            _state.TargetHost = System.Text.Encoding.ASCII.GetString(_bufServerIp).TrimEnd('\0');

        ImGui.Spacing();
        ImGui.Text("Server Port:");
        ImGui.SetNextItemWidth(90);
        if (ImGui.InputText("##srvPort", _bufServerPort, (uint)_bufServerPort.Length))
            if (int.TryParse(System.Text.Encoding.ASCII.GetString(_bufServerPort).TrimEnd('\0'), out int p))
                _state.TargetPort = p;

        ImGui.Spacing();
        ImGui.Separator();
        ImGui.Spacing();

        // Port configuration
        if (_state.UseUnifiedPort)
        {
            ImGui.Text("Unified Port (TCP + UDP):");
            ImGui.SetNextItemWidth(90);
            if (ImGui.InputText("##unifiedPort", _bufUnifiedPort, (uint)_bufUnifiedPort.Length))
                if (int.TryParse(System.Text.Encoding.ASCII.GetString(_bufUnifiedPort).TrimEnd('\0'), out int p))
                    _state.UnifiedPort = p;

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

        // Control buttons
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

        // Advanced options
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
        }
    }

    private void RenderRightPanel(float rightW)
    {
        ImGui.Spacing();
        ImGui.Text("Status & Diagnostics");
        ImGui.Separator();
        ImGui.Spacing();

        // Visual status indicators
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

        // Traffic stats
        ImGui.Text("Traffic Statistics");
        ImGui.Separator();
        ImGui.Spacing();

        // Big numbers
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

        // Registry status
        ImGui.Text("Registry Status");
        ImGui.Separator();
        ImGui.Spacing();

        bool regRx = Protocol.RegistrySyncParser.RegistrySyncReceived;

        // Big registry indicator
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

        // Debug info
        if (_showAdvanced)
        {
            ImGui.Spacing();
            ImGui.Separator();
            ImGui.TextColored(Theme.ColWarn, "Debug Info:");
            ImGui.Text($"Target: {_state.TargetHost}:{_state.TargetPort}");
            ImGui.Text($"Listen: 127.0.0.1:{_state.UnifiedPort}");
            ImGui.Text($"TCP Status: {_state.TcpProxy.StatusMessage}");
            ImGui.Text($"UDP Status: {_state.UdpProxy.StatusMessage}");
        }
    }

    private void RenderStatusIndicator(string name, bool isRunning, string status, int sessions)
    {
        // Color dot
        var color = isRunning ? Theme.ColSuccess : Theme.ColDanger;
        var drawList = ImGui.GetWindowDrawList();
        var pos = ImGui.GetCursorScreenPos();
        drawList.AddCircleFilled(pos + new Vector2(10, 10), 8,
            ImGui.ColorConvertFloat4ToU32(color));
        ImGui.Dummy(new Vector2(25, 20));

        // Status text
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
}