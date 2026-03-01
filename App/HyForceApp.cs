// FILE: App/HyForceApp.cs - FIXED: PROPER EVENT ACCESS AND MENU
using HyForce.Core;
using HyForce.Tabs;
using HyForce.UI;
using HyForce.Protocol;
using ImGuiNET;
using Veldrid;
using Veldrid.Sdl2;
using System.Numerics;

namespace HyForce.App;

public class HyForceApp
{
    private readonly Sdl2Window _window;
    private readonly GraphicsDevice _graphicsDevice;
    private readonly ImGuiController _imguiController;
    private readonly CommandList _commandList;

    private readonly AppState _state;
    private readonly Protocol.PacketHandler _packetHandler;
    private readonly List<ITab> _tabs = new();
    private readonly Theme _theme;
    private int _selectedTab = 0;

    public HyForceApp(Sdl2Window window, GraphicsDevice graphicsDevice)
    {
        _window = window;
        _graphicsDevice = graphicsDevice;

        _imguiController = new ImGuiController(
            graphicsDevice,
            graphicsDevice.MainSwapchain.Framebuffer.OutputDescription,
            window.Width,
            window.Height
        );

        _commandList = graphicsDevice.ResourceFactory.CreateCommandList();

        _state = AppState.Instance;
        _theme = new Theme();

        _packetHandler = new Protocol.PacketHandler(_state);

        // Only UDP handler
        _state.UdpProxy.OnPacket += _packetHandler.ProcessPacket;

        InitializeTabs();
        SetupImGuiStyle();
    }

    private void InitializeTabs()
    {
        _tabs.Add(new ConnectTab(_state));
        _tabs.Add(new ItemsTab(_state));
        _tabs.Add(new PacketFeedTab(_state));
        _tabs.Add(new SecurityAuditTab(_state));
        _tabs.Add(new LogTab(_state));
        _tabs.Add(new MemoryTab(_state));        // Memory scanner
        _tabs.Add(new DecryptionTab(_state));    // Decryption management
        _tabs.Add(new SettingsTab(_state));
    }

    private void SetupImGuiStyle()
    {
        var io = ImGui.GetIO();
        io.ConfigFlags |= ImGuiConfigFlags.NavEnableKeyboard;
        _theme.Apply();
    }

    public void Run()
    {
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        double previousFrameTime = 0;

        while (_window.Exists)
        {
            double currentTime = stopwatch.Elapsed.TotalSeconds;
            double deltaTime = currentTime - previousFrameTime;
            previousFrameTime = currentTime;

            var snapshot = _window.PumpEvents();
            if (!_window.Exists) break;

            _imguiController.Update((float)deltaTime, snapshot);

            RenderFrame();

            _commandList.Begin();
            _commandList.SetFramebuffer(_graphicsDevice.MainSwapchain.Framebuffer);
            _commandList.ClearColorTarget(0, new RgbaFloat(0.08f, 0.08f, 0.10f, 1.0f));
            _imguiController.Render(_graphicsDevice, _commandList);
            _commandList.End();

            _graphicsDevice.SubmitCommands(_commandList);
            _graphicsDevice.SwapBuffers(_graphicsDevice.MainSwapchain);
        }

        _state.Dispose();
    }

    private void RenderFrame()
    {
        var viewport = ImGui.GetMainViewport();

        ImGui.SetNextWindowPos(viewport.WorkPos);
        ImGui.SetNextWindowSize(viewport.WorkSize);
        ImGui.SetNextWindowViewport(viewport.ID);

        var windowFlags =
            ImGuiWindowFlags.MenuBar |
            ImGuiWindowFlags.NoTitleBar |
            ImGuiWindowFlags.NoCollapse |
            ImGuiWindowFlags.NoResize |
            ImGuiWindowFlags.NoMove |
            ImGuiWindowFlags.NoBringToFrontOnFocus |
            ImGuiWindowFlags.NoNavFocus |
            ImGuiWindowFlags.NoBackground;

        ImGui.PushStyleVar(ImGuiStyleVar.WindowRounding, 0.0f);
        ImGui.PushStyleVar(ImGuiStyleVar.WindowBorderSize, 0.0f);
        ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, new Vector2(0, 0));

        ImGui.Begin("MainWindow", windowFlags);
        ImGui.PopStyleVar(3);

        RenderMenuBar();
        RenderTabBar();

        ImGui.BeginChild("TabContent", new Vector2(0, 0), ImGuiChildFlags.None);
        _tabs[_selectedTab].Render();
        ImGui.EndChild();

        ImGui.End();

        if (_state.ShowAboutWindow)
        {
            RenderAboutWindow();
        }
    }

    private void RenderMenuBar()
    {
        if (ImGui.BeginMenuBar())
        {
            if (ImGui.BeginMenu("File"))
            {
                if (ImGui.MenuItem("Export Diagnostics", "Ctrl+E"))
                {
                    ExportDiagnostics();
                }

                if (ImGui.MenuItem("Export Packet Log", "Ctrl+P"))
                {
                    ExportPacketLog();
                }

                if (ImGui.MenuItem("Export All Logs", "Ctrl+Shift+E"))
                {
                    ExportAllLogs();
                }

                ImGui.Separator();

                if (ImGui.MenuItem("Exit", "Alt+F4"))
                {
                    _window.Close();
                }

                ImGui.EndMenu();
            }

            if (ImGui.BeginMenu("View"))
            {
                bool showTs = _state.Config.ShowTimestamps;
                if (ImGui.MenuItem("Show Timestamps", "", showTs))
                {
                    _state.Config.ShowTimestamps = !showTs;
                }

                bool autoScroll = _state.Config.AutoScrollLogs;
                if (ImGui.MenuItem("Auto-scroll Logs", "", autoScroll))
                {
                    _state.Config.AutoScrollLogs = !autoScroll;
                }

                bool darkTheme = _state.Config.DarkTheme;
                if (ImGui.MenuItem("Dark Theme", "", darkTheme))
                {
                    _state.Config.DarkTheme = !darkTheme;
                    _theme.Apply();
                }

                ImGui.EndMenu();
            }

            if (ImGui.BeginMenu("Tools"))
            {
                if (ImGui.MenuItem("Clear All Data"))
                {
                    _state.ClearAll();
                }

                if (ImGui.MenuItem("Generate Diagnostics Report"))
                {
                    string report = _state.GenerateDiagnostics();
                    Console.WriteLine(report);
                    _state.AddInGameLog("Diagnostics report generated");
                }

                if (ImGui.MenuItem("Open Export Folder"))
                {
                    try
                    {
                        System.Diagnostics.Process.Start("explorer.exe", _state.ExportDirectory);
                    }
                    catch { }
                }

                // FIXED: Memory Tab now properly accessible from menu
                ImGui.Separator();
                if (ImGui.MenuItem("Memory Scanner", "Ctrl+M"))
                {
                    // Switch to Memory tab
                    for (int i = 0; i < _tabs.Count; i++)
                    {
                        if (_tabs[i] is MemoryTab)
                        {
                            _selectedTab = i;
                            break;
                        }
                    }
                }

                // FIXED: Use public method instead of direct event access
                if (ImGui.MenuItem("Quick Memory Scan", "Ctrl+Shift+M"))
                {
                    _state.TriggerMemoryScan();
                }

                ImGui.EndMenu();
            }

            if (ImGui.BeginMenu("Help"))
            {
                if (ImGui.MenuItem("About HyForce"))
                {
                    _state.ShowAboutWindow = true;
                }

                ImGui.EndMenu();
            }

            ImGui.EndMenuBar();
        }
    }

    private void RenderTabBar()
    {
        ImGui.BeginChild("TabBar", new Vector2(0, 40), ImGuiChildFlags.None);

        ImGui.PushStyleVar(ImGuiStyleVar.ItemSpacing, new Vector2(4, 0));

        for (int i = 0; i < _tabs.Count; i++)
        {
            bool isSelected = _selectedTab == i;

            if (isSelected)
            {
                ImGui.PushStyleColor(ImGuiCol.Button, Theme.ColAccent);
                ImGui.PushStyleColor(ImGuiCol.ButtonHovered, Theme.ColAccent);
                ImGui.PushStyleColor(ImGuiCol.ButtonActive, Theme.ColAccent);
            }
            else
            {
                ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.12f, 0.12f, 0.15f, 1f));
            }

            if (ImGui.Button(_tabs[i].Name, new Vector2(100, 32)))
            {
                _selectedTab = i;
            }

            ImGui.PopStyleColor(isSelected ? 3 : 1);

            if (i < _tabs.Count - 1)
                ImGui.SameLine();
        }

        ImGui.PopStyleVar();
        ImGui.EndChild();

        ImGui.Separator();
    }

    private void RenderAboutWindow()
    {
        ImGui.SetNextWindowSize(new Vector2(400, 300), ImGuiCond.FirstUseEver);
        ImGui.SetNextWindowPos(ImGui.GetIO().DisplaySize * 0.5f, ImGuiCond.FirstUseEver, new Vector2(0.5f, 0.5f));

        bool showWindow = _state.ShowAboutWindow;

        if (ImGui.Begin("About HyForce", ref showWindow, ImGuiWindowFlags.NoCollapse | ImGuiWindowFlags.NoResize))
        {
            _state.ShowAboutWindow = showWindow;

            var windowWidth = ImGui.GetWindowWidth();

            ImGui.Spacing();

            var titleSize = ImGui.CalcTextSize(Constants.BuildName);
            ImGui.SetCursorPosX((windowWidth - titleSize.X) * 0.5f);
            ImGui.Text(Constants.BuildName);

            ImGui.Spacing();

            var subtitleSize = ImGui.CalcTextSize(Constants.AppSubtitle);
            ImGui.SetCursorPosX((windowWidth - subtitleSize.X) * 0.5f);
            ImGui.TextColored(Theme.ColTextMuted, Constants.AppSubtitle);

            ImGui.Spacing();
            ImGui.Separator();
            ImGui.Spacing();

            ImGui.Text($"Version: {Constants.BuildVersion}");
            ImGui.Text($"Build Date: {Constants.BuildDate}");

            ImGui.Spacing();
            ImGui.Separator();
            ImGui.Spacing();

            ImGui.TextWrapped("HyForce is a network security analysis tool for Hytale. " +
                "It captures and analyzes UDP (QUIC gameplay) traffic " +
                "to help identify security vulnerabilities and understand game protocol behavior. " +
                "Hytale uses UDP/QUIC only - no TCP required!");

            ImGui.Spacing();
            ImGui.Separator();
            ImGui.Spacing();

            ImGui.TextColored(Theme.ColAccent, "Decryption Status:");
            ImGui.Text($"Keys Available: {PacketDecryptor.DiscoveredKeys.Count}");
            ImGui.Text($"Packets Decrypted: {PacketDecryptor.SuccessfulDecryptions}");
            ImGui.Text($"Packets Failed: {PacketDecryptor.FailedDecryptions}");

            ImGui.Spacing();
            ImGui.Separator();
            ImGui.Spacing();

            var buttonWidth = 100f;
            ImGui.SetCursorPosX((windowWidth - buttonWidth) * 0.5f);
            if (ImGui.Button("Close", new Vector2(buttonWidth, 30)))
            {
                _state.ShowAboutWindow = false;
            }
        }
        ImGui.End();

        _state.ShowAboutWindow = showWindow;
    }

    private void ExportDiagnostics()
    {
        try
        {
            string report = _state.GenerateDiagnostics();
            string filename = Path.Combine(_state.ExportDirectory,
                $"hyforce_diagnostics_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
            File.WriteAllText(filename, report);
            _state.Log.Success($"Diagnostics exported to {filename}", "Export");
            _state.AddInGameLog($"[SUCCESS] Diagnostics exported to {filename}");
        }
        catch (Exception ex)
        {
            _state.Log.Error($"Export failed: {ex.Message}", "Export");
            _state.AddInGameLog($"[ERROR] Export failed: {ex.Message}");
        }
    }

    private void ExportPacketLog()
    {
        try
        {
            string report = _state.ExportPacketLog();
            string filename = Path.Combine(_state.ExportDirectory,
                $"hyforce_packets_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
            File.WriteAllText(filename, report);
            _state.Log.Success($"Packet log exported to {filename}", "Export");
            _state.AddInGameLog($"[SUCCESS] Packet log exported to {filename}");
        }
        catch (Exception ex)
        {
            _state.Log.Error($"Export failed: {ex.Message}", "Export");
            _state.AddInGameLog($"[ERROR] Export failed: {ex.Message}");
        }
    }

    private void ExportAllLogs()
    {
        try
        {
            string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            string basePath = Path.Combine(_state.ExportDirectory, $"hyforce_full_export_{timestamp}");
            Directory.CreateDirectory(basePath);

            File.WriteAllText(Path.Combine(basePath, "diagnostics.txt"), _state.GenerateDiagnostics());
            File.WriteAllText(Path.Combine(basePath, "packets.txt"), _state.ExportPacketLog());

            lock (_state.InGameLog)
            {
                File.WriteAllLines(Path.Combine(basePath, "ingame_log.txt"), _state.InGameLog);
            }

            var securitySb = new System.Text.StringBuilder();
            securitySb.AppendLine("=== SECURITY EVENTS ===");
            foreach (var evt in _state.SecurityEvents.OrderBy(e => e.Timestamp))
            {
                securitySb.AppendLine($"[{evt.Timestamp:yyyy-MM-dd HH:mm:ss}] [{evt.Category}] {evt.Message}");
            }
            File.WriteAllText(Path.Combine(basePath, "security_events.txt"), securitySb.ToString());

            if (PacketDecryptor.DiscoveredKeys.Count > 0)
            {
                var keysSb = new System.Text.StringBuilder();
                keysSb.AppendLine("=== ENCRYPTION KEYS ===");
                foreach (var key in PacketDecryptor.DiscoveredKeys)
                {
                    keysSb.AppendLine($"Type: {key.Type}");
                    keysSb.AppendLine($"Source: {key.Source}");
                    keysSb.AppendLine($"Key: {Convert.ToHexString(key.Key)}");
                    if (key.MemoryAddress.HasValue)
                        keysSb.AppendLine($"Address: 0x{(ulong)key.MemoryAddress.Value:X}");
                    keysSb.AppendLine();
                }
                File.WriteAllText(Path.Combine(basePath, "encryption_keys.txt"), keysSb.ToString());
            }

            _state.AddInGameLog($"[SUCCESS] Full export completed to {basePath}");
            try
            {
                System.Diagnostics.Process.Start("explorer.exe", basePath);
            }
            catch { }
        }
        catch (Exception ex)
        {
            _state.AddInGameLog($"[ERROR] Full export failed: {ex.Message}");
        }
    }
}