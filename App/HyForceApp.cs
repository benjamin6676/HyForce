// FILE: App/HyForceApp.cs -- UI Overhaul: diag bar, theme switcher, improved tab bar
using HyForce.Core;
using HyForce.Tabs;
using HyForce.UI;
using HyForce.Protocol;
using HyForce.Utils;
using ImGuiNET;
using Veldrid;
using Veldrid.Sdl2;
using System.Numerics;

namespace HyForce.App;

public class HyForceApp
{
    private readonly Sdl2Window      _window;
    private readonly GraphicsDevice  _graphicsDevice;
    private readonly ImGuiController _imguiController;
    private readonly CommandList     _commandList;

    private readonly AppState               _state;
    private readonly Protocol.PacketHandler _packetHandler;
    private readonly List<ITab>             _tabs    = new();
    private readonly Theme                  _theme;
    private readonly GlobalHotkeys          _hotkeys;
    private int  _selectedTab    = 0;
    private bool _showThemePopup = false;

    public HyForceApp(Sdl2Window window, GraphicsDevice graphicsDevice)
    {
        _window         = window;
        _graphicsDevice = graphicsDevice;

        _imguiController = new ImGuiController(
            graphicsDevice,
            graphicsDevice.MainSwapchain.Framebuffer.OutputDescription,
            window.Width,
            window.Height);

        _commandList = graphicsDevice.ResourceFactory.CreateCommandList();

        _state   = AppState.Instance;
        _theme   = new Theme();
        _hotkeys = new GlobalHotkeys();

        _packetHandler = new Protocol.PacketHandler(_state);
        _state.UdpProxy.OnPacket += _packetHandler.ProcessPacket;

        InitializeTabs();
        SetupImGuiStyle();

        var correlator = _tabs.OfType<ActionCorrelatorTab>().FirstOrDefault();
        if (correlator != null)
            _hotkeys.OnCorrelatorCapture += correlator.TriggerCapture;
    }

    private void InitializeTabs()
    {
        var inspector = new PacketInspectorTab(_state);
        var feed      = new PacketFeedTab(_state, inspector);

        _tabs.Add(new ConnectTab(_state));
        _tabs.Add(new ItemsTab(_state));
        _tabs.Add(feed);
        _tabs.Add(new OpcodeManager(_state));
        _tabs.Add(new SecurityAuditTab(_state));
        _tabs.Add(new LogTab(_state));
        _tabs.Add(new MemoryAnalysisTab(_state));
        _tabs.Add(new ActionCorrelatorTab(_state));
        _tabs.Add(new DecryptionTab(_state));
        _tabs.Add(new InjectionTab(_state));   // DLL injection capture (no proxy needed)
        _tabs.Add(new SettingsTab(_state));
        _tabs.Add(new PacketAnalyticsTab(_state));
        _tabs.Add(inspector);
        _tabs.Add(new RegistryTab(_state));
        _tabs.Add(new DecryptionStatsWindow(_state));
    }

    private void SetupImGuiStyle()
    {
        var io = ImGui.GetIO();
        io.ConfigFlags |= ImGuiConfigFlags.NavEnableKeyboard;

        // ── Global style — makes the whole UI look more polished and readable ──
        var style = ImGui.GetStyle();

        // Geometry
        style.WindowRounding    = 6f;
        style.FrameRounding     = 4f;
        style.GrabRounding      = 4f;
        style.PopupRounding     = 4f;
        style.ScrollbarRounding = 4f;
        style.TabRounding       = 4f;
        style.ChildRounding     = 4f;

        // Spacing — generous padding so everything breathes
        style.WindowPadding     = new Vector2(10f, 8f);
        style.FramePadding      = new Vector2(8f,  5f);
        style.ItemSpacing       = new Vector2(8f,  5f);
        style.ItemInnerSpacing  = new Vector2(6f,  4f);
        style.CellPadding       = new Vector2(6f,  4f);
        style.IndentSpacing     = 16f;

        // Sizes
        style.ScrollbarSize     = 10f;
        style.GrabMinSize       = 8f;
        style.WindowBorderSize  = 1f;
        style.ChildBorderSize   = 1f;
        style.PopupBorderSize   = 1f;
        style.FrameBorderSize   = 0f;
        style.TabBorderSize     = 0f;

        // Separators
        style.SeparatorTextBorderSize = 2f;

        _theme.Apply();
    }

    // -------------------------------------------------------------------------
    public void Run()
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        double prev = 0;

        while (_window.Exists)
        {
            double cur = sw.Elapsed.TotalSeconds;
            double dt  = cur - prev;
            prev = cur;

            var snap = _window.PumpEvents();
            if (!_window.Exists) break;

            _hotkeys.Poll();
            _imguiController.Update((float)dt, snap);
            RenderFrame();

            _commandList.Begin();
            _commandList.SetFramebuffer(_graphicsDevice.MainSwapchain.Framebuffer);
            _commandList.ClearColorTarget(0, new RgbaFloat(
                Theme.Current?.WindowBg.X ?? 0.08f,
                Theme.Current?.WindowBg.Y ?? 0.08f,
                Theme.Current?.WindowBg.Z ?? 0.10f, 1f));
            _imguiController.Render(_graphicsDevice, _commandList);
            _commandList.End();

            _graphicsDevice.SubmitCommands(_commandList);
            _graphicsDevice.SwapBuffers(_graphicsDevice.MainSwapchain);
        }

        _state.Dispose();
    }

    // -------------------------------------------------------------------------
    private void RenderFrame()
    {
        var vp = ImGui.GetMainViewport();
        ImGui.SetNextWindowPos(vp.WorkPos);
        ImGui.SetNextWindowSize(vp.WorkSize);
        ImGui.SetNextWindowViewport(vp.ID);

        var flags =
            ImGuiWindowFlags.MenuBar              |
            ImGuiWindowFlags.NoTitleBar            |
            ImGuiWindowFlags.NoCollapse            |
            ImGuiWindowFlags.NoResize              |
            ImGuiWindowFlags.NoMove                |
            ImGuiWindowFlags.NoBringToFrontOnFocus |
            ImGuiWindowFlags.NoNavFocus            |
            ImGuiWindowFlags.NoBackground;

        ImGui.PushStyleVar(ImGuiStyleVar.WindowRounding,   0f);
        ImGui.PushStyleVar(ImGuiStyleVar.WindowBorderSize, 0f);
        ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding,    new Vector2(0, 0));
        ImGui.Begin("##main", flags);
        ImGui.PopStyleVar(3);

        RenderMenuBar();
        RenderDiagBar();
        RenderTabBar();

        float contentH = ImGui.GetContentRegionAvail().Y;
        ImGui.BeginChild("##content", new Vector2(0, contentH), ImGuiChildFlags.None);
        try
        {
            _tabs[_selectedTab].Render();
        }
        catch (Exception ex)
        {
            ImGui.TextColored(Theme.ColDanger, $"TAB ERROR: {ex.Message}");
            _state.AddInGameLog($"[TAB ERROR] {_tabs[_selectedTab].Name}: {ex.Message}");
        }
        ImGui.EndChild();

        ImGui.End();

        _hotkeys.RenderOverlay();
        if (_state.ShowAboutWindow) RenderAboutWindow();
        if (_showThemePopup)        RenderThemePopup();
    }

    // -- Menu bar -------------------------------------------------------------
    private void RenderMenuBar()
    {
        if (!ImGui.BeginMenuBar()) return;

        ImGui.PushStyleColor(ImGuiCol.Text, Theme.ColAccent);
        ImGui.Text("HYFORCE");
        ImGui.PopStyleColor();
        ImGui.SameLine();
        ImGui.TextColored(Theme.ColTextMuted, "v23");
        ImGui.SameLine(0, 16);

        if (ImGui.BeginMenu("File"))
        {
            if (ImGui.MenuItem("Export Diagnostics", "Ctrl+E")) ExportDiagnostics();
            if (ImGui.MenuItem("Export Packet Log", "Ctrl+P")) ExportPacketLog();
            if (ImGui.MenuItem("Export All Logs", "Ctrl+Shift+E")) ExportAllLogs();
            ImGui.Separator();
            if (ImGui.MenuItem("Open Export Folder"))
                try { System.Diagnostics.Process.Start("explorer.exe", _state.ExportDirectory); } catch { }
            ImGui.Separator();
            if (ImGui.MenuItem("Exit", "Alt+F4")) _window.Close();
            ImGui.EndMenu();
        }

        if (ImGui.BeginMenu("View"))
        {
            bool ts = _state.Config.ShowTimestamps;
            if (ImGui.MenuItem("Show Timestamps", "", ts)) _state.Config.ShowTimestamps = !ts;
            bool asl = _state.Config.AutoScrollLogs;
            if (ImGui.MenuItem("Auto-scroll Logs", "", asl)) _state.Config.AutoScrollLogs = !asl;
            ImGui.Separator();
            if (ImGui.MenuItem("Change Theme...")) _showThemePopup = !_showThemePopup;
            ImGui.EndMenu();
        }

        // === ENCRYPTION MENU ===
        if (ImGui.BeginMenu("Encryption"))
        {
            bool autoDecrypt = PacketDecryptor.AutoDecryptEnabled;
            if (ImGui.MenuItem("Auto-Decrypt Packets", "", autoDecrypt))
            {
                PacketDecryptor.AutoDecryptEnabled = !autoDecrypt;
                _state.AddInGameLog(autoDecrypt ? "[CRYPTO] Auto-decrypt disabled" : "[CRYPTO] Auto-decrypt enabled");
            }

            ImGui.Separator();

            if (ImGui.MenuItem("Clear All Keys", "Ctrl+K"))
            {
                PacketDecryptor.ClearKeys();
                _state.AddInGameLog("[CRYPTO] All encryption keys cleared");
            }

            if (ImGui.MenuItem("Clear Key Log File", "Ctrl+L"))
            {
                _state.ClearKeyLogFile();
            }

            if (ImGui.MenuItem("Prepare Fresh Key Log", "Ctrl+F"))
            {
                // Call the AppState version which handles everything properly
                _state.ClearKeyLogFile();
                // Create new session file
                string sessionId = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                string keyLogPath = Path.Combine(_state.ExportDirectory, $"sslkeys_session_{sessionId}.log");
                Environment.SetEnvironmentVariable("SSLKEYLOGFILE", keyLogPath, EnvironmentVariableTarget.Process);
                File.WriteAllText(keyLogPath, "# Fresh session key log - prepared by HyForce\r\n");
                _state.AddInGameLog($"[KEYLOG] Fresh key log ready: {Path.GetFileName(keyLogPath)}");
                _state.AddInGameLog("[KEYLOG] >>> NOW START HYTALE <<<");
            }

            ImGui.Separator();

            if (ImGui.MenuItem("Open Key Log Folder"))
            {
                try
                {
                    System.Diagnostics.Process.Start("explorer.exe", _state.ExportDirectory);
                }
                catch { }
            }

            // Show current key status
            var keyStatus = _state.GetKeyStatus();
            ImGui.Separator();
            ImGui.TextColored(Theme.ColTextMuted, $"Keys: {keyStatus.TotalKeys} | Success: {keyStatus.SuccessfulDecryptions} | Failed: {keyStatus.FailedDecryptions}");

            ImGui.EndMenu();
        }

        if (ImGui.BeginMenu("Tools"))
        {
            if (ImGui.MenuItem("Clear All Data")) _state.ClearAll();
            if (ImGui.MenuItem("Generate Diagnostics Report"))
            { _state.GenerateDiagnostics(); _state.AddInGameLog("Diagnostics generated"); }
            ImGui.Separator();
            if (ImGui.MenuItem("Memory Scanner", "Ctrl+M")) SwitchToTab<MemoryAnalysisTab>();
            if (ImGui.MenuItem("Quick Memory Scan", "Ctrl+Shift+M")) _state.TriggerMemoryScan();
            ImGui.EndMenu();
        }

        if (ImGui.BeginMenu("Help"))
        {
            if (ImGui.MenuItem("About HyForce")) _state.ShowAboutWindow = true;
            ImGui.EndMenu();
        }

        ImGui.EndMenuBar();
    }

    // -- Diagnostic bar -------------------------------------------------------
    private void RenderDiagBar()
    {
        // Bright glowing bottom border on the diag bar
        var diagBg = Theme.Current?.ChildBg ?? Theme.ColBg3;
        ImGui.PushStyleColor(ImGuiCol.ChildBg, diagBg);
        ImGui.BeginChild("##diagbar", new Vector2(0, 24), ImGuiChildFlags.None);

        ImGui.SetCursorPosY(ImGui.GetCursorPosY() + 2); // vertical center

        bool udpOk = _state.UdpProxy.IsRunning;
        bool tcpOk = _state.TcpProxy.IsRunning;
        Pill("UDP", udpOk); ImGui.SameLine(0, 6);
        Pill("TCP", tcpOk);

        DiagSep();

        // Packet counts
        DiagVal("C>S", $"{_state.PacketLog.PacketsCs:N0}", Theme.ColSuccess);
        ImGui.SameLine(0, 6);
        DiagVal("S>C", $"{_state.PacketLog.PacketsSc:N0}", Theme.ColAccent);

        DiagSep();

        // Key/decryption status
        int keys = PacketDecryptor.DiscoveredKeys.Count;
        DiagVal("Keys", $"{keys}", keys > 0 ? Theme.ColSuccess : Theme.ColDanger);
        ImGui.SameLine(0, 6);
        DiagVal("Dec",  $"{PacketDecryptor.SuccessfulDecryptions:N0}", Theme.ColSuccess);
        if (PacketDecryptor.FailedDecryptions > 0)
        {
            ImGui.SameLine(0, 6);
            DiagVal("Fail", $"{PacketDecryptor.FailedDecryptions:N0}", Theme.ColWarn);
        }

        DiagSep();

        int items = Protocol.RegistrySyncParser.NumericIdToName.Count;
        DiagVal("Items", $"{items:N0}", items > 0 ? Theme.ColAccent : Theme.ColTextMuted);

        DiagSep();
        ImGui.TextColored(Theme.ColTextMuted, "F8:Cap");

        // Right-aligned: session timer + theme button
        // Use SameLine with a fixed offset from window right so it never overlaps left content
        string sessionStr = _state.StartTime.HasValue
            ? FormatDuration(DateTime.Now - _state.StartTime.Value)
            : "idle";

        // Reserve 160px on the right for timer + theme button
        const float RIGHT_RESERVE = 160f;
        float rX = ImGui.GetWindowWidth() - RIGHT_RESERVE;
        float curX = ImGui.GetCursorPosX();
        if (rX > curX + 20) ImGui.SetCursorPosX(rX);

        // Session timer (just text, compact)
        ImGui.TextColored(Theme.ColTextMuted, sessionStr);
        ImGui.SameLine(0, 8);

        // Theme button — fixed 90px width so it never wraps
        var ac = Theme.ColAccent;
        ImGui.PushStyleColor(ImGuiCol.Button,        new Vector4(ac.X*.18f, ac.Y*.18f, ac.Z*.18f, 1f));
        ImGui.PushStyleColor(ImGuiCol.ButtonHovered, new Vector4(ac.X*.30f, ac.Y*.30f, ac.Z*.30f, 1f));
        ImGui.PushStyleColor(ImGuiCol.Text,          ac);
        ImGui.PushStyleColor(ImGuiCol.Border,        ac with { W = .70f });
        ImGui.PushStyleVar(ImGuiStyleVar.FrameRounding, 8f);
        ImGui.PushStyleVar(ImGuiStyleVar.FramePadding,  new Vector2(5f, 1f));
        if (ImGui.Button("[T]##theme", new Vector2(32, 0)))
            _showThemePopup = !_showThemePopup;
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip($"Theme: {Theme.CurrentThemeName}");
        ImGui.PopStyleVar(2);
        ImGui.PopStyleColor(4);

        ImGui.EndChild();
        ImGui.PopStyleColor();

        // Accent separator line under diag bar
        var drawList = ImGui.GetWindowDrawList();
        var p0 = ImGui.GetCursorScreenPos();
        drawList.AddLine(p0, new System.Numerics.Vector2(p0.X + ImGui.GetWindowWidth(), p0.Y),
            ImGui.ColorConvertFloat4ToU32(Theme.ColAccent with { W = .25f }), 1f);
        ImGui.Separator();
    }

    private static void DiagVal(string label, string val, System.Numerics.Vector4 valCol)
    {
        ImGui.TextColored(Theme.ColTextMuted, label);
        ImGui.SameLine(0, 3);
        ImGui.TextColored(valCol, val);
    }

    private static void Pill(string label, bool ok)
    {
        var col   = ok ? Theme.ColSuccess : Theme.ColDanger;
        var bgCol = new Vector4(col.X*.25f, col.Y*.25f, col.Z*.25f, 1f);
        ImGui.PushStyleColor(ImGuiCol.Button,        bgCol);
        ImGui.PushStyleColor(ImGuiCol.ButtonHovered, bgCol);
        ImGui.PushStyleColor(ImGuiCol.ButtonActive,  bgCol);
        ImGui.PushStyleColor(ImGuiCol.Text,          col);
        ImGui.PushStyleColor(ImGuiCol.Border,        col with { W = .6f });
        ImGui.PushStyleVar(ImGuiStyleVar.FrameRounding, 8f);
        ImGui.PushStyleVar(ImGuiStyleVar.FramePadding,  new Vector2(6f, 1f));
        ImGui.SmallButton(ok ? $"{label} ON" : $"{label} OFF");
        ImGui.PopStyleVar(2);
        ImGui.PopStyleColor(5);
    }
    private static void DiagSep()
    {
        ImGui.SameLine(0, 8);
        ImGui.TextColored(new Vector4(.28f,.28f,.28f,1f), "|");
        ImGui.SameLine(0, 8);
    }

    // -- Tab bar: fixed compact padding, horizontal scroll if needed ----------
    private void RenderTabBar()
    {
        ImGui.PushStyleColor(ImGuiCol.ChildBg, Theme.Current?.ChildBg ?? Theme.ColBg3);
        // Tall enough to look good, narrow enough to not eat content space
        ImGui.BeginChild("##tabbar", new Vector2(0, 28),
            ImGuiChildFlags.None, ImGuiWindowFlags.HorizontalScrollbar);

        // Compact fixed padding: 10px horizontal, 4px vertical — tabs never truncate
        ImGui.PushStyleVar(ImGuiStyleVar.ItemSpacing,  new Vector2(1, 0));
        ImGui.PushStyleVar(ImGuiStyleVar.FramePadding, new Vector2(10, 4));

        var dl = ImGui.GetWindowDrawList();

        for (int i = 0; i < _tabs.Count; i++)
        {
            bool sel = _selectedTab == i;

            if (sel)
            {
                var ac = Theme.ColAccent;
                ImGui.PushStyleColor(ImGuiCol.Button,        new Vector4(ac.X*.14f, ac.Y*.14f, ac.Z*.14f, 1f));
                ImGui.PushStyleColor(ImGuiCol.ButtonHovered, new Vector4(ac.X*.22f, ac.Y*.22f, ac.Z*.22f, 1f));
            }
            else
            {
                ImGui.PushStyleColor(ImGuiCol.Button,        new Vector4(0,0,0,0));
                ImGui.PushStyleColor(ImGuiCol.ButtonHovered, new Vector4(.06f,.06f,.08f,.8f));
            }
            ImGui.PushStyleColor(ImGuiCol.ButtonActive, new Vector4(0,0,0,0));
            ImGui.PushStyleColor(ImGuiCol.Text,   sel ? Theme.ColAccent : Theme.ColTextMuted);
            ImGui.PushStyleColor(ImGuiCol.Border, new Vector4(0,0,0,0)); // no per-button border

            if (ImGui.Button(_tabs[i].Name)) _selectedTab = i;
            ImGui.PopStyleColor(5);

            // Scroll to active tab on first frame / when tab changes
            if (sel && ImGui.IsItemVisible())
                ImGui.SetScrollHereX(0.5f);

            // Glowing underline
            if (sel)
            {
                var mn = ImGui.GetItemRectMin();
                var mx = ImGui.GetItemRectMax();
                var ac = Theme.ColAccent;
                dl.AddLine(new Vector2(mn.X+2, mx.Y-1), new Vector2(mx.X-2, mx.Y-1),
                    ImGui.ColorConvertFloat4ToU32(ac with { W = .25f }), 3f);
                dl.AddLine(new Vector2(mn.X+2, mx.Y-1), new Vector2(mx.X-2, mx.Y-1),
                    ImGui.ColorConvertFloat4ToU32(ac), 1.5f);
            }

            if (i < _tabs.Count - 1) ImGui.SameLine();
        }

        ImGui.PopStyleVar(2);
        ImGui.EndChild();
        ImGui.PopStyleColor();

        var p0 = ImGui.GetCursorScreenPos();
        ImGui.GetWindowDrawList().AddLine(p0, new Vector2(p0.X + ImGui.GetWindowWidth(), p0.Y),
            ImGui.ColorConvertFloat4ToU32(Theme.ColAccent with { W = .15f }), 1f);
        ImGui.Separator();
    }

    // -- Theme popup ----------------------------------------------------------
    private void RenderThemePopup()
    {
        var io = ImGui.GetIO();
        ImGui.SetNextWindowPos(new Vector2(io.DisplaySize.X - 290, 50), ImGuiCond.Always);
        ImGui.SetNextWindowSize(new Vector2(280, 0), ImGuiCond.Always);

        ImGui.Begin("##themepopup", ref _showThemePopup,
            ImGuiWindowFlags.NoTitleBar | ImGuiWindowFlags.NoResize |
            ImGuiWindowFlags.NoMove     | ImGuiWindowFlags.NoScrollbar);

        ImGui.TextColored(Theme.ColAccent, "THEME SELECTOR");
        ImGui.Separator();

        foreach (var group in Theme.AllThemes.Values.Select(t => t.Group).Distinct())
        {
            ImGui.TextColored(Theme.ColTextMuted, group.ToUpper());
            ImGui.Separator();
            foreach (var (key, def) in Theme.AllThemes.Where(kv => kv.Value.Group == group))
            {
                bool active = Theme.CurrentThemeName == key;
                ImGui.PushStyleColor(ImGuiCol.Button,        active ? def.Accent : def.AccentDim);
                ImGui.PushStyleColor(ImGuiCol.ButtonHovered, def.AccentMid);
                if (ImGui.Button($"[#]##{key}", new Vector2(20, 20)))
                { Theme.SwitchTo(key); _showThemePopup = false; }
                ImGui.PopStyleColor(2);
                ImGui.SameLine();
                if (active) ImGui.PushStyleColor(ImGuiCol.Text, def.Accent);
                if (ImGui.Selectable(def.Name, active))
                { Theme.SwitchTo(key); _showThemePopup = false; }
                if (active) ImGui.PopStyleColor();
            }
            ImGui.Spacing();
        }

        ImGui.Separator();
        if (ImGui.Button("Close", new Vector2(-1, 22))) _showThemePopup = false;
        ImGui.End();
    }

    // -- About ----------------------------------------------------------------
    private void RenderAboutWindow()
    {
        ImGui.SetNextWindowSize(new Vector2(460, 420), ImGuiCond.FirstUseEver);
        ImGui.SetNextWindowPos(ImGui.GetIO().DisplaySize * 0.5f, ImGuiCond.FirstUseEver, new Vector2(0.5f, 0.5f));
        bool show = _state.ShowAboutWindow;
        if (ImGui.Begin("About HyForce", ref show, ImGuiWindowFlags.NoCollapse | ImGuiWindowFlags.NoResize))
        {
            _state.ShowAboutWindow = show;
            float w = ImGui.GetWindowWidth();
            ImGui.Spacing();
            CenterText(Constants.BuildName,    Theme.ColAccent);
            ImGui.Spacing();
            CenterText(Constants.AppSubtitle,  Theme.ColTextMuted);
            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();
            ImGui.Text($"Version:    {Constants.BuildVersion}");
            ImGui.Text($"Build Date: {Constants.BuildDate}");
            ImGui.Text($"Theme:      {Theme.CurrentThemeName}");
            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();
            ImGui.TextWrapped("HyForce is a network security analysis tool for Hytale. " +
                "Captures and analyses QUIC/UDP gameplay and TCP registry traffic.");
            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();
            var st = _state.GetKeyStatus();
            ImGui.TextColored(Theme.ColAccent, "Decryption Status");
            ImGui.Text($"Keys:      {st.TotalKeys}");
            ImGui.Text($"Decrypted: {st.SuccessfulDecryptions}");
            ImGui.Text($"Failed:    {st.FailedDecryptions}");
            if (st.LastKeyAdded.HasValue)
            {
                var ago = DateTime.Now - st.LastKeyAdded.Value;
                ImGui.TextColored(Theme.ColTextMuted,
                    $"Last key:  {(ago.TotalMinutes < 1 ? "just now" : $"{ago.TotalMinutes:F0}m ago")}");
            }
            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();
            ImGui.SetCursorPosX((w - 100f) * .5f);
            if (ImGui.Button("Close", new Vector2(100f, 28))) _state.ShowAboutWindow = false;
        }
        ImGui.End();
        _hotkeys.RenderOverlay();
        _state.ShowAboutWindow = show;
    }

    // -- Helpers --------------------------------------------------------------
    private void SwitchToTab<T>() where T : ITab
    {
        for (int i = 0; i < _tabs.Count; i++)
            if (_tabs[i] is T) { _selectedTab = i; return; }
    }
    private static void CenterText(string t, Vector4 c)
    {
        ImGui.SetCursorPosX((ImGui.GetWindowWidth() - ImGui.CalcTextSize(t).X) * .5f);
        ImGui.TextColored(c, t);
    }
    private static string FormatDuration(TimeSpan t)
    {
        if (t.TotalHours >= 1) return $"{(int)t.TotalHours}h {t.Minutes:D2}m";
        if (t.TotalMinutes >= 1) return $"{t.Minutes}m {t.Seconds:D2}s";
        return $"{t.Seconds}s";
    }

    

    // -- Exports --------------------------------------------------------------
    private void ExportDiagnostics()
    {
        try
        {
            string p = Path.Combine(_state.ExportDirectory, $"hyforce_diagnostics_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
            File.WriteAllText(p, _state.GenerateDiagnostics());
            _state.AddInGameLog($"[OK] Diagnostics -> {Path.GetFileName(p)}");
        }
        catch (Exception ex) { _state.AddInGameLog($"[ERR] {ex.Message}"); }
    }
    private void ExportPacketLog()
    {
        try
        {
            string p = Path.Combine(_state.ExportDirectory, $"hyforce_packets_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
            File.WriteAllText(p, _state.ExportPacketLog());
            _state.AddInGameLog($"[OK] Packets -> {Path.GetFileName(p)}");
        }
        catch (Exception ex) { _state.AddInGameLog($"[ERR] {ex.Message}"); }
    }
    private void ExportAllLogs()
    {
        try
        {
            string ts    = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            string base_ = Path.Combine(_state.ExportDirectory, $"hyforce_export_{ts}");
            Directory.CreateDirectory(base_);
            File.WriteAllText(Path.Combine(base_, "diagnostics.txt"), _state.GenerateDiagnostics());
            File.WriteAllText(Path.Combine(base_, "packets.txt"),      _state.ExportPacketLog());
            File.WriteAllLines(Path.Combine(base_, "ingame_log.txt"),  _state.InGameLog.ToArray());
            _state.AddInGameLog($"[OK] Full export -> {base_}");
            try { System.Diagnostics.Process.Start("explorer.exe", base_); } catch { }
        }
        catch (Exception ex) { _state.AddInGameLog($"[ERR] ExportAll: {ex.Message}"); }
    }
}
