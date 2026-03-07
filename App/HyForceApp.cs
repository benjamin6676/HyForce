using HyForce.Core;
using HyForce.Diagnostics;
using HyForce.Tabs;
using HyForce.UI;
using HyForce.Utils;
using ImGuiNET;
using Veldrid;
using Veldrid.Sdl2;
using System.Numerics;
using System;
using System.Collections.Generic;
using System.Linq;  // For .OfType<InjectionTab>()

namespace HyForce.App
{
    public class HyForceApp : IDisposable
    {
        // ── Veldrid / ImGui ───────────────────────────────────────
        private readonly Sdl2Window         _window;
        private readonly GraphicsDevice     _graphicsDevice;
        private readonly ImGuiController    _imguiController;
        private readonly CommandList        _commandList;

        // ── Core state ────────────────────────────────────────────
        private readonly AppState           _state;
        private readonly Theme              _theme;
        private readonly GlobalHotkeys _hotkeys;
        private readonly Protocol.PacketHandler _packetHandler;
        private bool _showRestartBanner = false;

        // ── Capture ───────────────────────────────────────────────
        private HyForce.Networking.PipeCaptureServer _pipeServer;
        private HyForce.Networking.WinDivertCapture? _winDivert;
        private DateTime _winDivertCheckAt = DateTime.MinValue;

        // ── Tabs (7 total) ────────────────────────────────────────
        private readonly List<ITab> _tabs = new();
        private int _activeTab;

        // ── Memory Toggle Manager ─────────────────────────────────
        private HyForce.Core.MemoryToggleManager _toggleMgr = null!;

        // ── Frame state ───────────────────────────────────────────
        private float _dt;
        private float _fpsSmooth = 60f;
        private bool _showAbout;

        public HyForceApp(Sdl2Window window, GraphicsDevice graphicsDevice)
        {
            _window = window;
            _graphicsDevice = graphicsDevice;

            _imguiController = new ImGuiController(
                graphicsDevice,
                graphicsDevice.MainSwapchain.Framebuffer.OutputDescription,
                window.Width, window.Height);

            _commandList = graphicsDevice.ResourceFactory.CreateCommandList();

            _state = AppState.Instance;
            _theme = new Theme();
            // dll crashes can happen, so we set up handlers to ensure we eject cleanly and don't leave the game in a bad state
            SetupCrashHandlers();

            _hotkeys = new GlobalHotkeys();
            _packetHandler = new Protocol.PacketHandler(_state);

            // Pipe server (DLL injection capture)
            _pipeServer = new HyForce.Networking.PipeCaptureServer(_state);
            _pipeServer.OnPacketReceived += pkt => _state.OnHookPacket(pkt);
            _pipeServer.Start();

            // WinDivert auto-start check: if DLL shows 0 packets after 30s
            _winDivertCheckAt = DateTime.Now.AddSeconds(30);

            // ── Register the tabs ─────────────────────────────────
            _tabs.Add(new PacketFeedTab(_state, _pipeServer));
            _tabs.Add(new DecryptionTab(_state));
            _toggleMgr = new HyForce.Core.MemoryToggleManager(_pipeServer, _state);
            var togglesTab    = new MemoryTogglesTab(_state, _pipeServer, _toggleMgr);
            var valueToggleTab = new ValueToggleTab(_state, _pipeServer);   // v11 modular system
            _tabs.Add(new MemoryResearchTab(_state, _pipeServer));
            _tabs.Add(togglesTab);
            _tabs.Add(valueToggleTab);
            _tabs.Add(new ProtocolLabTab(_state, _pipeServer));
            _tabs.Add(new SecurityAuditTab(_state, _pipeServer));
            _tabs.Add(new InjectionTab(_state, _pipeServer));
            _tabs.Add(new LogTab(_state));
            _tabs.Add(new DiagnosticsTab(_state, _pipeServer, _toggleMgr, valueToggleTab));
            _tabs.Add(new SettingsTab(_state));


        }

        // ─── Main update/render loop ──────────────────────────────
        public void Update(float deltaSeconds)
        {
            _dt = deltaSeconds;
            _fpsSmooth = _fpsSmooth * 0.95f + (1f / Math.Max(deltaSeconds, 0.0001f)) * 0.05f;

            // WinDivert auto-fallback
            if (_winDivert == null && DateTime.Now > _winDivertCheckAt &&
                _pipeServer.IsRunning && _pipeServer.PacketCount == 0 &&
                HyForce.Networking.WinDivertCapture.IsAvailable)
            {
                _winDivert = new HyForce.Networking.WinDivertCapture(_state);
                _winDivert.OnPacket += pkt => _state.OnHookPacket(pkt);
                bool ok = _winDivert.Start();
                _state.AddInGameLog(ok
                    ? "[WINDIVERT] Auto-started (DLL hooks: 0 packets after 30s)"
                    : "[WINDIVERT] Auto-start failed — run as Administrator");
                _winDivertCheckAt = DateTime.Now.AddSeconds(300);
            }

            _state.CheckForNewKeys();

        }


        // ─── Render ───────────────────────────────────────────────
        public void Render(float deltaSeconds, InputSnapshot snapshot)
        {
            _imguiController.Update(deltaSeconds, snapshot);
            _theme.Apply();

            if (_state.ShowRestartBanner)
            {
                RenderRestartBanner();
            }

            var vp = ImGui.GetMainViewport();
            ImGui.SetNextWindowPos(vp.WorkPos);
            ImGui.SetNextWindowSize(vp.WorkSize);
            ImGui.SetNextWindowViewport(vp.ID);

            ImGui.Begin("##root",
                ImGuiWindowFlags.NoDecoration | ImGuiWindowFlags.NoMove |
                ImGuiWindowFlags.NoResize | ImGuiWindowFlags.NoSavedSettings |
                ImGuiWindowFlags.NoBringToFrontOnFocus);

            RenderTitleBar();
            RenderTabBar();

            ImGui.End();

            if (_showAbout) RenderAbout();

            // Render to GPU
            _commandList.Begin();
            _commandList.SetFramebuffer(_graphicsDevice.MainSwapchain.Framebuffer);
            _commandList.ClearColorTarget(0, new RgbaFloat(0.05f, 0.05f, 0.06f, 1f));
            _imguiController.Render(_graphicsDevice, _commandList);
            _commandList.End();
            _graphicsDevice.SubmitCommands(_commandList);
            _graphicsDevice.SwapBuffers(_graphicsDevice.MainSwapchain);

            if (_showRestartBanner && AppState.Instance.NeedsFirstTimeSetup)
            {
                ImGui.SetNextWindowPos(ImGui.GetMainViewport().GetCenter(), ImGuiCond.Always, new Vector2(0.5f, 0.5f));
                ImGui.SetNextWindowSize(new Vector2(500, 200), ImGuiCond.Always);

                if (ImGui.Begin("Restart Required##restart", ref _showRestartBanner,
                    ImGuiWindowFlags.NoCollapse | ImGuiWindowFlags.NoResize))
                {
                    ImGui.TextColored(new Vector4(1f, 0.3f, 0.2f, 1f), "⚠️ HYTALE RESTART REQUIRED");
                    ImGui.Separator();
                    ImGui.TextWrapped(
                        "SSLKEYLOGFILE has been configured for automatic key capture, but Hytale was already running.\n\n1. Close Hytale completely (check system tray)\n2. Restart Hytale\n3. Keys will appear automatically in the Decryption tab");

                    if (ImGui.Button("I've Restarted Hytale", new Vector2(200, 40)))
                    {
                        _showRestartBanner = false;
                        AppState.Instance.ForceReImportKeys();
                    }

                    ImGui.SameLine();
                    if (ImGui.Button("Dismiss", new Vector2(100, 40)))
                    {
                        _showRestartBanner = false;
                    }
                }
                ImGui.End();
            }
        }

        private void RenderTitleBar()
        {
            var live    = _pipeServer.DllConnected;
            var dllCol  = live ? new Vector4(0.1f,1f,0.4f,1f) : new Vector4(0.5f,0.5f,0.5f,1f);
            var pktCol  = _pipeServer.PacketCount > 0 ? new Vector4(0.2f,0.8f,1f,1f) : new Vector4(0.5f,0.5f,0.5f,1f);
            var decCol  = AppState.Instance.PacketLog.TotalDecrypted > 0
                ? new Vector4(0.9f,0.6f,0.1f,1f) : new Vector4(0.5f,0.5f,0.5f,1f);

            ImGui.TextColored(new Vector4(0.4f,0.8f,1f,1f), "HyForce");
            ImGui.SameLine();
            ImGui.TextColored(new Vector4(0.4f,0.4f,0.4f,1f), "v23");
            ImGui.SameLine(0, 24);
            ImGui.TextColored(dllCol, live ? "● DLL" : "○ DLL");
            ImGui.SameLine(0, 12);
            ImGui.TextColored(pktCol, $"▲ {_pipeServer.PacketCount:N0}");
            ImGui.SameLine(0, 12);
            ImGui.TextColored(decCol, $"🔓 {AppState.Instance.PacketLog.TotalDecrypted:N0}");
            ImGui.SameLine(0, 12);
            ImGui.TextColored(new Vector4(0.5f,0.5f,0.5f,1f), $"{_fpsSmooth:F0}fps");
            ImGui.SameLine(ImGui.GetContentRegionAvail().X - 48);
            if (ImGui.SmallButton("About")) _showAbout = !_showAbout;
            ImGui.Separator();
        }

        private void RenderTabBar()
        {
            if (!ImGui.BeginTabBar("##main")) return;
            for (int i = 0; i < _tabs.Count; i++)
            {
                bool open = ImGui.BeginTabItem(_tabs[i].Name + $"##t{i}");
                if (open)
                {
                    _activeTab = i;
                    _tabs[i].Render();
                    ImGui.EndTabItem();
                }
            }
            ImGui.EndTabBar();
        }

        private void RenderAbout()
        {
            ImGui.SetNextWindowSize(new Vector2(380, 220), ImGuiCond.Always);
            ImGui.SetNextWindowPos(ImGui.GetMainViewport().GetCenter(), ImGuiCond.Always, new Vector2(0.5f, 0.5f));
            if (ImGui.Begin("About HyForce##about", ref _showAbout))
            {
                ImGui.TextColored(new Vector4(0.4f, 0.8f, 1f, 1f), "HyForce v23");
                ImGui.TextColored(new Vector4(0.6f, 0.6f, 0.6f, 1f), "Hytale Security Research Tool");
                ImGui.Separator();
                ImGui.Spacing();
                ImGui.Text("Tabs: Packets · Decryption · Memory");
                ImGui.Text("      Protocol Lab · Injection · Log · Settings");
                ImGui.Spacing();
                ImGui.Text("DLL capture: WSASendTo + sendto + WSARecvFrom + recvfrom");
                ImGui.Text("Fallback:    WinDivert kernel-level capture");
                ImGui.Text("Decryption:  QUIC/TLS HKDF RFC9001_NoPrefix");
            }
            ImGui.End();
        }
        private void RenderRestartBanner()
        {
            var center = ImGui.GetMainViewport().GetCenter();
            ImGui.SetNextWindowPos(center, ImGuiCond.Always, new Vector2(0.5f, 0.5f));
            ImGui.SetNextWindowSize(new Vector2(500, 200), ImGuiCond.Always);
            bool show = _state.ShowRestartBanner;
            if (ImGui.Begin("Restart Required##restart", ref show,
                ImGuiWindowFlags.NoCollapse | ImGuiWindowFlags.NoResize | ImGuiWindowFlags.Modal))
            {
                ImGui.TextColored(new Vector4(1f, 0.3f, 0.2f, 1f), "HYTALE RESTART REQUIRED");
                ImGui.Separator();
                ImGui.TextWrapped("SSLKEYLOGFILE configured. Close Hytale completely (system tray!), then restart it.");
                if (ImGui.Button("I've Restarted Hytale", new Vector2(180, 40)))
                {
                    show = false;
                    _state.ForceReImportKeys();
                }
                ImGui.SameLine();
                if (ImGui.Button("Dismiss", new Vector2(100, 40))) show = false;
            }
            ImGui.End();
            _state.ShowRestartBanner = show;
        }

        private void SetupCrashHandlers()
        {
            AppDomain.CurrentDomain.UnhandledException += (s, e) =>
            {
                _state.AddInGameLog("[CRASH] Unhandled exception - forcing DLL eject");

                // Find InjectionTab and call ejection
                var injectTab = _tabs.OfType<InjectionTab>().FirstOrDefault();
                injectTab?.OnApplicationClosing();

                // Give it a moment to eject
                Thread.Sleep(500);
            };

            TaskScheduler.UnobservedTaskException += (s, e) =>
            {
                _state.AddInGameLog("[CRASH] Unobserved task exception - forcing DLL eject");

                var injectTab = _tabs.OfType<InjectionTab>().FirstOrDefault();
                injectTab?.OnApplicationClosing();

                e.SetObserved();
            };
        }

        public void Run()
        {
            while (_window.Exists)
            {
                var snapshot = _window.PumpEvents();  // Use PumpEvents(), not GetSnapshot()

                if (!_window.Exists)
                    break;

                float deltaSeconds = 1f / 60f;

                Update(deltaSeconds);
                Render(deltaSeconds, snapshot);  // Pass snapshot to Render
            }
        }

        // FILE: .\App\HyForceApp.cs
        // REPLACE the existing Dispose() method with this:

        public void Dispose()
        {
            // NEW: Eject DLL before closing if injected
            // Must do this BEFORE stopping pipe server
            var injectTab = _tabs.OfType<InjectionTab>().FirstOrDefault();
            injectTab?.OnApplicationClosing();

            // Small delay to allow ejection to complete
            Thread.Sleep(200);

            _pipeServer.Stop();
            _winDivert?.Stop();
            _hotkeys.Dispose();
            _imguiController.Dispose();
            _commandList.Dispose();
            _graphicsDevice.Dispose();
        }
    }
}
