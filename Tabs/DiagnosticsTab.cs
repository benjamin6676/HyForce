// DiagnosticsTab.cs — Full export hub + live status overview

using HyForce;
using HyForce.Core;
using HyForce.Diagnostics;
using HyForce.Networking;
using ImGuiNET;
using System;
using System.IO;
using System.Numerics;
using System.Threading.Tasks;

namespace HyForce.Tabs
{
    public class DiagnosticsTab : ITab
    {
        public string Name => "Diagnostics";

        private readonly AppState            _state;
        private readonly PipeCaptureServer   _pipe;
        private readonly MemoryToggleManager _toggleMgr;

        private bool   _collecting      = false;
        private string _lastExportPath  = "";
        private string _previewText     = "Click 'Collect & Export' to generate a full diagnostic report.";
        private int    _maxPackets      = 20;
        private int    _maxLogLines     = 500;
        private bool   _autoOpen        = true;
        private string _copyBuf         = "";

        static readonly Vector4 Green  = new(0.2f, 1f, 0.4f, 1f);
        static readonly Vector4 Red    = new(1f, 0.3f, 0.2f, 1f);
        static readonly Vector4 Yellow = new(1f, 0.85f, 0.1f, 1f);
        static readonly Vector4 Muted  = new(0.55f, 0.55f, 0.55f, 1f);
        static readonly Vector4 Accent = new(0.75f, 0.45f, 1f, 1f);

        public DiagnosticsTab(AppState state, PipeCaptureServer pipe, MemoryToggleManager toggleMgr,
                              ValueToggleTab? valueToggleTab = null)
        {
            _state          = state;
            _pipe           = pipe;
            _toggleMgr      = toggleMgr;
            _valueToggleTab = valueToggleTab;
        }

        private readonly ValueToggleTab? _valueToggleTab;

        public void Render()
        {
            // ── Status bar ────────────────────────────────────────────────────
            ImGui.TextColored(Accent, "HyForce Diagnostics — captures everything for AI/developer analysis");
            ImGui.Separator();

            // ── Quick health overview ─────────────────────────────────────────
            bool dll = _pipe.DllConnected;
            ImGui.TextColored(dll ? Green : Red,
                dll ? $"● DLL: Connected ({_pipe.PacketCount} pkts)" : "○ DLL: Not Connected");
            ImGui.SameLine();
            int keys = PacketDecryptor.DiscoveredKeys.Count;
            ImGui.TextColored(keys > 0 ? Green : Yellow,
                $"  Keys: {keys}");
            ImGui.SameLine();
            var dstats = PacketDecryptor.GetDebugStats();
            int ok = Convert.ToInt32(dstats["SuccessfulDecryptions"]);
            int fail = Convert.ToInt32(dstats["FailedDecryptions"]);
            ImGui.TextColored(ok > 0 ? Green : (fail > 100 ? Red : Muted),
                $"  Decrypt: {ok} ok / {fail} fail");
            ImGui.SameLine();
            ImGui.TextColored(_pipe.MemHits.Count > 0 ? Green : Muted,
                $"  MemHits: {_pipe.MemHits.Count}");
            ImGui.SameLine();
            ImGui.TextColored(_toggleMgr.Toggles.Count > 0 ? Accent : Muted,
                $"  Toggles: {_toggleMgr.Toggles.Count} ({_toggleMgr.Toggles.Count(t => t.Active)} active)");

            ImGui.Separator();

            // ── Controls ──────────────────────────────────────────────────────
            ImGui.SetNextItemWidth(80);
            ImGui.InputInt("Max packets##mp", ref _maxPackets);
            ImGui.SameLine();
            ImGui.SetNextItemWidth(80);
            ImGui.InputInt("Max log lines##ml", ref _maxLogLines);
            ImGui.SameLine();
            ImGui.Checkbox("Open in Notepad##ao", ref _autoOpen);

            ImGui.Spacing();

            if (_collecting)
            {
                ImGui.TextColored(Yellow, "⏳ Collecting...");
            }
            else
            {
                if (ImGui.Button("🔍  Collect & Export Full Report", new Vector2(260, 32)))
                    CollectAndExport();
                ImGui.SameLine();
                if (ImGui.Button("📋  Copy to Clipboard", new Vector2(160, 32)) && _previewText.Length > 50)
                {
                    _copyBuf = _previewText;
                    ImGui.SetClipboardText(_copyBuf);
                    _state.AddInGameLog("[DIAG] Report copied to clipboard");
                }
            }

            if (!string.IsNullOrEmpty(_lastExportPath))
            {
                ImGui.TextColored(Green, $"✓ Saved: {_lastExportPath}");
                ImGui.SameLine();
                if (ImGui.SmallButton("Open##op"))
                    try { System.Diagnostics.Process.Start("notepad.exe", _lastExportPath); } catch { }
            }

            ImGui.Separator();

            // ── Diagnose now hints ─────────────────────────────────────────────
            ImGui.TextColored(Accent, "Quick Checks");

            if (!dll)
            {
                ImGui.TextColored(Red, "  ✗ DLL not connected — go to Injection tab and inject HyForceHook.dll into HytaleClient.exe");
            }
            else
            {
                ImGui.TextColored(Green, "  ✓ DLL connected");
                if (_pipe.PacketCount == 0)
                    ImGui.TextColored(Yellow, "  ⚠ 0 packets — send STATS via InjectionTab to check hook fires");
                else
                    ImGui.TextColored(Green, $"  ✓ {_pipe.PacketCount} packets hooked");
            }

            if (keys == 0)
                ImGui.TextColored(Red, "  ✗ No SSL keys — make sure SSLKEYLOGFILE is set (Decryption tab → Auto-Setup)");
            else if (ok == 0 && fail > 50)
                ImGui.TextColored(Yellow, "  ⚠ Keys loaded but 0 successes — session mismatch, reconnect Hytale");
            else if (ok > 0)
                ImGui.TextColored(Green, $"  ✓ Decryption working ({ok} packets)");

            if (_pipe.MemHits.Count == 0)
                ImGui.TextColored(Muted, "  ⚠ No memory hits — run MEMSCAN from Memory Research tab (Hytale must be in-game)");
            else
                ImGui.TextColored(Green, $"  ✓ {_pipe.MemHits.Count} entity struct(s) found");

            ImGui.Separator();

            // ── Preview panel ─────────────────────────────────────────────────
            ImGui.TextColored(Muted, "Report preview:");
            ImGui.BeginChild("##diagprev", new Vector2(-1, -1), ImGuiChildFlags.Borders);
            ImGui.InputTextMultiline("##prevtxt", ref _previewText, 1 << 20,
                new Vector2(-1, -1), ImGuiInputTextFlags.ReadOnly);
            ImGui.EndChild();
        }

        private void CollectAndExport()
        {
            _collecting = true;
            Task.Run(() =>
            {
                try
                {
                    string content = HyForce.Diagnostics.DiagnosticsCollector.Collect(
                        _state, _pipe, _toggleMgr, _maxPackets, _maxLogLines,
                        _valueToggleTab?.Entries);

                    Directory.CreateDirectory(_state.ExportDirectory);
                    string path = Path.Combine(_state.ExportDirectory,
                        $"hyforce_diag_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
                    File.WriteAllText(path, content);
                    _lastExportPath = path;
                    _previewText    = content;
                    _state.AddInGameLog($"[DIAG] Report saved → {Path.GetFileName(path)}");

                    if (_autoOpen)
                        try { System.Diagnostics.Process.Start("notepad.exe", path); } catch { }
                }
                catch (Exception ex)
                {
                    _previewText = $"[ERROR] {ex}";
                    _state.AddInGameLog($"[DIAG] Export error: {ex.Message}");
                }
                finally { _collecting = false; }
            });
        }
    }
}
