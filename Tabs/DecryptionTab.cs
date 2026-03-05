using HyForce.Core;
using ImGuiNET;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace HyForce.Tabs
{
    public class DecryptionTab : ITab
    {
        public string Name => "Decryption";
        private readonly AppState _state;

        private string _hexInput     = "";
        private string _testResult   = "";
        private int    _selectedFmt  = 1; // RFC8446_WithPrefix default
        private string[] _fmtLabels = { "RFC9001 (no prefix)", "RFC8446 tls13 ✓", "QUICv2", "TestVec" };
        // Pathing for .key files (Netty session cache) -- for DPAPI scanning
        private string _manualKeyPath = @"C:\Users\benja\AppData\Roaming\Hytale\.keys";

        private bool   _showAdvanced = false;
        private bool   _showDPAPI    = false;
        private string _dpapiResult  = "";
        private string _analyzeHex   = "";
        private string _analyzeResult= "";

        private static bool _initialized = false;

        public DecryptionTab(AppState state)
        {
            _state = state;
            if (!_initialized)
            {
                PacketDecryptor.CurrentLabelFormat = PacketDecryptor.HkdfLabelFormat.RFC8446_WithPrefix;
                _initialized = true;
            }
        }

        public void Render()
        {
            var stats   = PacketDecryptor.GetDebugStats();
            int keys    = (int)stats["TotalKeys"];
            int success = (int)stats["SuccessfulDecryptions"];
            int failed  = (int)stats["FailedDecryptions"];
            bool hasKeys = keys > 0;

            // Status panel
            var bgCol = hasKeys ? new Vector4(.04f,.14f,.04f,1f) : new Vector4(.18f,.10f,.02f,1f);
            ImGui.PushStyleColor(ImGuiCol.ChildBg, bgCol);
            ImGui.BeginChild("##status", new Vector2(-1, 70), ImGuiChildFlags.Borders);

            if (!hasKeys)
            {
                ImGui.TextColored(new Vector4(1f,.7f,.1f,1f), "WAITING FOR HYTALE");
                ImGui.TextColored(new Vector4(.6f,.6f,.6f,1f), "Launch Hytale -- keys will appear here automatically.");
            }
            else if (failed > 200 && success == 0)
            {
                // 200+ failures = almost certainly session mismatch
                ImGui.TextColored(new Vector4(1f,.4f,.1f,1f), $"SESSION MISMATCH — {keys} keys loaded but 0 decrypted from {failed} attempts");
                ImGui.TextColored(new Vector4(1f,.9f,.2f,1f), "FIX: With proxy running, RESTART HYTALE so it connects THROUGH the proxy.");
                ImGui.TextColored(new Vector4(.5f,.5f,.5f,1f), "Keys log new session on reconnect — they will then match the captured packets.");
            }
            else
            {
                ImGui.TextColored(new Vector4(.2f,1f,.4f,1f), $"KEYS READY ({keys})  --  label: {_fmtLabels[_selectedFmt]}");
                ImGui.TextColored(new Vector4(.6f,.6f,.6f,1f), failed == 0
                    ? "Start capturing to see decryption results"
                    : $"Decrypting: {success} OK  {failed} failed");
            }

            if (ImGui.Button("Re-Import Keys")) _state.ForceReImportKeys();
            ImGui.SameLine();
            if (ImGui.Button("Open Key Log File")) { try { System.Diagnostics.Process.Start("notepad.exe", _state.PermanentKeyLogPath); } catch { } }
            ImGui.SameLine();
            if (ImGui.Button("Export Diagnostics")) ExportDiagnostics();
            ImGui.SameLine();
            if (ImGui.Button("Open Live Log"))
            {
                try
                {
                    if (!string.IsNullOrEmpty(_state.SessionLogPath) && File.Exists(_state.SessionLogPath))
                        System.Diagnostics.Process.Start("notepad.exe", _state.SessionLogPath);
                    else
                        _state.AddInGameLog("[LOG] No session log yet — start a capture first");
                }
                catch (Exception ex) { _state.AddInGameLog($"[LOG] Open failed: {ex.Message}"); }
            }
            ImGui.SameLine();
            if (ImGui.Button("Advanced")) _showAdvanced = !_showAdvanced;

            ImGui.EndChild();
            ImGui.PopStyleColor();

            // Pill badges
            ImGui.Spacing();
            Pill($"Keys: {keys}",         hasKeys ? new Vector4(.1f,.7f,.3f,1f) : new Vector4(.4f,.4f,.4f,1f)); ImGui.SameLine();
            Pill($"Decrypted: {success}",  success > 0 ? new Vector4(.1f,.7f,.3f,1f) : new Vector4(.4f,.4f,.4f,1f)); ImGui.SameLine();
            Pill($"Failed: {failed}",      failed  > 0 ? new Vector4(.8f,.2f,.2f,1f) : new Vector4(.4f,.4f,.4f,1f));
            ImGui.Spacing();

            // Key list (left)
            ImGui.BeginChild("##keys", new Vector2(400, -1), ImGuiChildFlags.Borders);
            ImGui.TextColored(new Vector4(.4f,.8f,1f,1f), $"Active Keys ({keys})");
            ImGui.Separator();
            if (!hasKeys)
            {
                ImGui.TextColored(new Vector4(.5f,.5f,.5f,1f), "No keys yet.\nLaunch Hytale -- they'll appear here automatically.");
            }
            else
            {
                foreach (var key in PacketDecryptor.DiscoveredKeys.Take(80))
                {
                    string t = key.Type switch
                    {
                        PacketDecryptor.EncryptionType.QUIC_Client1RTT      => "[C 1RTT]",
                        PacketDecryptor.EncryptionType.QUIC_Server1RTT      => "[S 1RTT]",
                        PacketDecryptor.EncryptionType.QUIC_ClientHandshake => "[C  HS ]",
                        PacketDecryptor.EncryptionType.QUIC_ServerHandshake => "[S  HS ]",
                        PacketDecryptor.EncryptionType.QUIC_Client0RTT      => "[C 0RTT]",
                        _ => "[  ?   ]"
                    };
                    var c = key.IsClient ? new Vector4(.3f,.8f,.3f,1f) : new Vector4(.3f,.6f,1f,1f);
                    string kh = key.Key != null && key.Key.Length > 0 ? Convert.ToHexString(key.Key).Substring(0,16)+"..." : "not derived";
                    ImGui.TextColored(c, $"{t} {kh}  {key.DiscoveredAt:HH:mm:ss}");
                }
                if (keys > 80) ImGui.TextColored(new Vector4(.5f,.5f,.5f,1f), $"... +{keys-80} more");
            }
            ImGui.EndChild();

            ImGui.SameLine();

            // Right panel
            ImGui.BeginChild("##right", new Vector2(-1, -1));

            // ── Advanced ──────────────────────────────────────────────────────
            if (_showAdvanced)
            {
                ImGui.TextColored(new Vector4(.8f,.5f,1f,1f), "Advanced Settings");
                ImGui.Separator();

                if (ImGui.Combo("HKDF Label##fmt", ref _selectedFmt, _fmtLabels, _fmtLabels.Length))
                    PacketDecryptor.CurrentLabelFormat = (PacketDecryptor.HkdfLabelFormat)_selectedFmt;

                int maxDcid = PacketDecryptor.MaxDCIDLengthToTry;
                int timeout = PacketDecryptor.DecryptionTimeoutMs;
                bool autoDecrypt = PacketDecryptor.AutoDecryptEnabled;
                bool debug = PacketDecryptor.DebugMode;
                if (ImGui.Checkbox("Auto-Decrypt", ref autoDecrypt)) PacketDecryptor.AutoDecryptEnabled = autoDecrypt;
                ImGui.SameLine();
                if (ImGui.Checkbox("Debug Log", ref debug)) PacketDecryptor.DebugMode = debug;
                ImGui.SliderInt("Max DCID candidates##sl", ref maxDcid, 1, 8);
                ImGui.SliderInt("Timeout ms##sl", ref timeout, 20, 500);
                PacketDecryptor.MaxDCIDLengthToTry = maxDcid;
                PacketDecryptor.DecryptionTimeoutMs = timeout;

                if (ImGui.Button("Dump Keys##adv")) _testResult = PacketDecryptor.DumpAllKeys();
                ImGui.SameLine();
                if (ImGui.Button("Clear Keys##adv")) { PacketDecryptor.ClearKeys(); _testResult = "Cleared."; }
                ImGui.SameLine();
                if (ImGui.Button("Test RFC Vector")) RunTestVector();

                ImGui.Separator();

                // DPAPI scanner
                if (ImGui.Button(_showDPAPI ? "Hide DPAPI Scanner" : "Scan .key Files (DPAPI)"))
                    _showDPAPI = !_showDPAPI;

                if (_showDPAPI)
                {
                    ImGui.TextColored(new Vector4(.9f,.7f,.2f,1f), "Scans Netty/BoringSSL .key session cache files and DPAPI-decrypts them.");
                    if (ImGui.Button("Scan Now##dp")) _dpapiResult = ScanDPAPI();
                    if (!string.IsNullOrEmpty(_dpapiResult))
                        ImGui.InputTextMultiline("##dpres", ref _dpapiResult, 8000, new Vector2(-1, 120), ImGuiInputTextFlags.ReadOnly);
                }

                ImGui.Separator();

                // Packet analyzer
                ImGui.TextColored(new Vector4(.4f,.8f,1f,1f), "QUIC Packet Analyzer");
                ImGui.InputTextMultiline("##pahex", ref _analyzeHex, 4000, new Vector2(-1, 40));
                ImGui.SameLine();
                if (ImGui.Button("Analyze##pa")) _analyzeResult = Analyze(_analyzeHex);
                if (!string.IsNullOrEmpty(_analyzeResult))
                    ImGui.InputTextMultiline("##pares", ref _analyzeResult, 4000, new Vector2(-1, 120), ImGuiInputTextFlags.ReadOnly);

                ImGui.Separator();
            }

            // ── Test Lab ──────────────────────────────────────────────────────
            ImGui.TextColored(new Vector4(.4f,.8f,1f,1f), "Test Lab");

            if (ImGui.Button("Deep Diagnose Last Packet"))
            {
                Task.Run(() =>
                {
                    var packets = _state.PacketLog.GetLast(200);
                    var quic = packets.Where(p => !p.IsTcp).ToList();
                    if (quic.Count == 0) { _testResult = "No QUIC packets captured yet."; return; }

                    // First: scan for Initial packet
                    var initLines = QUICDecryptionDiagnostic.AnalyzeFirstPackets(quic.Select(p => p.RawBytes));
                    var sb = new System.Text.StringBuilder();
                    foreach (var l in initLines) sb.AppendLine(l.Replace("[SESSIONDIAG] ",""));

                    // Then: deep diagnose the last S2C packet
                    var s2c = quic.LastOrDefault(p => p.Direction == Networking.PacketDirection.ServerToClient);
                    var target = s2c ?? quic.Last();
                    sb.AppendLine();
                    sb.AppendLine($"=== Diagnosing packet {target.RawBytes.Length}B ===");
                    var diag = QUICDecryptionDiagnostic.DiagnosePacket(target.RawBytes);
                    foreach (var l in diag.Steps.Concat(diag.Errors))
                        sb.AppendLine(l.Replace("[DIAG] ",""));

                    _testResult = sb.ToString();
                    _state.AddInGameLog($"[TESTLAB] Deep diag: {diag.Summary}");
                });
            }
            ImGui.SameLine();
            if (ImGui.Button("Verify RFC 9001 Derivation")) RunTestVector();

            ImGui.Text("Manual hex:");
            ImGui.InputTextMultiline("##hex", ref _hexInput, 20000, new Vector2(-1, 80));

            if (ImGui.Button("Decrypt"))
            {
                _testResult = "Decrypting...";
                Task.Run(() => DoDecrypt());
            }
            ImGui.SameLine();
            if (ImGui.Button("Paste")) { try { _hexInput = ImGui.GetClipboardText(); } catch { } }
            ImGui.SameLine();
            if (ImGui.Button("Clear")) { _hexInput = ""; _testResult = ""; }

            ImGui.Separator();
            if (!string.IsNullOrEmpty(_testResult))
            {
                var col = _testResult.Contains("SUCCESS") || _testResult.Contains("PASS")
                    ? new Vector4(.2f,1f,.4f,1f)
                    : _testResult.Contains("FAIL") || _testResult.Contains("Error")
                        ? new Vector4(1f,.3f,.3f,1f)
                        : new Vector4(.8f,.8f,.8f,1f);
                ImGui.InputTextMultiline("##res", ref _testResult, 20000, new Vector2(-1, -1), ImGuiInputTextFlags.ReadOnly);
            }

            ImGui.EndChild();
        }

        private string ScanDPAPI()
        {
            throw new NotImplementedException();
        }

        private void DoDecrypt()
        {
            if (string.IsNullOrWhiteSpace(_hexInput)) { _testResult = "Paste hex first."; return; }
            try
            {
                byte[] data = Convert.FromHexString(_hexInput.Replace(" ","").Replace("-","").Replace(":","").Replace("\n","").Replace("\r",""));
                var sb = new StringBuilder();
                sb.AppendLine($"Packet: {data.Length} bytes  Keys: {PacketDecryptor.DiscoveredKeys.Count}");
                sb.AppendLine($"Label: {_fmtLabels[_selectedFmt]}");
                sb.AppendLine($"First 16: {Convert.ToHexString(data.Take(16).ToArray()).ToLower()}");
                sb.AppendLine();

                // Try all label formats until one succeeds
                bool anySuccess = false;
                foreach (var fmt in new[] {
                    (PacketDecryptor.HkdfLabelFormat)_selectedFmt,
                    PacketDecryptor.HkdfLabelFormat.RFC8446_WithPrefix,
                    PacketDecryptor.HkdfLabelFormat.RFC9001_NoPrefix })
                {
                    var capturedFmt = fmt;
                    var task = Task.Run(() => PacketDecryptor.TryDecryptManual(data, 8000, capturedFmt));
                    if (!task.Wait(500)) { sb.AppendLine($"TIMEOUT (500ms) for {fmt}"); continue; }
                    var r = task.Result;
                    if (r.Success)
                    {
                        sb.AppendLine($"SUCCESS with format={fmt}");
                        sb.AppendLine($"  {r.DecryptedData.Length} bytes decrypted");
                        sb.AppendLine($"  Hex: {Convert.ToHexString(r.DecryptedData.Take(64).ToArray()).ToLower()}");
                        try { sb.AppendLine($"  ASCII: {Encoding.ASCII.GetString(r.DecryptedData.Take(64).ToArray()).Replace("\0",".")}"); } catch { }
                        anySuccess = true;
                        break;
                    }
                    sb.AppendLine($"FAIL [{fmt}]: {r.ErrorMessage}");
                }

                if (!anySuccess)
                {
                    sb.AppendLine();
                    sb.AppendLine("Possible causes:");
                    if (PacketDecryptor.DiscoveredKeys.Count == 0)
                        sb.AppendLine("  No keys loaded - launch Hytale first");
                    else
                    {
                        sb.AppendLine($"  {PacketDecryptor.DiscoveredKeys.Count} keys tried, all failed");
                        sb.AppendLine("  Most likely: keys from a DIFFERENT TLS session than this packet");
                        sb.AppendLine("  Fix: restart Hytale WHILE HyForce proxy is running");
                        sb.AppendLine("  Note: Netty QUIC default DCID = 20 bytes for 1-RTT packets");
                    }
                }
                _testResult = sb.ToString();
            }
            catch (Exception ex) { _testResult = $"Error: {ex.Message}"; }
        }

        private void RunTestVector()
        {
            Task.Run(() =>
            {
                try
                {
                    // RFC 9001 A.1: derive client_in_secret from DCID 8394c8f03e515708
                    byte[] salt    = Convert.FromHexString("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
                    byte[] dcid    = Convert.FromHexString("8394c8f03e515708");
                    byte[] initSec = HKDF.Extract(HashAlgorithmName.SHA256, dcid, salt);
                    byte[] lbl     = Encoding.ASCII.GetBytes("tls13 client in");
                    byte[] info    = new byte[3 + lbl.Length + 1];
                    info[1] = 32; info[2] = (byte)lbl.Length;
                    lbl.CopyTo(info, 3);
                    byte[] secret = HKDF.Expand(HashAlgorithmName.SHA256, initSec, 32, info);

                    var saved = PacketDecryptor.CurrentLabelFormat;
                    PacketDecryptor.CurrentLabelFormat = PacketDecryptor.HkdfLabelFormat.RFC8446_WithPrefix;
                    var k = new PacketDecryptor.EncryptionKey { Secret = secret, Type = PacketDecryptor.EncryptionType.QUIC_Client1RTT, Source = "RFC9001-A.1" };
                    PacketDecryptor.DeriveQUICKeys(k);
                    PacketDecryptor.CurrentLabelFormat = saved;

                    bool kOk = k.Key?.SequenceEqual(Convert.FromHexString("1f369613dd76d5467730efcbe3b1a22d")) == true;
                    bool iOk = k.IV?.SequenceEqual(Convert.FromHexString("fa044b2f42a3fd3b46fb255c")) == true;
                    bool hOk = k.HeaderProtectionKey?.SequenceEqual(Convert.FromHexString("9f50449e04a0e810283a1e9933adedd2")) == true;

                    string pass = kOk && iOk && hOk ? "✓ ALL PASS" : "✗ FAIL";
                    var sb = new StringBuilder();
                    sb.AppendLine($"RFC 9001 Appendix A.1 Test Vector: {pass}");
                    sb.AppendLine($"Key: {(kOk?"PASS":"FAIL")}  Got: {(k.Key != null ? Convert.ToHexString(k.Key) : "null")}");
                    sb.AppendLine($"IV:  {(iOk?"PASS":"FAIL")}  Got: {(k.IV != null ? Convert.ToHexString(k.IV) : "null")}");
                    sb.AppendLine($"HP:  {(hOk?"PASS":"FAIL")}  Got: {(k.HeaderProtectionKey != null ? Convert.ToHexString(k.HeaderProtectionKey) : "null")}");
                    if (kOk && iOk && hOk)
                    {
                        sb.AppendLine();
                        sb.AppendLine("HKDF is correct. If decryption still fails:");
                        sb.AppendLine("1. DCID length mismatch - Netty uses 20 bytes by default");
                        sb.AppendLine("2. Keys from wrong session - restart Hytale to get fresh keys");
                        sb.AppendLine("3. Packet number counter out of sync");
                    }
                    _testResult = sb.ToString();
                    _state.AddInGameLog($"[TESTLAB] RFC 9001: Key:{(kOk?"PASS":"FAIL")} IV:{(iOk?"PASS":"FAIL")} HP:{(hOk?"PASS":"FAIL")} → {pass}");
                }
                catch (Exception ex) { _testResult = $"Test vector error: {ex.Message}"; }
            });
        }

        private void ExportDiagnostics()
        {
            _state.AddInGameLog("[EXPORT] Starting diagnostics export...");
            Task.Run(() =>
            {
                var sb = new StringBuilder();
                sb.AppendLine("=== HyForce Decryption Diagnostics ===");
                sb.AppendLine($"Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                sb.AppendLine($"Session log: {_state.SessionLogPath}");
                sb.AppendLine();

                // ── Stats ──
                try
                {
                    sb.AppendLine("--- Decryption Stats ---");
                    sb.AppendLine($"  Keys:         {PacketDecryptor.DiscoveredKeys.Count}");
                    sb.AppendLine($"  Successful:   {PacketDecryptor.SuccessfulDecryptions}");
                    sb.AppendLine($"  Failed:       {PacketDecryptor.FailedDecryptions}");
                    sb.AppendLine($"  HP-filtered:  {PacketDecryptor.SkippedDecryptions}");
                    sb.AppendLine($"  Label:        {PacketDecryptor.CurrentLabelFormat}");
                    sb.AppendLine();
                    _state.AddInGameLog("[EXPORT] Stats ✓");
                }
                catch (Exception ex) { sb.AppendLine($"  [STATS ERROR] {ex.Message}"); _state.AddInGameLog($"[EXPORT] Stats error: {ex.Message}"); }

                // ── RFC 9001 self-test ──
                try
                {
                    sb.AppendLine("--- RFC 9001 Self-Test ---");
                    var testLines = QUICDecryptionDiagnostic.RunRFC9001SelfTest();
                    foreach (var l in testLines) sb.AppendLine(l);
                    sb.AppendLine();
                    string result = testLines.LastOrDefault() ?? "?";
                    _state.AddInGameLog($"[EXPORT] RFC9001: {result}");
                }
                catch (Exception ex) { sb.AppendLine($"  [RFC9001 ERROR] {ex.Message}"); _state.AddInGameLog($"[EXPORT] RFC9001 error: {ex.Message}"); }

                // ── Keys ──
                try
                {
                    sb.AppendLine("--- Active Keys ---");
                    foreach (var k in PacketDecryptor.DiscoveredKeys)
                    {
                        sb.AppendLine($"  [{k.Type}]  src={k.Source}  added={k.DiscoveredAt:HH:mm:ss}");
                        sb.AppendLine($"    secret= {Convert.ToHexString(k.Secret ?? Array.Empty<byte>())}");
                        sb.AppendLine($"    key=    {Convert.ToHexString(k.Key ?? Array.Empty<byte>())}");
                        sb.AppendLine($"    iv=     {Convert.ToHexString(k.IV ?? Array.Empty<byte>())}");
                        sb.AppendLine($"    hp=     {Convert.ToHexString(k.HeaderProtectionKey ?? Array.Empty<byte>())}");
                    }
                    sb.AppendLine();
                    _state.AddInGameLog($"[EXPORT] {PacketDecryptor.DiscoveredKeys.Count} keys dumped ✓");
                }
                catch (Exception ex) { sb.AppendLine($"  [KEYS ERROR] {ex.Message}"); _state.AddInGameLog($"[EXPORT] Keys error: {ex.Message}"); }

                // ── Last packets ──
                try
                {
                    sb.AppendLine("--- Last 10 QUIC Packets (hex + diagnosis) ---");
                    var pkts = _state.PacketLog.GetLast(500).Where(p => !p.IsTcp).TakeLast(10).ToList();
                    _state.AddInGameLog($"[EXPORT] Diagnosing {pkts.Count} packets...");
                    foreach (var pkt in pkts)
                    {
                        sb.AppendLine($"  [{pkt.Direction}] {pkt.RawBytes.Length}B  0x{pkt.RawBytes[0]:X2}");
                        sb.AppendLine($"  HEX: {Convert.ToHexString(pkt.RawBytes).ToLower()}");
                        try
                        {
                            var diag = QUICDecryptionDiagnostic.DiagnosePacket(pkt.RawBytes);
                            foreach (var l in diag.Steps.Concat(diag.Errors)) sb.AppendLine($"    {l}");
                        }
                        catch (Exception ex2) { sb.AppendLine($"    [DIAG ERR] {ex2.Message}"); }
                        sb.AppendLine();
                    }
                    _state.AddInGameLog("[EXPORT] Packets dumped ✓");
                }
                catch (Exception ex) { sb.AppendLine($"  [PACKETS ERROR] {ex.Message}"); _state.AddInGameLog($"[EXPORT] Packets error: {ex.Message}"); }

                // ── In-game log ──
                try
                {
                    sb.AppendLine("--- In-Game Log (last 200) ---");
                    foreach (var entry in _state.GetRecentLog(200)) sb.AppendLine($"  {entry}");
                    sb.AppendLine();
                }
                catch (Exception ex) { sb.AppendLine($"  [LOG ERROR] {ex.Message}"); }

                sb.AppendLine($"--- Live Session Log ---");
                sb.AppendLine($"  File: {_state.SessionLogPath}");

                // ── Write ──
                try
                {
                    string outPath = Path.Combine(_state.ExportDirectory,
                        $"decrypt_diag_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
                    Directory.CreateDirectory(_state.ExportDirectory);
                    File.WriteAllText(outPath, sb.ToString());
                    _testResult = $"✓ Exported to:{outPath} Live log:{_state.SessionLogPath}";

                    _state.AddInGameLog($"[EXPORT] ✓ {Path.GetFileName(outPath)}");
                    try { System.Diagnostics.Process.Start("notepad.exe", outPath); } catch { }
                }
                catch (Exception ex)
                {
                    _testResult = $"File write failed: {ex.Message}Content:{sb.ToString().Substring(0, Math.Min(400, sb.Length))}";

                    _state.AddInGameLog($"[EXPORT] ✗ Write failed: {ex.Message}");
                }
            });
        }

        private static string ScanDPAPI(string searchOption)
        {
            var sb = new StringBuilder();
            int found = 0;

            // Common locations to search
            var candidates = new List<string>();

            if (searchOption == "Common locations" || searchOption == "All")
            {
                string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                candidates.Add(Path.Combine(home, "AppData", "Roaming", "Hytale", ".keys"));
                candidates.Add(Path.Combine(home, "AppData", "Local", "Hytale", ".keys"));
                candidates.Add(Path.Combine(home, ".hytale", "keys"));
                candidates.Add(Path.Combine(home, "source", "repos", "HyForce", "Exported logs"));
            }

            if (searchOption == "Current directory" || searchOption == "All")
            {
                candidates.Add(Directory.GetCurrentDirectory());
            }

            // MANUAL PATH - Add your specific Hytale keys folder
            string manualKeyPath = @"C:\Users\benja\AppData\Roaming\Hytale\.keys";
            if (!candidates.Contains(manualKeyPath, StringComparer.OrdinalIgnoreCase))
            {
                candidates.Insert(0, manualKeyPath); // Put first so it tries manual path first
            }

            sb.AppendLine($"Scanning {candidates.Count} location(s) for .key files...\n");

            foreach (var dir in candidates.Where(Directory.Exists))
            {
                sb.AppendLine($"[{dir}]");

                try
                {
                    var files = Directory.GetFiles(dir, "*.key", SearchOption.TopDirectoryOnly);

                    foreach (var f in files)
                    {
                        found++;
                        sb.AppendLine($"\n  File: {Path.GetFileName(f)}");

                        try
                        {
                            byte[] raw = File.ReadAllBytes(f);
                            sb.AppendLine($"    Size: {raw.Length}b");
                            sb.AppendLine($"    Header: {Convert.ToHexString(raw.Take(8).ToArray())}");

                            try
                            {
                                byte[] dec = System.Security.Cryptography.ProtectedData.Unprotect(
                                    raw,
                                    null,
                                    System.Security.Cryptography.DataProtectionScope.CurrentUser);

                                sb.AppendLine($"    DPAPI: SUCCESS -> {dec.Length} bytes");
                                sb.AppendLine($"    Data: {Convert.ToHexString(dec.Take(32).ToArray())}...");
                            }
                            catch (CryptographicException)
                            {
                                sb.AppendLine("    DPAPI: Cannot decrypt (different user/machine?)");
                            }
                            catch (Exception ex)
                            {
                                sb.AppendLine($"    Error: {ex.Message}");
                            }
                        }
                        catch (Exception ex)
                        {
                            sb.AppendLine($"    Read error: {ex.Message}");
                        }
                    }

                    if (files.Length == 0)
                    {
                        sb.AppendLine("  (no .key files)");
                    }
                }
                catch (Exception ex)
                {
                    sb.AppendLine($"  Access error: {ex.Message}");
                }

                sb.AppendLine();
            }

            // If still nothing found, show manual path suggestion
            if (found == 0)
            {
                sb.AppendLine("No .key files found in any location.");
                sb.AppendLine();
                sb.AppendLine("To add a manual path, edit this line in DecryptionTab.cs:");
                sb.AppendLine($"  string manualKeyPath = @\"{manualKeyPath}\";");
                sb.AppendLine();
                sb.AppendLine("Or set the HYFORCE_KEY_PATH environment variable.");
            }
            else
            {
                sb.AppendLine($"=== Total: {found} file(s) found ===");
            }

            return sb.ToString();
        }

        private static string Analyze(string hex)
        {
            if (string.IsNullOrWhiteSpace(hex)) return "Paste hex packet first.";
            try
            {
                byte[] p = Convert.FromHexString(hex.Replace(" ","").Replace("-","").Replace("\n","").Replace("\r",""));
                var sb = new StringBuilder();
                sb.AppendLine($"Size: {p.Length} bytes");
                sb.AppendLine($"Byte0: 0x{p[0]:X2} = {Convert.ToString(p[0],2).PadLeft(8,'0')}b");
                bool isLong = (p[0] & 0x80) != 0;
                bool fixed1 = (p[0] & 0x40) != 0;
                sb.AppendLine($"Header: {(isLong ? "LONG" : "SHORT (1-RTT)")}  Fixed-bit: {(fixed1?"✓":"✗ may not be QUIC")}");

                if (isLong && p.Length >= 6)
                {
                    uint ver = (uint)(p[1]<<24|p[2]<<16|p[3]<<8|p[4]);
                    string verStr = ver == 1 ? "QUIC v1" : ver == 0x6b3343cf ? "QUIC v2" : $"unknown 0x{ver:X}";
                    byte[] pktTypes = { (byte)((p[0]>>4)&0x3) };
                    string[] names = { "Initial","0-RTT","Handshake","Retry" };
                    sb.AppendLine($"Version: {verStr}  Type: {names[pktTypes[0]]}");
                    int dcidLen = p[5];
                    sb.AppendLine($"DCID length: {dcidLen}  DCID: {(p.Length>6+dcidLen?Convert.ToHexString(p.Skip(6).Take(dcidLen).ToArray()):"?")}");
                }
                else if (!isLong)
                {
                    sb.AppendLine($"Spin: {(p[0]>>5)&1}  KeyPhase: {(p[0]>>2)&1}  PN-len bits: {(p[0]&3)+1}");
                    sb.AppendLine("DCID guesses (Netty default = 20 bytes):");
                    foreach (int d in new[]{8,16,20})
                    {
                        int so = 1+d+4;
                        if (p.Length >= so+4)
                            sb.AppendLine($"  dcid={d}: pn_region={Convert.ToHexString(p.Skip(1+d).Take(4).ToArray())} sample={Convert.ToHexString(p.Skip(so).Take(4).ToArray())}");
                    }
                }

                double h = 0; var freq = new int[256]; foreach (var b in p) freq[b]++;
                foreach (var f in freq) if(f>0){double pp=(double)f/p.Length; h-=pp*Math.Log2(pp);}
                sb.AppendLine($"Entropy: {h:F2}/8.0  {(h>6.5?"(likely encrypted)":"(may be plaintext)")}");
                sb.AppendLine($"Keys ready: {PacketDecryptor.DiscoveredKeys.Count}");
                return sb.ToString();
            }
            catch (Exception ex) { return $"Error: {ex.Message}"; }
        }

        private static void Pill(string text, Vector4 col)
        {
            ImGui.PushStyleColor(ImGuiCol.Button, col with { W = .22f });
            ImGui.PushStyleColor(ImGuiCol.ButtonHovered, col with { W = .22f });
            ImGui.PushStyleColor(ImGuiCol.Text, col);
            ImGui.PushStyleColor(ImGuiCol.Border, col with { W = .55f });
            ImGui.SmallButton(text);
            ImGui.PopStyleColor(4);
        }
    }
}
