// FILE: Tabs/DecryptionTab.cs
// Fully automatic SSLKEYLOGFILE -- zero manual steps after first-time setup
using HyForce.Core;
using HyForce.Protocol;
using HyForce.UI;
using ImGuiNET;
using System.Numerics;
using System.Text;

namespace HyForce.Tabs;

public class DecryptionTab : ITab
{
    public string Name => "Decryption";

    private readonly AppState _state;

    // Key management
    private string   _manualKey        = "";
    private int      _selectedKeyType  = 1;
    private int      _selectedKeyIndex = -1;
    private string   _statusMessage    = "";
    private float    _statusTime       = 0;
    private List<PacketDecryptor.EncryptionKey> _cachedKeys      = new();
    private DateTime _lastKeyCacheTime = DateTime.MinValue;

    // Wizard / advanced
    private bool _showAdvanced  = false;
    private bool _showRfcRef    = false;
    private int  _wizardStep    = 1;

    // Test lab
    private string _testLabHex    = "";
    private string _testLabResult = "";
    private bool   _testLabRunning = false;
    private PacketDecryptor.DecryptionResult? _lastResult;

    // Layout
    private float _leftW = 430f;

    public DecryptionTab(AppState state)
    {
        _state = state;
        _state.OnKeysUpdated += () =>
        {
            _statusMessage    = "New keys loaded!";
            _statusTime       = (float)ImGui.GetTime();
            _lastKeyCacheTime = DateTime.MinValue;
        };
    }

    // =========================================================================
    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();

        ImGui.Spacing();
        ImGui.TextColored(Theme.ColAccent, "PACKET DECRYPTION");
        ImGui.SameLine(0, 6);
        ImGui.TextColored(Theme.ColTextMuted, "-- Automatic TLS 1.3 / QUIC Key Management");
        ImGui.Separator();
        ImGui.Spacing();

        // ── Main auto-status card (always visible, most important) ────────────
        RenderAutoStatusCard();
        ImGui.Spacing();

        // ── Key stats bar ─────────────────────────────────────────────────────
        RenderKeyStatsBar();
        ImGui.Spacing();
        ImGui.Separator();
        ImGui.Spacing();

        // ── Split: key list (left) + test lab (right) ─────────────────────────
        float colH = Math.Max(220, avail.Y - ImGui.GetCursorPosY() - 10);
        float rightW = avail.X - _leftW - 8;
        if (rightW < 200) { _leftW = avail.X - 208; rightW = 200; }

        ImGui.BeginChild("##dec_left",  new Vector2(_leftW, colH));
        RenderKeyList();
        ImGui.EndChild();

        ImGui.SameLine(0, 2);
        ImGui.Button("##vsplit_d", new Vector2(4, colH));
        if (ImGui.IsItemActive()) { _leftW += ImGui.GetIO().MouseDelta.X; _leftW = Math.Clamp(_leftW, 220, avail.X - 220); }
        if (ImGui.IsItemHovered()) ImGui.SetMouseCursor(ImGuiMouseCursor.ResizeEW);

        ImGui.SameLine(0, 2);
        ImGui.BeginChild("##dec_right", new Vector2(rightW, colH));
        RenderTestLab();
        ImGui.EndChild();

        // ── Advanced / RFC reference ──────────────────────────────────────────
        if (_showRfcRef) { ImGui.Spacing(); RenderRfcRef(); }
    }

    // =========================================================================
    // AUTO STATUS CARD — the main panel users see
    // =========================================================================
    private void RenderAutoStatusCard()
    {
        var status   = _state.GetKeyStatus();
        bool hasKeys = status.TotalKeys > 0;
        bool hasDecr = status.SuccessfulDecryptions > 0;
        bool needsSetup = _state.NeedsFirstTimeSetup;

        // Choose card color and message
        Vector4 cardCol;
        string  headline;
        string  subline;

        if (hasDecr)
        {
            cardCol  = Theme.ColSuccess;
            headline = $"DECRYPTING  --  {status.SuccessfulDecryptions:N0} packets decrypted";
            subline  = $"{status.TotalKeys} key(s) active  |  {Path.GetFileName(_state.PermanentKeyLogPath)}";
        }
        else if (hasKeys)
        {
            cardCol  = Theme.ColWarn;
            headline = $"KEYS READY ({status.TotalKeys})  --  waiting for QUIC traffic";
            subline  = "Start capturing to see decryption results";
        }
        else if (needsSetup)
        {
            cardCol  = Theme.ColDanger;
            headline = "ONE-TIME SETUP REQUIRED";
            subline  = "SSLKEYLOGFILE has been set -- restart Hytale once, then everything is automatic.";
        }
        else
        {
            cardCol  = Theme.ColWarn;
            headline = "WAITING FOR HYTALE";
            subline  = "Launch Hytale -- keys will appear here automatically when it connects.";
        }

        // Card background
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(cardCol.X*.15f, cardCol.Y*.15f, cardCol.Z*.15f, 1f));
        ImGui.PushStyleColor(ImGuiCol.Border,   cardCol with { W = .8f });
        ImGui.BeginChild("##auto_card", new Vector2(0, needsSetup ? 120 : 82), ImGuiChildFlags.Borders);

        ImGui.Spacing();
        ImGui.SetCursorPosX(10);
        ImGui.TextColored(cardCol, headline);
        ImGui.SetCursorPosX(10);
        ImGui.TextColored(Theme.ColTextMuted, subline);

        if (needsSetup)
        {
            ImGui.Spacing();
            ImGui.SetCursorPosX(10);
            ImGui.TextColored(Theme.ColAccent, "What to do right now:");
            ImGui.SetCursorPosX(18);
            ImGui.TextColored(Theme.ColTextMuted,
                "1. Close Hytale completely  2. Launch Hytale  3. Done forever.");
            ImGui.SetCursorPosX(10);
            ImGui.TextColored(Theme.ColTextMuted,
                "After that one restart you never need to touch this tab again.");
        }

        ImGui.Spacing();
        ImGui.SetCursorPosX(10);

        // Action buttons -- only the ones relevant for current state
        BtnAccent("Re-Import Keys", () =>
        {
            _state.ForceReImportKeys();
            _statusMessage = "Re-importing...";
            _statusTime    = (float)ImGui.GetTime();
        });
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("Re-reads the entire permanent log file.\nUse if HyForce was opened after Hytale was already running.");

        ImGui.SameLine(0, 6);

        BtnNeutral("Open Key Log File", () =>
        {
            try { System.Diagnostics.Process.Start("notepad.exe", _state.PermanentKeyLogPath); } catch { }
        });
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip(_state.PermanentKeyLogPath);

        ImGui.SameLine(0, 6);

        BtnNeutral(_showAdvanced ? "Hide Advanced" : "Advanced", () => _showAdvanced = !_showAdvanced);

        if (!string.IsNullOrEmpty(_statusMessage) && ImGui.GetTime() - _statusTime < 3.0)
        {
            ImGui.SameLine(0, 10);
            ImGui.TextColored(Theme.ColSuccess, _statusMessage);
        }

        ImGui.EndChild();
        ImGui.PopStyleColor(2);

        // Advanced collapsible section
        if (_showAdvanced) RenderAdvancedSection();
    }

    // =========================================================================
    // ADVANCED SECTION (hidden by default)
    // =========================================================================
    private void RenderAdvancedSection()
    {
        ImGui.Spacing();
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(.10f,.10f,.13f,1f));
        ImGui.BeginChild("##advanced", new Vector2(0, 0), ImGuiChildFlags.Borders | ImGuiChildFlags.AutoResizeY);



        ImGui.TextColored(Theme.ColAccent, "Advanced / Manual Controls");
        ImGui.Separator();
        ImGui.Spacing();

        // Permanent log info
        ImGui.TextColored(Theme.ColTextMuted, "Permanent key log path:");
        ImGui.SameLine();
        ImGui.TextColored(Theme.Current?.Text ?? Vector4.One, _state.PermanentKeyLogPath);


        if (File.Exists(_state.PermanentKeyLogPath))
        {
            var fi = new FileInfo(_state.PermanentKeyLogPath);
            ImGui.TextColored(Theme.ColTextMuted, $"Size: {fi.Length:N0} bytes  |  Modified: {fi.LastWriteTime:HH:mm:ss}  |  Lines with keys: ~{(fi.Length / 120)}");
        }

        ImGui.Spacing();

        // Show env var status
        string? userVal = Environment.GetEnvironmentVariable("SSLKEYLOGFILE", EnvironmentVariableTarget.User);
        string? machVal = Environment.GetEnvironmentVariable("SSLKEYLOGFILE", EnvironmentVariableTarget.Machine);
        bool userOk  = string.Equals(userVal,  _state.PermanentKeyLogPath, StringComparison.OrdinalIgnoreCase);
        bool machOk  = string.Equals(machVal,  _state.PermanentKeyLogPath, StringComparison.OrdinalIgnoreCase);

        ImGui.TextColored(Theme.ColTextMuted, "SSLKEYLOGFILE env var:");
        ImGui.SameLine();
        if (userOk || machOk)
            ImGui.TextColored(Theme.ColSuccess, $"OK  ({(userOk ? "User" : "Machine")} scope)");
        else
            ImGui.TextColored(Theme.ColDanger, $"Not pointing at our file  (User={userVal ?? "unset"})");

        ImGui.Spacing();
        ImGui.Separator();
        ImGui.TextColored(Theme.ColTextMuted, "Manual key entry:");

        string[] keyTypes = { "AES-128", "AES-256", "XOR" };
        ImGui.SetNextItemWidth(120);
        ImGui.Combo("##kt", ref _selectedKeyType, keyTypes, keyTypes.Length);
        ImGui.SameLine();
        ImGui.SetNextItemWidth(300);
        ImGui.InputText("##mk", ref _manualKey, 256);
        ImGui.SameLine();
        BtnAccent("Add##mk", AddManualKey);

        ImGui.Spacing();
        BtnDanger("Clear All Keys", () =>
        {
            PacketDecryptor.ClearKeys();
            _state.AddInGameLog("[DECRYPT] All keys cleared");
            _lastKeyCacheTime = DateTime.MinValue;
        });
        ImGui.SameLine(0, 6);
        BtnDanger("Clear + Wipe Log File", () => _state.ClearPermanentKeyLog());
        ImGui.SameLine(0, 6);
        BtnNeutral("RFC 9001 Reference", () => _showRfcRef = !_showRfcRef);
        ImGui.SameLine(0, 6);
        BtnNeutral("Verify Derivation", VerifyKeyDerivation);

        // Auto-decrypt toggle
        ImGui.Spacing();
        bool ad = PacketDecryptor.AutoDecryptEnabled;
        if (ImGui.Checkbox("Auto-Decrypt on capture", ref ad))
        {
            PacketDecryptor.AutoDecryptEnabled = ad;
            _state.AddInGameLog($"[DECRYPT] Auto-decrypt {(ad ? "ON" : "OFF")}");
        }
        ImGui.Spacing();
        BtnAccent("EMERGENCY: Scan ALL Key Locations", () =>
        {
            _state.ScanAllPossibleKeyLocations();
        });

        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("Searches everywhere for SSL key logs and imports them");

        ImGui.EndChild();
        ImGui.PopStyleColor();
        ImGui.Spacing();
    }

    // =========================================================================
    // KEY STATS BAR
    // =========================================================================
    private void RenderKeyStatsBar()
    {
        var st = _state.GetKeyStatus();
        UpdateKeyCache();

        // Mini stat pills
        StatPill("Keys",    st.TotalKeys.ToString(),                   st.TotalKeys > 0 ? Theme.ColSuccess : Theme.ColTextMuted);
        ImGui.SameLine(0, 4);
        StatPill("Decrypted", st.SuccessfulDecryptions.ToString("N0"), st.SuccessfulDecryptions > 0 ? Theme.ColSuccess : Theme.ColTextMuted);
        ImGui.SameLine(0, 4);
        StatPill("Failed",  st.FailedDecryptions.ToString("N0"),       st.FailedDecryptions > 0 ? Theme.ColWarn : Theme.ColTextMuted);
        ImGui.SameLine(0, 4);

        // Source breakdown
        var sources = st.KeySources.Select(Path.GetFileName).Distinct().Take(3).ToList();
        if (sources.Any())
        {
            ImGui.TextColored(Theme.ColTextMuted, " from:");
            foreach (var src in sources)
            {
                ImGui.SameLine(0, 4);
                ImGui.TextColored(Theme.ColTextMuted, src ?? "?");
            }
        }

        // Last key time
        if (st.LastKeyAdded.HasValue)
        {
            ImGui.SameLine(0, 10);
            ImGui.TextColored(Theme.ColTextMuted, $"last: {st.LastKeyAdded.Value:HH:mm:ss}");
        }
    }

    // =========================================================================
    // KEY LIST (left column)
    // =========================================================================
    private void RenderKeyList()
    {
        ImGui.TextColored(Theme.ColAccent, $"Active Keys  ({_cachedKeys.Count})");
        ImGui.Separator();
        ImGui.Spacing();

        ImGui.BeginChild("##klist", new Vector2(-1, -1), ImGuiChildFlags.Borders);

        if (_cachedKeys.Count == 0)
        {
            ImGui.Spacing();
            ImGui.SetCursorPosX(10);
            ImGui.TextColored(Theme.ColTextMuted, "No keys yet.");
            ImGui.SetCursorPosX(10);
            ImGui.TextColored(Theme.ColTextMuted, "Launch Hytale -- they'll appear here automatically.");
            ImGui.EndChild();
            return;
        }

        for (int i = 0; i < _cachedKeys.Count; i++)
        {
            var  k   = _cachedKeys[i];
            bool sel = _selectedKeyIndex == i;
            ImGui.PushID(i);

            var cc = k.Type switch
            {
                PacketDecryptor.EncryptionType.QUIC_Client1RTT    => Theme.ColSuccess,
                PacketDecryptor.EncryptionType.QUIC_Server1RTT    => Theme.ColAccent,
                PacketDecryptor.EncryptionType.QUIC_ClientHandshake => Theme.ColInfo,
                PacketDecryptor.EncryptionType.QUIC_ServerHandshake => Theme.ColInfo,
                PacketDecryptor.EncryptionType.QUIC_Client0RTT    => Theme.ColWarn,
                _ => Theme.ColTextMuted
            };

            // Color bar
            ImGui.PushStyleColor(ImGuiCol.Text, cc);
            ImGui.Text("|");
            ImGui.PopStyleColor();
            ImGui.SameLine(0, 4);

            ImGui.BeginGroup();
            string ago     = (DateTime.Now - k.DiscoveredAt).TotalMinutes < 1 ? "just now"
                           : $"{(DateTime.Now - k.DiscoveredAt).TotalMinutes:F0}m ago";
            string derived = k.Key.Length == 16 ? " [RFC9001]" : "";
            bool   isSelected = ImGui.Selectable($"{k.Type}{derived}##k{i}", sel,
                                                 ImGuiSelectableFlags.AllowOverlap | ImGuiSelectableFlags.SpanAllColumns,
                                                 new Vector2(0, sel ? 52 : 32));
            if (isSelected) _selectedKeyIndex = sel ? -1 : i;

            ImGui.SameLine();
            ImGui.TextColored(Theme.ColTextMuted, $"{ago}  used:{k.UseCount}x");

            if (sel)
            {
                ImGui.SetCursorPosX(ImGui.GetCursorPosX() + 8);
                ImGui.TextColored(Theme.ColTextMuted, $"src: {Path.GetFileName(k.Source)}");
                if (k.Key.Length > 0)
                {
                    string kp = BitConverter.ToString(k.Key.Take(8).ToArray()).Replace("-", " ") + "...";
                    ImGui.SetCursorPosX(ImGui.GetCursorPosX() + 8);
                    ImGui.TextColored(Theme.ColTextMuted, $"key: {kp} ({k.Key.Length * 8}bit)");
                }
            }
            ImGui.EndGroup();

            ImGui.Separator();
            ImGui.PopID();
        }

        ImGui.EndChild();
    }

    // =========================================================================
    // TEST LAB (right column)
    // =========================================================================
    private void RenderTestLab()
    {
        ImGui.TextColored(Theme.ColAccent, "Test Lab");
        ImGui.Separator();
        ImGui.Spacing();

        BtnSuccess("Test Last QUIC Packet", TestLastQuicPacket);
        ImGui.SameLine(0, 6);
        BtnNeutral("Verify RFC 9001 Derivation", VerifyKeyDerivation);

        ImGui.Spacing();
        ImGui.TextColored(Theme.ColTextMuted, "Manual hex:");
        ImGui.SetNextItemWidth(-1);
        ImGui.InputTextMultiline("##tlhex", ref _testLabHex, 8192, new Vector2(-1, 75));

        BtnAccent("Decrypt##tl", TestManualHexDecrypt);
        ImGui.SameLine(0, 4);
        BtnNeutral("Paste##tl", () => { try { _testLabHex = TextCopy.ClipboardService.GetText() ?? ""; } catch { } });
        ImGui.SameLine(0, 4);
        BtnNeutral("Clear##tl", () => { _testLabHex = ""; _testLabResult = ""; });

        ImGui.Spacing();
        ImGui.Separator();

        if (_testLabRunning)
            ImGui.TextColored(Theme.ColWarn, "Running...");
        else if (!string.IsNullOrEmpty(_testLabResult))
        {
            var rc = _testLabResult.StartsWith("SUCCESS") ? Theme.ColSuccess : Theme.ColDanger;
            ImGui.TextColored(rc, _testLabResult);
        }
        else
            ImGui.TextColored(Theme.ColTextMuted, "Run a test to see results.");

        if (_lastResult?.Success == true && _lastResult.DecryptedData != null)
        {
            ImGui.Spacing();
            ImGui.Separator();
            ImGui.TextColored(Theme.ColAccent, "Last Result:");
            ImGui.TextColored(Theme.ColTextMuted, $"  {_lastResult.DecryptedData.Length}B  |  PN={_lastResult.PacketNumber}  |  {_lastResult.Metadata.GetValueOrDefault("algorithm","?")}");
            string hex16 = BitConverter.ToString(_lastResult.DecryptedData.Take(16).ToArray()).Replace("-", " ");
            ImGui.TextColored(Theme.ColSuccess, $"  {hex16}...");

            BtnNeutral("Export Decrypted", () =>
            {
                try
                {
                    string fn = Path.Combine(_state.ExportDirectory,
                        $"decrypted_{DateTime.Now:yyyyMMdd_HHmmss}.bin");
                    File.WriteAllBytes(fn, _lastResult.DecryptedData);
                    _state.AddInGameLog($"[TESTLAB] Saved {Path.GetFileName(fn)}");
                }
                catch { }
            });
        }
    }

    // =========================================================================
    // RFC REFERENCE
    // =========================================================================
    private void RenderRfcRef()
    {
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(.07f,.09f,.11f,1f));
        ImGui.BeginChild("##rfc", new Vector2(0, 185), ImGuiChildFlags.Borders);

        ImGui.TextColored(Theme.ColInfo, "RFC 9001 -- TLS 1.3 Secret -> QUIC Keys");
        ImGui.Separator();
        ImGui.TextColored(Theme.ColTextMuted, "From SSLKEYLOGFILE:  CLIENT_TRAFFIC_SECRET_0  (32 or 48 bytes)");
        ImGui.TextColored(Theme.ColAccent,    "  -> HKDF-Expand-Label(secret, \"quic key\", \"\", 16)  =  AEAD key (AES-128-GCM)");
        ImGui.TextColored(Theme.ColAccent,    "  -> HKDF-Expand-Label(secret, \"quic iv\",  \"\", 12)  =  IV");
        ImGui.TextColored(Theme.ColAccent,    "  -> HKDF-Expand-Label(secret, \"quic hp\",  \"\", 16)  =  Header protection key");
        ImGui.Spacing();
        ImGui.TextColored(Theme.ColTextMuted, "Nonce = IV XOR packet_number  |  Cipher: AES-128-GCM");
        ImGui.Separator();
        ImGui.TextColored(Theme.ColTextMuted, "quic key: 00 10 0e 74 6c 73 31 33 20 71 75 69 63 20 6b 65 79 00");
        ImGui.TextColored(Theme.ColTextMuted, "quic iv:  00 0c 0d 74 6c 73 31 33 20 71 75 69 63 20 69 76 00");
        ImGui.TextColored(Theme.ColTextMuted, "quic hp:  00 10 0d 74 6c 73 31 33 20 71 75 69 63 20 68 70 00");
        ImGui.Spacing();
        BtnNeutral("Close", () => _showRfcRef = false);
        ImGui.SameLine();
        BtnNeutral("Copy Labels", () => { try { TextCopy.ClipboardService.SetText("quic key, quic iv, quic hp"); } catch { } });

        ImGui.EndChild();
        ImGui.PopStyleColor();
    }

    // =========================================================================
    // HELPERS
    // =========================================================================
    private void UpdateKeyCache()
    {
        if (DateTime.Now - _lastKeyCacheTime > TimeSpan.FromSeconds(3))
        {
            _cachedKeys       = PacketDecryptor.DiscoveredKeys.OrderByDescending(k => k.UseCount).Take(25).ToList();
            _lastKeyCacheTime = DateTime.Now;
        }
    }

    private void AddManualKey()
    {
        try
        {
            var data = Convert.FromHexString(_manualKey.Replace(" ","").Replace("-",""));
            if (data.Length != 16 && data.Length != 32)
            { _state.AddInGameLog($"[KEY] Need 16 or 32 bytes, got {data.Length}"); return; }
            var key = new PacketDecryptor.EncryptionKey
            {
                Key    = data,
                IV     = new byte[12],
                Type   = _selectedKeyType switch { 0 => PacketDecryptor.EncryptionType.AES128GCM,
                                                   2 => PacketDecryptor.EncryptionType.XOR,
                                                   _ => PacketDecryptor.EncryptionType.AES256GCM },
                Source = "Manual"
            };
            PacketDecryptor.AddKey(key);
            _state.AddInGameLog($"[KEY] Manual {key.Type} ({data.Length*8}bit) added");
            _manualKey        = "";
            _lastKeyCacheTime = DateTime.MinValue;
        }
        catch (Exception ex) { _state.AddInGameLog($"[KEY] {ex.Message}"); }
    }

    private void TestLastQuicPacket()
    {
        var pkt = _state.PacketLog.GetLast(50).LastOrDefault(p => !p.IsTcp);
        if (pkt == null) { _testLabResult = "No QUIC packets captured yet"; return; }
        RunDecryptTest(pkt.RawBytes, $"QUIC 0x{pkt.OpcodeDecimal:X4}");
    }

    private void TestManualHexDecrypt()
    {
        if (string.IsNullOrWhiteSpace(_testLabHex)) { _testLabResult = "Enter hex data first"; return; }
        try
        {
            var clean = new string(_testLabHex.Where(char.IsLetterOrDigit).ToArray());
            if (clean.Length % 2 != 0) { _testLabResult = "Odd-length hex"; return; }
            RunDecryptTest(Convert.FromHexString(clean), "manual hex");
        }
        catch (Exception ex) { _testLabResult = $"Parse error: {ex.Message}"; }
    }

    private void RunDecryptTest(byte[] data, string label)
    {
        if (_testLabRunning) return;
        _testLabRunning = true;
        _testLabResult  = "Decrypting...";
        Task.Run(() =>
        {
            try
            {
                _state.AddInGameLog($"[TESTLAB] {label} ({data.Length}B)");
                var r = PacketDecryptor.TryDecryptManual(data, 15000);
                _lastResult     = r;
                _testLabResult  = r.Success && r.DecryptedData != null
                    ? $"SUCCESS! {r.DecryptedData.Length}B  PN={r.PacketNumber}"
                    : $"FAILED: {r.ErrorMessage}";
                _state.AddInGameLog($"[TESTLAB] {_testLabResult}");
            }
            catch (Exception ex) { _testLabResult = $"ERROR: {ex.Message}"; }
            finally { _testLabRunning = false; }
        });
    }

    private void VerifyKeyDerivation()
    {
        Task.Run(() =>
        {
            try
            {
                _state.AddInGameLog("[DIAG] RFC 9001 derivation check (Appendix A.1)...");
                // RFC 9001 Appendix A.1 official test vector:
                // client_initial_secret derived from DCID=8394c8f03e515708
                var secret = Convert.FromHexString(
                    "c00cf151ca5be075ed0ebfb5c80323c4" +
                    "2d0b7bef575472db26359bdd9a4e507");   // 32 bytes (AES-128-GCM / SHA-256)
                var k = new PacketDecryptor.EncryptionKey
                {
                    Secret = secret,
                    Type   = PacketDecryptor.EncryptionType.QUIC_Client1RTT,
                    Source = "RFC9001-TestVector"
                };
                PacketDecryptor.DeriveQUICKeys(k);

                // RFC 9001 Appendix A.1 expected outputs:
                bool kOk = k.Key.SequenceEqual(
                    Convert.FromHexString("1f369613dd76d5467730efcbe3b1a22d"));
                bool iOk = k.IV.SequenceEqual(
                    Convert.FromHexString("fa044b2f42a3fd3b46fb255c"));
                bool hOk = k.HeaderProtectionKey?.SequenceEqual(
                    Convert.FromHexString("9f50449e04a0e810283a1e9933adedd2")) == true;

                string kStr = kOk ? "PASS" : $"FAIL (got {(k.Key.Length > 0 ? Convert.ToHexString(k.Key) : "empty")})";
                string iStr = iOk ? "PASS" : $"FAIL (got {(k.IV.Length  > 0 ? Convert.ToHexString(k.IV)  : "empty")})";
                string hStr = hOk ? "PASS" : $"FAIL (got {(k.HeaderProtectionKey != null ? Convert.ToHexString(k.HeaderProtectionKey) : "null")})";

                _state.AddInGameLog($"[DIAG] Key:{kStr}  IV:{iStr}  HP:{hStr}");
                _state.AddInGameLog(kOk && iOk && hOk
                    ? "[DIAG] ✓ RFC 9001 HKDF is correct"
                    : "[DIAG] ✗ HKDF derivation failed -- see values above");
            }
            catch (Exception ex) { _state.AddInGameLog($"[DIAG] {ex.Message}"); }
        });
    }

    // ── Styled button helpers ─────────────────────────────────────────────────
    private static void BtnAccent(string label, Action onClick)
    {
        var c = Theme.ColAccent;
        ImGui.PushStyleColor(ImGuiCol.Button,  new Vector4(c.X*.28f, c.Y*.28f, c.Z*.28f, 1f));
        ImGui.PushStyleColor(ImGuiCol.ButtonHovered, new Vector4(c.X*.42f, c.Y*.42f, c.Z*.42f, 1f));
        ImGui.PushStyleColor(ImGuiCol.Text,    c);
        ImGui.PushStyleColor(ImGuiCol.Border,  c with { W = .65f });
        if (ImGui.Button(label)) onClick();
        ImGui.PopStyleColor(4);
    }
    private static void BtnSuccess(string label, Action onClick)
    {
        var c = Theme.ColSuccess;
        ImGui.PushStyleColor(ImGuiCol.Button,  new Vector4(c.X*.25f, c.Y*.25f, c.Z*.25f, 1f));
        ImGui.PushStyleColor(ImGuiCol.ButtonHovered, new Vector4(c.X*.38f, c.Y*.38f, c.Z*.38f, 1f));
        ImGui.PushStyleColor(ImGuiCol.Text,    c);
        ImGui.PushStyleColor(ImGuiCol.Border,  c with { W = .60f });
        if (ImGui.Button(label)) onClick();
        ImGui.PopStyleColor(4);
    }
    private static void BtnDanger(string label, Action onClick)
    {
        var c = Theme.ColDanger;
        ImGui.PushStyleColor(ImGuiCol.Button,  new Vector4(c.X*.22f, c.Y*.22f, c.Z*.22f, 1f));
        ImGui.PushStyleColor(ImGuiCol.ButtonHovered, new Vector4(c.X*.35f, c.Y*.35f, c.Z*.35f, 1f));
        ImGui.PushStyleColor(ImGuiCol.Text,    c);
        ImGui.PushStyleColor(ImGuiCol.Border,  c with { W = .55f });
        if (ImGui.Button(label)) onClick();
        ImGui.PopStyleColor(4);
    }
    private static void BtnNeutral(string label, Action onClick)
    {
        ImGui.PushStyleColor(ImGuiCol.Button, Theme.Current?.TabBg ?? Theme.ColBg3);
        if (ImGui.Button(label)) onClick();
        ImGui.PopStyleColor();
    }
    private static void StatPill(string label, string val, Vector4 col)
    {
        var bg = new Vector4(col.X*.25f, col.Y*.25f, col.Z*.25f, 1f);
        ImGui.PushStyleColor(ImGuiCol.Button,  bg);
        ImGui.PushStyleColor(ImGuiCol.ButtonHovered, bg);
        ImGui.PushStyleColor(ImGuiCol.Text,    col);
        ImGui.PushStyleColor(ImGuiCol.Border,  col with { W = .55f });
        ImGui.PushStyleVar(ImGuiStyleVar.FrameRounding, 8f);
        ImGui.PushStyleVar(ImGuiStyleVar.FramePadding, new Vector2(8, 2));
        ImGui.SmallButton($"{label}: {val}");
        ImGui.PopStyleVar(2);
        ImGui.PopStyleColor(4);
    }
}
