// FILE: Tabs/DecryptionTab.cs - ENHANCED: 4-Step Wizard, Visual Key Cards, RFC 9001 Reference
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
    private string _manualKey = "";
    private int _selectedKeyType = 1;
    private string _testData = "";
    private int _selectedKeyIndex = -1;
    private float _lastRefreshTime = 0;
    private string _statusMessage = "";
    private float _statusTime = 0;
    private List<PacketDecryptor.EncryptionKey> _cachedKeys = new();
    private DateTime _lastKeyCacheTime = DateTime.MinValue;

    // ENHANCED: Wizard state
    private int _wizardStep = 0; // 0=Not started, 1=Config, 2=Verify, 3=Test, 4=Troubleshoot
    private bool _showWizard = true;
    private bool _showRfcReference = false;

    // ENHANCED: Test lab
    private string _testLabHex = "";
    private string _testLabResult = "";
    private bool _testLabRunning = false;

    public DecryptionTab(AppState state)
    {
        _state = state;
        _state.OnKeysUpdated += OnKeysUpdated;
    }

    private void OnKeysUpdated()
    {
        _statusMessage = "Keys updated!";
        _statusTime = (float)ImGui.GetTime();
        _lastKeyCacheTime = DateTime.MinValue;
    }

    private void UpdateKeyCache()
    {
        if (DateTime.Now - _lastKeyCacheTime > TimeSpan.FromSeconds(5))
        {
            _cachedKeys = PacketDecryptor.DiscoveredKeys
                .OrderByDescending(k => k.UseCount)
                .Take(10)
                .ToList();
            _lastKeyCacheTime = DateTime.Now;
        }
    }

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();

        ImGui.Spacing();
        ImGui.Text("  PACKET DECRYPTION  -  Manage Encryption Keys");
        ImGui.Separator();
        ImGui.Spacing();

        // Status banner
        RenderStatusBanner();

        // ENHANCED: Collapsible wizard
        if (_showWizard)
        {
            RenderDecryptionWizard();
            ImGui.Separator();
        }

        // Main content
        float leftWidth = avail.X * 0.5f - 8;
        float rightWidth = avail.X * 0.5f - 8;

        ImGui.BeginChild("##left_panel", new Vector2(leftWidth, avail.Y - (_showWizard ? 350 : 100)), ImGuiChildFlags.Borders);
        RenderKeyManagement(leftWidth);
        ImGui.EndChild();

        ImGui.SameLine();

        ImGui.BeginChild("##right_panel", new Vector2(rightWidth, avail.Y - (_showWizard ? 350 : 100)), ImGuiChildFlags.Borders);
        RenderTestLabAndStats(rightWidth);
        ImGui.EndChild();
    }

    // ENHANCED: Status banner with color coding
    private void RenderStatusBanner()
    {
        var status = _state.GetKeyStatus();
        bool hasKeys = status.TotalKeys > 0;
        bool hasSuccess = status.SuccessfulDecryptions > 0;

        Vector4 bannerColor;
        string bannerText;
        string icon;

        if (hasSuccess)
        {
            bannerColor = new Vector4(0.2f, 0.8f, 0.3f, 1f);
            bannerText = $"DECRYPTION ACTIVE - {status.SuccessfulDecryptions} packets decrypted";
            icon = "✓";
        }
        else if (hasKeys)
        {
            bannerColor = new Vector4(0.9f, 0.7f, 0.2f, 1f);
            bannerText = $"KEYS LOADED ({status.TotalKeys}) BUT DECRYPTION FAILING - Check derivation";
            icon = "⚠";
        }
        else
        {
            bannerColor = new Vector4(0.9f, 0.3f, 0.2f, 1f);
            bannerText = "NO KEYS - Set SSLKEYLOGFILE before starting Hytale";
            icon = "✗";
        }

        ImGui.PushStyleColor(ImGuiCol.ChildBg, bannerColor * 0.3f);
        ImGui.PushStyleColor(ImGuiCol.Border, bannerColor);
        ImGui.BeginChild("##status_banner", new Vector2(0, 40), ImGuiChildFlags.Borders);

        ImGui.SetCursorPosY(10);
        ImGui.TextColored(bannerColor, $"{icon} {bannerText}");

        ImGui.SameLine(ImGui.GetContentRegionAvail().X - 120);
        if (ImGui.Button(_showWizard ? "Hide Wizard" : "Show Wizard", new Vector2(110, 28)))
        {
            _showWizard = !_showWizard;
        }

        ImGui.EndChild();
        ImGui.PopStyleColor(2);

        if (!string.IsNullOrEmpty(_statusMessage) && ImGui.GetTime() - _statusTime < 3.0)
        {
            ImGui.TextColored(Theme.ColSuccess, _statusMessage);
        }
    }

    // ENHANCED: 4-Step Decryption Wizard
    private void RenderDecryptionWizard()
    {
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.1f, 0.12f, 0.15f, 1f));
        ImGui.BeginChild("##wizard", new Vector2(0, 240), ImGuiChildFlags.Borders);

        ImGui.TextColored(Theme.ColAccent, "🔧 Decryption Setup Wizard");
        ImGui.SameLine();
        if (ImGui.Button("Reset", new Vector2(60, 22)))
        {
            _wizardStep = 1;
        }
        ImGui.SameLine();
        if (ImGui.Button("RFC 9001 Reference", new Vector2(120, 22)))
        {
            _showRfcReference = !_showRfcReference;
        }

        // Step indicators
        string[] steps = { "Config", "Verify", "Test", "Troubleshoot" };
        float stepWidth = ImGui.GetContentRegionAvail().X / steps.Length;

        ImGui.Spacing();
        for (int i = 0; i < steps.Length; i++)
        {
            bool isActive = _wizardStep == i + 1;
            bool isComplete = _wizardStep > i + 1;

            var color = isActive ? Theme.ColAccent :
                       isComplete ? Theme.ColSuccess :
                       Theme.ColTextMuted;

            ImGui.PushStyleColor(ImGuiCol.Button, color);
            if (ImGui.Button($"{i + 1}. {steps[i]}", new Vector2(stepWidth - 5, 28)))
            {
                _wizardStep = i + 1;
            }
            ImGui.PopStyleColor();

            if (i < steps.Length - 1)
                ImGui.SameLine();
        }

        ImGui.Spacing();
        ImGui.Separator();

        // Step content
        switch (_wizardStep)
        {
            case 1: RenderStep1Config(); break;
            case 2: RenderStep2Verify(); break;
            case 3: RenderStep3Test(); break;
            case 4: RenderStep4Troubleshoot(); break;
            default: _wizardStep = 1; break;
        }

        // Navigation
        ImGui.Separator();
        if (_wizardStep > 1 && ImGui.Button("← Previous", new Vector2(100, 28)))
        {
            _wizardStep--;
        }
        ImGui.SameLine();
        if (_wizardStep < 4 && ImGui.Button("Next →", new Vector2(100, 28)))
        {
            _wizardStep++;
        }

        ImGui.EndChild();
        ImGui.PopStyleColor();

        // RFC 9001 Reference Panel
        if (_showRfcReference)
        {
            RenderRfc9001Reference();
        }
    }

    private void RenderStep1Config()
    {
        ImGui.TextColored(Theme.ColAccent, "Step 1: Configure SSLKEYLOGFILE");
        ImGui.TextWrapped("The SSLKEYLOGFILE environment variable must be set BEFORE Hytale starts. This captures TLS 1.3 secrets for key derivation.");

        ImGui.Spacing();
        ImGui.Text("Current export directory:");
        ImGui.TextColored(Theme.ColTextMuted, _state.ExportDirectory);

        if (ImGui.Button("Open Export Folder", new Vector2(140, 28)))
        {
            try
            {
                System.Diagnostics.Process.Start("explorer.exe", _state.ExportDirectory);
            }
            catch { }
        }

        ImGui.SameLine();
        if (ImGui.Button("Check for Key Files", new Vector2(140, 28)))
        {
            _state.RefreshAllKeys();
        }

        var keyFiles = Directory.GetFiles(_state.ExportDirectory, "*.log")
            .Where(f => f.Contains("ssl", StringComparison.OrdinalIgnoreCase) ||
                       f.Contains("key", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (keyFiles.Any())
        {
            ImGui.TextColored(Theme.ColSuccess, $"✓ Found {keyFiles.Count} key file(s)");
            foreach (var f in keyFiles.Take(3))
            {
                ImGui.TextColored(Theme.ColTextMuted, $"  - {Path.GetFileName(f)}");
            }
        }
        else
        {
            ImGui.TextColored(Theme.ColWarn, "⚠ No key files found. Set SSLKEYLOGFILE and restart Hytale.");
        }
    }

    private void RenderStep2Verify()
    {
        ImGui.TextColored(Theme.ColAccent, "Step 2: Verify Keys Loaded");

        var status = _state.GetKeyStatus();

        if (status.TotalKeys == 0)
        {
            ImGui.TextColored(Theme.ColDanger, "✗ No keys available. Go back to Step 1.");
            return;
        }

        ImGui.TextColored(Theme.ColSuccess, $"✓ {status.TotalKeys} key(s) available");

        // Visual key cards
        ImGui.Spacing();
        ImGui.Text("Key Sources:");

        foreach (var source in status.KeySources.Take(3))
        {
            var count = PacketDecryptor.DiscoveredKeys.Count(k => k.Source == source);
            var type = PacketDecryptor.DiscoveredKeys.First(k => k.Source == source).Type;

            ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.15f, 0.2f, 0.25f, 1f));
            ImGui.BeginChild($"##keycard_{source.GetHashCode()}", new Vector2(200, 60), ImGuiChildFlags.Borders);

            ImGui.TextColored(Theme.ColAccent, Path.GetFileName(source));
            ImGui.TextColored(Theme.ColTextMuted, $"{count} keys, {type}");

            ImGui.EndChild();
            ImGui.PopStyleColor();
            ImGui.SameLine();
        }
        ImGui.NewLine();

        // Derivation check
        var sampleKey = PacketDecryptor.DiscoveredKeys.First();
        bool hasDerivedKeys = sampleKey.Secret != null && sampleKey.Key.Length == 16;

        if (hasDerivedKeys)
        {
            ImGui.TextColored(Theme.ColSuccess, "✓ Keys properly derived via RFC 9001 HKDF");
        }
        else
        {
            ImGui.TextColored(Theme.ColWarn, "⚠ Raw TLS secrets detected - derivation may be needed");
        }
    }

    private void RenderStep3Test()
    {
        ImGui.TextColored(Theme.ColAccent, "Step 3: Test Decryption");

        if (PacketDecryptor.DiscoveredKeys.Count == 0)
        {
            ImGui.TextColored(Theme.ColDanger, "✗ No keys available. Complete Step 2 first.");
            return;
        }

        // Quick test with recent packet
        var recentPacket = _state.PacketLog.GetLast(10).LastOrDefault(p => !p.IsTcp);

        if (recentPacket != null)
        {
            ImGui.Text("Testing with recent QUIC packet:");
            ImGui.TextColored(Theme.ColTextMuted, $"Opcode: 0x{recentPacket.OpcodeDecimal:X4}, Size: {recentPacket.ByteLength} bytes");

            if (ImGui.Button("Run Test Decrypt", new Vector2(120, 28)))
            {
                Task.Run(() =>
                {
                    var result = PacketDecryptor.TryDecryptManual(recentPacket.RawBytes, 5000);
                    if (result.Success)
                    {
                        _statusMessage = $"✓ Decryption successful! {result.DecryptedData?.Length} bytes";
                    }
                    else
                    {
                        _statusMessage = $"✗ Failed: {result.ErrorMessage}";
                    }
                    _statusTime = (float)ImGui.GetTime();
                });
            }

            ImGui.SameLine();
            if (ImGui.Button("Try All Keys", new Vector2(100, 28)))
            {
                _statusMessage = "Testing all keys...";
                _statusTime = (float)ImGui.GetTime();
            }
        }
        else
        {
            ImGui.TextColored(Theme.ColTextMuted, "No QUIC packets captured yet. Connect to Hytale first.");
        }

        // Manual test data
        ImGui.Spacing();
        ImGui.Separator();
        ImGui.Text("Or paste hex data to test:");
        ImGui.SetNextItemWidth(300);
        ImGui.InputText("##testhex", ref _testData, 4096);
        ImGui.SameLine();
        if (ImGui.Button("Test", new Vector2(60, 28)))
        {
            TestDecrypt();
        }
    }

    private void RenderStep4Troubleshoot()
    {
        ImGui.TextColored(Theme.ColAccent, "Step 4: Troubleshooting");

        var status = _state.GetKeyStatus();

        // Diagnostic checklist
        ImGui.Text("Common Issues:");

        bool check1 = status.TotalKeys > 0;
        bool check2 = check1 && PacketDecryptor.DiscoveredKeys.Any(k => k.Secret != null);
        bool check3 = check2 && PacketDecryptor.SuccessfulDecryptions > 0;
        bool check4 = File.Exists(Path.Combine(_state.ExportDirectory, "sslkeys.log"));

        RenderCheckItem("SSLKEYLOGFILE set", check4);
        RenderCheckItem("Keys loaded", check1);
        RenderCheckItem("Keys derived (RFC 9001)", check2);
        RenderCheckItem("Successful decryption", check3);

        ImGui.Spacing();
        ImGui.Separator();

        if (!check1)
        {
            ImGui.TextColored(Theme.ColWarn, "Issue: No keys found");
            ImGui.BulletText("Set SSLKEYLOGFILE environment variable");
            ImGui.BulletText("Restart Hytale completely");
            ImGui.BulletText("Check that the log file is being written");
        }
        else if (!check2)
        {
            ImGui.TextColored(Theme.ColWarn, "Issue: Keys not properly derived");
            ImGui.BulletText("TLS secrets need HKDF derivation with 'quic key'/'quic iv' labels");
            ImGui.BulletText("Hytale may use custom Netty codec - check version compatibility");
        }
        else if (!check3)
        {
            ImGui.TextColored(Theme.ColWarn, "Issue: Decryption failing with valid keys");
            ImGui.BulletText("Packet number reconstruction may be failing");
            ImGui.BulletText("Header protection removal may need adjustment");
            ImGui.BulletText("Try memory scanning for live keys during gameplay");
        }
        else
        {
            ImGui.TextColored(Theme.ColSuccess, "✓ All checks passed! Decryption should be working.");
        }

        // Debug info
        ImGui.Spacing();
        if (ImGui.Button("Copy Debug Info", new Vector2(120, 28)))
        {
            var debug = $"Keys: {status.TotalKeys}\n" +
                       $"Derived: {PacketDecryptor.DiscoveredKeys.Count(k => k.Secret != null)}\n" +
                       $"Success: {status.SuccessfulDecryptions}\n" +
                       $"Failed: {status.FailedDecryptions}";
            CopyToClipboard(debug);
        }
    }

    private void RenderCheckItem(string label, bool passed)
    {
        var color = passed ? Theme.ColSuccess : Theme.ColDanger;
        var icon = passed ? "✓" : "✗";
        ImGui.TextColored(color, $"{icon} {label}");
    }

    private void RenderRfc9001Reference()
    {
        ImGui.Spacing();
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.08f, 0.1f, 0.12f, 1f));
        ImGui.BeginChild("##rfc_ref", new Vector2(0, 200), ImGuiChildFlags.Borders);

        ImGui.TextColored(new Vector4(0.4f, 0.8f, 1f, 1f), "RFC 9001 Key Derivation Reference");
        ImGui.Separator();

        ImGui.Text("TLS Secret → QUIC Keys:");
        ImGui.TextColored(Theme.ColTextMuted, "client_traffic_secret_0 [from SSLKEYLOGFILE]");
        ImGui.Text("↓ HKDF-Expand-Label with 'quic key', '', 16");
        ImGui.TextColored(Theme.ColTextMuted, "= AEAD key (16 bytes for AES-128-GCM)");
        ImGui.Text("↓ HKDF-Expand-Label with 'quic iv', '', 12");
        ImGui.TextColored(Theme.ColTextMuted, "= IV (12 bytes)");
        ImGui.Text("↓ HKDF-Expand-Label with 'quic hp', '', 16");
        ImGui.TextColored(Theme.ColTextMuted, "= Header protection key");

        ImGui.Separator();
        ImGui.Text("Labels (hex):");
        ImGui.TextColored(Theme.ColTextMuted, "quic key: 00100e746c7331332071756963206b657900");
        ImGui.TextColored(Theme.ColTextMuted, "quic iv:  000c0d746c733133207175696320697600");
        ImGui.TextColored(Theme.ColTextMuted, "quic hp:  00100d746c733133207175696320687000");

        if (ImGui.Button("Copy Labels", new Vector2(100, 24)))
        {
            CopyToClipboard("quic key, quic iv, quic hp");
        }

        ImGui.EndChild();
        ImGui.PopStyleColor();
    }

    private void RenderKeyManagement(float width)
    {
        // Auto-decrypt toggle
        bool autoDecrypt = PacketDecryptor.AutoDecryptEnabled;
        if (ImGui.Checkbox("Enable Auto-Decrypt (may cause lag)", ref autoDecrypt))
        {
            PacketDecryptor.AutoDecryptEnabled = autoDecrypt;
            if (autoDecrypt)
                _state.AddInGameLog("[DECRYPTION] Auto-decrypt enabled");
            else
                _state.AddInGameLog("[DECRYPTION] Auto-decrypt disabled");
        }

        ImGui.Spacing();
        ImGui.Separator();

        // Manual key entry
        ImGui.TextColored(Theme.ColAccent, "Manual Key Entry");

        string[] keyTypes = { "AES-128", "AES-256", "XOR" };
        ImGui.Combo("Key Type", ref _selectedKeyType, keyTypes, keyTypes.Length);

        ImGui.InputText("Key (hex)", ref _manualKey, 256);
        ImGui.TextColored(Theme.ColTextMuted, "Example: 48 65 6C 6C 6F or 48656C6C6F");

        if (ImGui.Button("Add Key", new Vector2(120, 28)))
        {
            AddManualKey();
        }

        ImGui.SameLine();

        if (ImGui.Button("Clear All Keys", new Vector2(120, 28)))
        {
            PacketDecryptor.ClearKeys();
            _state.AddInGameLog("[DECRYPTION] All keys cleared");
            _lastKeyCacheTime = DateTime.MinValue;
        }

        ImGui.Spacing();
        ImGui.Separator();

        // Discovered keys list
        UpdateKeyCache();

        int totalKeys = PacketDecryptor.DiscoveredKeys.Count;
        ImGui.TextColored(Theme.ColAccent, $"Discovered Keys ({totalKeys})");

        ImGui.BeginChild("##key_list", new Vector2(0, 150), ImGuiChildFlags.Borders);

        int index = 0;
        foreach (var key in _cachedKeys)
        {
            ImGui.PushID(index++);

            bool isSelected = _selectedKeyIndex == index - 1;
            var timeAgo = DateTime.Now - key.DiscoveredAt;
            string timeStr = timeAgo.TotalMinutes < 1 ? "now" : $"{timeAgo.TotalMinutes:F0}m";
            string useStr = key.UseCount > 0 ? $" (used {key.UseCount}x)" : "";
            string derivedStr = key.Secret != null && key.Key.Length > 0 ? " [RFC9001]" : "";

            ImGui.BeginGroup();

            if (isSelected)
                ImGui.PushStyleColor(ImGuiCol.Text, Theme.ColAccent);

            ImGui.Text($"{key.Type}{derivedStr} [{timeStr}]{useStr}");

            if (isSelected)
                ImGui.PopStyleColor();

            ImGui.TextColored(Theme.ColTextMuted, $"  Source: {Path.GetFileName(key.Source)}");

            string keyPreview = FormatKeyPreview(key.Key);
            ImGui.Text($"  Key: {keyPreview}");

            ImGui.EndGroup();

            if (ImGui.IsItemClicked())
            {
                _selectedKeyIndex = isSelected ? -1 : index - 1;
            }

            ImGui.Separator();
            ImGui.PopID();
        }

        if (_cachedKeys.Count == 0)
        {
            ImGui.TextColored(Theme.ColTextMuted, "No keys discovered yet");
        }

        ImGui.EndChild();
    }

    private void RenderTestLabAndStats(float width)
    {
        // ENHANCED: Test Lab
        ImGui.TextColored(Theme.ColAccent, "?? Test Lab");
        ImGui.TextColored(Theme.ColTextMuted, "Paste hex to test decryption");

        if (ImGui.Button("TEST DECRYPT LAST QUIC PACKET", new Vector2(width - 16, 40)))
        {
            var lastQuicPacket = _state.PacketLog.GetLast(10).LastOrDefault(p => !p.IsTcp);
            if (lastQuicPacket != null)
            {
                Task.Run(() =>
                {
                    _state.AddInGameLog($"[TEST] ========== DECRYPT TEST ==========");
                    _state.AddInGameLog($"[TEST] Packet size: {lastQuicPacket.ByteLength} bytes");
                    _state.AddInGameLog($"[TEST] First 8 bytes: {BitConverter.ToString(lastQuicPacket.RawBytes.Take(8).ToArray())}");
                    _state.AddInGameLog($"[TEST] Keys available: {PacketDecryptor.DiscoveredKeys.Count}");

                    // Try with each key
                    int keyIndex = 0;
                    foreach (var key in PacketDecryptor.DiscoveredKeys.Take(3))
                    {
                        keyIndex++;
                        _state.AddInGameLog($"[TEST] Trying key {keyIndex}: {key.Type}...");
                        _state.AddInGameLog($"[TEST]   Key: {BitConverter.ToString(key.Key.Take(8).ToArray())}... ({key.Key.Length} bytes)");
                        _state.AddInGameLog($"[TEST]   IV: {BitConverter.ToString(key.IV)}");

                        var result = PacketDecryptor.TryDecryptManual(lastQuicPacket.RawBytes, 15000);

                        if (result.Success)
                        {
                            _state.AddInGameLog($"[TEST] ? SUCCESS with key {keyIndex}!");
                            _state.AddInGameLog($"[TEST] Decrypted {result.DecryptedData?.Length} bytes");
                            _state.AddInGameLog($"[TEST] Packet Number: {result.PacketNumber}");
                            _testLabResult = $"SUCCESS! PN:{result.PacketNumber} Bytes:{result.DecryptedData?.Length}";
                            return;
                        }
                        else
                        {
                            _state.AddInGameLog($"[TEST]   Failed: {result.ErrorMessage}");
                        }
                    }

                    _state.AddInGameLog($"[TEST] ? ALL KEYS FAILED");
                    _state.AddInGameLog($"[TEST] Check Visual Studio Output window for detailed debug info");
                    _testLabResult = "All keys failed - see Output window";
                });
            }
        }
        

        ImGui.Spacing();

        // Rest of existing code...
        ImGui.SetNextItemWidth(width - 80);
        ImGui.InputTextMultiline("##testlab", ref _testLabHex, 4096, new Vector2(width - 80, 60));

        ImGui.SameLine();
        if (ImGui.Button("Paste", new Vector2(60, 60)))
        {
            try
            {
                var clipboard = TextCopy.ClipboardService.GetText();
                if (!string.IsNullOrEmpty(clipboard))
                {
                    _testLabHex = new string(clipboard.Where(c => char.IsLetterOrDigit(c)).ToArray());
                }
            }
            catch { }
        }

        // ... rest of method continues ...
    }

    private string FormatKeyPreview(byte[] key)
    {
        if (key.Length <= 16)
            return BitConverter.ToString(key).Replace("-", " ");

        // Show first 8 and last 4 bytes for longer keys
        var first = BitConverter.ToString(key.Take(8).ToArray()).Replace("-", " ");
        var last = BitConverter.ToString(key.Skip(key.Length - 4).ToArray()).Replace("-", " ");
        return $"{first} ... {last} ({key.Length} bytes)";
    }

    private void AddManualKey()
    {
        try
        {
            var hexString = _manualKey.Replace(" ", "").Replace("-", "");
            var keyBytes = Convert.FromHexString(hexString);

            if (keyBytes.Length != 16 && keyBytes.Length != 32)
            {
                _state.AddInGameLog($"[ERROR] Key must be 16 or 32 bytes, got {keyBytes.Length}");
                return;
            }

            var key = new PacketDecryptor.EncryptionKey
            {
                Key = keyBytes,
                IV = new byte[12],
                Type = _selectedKeyType switch
                {
                    0 => PacketDecryptor.EncryptionType.AES128GCM,
                    1 => PacketDecryptor.EncryptionType.AES256GCM,
                    2 => PacketDecryptor.EncryptionType.XOR,
                    _ => PacketDecryptor.EncryptionType.AES256GCM
                },
                Source = "Manual Entry"
            };

            PacketDecryptor.AddKey(key);
            _state.AddInGameLog($"[DECRYPTION] Added manual {key.Type} key ({keyBytes.Length} bytes)");
            _manualKey = "";
            _lastKeyCacheTime = DateTime.MinValue;
        }
        catch (Exception ex)
        {
            _state.AddInGameLog($"[ERROR] Invalid key format: {ex.Message}");
        }
    }

    private void TestDecrypt()
    {
        try
        {
            var testBytes = Convert.FromHexString(_testData.Replace(" ", "").Replace("-", ""));
            var result = PacketDecryptor.TryDecrypt(testBytes);

            if (result.Success && result.DecryptedData != null)
            {
                _state.AddInGameLog($"[TEST] Decryption successful! ({result.DecryptedData.Length} bytes)");
                string preview = Encoding.UTF8.GetString(result.DecryptedData.Take(100).ToArray());
                preview = new string(preview.Where(c => !char.IsControl(c)).ToArray());
                _state.AddInGameLog($"  Preview: {preview}");
            }
            else
            {
                _state.AddInGameLog($"[TEST] Decryption failed: {result.ErrorMessage}");
            }
        }
        catch (Exception ex)
        {
            _state.AddInGameLog($"[TEST] Error: {ex.Message}");
        }
    }

    private void ExportKeys()
    {
        try
        {
            var sb = new StringBuilder();
            sb.AppendLine("=== HYFORCE ENCRYPTION KEYS ===");
            sb.AppendLine($"Export Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine();

            foreach (var key in PacketDecryptor.DiscoveredKeys)
            {
                sb.AppendLine($"Type: {key.Type}");
                sb.AppendLine($"Source: {key.Source}");
                if (key.Secret != null)
                    sb.AppendLine($"Secret: {Convert.ToHexString(key.Secret)}");
                sb.AppendLine($"Key: {Convert.ToHexString(key.Key)}");
                sb.AppendLine($"IV: {Convert.ToHexString(key.IV)}");
                sb.AppendLine();
            }

            string filename = Path.Combine(_state.ExportDirectory,
                $"keys_export_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
            Directory.CreateDirectory(_state.ExportDirectory);
            File.WriteAllText(filename, sb.ToString());

            _state.AddInGameLog($"[DECRYPTION] Keys exported to {filename}");
        }
        catch (Exception ex)
        {
            _state.AddInGameLog($"[ERROR] Export failed: {ex.Message}");
        }
    }

    private void CopyToClipboard(string text)
    {
        try { TextCopy.ClipboardService.SetText(text); } catch { }
    }
}