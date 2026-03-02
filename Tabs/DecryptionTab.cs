// FILE: Tabs/DecryptionTab.cs - FIXED: Removed duplicate toggle, moved manual decrypt up, added paste support
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
    private bool _showKeyDetails = false;
    private float _lastRefreshTime = 0;
    private string _statusMessage = "";
    private float _statusTime = 0;

    // FIXED: Cache key list to prevent constant re-allocation
    private List<PacketDecryptor.EncryptionKey> _cachedKeys = new();
    private DateTime _lastKeyCacheTime = DateTime.MinValue;
    private const int MAX_UI_KEYS = 20; // Only show top 20 in UI

    // NEW: Show fix explanation
    private bool _showFixExplanation = true;

    public DecryptionTab(AppState state)
    {
        _state = state;
        _state.OnKeysUpdated += OnKeysUpdated;
    }

    private void OnKeysUpdated()
    {
        _statusMessage = "Keys updated!";
        _statusTime = (float)ImGui.GetTime();
        _lastKeyCacheTime = DateTime.MinValue; // Invalidate cache
    }

    private void UpdateKeyCache()
    {
        // Refresh cache every 5 seconds max (was 2)
        if (DateTime.Now - _lastKeyCacheTime > TimeSpan.FromSeconds(5))
        {
            // FIXED: Limit to top 10 keys for UI performance
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

        // Show status message if recent
        if (!string.IsNullOrEmpty(_statusMessage) && ImGui.GetTime() - _statusTime < 3.0)
        {
            ImGui.TextColored(Theme.ColSuccess, _statusMessage);
        }

        // FIXED: Only ONE auto-decrypt toggle at the top (removed duplicate)
        bool autoDecrypt = PacketDecryptor.AutoDecryptEnabled;
        if (ImGui.Checkbox("Enable Auto-Decrypt (may cause lag)", ref autoDecrypt))
        {
            PacketDecryptor.AutoDecryptEnabled = autoDecrypt;
            if (autoDecrypt)
                _state.AddInGameLog("[DECRYPTION] Auto-decrypt enabled - may cause lag");
            else
                _state.AddInGameLog("[DECRYPTION] Auto-decrypt disabled");
        }

        ImGui.Spacing();
        ImGui.Separator();

        // FIXED: Manual decrypt section moved UP (visible without scrolling)
        RenderManualDecryptSection();

        ImGui.Spacing();
        ImGui.Separator();

        // NEW: Show the fix explanation panel
        if (_showFixExplanation)
        {
            RenderFixExplanation();
            ImGui.Spacing();
            ImGui.Separator();
        }

        // Key status header with refresh button
        RenderKeyStatusHeader();

        ImGui.Spacing();
        ImGui.Separator();

        // Two column layout
        float leftWidth = avail.X * 0.5f - 8;
        float rightWidth = avail.X * 0.5f - 8;

        ImGui.BeginChild("##left_panel", new Vector2(leftWidth, avail.Y - 280), ImGuiChildFlags.Borders);
        RenderKeyManagement(leftWidth);
        ImGui.EndChild();

        ImGui.SameLine();

        ImGui.BeginChild("##right_panel", new Vector2(rightWidth, avail.Y - 280), ImGuiChildFlags.Borders);
        RenderStatsAndTesting(rightWidth);
        ImGui.EndChild();
    }

    /// <summary>
    /// FIXED: New method for manual decrypt section at the TOP
    /// </summary>
    private void RenderManualDecryptSection()
    {
        ImGui.TextColored(Theme.ColAccent, "Manual Decryption");

        // FIXED: Input with proper paste support
        ImGui.Text("Test Data (hex):");

        float inputWidth = ImGui.GetContentRegionAvail().X - 70;
        ImGui.SetNextItemWidth(inputWidth);
        ImGui.InputTextMultiline("##testData", ref _testData, 4096, new Vector2(inputWidth, 60));

        ImGui.SameLine();

        // FIXED: Proper paste button that works
        if (ImGui.Button("Paste", new Vector2(60, 60)))
        {
            try
            {
                string? clipboard = TextCopy.ClipboardService.GetText();
                if (!string.IsNullOrEmpty(clipboard))
                {
                    // Clean up the clipboard content - remove spaces and dashes, keep only hex chars
                    string cleaned = new string(clipboard.Where(c => char.IsLetterOrDigit(c)).ToArray());
                    if (cleaned.Length > 0)
                    {
                        _testData = cleaned;
                        _state.AddInGameLog("[DECRYPTION] Pasted from clipboard");
                    }
                }
            }
            catch (Exception ex)
            {
                _state.AddInGameLog($"[DECRYPTION] Paste failed: {ex.Message}");
            }
        }

        // Decrypt button right below
        ImGui.Spacing();
        if (ImGui.Button("Decrypt Test Data", new Vector2(150, 28)))
        {
            TestDecrypt();
        }

        ImGui.SameLine();

        if (ImGui.Button("Clear", new Vector2(80, 28)))
        {
            _testData = "";
        }
    }

    /// <summary>
    /// NEW: Render the QUIC Key Derivation Fix explanation
    /// </summary>
    private void RenderFixExplanation()
    {
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.15f, 0.2f, 0.15f, 1f));
        ImGui.BeginChild("##fix_explanation", new Vector2(0, 140), ImGuiChildFlags.Borders);

        ImGui.TextColored(new Vector4(0.4f, 1f, 0.4f, 1f), "Why Your Keys Don't Work (FIXED):");
        ImGui.Spacing();

        // Create a table showing the issues
        if (ImGui.BeginTable("##fix_table", 2, ImGuiTableFlags.Borders | ImGuiTableFlags.RowBg))
        {
            ImGui.TableSetupColumn("Issue", ImGuiTableColumnFlags.WidthFixed, 180);
            ImGui.TableSetupColumn("Explanation", ImGuiTableColumnFlags.WidthStretch);
            ImGui.TableHeadersRow();

            // Row 1: Raw TLS secrets
            ImGui.TableNextRow();
            ImGui.TableSetColumnIndex(0);
            ImGui.Text("Raw TLS secrets");
            ImGui.TableSetColumnIndex(1);
            ImGui.TextColored(Theme.ColTextMuted, "SSLKEYLOGFILE contains TLS 1.3 traffic secrets, not QUIC packet keys");

            // Row 2: Missing HKDF
            ImGui.TableNextRow();
            ImGui.TableSetColumnIndex(0);
            ImGui.Text("Missing HKDF derivation");
            ImGui.TableSetColumnIndex(1);
            ImGui.TextColored(Theme.ColTextMuted, "QUIC requires HKDF-Expand-Label with \"quic key\" / \"quic iv\" labels");

            // Row 3: Wrong key length
            ImGui.TableNextRow();
            ImGui.TableSetColumnIndex(0);
            ImGui.Text("Wrong key length");
            ImGui.TableSetColumnIndex(1);
            ImGui.TextColored(Theme.ColTextMuted, "TLS secrets are 32-48 bytes, but QUIC uses 16-byte AES-128-GCM keys");

            // Row 4: Missing nonce
            ImGui.TableNextRow();
            ImGui.TableSetColumnIndex(0);
            ImGui.Text("Missing nonce construction");
            ImGui.TableSetColumnIndex(1);
            ImGui.TextColored(Theme.ColTextMuted, "QUIC requires XORing IV with packet number");

            ImGui.EndTable();
        }

        ImGui.Spacing();
        ImGui.TextColored(new Vector4(0.6f, 1f, 0.6f, 1f),
            "The fix derives actual QUIC packet keys from your TLS secrets using proper RFC 9001 key schedule.");

        ImGui.EndChild();
        ImGui.PopStyleColor();

        if (ImGui.Button(_showFixExplanation ? "Hide Explanation" : "Show Explanation"))
        {
            _showFixExplanation = !_showFixExplanation;
        }
        ImGui.SameLine();
        if (ImGui.Button("Copy Fix Info"))
        {
            var fixInfo = @"Why Your Keys Don't Work:

Issue: Raw TLS secrets
Explanation: SSLKEYLOGFILE contains TLS 1.3 traffic secrets, not QUIC packet keys

Issue: Missing HKDF derivation  
Explanation: QUIC requires deriving keys using HKDF-Expand-Label with ""quic key"" / ""quic iv"" labels

Issue: Wrong key length
Explanation: TLS secrets are 32-48 bytes, but QUIC uses 16-byte AES-128-GCM keys

Issue: Missing nonce construction
Explanation: QUIC requires XORing IV with packet number

The fix derives actual QUIC packet keys from your TLS secrets using the proper RFC 9001 key schedule.";
            CopyToClipboard(fixInfo);
            _state.AddInGameLog("[DECRYPTION] Fix info copied to clipboard");
        }
    }

    private void RenderKeyStatusHeader()
    {
        var status = _state.GetKeyStatus();
        bool hasKeys = status.TotalKeys > 0;

        var color = hasKeys ? Theme.ColSuccess : Theme.ColWarn;

        ImGui.BeginGroup();

        // Draw status circle
        var drawList = ImGui.GetWindowDrawList();
        var pos = ImGui.GetCursorScreenPos();

        drawList.AddCircleFilled(pos + new Vector2(10, 12), 8,
            ImGui.ColorConvertFloat4ToU32(color));
        ImGui.Dummy(new Vector2(25, 24));

        ImGui.SameLine();
        ImGui.BeginGroup();

        if (hasKeys)
        {
            ImGui.TextColored(color, $"ACTIVE - {status.TotalKeys} keys available");

            if (status.LastKeyAdded.HasValue)
            {
                var timeAgo = DateTime.Now - status.LastKeyAdded.Value;
                ImGui.TextColored(Theme.ColTextMuted,
                    $"Last added: {(timeAgo.TotalMinutes < 1 ? "just now" : $"{timeAgo.TotalMinutes:F0}m ago")}");
            }
        }
        else
        {
            ImGui.TextColored(color, "NO KEYS - Packets captured raw");
            ImGui.TextColored(Theme.ColTextMuted, "Use Memory Scanner or wait for SSL key log");
        }

        ImGui.EndGroup();

        // Refresh button
        ImGui.SameLine(ImGui.GetContentRegionAvail().X - 120);

        ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.2f, 0.6f, 0.9f, 1f));
        if (ImGui.Button("Refresh Keys", new Vector2(110, 28)))
        {
            // FIXED: Run on background thread
            Task.Run(() =>
            {
                _state.RefreshAllKeys();
                _lastKeyCacheTime = DateTime.MinValue;
            });
        }
        ImGui.PopStyleColor();

        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("Rescan export directory for key files");

        ImGui.EndGroup();

        // Show key sources if available
        if (status.KeySources.Any())
        {
            ImGui.TextColored(Theme.ColTextMuted, "Sources: " + string.Join(", ", status.KeySources.Take(3)));
        }
    }

    private void RenderKeyManagement(float width)
    {
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

        // FIXED: Use cached keys with limit
        UpdateKeyCache();

        int totalKeys = PacketDecryptor.DiscoveredKeys.Count;
        ImGui.TextColored(Theme.ColAccent, $"Discovered Keys (showing {_cachedKeys.Count} of {totalKeys})");

        ImGui.BeginChild("##key_list", new Vector2(0, 200), ImGuiChildFlags.Borders);

        int index = 0;
        foreach (var key in _cachedKeys)
        {
            ImGui.PushID(index++);

            bool isSelected = _selectedKeyIndex == index - 1;

            // Key header with type and time
            var timeAgo = DateTime.Now - key.DiscoveredAt;
            string timeStr = timeAgo.TotalMinutes < 1 ? "now" : $"{timeAgo.TotalMinutes:F0}m";
            string useStr = key.UseCount > 0 ? $" (used {key.UseCount}x)" : "";

            // NEW: Show if key is derived from secret
            string derivedStr = key.Secret != null && key.Key.Length > 0 ? " [RFC9001]" : "";

            ImGui.BeginGroup();

            if (isSelected)
                ImGui.PushStyleColor(ImGuiCol.Text, Theme.ColAccent);

            ImGui.Text($"{key.Type}{derivedStr} [{timeStr}]{useStr}");

            if (isSelected)
                ImGui.PopStyleColor();

            ImGui.TextColored(Theme.ColTextMuted, $"  Source: {key.Source}");

            // Key preview (first 8 bytes + ... + last 4 bytes)
            string keyPreview = FormatKeyPreview(key.Key);
            ImGui.Text($"  Key: {keyPreview}");

            if (key.MemoryAddress.HasValue)
            {
                ImGui.TextColored(Theme.ColTextMuted,
                    $"  Address: 0x{(ulong)key.MemoryAddress.Value:X}");
            }

            ImGui.EndGroup();

            // Click to select
            if (ImGui.IsItemClicked())
            {
                _selectedKeyIndex = isSelected ? -1 : index - 1;
            }

            // Right-click context menu
            if (ImGui.IsItemClicked(ImGuiMouseButton.Right))
                ImGui.OpenPopup($"key_ctx_{index}");

            if (ImGui.BeginPopup($"key_ctx_{index}"))
            {
                if (ImGui.MenuItem("Copy Full Key"))
                {
                    CopyToClipboard(Convert.ToHexString(key.Key));
                }
                if (ImGui.MenuItem("Copy Secret (if available)"))
                {
                    if (key.Secret != null)
                        CopyToClipboard(Convert.ToHexString(key.Secret));
                }
                if (ImGui.MenuItem("Use for Test Decryption"))
                {
                    _testData = Convert.ToHexString(key.Key.Take(16).ToArray());
                }
                ImGui.EndPopup();
            }

            ImGui.Separator();
            ImGui.PopID();
        }

        if (_cachedKeys.Count == 0)
        {
            ImGui.TextColored(Theme.ColTextMuted, "No keys discovered yet");
            ImGui.Spacing();
            ImGui.TextWrapped("Keys will appear here when:");
            ImGui.BulletText("SSL key log file is detected");
            ImGui.BulletText("Memory scanner finds keys");
            ImGui.BulletText("Manually entered above");
        }

        // Show message if there are more keys
        if (totalKeys > _cachedKeys.Count)
        {
            ImGui.TextColored(Theme.ColTextMuted, $"... and {totalKeys - _cachedKeys.Count} more keys");
        }

        ImGui.EndChild();

        // Key details panel if selected
        if (_selectedKeyIndex >= 0 && _selectedKeyIndex < _cachedKeys.Count)
        {
            var selectedKey = _cachedKeys[_selectedKeyIndex];
            RenderKeyDetails(selectedKey);
        }
    }

    private string FormatKeyPreview(byte[] key)
    {
        if (key.Length <= 12)
            return BitConverter.ToString(key).Replace("-", " ");

        var first = BitConverter.ToString(key.Take(8).ToArray()).Replace("-", " ");
        var last = BitConverter.ToString(key.Skip(key.Length - 4).ToArray()).Replace("-", " ");
        return $"{first} ... {last}";
    }

    private void RenderKeyDetails(PacketDecryptor.EncryptionKey key)
    {
        ImGui.Spacing();
        ImGui.Separator();
        ImGui.TextColored(Theme.ColAccent, "Key Details");

        ImGui.Text($"Type: {key.Type}");

        // NEW: Show derivation status
        if (key.Secret != null && key.Key.Length > 0)
        {
            ImGui.TextColored(new Vector4(0.4f, 1f, 0.4f, 1f), "Status: RFC 9001 Derived");
            ImGui.Text($"Secret Length: {key.Secret.Length * 8} bits");
        }

        ImGui.Text($"Key Size: {key.Key.Length * 8} bits ({key.Key.Length} bytes)");
        ImGui.Text($"IV Size: {key.IV.Length * 8} bits ({key.IV.Length} bytes)");
        ImGui.Text($"Source: {key.Source}");
        ImGui.Text($"Discovered: {key.DiscoveredAt:HH:mm:ss}");
        ImGui.Text($"Use Count: {key.UseCount}");

        if (key.MemoryAddress.HasValue)
        {
            ImGui.Text($"Memory Address: 0x{(ulong)key.MemoryAddress.Value:X16}");
        }

        // Full key display with copy button
        string fullKey = Convert.ToHexString(key.Key);
        ImGui.InputText("Full Key (hex)", ref fullKey, (uint)fullKey.Length,
            ImGuiInputTextFlags.ReadOnly);

        if (ImGui.Button("Copy Full Key", new Vector2(100, 24)))
        {
            CopyToClipboard(fullKey);
        }

        // NEW: Copy secret button
        if (key.Secret != null)
        {
            ImGui.SameLine();
            if (ImGui.Button("Copy Secret", new Vector2(100, 24)))
            {
                CopyToClipboard(Convert.ToHexString(key.Secret));
            }
        }
    }

    private void RenderStatsAndTesting(float width)
    {
        ImGui.TextColored(Theme.ColAccent, "Decryption Statistics");

        var status = _state.GetKeyStatus();

        // Stats with color coding
        ImGui.Text("Successful: ");
        ImGui.SameLine();
        ImGui.TextColored(Theme.ColSuccess, status.SuccessfulDecryptions.ToString());

        ImGui.Text("Failed: ");
        ImGui.SameLine();
        var failColor = status.FailedDecryptions > 0 ? Theme.ColWarn : Theme.ColTextMuted;
        ImGui.TextColored(failColor, status.FailedDecryptions.ToString());

        float successRate = status.SuccessfulDecryptions + status.FailedDecryptions > 0
            ? (float)status.SuccessfulDecryptions / (status.SuccessfulDecryptions + status.FailedDecryptions)
            : 0;

        ImGui.ProgressBar(successRate, new Vector2(-1, 20), $"{successRate:P0}");

        // Quick stats
        if (status.TotalKeys > 0)
        {
            ImGui.TextColored(Theme.ColTextMuted,
                $"Efficiency: {status.SuccessfulDecryptions} decryptions with {status.TotalKeys} keys");
        }

        ImGui.Spacing();
        ImGui.Separator();

        // Quick actions
        ImGui.TextColored(Theme.ColAccent, "Quick Actions");

        if (ImGui.Button("Scan Memory for Keys", new Vector2(180, 28)))
        {
            _state.AddInGameLog("[DECRYPTION] Use Memory tab to scan for keys");
        }

        ImGui.SameLine();

        if (ImGui.Button("Export Keys", new Vector2(120, 28)))
        {
            ExportKeys();
        }

        ImGui.Spacing();

        // File watcher status
        ImGui.TextColored(Theme.ColTextMuted, "Auto-detection: Active");
        ImGui.TextColored(Theme.ColTextMuted, $"Watching: {_state.ExportDirectory}");
    }

    private void VerifyKeys()
    {
        if (PacketDecryptor.DiscoveredKeys.Count == 0)
        {
            _state.AddInGameLog("[VERIFY] No keys to verify");
            return;
        }

        int validKeys = 0;
        int derivedKeys = 0;

        foreach (var key in PacketDecryptor.DiscoveredKeys)
        {
            // Check if properly derived
            if (key.Secret != null && key.Key.Length == 16)
            {
                derivedKeys++;
            }

            // Basic validation: check key isn't all zeros or repeating pattern
            bool isAllZero = key.Key.All(b => b == 0);
            bool isRepeating = key.Key.Distinct().Count() == 1;
            bool isValidLength = key.Key.Length == 16 || key.Key.Length == 32;

            if (!isAllZero && !isRepeating && isValidLength)
            {
                validKeys++;
            }
        }

        _state.AddInGameLog($"[VERIFY] {validKeys}/{PacketDecryptor.DiscoveredKeys.Count} keys appear valid");

        if (derivedKeys > 0)
        {
            _state.AddInGameLog($"[VERIFY] {derivedKeys} keys properly derived via RFC 9001");
        }

        if (validKeys < PacketDecryptor.DiscoveredKeys.Count)
        {
            _state.AddInGameLog("[VERIFY] Some keys may be corrupted or have invalid format");
        }
    }

    private void AddManualKey()
    {
        try
        {
            // Remove spaces and convert from hex
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

                // Show preview
                string preview = Encoding.UTF8.GetString(result.DecryptedData.Take(100).ToArray());
                preview = new string(preview.Where(c => !char.IsControl(c)).ToArray());
                _state.AddInGameLog($"  Preview: {preview}");

                // Show entropy
                double entropy = CalculateEntropy(result.DecryptedData);
                _state.AddInGameLog($"  Entropy: {entropy:F2} (lower = more structured)");
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

    private double CalculateEntropy(byte[] data)
    {
        if (data.Length == 0) return 0;

        var freq = new int[256];
        foreach (var b in data) freq[b]++;

        double entropy = 0;
        for (int i = 0; i < 256; i++)
        {
            if (freq[i] == 0) continue;
            double p = (double)freq[i] / data.Length;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    private void ExportKeys()
    {
        try
        {
            var sb = new StringBuilder();
            sb.AppendLine("=== HYFORCE ENCRYPTION KEYS ===");
            sb.AppendLine($"Export Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"Total Keys: {PacketDecryptor.DiscoveredKeys.Count}");
            sb.AppendLine();

            foreach (var key in PacketDecryptor.DiscoveredKeys)
            {
                sb.AppendLine($"Type: {key.Type}");
                sb.AppendLine($"Source: {key.Source}");
                sb.AppendLine($"Discovered: {key.DiscoveredAt:yyyy-MM-dd HH:mm:ss}");

                if (key.Secret != null)
                {
                    sb.AppendLine($"TLS Secret (hex): {Convert.ToHexString(key.Secret)}");
                }

                sb.AppendLine($"Derived Key (hex): {Convert.ToHexString(key.Key)}");
                sb.AppendLine($"IV (hex): {Convert.ToHexString(key.IV)}");

                if (key.MemoryAddress.HasValue)
                    sb.AppendLine($"Address: 0x{(ulong)key.MemoryAddress.Value:X}");
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

    public void ShowKeyDiagnostics()
    {
        foreach (var key in PacketDecryptor.DiscoveredKeys)
        {
            bool hasHP = key.HeaderProtectionKey != null && key.HeaderProtectionKey.Length > 0;
            bool hasIV = key.IV != null && key.IV.Length == 12;
            bool hasKey = key.Key != null && (key.Key.Length == 16 || key.Key.Length == 32);

            Console.WriteLine($"Key {key.Type}: Key={hasKey}, IV={hasIV}, HP={hasHP}");
        }
    }
}