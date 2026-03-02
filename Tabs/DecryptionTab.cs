// FILE: Tabs/DecryptionTab.cs - FIXED: UI freezing with many keys
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
    private bool _autoDecrypt = true;

    private int _selectedKeyIndex = -1;
    private bool _showKeyDetails = false;
    private float _lastRefreshTime = 0;
    private string _statusMessage = "";
    private float _statusTime = 0;

    // FIXED: Cache key list to prevent constant re-allocation
    private List<PacketDecryptor.EncryptionKey> _cachedKeys = new();
    private DateTime _lastKeyCacheTime = DateTime.MinValue;
    private const int MAX_UI_KEYS = 20; // Only show top 20 in UI

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
        // Refresh cache every 2 seconds max
        if (DateTime.Now - _lastKeyCacheTime > TimeSpan.FromSeconds(2))
        {
            _cachedKeys = PacketDecryptor.DiscoveredKeys
                .OrderByDescending(k => k.UseCount)
                .ThenByDescending(k => k.DiscoveredAt)
                .Take(MAX_UI_KEYS * 2) // Get more than we show
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

        // Key status header with refresh button
        RenderKeyStatusHeader();

        ImGui.Spacing();
        ImGui.Separator();

        // Two column layout
        float leftWidth = avail.X * 0.5f - 8;
        float rightWidth = avail.X * 0.5f - 8;

        ImGui.BeginChild("##left_panel", new Vector2(leftWidth, avail.Y - 100), ImGuiChildFlags.Borders);
        RenderKeyManagement(leftWidth);
        ImGui.EndChild();

        ImGui.SameLine();

        ImGui.BeginChild("##right_panel", new Vector2(rightWidth, avail.Y - 100), ImGuiChildFlags.Borders);
        RenderStatsAndTesting(rightWidth);
        ImGui.EndChild();
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
            _state.RefreshAllKeys();
            _lastKeyCacheTime = DateTime.MinValue;
        }
        ImGui.PopStyleColor();

        if (ImGui.IsItemHovered())
            ImGui.SetTooltip("Rescan export directory for key files");

        ImGui.EndGroup();

        ImGui.Checkbox("Auto-decrypt incoming packets", ref _autoDecrypt);

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

            ImGui.BeginGroup();

            if (isSelected)
                ImGui.PushStyleColor(ImGuiCol.Text, Theme.ColAccent);

            ImGui.Text($"{key.Type} [{timeStr}]{useStr}");

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
        ImGui.Text($"Size: {key.Key.Length * 8} bits ({key.Key.Length} bytes)");
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

        // Test decryption
        ImGui.TextColored(Theme.ColAccent, "Test Decryption");
        ImGui.InputTextMultiline("Test Data (hex)", ref _testData, 4096, new Vector2(-1, 100));

        if (ImGui.Button("Test Decrypt", new Vector2(120, 28)))
        {
            TestDecrypt();
        }

        ImGui.SameLine();

        if (ImGui.Button("Clear Stats", new Vector2(100, 28)))
        {
            // Note: Would need to add a method to reset stats
            _state.AddInGameLog("[DECRYPTION] Stats reset not implemented yet");
        }

        ImGui.SameLine();

        if (ImGui.Button("Verify Keys", new Vector2(100, 28)))
        {
            VerifyKeys();
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
        foreach (var key in PacketDecryptor.DiscoveredKeys)
        {
            // Basic validation: check key isn't all zeros or repeating pattern
            bool isAllZero = key.Key.All(b => b == 0);
            bool isRepeating = key.Key.Distinct().Count() == 1;
            bool isValidLength = key.Key.Length == 16 || key.Key.Length == 32 || key.Key.Length == 48;

            if (!isAllZero && !isRepeating && isValidLength)
            {
                validKeys++;
            }
        }

        _state.AddInGameLog($"[VERIFY] {validKeys}/{PacketDecryptor.DiscoveredKeys.Count} keys appear valid");

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
                sb.AppendLine($"Key (hex): {Convert.ToHexString(key.Key)}");
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
}