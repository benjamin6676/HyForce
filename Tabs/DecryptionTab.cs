// FILE: Tabs/DecryptionTab.cs - DECRYPTION MANAGEMENT UI
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
    private int _selectedKeyType = 1; // Default to AES-256
    private string _testData = "";
    private bool _autoDecrypt = true;

    public DecryptionTab(AppState state)
    {
        _state = state;
    }

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();

        ImGui.Spacing();
        ImGui.Text("  PACKET DECRYPTION  �  Manage Encryption Keys");
        ImGui.Separator();
        ImGui.Spacing();

        // Key status
        RenderKeyStatus();

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

    private void RenderKeyStatus()
    {
        bool hasKeys = PacketDecryptor.DiscoveredKeys.Count > 0;

        var color = hasKeys ? Theme.ColSuccess : Theme.ColWarn;
        var status = hasKeys
            ? $"ACTIVE - {PacketDecryptor.DiscoveredKeys.Count} keys available"
            : "NO KEYS - Packets will be captured raw";

        ImGui.TextColored(color, status);

        if (!hasKeys)
        {
            ImGui.TextWrapped("Use the Memory Scanner to find encryption keys, or enter them manually below.");
        }

        ImGui.Checkbox("Auto-decrypt incoming packets", ref _autoDecrypt);
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
        }

        ImGui.Spacing();
        ImGui.Separator();
        ImGui.TextColored(Theme.ColAccent, $"Discovered Keys ({PacketDecryptor.DiscoveredKeys.Count})");

        ImGui.BeginChild("##key_list", new Vector2(0, 200), ImGuiChildFlags.Borders);

        int index = 0;
        foreach (var key in PacketDecryptor.DiscoveredKeys)
        {
            ImGui.PushID(index++);

            ImGui.TextColored(Theme.ColAccent, $"{key.Type}");
            ImGui.Text($"  Source: {key.Source}");

            string keyPreview = key.Key.Length > 8
                ? BitConverter.ToString(key.Key.Take(8).ToArray()).Replace("-", " ") + "..."
                : BitConverter.ToString(key.Key).Replace("-", " ");
            ImGui.Text($"  Key: {keyPreview}");

            if (key.MemoryAddress.HasValue)
            {
                ImGui.Text($"  Address: 0x{(ulong)key.MemoryAddress.Value:X}");
            }

            ImGui.Separator();
            ImGui.PopID();
        }

        if (PacketDecryptor.DiscoveredKeys.Count == 0)
        {
            ImGui.TextColored(Theme.ColTextMuted, "No keys discovered yet");
        }

        ImGui.EndChild();
    }

    private void RenderStatsAndTesting(float width)
    {
        ImGui.TextColored(Theme.ColAccent, "Decryption Statistics");

        ImGui.Text($"Successful: {PacketDecryptor.SuccessfulDecryptions}");
        ImGui.Text($"Failed: {PacketDecryptor.FailedDecryptions}");

        float successRate = PacketDecryptor.SuccessfulDecryptions + PacketDecryptor.FailedDecryptions > 0
            ? (float)PacketDecryptor.SuccessfulDecryptions / (PacketDecryptor.SuccessfulDecryptions + PacketDecryptor.FailedDecryptions)
            : 0;

        ImGui.ProgressBar(successRate, new Vector2(-1, 20), $"{successRate:P0}");

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
            // Reset counters via reflection or add a method to PacketDecryptor
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
                sb.AppendLine($"Key (hex): {Convert.ToHexString(key.Key)}");
                if (key.MemoryAddress.HasValue)
                    sb.AppendLine($"Address: 0x{(ulong)key.MemoryAddress.Value:X}");
                sb.AppendLine();
            }

            string filename = Path.Combine(_state.ExportDirectory, $"keys_export_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
            Directory.CreateDirectory(_state.ExportDirectory);
            File.WriteAllText(filename, sb.ToString());

            _state.AddInGameLog($"[DECRYPTION] Keys exported to {filename}");
        }
        catch (Exception ex)
        {
            _state.AddInGameLog($"[ERROR] Export failed: {ex.Message}");
        }
    }
}