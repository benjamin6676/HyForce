using HyForce.Core;
using ImGuiNET;
using System;
using System.Numerics;
using System.Text;

namespace HyForce.Tabs
{
    /// <summary>
    /// SIMPLIFIED DecryptionTab - No freezing, minimal UI
    /// </summary>
    public class DecryptionTab : ITab
    {
        public string Name => "Decryption";
        private readonly AppState _state;

        private string _testInput = "";
        private string _testResult = "";
        private int _selectedDCIDLength = 8;
        private int _selectedLabelFormat = 0;
        private string[] _labelFormats = { "RFC9001", "RFC8446", "QUICv2", "Test" };

        public DecryptionTab(AppState state) { _state = state; }

        public void Render()
        {
            // Status - simple, no complex calculations
            ImGui.TextColored(new Vector4(0, 1, 1, 1), "=== DECRYPTION ===");
            ImGui.Separator();

            // Get stats once
            var stats = PacketDecryptor.GetDebugStats();
            ImGui.Text($"Connections: {stats["Connections"]} | Keys: {stats["TotalKeys"]}");
            ImGui.Text($"Success: {stats["SuccessfulDecryptions"]} | Failed: {stats["FailedDecryptions"]}");

            ImGui.Separator();

            // Controls - simple buttons
            if (ImGui.Button("Load SSL Key Log", new Vector2(130, 25)))
            {
                try
                {
                    PacketDecryptor.LoadSSLKeyLog(_state.PermanentKeyLogPath);
                    _testResult = "Keys loaded!";
                }
                catch (Exception ex)
                {
                    _testResult = $"Error: {ex.Message}";
                }
            }
            ImGui.SameLine();

            if (ImGui.Button("Clear Keys", new Vector2(90, 25)))
            {
                try
                {
                    PacketDecryptor.ClearKeys();
                    _testResult = "Keys cleared!";
                }
                catch (Exception ex)
                {
                    _testResult = $"Error: {ex.Message}";
                }
            }
            ImGui.SameLine();

            if (ImGui.Button("Dump Keys", new Vector2(90, 25)))
            {
                try
                {
                    _testResult = PacketDecryptor.DumpAllKeys();
                }
                catch (Exception ex)
                {
                    _testResult = $"Error: {ex.Message}";
                }
            }
            ImGui.SameLine();

            if (ImGui.Button("Test Keys", new Vector2(80, 25)))
            {
                try
                {
                    _testResult = PacketDecryptor.TestKeyDerivation();
                }
                catch (Exception ex)
                {
                    _testResult = $"Error: {ex.Message}";
                }
            }

            bool debugMode = PacketDecryptor.DebugMode;
            bool autoDecrypt = PacketDecryptor.AutoDecryptEnabled;

            // Toggles - simple
            ImGui.Separator();
            if (ImGui.Checkbox("Debug Mode", ref debugMode))
                PacketDecryptor.DebugMode = debugMode;
            ImGui.SameLine();
            if (ImGui.Checkbox("Auto-Decrypt (WARNING: May cause lag)", ref autoDecrypt))
                PacketDecryptor.AutoDecryptEnabled = autoDecrypt;

            // Settings - sliders

            int maxDCID = PacketDecryptor.MaxDCIDLengthToTry;
            int timeoutMs = PacketDecryptor.DecryptionTimeoutMs;

            ImGui.Separator();
            ImGui.Text("Settings (lower = faster):");
            ImGui.SliderInt("Max DCID", ref maxDCID, 1, 5);
            ImGui.SliderInt("Timeout (ms)", ref timeoutMs, 20, 200);
            PacketDecryptor.MaxDCIDLengthToTry = maxDCID;
            PacketDecryptor.DecryptionTimeoutMs = timeoutMs;

            ImGui.Combo("Label Format", ref _selectedLabelFormat, _labelFormats, _labelFormats.Length);
            PacketDecryptor.CurrentLabelFormat = (PacketDecryptor.HkdfLabelFormat)_selectedLabelFormat;

            // Test Lab
            ImGui.Separator();
            ImGui.Text("Test Lab:");
            ImGui.InputTextMultiline("##input", ref _testInput, 10000, new Vector2(-1, 60));

            if (ImGui.Button("Try Decrypt", new Vector2(100, 25))) TryDecryptTest();
            ImGui.SameLine();
            if (ImGui.Button("Clear", new Vector2(60, 25))) { _testInput = ""; _testResult = ""; }

            // Result
            ImGui.Separator();
            ImGui.Text("Result:");
            ImGui.InputTextMultiline("##result", ref _testResult, 10000, new Vector2(-1, 100), ImGuiInputTextFlags.ReadOnly);
        }

        private void TryDecryptTest()
        {
            try
            {
                string hex = _testInput.Replace(" ", "").Replace("-", "").Replace(":", "");
                byte[] data = Convert.FromHexString(hex);

                var sb = new StringBuilder();
                sb.AppendLine($"Input: {data.Length} bytes");
                sb.AppendLine($"Encrypted: {PacketDecryptor.IsLikelyEncrypted(data)}");

                // Run on background thread to prevent UI freeze
                var task = System.Threading.Tasks.Task.Run(() =>
                {
                    return PacketDecryptor.TryDecryptManual(data, _selectedDCIDLength, (PacketDecryptor.HkdfLabelFormat)_selectedLabelFormat);
                });

                if (task.Wait(500)) // 500ms max for UI
                {
                    var result = task.Result;
                    sb.AppendLine($"Success: {result.Success}");
                    if (result.DecryptedData != null)
                        sb.AppendLine($"Decrypted: {result.DecryptedData.Length} bytes");
                    if (!string.IsNullOrEmpty(result.ErrorMessage))
                        sb.AppendLine($"Error: {result.ErrorMessage}");
                }
                else
                {
                    sb.AppendLine("Timeout - operation took too long");
                }

                _testResult = sb.ToString();
            }
            catch (Exception ex)
            {
                _testResult = $"Error: {ex.Message}";
            }
        }
    }
}