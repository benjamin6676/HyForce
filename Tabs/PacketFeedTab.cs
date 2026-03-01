// FILE: Tabs/PacketFeedTab.cs
using HyForce.Core;
using HyForce.Data;
using HyForce.UI;
using ImGuiNET;
using System.Numerics;

namespace HyForce.Tabs;

public class PacketFeedTab : ITab
{
    public string Name => "Packet Feed";

    private readonly AppState _state;
    private bool _autoScroll = true;
    private bool _filterTcp = true;
    private bool _filterUdp = true;
    private bool _pauseCapture = false;
    private ushort? _filterOpcode = null;
    private int _selectedEntry = -1;
    private PacketLogEntry? _selectedPacket = null;
    private string _searchText = "";
    private List<PacketLogEntry> _displayedPackets = new();

    public PacketFeedTab(AppState state)
    {
        _state = state;
    }

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();

        ImGui.Spacing();
        ImGui.Text("  PACKET FEED  —  Real-time Traffic Monitor");
        ImGui.Separator();
        ImGui.Spacing();

        // Main layout: Left = packet list, Right = details panel
        float detailsWidth = 380;
        float listWidth = avail.X - detailsWidth - 16;

        // Two columns
        ImGui.BeginChild("##packet_list_container", new Vector2(listWidth, avail.Y - 20), ImGuiChildFlags.None);
        RenderPacketListSection(listWidth);
        ImGui.EndChild();

        ImGui.SameLine();

        ImGui.BeginChild("##packet_details_panel", new Vector2(detailsWidth, avail.Y - 20), ImGuiChildFlags.Borders);
        RenderDetailsPanel(detailsWidth);
        ImGui.EndChild();
    }

    private void RenderPacketListSection(float width)
    {
        // Toolbar
        RenderToolbar(width);
        ImGui.Spacing();

        // Packet list
        float listHeight = ImGui.GetContentRegionAvail().Y - 10;
        ImGui.BeginChild("##packet_list", new Vector2(0, listHeight), ImGuiChildFlags.Borders);
        RenderPacketList();
        ImGui.EndChild();
    }

    private void RenderToolbar(float width)
    {
        // Row 1: Protocol filters and controls
        ImGui.Checkbox("TCP", ref _filterTcp);
        ImGui.SameLine();
        ImGui.Checkbox("UDP", ref _filterUdp);
        ImGui.SameLine();
        ImGui.Checkbox("Auto-scroll", ref _autoScroll);
        ImGui.SameLine();
        ImGui.Checkbox("Pause", ref _pauseCapture);

        ImGui.SameLine(width - 320);

        if (_filterOpcode.HasValue)
        {
            ImGui.TextColored(Theme.ColWarn, $"Filter: 0x{_filterOpcode.Value:X2}");
            ImGui.SameLine();
            if (ImGui.Button("Clear Filter", new Vector2(80, 0)))
            {
                _filterOpcode = null;
            }
            ImGui.SameLine();
        }

        if (ImGui.Button("Clear All", new Vector2(80, 0)))
        {
            _state.PacketLog.Clear();
            _selectedEntry = -1;
            _selectedPacket = null;
        }

        // Row 2: Search
        ImGui.SetNextItemWidth(300);
        ImGui.InputText("Search", ref _searchText, 256);

        ImGui.SameLine();
        ImGui.Text($"Total: {_state.TotalPackets:N0} | Showing: {_displayedPackets.Count}");

        ImGui.SameLine(width - 150);
        if (ImGui.Button("Export Visible", new Vector2(120, 0)))
        {
            ExportVisiblePackets();
        }
    }

    private void RenderPacketList()
    {
        if (!_pauseCapture)
        {
            _displayedPackets = _state.PacketLog.GetLast(1000)
                .Where(p => (_filterTcp && p.IsTcp) || (_filterUdp && !p.IsTcp))
                .Where(p => _filterOpcode == null || p.OpcodeDecimal == _filterOpcode)
                .Where(p => string.IsNullOrEmpty(_searchText) ||
                    p.OpcodeName.Contains(_searchText, StringComparison.OrdinalIgnoreCase) ||
                    p.RawHexPreview.Contains(_searchText, StringComparison.OrdinalIgnoreCase))
                .ToList();
        }

        if (ImGui.BeginTable("##packets", 6,
            ImGuiTableFlags.Resizable |
            ImGuiTableFlags.RowBg |
            ImGuiTableFlags.ScrollY |
            ImGuiTableFlags.BordersInnerH |
            ImGuiTableFlags.Reorderable |
            ImGuiTableFlags.Hideable))
        {
            ImGui.TableSetupColumn("Time", ImGuiTableColumnFlags.WidthFixed, 70);
            ImGui.TableSetupColumn("Dir", ImGuiTableColumnFlags.WidthFixed, 40);
            ImGui.TableSetupColumn("Proto", ImGuiTableColumnFlags.WidthFixed, 45);
            ImGui.TableSetupColumn("Opcode", ImGuiTableColumnFlags.WidthFixed, 80);
            ImGui.TableSetupColumn("Size", ImGuiTableColumnFlags.WidthFixed, 55);
            ImGui.TableSetupColumn("Name/Info", ImGuiTableColumnFlags.WidthStretch);
            ImGui.TableHeadersRow();

            for (int i = 0; i < _displayedPackets.Count; i++)
            {
                var pkt = _displayedPackets[i];
                ImGui.TableNextRow();

                bool isSelected = i == _selectedEntry;
                if (isSelected)
                {
                    ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg0,
                        ImGui.ColorConvertFloat4ToU32(new Vector4(0.2f, 0.5f, 0.8f, 0.4f)));
                }

                // Time
                ImGui.TableSetColumnIndex(0);
                ImGui.Text(pkt.Timestamp.ToString("HH:mm:ss.ff"));

                // Direction with color
                ImGui.TableSetColumnIndex(1);
                var dirColor = pkt.Direction == Networking.PacketDirection.ServerToClient
                    ? Theme.ColSuccess
                    : new Vector4(0.6f, 0.6f, 0.9f, 1f);
                ImGui.TextColored(dirColor, pkt.DirStr);

                // Protocol
                ImGui.TableSetColumnIndex(2);
                var protoColor = pkt.IsTcp
                    ? new Vector4(0.8f, 0.6f, 0.4f, 1f)
                    : new Vector4(0.4f, 0.6f, 0.8f, 1f);
                ImGui.TextColored(protoColor, pkt.ProtoStr);

                // Opcode (clickable)
                ImGui.TableSetColumnIndex(3);
                ImGui.PushID(i);
                string opcodeStr = $"0x{pkt.OpcodeDecimal:X4}";
                if (ImGui.Selectable(opcodeStr, isSelected, ImGuiSelectableFlags.SpanAllColumns))
                {
                    _selectedEntry = i;
                    _selectedPacket = pkt;
                }

                // Context menu
                if (ImGui.IsItemHovered() && ImGui.IsMouseClicked(ImGuiMouseButton.Right))
                {
                    ImGui.OpenPopup($"context_{i}");
                }

                if (ImGui.BeginPopup($"context_{i}"))
                {
                    if (ImGui.MenuItem("🔍 View Details"))
                    {
                        _selectedPacket = pkt;
                    }
                    if (ImGui.MenuItem("📋 Copy Hex"))
                    {
                        CopyToClipboard(pkt.RawHexPreview);
                    }
                    if (ImGui.MenuItem("🔎 Filter This Opcode"))
                    {
                        _filterOpcode = pkt.OpcodeDecimal;
                    }
                    if (ImGui.MenuItem("🚫 Block This Opcode"))
                    {
                        _state.AddInGameLog($"[SECURITY] Blocked opcode 0x{pkt.OpcodeDecimal:X4} requested");
                    }
                    ImGui.EndPopup();
                }
                ImGui.PopID();

                // Size
                ImGui.TableSetColumnIndex(4);
                string sizeStr = pkt.ByteLength < 1024
                    ? $"{pkt.ByteLength}B"
                    : $"{pkt.ByteLength / 1024.0:F1}KB";
                ImGui.Text(sizeStr);

                // Name/Info
                ImGui.TableSetColumnIndex(5);
                ImGui.Text(pkt.OpcodeName);

                // Encryption/Compression indicators inline
                ImGui.SameLine();
                if (pkt.IsCompressed)
                {
                    ImGui.TextColored(Theme.ColWarn, $"  📦 {pkt.CompressionMethod}");
                }
                else if (pkt.EncryptionHint == "encrypted")
                {
                    ImGui.TextColored(Theme.ColDanger, "  🔒 encrypted");
                }
            }

            ImGui.EndTable();

            if (_autoScroll && !_pauseCapture && ImGui.GetScrollY() < ImGui.GetScrollMaxY())
                ImGui.SetScrollHereY(1.0f);
        }
    }

    private void RenderDetailsPanel(float width)
    {
        if (_selectedPacket == null)
        {
            ImGui.TextColored(Theme.ColTextMuted, "Select a packet to view details");
            ImGui.Spacing();
            ImGui.TextWrapped("Click on any packet in the list to see detailed information here.");
            return;
        }

        var pkt = _selectedPacket;
        float halfWidth = (width - 20) / 2;

        // Header with big opcode
        ImGui.PushStyleColor(ImGuiCol.Text, Theme.ColAccent);
        ImGui.SetWindowFontScale(1.5f);
        ImGui.Text($"0x{pkt.OpcodeDecimal:X4}");
        ImGui.SetWindowFontScale(1.0f);
        ImGui.PopStyleColor();

        ImGui.SameLine();
        ImGui.TextColored(Theme.ColTextMuted, pkt.OpcodeName);

        ImGui.Separator();

        // Quick stats in 2 columns
        ImGui.Columns(2, "##quick_stats", false);

        ImGui.TextColored(Theme.ColTextMuted, "Time");
        ImGui.Text(pkt.Timestamp.ToString("HH:mm:ss.fff"));
        ImGui.NextColumn();

        ImGui.TextColored(Theme.ColTextMuted, "Direction");
        var dirColor = pkt.Direction == Networking.PacketDirection.ServerToClient ? Theme.ColSuccess : Theme.ColBlue;
        ImGui.TextColored(dirColor, pkt.DirStr);
        ImGui.NextColumn();

        ImGui.TextColored(Theme.ColTextMuted, "Protocol");
        ImGui.Text(pkt.ProtoStr);
        ImGui.NextColumn();

        ImGui.TextColored(Theme.ColTextMuted, "Size");
        ImGui.Text($"{pkt.ByteLength} bytes ({pkt.ByteLength * 8} bits)");
        ImGui.NextColumn();

        ImGui.Columns(1);
        ImGui.Separator();

        // Processing info
        ImGui.TextColored(Theme.ColAccent, "Processing Info");
        ImGui.Text($"Compression: {pkt.CompressionMethod}");
        ImGui.Text($"Encryption: {(pkt.EncryptionHint == "encrypted" ? "Yes 🔒" : "No")}");
        ImGui.Text($"Injected: {(pkt.Injected ? "Yes" : "No")}");

        if (pkt.QuicInfo != null)
        {
            ImGui.Text($"QUIC: {(pkt.QuicInfo.IsLongHeader ? "Long Header" : "Short Header")}");
        }

        ImGui.Separator();

        // Hex preview
        ImGui.TextColored(Theme.ColAccent, "Hex Preview (first 48 bytes)");
        ImGui.BeginChild("##hex_preview", new Vector2(0, 120), ImGuiChildFlags.Borders);
        RenderHexDump(pkt.RawHexPreview, 48);
        ImGui.EndChild();

        // Action buttons
        ImGui.Spacing();
        if (ImGui.Button("📋 Copy Hex", new Vector2((width - 20) / 2, 28)))
        {
            CopyToClipboard(pkt.RawHexPreview);
        }
        ImGui.SameLine();
        if (ImGui.Button("💾 Save Packet", new Vector2((width - 20) / 2, 28)))
        {
            SavePacketToFile(pkt);
        }

        // Full details section
        ImGui.Spacing();
        ImGui.Separator();
        ImGui.TextColored(Theme.ColAccent, "Full Analysis");

        // Entropy analysis
        var entropy = CalculateEntropy(pkt.RawHexPreview);
        ImGui.Text($"Entropy: {entropy:F2}");
        ImGui.ProgressBar((float)entropy / 8.0f, new Vector2(width - 20, 16),
            entropy > 7.5 ? "High (Encrypted)" : entropy > 5 ? "Medium" : "Low (Structured)");

        // String extraction
        var strings = ExtractStrings(pkt.RawHexPreview);
        if (strings.Any())
        {
            ImGui.TextColored(Theme.ColSuccess, "Found Strings:");
            foreach (var s in strings.Take(10))
            {
                ImGui.Text($"  \"{s}\"");
            }
        }

        // Decompressed data if available
        if (pkt.IsCompressed && !string.IsNullOrEmpty(pkt.DecompHexPreview))
        {
            ImGui.Spacing();
            ImGui.TextColored(Theme.ColAccent, $"Decompressed ({pkt.DecompressedSize} bytes)");
            ImGui.BeginChild("##decomp_preview", new Vector2(0, 100), ImGuiChildFlags.Borders);
            RenderHexDump(pkt.DecompHexPreview!, 32);
            ImGui.EndChild();
        }
    }

    private void RenderHexDump(string hex, int maxBytes)
    {
        if (string.IsNullOrEmpty(hex)) return;

        var parts = hex.Split('-', StringSplitOptions.RemoveEmptyEntries);
        int count = Math.Min(parts.Length, maxBytes);

        ImGui.PushStyleVar(ImGuiStyleVar.ItemSpacing, new Vector2(4, 2));

        for (int i = 0; i < count; i += 8)
        {
            // Offset
            ImGui.TextColored(Theme.ColTextMuted, $"{i:X3}: ");
            ImGui.SameLine();

            // Hex bytes
            for (int j = 0; j < 8 && (i + j) < count; j++)
            {
                if (j == 4) { ImGui.Text(" "); ImGui.SameLine(); }

                var b = parts[i + j];
                // Color non-printable differently
                if (byte.TryParse(b, System.Globalization.NumberStyles.HexNumber, null, out var val) && val >= 0x20 && val <= 0x7E)
                    ImGui.Text(b);
                else
                    ImGui.TextColored(new Vector4(0.5f, 0.5f, 0.5f, 1), b);

                if (j < 7 && (i + j + 1) < count)
                {
                    ImGui.SameLine();
                    ImGui.Text(" ");
                    ImGui.SameLine();
                }
            }
        }

        ImGui.PopStyleVar();
    }

    private double CalculateEntropy(string hex)
    {
        if (string.IsNullOrEmpty(hex)) return 0;
        var bytes = hex.Split('-', StringSplitOptions.RemoveEmptyEntries);
        if (bytes.Length == 0) return 0;

        var freq = new Dictionary<string, int>();
        foreach (var b in bytes)
        {
            if (freq.ContainsKey(b)) freq[b]++;
            else freq[b] = 1;
        }

        double entropy = 0;
        int len = bytes.Length;
        foreach (var count in freq.Values)
        {
            double p = (double)count / len;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    private List<string> ExtractStrings(string hex)
    {
        var result = new List<string>();
        if (string.IsNullOrEmpty(hex)) return result;

        var bytes = hex.Split('-', StringSplitOptions.RemoveEmptyEntries);
        var sb = new System.Text.StringBuilder();

        foreach (var b in bytes)
        {
            if (byte.TryParse(b, System.Globalization.NumberStyles.HexNumber, null, out var val) && val >= 0x20 && val <= 0x7E)
            {
                sb.Append((char)val);
            }
            else
            {
                if (sb.Length >= 4) result.Add(sb.ToString());
                sb.Clear();
            }
        }
        if (sb.Length >= 4) result.Add(sb.ToString());

        return result;
    }

    private void CopyToClipboard(string text)
    {
        try { TextCopy.ClipboardService.SetText(text); } catch { }
    }

    private void SavePacketToFile(PacketLogEntry pkt)
    {
        try
        {
            Directory.CreateDirectory(_state.ExportDirectory);
            string filename = Path.Combine(_state.ExportDirectory,
                $"packet_{pkt.Timestamp:yyyyMMdd_HHmmss}_{pkt.OpcodeDecimal:X4}.txt");

            var sb = new System.Text.StringBuilder();
            sb.AppendLine("=== HYFORCE PACKET EXPORT ===");
            sb.AppendLine($"Exported: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine();
            sb.AppendLine($"Timestamp: {pkt.Timestamp:yyyy-MM-dd HH:mm:ss.fff}");
            sb.AppendLine($"Direction: {pkt.DirStr}");
            sb.AppendLine($"Protocol: {pkt.ProtoStr}");
            sb.AppendLine($"Opcode: 0x{pkt.OpcodeDecimal:X4} ({pkt.OpcodeName})");
            sb.AppendLine($"Size: {pkt.ByteLength} bytes");
            sb.AppendLine($"Compression: {pkt.CompressionMethod}");
            sb.AppendLine($"Encryption: {pkt.EncryptionHint}");
            sb.AppendLine();
            sb.AppendLine("=== RAW HEX ===");
            sb.AppendLine(pkt.RawHexPreview);

            File.WriteAllText(filename, sb.ToString());
            _state.AddInGameLog($"[SUCCESS] Packet saved to {filename}");
        }
        catch (Exception ex)
        {
            _state.AddInGameLog($"[ERROR] Failed to save packet: {ex.Message}");
        }
    }

    private void ExportVisiblePackets()
    {
        try
        {
            Directory.CreateDirectory(_state.ExportDirectory);
            string filename = Path.Combine(_state.ExportDirectory,
                $"packet_export_{DateTime.Now:yyyyMMdd_HHmmss}.csv");

            var sb = new System.Text.StringBuilder();
            sb.AppendLine("Timestamp,Direction,Protocol,Opcode,Name,Size,Compression,Encryption");

            foreach (var pkt in _displayedPackets)
            {
                sb.AppendLine($"{pkt.Timestamp:yyyy-MM-dd HH:mm:ss},{pkt.DirStr},{pkt.ProtoStr}," +
                    $"0x{pkt.OpcodeDecimal:X4},{pkt.OpcodeName},{pkt.ByteLength},{pkt.CompressionMethod},{pkt.EncryptionHint}");
            }

            File.WriteAllText(filename, sb.ToString());
            _state.AddInGameLog($"[SUCCESS] Exported {_displayedPackets.Count} packets to {filename}");
        }
        catch (Exception ex)
        {
            _state.AddInGameLog($"[ERROR] Export failed: {ex.Message}");
        }
    }
}