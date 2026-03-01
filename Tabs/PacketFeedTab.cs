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
    private bool _showDetailWindow = false;
    private PacketLogEntry? _selectedPacket = null;
    private string _searchText = "";
    private List<PacketLogEntry> _displayedPackets = new();
    private int _lastPacketCount = 0;

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

        // Filters toolbar
        RenderToolbar();
        ImGui.Spacing();

        float listHeight = avail.Y - 200;

        // Packet list
        ImGui.BeginChild("##packet_list", new Vector2(avail.X, listHeight), ImGuiChildFlags.Borders);
        RenderPacketList();
        ImGui.EndChild();

        // Details panel
        ImGui.Spacing();
        ImGui.BeginChild("##packet_details", new Vector2(avail.X, 160), ImGuiChildFlags.Borders);
        RenderDetails();
        ImGui.EndChild();

        // Detail popup window
        if (_showDetailWindow && _selectedPacket != null)
        {
            RenderDetailWindow();
        }
    }

    private void RenderToolbar()
    {
        // Row 1: Protocol filters and controls
        ImGui.Checkbox("TCP", ref _filterTcp);
        ImGui.SameLine();
        ImGui.Checkbox("UDP", ref _filterUdp);
        ImGui.SameLine();
        ImGui.Checkbox("Auto-scroll", ref _autoScroll);
        ImGui.SameLine();
        ImGui.Checkbox("Pause", ref _pauseCapture);

        ImGui.SameLine(ImGui.GetWindowWidth() - 320);

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

        ImGui.SameLine(ImGui.GetWindowWidth() - 150);
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

        if (ImGui.BeginTable("##packets", 7,
            ImGuiTableFlags.Resizable |
            ImGuiTableFlags.RowBg |
            ImGuiTableFlags.ScrollY |
            ImGuiTableFlags.BordersInnerH |
            ImGuiTableFlags.Reorderable |
            ImGuiTableFlags.Hideable))
        {
            ImGui.TableSetupColumn("Time", ImGuiTableColumnFlags.WidthFixed, 70);
            ImGui.TableSetupColumn("Dir", ImGuiTableColumnFlags.WidthFixed, 45);
            ImGui.TableSetupColumn("Proto", ImGuiTableColumnFlags.WidthFixed, 50);
            ImGui.TableSetupColumn("Opcode", ImGuiTableColumnFlags.WidthFixed, 90);
            ImGui.TableSetupColumn("Size", ImGuiTableColumnFlags.WidthFixed, 60);
            ImGui.TableSetupColumn("Name", ImGuiTableColumnFlags.WidthStretch, 150);
            ImGui.TableSetupColumn("Info", ImGuiTableColumnFlags.WidthStretch, 200);
            ImGui.TableHeadersRow();

            for (int i = 0; i < _displayedPackets.Count; i++)
            {
                var pkt = _displayedPackets[i];
                ImGui.TableNextRow();

                // Selection highlight
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
                if (ImGui.Selectable(opcodeStr, isSelected,
                    ImGuiSelectableFlags.SpanAllColumns))
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
                        _showDetailWindow = true;
                    }
                    if (ImGui.MenuItem("📋 Copy Hex"))
                    {
                        ImGui.SetClipboardText(pkt.RawHexPreview);
                    }
                    if (ImGui.MenuItem("🔎 Filter This Opcode"))
                    {
                        _filterOpcode = pkt.OpcodeDecimal;
                    }
                    if (ImGui.MenuItem("🚫 Block This Opcode"))
                    {
                        _state.AddInGameLog($"[SECURITY] Blocked opcode 0x{pkt.OpcodeDecimal:X4} requested");
                    }
                    ImGui.Separator();
                    if (ImGui.MenuItem("📊 Send to Analytics"))
                    {
                        // Could add to a favorites list
                    }
                    ImGui.EndPopup();
                }

                // Double-click for details
                if (ImGui.IsItemHovered() && ImGui.IsMouseDoubleClicked(ImGuiMouseButton.Left))
                {
                    _selectedPacket = pkt;
                    _showDetailWindow = true;
                }

                ImGui.PopID();

                // Size
                ImGui.TableSetColumnIndex(4);
                string sizeStr = pkt.ByteLength < 1024
                    ? $"{pkt.ByteLength}B"
                    : $"{pkt.ByteLength / 1024.0:F1}KB";
                ImGui.Text(sizeStr);

                // Name
                ImGui.TableSetColumnIndex(5);
                ImGui.Text(pkt.OpcodeName);

                // Info
                ImGui.TableSetColumnIndex(6);
                if (pkt.IsCompressed)
                {
                    ImGui.TextColored(Theme.ColWarn, $"📦 {pkt.CompressionMethod}");
                }
                else if (pkt.EncryptionHint == "encrypted")
                {
                    ImGui.TextColored(Theme.ColDanger, "🔒 encrypted");
                }
                else
                {
                    ImGui.TextColored(Theme.ColTextMuted, pkt.CompressionMethod);
                }
            }

            ImGui.EndTable();

            if (_autoScroll && !_pauseCapture && ImGui.GetScrollY() < ImGui.GetScrollMaxY())
                ImGui.SetScrollHereY(1.0f);
        }
    }

    private void RenderDetails()
    {
        if (_selectedPacket == null)
        {
            ImGui.TextColored(Theme.ColTextMuted, "Select a packet to view details (double-click or right-click for options)");
            return;
        }

        var pkt = _selectedPacket;

        // Two column layout
        ImGui.Columns(3, "##pkt_details", false);

        // Column 1: Basic info
        ImGui.TextColored(Theme.ColAccent, "Basic Info");
        ImGui.Separator();
        ImGui.Text($"Time: {pkt.Timestamp:HH:mm:ss.fff}");
        ImGui.Text($"Direction: ");
        ImGui.SameLine();
        var dirColor = pkt.Direction == Networking.PacketDirection.ServerToClient ? Theme.ColSuccess : Theme.ColBlue;
        ImGui.TextColored(dirColor, pkt.DirStr);
        ImGui.Text($"Protocol: {pkt.ProtoStr}");
        ImGui.NextColumn();

        // Column 2: Technical details
        ImGui.TextColored(Theme.ColAccent, "Technical");
        ImGui.Separator();
        ImGui.Text($"Opcode: 0x{pkt.OpcodeDecimal:X4}");
        ImGui.Text($"Name: {pkt.OpcodeName}");
        ImGui.Text($"Size: {pkt.ByteLength} bytes");
        ImGui.NextColumn();

        // Column 3: Processing info
        ImGui.TextColored(Theme.ColAccent, "Processing");
        ImGui.Separator();
        ImGui.Text($"Compression: {pkt.CompressionMethod}");
        ImGui.Text($"Encrypted: {(pkt.EncryptionHint == "encrypted" ? "Yes" : "No")}");
        ImGui.Text($"Injected: {(pkt.Injected ? "Yes" : "No")}");
        ImGui.NextColumn();

        ImGui.Columns(1);
        ImGui.Separator();

        // Hex preview
        ImGui.TextColored(Theme.ColAccent, "Hex Preview (first 48 bytes):");
        ImGui.TextWrapped(pkt.RawHexPreview.Length > 144 ? pkt.RawHexPreview[..144] + "..." : pkt.RawHexPreview);

        // Action buttons
        ImGui.SameLine(ImGui.GetWindowWidth() - 320);
        if (ImGui.Button("🔍 Full Details", new Vector2(100, 0)))
        {
            _showDetailWindow = true;
        }
        ImGui.SameLine();
        if (ImGui.Button("📋 Copy Hex", new Vector2(100, 0)))
        {
            ImGui.SetClipboardText(pkt.RawHexPreview);
        }
        ImGui.SameLine();
        if (ImGui.Button("💾 Save Packet", new Vector2(100, 0)))
        {
            SavePacketToFile(pkt);
        }
    }

    private void RenderDetailWindow()
    {
        ImGui.SetNextWindowSize(new Vector2(700, 600), ImGuiCond.FirstUseEver);
        ImGui.SetNextWindowPos(ImGui.GetIO().DisplaySize * 0.5f, ImGuiCond.FirstUseEver, new Vector2(0.5f, 0.5f));

        bool show = _showDetailWindow;
        if (ImGui.Begin("Packet Details", ref show,
            ImGuiWindowFlags.NoCollapse |
            ImGuiWindowFlags.NoResize |
            ImGuiWindowFlags.MenuBar))
        {
            _showDetailWindow = show;
            var pkt = _selectedPacket!;

            // Menu bar
            if (ImGui.BeginMenuBar())
            {
                if (ImGui.BeginMenu("Actions"))
                {
                    if (ImGui.MenuItem("Copy All to Clipboard"))
                    {
                        CopyPacketToClipboard(pkt);
                    }
                    if (ImGui.MenuItem("Save to File..."))
                    {
                        SavePacketToFile(pkt);
                    }
                    ImGui.Separator();
                    if (ImGui.MenuItem("Previous Packet", "PgUp")) { }
                    if (ImGui.MenuItem("Next Packet", "PgDown")) { }
                    ImGui.EndMenu();
                }
                ImGui.EndMenuBar();
            }

            // Header info in a nice box
            ImGui.BeginChild("##header", new Vector2(0, 120), ImGuiChildFlags.Borders);

            ImGui.Columns(4, "##detail_header", false);

            ImGui.TextColored(Theme.ColTextMuted, "Timestamp");
            ImGui.Text(pkt.Timestamp.ToString("yyyy-MM-dd HH:mm:ss.fff"));
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

            ImGui.TextColored(Theme.ColTextMuted, "Opcode");
            ImGui.SameLine(100);
            ImGui.TextColored(Theme.ColAccent, $"0x{pkt.OpcodeDecimal:X4}");
            ImGui.SameLine(200);
            ImGui.Text(pkt.OpcodeName);

            ImGui.EndChild();

            ImGui.Spacing();

            // Tabbed content
            if (ImGui.BeginTabBar("##packet_tabs"))
            {
                // Hex tab
                if (ImGui.BeginTabItem("Hex Dump"))
                {
                    ImGui.BeginChild("##hex_scroll", new Vector2(0, 350), ImGuiChildFlags.Borders);
                    RenderFullHexDump(pkt.RawHexPreview);
                    ImGui.EndChild();

                    ImGui.Spacing();
                    ImGui.TextColored(Theme.ColTextMuted, $"Total: {pkt.RawHexPreview.Length / 3} bytes shown");
                    ImGui.EndTabItem();
                }

                // Decompressed tab
                if (pkt.IsCompressed && !string.IsNullOrEmpty(pkt.DecompHexPreview))
                {
                    if (ImGui.BeginTabItem($"Decompressed ({pkt.DecompressedSize}B)"))
                    {
                        ImGui.BeginChild("##decomp_scroll", new Vector2(0, 350), ImGuiChildFlags.Borders);
                        RenderFullHexDump(pkt.DecompHexPreview!);
                        ImGui.EndChild();

                        float ratio = (float)pkt.DecompressedSize / pkt.CompressedSize;
                        ImGui.TextColored(Theme.ColTextMuted,
                            $"Compressed: {pkt.CompressedSize}B → Decompressed: {pkt.DecompressedSize}B (ratio: {ratio:F2}x)");
                        ImGui.EndTabItem();
                    }
                }

                // Analysis tab
                if (ImGui.BeginTabItem("Analysis"))
                {
                    RenderPacketAnalysis(pkt);
                    ImGui.EndTabItem();
                }

                // Raw JSON tab
                if (ImGui.BeginTabItem("JSON"))
                {
                    RenderPacketJson(pkt);
                    ImGui.EndTabItem();
                }

                ImGui.EndTabBar();
            }

            // Footer buttons
            ImGui.Spacing();
            float btnWidth = 120;
            float startX = (ImGui.GetWindowWidth() - (btnWidth * 3 + 20)) / 2;
            ImGui.SetCursorPosX(startX);

            if (ImGui.Button("Copy Hex", new Vector2(btnWidth, 0)))
            {
                ImGui.SetClipboardText(pkt.RawHexPreview);
            }
            ImGui.SameLine();
            if (ImGui.Button("Save to File", new Vector2(btnWidth, 0)))
            {
                SavePacketToFile(pkt);
            }
            ImGui.SameLine();
            if (ImGui.Button("Close", new Vector2(btnWidth, 0)))
            {
                _showDetailWindow = false;
            }
        }
        ImGui.End();
    }

    private void RenderFullHexDump(string hex)
    {
        var bytes = hex.Split('-', StringSplitOptions.RemoveEmptyEntries);

        ImGui.PushStyleVar(ImGuiStyleVar.ItemSpacing, new Vector2(0, 0));

        for (int i = 0; i < bytes.Length; i += 16)
        {
            // Offset
            ImGui.TextColored(Theme.ColTextMuted, $"{i:X6}:  ");
            ImGui.SameLine();

            // Hex bytes
            for (int j = 0; j < 16 && (i + j) < bytes.Length; j++)
            {
                if (j == 8) ImGui.Text(" "); // Middle separator
                ImGui.SameLine();

                var b = bytes[i + j];
                // Color non-printable bytes differently
                bool isPrintable = byte.TryParse(b, System.Globalization.NumberStyles.HexNumber, null, out var val) && val >= 0x20 && val <= 0x7E;
                if (!isPrintable)
                    ImGui.TextColored(new Vector4(0.5f, 0.5f, 0.5f, 1f), b);
                else
                    ImGui.Text(b);

                if (j < 15 && (i + j + 1) < bytes.Length)
                {
                    ImGui.SameLine();
                    ImGui.Text(" ");
                    ImGui.SameLine();
                }
            }

            // ASCII representation
            ImGui.SameLine(500);
            ImGui.Text("  |");
            ImGui.SameLine();

            for (int j = 0; j < 16 && (i + j) < bytes.Length; j++)
            {
                byte.TryParse(bytes[i + j], System.Globalization.NumberStyles.HexNumber, null, out var val);
                char c = val >= 0x20 && val <= 0x7E ? (char)val : '.';
                ImGui.Text(c.ToString());
                if (j < 15 && (i + j + 1) < bytes.Length)
                    ImGui.SameLine();
            }
            ImGui.SameLine();
            ImGui.Text("|");
        }

        ImGui.PopStyleVar();
    }

    private void RenderPacketAnalysis(PacketLogEntry pkt)
    {
        ImGui.TextColored(Theme.ColAccent, "Entropy Analysis");
        ImGui.Separator();

        // Calculate rough entropy from hex string
        var bytes = pkt.RawHexPreview.Split('-');
        var uniqueBytes = new HashSet<string>(bytes);
        double entropy = uniqueBytes.Count / 256.0;

        ImGui.Text($"Unique bytes: {uniqueBytes.Count} / 256");
        ImGui.Text($"Entropy estimate: {entropy:P0}");

        // Progress bar for entropy
        ImGui.ProgressBar((float)entropy, new Vector2(300, 20),
            entropy > 0.9 ? "High (likely encrypted)" :
            entropy > 0.7 ? "Medium" : "Low (likely structured)");

        ImGui.Spacing();
        ImGui.TextColored(Theme.ColAccent, "Pattern Detection");
        ImGui.Separator();

        // Check for patterns
        if (pkt.RawHexPreview.StartsWith("28-B5-2F-FD"))
            ImGui.TextColored(Theme.ColWarn, "🔍 Zstd magic number detected");
        else if (pkt.RawHexPreview.StartsWith("1F-8B"))
            ImGui.TextColored(Theme.ColWarn, "🔍 Gzip magic number detected");
        else
            ImGui.TextColored(Theme.ColTextMuted, "No known compression signatures");

        // Check for text patterns
        var textMatches = System.Text.RegularExpressions.Regex.Matches(pkt.RawHexPreview, @"[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}")
            .Where(m => m.Value.Split('-').All(b => byte.Parse(b, System.Globalization.NumberStyles.HexNumber) >= 0x20 && byte.Parse(b, System.Globalization.NumberStyles.HexNumber) <= 0x7E))
            .Take(5);

        if (textMatches.Any())
        {
            ImGui.TextColored(Theme.ColSuccess, "🔤 Printable ASCII sequences found:");
            foreach (var match in textMatches)
            {
                var chars = match.Value.Split('-').Select(b => (char)byte.Parse(b, System.Globalization.NumberStyles.HexNumber));
                ImGui.Text($"  '{string.Join("", chars)}' at offset {match.Index / 3}");
            }
        }
    }

    private void RenderPacketJson(PacketLogEntry pkt)
    {
        var jsonObj = new Dictionary<string, object>
        {
            ["timestamp"] = pkt.Timestamp,
            ["direction"] = pkt.DirStr,
            ["protocol"] = pkt.ProtoStr,
            ["opcode"] = new Dictionary<string, object>
            {
                ["hex"] = $"0x{pkt.OpcodeDecimal:X4}",
                ["decimal"] = pkt.OpcodeDecimal,
                ["name"] = pkt.OpcodeName
            },
            ["size"] = new Dictionary<string, object>
            {
                ["bytes"] = pkt.ByteLength,
                ["bits"] = pkt.ByteLength * 8
            },
            ["compression"] = new Dictionary<string, object>
            {
                ["method"] = pkt.CompressionMethod,
                ["compressed"] = pkt.CompressedSize,
                ["decompressed"] = pkt.DecompressedSize
            },
            ["encryption"] = pkt.EncryptionHint,
            ["hex_preview"] = pkt.RawHexPreview,
            ["injected"] = pkt.Injected
        };

        var json = System.Text.Json.JsonSerializer.Serialize(jsonObj, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });

        ImGui.InputTextMultiline("##json", ref json, (uint)json.Length,
            new Vector2(0, 400), ImGuiInputTextFlags.ReadOnly);

        if (ImGui.Button("Copy JSON"))
        {
            ImGui.SetClipboardText(json);
        }
    }

    private void CopyPacketToClipboard(PacketLogEntry pkt)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"=== PACKET {pkt.OpcodeName} ===");
        sb.AppendLine($"Timestamp: {pkt.Timestamp:yyyy-MM-dd HH:mm:ss.fff}");
        sb.AppendLine($"Direction: {pkt.DirStr}");
        sb.AppendLine($"Protocol: {pkt.ProtoStr}");
        sb.AppendLine($"Opcode: 0x{pkt.OpcodeDecimal:X4}");
        sb.AppendLine($"Size: {pkt.ByteLength} bytes");
        sb.AppendLine($"Compression: {pkt.CompressionMethod}");
        sb.AppendLine();
        sb.AppendLine("=== HEX DUMP ===");
        sb.AppendLine(pkt.RawHexPreview);
        ImGui.SetClipboardText(sb.ToString());
    }

    private void SavePacketToFile(PacketLogEntry pkt)
    {
        try
        {
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
            string filename = Path.Combine(_state.ExportDirectory,
                $"packet_export_{DateTime.Now:yyyyMMdd_HHmmss}.csv");

            var sb = new System.Text.StringBuilder();
            sb.AppendLine("Timestamp,Direction,Protocol,Opcode,Name,Size,Compression");

            foreach (var pkt in _displayedPackets)
            {
                sb.AppendLine($"{pkt.Timestamp:yyyy-MM-dd HH:mm:ss},{pkt.DirStr},{pkt.ProtoStr}," +
                    $"0x{pkt.OpcodeDecimal:X4},{pkt.OpcodeName},{pkt.ByteLength},{pkt.CompressionMethod}");
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