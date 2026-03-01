// FILE: Tabs/PacketFeedTab.cs (ENHANCED)
using HyForce.Core;
using HyForce.Data;
using HyForce.Networking;
using HyForce.Protocol;
using HyForce.UI;
using HyForce.Utils;
using ImGuiNET;
using System.Numerics;

namespace HyForce.Tabs;

public class PacketFeedTab : ITab
{
    public string Name => "Packet Feed";
    private readonly AppState _state;
    private readonly List<PacketLogEntry> _displayPackets = new();
    private PacketLogEntry? _selectedPacket;
    private string _filterOpcode = "";
    private string _filterCategory = "";
    private bool _showOnlyCritical;
    private bool _showOnlyUnknown;
    private bool _autoScroll = true;
    private int _lastPacketCount;

    public PacketFeedTab(AppState state)
    {
        _state = state;
    }

    public void Render()
    {
        var windowSize = ImGui.GetContentRegionAvail();

        // Top toolbar
        RenderToolbar();

        ImGui.Separator();

        // Main content: Packet list on left, details on right
        var listWidth = windowSize.X * 0.6f;
        var detailsWidth = windowSize.X - listWidth - 20;

        ImGui.BeginChild("PacketList", new Vector2(listWidth, 0), ImGuiChildFlags.Borders);
        RenderPacketList();
        ImGui.EndChild();

        ImGui.SameLine();

        ImGui.BeginChild("PacketDetails", new Vector2(detailsWidth, 0), ImGuiChildFlags.Borders);
        RenderPacketDetails();
        ImGui.EndChild();
    }

    private void RenderToolbar()
    {
        ImGui.PushItemWidth(100);
        ImGui.InputText("Filter Opcode", ref _filterOpcode, 10);
        ImGui.SameLine();

        ImGui.InputText("Filter Category", ref _filterCategory, 20);
        ImGui.SameLine();

        ImGui.Checkbox("Critical Only", ref _showOnlyCritical);
        ImGui.SameLine();

        ImGui.Checkbox("Unknown Only", ref _showOnlyUnknown);
        ImGui.SameLine();

        ImGui.Checkbox("Auto-scroll", ref _autoScroll);

        if (ImGui.Button("Clear"))
        {
            _state.PacketLog.Clear();
            _displayPackets.Clear();
        }

        ImGui.SameLine();

        if (ImGui.Button("Analyze Patterns"))
        {
            ShowPatternAnalysis();
        }
    }

    private void RenderPacketList()
    {
        var packets = _state.PacketLog.GetLast(500);

        // Apply filters
        var filtered = packets.Where(p =>
        {
            if (!string.IsNullOrEmpty(_filterOpcode) &&
                !p.OpcodeDecimal.ToString("X4").Contains(_filterOpcode, StringComparison.OrdinalIgnoreCase))
                return false;

            if (_showOnlyCritical)
            {
                var info = OpcodeRegistry.GetInfo(p.OpcodeDecimal, p.Direction);
                if (info?.IsCritical != true) return false;
            }

            if (_showOnlyUnknown && OpcodeRegistry.IsKnownOpcode(p.OpcodeDecimal, p.Direction))
                return false;

            return true;
        }).ToList();

        // Table header
        if (ImGui.BeginTable("Packets", 6, ImGuiTableFlags.Resizable | ImGuiTableFlags.Reorderable | ImGuiTableFlags.RowBg))
        {
            ImGui.TableSetupColumn("Time", ImGuiTableColumnFlags.WidthFixed, 80);
            ImGui.TableSetupColumn("Dir", ImGuiTableColumnFlags.WidthFixed, 40);
            ImGui.TableSetupColumn("Opcode", ImGuiTableColumnFlags.WidthFixed, 60);
            ImGui.TableSetupColumn("Name", ImGuiTableColumnFlags.WidthStretch);
            ImGui.TableSetupColumn("Size", ImGuiTableColumnFlags.WidthFixed, 60);
            ImGui.TableSetupColumn("Info", ImGuiTableColumnFlags.WidthFixed, 80);
            ImGui.TableHeadersRow();

            foreach (var pkt in filtered)
            {
                ImGui.TableNextRow();

                // Highlight selected
                if (_selectedPacket == pkt)
                    ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg0, ImGui.GetColorU32(new Vector4(0.2f, 0.4f, 0.6f, 0.5f)));

                // Time
                ImGui.TableSetColumnIndex(0);
                ImGui.Text(pkt.Timestamp.ToString("HH:mm:ss.fff"));

                // Direction with color
                ImGui.TableSetColumnIndex(1);
                var dirColor = pkt.Direction == PacketDirection.ClientToServer
                    ? new Vector4(0.3f, 0.8f, 0.3f, 1) // Green for C2S
                    : new Vector4(0.8f, 0.5f, 0.2f, 1); // Orange for S2C
                ImGui.TextColored(dirColor, pkt.DirStr);

                // Opcode
                ImGui.TableSetColumnIndex(2);
                var isKnown = OpcodeRegistry.IsKnownOpcode(pkt.OpcodeDecimal, pkt.Direction);
                var opcodeColor = isKnown ? new Vector4(1, 1, 1, 1) : new Vector4(1, 0.3f, 0.3f, 1);
                ImGui.TextColored(opcodeColor, $"0x{pkt.OpcodeDecimal:X4}");

                // Name
                ImGui.TableSetColumnIndex(3);
                var info = OpcodeRegistry.GetInfo(pkt.OpcodeDecimal, pkt.Direction);
                var name = info?.Name ?? pkt.OpcodeName;
                if (info?.IsCritical == true)
                    ImGui.TextColored(new Vector4(1, 0.8f, 0.2f, 1), $"★ {name}");
                else
                    ImGui.Text(name);

                // Size
                ImGui.TableSetColumnIndex(4);
                ImGui.Text($"{pkt.ByteLength}B");

                // Info icons
                ImGui.TableSetColumnIndex(5);
                if (pkt.IsCompressed) ImGui.TextColored(new Vector4(0.5f, 0.8f, 1, 1), "[C]");
                if (pkt.EncryptionHint == "encrypted") ImGui.TextColored(new Vector4(1, 0.3f, 0.3f, 1), "[E]");

                // Selection
                if (ImGui.IsItemClicked())
                    _selectedPacket = pkt;
            }

            ImGui.EndTable();
        }

        if (_autoScroll && filtered.Count > 0)
        {
            ImGui.SetScrollHereY(1.0f);
        }
    }

    private void RenderPacketDetails()
    {
        if (_selectedPacket == null)
        {
            ImGui.TextColored(Theme.ColTextMuted, "Select a packet to view details");
            return;
        }

        var pkt = _selectedPacket;
        var analysis = PacketInspector.Analyze(new CapturedPacket
        {
            RawBytes = new byte[0], // Convert from entry
            Direction = pkt.Direction,
            IsTcp = pkt.IsTcp,
            Timestamp = pkt.Timestamp
        });

        // Header
        ImGui.PushFont(ImGui.GetIO().FontDefault);
        ImGui.TextColored(new Vector4(0.4f, 0.8f, 1, 1), analysis.PacketName);
        ImGui.PopFont();

        ImGui.SameLine();
        ImGui.TextColored(Theme.ColTextMuted, $"0x{pkt.OpcodeDecimal:X4}");

        if (analysis.IsCritical)
        {
            ImGui.SameLine();
            ImGui.TextColored(new Vector4(1, 0.8f, 0.2f, 1), " ★ CRITICAL");
        }

        ImGui.Separator();

        // Basic Info
        ImGui.Text("Direction: "); ImGui.SameLine();
        var dirColor = pkt.Direction == PacketDirection.ClientToServer
            ? new Vector4(0.3f, 0.8f, 0.3f, 1)
            : new Vector4(0.8f, 0.5f, 0.2f, 1);
        ImGui.TextColored(dirColor, pkt.Direction.ToString());

        ImGui.Text($"Category: {analysis.Category}");
        ImGui.Text($"Description: {analysis.Description}");
        ImGui.Text($"Size: {pkt.ByteLength} bytes ({pkt.ByteLength * 8} bits)");
        ImGui.Text($"Protocol: {(pkt.IsTcp ? "TCP" : "UDP/QUIC")}");
        ImGui.Text($"Timestamp: {pkt.Timestamp:yyyy-MM-dd HH:mm:ss.fff}");

        // Compression/Encryption
        ImGui.Separator();
        ImGui.TextColored(new Vector4(0.8f, 0.8f, 0.8f, 1), "Processing Info");

        if (pkt.IsCompressed)
        {
            ImGui.TextColored(new Vector4(0.5f, 0.8f, 1, 1), $"Compression: {pkt.CompressionMethod}");
            ImGui.Text($"  Compressed: {pkt.CompressedSize}B → Decompressed: {pkt.DecompressedSize}B");
        }
        else
        {
            ImGui.Text("Compression: none");
        }

        var encColor = pkt.EncryptionHint == "encrypted"
            ? new Vector4(1, 0.3f, 0.3f, 1)
            : new Vector4(0.3f, 1, 0.3f, 1);
        ImGui.TextColored(encColor, $"Encryption: {pkt.EncryptionHint}");

        if (!string.IsNullOrEmpty(analysis.CompressionHint))
            ImGui.TextColored(new Vector4(1, 0.8f, 0.4f, 1), $"Note: {analysis.CompressionHint}");

        // Entropy analysis
        ImGui.Separator();
        ImGui.TextColored(new Vector4(0.8f, 0.8f, 0.8f, 1), "Entropy Analysis");
        var entropy = ByteUtils.CalculateEntropy(Convert.FromHexString(pkt.RawHexPreview.Replace("-", "")));
        ImGui.Text($"Entropy: {entropy:F2}");

        var entropyColor = entropy > 7.8 ? new Vector4(1, 0.3f, 0.3f, 1) :
                          entropy > 7.0 ? new Vector4(1, 0.8f, 0.2f, 1) :
                          new Vector4(0.3f, 1, 0.3f, 1);
        ImGui.ProgressBar(entropy / 8.0f, new Vector2(-1, 20), entropy > 7.8 ? "High (Encrypted?)" : entropy > 5 ? "Medium" : "Low (Structured)");
        ImGui.TextColored(entropyColor, entropy > 7.8 ? "Likely encrypted/Random" : "Likely structured data");

        // Parsed Fields
        if (analysis.Fields.Count > 0)
        {
            ImGui.Separator();
            ImGui.TextColored(new Vector4(0.8f, 0.8f, 0.8f, 1), "Parsed Fields");
            foreach (var field in analysis.Fields)
            {
                ImGui.TextColored(new Vector4(0.6f, 0.8f, 1, 1), $"{field.Key}:");
                ImGui.SameLine();
                ImGui.Text(field.Value);
            }
        }

        // Hex Preview
        ImGui.Separator();
        ImGui.TextColored(new Vector4(0.8f, 0.8f, 0.8f, 1), "Hex Preview (First 48 bytes)");

        var hexLines = pkt.RawHexPreview.Split('-');
        for (int i = 0; i < hexLines.Length; i += 8)
        {
            var line = string.Join(" ", hexLines.Skip(i).Take(8));
            var addr = (i * 3).ToString("X3");
            ImGui.TextColored(new Vector4(0.5f, 0.5f, 0.5f, 1), $"{addr}:");
            ImGui.SameLine();
            ImGui.Text(line);
        }

        // Actions
        ImGui.Separator();
        if (ImGui.Button("Copy Hex", new Vector2(120, 30)))
        {
            try { TextCopy.ClipboardService.SetText(pkt.RawHexPreview); } catch { }
        }
        ImGui.SameLine();
        if (ImGui.Button("Save Packet", new Vector2(120, 30)))
        {
            SavePacket(pkt);
        }
    }

    private void ShowPatternAnalysis()
    {
        var patterns = PacketInspector.DetectPatterns(_state.PacketLog.GetAll());

        ImGui.OpenPopup("Pattern Analysis");
        if (ImGui.BeginPopupModal("Pattern Analysis", ref _showPatternAnalysis, ImGuiWindowFlags.AlwaysAutoResize))
        {
            ImGui.Text("Detected Traffic Patterns");
            ImGui.Separator();

            foreach (var pattern in patterns.Take(20))
            {
                var color = pattern.IsPeriodic ? new Vector4(0.3f, 1, 0.3f, 1) :
                           pattern.IsBurst ? new Vector4(1, 0.5f, 0.2f, 1) :
                           new Vector4(1, 1, 1, 1);

                ImGui.TextColored(color, $"{pattern.PacketName}");
                ImGui.Text($"  Count: {pattern.Count} | Avg Size: {pattern.AvgSize}B");

                if (pattern.IsPeriodic)
                    ImGui.Text($"  Periodic: {pattern.PeriodMs:F1}ms interval");
                if (pattern.IsBurst)
                    ImGui.Text($"  Burst: {pattern.RatePerSecond:F1} packets/sec");

                ImGui.Separator();
            }

            if (ImGui.Button("Close", new Vector2(120, 30)))
                _showPatternAnalysis = false;

            ImGui.EndPopup();
        }
    }

    private bool _showPatternAnalysis = false;

    private void SavePacket(PacketLogEntry pkt)
    {
        try
        {
            var filename = Path.Combine(_state.ExportDirectory, $"packet_{pkt.Timestamp:yyyyMMdd_HHmmss}_{pkt.OpcodeDecimal:X4}.bin");
            var bytes = Convert.FromHexString(pkt.RawHexPreview.Replace("-", ""));
            File.WriteAllBytes(filename, bytes);
            _state.AddInGameLog($"[SUCCESS] Packet saved to {filename}");
        }
        catch (Exception ex)
        {
            _state.AddInGameLog($"[ERROR] Failed to save packet: {ex.Message}");
        }
    }
}