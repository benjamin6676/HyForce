// FILE: Tabs/PacketFeedTab.cs - FIXED WITH FILTER BUTTONS AND IMPROVED UI
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
    private PacketLogEntry? _selectedPacket;
    private string _filterOpcode = "";
    private bool _showOnlyCritical;
    private bool _showOnlyUnknown;
    private bool _autoScroll = true;
    private bool _showPatternAnalysis = false;

    // NEW: Filter toggles
    private bool _hideEncrypted = false;
    private bool _showOnlyEncrypted = false;
    private bool _hideQuic = false;
    private bool _showOnlyQuic = false;
    private bool _hideTcp = false;
    private bool _showOnlyTcp = false;

    public PacketFeedTab(AppState state)
    {
        _state = state;
    }

    public void Render()
    {
        var windowSize = ImGui.GetContentRegionAvail();

        float toolbarHeight = 70; // Increased for two rows of buttons
        float remainingHeight = Math.Max(0, windowSize.Y - toolbarHeight - 10);

        RenderToolbar();
        ImGui.Separator();

        var listWidth = Math.Min(windowSize.X * 0.6f, windowSize.X - 320);
        var detailsWidth = Math.Max(0, windowSize.X - listWidth - 20);

        ImGui.BeginChild("PacketList", new Vector2(listWidth, remainingHeight), ImGuiChildFlags.Borders);
        RenderPacketList();
        ImGui.EndChild();

        ImGui.SameLine();

        ImGui.BeginChild("PacketDetails", new Vector2(detailsWidth, remainingHeight), ImGuiChildFlags.Borders);
        RenderPacketDetails();
        ImGui.EndChild();
    }

    private void RenderToolbar()
    {
        float buttonHeight = 25;

        // Row 1: Basic filters
        ImGui.PushItemWidth(100);
        ImGui.InputText("Filter Opcode", ref _filterOpcode, 10);
        ImGui.SameLine();
        ImGui.Checkbox("Critical", ref _showOnlyCritical);
        ImGui.SameLine();
        ImGui.Checkbox("Unknown", ref _showOnlyUnknown);
        ImGui.SameLine();
        ImGui.Checkbox("Auto-scroll", ref _autoScroll);

        ImGui.SameLine();
        if (ImGui.Button("Clear", new Vector2(60, buttonHeight)))
        {
            _state.PacketLog.Clear();
        }

        // Row 2: Encryption/Protocol filters
        ImGui.NewLine(); // Move to next line

        // Encryption filters
        ImGui.Text("Show:"); ImGui.SameLine();

        if (ImGui.Button(_hideEncrypted ? "Show Encrypted" : "Hide Encrypted", new Vector2(110, buttonHeight)))
        {
            _hideEncrypted = !_hideEncrypted;
            if (_hideEncrypted) _showOnlyEncrypted = false; // Mutually exclusive
        }
        ImGui.SameLine();

        if (ImGui.Button(_showOnlyEncrypted ? "All Packets" : "Only Encrypted", new Vector2(110, buttonHeight)))
        {
            _showOnlyEncrypted = !_showOnlyEncrypted;
            if (_showOnlyEncrypted) _hideEncrypted = false;
        }

        ImGui.SameLine();
        ImGui.Text("|"); ImGui.SameLine();

        // Protocol filters
        if (ImGui.Button(_hideQuic ? "Show QUIC" : "Hide QUIC", new Vector2(90, buttonHeight)))
        {
            _hideQuic = !_hideQuic;
            if (_hideQuic) _showOnlyQuic = false;
        }
        ImGui.SameLine();

        if (ImGui.Button(_showOnlyQuic ? "All Protocols" : "Only QUIC", new Vector2(90, buttonHeight)))
        {
            _showOnlyQuic = !_showOnlyQuic;
            if (_showOnlyQuic)
            {
                _hideQuic = false;
                _hideTcp = false;
                _showOnlyTcp = false;
            }
        }
        ImGui.SameLine();

        if (ImGui.Button(_hideTcp ? "Show TCP" : "Hide TCP", new Vector2(80, buttonHeight)))
        {
            _hideTcp = !_hideTcp;
            if (_hideTcp) _showOnlyTcp = false;
        }
        ImGui.SameLine();

        if (ImGui.Button(_showOnlyTcp ? "All Protocols" : "Only TCP", new Vector2(80, buttonHeight)))
        {
            _showOnlyTcp = !_showOnlyTcp;
            if (_showOnlyTcp)
            {
                _hideQuic = false;
                _hideTcp = false;
                _showOnlyQuic = false;
            }
        }

        ImGui.SameLine();
        ImGui.Text("|"); ImGui.SameLine();

        if (ImGui.Button("Analyze", new Vector2(80, buttonHeight)))
        {
            _showPatternAnalysis = true;
        }
    }

    private void RenderPacketList()
    {
        var contentAvail = ImGui.GetContentRegionAvail();

        var tableFlags = ImGuiTableFlags.Resizable | ImGuiTableFlags.RowBg |
                        ImGuiTableFlags.BordersInnerV | ImGuiTableFlags.ScrollY;

        if (ImGui.BeginTable("Packets", 6, tableFlags, contentAvail))
        {
            ImGui.TableSetupColumn("Time", ImGuiTableColumnFlags.WidthFixed, 80);
            ImGui.TableSetupColumn("Dir", ImGuiTableColumnFlags.WidthFixed, 40);
            ImGui.TableSetupColumn("Opcode", ImGuiTableColumnFlags.WidthFixed, 60);
            ImGui.TableSetupColumn("Name", ImGuiTableColumnFlags.WidthStretch);
            ImGui.TableSetupColumn("Size", ImGuiTableColumnFlags.WidthFixed, 60);
            ImGui.TableSetupColumn("Info", ImGuiTableColumnFlags.WidthFixed, 80);
            ImGui.TableHeadersRow();

            var packets = GetFilteredPackets();

            foreach (var pkt in packets)
            {
                ImGui.TableNextRow();

                bool isSelected = _selectedPacket == pkt;

                // Column 0: Time with selectable
                ImGui.TableSetColumnIndex(0);

                string selectableId = $"##pkt_{pkt.Timestamp.Ticks}_{pkt.GetHashCode()}";

                if (ImGui.Selectable(selectableId, isSelected,
                    ImGuiSelectableFlags.SpanAllColumns))
                {
                    _selectedPacket = pkt;
                }

                if (isSelected)
                {
                    ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg0,
                        ImGui.ColorConvertFloat4ToU32(new Vector4(0.2f, 0.4f, 0.8f, 0.4f)));
                }

                ImGui.SameLine();
                ImGui.Text(pkt.Timestamp.ToString("HH:mm:ss.fff"));

                // Column 1: Direction
                ImGui.TableSetColumnIndex(1);
                var dirColor = pkt.Direction == PacketDirection.ClientToServer
                    ? new Vector4(0.3f, 0.8f, 0.3f, 1)
                    : new Vector4(0.8f, 0.5f, 0.2f, 1);
                ImGui.TextColored(dirColor, pkt.DirStr);

                // Column 2: Opcode
                ImGui.TableSetColumnIndex(2);
                var isKnown = OpcodeRegistry.IsKnownOpcode(pkt.OpcodeDecimal, pkt.Direction);
                var opcodeColor = isKnown ? new Vector4(1, 1, 1, 1) : new Vector4(1, 0.3f, 0.3f, 1);
                ImGui.TextColored(opcodeColor, $"0x{pkt.OpcodeDecimal:X4}");

                // Column 3: Name
                ImGui.TableSetColumnIndex(3);
                var info = OpcodeRegistry.GetInfo(pkt.OpcodeDecimal, pkt.Direction);
                var name = info?.Name ?? pkt.OpcodeName;
                if (name.Length > 30)
                    name = name[..27] + "...";
                ImGui.Text(name);

                // Column 4: Size
                ImGui.TableSetColumnIndex(4);
                ImGui.Text($"{pkt.ByteLength}B");

                // Column 5: Info
                ImGui.TableSetColumnIndex(5);
                if (pkt.IsCompressed)
                {
                    ImGui.TextColored(new Vector4(0.5f, 0.8f, 1, 1), "[C]");
                    ImGui.SameLine();
                }
                if (pkt.EncryptionHint == "encrypted")
                {
                    ImGui.TextColored(new Vector4(1, 0.3f, 0.3f, 1), "[E]");
                }
                if (!pkt.IsTcp)
                {
                    ImGui.TextColored(new Vector4(0.4f, 0.6f, 0.8f, 1), "[Q]");
                }
            }
            ImGui.EndTable();
        }

        if (_autoScroll && ImGui.GetScrollY() < ImGui.GetScrollMaxY())
            ImGui.SetScrollHereY(1.0f);
    }

    private List<PacketLogEntry> GetFilteredPackets()
    {
        var packets = _state.PacketLog.GetLast(500);
        return packets.Where(p =>
        {
            // Opcode filter
            if (!string.IsNullOrEmpty(_filterOpcode) &&
                !p.OpcodeDecimal.ToString("X4").Contains(_filterOpcode, StringComparison.OrdinalIgnoreCase))
                return false;

            // Critical filter
            if (_showOnlyCritical)
            {
                var info = OpcodeRegistry.GetInfo(p.OpcodeDecimal, p.Direction);
                if (info?.IsCritical != true) return false;
            }

            // Unknown filter
            if (_showOnlyUnknown && OpcodeRegistry.IsKnownOpcode(p.OpcodeDecimal, p.Direction))
                return false;

            // Encryption filters
            bool isEncrypted = p.EncryptionHint == "encrypted";
            if (_hideEncrypted && isEncrypted) return false;
            if (_showOnlyEncrypted && !isEncrypted) return false;

            // Protocol filters
            bool isQuic = !p.IsTcp;
            if (_hideQuic && isQuic) return false;
            if (_showOnlyQuic && !isQuic) return false;
            if (_hideTcp && p.IsTcp) return false;
            if (_showOnlyTcp && !p.IsTcp) return false;

            return true;
        }).ToList();
    }

    private void RenderPacketDetails()
    {
        if (_selectedPacket == null)
        {
            ImGui.TextColored(Theme.ColTextMuted, "Select a packet to view details");
            return;
        }

        var pkt = _selectedPacket;
        var analysis = HyForce.Protocol.PacketInspector.Analyze(new CapturedPacket
        {
            RawBytes = Array.Empty<byte>(),
            Direction = pkt.Direction,
            IsTcp = pkt.IsTcp,
            Timestamp = pkt.Timestamp,
            Opcode = pkt.OpcodeDecimal
        });

        var contentAvail = ImGui.GetContentRegionAvail();
        ImGui.BeginChild("DetailsScroll", contentAvail, ImGuiChildFlags.None);

        ImGui.TextColored(new Vector4(0.4f, 0.8f, 1, 1), analysis.PacketName);
        ImGui.SameLine();
        ImGui.TextColored(Theme.ColTextMuted, $"0x{pkt.OpcodeDecimal:X4}");

        if (analysis.IsCritical)
        {
            ImGui.SameLine();
            ImGui.TextColored(new Vector4(1, 0.8f, 0.2f, 1), " CRITICAL");
        }

        ImGui.Separator();

        ImGui.Text("Direction: "); ImGui.SameLine();
        var dirColor = pkt.Direction == PacketDirection.ClientToServer
            ? new Vector4(0.3f, 0.8f, 0.3f, 1)
            : new Vector4(0.8f, 0.5f, 0.2f, 1);
        ImGui.TextColored(dirColor, pkt.Direction.ToString());

        ImGui.Text($"Category: {analysis.Category}");
        ImGui.TextWrapped($"Description: {analysis.Description}");
        ImGui.Text($"Size: {pkt.ByteLength} bytes");
        ImGui.Text($"Protocol: {(pkt.IsTcp ? "TCP" : "UDP/QUIC")}");

        ImGui.Separator();
        ImGui.TextColored(new Vector4(0.8f, 0.8f, 0.8f, 1), "Processing Info");

        if (pkt.IsCompressed)
        {
            ImGui.TextColored(new Vector4(0.5f, 0.8f, 1, 1), $"Compression: {pkt.CompressionMethod}");
        }
        else
        {
            ImGui.Text("Compression: none");
        }

        var encColor = pkt.EncryptionHint == "encrypted"
            ? new Vector4(1, 0.3f, 0.3f, 1)
            : new Vector4(0.3f, 1, 0.3f, 1);
        ImGui.TextColored(encColor, $"Encryption: {pkt.EncryptionHint}");

        ImGui.Separator();
        ImGui.TextColored(new Vector4(0.8f, 0.8f, 0.8f, 1), "Entropy Analysis");

        double entropy = 0;
        try
        {
            var hexString = pkt.RawHexPreview.Replace("-", "");
            if (hexString.Length % 2 == 0 && hexString.Length > 0)
            {
                var bytes = Convert.FromHexString(hexString);
                entropy = ByteUtils.CalculateEntropy(bytes);
            }
        }
        catch { }

        ImGui.Text($"Entropy: {entropy:F2}");
        var entropyColor = entropy > 7.8 ? new Vector4(1, 0.3f, 0.3f, 1) :
                          entropy > 7.0 ? new Vector4(1, 0.8f, 0.2f, 1) :
                          new Vector4(0.3f, 1, 0.3f, 1);

        ImGui.ProgressBar((float)(entropy / 8.0), new Vector2(Math.Min(300, ImGui.GetContentRegionAvail().X - 20), 20),
            entropy > 7.8 ? "High" : "Low");
        ImGui.TextColored(entropyColor, entropy > 7.8 ? "Likely encrypted" : "Likely structured");

        if (analysis.Fields.Count > 0)
        {
            ImGui.Separator();
            ImGui.TextColored(new Vector4(0.8f, 0.8f, 0.8f, 1), "Parsed Fields");
            foreach (var field in analysis.Fields)
            {
                ImGui.TextColored(new Vector4(0.6f, 0.8f, 1, 1), $"{field.Key}:");
                ImGui.SameLine();
                ImGui.TextWrapped(field.Value);
            }
        }

        ImGui.Separator();
        ImGui.TextColored(new Vector4(0.8f, 0.8f, 0.8f, 1), "Hex Preview");

        var hexLines = pkt.RawHexPreview.Split('-');
        for (int i = 0; i < hexLines.Length && i < 32; i += 8)
        {
            var line = string.Join(" ", hexLines.Skip(i).Take(8));
            var addr = (i * 3).ToString("X3");
            ImGui.TextColored(new Vector4(0.5f, 0.5f, 0.5f, 1), $"{addr}:");
            ImGui.SameLine();
            ImGui.Text(line);
        }

        ImGui.Separator();
        if (ImGui.Button("Copy Hex", new Vector2(120, 30)))
        {
            try { TextCopy.ClipboardService.SetText(pkt.RawHexPreview); } catch { }
        }

        ImGui.EndChild();
    }
}