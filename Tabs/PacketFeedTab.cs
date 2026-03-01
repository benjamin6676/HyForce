// FILE: Tabs/PacketFeedTab.cs
using HyForce.Core;
using HyForce.Data;
using ImGuiNET;
using System.Numerics;

namespace HyForce.Tabs;

public class PacketFeedTab : ITab
{
    private readonly AppState _state;
    private int _selectedPacket = -1;
    private bool _autoScroll = true;
    private bool _filterTcp = true;
    private bool _filterUdp = true;
    private string _opcodeFilter = "";

    public string Name => "Packets";

    public PacketFeedTab(AppState state)
    {
        _state = state;
    }

    public void Render()
    {
        ImGui.BeginChild("PacketFeed", new Vector2(0, 0), ImGuiChildFlags.None);

        ImGui.Checkbox("TCP", ref _filterTcp);
        ImGui.SameLine();
        ImGui.Checkbox("UDP", ref _filterUdp);
        ImGui.SameLine();
        ImGui.Checkbox("Auto-scroll", ref _autoScroll);

        ImGui.SameLine();
        ImGui.SetNextItemWidth(100);
        ImGui.InputText("Opcode Filter", ref _opcodeFilter, 10);

        ImGui.Separator();

        var packets = _state.PacketLog.GetAll();
        var filtered = packets.Where(p =>
            (_filterTcp && p.IsTcp) || (_filterUdp && !p.IsTcp)
        ).ToList();

        if (!string.IsNullOrEmpty(_opcodeFilter) && ushort.TryParse(_opcodeFilter, System.Globalization.NumberStyles.HexNumber, null, out var opcode))
        {
            filtered = filtered.Where(p => p.OpcodeDecimal == opcode).ToList();
        }

        ImGui.Text($"Showing {filtered.Count} / {packets.Count} packets");

        ImGui.BeginChild("PacketList", new Vector2(0, 300), ImGuiChildFlags.None);

        ImGui.Columns(6, "PacketColumns", false);
        ImGui.SetColumnWidth(0, 80);
        ImGui.SetColumnWidth(1, 50);
        ImGui.SetColumnWidth(2, 50);
        ImGui.SetColumnWidth(3, 80);
        ImGui.SetColumnWidth(4, 200);
        ImGui.SetColumnWidth(5, 60);

        ImGui.Text("Time"); ImGui.NextColumn();
        ImGui.Text("Dir"); ImGui.NextColumn();
        ImGui.Text("Proto"); ImGui.NextColumn();
        ImGui.Text("Opcode"); ImGui.NextColumn();
        ImGui.Text("Name"); ImGui.NextColumn();
        ImGui.Text("Size"); ImGui.NextColumn();
        ImGui.Separator();

        for (int i = 0; i < filtered.Count; i++)
        {
            var pkt = filtered[i];
            bool isSelected = _selectedPacket == i;

            if (isSelected)
                ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(1, 0.8f, 0.2f, 1));

            ImGui.Text(pkt.Timestamp.ToString("HH:mm:ss.fff")); ImGui.NextColumn();
            ImGui.Text(pkt.DirStr); ImGui.NextColumn();
            ImGui.Text(pkt.ProtoStr); ImGui.NextColumn();
            ImGui.Text($"0x{pkt.OpcodeDecimal:X4}"); ImGui.NextColumn();
            ImGui.Text(pkt.OpcodeName); ImGui.NextColumn();
            ImGui.Text($"{pkt.ByteLength}"); ImGui.NextColumn();

            if (isSelected)
                ImGui.PopStyleColor();

            if (ImGui.IsItemClicked())
                _selectedPacket = i;
        }

        if (_autoScroll && filtered.Count > 0)
            ImGui.SetScrollHereY(1.0f);

        ImGui.Columns(1);
        ImGui.EndChild();

        if (_selectedPacket >= 0 && _selectedPacket < filtered.Count)
        {
            RenderPacketDetails(filtered[_selectedPacket]);
        }

        ImGui.EndChild();
    }

    private void RenderPacketDetails(PacketLogEntry pkt)
    {
        ImGui.Separator();
        ImGui.TextColored(new Vector4(0.4f, 0.8f, 1, 1), "Packet Details");

        ImGui.Text($"Timestamp: {pkt.Timestamp:yyyy-MM-dd HH:mm:ss.fff}");
        ImGui.Text($"Direction: {pkt.DirStr}");
        ImGui.Text($"Protocol: {pkt.ProtoStr}");
        ImGui.Text($"Opcode: 0x{pkt.OpcodeDecimal:X4} ({pkt.OpcodeDecimal})");
        ImGui.Text($"Name: {pkt.OpcodeName}");
        ImGui.Text($"Size: {pkt.ByteLength} bytes");
        ImGui.Text($"Compression: {pkt.CompressionMethod}");
        ImGui.Text($"Encryption: {pkt.EncryptionHint}");

        if (pkt.QuicInfo != null)
        {
            ImGui.TextColored(new Vector4(1, 0.8f, 0.4f, 1), "QUIC Info:");
            ImGui.Text($"  Header Type: {pkt.QuicInfo.HeaderType}");
            ImGui.Text($"  Version: {pkt.QuicInfo.Version}");
            ImGui.Text($"  Packet Number: {pkt.QuicInfo.PacketNumber}");
        }

        ImGui.Separator();
        ImGui.Text("Raw Data (Hex):");

        string hex = pkt.RawHexPreview;
        if (!string.IsNullOrEmpty(hex))
        {
            ImGui.InputTextMultiline("##hex", ref hex, 5000, new Vector2(-1, 120),
                ImGuiInputTextFlags.ReadOnly);
        }

        if (!string.IsNullOrEmpty(pkt.DecompHexPreview) && pkt.IsCompressed)
        {
            ImGui.Text("Decompressed Data:");
            string decomp = pkt.DecompHexPreview;
            ImGui.InputTextMultiline("##decomp", ref decomp, 5000, new Vector2(-1, 120),
                ImGuiInputTextFlags.ReadOnly);
        }
    }
}