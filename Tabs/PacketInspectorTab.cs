// FILE: Tabs/PacketInspectorTab.cs
using HyForce.Core;
using HyForce.Data;
using HyForce.Networking;
using HyForce.Utils;
using ImGuiNET;
using System.Numerics;

namespace HyForce.Tabs;

public class PacketInspectorTab : ITab
{
    private readonly AppState _state;
    private PacketLogEntry? _selectedPacket;

    public string Name => "Inspector";

    public PacketInspectorTab(AppState state)
    {
        _state = state;
    }

    public void Render()
    {
        ImGui.BeginChild("Inspector", new Vector2(0, 0), ImGuiChildFlags.None);

        if (_selectedPacket == null)
        {
            ImGui.TextDisabled("Select a packet from the Packet Feed to inspect");
            ImGui.EndChild();
            return;
        }

        var pkt = _selectedPacket;

        ImGui.TextColored(new Vector4(0.2f, 0.8f, 0.2f, 1), "Packet Inspector");
        ImGui.Separator();

        if (ImGui.BeginTable("PacketInfo", 2, ImGuiTableFlags.Borders | ImGuiTableFlags.RowBg))
        {
            ImGui.TableSetupColumn("Property", ImGuiTableColumnFlags.WidthFixed, 120);
            ImGui.TableSetupColumn("Value", ImGuiTableColumnFlags.WidthStretch);
            ImGui.TableHeadersRow();

            Row("Timestamp", pkt.Timestamp.ToString("O"));
            Row("Direction", pkt.DirStr);
            Row("Protocol", pkt.ProtoStr);
            Row("Opcode", $"0x{pkt.OpcodeDecimal:X4} ({pkt.OpcodeDecimal})");
            Row("Name", pkt.OpcodeName);
            Row("Size", $"{pkt.ByteLength} bytes");
            Row("Compressed", pkt.IsCompressed ? $"{pkt.CompressionMethod} ({pkt.CompressedSize} → {pkt.DecompressedSize})" : "No");
            Row("Encrypted", pkt.EncryptionHint);
            Row("Injected", pkt.Injected ? "YES" : "No");

            ImGui.EndTable();
        }

        if (pkt.QuicInfo != null)
        {
            ImGui.Spacing();
            ImGui.TextColored(new Vector4(0.4f, 0.6f, 1, 1), "QUIC Header Information");

            if (ImGui.BeginTable("QuicInfo", 2, ImGuiTableFlags.Borders | ImGuiTableFlags.RowBg))
            {
                ImGui.TableSetupColumn("Property", ImGuiTableColumnFlags.WidthFixed, 150);
                ImGui.TableSetupColumn("Value", ImGuiTableColumnFlags.WidthStretch);
                ImGui.TableHeadersRow();

                Row("Header Type", pkt.QuicInfo.HeaderType);
                Row("Version", pkt.QuicInfo.Version.ToString());
                Row("Packet Number", pkt.QuicInfo.PacketNumber.ToString());

                if (pkt.QuicInfo.DestinationConnectionId != null)
                    Row("Destination CID", BitConverter.ToString(pkt.QuicInfo.DestinationConnectionId));

                if (pkt.QuicInfo.SourceConnectionId != null)
                    Row("Source CID", BitConverter.ToString(pkt.QuicInfo.SourceConnectionId));

                ImGui.EndTable();
            }
        }

        ImGui.Spacing();
        ImGui.TextColored(new Vector4(1, 0.8f, 0.2f, 1), "Raw Data");

        string hexData = ByteUtils.ToHex(pkt.RawHexPreview.Replace("-", "").HexToBytes() ?? Array.Empty<byte>(), 32);

        ImGui.InputTextMultiline("##raw", ref hexData, 100000, new Vector2(-1, 200),
            ImGuiInputTextFlags.ReadOnly);

        ImGui.Spacing();
        if (ImGui.Button("Analyze Entropy"))
        {
            byte[] data = pkt.RawHexPreview.Replace("-", "").HexToBytes() ?? Array.Empty<byte>();
            double entropy = ByteUtils.CalculateEntropy(data);
            ImGui.Text($"Shannon Entropy: {entropy:F2} bits/byte");
            ImGui.ProgressBar((float)(entropy / 8.0), new Vector2(300, 20), $"{entropy:F2}/8.0");
        }

        ImGui.EndChild();
    }

    private void Row(string label, string value)
    {
        ImGui.TableNextRow();
        ImGui.TableNextColumn();
        ImGui.Text(label);
        ImGui.TableNextColumn();
        ImGui.Text(value);
    }

    public void SelectPacket(PacketLogEntry packet)
    {
        _selectedPacket = packet;
    }
}

public static class PacketInspectorExtensions
{
    public static byte[]? HexToBytes(this string hex)
    {
        if (string.IsNullOrEmpty(hex)) return null;
        try
        {
            hex = hex.Replace("-", "").Replace(" ", "");
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < hex.Length; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }
        catch { return null; }
    }
}