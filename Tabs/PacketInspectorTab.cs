using HyForce.Core;
using HyForce.Data;
using HyForce.Networking;
using HyForce.Protocol;
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
            Row("Opcode", $"0x{pkt.OpcodeDecimal:X4}");
            Row("Name", pkt.OpcodeName);
            Row("Size", $"{pkt.ByteLength} bytes");
            Row("Compressed", pkt.IsCompressed ? "Yes" : "No");
            Row("Encrypted", pkt.EncryptionHint);
            Row("Injected", pkt.Injected ? "YES" : "No");

            ImGui.EndTable();
        }

        if (pkt.QuicInfo != null)
        {
            ImGui.Spacing();
            ImGui.TextColored(new Vector4(0.4f, 0.6f, 1, 1), "QUIC Header Information");
            ImGui.Text($"Header Type: {pkt.QuicInfo.HeaderType}");
            ImGui.Text($"Version: {pkt.QuicInfo.Version}");
            ImGui.Text($"Packet Number: {pkt.QuicInfo.PacketNumber}");
        }

        ImGui.Spacing();
        ImGui.TextColored(new Vector4(1, 0.8f, 0.2f, 1), "Raw Data");

        string hexData = pkt.RawHexPreview;

        ImGui.InputTextMultiline("##raw", ref hexData, 100000, new Vector2(-1, 200),
            ImGuiInputTextFlags.ReadOnly);

        ImGui.Spacing();
        if (ImGui.Button("Analyze Entropy"))
        {
            try
            {
                byte[] data = Convert.FromHexString(pkt.RawHexPreview.Replace("-", ""));
                double entropy = ByteUtils.CalculateEntropy(data);
                ImGui.Text($"Shannon Entropy: {entropy:F2} bits/byte");
                ImGui.ProgressBar((float)(entropy / 8.0), new Vector2(300, 20));
            }
            catch { }
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