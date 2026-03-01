using HyForce.Core;
using HyForce.Protocol;
using HyForce.UI;
using ImGuiNET;
using System.Numerics;

namespace HyForce.Tabs;

public class AnalyticsTab : ITab
{
    public string Name => "Analytics";

    private readonly AppState _state;
    private int _selectedView = 0; // 0=Overview, 1=Traffic, 2=Opcodes, 3=Items

    public AnalyticsTab(AppState state)
    {
        _state = state;
    }

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();

        ImGui.Spacing();
        ImGui.Text("  ANALYTICS  —  Traffic Analysis & Statistics");
        ImGui.Separator();
        ImGui.Spacing();

        // View selector
        string[] views = { "Overview", "Traffic", "Opcodes", "Items" };
        ImGui.Combo("View", ref _selectedView, views, views.Length);
        ImGui.Separator();
        ImGui.Spacing();

        switch (_selectedView)
        {
            case 0: RenderOverview(); break;
            case 1: RenderTraffic(); break;
            case 2: RenderOpcodes(); break;
            case 3: RenderItems(); break;
        }
    }

    private void RenderOverview()
    {
        var avail = ImGui.GetContentRegionAvail();

        ImGui.Columns(2, "##overview", false);

        // Left column
        ImGui.Text("Traffic Summary");
        ImGui.Separator();
        ImGui.Text($"Total Packets: {_state.TotalPackets}");
        ImGui.Text($"TCP Packets: {_state.TcpPackets}");
        ImGui.Text($"UDP Packets: {_state.UdpPackets}");
        ImGui.Spacing();
        ImGui.Text($"Total Bytes: {FormatBytes(_state.PacketLog.BytesSc + _state.PacketLog.BytesCs)}");

        ImGui.NextColumn();

        // Right column
        ImGui.Text("Registry Summary");
        ImGui.Separator();
        ImGui.Text($"Items Found: {_state.Database.Items.Count}");
        ImGui.Text($"Players Seen: {_state.Database.Players.Count}");
        ImGui.Text($"Unique Opcodes: {_state.PacketLog.UniqueOpcodes}");

        ImGui.Columns(1);
    }

    private void RenderTraffic()
    {
        // Traffic over time graph (simplified)
        ImGui.Text("Traffic Rate (packets/second)");

        float[] data = GenerateTrafficData();
        ImGui.PlotLines("##traffic", ref data[0], data.Length, 0, "", 0, float.MaxValue, new Vector2(ImGui.GetContentRegionAvail().X, 200));

        ImGui.Spacing();

        ImGui.Columns(2, "##traffic_stats", false);
        ImGui.Text($"Peak: {data.Max():F1} pkt/s");
        ImGui.NextColumn();
        ImGui.Text($"Average: {data.Average():F1} pkt/s");
        ImGui.Columns(1);
    }

    private void RenderOpcodes()
    {
        var counts = _state.PacketLog.GetOpcodeCounts().OrderByDescending(x => x.Value).Take(20);

        ImGui.Text("Top 20 Opcodes");
        ImGui.Separator();

        foreach (var kv in counts)
        {
            string name = OpcodeRegistry.Label(kv.Key, Networking.PacketDirection.ServerToClient);
            float pct = _state.TotalPackets > 0 ? kv.Value / (float)_state.TotalPackets : 0;

            ImGui.Text($"0x{kv.Key:X2}");
            ImGui.SameLine(60);
            ImGui.Text(name);
            ImGui.SameLine(200);
            ImGui.ProgressBar(pct, new Vector2(200, 16), $"{kv.Value}");
        }
    }

    private void RenderItems()
    {
        ImGui.Text("Discovered Items");
        ImGui.Separator();

        var items = _state.Database.Items.Values.Take(100);

        ImGui.BeginChild("##items_list", new Vector2(0, 400), ImGuiChildFlags.Borders);

        foreach (var item in items)
        {
            ImGui.Text($"[{item.Id:X8}] {item.Name}");
        }

        ImGui.EndChild();
    }

    private float[] GenerateTrafficData()
    {
        // Generate sample data - in production would be real metrics
        var random = new Random();
        var data = new float[100];
        for (int i = 0; i < 100; i++)
            data[i] = random.Next(10, 100);
        return data;
    }

    private string FormatBytes(long bytes)
    {
        string[] suffixes = { "B", "KB", "MB", "GB" };
        int i = 0;
        double d = bytes;
        while (d >= 1024 && i < suffixes.Length - 1)
        {
            d /= 1024;
            i++;
        }
        return $"{d:F2} {suffixes[i]}";
    }
}