// FILE: Tabs/PacketAnalyticsTab.cs (NEW)
using HyForce.Core;
using HyForce.Protocol;
using ImGuiNET;
using System.Numerics;

namespace HyForce.Tabs;

public class PacketAnalyticsTab : ITab
{
    public string Name => "Analytics";
    private readonly AppState _state;
    private Dictionary<PacketCategory, int> _categoryStats = new();
    private List<PacketPattern> _patterns = new();

    public PacketAnalyticsTab(AppState state)
    {
        _state = state;
    }

    public void Render()
    {
        UpdateStats();

        ImGui.Text("Packet Analytics Dashboard");
        ImGui.Separator();

        // Top stats row
        RenderOverviewCards();

        ImGui.Separator();

        // Category breakdown
        ImGui.BeginChild("Categories", new Vector2(300, 0), ImGuiChildFlags.Borders);
        RenderCategoryBreakdown();
        ImGui.EndChild();

        ImGui.SameLine();

        // Pattern analysis
        ImGui.BeginChild("Patterns", new Vector2(0, 0), ImGuiChildFlags.Borders);
        RenderPatternAnalysis();
        ImGui.EndChild();
    }

    private void RenderOverviewCards()
    {
        var packets = _state.PacketLog.GetAll();

        // Total packets card
        ImGui.BeginChild("Card1", new Vector2(150, 80), ImGuiChildFlags.Borders);
        ImGui.TextColored(new Vector4(0.5f, 0.8f, 1, 1), "TOTAL");
        ImGui.Text($"{packets.Count:N0}");
        ImGui.EndChild();

        ImGui.SameLine();

        // C2S card
        var c2s = packets.Count(p => p.Direction == Networking.PacketDirection.ClientToServer);
        ImGui.BeginChild("Card2", new Vector2(150, 80), ImGuiChildFlags.Borders);
        ImGui.TextColored(new Vector4(0.3f, 0.8f, 0.3f, 1), "C2S (Client→Server)");
        ImGui.Text($"{c2s:N0}");
        ImGui.EndChild();

        ImGui.SameLine();

        // S2C card
        var s2c = packets.Count(p => p.Direction == Networking.PacketDirection.ServerToClient);
        ImGui.BeginChild("Card3", new Vector2(150, 80), ImGuiChildFlags.Borders);
        ImGui.TextColored(new Vector4(0.8f, 0.5f, 0.2f, 1), "S2C (Server→Client)");
        ImGui.Text($"{s2c:N0}");
        ImGui.EndChild();

        ImGui.SameLine();

        // Unknown packets
        var unknown = packets.Count(p => !OpcodeRegistry.IsKnownOpcode(p.OpcodeDecimal, p.Direction));
        ImGui.BeginChild("Card4", new Vector2(150, 80), ImGuiChildFlags.Borders);
        ImGui.TextColored(new Vector4(1, 0.3f, 0.3f, 1), "UNKNOWN");
        ImGui.Text($"{unknown:N0}");
        ImGui.EndChild();
    }

    private void RenderCategoryBreakdown()
    {
        ImGui.Text("Traffic by Category");
        ImGui.Separator();

        foreach (var cat in _categoryStats.OrderByDescending(x => x.Value))
        {
            var pct = (float)cat.Value / _categoryStats.Values.Sum();
            ImGui.Text($"{cat.Key}: {cat.Value}");
            ImGui.ProgressBar(pct, new Vector2(-1, 15));
        }
    }

    private void RenderPatternAnalysis()
    {
        ImGui.Text("Traffic Patterns");
        ImGui.Separator();

        foreach (var pattern in _patterns.Take(15))
        {
            var color = pattern.IsPeriodic ? new Vector4(0.2f, 1, 0.2f, 1) :
                       pattern.IsBurst ? new Vector4(1, 0.6f, 0.2f, 1) :
                       new Vector4(1, 1, 1, 1);

            ImGui.TextColored(color, pattern.PacketName);
            ImGui.Text($"  Opcode: 0x{pattern.Opcode:X4} | Count: {pattern.Count}");

            if (pattern.IsPeriodic)
                ImGui.Text($"  Periodic every {pattern.PeriodMs:F0}ms");
            if (pattern.IsBurst)
                ImGui.Text($"  Burst rate: {pattern.RatePerSecond:F0}/sec");

            ImGui.Separator();
        }
    }

    private void UpdateStats()
    {
        var packets = _state.PacketLog.GetAll();

        // Update category stats
        _categoryStats = packets
            .Select(p => OpcodeRegistry.GetInfo(p.OpcodeDecimal, p.Direction)?.Category ?? PacketCategory.Unknown)
            .GroupBy(c => c)
            .ToDictionary(g => g.Key, g => g.Count());

        // Update patterns
        _patterns = PacketInspector.DetectPatterns(packets);
    }
}