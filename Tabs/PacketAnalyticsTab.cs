using HyForce.Core;
using HyForce.Data;
using HyForce.Networking;
using ImGuiNET;
using System.Linq;
using System.Numerics;

namespace HyForce.Tabs;

public class PacketAnalyticsTab : ITab
{
    public string Name => "Analytics";
    private readonly AppState _state;
    private Dictionary<PacketCategory, int> _categoryStats = new();
    private List<PacketPattern>             _patterns        = new();
    private DateTime                        _lastStatsUpdate = DateTime.MinValue;
    private const int                       STATS_THROTTLE_MS = 500;

    public PacketAnalyticsTab(AppState state)
    {
        _state = state;
    }

    public void Render()
    {
        UpdateStats();

        ImGui.Text("Packet Analytics Dashboard");
        ImGui.Separator();

        RenderOverviewCards();
        ImGui.Separator();

        ImGui.BeginChild("Categories", new Vector2(300, 0), ImGuiChildFlags.Borders);
        RenderCategoryBreakdown();
        ImGui.EndChild();

        ImGui.SameLine();

        ImGui.BeginChild("Patterns", new Vector2(0, 0), ImGuiChildFlags.Borders);
        RenderPatternAnalysis();
        ImGui.EndChild();
    }
    
    private void RenderOverviewCards()
    {
        var log = _state.PacketLog;

        ImGui.BeginChild("Card1", new Vector2(150, 80), ImGuiChildFlags.Borders);
        ImGui.TextColored(new Vector4(0.5f, 0.8f, 1, 1), "TOTAL");
        ImGui.Text($"{log.TotalPackets:N0}");
        ImGui.EndChild();

        ImGui.SameLine();

        var packets = _state.PacketLog.GetAll();
        var c2s = packets.Count(p => p.Direction == PacketDirection.ClientToServer);
        ImGui.BeginChild("Card2", new Vector2(150, 80), ImGuiChildFlags.Borders);
        ImGui.TextColored(new Vector4(0.3f, 0.8f, 0.3f, 1), "C2S");
        ImGui.Text($"{c2s:N0}");
        ImGui.EndChild();

        ImGui.SameLine();

        var s2c = packets.Count(p => p.Direction == PacketDirection.ServerToClient);
        ImGui.BeginChild("Card3", new Vector2(150, 80), ImGuiChildFlags.Borders);
        ImGui.TextColored(new Vector4(0.8f, 0.5f, 0.2f, 1), "S2C");
        ImGui.Text($"{s2c:N0}");
        ImGui.EndChild();

        ImGui.SameLine();

        var unknown = packets.Count(p => !Protocol.OpcodeRegistry.IsKnownOpcode(p.OpcodeDecimal, p.Direction));
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
        if ((DateTime.Now - _lastStatsUpdate).TotalMilliseconds < STATS_THROTTLE_MS) return;
        _lastStatsUpdate = DateTime.Now;
        var packets = _state.PacketLog.GetLast(500); // FIX: was GetAll()

        _categoryStats = packets
            .Select(p => Protocol.OpcodeRegistry.GetInfo(p.OpcodeDecimal, p.Direction)?.Category ?? PacketCategory.Unknown)
            .GroupBy(c => c)
            .ToDictionary(g => g.Key, g => g.Count());

        _patterns = PacketPatternDetector.DetectPatterns(packets);
    }
}