// FILE: Tabs/SecurityAuditTab.cs - FIXED: REMOVED TcpPackets
using HyForce.Core;
using HyForce.Data;
using HyForce.UI;
using ImGuiNET;
using System.Numerics;

namespace HyForce.Tabs;

public class SecurityAuditTab : ITab
{
    public string Name => "Security";

    private readonly AppState _state;
    private bool _autoScroll = true;

    public SecurityAuditTab(AppState state)
    {
        _state = state;
    }

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();

        ImGui.Spacing();
        ImGui.Text("  SECURITY AUDIT  -  Defensive Testing");
        ImGui.Separator();
        ImGui.Spacing();

        // Security score
        RenderSecurityScore(avail.X);
        ImGui.Spacing();

        // Event list
        ImGui.Text("Security Events");
        ImGui.Separator();

        ImGui.BeginChild("##events", new Vector2(avail.X - 16, avail.Y - 200), ImGuiChildFlags.Borders);

        foreach (var evt in _state.SecurityEvents)
        {
            RenderEvent(evt);
        }

        if (_autoScroll && ImGui.GetScrollY() < ImGui.GetScrollMaxY())
            ImGui.SetScrollHereY(1.0f);

        ImGui.EndChild();

        // Controls
        ImGui.Checkbox("Auto-scroll", ref _autoScroll);
        ImGui.SameLine();
        if (ImGui.Button("Export Report"))
        {
            string report = _state.GenerateDiagnostics();
            File.WriteAllText($"security_report_{DateTime.Now:yyyyMMdd_HHmmss}.txt", report);
            _state.Log.Success("Security report exported", "Export");
        }
    }

    private void RenderSecurityScore(float w)
    {
        int score = CalculateSecurityScore();
        var color = score switch
        {
            >= 90 => Theme.ColSuccess,
            >= 70 => new Vector4(0.9f, 0.9f, 0.2f, 1),
            >= 50 => new Vector4(0.9f, 0.6f, 0.2f, 1),
            _ => Theme.ColDanger
        };

        ImGui.Columns(2, "##score", false);

        ImGui.Text("Security Score:");
        ImGui.NextColumn();
        ImGui.TextColored(color, $"{score}/100");
        ImGui.NextColumn();

        ImGui.Columns(1);

        // Progress bar
        ImGui.ProgressBar(score / 100.0f, new Vector2(w - 32, 20), $"{score}%");
    }

    private int CalculateSecurityScore()
    {
        int score = 100;

        var anomalies = _state.SecurityEvents.Count(e => e.Category == "Anomaly");
        score -= anomalies * 5;

        // FIXED: Removed TcpPackets reference - UDP only
        // Check if we have reasonable UDP traffic instead
        if (_state.UdpPackets < 10 && _state.IsRunning)
            score -= 20; // No traffic captured

        return Math.Max(0, score);
    }

    private void RenderEvent(SecurityEvent evt)
    {
        var color = evt.Category switch
        {
            "Anomaly" => Theme.ColDanger,
            "Registry" => new Vector4(0.2f, 0.7f, 0.9f, 1),
            _ => Theme.ColTextMuted
        };

        ImGui.TextColored(color, $"[{evt.Timestamp:HH:mm:ss}]");
        ImGui.SameLine();
        ImGui.Text($"[{evt.Category}]");
        ImGui.SameLine();
        ImGui.Text(evt.Message);

        if (evt.Metadata.Any() && ImGui.IsItemHovered())
        {
            ImGui.BeginTooltip();
            foreach (var kvp in evt.Metadata)
            {
                ImGui.Text($"{kvp.Key}: {kvp.Value}");
            }
            ImGui.EndTooltip();
        }
    }
}