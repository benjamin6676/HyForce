using HyForce.Core;
using HyForce.UI;
using ImGuiNET;

namespace HyForce.Tabs;

public class SettingsTab : ITab
{
    public string Name => "Settings";

    private readonly AppState _state;

    // Local copies for editing
    private bool _showTimestamps;
    private bool _autoScrollLogs;
    private bool _darkTheme;
    private bool _captureTcp;
    private bool _captureUdp;
    private bool _autoAnalyzeRegistry;
    private bool _enableAnomalyDetection;
    private bool _logSecurityEvents;
    private bool _autoExportOnStop;
    private int _maxPacketLogSize;
    private int _connectionTimeoutMs;
    private int _anomalyThresholdSize;
    private string _exportDirectory = "";

    public SettingsTab(AppState state)
    {
        _state = state;
        LoadFromConfig();
    }

    private void LoadFromConfig()
    {
        var config = _state.Config;
        _showTimestamps = config.ShowTimestamps;
        _autoScrollLogs = config.AutoScrollLogs;
        _darkTheme = config.DarkTheme;
        _captureTcp = config.CaptureTcp;
        _captureUdp = config.CaptureUdp;
        _autoAnalyzeRegistry = config.AutoAnalyzeRegistry;
        _enableAnomalyDetection = config.EnableAnomalyDetection;
        _logSecurityEvents = config.LogSecurityEvents;
        _autoExportOnStop = config.AutoExportOnStop;
        _maxPacketLogSize = config.MaxPacketLogSize;
        _connectionTimeoutMs = config.ConnectionTimeoutMs;
        _anomalyThresholdSize = config.AnomalyThresholdSize;
        _exportDirectory = config.ExportDirectory;
    }

    private void SaveToConfig()
    {
        var config = _state.Config;
        config.ShowTimestamps = _showTimestamps;
        config.AutoScrollLogs = _autoScrollLogs;
        config.DarkTheme = _darkTheme;
        config.CaptureTcp = _captureTcp;
        config.CaptureUdp = _captureUdp;
        config.AutoAnalyzeRegistry = _autoAnalyzeRegistry;
        config.EnableAnomalyDetection = _enableAnomalyDetection;
        config.LogSecurityEvents = _logSecurityEvents;
        config.AutoExportOnStop = _autoExportOnStop;
        config.MaxPacketLogSize = _maxPacketLogSize;
        config.ConnectionTimeoutMs = _connectionTimeoutMs;
        config.AnomalyThresholdSize = _anomalyThresholdSize;
        config.ExportDirectory = _exportDirectory;
    }

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();

        ImGui.Spacing();
        ImGui.Text("  SETTINGS  —  Configuration");
        ImGui.Separator();
        ImGui.Spacing();

        if (ImGui.BeginTabBar("##settings_tabs"))
        {
            if (ImGui.BeginTabItem("General"))
            {
                RenderGeneralSettings();
                ImGui.EndTabItem();
            }

            if (ImGui.BeginTabItem("Capture"))
            {
                RenderCaptureSettings();
                ImGui.EndTabItem();
            }

            if (ImGui.BeginTabItem("Analysis"))
            {
                RenderAnalysisSettings();
                ImGui.EndTabItem();
            }

            ImGui.EndTabBar();
        }

        // Save changes
        SaveToConfig();
    }

    private void RenderGeneralSettings()
    {
        ImGui.Checkbox("Show Timestamps", ref _showTimestamps);
        ImGui.Checkbox("Auto-scroll Logs", ref _autoScrollLogs);
        ImGui.Checkbox("Dark Theme", ref _darkTheme);

        ImGui.Spacing();
        ImGui.Separator();
        ImGui.Text("Export");

        ImGui.InputText("Export Directory", ref _exportDirectory, 256);
        ImGui.Checkbox("Auto-export on Stop", ref _autoExportOnStop);
    }

    private void RenderCaptureSettings()
    {
        ImGui.Checkbox("Capture TCP Traffic", ref _captureTcp);
        ImGui.Checkbox("Capture UDP Traffic", ref _captureUdp);

        ImGui.Spacing();
        ImGui.InputInt("Max Packet Log Size", ref _maxPacketLogSize);
        _maxPacketLogSize = Math.Max(1000, Math.Min(50000, _maxPacketLogSize));

        ImGui.Spacing();
        ImGui.InputInt("Connection Timeout (ms)", ref _connectionTimeoutMs);
        _connectionTimeoutMs = Math.Max(5000, _connectionTimeoutMs);
    }

    private void RenderAnalysisSettings()
    {
        ImGui.Checkbox("Auto-analyze Registry", ref _autoAnalyzeRegistry);
        ImGui.Checkbox("Detect Anomalies", ref _enableAnomalyDetection);
        ImGui.Checkbox("Log Security Events", ref _logSecurityEvents);

        ImGui.Spacing();
        ImGui.InputInt("Anomaly Threshold (bytes)", ref _anomalyThresholdSize);
        _anomalyThresholdSize = Math.Max(10000, _anomalyThresholdSize);
    }
}