using HyForce.Core;
using HyForce.UI;
using ImGuiNET;
using System.Numerics;

namespace HyForce.Tabs;

public class LogTab : ITab
{
    public string Name => "Log";

    private readonly AppState _state;
    private bool _autoScroll = true;
    private string _filter = "";
    private bool _showTimestamps = true;
    private int _logVersion = 0;

    public LogTab(AppState state)
    {
        _state = state;
        _state.OnPacketReceived += (packet) => _logVersion++;  // FIXED - accept the packet parameter
    }

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();

        ImGui.Spacing();
        ImGui.Text("  IN-GAME LOG  --  Debug Output");
        ImGui.Separator();
        ImGui.Spacing();

        // Toolbar
        ImGui.Checkbox("Auto-scroll", ref _autoScroll);
        ImGui.SameLine();
        ImGui.Checkbox("Timestamps", ref _showTimestamps);
        ImGui.SameLine();
        ImGui.SetNextItemWidth(200);
        ImGui.InputText("Filter", ref _filter, 256);

        ImGui.SameLine(ImGui.GetWindowWidth() - 220);
        if (ImGui.Button("Copy All", new Vector2(100, 0)))
        {
            lock (_state.InGameLog)
            {
                ImGui.SetClipboardText(string.Join("\n", _state.InGameLog));
            }
        }
        ImGui.SameLine();
        if (ImGui.Button("Clear", new Vector2(100, 0)))
        {
            lock (_state.InGameLog) _state.InGameLog.Clear();
        }

        ImGui.Spacing();

        // Log display with colored lines
        ImGui.BeginChild("##log_content", new Vector2(0, avail.Y - 100), ImGuiChildFlags.Borders);

        lock (_state.InGameLog)
        {
            var logs = string.IsNullOrEmpty(_filter)
                ? _state.InGameLog
                : _state.InGameLog.Where(l => l.Contains(_filter, StringComparison.OrdinalIgnoreCase)).ToList();

            ImGui.PushStyleVar(ImGuiStyleVar.ItemSpacing, new Vector2(0, 2));

            for (int i = 0; i < logs.Count; i++)
            {
                var line = logs[i];

                // Determine color based on content
                var color = Vector4.One;
                var bgColor = new Vector4(0, 0, 0, 0);

                if (line.Contains("[ERROR]") || line.Contains("failed") || line.Contains("FAIL"))
                {
                    color = Theme.ColDanger;
                    bgColor = new Vector4(0.3f, 0.1f, 0.1f, 0.3f);
                }
                else if (line.Contains("[SECURITY]") || line.Contains("Anomaly") || line.Contains("suspicious"))
                {
                    color = Theme.ColWarn;
                    bgColor = new Vector4(0.3f, 0.25f, 0.1f, 0.3f);
                }
                else if (line.Contains("[SUCCESS]") || line.Contains("started") || line.Contains("RUNNING"))
                {
                    color = Theme.ColSuccess;
                    bgColor = new Vector4(0.1f, 0.3f, 0.1f, 0.3f);
                }
                else if (line.Contains("[Registry]") || line.Contains("RegistrySync"))
                {
                    color = Theme.ColBlue;
                }
                else if (line.Contains("[TCP]"))
                {
                    color = new Vector4(0.8f, 0.6f, 0.4f, 1f);
                }
                else if (line.Contains("[UDP]"))
                {
                    color = new Vector4(0.4f, 0.6f, 0.8f, 1f);
                }

                // Draw background if colored
                if (bgColor.W > 0)
                {
                    var drawList = ImGui.GetWindowDrawList();
                    var pos = ImGui.GetCursorScreenPos();
                    var size = new Vector2(ImGui.GetContentRegionAvail().X, ImGui.GetTextLineHeight());
                    drawList.AddRectFilled(pos, pos + size, ImGui.ColorConvertFloat4ToU32(bgColor));
                }

                ImGui.PushStyleColor(ImGuiCol.Text, color);

                // Remove timestamp if disabled
                var displayLine = line;
                if (!_showTimestamps && line.Length > 10 && line[0] == '[' && line[9] == ']')
                {
                    displayLine = line[10..].TrimStart();
                }

                ImGui.TextUnformatted(displayLine);
                ImGui.PopStyleColor();

                // Right-click to copy line
                if (ImGui.IsItemHovered() && ImGui.IsMouseClicked(ImGuiMouseButton.Right))
                {
                    ImGui.SetClipboardText(line);
                }
            }

            ImGui.PopStyleVar();

            if (_autoScroll && ImGui.GetScrollY() < ImGui.GetScrollMaxY())
                ImGui.SetScrollHereY(1.0f);
        }

        ImGui.EndChild();

        // Quick actions footer
        ImGui.Spacing();
        ImGui.Separator();

        ImGui.Text("Quick Actions:");
        ImGui.SameLine();

        if (ImGui.Button("Test Message", new Vector2(100, 0)))
        {
            _state.AddInGameLog("Test message from button");
        }
        ImGui.SameLine();

        if (ImGui.Button("Test Error", new Vector2(100, 0)))
        {
            _state.AddInGameLog("[ERROR] Test error message");
        }
        ImGui.SameLine();

        if (ImGui.Button("Test Security", new Vector2(100, 0)))
        {
            _state.AddInGameLog("[SECURITY] Test security event");
        }
        ImGui.SameLine();

        if (ImGui.Button("Export Log", new Vector2(100, 0)))
        {
            try
            {
                string filename = Path.Combine(_state.ExportDirectory,
                    $"hyforce_ingamelog_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
                lock (_state.InGameLog)
                {
                    File.WriteAllLines(filename, _state.InGameLog);
                }
                _state.AddInGameLog($"[SUCCESS] Log exported to {filename}");
            }
            catch (Exception ex)
            {
                _state.AddInGameLog($"[ERROR] Export failed: {ex.Message}");
            }
        }
    }
}