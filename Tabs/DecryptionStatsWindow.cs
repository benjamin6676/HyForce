using HyForce.Core;
using HyForce.Protocol;
using HyForce.UI;
using ImGuiNET;
using System.Numerics;

namespace HyForce.Tabs;

public class DecryptionStatsWindow : ITab
{
    public string Name => "Decrypt Stats";

    private readonly AppState _state;

    // Live stats
    private long _lastSuccessful = 0;
    private long _lastFailed = 0;
    private long _lastSkipped = 0;
    private int _successRate = 0;
    private DateTime _startTime = DateTime.Now;

    // History for graph
    private List<float> _successHistory = new();
    private List<float> _failHistory = new();
    private const int MAX_HISTORY = 100;

    // Recent activity log
    private List<DecryptActivity> _activityLog = new();
    private const int MAX_LOG = 50;

    public DecryptionStatsWindow(AppState state)
    {
        _state = state;
    }

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();

        // Get current stats
        var currentSuccess = PacketDecryptor.SuccessfulDecryptions;
        var currentFailed = PacketDecryptor.FailedDecryptions;
        var currentSkipped = PacketDecryptor.SkippedDecryptions;
        var totalKeys = PacketDecryptor.DiscoveredKeys.Count;

        // Calculate deltas
        long newSuccess = currentSuccess - _lastSuccessful;
        long newFailed = currentFailed - _lastFailed;
        long newSkipped = currentSkipped - _lastSkipped;

        // Update history
        UpdateHistory(newSuccess, newFailed);

        // Update last values
        _lastSuccessful = currentSuccess;
        _lastFailed = currentFailed;
        _lastSkipped = currentSkipped;

        // Calculate success rate
        long totalAttempts = currentSuccess + currentFailed;
        _successRate = totalAttempts > 0 ? (int)((currentSuccess * 100) / totalAttempts) : 0;

        ImGui.Spacing();
        ImGui.Text("  LIVE DECRYPTION STATISTICS");
        ImGui.Separator();
        ImGui.Spacing();

        // Big counters row
        RenderBigCounters(currentSuccess, currentFailed, currentSkipped, totalKeys, _successRate);

        ImGui.Spacing();
        ImGui.Separator();

        // Two column layout
        float leftWidth = avail.X * 0.6f - 8;
        float rightWidth = avail.X * 0.4f - 8;

        ImGui.BeginChild("##left_panel", new Vector2(leftWidth, avail.Y - 150), ImGuiChildFlags.Borders);
        RenderActivityGraph(leftWidth);
        ImGui.EndChild();

        ImGui.SameLine();

        ImGui.BeginChild("##right_panel", new Vector2(rightWidth, avail.Y - 150), ImGuiChildFlags.Borders);
        RenderActivityLog(rightWidth);
        ImGui.EndChild();

        // Add recent activity to log
        if (newSuccess > 0 || newFailed > 0)
        {
            AddActivity(newSuccess, newFailed);
        }
    }

    private void RenderBigCounters(long success, long failed, long skipped, int keys, int rate)
    {
        float windowWidth = ImGui.GetContentRegionAvail().X;
        float boxWidth = (windowWidth - 60) / 5;

        // Success box - GREEN
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.1f, 0.3f, 0.1f, 1f));
        ImGui.BeginChild("##success_box", new Vector2(boxWidth, 80), ImGuiChildFlags.Borders);
        ImGui.TextColored(new Vector4(0.2f, 0.9f, 0.2f, 1f), "SUCCESS");
        ImGui.SetWindowFontScale(2.0f);
        ImGui.TextColored(new Vector4(0.2f, 1f, 0.2f, 1f), success.ToString());
        ImGui.SetWindowFontScale(1.0f);
        ImGui.EndChild();
        ImGui.PopStyleColor();

        ImGui.SameLine();

        // Failed box - RED
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.3f, 0.1f, 0.1f, 1f));
        ImGui.BeginChild("##failed_box", new Vector2(boxWidth, 80), ImGuiChildFlags.Borders);
        ImGui.TextColored(new Vector4(0.9f, 0.2f, 0.2f, 1f), "FAILED");
        ImGui.SetWindowFontScale(2.0f);
        ImGui.TextColored(new Vector4(1f, 0.2f, 0.2f, 1f), failed.ToString());
        ImGui.SetWindowFontScale(1.0f);
        ImGui.EndChild();
        ImGui.PopStyleColor();

        ImGui.SameLine();

        // Skipped box - YELLOW
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.3f, 0.3f, 0.1f, 1f));
        ImGui.BeginChild("##skipped_box", new Vector2(boxWidth, 80), ImGuiChildFlags.Borders);
        ImGui.TextColored(new Vector4(0.9f, 0.9f, 0.2f, 1f), "SKIPPED");
        ImGui.SetWindowFontScale(2.0f);
        ImGui.TextColored(new Vector4(1f, 1f, 0.2f, 1f), skipped.ToString());
        ImGui.SetWindowFontScale(1.0f);
        ImGui.EndChild();
        ImGui.PopStyleColor();

        ImGui.SameLine();

        // Keys box - BLUE
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.1f, 0.2f, 0.3f, 1f));
        ImGui.BeginChild("##keys_box", new Vector2(boxWidth, 80), ImGuiChildFlags.Borders);
        ImGui.TextColored(new Vector4(0.4f, 0.7f, 1f, 1f), "KEYS");
        ImGui.SetWindowFontScale(2.0f);
        ImGui.TextColored(new Vector4(0.5f, 0.8f, 1f, 1f), keys.ToString());
        ImGui.SetWindowFontScale(1.0f);
        ImGui.EndChild();
        ImGui.PopStyleColor();

        ImGui.SameLine();

        // Rate box - PURPLE
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.3f, 0.1f, 0.3f, 1f));
        ImGui.BeginChild("##rate_box", new Vector2(boxWidth, 80), ImGuiChildFlags.Borders);
        ImGui.TextColored(new Vector4(0.9f, 0.5f, 0.9f, 1f), "RATE");
        ImGui.SetWindowFontScale(2.0f);
        ImGui.TextColored(new Vector4(1f, 0.6f, 1f, 1f), $"{rate}%");
        ImGui.SetWindowFontScale(1.0f);
        ImGui.EndChild();
        ImGui.PopStyleColor();
    }

    private void RenderActivityGraph(float width)
    {
        ImGui.TextColored(Theme.ColAccent, "Live Activity (Last 100 frames)");
        ImGui.Separator();

        if (_successHistory.Count < 2)
        {
            ImGui.TextColored(Theme.ColTextMuted, "Collecting data...");
            return;
        }

        // Draw simple bar graph
        float barWidth = width / MAX_HISTORY;
        float maxVal = Math.Max(_successHistory.Max(), _failHistory.Max());
        maxVal = Math.Max(maxVal, 1); // Avoid divide by zero

        var drawList = ImGui.GetWindowDrawList();
        var pos = ImGui.GetCursorScreenPos();

        for (int i = 0; i < _successHistory.Count; i++)
        {
            float x = pos.X + i * barWidth;

            // Success bar (green, from bottom up)
            float successHeight = (_successHistory[i] / maxVal) * 100;
            if (successHeight > 0)
            {
                drawList.AddRectFilled(
                    new Vector2(x, pos.Y + 100 - successHeight),
                    new Vector2(x + barWidth - 1, pos.Y + 100),
                    ImGui.ColorConvertFloat4ToU32(new Vector4(0.2f, 0.8f, 0.2f, 1f))
                );
            }

            // Fail bar (red, on top of success)
            float failHeight = (_failHistory[i] / maxVal) * 100;
            if (failHeight > 0)
            {
                drawList.AddRectFilled(
                    new Vector2(x, pos.Y + 100 - successHeight - failHeight),
                    new Vector2(x + barWidth - 1, pos.Y + 100 - successHeight),
                    ImGui.ColorConvertFloat4ToU32(new Vector4(0.9f, 0.2f, 0.2f, 1f))
                );
            }
        }

        ImGui.Dummy(new Vector2(0, 110));

        // Legend
        ImGui.TextColored(new Vector4(0.2f, 0.8f, 0.2f, 1f), "■ Success");
        ImGui.SameLine();
        ImGui.TextColored(new Vector4(0.9f, 0.2f, 0.2f, 1f), "■ Failed");
    }

    private void RenderActivityLog(float width)
    {
        ImGui.TextColored(Theme.ColAccent, "Recent Activity");
        ImGui.Separator();

        ImGui.BeginChild("##activity_scroll", new Vector2(0, 0), ImGuiChildFlags.None);

        foreach (var activity in _activityLog.TakeLast(20).Reverse())
        {
            var color = activity.Success > 0 ? new Vector4(0.2f, 1f, 0.2f, 1f) :
                       activity.Failed > 0 ? new Vector4(1f, 0.3f, 0.3f, 1f) :
                       Theme.ColTextMuted;

            string msg = activity.Success > 0
                ? $"+{activity.Success} success"
                : $"+{activity.Failed} failed";

            ImGui.TextColored(color, $"[{activity.Time:HH:mm:ss.fff}] {msg}");
        }

        if (!_activityLog.Any())
        {
            ImGui.TextColored(Theme.ColTextMuted, "No activity yet...");
        }

        ImGui.EndChild();
    }

    private void UpdateHistory(float success, float failed)
    {
        _successHistory.Add(success);
        _failHistory.Add(failed);

        if (_successHistory.Count > MAX_HISTORY)
            _successHistory.RemoveAt(0);
        if (_failHistory.Count > MAX_HISTORY)
            _failHistory.RemoveAt(0);
    }

    private void AddActivity(long success, long failed)
    {
        _activityLog.Add(new DecryptActivity
        {
            Time = DateTime.Now,
            Success = success,
            Failed = failed
        });

        if (_activityLog.Count > MAX_LOG)
            _activityLog.RemoveAt(0);
    }

    private class DecryptActivity
    {
        public DateTime Time { get; set; }
        public long Success { get; set; }
        public long Failed { get; set; }
    }
}