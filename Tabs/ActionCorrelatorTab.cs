using HyForce.Core;
using HyForce.Data;
using HyForce.Networking;
using HyForce.Protocol;
using HyForce.UI;
using ImGuiNET;
using System.Numerics;
using System.Diagnostics;

namespace HyForce.Tabs;

public class ActionCorrelatorTab : ITab
{
    public string Name => "Action Correlator";

    private readonly AppState _state;

    // Action tracking
    private enum ActionState { Idle, Countdown, Capturing, Analyzing }
    private ActionState _currentState = ActionState.Idle;
    private DateTime _actionTimestamp;
    private int _countdownValue = 3;
    private double _lastCountdownUpdate = 0;

    // Captured packets around action
    private List<CapturedAction> _capturedPackets = new();
    private List<CorrelatedOpcode> _correlatedOpcodes = new();

    // FIX: Pre-capture ring buffer -- keeps last 50 packets before action trigger
    private readonly Queue<CapturedAction> _preBuffer = new();
    private const int PRE_BUFFER_CAPACITY = 50;

    // Settings
    private float _captureWindowSeconds = 3.0f;
    private int _minOccurrences = 2;
    private bool _showOnlyC2S = true;

    // Results
    private string _selectedOpcode = "";
    private string _exportText = "";

    public ActionCorrelatorTab(AppState state)
    {
        _state = state;
        _state.OnPacketReceived += OnPacketReceived;
    }

    private void OnPacketReceived(CapturedPacket packet)
    {
        // Always buffer recent packets as pre-action context
        var preEntry = new CapturedAction
        {
            Packet = packet,
            TimeBeforeAction = 0, // corrected when trigger fires
            IsYourAction = false
        };
        _preBuffer.Enqueue(preEntry);
        while (_preBuffer.Count > PRE_BUFFER_CAPACITY) _preBuffer.Dequeue();

        if (_currentState != ActionState.Capturing) return;

        // FIX: positive = AFTER trigger, negative = BEFORE trigger
        var timeSinceAction = (DateTime.Now - _actionTimestamp).TotalSeconds;
        if (timeSinceAction > _captureWindowSeconds) return;

        _capturedPackets.Add(new CapturedAction
        {
            Packet = packet,
            TimeBeforeAction = timeSinceAction, // FIX: was -timeSinceAction (inverted)
            IsYourAction = true
        });
    }

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();

        ImGui.Spacing();
        ImGui.Text("  ACTION CORRELATOR  -  Identify Your Packets");
        ImGui.Separator();
        ImGui.Spacing();

        // State machine
        switch (_currentState)
        {
            case ActionState.Idle:
                RenderIdleState();
                break;
            case ActionState.Countdown:
                RenderCountdownState();
                break;
            case ActionState.Capturing:
                RenderCapturingState();
                break;
            case ActionState.Analyzing:
                RenderAnalyzingState(avail);
                break;
        }
    }

    private void RenderIdleState()
    {
        ImGui.TextColored(Theme.ColAccent, "How it works:");
        ImGui.BulletText("Click 'Start Action Capture' below");
        ImGui.BulletText("3-second countdown will begin");
        ImGui.BulletText("Perform your action in-game (jump, attack, etc.)");
        ImGui.BulletText("Tool captures packets +/-3 seconds around action");
        ImGui.BulletText("Analyzes timing to identify your specific packets");

        ImGui.Spacing();
        ImGui.Separator();
        ImGui.Spacing();

        // Settings
        ImGui.TextColored(Theme.ColAccent, "Settings:");
        ImGui.SliderFloat("Capture Window (seconds)", ref _captureWindowSeconds, 1.0f, 10.0f);
        ImGui.InputInt("Min Occurrences", ref _minOccurrences);
        _minOccurrences = Math.Max(1, _minOccurrences);
        ImGui.Checkbox("Show only C2S (Client->Server)", ref _showOnlyC2S);

        ImGui.Spacing();

        ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.2f, 0.8f, 0.4f, 1f));
        if (ImGui.Button("  START ACTION CAPTURE  ", new Vector2(200, 40)))
        {
            StartCapture();
        }
        ImGui.PopStyleColor();

        ImGui.SameLine();

        if (ImGui.Button("Reset Data", new Vector2(120, 40)))
        {
            ResetData();
        }

        // Show previous results if available
        if (_correlatedOpcodes.Count > 0)
        {
            ImGui.Spacing();
            ImGui.Separator();
            ImGui.TextColored(Theme.ColAccent, "Previous Results:");
            RenderOpcodeList();
        }
    }

    private void RenderCountdownState()
    {
        // Update countdown
        if (ImGui.GetTime() - _lastCountdownUpdate >= 1.0)
        {
            _countdownValue--;
            _lastCountdownUpdate = ImGui.GetTime();

            if (_countdownValue <= 0)
            {
                StartCapturing();
            }
        }

        ImGui.TextColored(Theme.ColWarn, "GET READY!");
        ImGui.Spacing();

        // Big countdown display
        var windowWidth = ImGui.GetWindowWidth();
        var textSize = ImGui.CalcTextSize(_countdownValue.ToString());
        ImGui.SetCursorPosX((windowWidth - textSize.X) * 0.5f);

        ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(1, 0.3f, 0.3f, 1));
        ImGui.SetWindowFontScale(4.0f);
        ImGui.Text(_countdownValue.ToString());
        ImGui.SetWindowFontScale(1.0f);
        ImGui.PopStyleColor();

        ImGui.Spacing();
        ImGui.TextColored(Theme.ColTextMuted, "Perform your action when countdown reaches 0!");

        if (ImGui.Button("Cancel", new Vector2(100, 30)))
        {
            CancelCapture();
        }
    }

    private void RenderCapturingState()
    {
        var elapsed = (DateTime.Now - _actionTimestamp).TotalSeconds;
        var remaining = Math.Max(0, _captureWindowSeconds - elapsed);

        ImGui.TextColored(Theme.ColSuccess, "CAPTURING!");
        ImGui.Spacing();

        ImGui.Text($"Time remaining: {remaining:F1}s");
        ImGui.ProgressBar((float)(elapsed / _captureWindowSeconds), new Vector2(-1, 20));

        ImGui.Text($"Packets captured: {_capturedPackets.Count}");

        if (remaining <= 0)
        {
            StartAnalysis();
        }

        if (ImGui.Button("Stop Early", new Vector2(100, 30)))
        {
            StartAnalysis();
        }
    }

    private void RenderAnalyzingState(Vector2 avail)
    {
        ImGui.TextColored(Theme.ColAccent, "ANALYSIS RESULTS");
        ImGui.Separator();

        // Summary stats
        ImGui.Text($"Total packets captured: {_capturedPackets.Count}");
        ImGui.Text($"Unique opcodes: {_capturedPackets.Select(p => p.Packet.Opcode).Distinct().Count()}");

        ImGui.Spacing();

        // Two column layout
        float leftWidth = avail.X * 0.5f - 8;
        float rightWidth = avail.X * 0.5f - 8;

        ImGui.BeginChild("##opcode_list", new Vector2(leftWidth, avail.Y - 150), ImGuiChildFlags.Borders);
        RenderOpcodeList();
        ImGui.EndChild();

        ImGui.SameLine();

        ImGui.BeginChild("##opcode_details", new Vector2(rightWidth, avail.Y - 150), ImGuiChildFlags.Borders);
        RenderOpcodeDetails();
        ImGui.EndChild();

        // Bottom buttons
        ImGui.Spacing();
        if (ImGui.Button("New Capture", new Vector2(120, 30)))
        {
            ResetData();
            _currentState = ActionState.Idle;
        }

        ImGui.SameLine();

        if (ImGui.Button("Export Results", new Vector2(120, 30)))
        {
            ExportResults();
        }

        ImGui.SameLine();

        if (ImGui.Button("Copy C# Code", new Vector2(120, 30)))
        {
            CopyCSharpCode();
        }
    }

    private void RenderOpcodeList()
    {
        ImGui.TextColored(Theme.ColAccent, "Correlated Opcodes (Likely Yours)");
        ImGui.Separator();

        if (_correlatedOpcodes.Count == 0)
        {
            ImGui.TextColored(Theme.ColTextMuted, "No opcodes found. Try again with different action.");
            return;
        }

        // Sort by correlation score
        var sorted = _correlatedOpcodes
            .Where(o => !_showOnlyC2S || o.IsC2S)
            .OrderByDescending(o => o.CorrelationScore)
            .ToList();

        ImGui.BeginTable("##opcodes", 4, ImGuiTableFlags.RowBg | ImGuiTableFlags.BordersInnerH | ImGuiTableFlags.ScrollY);

        ImGui.TableSetupColumn("Opcode", ImGuiTableColumnFlags.WidthFixed, 70);
        ImGui.TableSetupColumn("Name", ImGuiTableColumnFlags.WidthStretch);
        ImGui.TableSetupColumn("Timing", ImGuiTableColumnFlags.WidthFixed, 80);
        ImGui.TableSetupColumn("Score", ImGuiTableColumnFlags.WidthFixed, 60);
        ImGui.TableHeadersRow();

        foreach (var opcode in sorted)
        {
            ImGui.TableNextRow();

            bool isSelected = _selectedOpcode == opcode.OpcodeHex;

            if (isSelected)
            {
                ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg0,
                    ImGui.ColorConvertFloat4ToU32(new Vector4(0.2f, 0.5f, 0.8f, 0.3f)));
            }

            ImGui.TableSetColumnIndex(0);
            if (ImGui.Selectable(opcode.OpcodeHex, isSelected, ImGuiSelectableFlags.SpanAllColumns))
            {
                _selectedOpcode = opcode.OpcodeHex;
                GenerateExportText(opcode);
            }

            ImGui.TableSetColumnIndex(1);
            ImGui.Text(opcode.OpcodeName);

            ImGui.TableSetColumnIndex(2);
            var timingColor = opcode.AvgTimingMs < 0 ? Theme.ColSuccess : Theme.ColWarn;
            ImGui.TextColored(timingColor, $"{opcode.AvgTimingMs:F0}ms");

            ImGui.TableSetColumnIndex(3);
            var scoreColor = opcode.CorrelationScore > 0.8f ? Theme.ColSuccess :
                            opcode.CorrelationScore > 0.5f ? Theme.ColWarn : Theme.ColTextMuted;
            ImGui.TextColored(scoreColor, $"{opcode.CorrelationScore:P0}");
        }

        ImGui.EndTable();
    }

    private void RenderOpcodeDetails()
    {
        if (string.IsNullOrEmpty(_selectedOpcode))
        {
            ImGui.TextColored(Theme.ColTextMuted, "Select an opcode to view details");
            return;
        }

        var opcode = _correlatedOpcodes.FirstOrDefault(o => o.OpcodeHex == _selectedOpcode);
        if (opcode == null) return;

        ImGui.TextColored(Theme.ColAccent, $"Opcode: {opcode.OpcodeHex}");
        ImGui.Text($"Name: {opcode.OpcodeName}");
        ImGui.Text($"Direction: {(opcode.IsC2S ? "Client->Server" : "Server->Client")}");
        ImGui.Text($"Occurrences: {opcode.Occurrences}");
        ImGui.Text($"Average timing: {opcode.AvgTimingMs:F2}ms from action");
        ImGui.Text($"Correlation score: {opcode.CorrelationScore:P2}");

        ImGui.Separator();

        ImGui.TextColored(Theme.ColAccent, "Timing Distribution:");
        foreach (var timing in opcode.TimingDistribution.OrderBy(t => t.Key))
        {
            ImGui.Text($"  {timing.Key:F0}ms: {timing.Value} packets");
        }

        ImGui.Separator();

        if (!string.IsNullOrEmpty(_exportText))
        {
            ImGui.TextColored(Theme.ColAccent, "Export:");
            ImGui.InputTextMultiline("##export", ref _exportText, 1000, new Vector2(-1, 100),
                ImGuiInputTextFlags.ReadOnly);
        }
    }

    private void StartCapture()
    {
        _countdownValue = 3;
        _lastCountdownUpdate = ImGui.GetTime();
        _currentState = ActionState.Countdown;
        _state.AddInGameLog("[ACTION] Countdown started...");
    }

    private void StartCapturing()
    {
        _actionTimestamp = DateTime.Now;
        _capturedPackets.Clear();

        // Flush pre-buffer: assign correct negative timestamps (before trigger)
        foreach (var pre in _preBuffer)
        {
            pre.TimeBeforeAction = (pre.Packet.Timestamp - _actionTimestamp).TotalSeconds;
            _capturedPackets.Add(pre);
        }
        _preBuffer.Clear();

        _currentState = ActionState.Capturing;
        _state.AddInGameLog($"[ACTION] CAPTURING! Pre-buffered {_capturedPackets.Count} context packets. Perform your action now!");
    }

    /// <summary>Called by GlobalHotkeys (F8) -- triggers a 3-second capture immediately.</summary>
    public void TriggerCapture()
    {
        if (_currentState != ActionState.Idle) return;
        StartCapturing();
    }

    private void StartAnalysis()
    {
        _currentState = ActionState.Analyzing;
        AnalyzeCapturedPackets();
        _state.AddInGameLog($"[ACTION] Analysis complete. Found {_correlatedOpcodes.Count} correlated opcodes.");
    }

    private void CancelCapture()
    {
        _currentState = ActionState.Idle;
        _capturedPackets.Clear();
        _state.AddInGameLog("[ACTION] Capture cancelled.");
    }

    private void ResetData()
    {
        _capturedPackets.Clear();
        _correlatedOpcodes.Clear();
        _selectedOpcode = "";
        _exportText = "";
        _currentState = ActionState.Idle;
    }

    private void AnalyzeCapturedPackets()
    {
        _correlatedOpcodes.Clear();

        // Group by opcode
        var grouped = _capturedPackets
            .GroupBy(p => new { p.Packet.Opcode, p.Packet.Direction })
            .ToList();

        foreach (var group in grouped)
        {
            var packets = group.ToList();
            if (packets.Count < _minOccurrences) continue;

            var timings = packets.Select(p => p.TimeBeforeAction * 1000).ToList(); // Convert to ms
            var avgTiming = timings.Average();

            // Calculate correlation score based on:
            // 1. Timing consistency (lower variance = higher score)
            // 2. Proximity to action (closer to 0 = higher score)
            // 3. Direction (C2S more likely to be your action)

            double variance = timings.Count > 1 ?
                timings.Select(t => Math.Pow(t - avgTiming, 2)).Average() : 0;
            double stdDev = Math.Sqrt(variance);

            double timingScore = Math.Max(0, 1.0 - (Math.Abs(avgTiming) / 1000.0)); // Closer to 0 = better
            double consistencyScore = Math.Max(0, 1.0 - (stdDev / 500.0)); // Lower variance = better
            double directionScore = group.Key.Direction == PacketDirection.ClientToServer ? 1.0 : 0.5;

            double correlationScore = (timingScore * 0.4 + consistencyScore * 0.4 + directionScore * 0.2);

            // Build timing distribution
            var distribution = new Dictionary<double, int>();
            foreach (var t in timings)
            {
                var bucket = Math.Round(t / 100) * 100; // Round to nearest 100ms
                distribution[bucket] = distribution.GetValueOrDefault(bucket) + 1;
            }

            var info = OpcodeRegistry.GetInfo(group.Key.Opcode, group.Key.Direction);

            _correlatedOpcodes.Add(new CorrelatedOpcode
            {
                OpcodeHex = $"0x{group.Key.Opcode:X4}",
                OpcodeName = info?.Name ?? "Unknown",
                IsC2S = group.Key.Direction == PacketDirection.ClientToServer,
                Occurrences = packets.Count,
                AvgTimingMs = avgTiming,
                CorrelationScore = correlationScore,
                TimingDistribution = distribution,
                SamplePacket = packets.First().Packet
            });
        }

        // Auto-select highest correlation
        if (_correlatedOpcodes.Count > 0)
        {
            _selectedOpcode = _correlatedOpcodes.OrderByDescending(o => o.CorrelationScore).First().OpcodeHex;
            GenerateExportText(_correlatedOpcodes.First());
        }
    }

    private void GenerateExportText(CorrelatedOpcode opcode)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"// Action Correlator Result");
        sb.AppendLine($"// Opcode: {opcode.OpcodeHex}");
        sb.AppendLine($"// Name: {opcode.OpcodeName}");
        sb.AppendLine($"// Direction: {(opcode.IsC2S ? "C2S" : "S2C")}");
        sb.AppendLine($"// Correlation: {opcode.CorrelationScore:P2}");
        sb.AppendLine($"// Average timing: {opcode.AvgTimingMs:F2}ms from action");
        sb.AppendLine();
        sb.AppendLine($"public const ushort {SanitizeName(opcode.OpcodeName)} = {opcode.OpcodeHex};");

        _exportText = sb.ToString();
    }

    private void ExportResults()
    {
        try
        {
            var sb = new System.Text.StringBuilder();
            sb.AppendLine("=== HYFORCE ACTION CORRELATOR RESULTS ===");
            sb.AppendLine($"Export Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"Capture Window: {_captureWindowSeconds}s");
            sb.AppendLine($"Total Packets: {_capturedPackets.Count}");
            sb.AppendLine();

            sb.AppendLine("=== CORRELATED OPCODES ===");
            sb.AppendLine();

            foreach (var opcode in _correlatedOpcodes.OrderByDescending(o => o.CorrelationScore))
            {
                sb.AppendLine($"Opcode: {opcode.OpcodeHex}");
                sb.AppendLine($"  Name: {opcode.OpcodeName}");
                sb.AppendLine($"  Direction: {(opcode.IsC2S ? "Client->Server" : "Server->Client")}");
                sb.AppendLine($"  Occurrences: {opcode.Occurrences}");
                sb.AppendLine($"  Avg Timing: {opcode.AvgTimingMs:F2}ms");
                sb.AppendLine($"  Correlation Score: {opcode.CorrelationScore:P2}");
                sb.AppendLine();
            }

            sb.AppendLine("=== RAW CAPTURED PACKETS ===");
            sb.AppendLine();

            foreach (var cap in _capturedPackets.OrderBy(p => p.TimeBeforeAction))
            {
                sb.AppendLine($"[{cap.TimeBeforeAction * 1000:F0}ms] {cap.Packet.Direction} 0x{cap.Packet.Opcode:X4} ({cap.Packet.RawBytes.Length} bytes)");
            }

            string filename = System.IO.Path.Combine(_state.ExportDirectory,
                $"action_correlator_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
            System.IO.File.WriteAllText(filename, sb.ToString());

            _state.AddInGameLog($"[ACTION] Results exported to {System.IO.Path.GetFileName(filename)}");
        }
        catch (Exception ex)
        {
            _state.AddInGameLog($"[ACTION] Export failed: {ex.Message}");
        }
    }

    private void CopyCSharpCode()
    {
        if (!string.IsNullOrEmpty(_exportText))
        {
            try
            {
                TextCopy.ClipboardService.SetText(_exportText);
                _state.AddInGameLog("[ACTION] C# code copied to clipboard!");
            }
            catch { }
        }
    }

    private string SanitizeName(string name)
    {
        return name.Replace(" ", "_").Replace("-", "_").Replace(".", "_");
    }

    // Data structures
    private class CapturedAction
    {
        public CapturedPacket Packet { get; set; } = null!;
        public double TimeBeforeAction { get; set; } // Negative = before action, positive = after
        public bool IsYourAction { get; set; }
    }

    private class CorrelatedOpcode
    {
        public string OpcodeHex { get; set; } = "";
        public string OpcodeName { get; set; } = "";
        public bool IsC2S { get; set; }
        public int Occurrences { get; set; }
        public double AvgTimingMs { get; set; }
        public double CorrelationScore { get; set; }
        public Dictionary<double, int> TimingDistribution { get; set; } = new();
        public CapturedPacket SamplePacket { get; set; } = null!;
    }
}