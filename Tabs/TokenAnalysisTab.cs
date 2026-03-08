// Tabs/TokenAnalysisTab.cs  v19
using HyForce.Core;
using HyForce.Networking;
using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;

namespace HyForce.Tabs;

public class TokenAnalysisTab : ITab
{
    public string Name => "Token Analysis";

    private readonly AppState          _state;
    private readonly PipeCaptureServer _pipe;
    private readonly TokenAnalyzer     _analyzer;
    private readonly SessionCapture    _session;

    private int    _selectedHistIdx = -1;
    private bool   _logScroll       = true;
    private readonly List<string> _log = new();

    public TokenAnalysisTab(AppState state, PipeCaptureServer pipe)
    {
        _state    = state;
        _pipe     = pipe;
        _analyzer = state.TokenAnalyzer;
        _session  = state.SessionCapture;
        _analyzer.OnLog += line => { lock(_log) { _log.Add(line); if(_log.Count>500) _log.RemoveAt(0); } };
    }

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();
        float leftW = 280f;

        ImGui.TextDisabled("Decodes and diffs AuthToken (0x02) + ConnectAccept (0x03) session tokens.");
        ImGui.TextDisabled("Detects: UUID, HMAC-SHA256, JWT, timestamp+nonce, cross-session reuse.");
        ImGui.Separator();

        ImGui.BeginChild("ta_left", new Vector2(leftW, avail.Y-4), ImGuiChildFlags.Borders);
        {
            ImGui.TextColored(new Vector4(0.4f,0.85f,1f,1f), "TOKEN HISTORY");
            ImGui.TextDisabled($"{_analyzer.History.Count} tokens analyzed");
            ImGui.Spacing();

            ImGui.BeginChild("ta_hist", new Vector2(-1,200), ImGuiChildFlags.Borders);
            for (int i = 0; i < _analyzer.History.Count; i++)
            {
                var ta = _analyzer.History[i];
                bool sel = _selectedHistIdx == i;
                Vector4 col = ta.IsReuse ? new(1f,0.4f,0.4f,1f) : new(0.85f,0.9f,1f,1f);
                ImGui.PushStyleColor(ImGuiCol.Text, col);
                if (ImGui.Selectable($"[{ta.CapturedAt:HH:mm:ss}] {ta.Description}##tahi{i}", sel))
                    _selectedHistIdx = sel ? -1 : i;
                ImGui.PopStyleColor();
            }
            if (_analyzer.History.Count == 0) ImGui.TextDisabled("  (connect to server to capture)");
            ImGui.EndChild();

            if (ImGui.SmallButton("Clear History##tacl")) { _analyzer.Clear(); _selectedHistIdx=-1; }

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

            // Current session info
            var snap = _session.Current;
            ImGui.TextColored(new Vector4(0.3f,1f,0.5f,1f), "SESSION TOKENS");
            if (snap == null)
            {
                ImGui.TextDisabled("  No session captured yet.");
            }
            else
            {
                ImGui.TextDisabled($"Auth:    {snap.RawAuthToken.Length}B");
                ImGui.SameLine();
                if (ImGui.SmallButton("Re-analyze##tara") && snap.RawAuthToken.Length > 0)
                    _analyzer.Analyze(snap.RawAuthToken, "AuthToken (manual)");

                ImGui.TextDisabled($"Connect: {snap.RawConnectAccept.Length}B");
                ImGui.SameLine();
                if (ImGui.SmallButton("Re-analyze##tarca") && snap.RawConnectAccept.Length > 0)
                    _analyzer.Analyze(snap.RawConnectAccept, "ConnectAccept (manual)");
            }

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

            // Replay actions
            ImGui.TextColored(new Vector4(1f,0.75f,0.3f,1f), "REPLAY ACTIONS");
            if (_selectedHistIdx >= 0 && _selectedHistIdx < _analyzer.History.Count)
            {
                var sel = _analyzer.History[_selectedHistIdx];
                ImGui.TextDisabled($"Selected: {sel.Description}  {sel.Raw.Length}B");

                if (ImGui.Button("Replay Exact (ConnectAccept)##tarep", new Vector2(-1,0)))
                {
                    _pipe.ReplaySetup(sel.Raw);
                    AddLog($"[REPLAY] Exact token replayed {sel.Raw.Length}B");
                }

                if (sel.HasTimestamp)
                {
                    if (ImGui.Button("Replay with Fresh Timestamp##tarts", new Vector2(-1,0)))
                    {
                        byte[]? patched = _analyzer.BuildReplayWithFreshTimestamp(sel);
                        if (patched != null)
                        {
                            _pipe.ReplaySetup(patched);
                            AddLog($"[REPLAY] Fresh-timestamp replay {patched.Length}B");
                        }
                    }
                }

                if (sel.IsReuse)
                    ImGui.TextColored(new Vector4(1f,0.4f,0.4f,1f), "⚠ Reuse detected — server may reject");
            }
            else
                ImGui.TextDisabled("Select a token from history.");
        }
        ImGui.EndChild();

        ImGui.SameLine();

        float rightW = avail.X - leftW - 8;
        ImGui.BeginChild("ta_right", new Vector2(rightW, avail.Y-4), ImGuiChildFlags.None);
        {
            if (ImGui.BeginTabBar("ta_right_tabs"))
            {
                if (ImGui.BeginTabItem("Analysis##taan"))
                {
                    RenderAnalysis(avail.Y-50);
                    ImGui.EndTabItem();
                }
                if (ImGui.BeginTabItem("Diff##tadiff"))
                {
                    RenderDiff(avail.Y-50);
                    ImGui.EndTabItem();
                }
                if (ImGui.BeginTabItem("Log##talog"))
                {
                    RenderLog(avail.Y-50);
                    ImGui.EndTabItem();
                }
                ImGui.EndTabBar();
            }
        }
        ImGui.EndChild();
    }

    private void RenderAnalysis(float h)
    {
        if (_selectedHistIdx < 0 || _selectedHistIdx >= _analyzer.History.Count)
        { ImGui.TextDisabled("Select a token on the left."); return; }

        var ta = _analyzer.History[_selectedHistIdx];
        ImGui.TextColored(new Vector4(0.4f,0.85f,1f,1f), ta.Description);
        ImGui.TextDisabled($"Captured: {ta.CapturedAt:HH:mm:ss.fff}  Length: {ta.Raw.Length}B");
        if (ta.IsReuse) ImGui.TextColored(new Vector4(1f,0.4f,0.4f,1f), "⚠ IDENTICAL TOKEN seen in a previous session");
        ImGui.Separator();

        // Notes
        ImGui.Text("Analysis:");
        foreach(var note in ta.Notes)
            ImGui.TextWrapped("  • " + note);

        ImGui.Spacing(); ImGui.Separator();
        ImGui.Text("Hex dump:");
        ImGui.BeginChild("ta_hex", new Vector2(-1, h/2-80), ImGuiChildFlags.Borders);
        // 16 bytes per line
        for (int i = 0; i < ta.Raw.Length; i += 16)
        {
            int end = Math.Min(i+16, ta.Raw.Length);
            string hex = BitConverter.ToString(ta.Raw, i, end-i).Replace("-"," ");
            string asc = new string(ta.Raw.Skip(i).Take(end-i)
                .Select(b => b>=0x20&&b<0x7F ? (char)b : '.').ToArray());
            ImGui.TextDisabled($"{i:X4}  ");
            ImGui.SameLine(); ImGui.TextUnformatted(hex.PadRight(47));
            ImGui.SameLine(); ImGui.TextDisabled(" | " + asc);
        }
        ImGui.EndChild();
    }

    private void RenderDiff(float h)
    {
        ImGui.TextDisabled("Select two tokens from history to diff byte-by-byte.");
        if (_analyzer.History.Count < 2) { ImGui.TextDisabled("Need at least 2 tokens."); return; }

        var t1 = _analyzer.History.Count >= 2 ? _analyzer.History[^2] : null;
        var t2 = _analyzer.History.Count >= 1 ? _analyzer.History[^1] : null;

        if (t1 == null || t2 == null) return;

        ImGui.TextDisabled($"Comparing: [{t1.CapturedAt:HH:mm:ss}] vs [{t2.CapturedAt:HH:mm:ss}]");
        ImGui.Separator();

        int maxLen = Math.Max(t1.Raw.Length, t2.Raw.Length);
        int diffs  = 0;
        ImGui.BeginChild("ta_diff", new Vector2(-1, h-80), ImGuiChildFlags.Borders);
        for (int i = 0; i < maxLen; i += 4)
        {
            int end = Math.Min(i+4, maxLen);
            bool hasDiff = false;
            for (int j = i; j < end; j++)
            {
                byte b1 = j < t1.Raw.Length ? t1.Raw[j] : (byte)0;
                byte b2 = j < t2.Raw.Length ? t2.Raw[j] : (byte)0;
                if (b1 != b2) { hasDiff = true; diffs++; }
            }
            Vector4 col = hasDiff ? new(1f,0.5f,0.5f,1f) : new(0.5f,0.5f,0.5f,1f);
            string s1 = string.Join(" ", Enumerable.Range(i,end-i).Select(j => j<t1.Raw.Length ? t1.Raw[j].ToString("X2") : "--"));
            string s2 = string.Join(" ", Enumerable.Range(i,end-i).Select(j => j<t2.Raw.Length ? t2.Raw[j].ToString("X2") : "--"));
            ImGui.TextColored(col, $"{i:X4}  {s1,-12}  {s2,-12}  {(hasDiff?"DIFF":"")}");
        }
        ImGui.EndChild();
        ImGui.TextDisabled($"Total differing offsets: {diffs}/{maxLen}");
    }

    private void RenderLog(float h)
    {
        ImGui.Checkbox("Auto-scroll##talsc", ref _logScroll);
        ImGui.SameLine(); if (ImGui.SmallButton("Clear##talcl")) lock(_log) _log.Clear();
        ImGui.Separator();
        ImGui.BeginChild("ta_log_ch", new Vector2(-1, h-60), ImGuiChildFlags.Borders);
        List<string> snap; lock(_log) snap=_log.ToList();
        foreach(var line in snap) ImGui.TextUnformatted(line);
        if(_logScroll && ImGui.GetScrollY()>=ImGui.GetScrollMaxY()-5) ImGui.SetScrollHereY(1f);
        ImGui.EndChild();
    }

    private void AddLog(string msg)
    {
        var line = $"[{DateTime.Now:HH:mm:ss.fff}] {msg}";
        lock(_log) { _log.Add(line); if(_log.Count>500) _log.RemoveAt(0); }
    }
}
