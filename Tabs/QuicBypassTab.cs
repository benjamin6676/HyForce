// FILE: Tabs/QuicBypassTab.cs
// v16 — msquic plaintext bypass UI
// Shows all decrypted stream payloads (pre/post-app delivery) and exposes
// full packet testing controls: inject, race delay, fuzz, duplicate, drop, replay.

using HyForce.Core;
using HyForce.Networking;
using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;

namespace HyForce.Tabs;

public class QuicBypassTab : ITab
{
    public string Name => "QUIC Bypass";

    private readonly AppState          _state;
    private readonly PipeCaptureServer _pipe;

    // ── Stream feed ──────────────────────────────────────────────────────────
    private readonly List<QuicStreamEntry> _feed = new();
    private bool   _autoScroll    = true;
    private string _filter        = "";
    private bool   _showAscii     = false;
    private bool   _pauseFeed     = false;
    private int    _maxFeed       = 500;
    private int    _selectedIdx   = -1;

    // ── Probe / status ───────────────────────────────────────────────────────
    private string _probeStatus = "Not probed yet";

    // ── Inject ───────────────────────────────────────────────────────────────
    private string _injectHex = "0102030405060708";
    private string _injectStatus = "";

    // ── Race delay ───────────────────────────────────────────────────────────
    private int  _raceDelayMs   = 0;
    private bool _raceActive    = false;

    // ── Fuzz ─────────────────────────────────────────────────────────────────
    private int  _fuzzBits      = 0;
    private bool _fuzzActive    = false;

    // ── Duplicate ────────────────────────────────────────────────────────────
    private int  _dupCount      = 1;

    // ── Stats ────────────────────────────────────────────────────────────────
    private int  _totalSeen     = 0;
    private int  _totalBytes    = 0;
    private readonly Dictionary<string, int> _streamStats = new();

    public QuicBypassTab(AppState state, PipeCaptureServer pipe)
    {
        _state = state;
        _pipe  = pipe;
        _pipe.OnQuicStream += OnStream;
    }

    private void OnStream(QuicStreamEntry entry)
    {
        if (_pauseFeed) return;
        lock (_feed)
        {
            _feed.Add(entry);
            if (_feed.Count > _maxFeed) _feed.RemoveAt(0);
        }
        _totalSeen++;
        _totalBytes += entry.Data.Length;
        string key = $"0x{entry.StreamHandle:X}";
        if (!_streamStats.ContainsKey(key)) _streamStats[key] = 0;
        _streamStats[key]++;
    }

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();

        // ── Status bar ──────────────────────────────────────────────────────
        bool hooked = _pipe.DllConnected;
        ImGui.TextColored(hooked ? new Vector4(0.2f, 1f, 0.4f, 1f) : new Vector4(1f, 0.5f, 0.2f, 1f),
            hooked ? "● DLL Connected" : "○ DLL Not Connected");
        ImGui.SameLine(0, 20);
        ImGui.TextColored(new Vector4(0.7f, 0.7f, 0.7f, 1f),
            $"Streams seen: {_totalSeen}  |  Bytes: {_totalBytes:N0}  |  Active streams: {_streamStats.Count}");
        ImGui.SameLine();
        ImGui.TextColored(new Vector4(0.5f, 0.8f, 1f, 1f), _probeStatus);

        ImGui.Separator();

        // ── Left panel: controls ─────────────────────────────────────────────
        float leftW = 300f;
        ImGui.BeginChild("quic_controls", new Vector2(leftW, avail.Y - 4), ImGuiChildFlags.Borders);
        {
            // Probe
            ImGui.TextColored(new Vector4(1f, 0.85f, 0.2f, 1f), "HOOK SETUP");
            if (ImGui.Button("Probe msquic.dll", new Vector2(-1, 0)))
            {
                _pipe.QuicProbe();
                _probeStatus = "Probing...";
            }
            if (ImGui.Button("List Active Streams", new Vector2(-1, 0)))
                _pipe.QuicListStreams();

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

            // Inject
            ImGui.TextColored(new Vector4(1f, 0.5f, 0.2f, 1f), "INJECT");
            ImGui.SetNextItemWidth(-1);
            ImGui.InputText("##hex", ref _injectHex, 16384);
            ImGui.TextDisabled("Hex bytes, no spaces (e.g. deadbeef)");
            if (ImGui.Button("Inject on New Stream", new Vector2(-1, 0)))
            {
                try
                {
                    byte[] data = HexToBytes(_injectHex);
                    _pipe.QuicInject(data);
                    _injectStatus = $"Injected {data.Length}B";
                }
                catch (Exception ex) { _injectStatus = $"Error: {ex.Message}"; }
            }
            if (ImGui.Button("Replay Last Captured", new Vector2(-1, 0)))
                _pipe.QuicReplayStream();
            if (!string.IsNullOrEmpty(_injectStatus))
                ImGui.TextColored(new Vector4(0.5f, 1f, 0.5f, 1f), _injectStatus);

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

            // Race delay
            ImGui.TextColored(new Vector4(0.8f, 0.4f, 1f, 1f), "RACE CONDITIONS");
            ImGui.SetNextItemWidth(-1);
            ImGui.SliderInt("Delay (ms)##race", ref _raceDelayMs, 0, 5000);
            ImGui.TextDisabled("Holds RECEIVE in callback — real TCP backpressure");
            if (ImGui.Button(_raceActive ? "Race: ON  [click off]" : "Race: OFF [click on]", new Vector2(-1, 0)))
            {
                _raceActive = !_raceActive;
                _pipe.QuicSetRaceDelay(_raceActive ? _raceDelayMs : 0);
            }
            if (_raceActive)
                ImGui.TextColored(new Vector4(1f, 0.3f, 0.3f, 1f), $"  Active — {_raceDelayMs}ms delay");

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

            // Fuzz
            ImGui.TextColored(new Vector4(1f, 0.3f, 0.5f, 1f), "STREAM FUZZ");
            ImGui.SetNextItemWidth(-1);
            ImGui.SliderInt("Bit flips##fuzz", ref _fuzzBits, 0, 32);
            ImGui.TextDisabled("Mutates RX data before app sees it");
            if (ImGui.Button(_fuzzActive ? "Fuzz: ON  [click off]" : "Fuzz: OFF [click on]", new Vector2(-1, 0)))
            {
                _fuzzActive = !_fuzzActive;
                _pipe.QuicFuzzStream(_fuzzActive ? _fuzzBits : 0);
            }
            if (_fuzzActive)
                ImGui.TextColored(new Vector4(1f, 0.3f, 0.3f, 1f), $"  Active — {_fuzzBits} bit-flips/packet");

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

            // Duplicate / Drop
            ImGui.TextColored(new Vector4(0.3f, 0.8f, 1f, 1f), "DUPLICATE / DROP");
            ImGui.SetNextItemWidth(-1);
            ImGui.SliderInt("Dup count##dup", ref _dupCount, 1, 8);
            ImGui.TextDisabled("Replays RX event N extra times to app");
            if (ImGui.Button("Duplicate Next RX", new Vector2(-1, 0)))
                _pipe.QuicDuplicate(_dupCount);
            if (ImGui.Button("Drop Next RX", new Vector2(-1, 0)))
                _pipe.QuicDropNext();

            ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

            // Stream stats
            ImGui.TextColored(new Vector4(0.7f, 0.7f, 0.7f, 1f), "STREAM STATS");
            foreach (var kv in _streamStats.OrderByDescending(x => x.Value).Take(12))
                ImGui.Text($"  {kv.Key,-20} {kv.Value,6} pkts");
            if (ImGui.Button("Clear Stats", new Vector2(-1, 0)))
            {
                _streamStats.Clear(); _totalSeen = 0; _totalBytes = 0;
            }
        }
        ImGui.EndChild();

        ImGui.SameLine();

        // ── Right panel: stream feed ─────────────────────────────────────────
        ImGui.BeginChild("quic_feed", new Vector2(avail.X - leftW - 8, avail.Y - 4), ImGuiChildFlags.Borders);
        {
            // Toolbar
            ImGui.Checkbox("Auto-scroll", ref _autoScroll); ImGui.SameLine();
            ImGui.Checkbox("ASCII preview", ref _showAscii); ImGui.SameLine();
            ImGui.Checkbox("Pause", ref _pauseFeed); ImGui.SameLine();
            ImGui.SetNextItemWidth(200);
            ImGui.InputText("Filter##feed", ref _filter, 128); ImGui.SameLine();
            if (ImGui.Button("Clear Feed"))
            {
                lock (_feed) _feed.Clear();
                _selectedIdx = -1;
            }
            ImGui.Separator();

            float feedH = _selectedIdx >= 0 ? (avail.Y - 200) : (avail.Y - 50);
            ImGui.BeginChild("feed_list", new Vector2(-1, feedH - 40), ImGuiChildFlags.None);
            {
                List<QuicStreamEntry> snapshot;
                lock (_feed) snapshot = _feed.ToList();

                string fl = _filter.ToLower();
                for (int i = 0; i < snapshot.Count; i++)
                {
                    var e = snapshot[i];
                    string line = $"{e.Timestamp:HH:mm:ss.fff}  {e.Direction,-6}  0x{e.StreamHandle:X14}  {e.Data.Length,6}B  {e.HexPreview}";
                    if (!string.IsNullOrEmpty(fl) && !line.ToLower().Contains(fl)) continue;

                    Vector4 col = e.Direction == "C→S"
                        ? new Vector4(0.9f, 0.7f, 0.3f, 1f)
                        : e.Direction.StartsWith("DUP")
                            ? new Vector4(0.6f, 0.4f, 1f, 1f)
                            : new Vector4(0.3f, 0.9f, 0.6f, 1f);

                    ImGui.PushStyleColor(ImGuiCol.Text, col);
                    if (ImGui.Selectable(line, _selectedIdx == i))
                        _selectedIdx = i;
                    ImGui.PopStyleColor();
                }
                if (_autoScroll && ImGui.GetScrollY() >= ImGui.GetScrollMaxY() - 5)
                    ImGui.SetScrollHereY(1f);
            }
            ImGui.EndChild();

            // ── Detail pane ─────────────────────────────────────────────────
            if (_selectedIdx >= 0)
            {
                List<QuicStreamEntry> snapshot;
                lock (_feed) snapshot = _feed.ToList();

                if (_selectedIdx < snapshot.Count)
                {
                    var e = snapshot[_selectedIdx];
                    ImGui.Separator();
                    ImGui.TextDisabled($"Stream 0x{e.StreamHandle:X}  |  {e.Direction}  |  {e.Data.Length} bytes  |  {e.Timestamp:HH:mm:ss.ffffff}");
                    ImGui.Spacing();

                    // Hex dump (16 bytes per row)
                    StringBuilder sb = new();
                    for (int row = 0; row < e.Data.Length; row += 16)
                    {
                        sb.Append($"  {row:X4}  ");
                        for (int col = 0; col < 16; col++)
                        {
                            if (row + col < e.Data.Length) sb.Append($"{e.Data[row + col]:X2} ");
                            else sb.Append("   ");
                            if (col == 7) sb.Append(' ');
                        }
                        sb.Append("  ");
                        for (int col = 0; col < 16 && row + col < e.Data.Length; col++)
                        {
                            byte b = e.Data[row + col];
                            sb.Append(b is >= 32 and < 127 ? (char)b : '.');
                        }
                        sb.AppendLine();
                    }
                    string hexDump = sb.ToString();
                    ImGui.InputTextMultiline("##hexdump", ref hexDump, (uint)(hexDump.Length + 4),
                        new Vector2(-1, 130), ImGuiInputTextFlags.ReadOnly);

                    ImGui.SameLine();
                    if (ImGui.Button("Reinject This##detail", new Vector2(120, 0)))
                        _pipe.QuicInject(e.Data);
                }
            }
        }
        ImGui.EndChild();
    }

    private static byte[] HexToBytes(string hex)
    {
        hex = hex.Replace(" ", "").Replace("-", "");
        if (hex.Length % 2 != 0) throw new ArgumentException("Odd hex length");
        byte[] result = new byte[hex.Length / 2];
        for (int i = 0; i < result.Length; i++)
            result[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return result;
    }
}
