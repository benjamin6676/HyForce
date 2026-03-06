using HyForce.Core;
using HyForce.Networking;
using ImGuiNET;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;

namespace HyForce.Tabs
{
    /// <summary>
    /// Protocol Lab — server-side security testing tools:
    ///   Fuzzer, Replay, Rate-limit prober, PCAP export,
    ///   Sequence tracker, Opcode map, RTT/timing graph
    /// </summary>
    public class ProtocolLabTab : ITab
    {
        public string Name => "Protocol Lab";

        private readonly AppState          _state;
        private readonly PipeCaptureServer _pipe;

        // ── Fuzzer ────────────────────────────────────────────────
        private int    _fuzzBits    = 4;
        private string _fuzzResult  = "";

        // ── Replay ────────────────────────────────────────────────
        private string _replayHex   = "";
        private string _replayStatus= "";

        // ── Rate-limit ────────────────────────────────────────────
        private int  _rlCount  = 100;
        private int  _rlMs     = 1000;
        private bool _rlRunning= false;

        // ── PCAP ──────────────────────────────────────────────────
        private string _pcapPath   = "";
        private bool   _pcapActive = false;

        // ── Opcode map ───────────────────────────────────────────
        private Dictionary<byte, int> _opcodeMap = new();
        private readonly object        _opLock    = new();
        private List<(byte op, int cnt)> _opcodeSorted = new();
        private DateTime _lastOpSort = DateTime.MinValue;

        // ── RTT graph ────────────────────────────────────────────
        private float[] _rttGraph  = new float[200];
        private int     _rttHead   = 0;
        private ulong   _lastSendUs= 0;

        // ── Seq anomaly log ───────────────────────────────────────
        private int _seqAnomalyCount = 0;

        public ProtocolLabTab(AppState state, PipeCaptureServer pipe)
        {
            _state = state;
            _pipe  = pipe;

            // Hook packet feed to build opcode map + RTT graph
            pipe.OnPacketReceived += OnPacket;

            // Default pcap path
            _pcapPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "HyForce", "Exports", $"capture_{DateTime.Now:yyyyMMdd_HHmmss}.pcap");
        }

        private void OnPacket(CapturedPacket pkt)
        {
            if (pkt.RawBytes.Length < 2) return;

            // Opcode map — first byte of decrypted or raw payload
            byte op = pkt.RawBytes[0];
            lock (_opLock) { _opcodeMap.TryGetValue(op, out int cnt); _opcodeMap[op] = cnt+1; }

            // RTT: track last send timestamp, compute round-trip on recv
            // Simple approximation: timestamp delta between last C→S and first S→C after it
            lock (_rttGraph) {
                var timing = _pipe.TimingLog;
                if (timing.Count >= 2) {
                    var last = timing[timing.Count-1];
                    var prev = timing[timing.Count-2];
                    if (last.Dir == 1 && prev.Dir == 0 && last.TimestampUs > prev.TimestampUs) {
                        float rtt_ms = (last.TimestampUs - prev.TimestampUs) / 1000f;
                        if (rtt_ms < 5000) { // sanity cap
                            _rttGraph[_rttHead % 200] = rtt_ms;
                            _rttHead++;
                        }
                    }
                }
            }
        }

        public void Render()
        {
            ImGui.TextColored(new Vector4(0.4f,0.9f,0.6f,1f), "Protocol Lab  —  Server Security Testing");
            ImGui.SameLine();
            bool live = _pipe.DllConnected;
            ImGui.TextColored(live ? new Vector4(0.1f,1f,0.4f,1f) : new Vector4(0.7f,0.3f,0.3f,1f),
                live ? "● DLL Live" : "○ DLL not connected (inject first)");
            ImGui.Separator();

            if (ImGui.BeginTabBar("##plab"))
            {
                if (ImGui.BeginTabItem("Fuzzer"))       { RenderFuzzer();    ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Replay"))       { RenderReplay();    ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Rate Limit"))   { RenderRateLimit(); ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("PCAP Export"))  { RenderPcap();      ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Seq Tracker"))  { RenderSeq();       ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Opcode Map"))   { RenderOpcodeMap(); ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("RTT / Timing")) { RenderTiming();    ImGui.EndTabItem(); }
                ImGui.EndTabBar();
            }
        }

        // ─── Fuzzer ───────────────────────────────────────────────
        private void RenderFuzzer()
        {
            ImGui.TextColored(new Vector4(0.9f,0.7f,0.2f,1f), "Packet Fuzzer");
            ImGui.TextWrapped("Flips random bits in the NEXT outgoing C→S packet, then sends it. " +
                "Observe whether the server disconnects you, sends an error opcode, or accepts it silently " +
                "(silent acceptance = missing validation).");
            ImGui.Spacing();

            ImGui.SetNextItemWidth(200);
            ImGui.SliderInt("Bits to flip##fz", ref _fuzzBits, 1, 64);
            ImGui.SameLine();
            if (ImGui.Button("Arm Fuzzer"))
            {
                _pipe.Fuzz(_fuzzBits);
                _fuzzResult = $"Armed: next outgoing packet will have {_fuzzBits} random bit(s) flipped.";
            }
            if (!string.IsNullOrEmpty(_fuzzResult))
                ImGui.TextColored(new Vector4(0.9f,0.8f,0.2f,1f), _fuzzResult);

            ImGui.Spacing();
            ImGui.TextColored(new Vector4(0.6f,0.6f,0.6f,1f),
                "What to look for:\n" +
                "  - Kicked / disconnected  →  server validates packet integrity\n" +
                "  - Graceful error reply   →  server has error handling\n" +
                "  - Nothing happens        →  server silently drops bad packets (good)\n" +
                "  - Server crashes / hangs →  potential DoS vulnerability (report this!)");
        }

        // ─── Replay ───────────────────────────────────────────────
        private void RenderReplay()
        {
            ImGui.TextColored(new Vector4(0.9f,0.7f,0.2f,1f), "Packet Replay");
            ImGui.TextWrapped("Resend a previously captured packet verbatim, or inject custom hex bytes. " +
                "Tests replay-attack resistance and idempotency.");
            ImGui.Spacing();

            if (ImGui.Button("Replay Last C→S Packet"))
            {
                _pipe.Replay();
                _replayStatus = $"Replay command sent at {DateTime.Now:HH:mm:ss.fff}";
            }
            ImGui.SameLine();
            ImGui.TextColored(new Vector4(0.6f,0.6f,0.6f,1f),
                "(replays whatever the last client→server packet was)");

            ImGui.Spacing();
            ImGui.Separator();
            ImGui.Spacing();

            ImGui.Text("Inject custom hex packet:");
            ImGui.SetNextItemWidth(500);
            ImGui.InputText("Hex bytes##rhex", ref _replayHex, 4096);
            ImGui.SameLine();
            if (ImGui.Button("Send##rhex"))
            {
                string clean = _replayHex.Replace(" ","").Replace("\n","").Trim();
                if (clean.Length > 0 && clean.Length % 2 == 0) {
                    _pipe.ReplayHex(clean);
                    _replayStatus = $"Sent {clean.Length/2}B custom packet.";
                } else {
                    _replayStatus = "Bad hex (needs even number of hex chars, no spaces)";
                }
            }
            if (!string.IsNullOrEmpty(_replayStatus))
                ImGui.TextColored(new Vector4(0.2f,1f,0.5f,1f), _replayStatus);

            ImGui.Spacing();
            ImGui.TextColored(new Vector4(0.6f,0.6f,0.6f,1f),
                "What to look for:\n" +
                "  - Replay accepted = no replay protection (e.g. duplicate item use, duplicate purchase)\n" +
                "  - Nonce / sequence rejection = server has replay protection\n" +
                "  - Crash on custom hex = unsafe deserialization / missing length check");
        }

        // ─── Rate Limit ───────────────────────────────────────────
        private void RenderRateLimit()
        {
            ImGui.TextColored(new Vector4(0.9f,0.7f,0.2f,1f), "Rate-Limit Prober");
            ImGui.TextWrapped("Floods the last captured C→S packet N times over T milliseconds " +
                "to find where the server starts dropping, throttling, or kicking.");
            ImGui.Spacing();

            ImGui.SetNextItemWidth(180);
            ImGui.InputInt("Count##rl", ref _rlCount);
            ImGui.SameLine();
            ImGui.SetNextItemWidth(180);
            ImGui.InputInt("Over (ms)##rl", ref _rlMs);
            ImGui.SameLine();

            if (_rlRunning) ImGui.BeginDisabled();
            if (ImGui.Button("Run##rl"))
            {
                _rlCount  = Math.Max(1,  Math.Min(_rlCount, 10000));
                _rlMs     = Math.Max(10, Math.Min(_rlMs,    60000));
                _pipe.RateLimit(_rlCount, _rlMs);
                _rlRunning = true;
            }
            if (_rlRunning) ImGui.EndDisabled();

            if (_pipe.LastRateLimitSent > 0)
            {
                _rlRunning = false;
                ImGui.TextColored(new Vector4(0.2f,1f,0.5f,1f),
                    $"Result: {_pipe.LastRateLimitSent} packets sent over {_pipe.LastRateLimitIntervalMs}ms");
            }

            ImGui.Spacing();
            ImGui.TextColored(new Vector4(0.6f,0.6f,0.6f,1f),
                "Recommended test sequence:\n" +
                "  10/1000ms → 50/1000ms → 100/1000ms → 500/1000ms\n" +
                "  Watch the log for disconnects or error packets coming back.\n" +
                "  Also watch server CPU via task manager if you have server access.");
        }

        // ─── PCAP Export ──────────────────────────────────────────
        private void RenderPcap()
        {
            ImGui.TextColored(new Vector4(0.9f,0.7f,0.2f,1f), "PCAP Export");
            ImGui.TextWrapped("Write all captured UDP traffic to a .pcap file. " +
                "Open in Wireshark for deep protocol analysis with its QUIC dissector.");
            ImGui.Spacing();

            ImGui.SetNextItemWidth(500);
            ImGui.InputText("Output path##pcap", ref _pcapPath, 1024);
            ImGui.Spacing();

            if (!_pcapActive)
            {
                if (ImGui.Button("  Start Recording  ", new Vector2(160,32)))
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(_pcapPath) ?? ".");
                    _pipe.StartPcap(_pcapPath);
                    _pcapActive = true;
                }
            }
            else
            {
                ImGui.TextColored(new Vector4(0.1f,1f,0.4f,1f), "● Recording…");
                ImGui.SameLine();
                if (ImGui.Button("Stop Recording"))
                { _pipe.StopPcap(); _pcapActive = false; }
            }

            ImGui.Spacing();
            ImGui.TextColored(new Vector4(0.6f,0.6f,0.6f,1f),
                "In Wireshark: Edit → Preferences → Protocols → QUIC\n" +
                "Add your SSLKEYLOGFILE path under 'TLS key log file' to decrypt inline.");
        }

        // ─── Sequence Tracker ─────────────────────────────────────
        private void RenderSeq()
        {
            ImGui.TextColored(new Vector4(0.9f,0.7f,0.2f,1f), "QUIC Sequence Number Tracker");
            ImGui.TextWrapped("QUIC packet numbers must be strictly monotonically increasing. " +
                "Non-monotonic or duplicate packet numbers indicate a client-side bug or " +
                "a server that doesn't properly reject replayed/reordered packets.");
            ImGui.Spacing();

            lock (_pipe.SeqAnomalies)
            {
                int count = _pipe.SeqAnomalies.Count;
                ImGui.Text($"Anomalies detected: {count}");
                ImGui.SameLine();
                if (ImGui.SmallButton("Clear")) _pipe.SeqAnomalies.Clear();
                ImGui.SameLine();
                if (ImGui.SmallButton("Reset tracker")) _pipe.SeqReset();

                if (count == 0) {
                    ImGui.TextColored(new Vector4(0.2f,1f,0.4f,1f), "No anomalies — sequence numbers look clean.");
                } else {
                    ImGui.BeginChild("##seqlog", new Vector2(-1, -1), ImGuiChildFlags.Borders);
                    foreach (var a in _pipe.SeqAnomalies.TakeLast(200))
                        ImGui.TextColored(new Vector4(1f,0.4f,0.2f,1f), a);
                    ImGui.EndChild();
                }
            }
        }

        // ─── Opcode Map ───────────────────────────────────────────
        private void RenderOpcodeMap()
        {
            ImGui.TextColored(new Vector4(0.9f,0.7f,0.2f,1f), "Opcode / Message-Type Map");
            ImGui.TextWrapped("Catalogues unique first-byte values seen in captured packets. " +
                "After decryption works, this maps the server's message type space.");
            ImGui.Spacing();

            if ((DateTime.Now - _lastOpSort).TotalSeconds > 1) {
                lock (_opLock) {
                    _opcodeSorted = _opcodeMap.Select(kv=>(kv.Key,kv.Value))
                        .OrderByDescending(x=>x.Value).ToList();
                }
                _lastOpSort = DateTime.Now;
            }

            ImGui.SameLine();
            if (ImGui.SmallButton("Clear##op")) { lock(_opLock) _opcodeMap.Clear(); }

            ImGui.Text($"Unique first-bytes seen: {_opcodeSorted.Count}");
            ImGui.Separator();

            if (ImGui.BeginTable("##opmap", 3, ImGuiTableFlags.Borders | ImGuiTableFlags.RowBg))
            {
                ImGui.TableSetupColumn("Byte (hex)", ImGuiTableColumnFlags.WidthFixed, 90);
                ImGui.TableSetupColumn("Count",      ImGuiTableColumnFlags.WidthFixed, 80);
                ImGui.TableSetupColumn("Bar",        ImGuiTableColumnFlags.WidthStretch);
                ImGui.TableHeadersRow();

                int maxCount = _opcodeSorted.Count > 0 ? _opcodeSorted[0].cnt : 1;
                foreach (var (op, cnt) in _opcodeSorted.Take(64))
                {
                    ImGui.TableNextRow();
                    ImGui.TableSetColumnIndex(0);
                    ImGui.Text($"0x{op:X2}  ({op})");
                    ImGui.TableSetColumnIndex(1);
                    ImGui.Text($"{cnt}");
                    ImGui.TableSetColumnIndex(2);
                    float frac = maxCount > 0 ? (float)cnt/maxCount : 0;
                    ImGui.ProgressBar(frac, new Vector2(-1, 0), "");
                }
                ImGui.EndTable();
            }
        }

        // ─── RTT / Timing ─────────────────────────────────────────
        private void RenderTiming()
        {
            ImGui.TextColored(new Vector4(0.9f,0.7f,0.2f,1f), "RTT / Timing Analysis");
            ImGui.TextWrapped("Approximate round-trip times from C→S send to next S→C receive. " +
                "Useful as baseline — large spikes during rate-limit tests indicate server load.");
            ImGui.Spacing();

            // Build a display array
            float[] disp = new float[200];
            for (int i=0; i<200; i++)
                disp[i] = _rttGraph[((_rttHead - 200 + i) % 200 + 200) % 200];

            float maxV = disp.Length > 0 ? disp.Max() : 1f;
            if (maxV < 1f) maxV = 1f;

            ImGui.PlotLines("##rtt", ref disp[0], 200, 0, $"RTT (ms) — max {maxV:F1}ms",
                0f, maxV * 1.2f, new Vector2(-1, 120));

            ImGui.Spacing();

            var timing = _pipe.TimingLog;
            lock (timing)
            {
                ImGui.Text($"Total timing entries: {timing.Count}");
                if (timing.Count > 2)
                {
                    var cs  = timing.Where(t=>t.Dir==0).ToList();
                    var sc  = timing.Where(t=>t.Dir==1).ToList();
                    float avgCs = cs.Count > 0 ? (float)cs.Average(t=>t.Length) : 0;
                    float avgSc = sc.Count > 0 ? (float)sc.Average(t=>t.Length) : 0;
                    ImGui.Text($"Avg C→S size: {avgCs:F0} bytes   Avg S→C size: {avgSc:F0} bytes");
                    ImGui.Text($"C→S packets: {cs.Count}   S→C packets: {sc.Count}");
                }
                if (ImGui.SmallButton("Export Timing CSV"))
                    ExportTimingCsv(timing);
            }
        }

        private void ExportTimingCsv(List<TimingEntry> entries)
        {
            try {
                string path = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "HyForce","Exports",$"timing_{DateTime.Now:yyyyMMdd_HHmmss}.csv");
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                var sb = new StringBuilder("timestamp_us,length,direction\n");
                foreach (var e in entries)
                    sb.AppendLine($"{e.TimestampUs},{e.Length},{(e.Dir==0?"C->S":"S->C")}");
                File.WriteAllText(path, sb.ToString());
                _state.AddInGameLog($"[LAB] Timing CSV: {path}");
            } catch (Exception ex) { _state.AddInGameLog($"[LAB] CSV export failed: {ex.Message}"); }
        }
    }
}
