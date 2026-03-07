// SecurityAuditTab.cs — Protocol Security Audit Suite
// Subtabs: Fuzzer | Replay+Mutate | Rate Limit | Session Replay | Report
// All tests run over the QUIC/UDP pipe. Findings auto-collected for export.
// Encrypted packets use the fixed TryEncrypt (real AES-128-GCM + HP).

using HyForce.Core;
using HyForce.Networking;
using HyForce.Protocol;
using ImGuiNET;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace HyForce.Tabs
{
    // ── Finding severity ─────────────────────────────────────────────────────
    public enum AuditSeverity { Info, Low, Medium, High, Critical }

    public class AuditFinding
    {
        public DateTime    At        { get; set; } = DateTime.Now;
        public string      Category  { get; set; } = "";
        public AuditSeverity Severity{ get; set; } = AuditSeverity.Info;
        public string      Title     { get; set; } = "";
        public string      Detail    { get; set; } = "";
        public string      Evidence  { get; set; } = ""; // hex bytes / packet dump
        public bool        Confirmed { get; set; } = false; // server responded
    }

    // ── Audit state shared across sub-tabs ───────────────────────────────────
    public class AuditState
    {
        public List<AuditFinding> Findings { get; } = new();
        public readonly object Lock = new();

        public void Add(AuditFinding f) { lock (Lock) Findings.Add(f); }
        public void Add(AuditSeverity sev, string cat, string title, string detail, string evidence = "")
            => Add(new AuditFinding { Severity = sev, Category = cat, Title = title, Detail = detail, Evidence = evidence });
    }

    // ═══════════════════════════════════════════════════════════════════════════
    public class SecurityAuditTab : ITab
    {
        public string Name => "Security Audit";

        private readonly AppState          _state;
        private readonly PipeCaptureServer _pipe;
        private readonly AuditState        _audit = new();

        // sub-tabs
        private readonly FuzzerPanel       _fuzzer;
        private readonly ReplayPanel       _replay;
        private readonly RateLimitPanel    _rateLimit;
        private readonly SessionReplayPanel _sessionReplay;

        // UDP socket for sending test packets
        private UdpClient? _udp;
        private string _serverIp   = "127.0.0.1";
        private int    _serverPort = 5520;
        private bool   _socketOpen = false;

        static readonly Vector4 Accent  = new(0.75f, 0.45f, 1f,  1f);
        static readonly Vector4 Green   = new(0.2f,  1f,    0.4f, 1f);
        static readonly Vector4 Yellow  = new(1f,    0.85f, 0.1f, 1f);
        static readonly Vector4 Red     = new(1f,    0.3f,  0.2f, 1f);
        static readonly Vector4 Muted   = new(0.55f, 0.55f, 0.55f, 1f);

        static readonly Vector4[] SevColour = {
            new(0.6f, 0.6f, 0.6f, 1f),   // Info
            new(0.3f, 0.7f, 1f,   1f),   // Low
            new(1f,   0.8f, 0.2f, 1f),   // Medium
            new(1f,   0.4f, 0.1f, 1f),   // High
            new(1f,   0.1f, 0.1f, 1f),   // Critical
        };
        static readonly string[] SevLabel = { "INFO", "LOW", "MED", "HIGH", "CRIT" };

        public SecurityAuditTab(AppState state, PipeCaptureServer pipe)
        {
            _state       = state;
            _pipe        = pipe;
            _fuzzer      = new FuzzerPanel(state, audit: _audit, sendFn: SendRaw);
            _replay      = new ReplayPanel(state, pipe, audit: _audit, sendFn: SendRaw);
            _rateLimit   = new RateLimitPanel(state, audit: _audit, sendFn: SendRaw);
            _sessionReplay = new SessionReplayPanel(state, pipe, audit: _audit, sendFn: SendRaw);
        }

        // ── Render ─────────────────────────────────────────────────────────────
        public void Render()
        {
            // ── Target bar ──────────────────────────────────────────────────────
            ImGui.TextColored(Accent, "Security Audit Suite");
            ImGui.SameLine(ImGui.GetContentRegionAvail().X - 520);
            ImGui.Text("Target:");
            ImGui.SameLine(); ImGui.SetNextItemWidth(130);
            ImGui.InputText("##sip", ref _serverIp, 48);
            ImGui.SameLine(); ImGui.SetNextItemWidth(70);
            ImGui.InputInt("##sport", ref _serverPort);
            ImGui.SameLine();
            if (_socketOpen)
            {
                ImGui.TextColored(Green, "● Socket open");
                ImGui.SameLine();
                if (ImGui.SmallButton("Close")) CloseSocket();
            }
            else
            {
                if (ImGui.Button("Open UDP Socket")) OpenSocket();
            }
            ImGui.SameLine();
            ImGui.TextColored(Muted, $"  {_audit.Findings.Count} findings");

            ImGui.Separator();

            if (!ImGui.BeginTabBar("##saudit")) return;

            if (ImGui.BeginTabItem("Fuzzer"))        { _fuzzer.Render(_serverIp, _serverPort);       ImGui.EndTabItem(); }
            if (ImGui.BeginTabItem("Replay+Mutate")) { _replay.Render(_serverIp, _serverPort);       ImGui.EndTabItem(); }
            if (ImGui.BeginTabItem("Rate Limit"))    { _rateLimit.Render(_serverIp, _serverPort);    ImGui.EndTabItem(); }
            if (ImGui.BeginTabItem("Session Replay")){ _sessionReplay.Render(_serverIp, _serverPort);ImGui.EndTabItem(); }
            if (ImGui.BeginTabItem($"Findings ({_audit.Findings.Count})")) { RenderFindings(); ImGui.EndTabItem(); }
            if (ImGui.BeginTabItem("Audit Report"))  { RenderReport(); ImGui.EndTabItem(); }

            ImGui.EndTabBar();
        }

        // ── Findings panel ─────────────────────────────────────────────────────
        private string _findFilter = "";
        private int    _findSevFilter = -1; // -1 = all
        private void RenderFindings()
        {
            ImGui.SetNextItemWidth(160); ImGui.InputText("Filter##ff", ref _findFilter, 64);
            ImGui.SameLine();
            ImGui.SetNextItemWidth(100);
            string[] sevOpts = { "All", "Info", "Low", "Medium", "High", "Critical" };
            ImGui.Combo("Severity##fs", ref _findSevFilter, sevOpts, sevOpts.Length);
            ImGui.SameLine();
            if (ImGui.SmallButton("Clear##fc")) { lock (_audit.Lock) _audit.Findings.Clear(); }
            ImGui.Separator();

            List<AuditFinding> findings;
            lock (_audit.Lock) findings = _audit.Findings.ToList();
            var filtered = findings
                .Where(f => _findSevFilter <= 0 || (int)f.Severity == _findSevFilter - 1)
                .Where(f => string.IsNullOrEmpty(_findFilter) ||
                    f.Title.Contains(_findFilter, StringComparison.OrdinalIgnoreCase) ||
                    f.Detail.Contains(_findFilter, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(f => f.Severity).ThenByDescending(f => f.At)
                .ToList();

            ImGui.BeginChild("##findings", new Vector2(-1, -1), ImGuiChildFlags.Borders);
            for (int i = 0; i < filtered.Count; i++)
            {
                var f = filtered[i];
                ImGui.PushID(i);
                var col = SevColour[(int)f.Severity];
                ImGui.TextColored(col, $"[{SevLabel[(int)f.Severity]}]");
                ImGui.SameLine();
                ImGui.TextColored(Muted, $"[{f.Category}]");
                ImGui.SameLine();
                ImGui.TextColored(f.Confirmed ? Green : Yellow, f.Confirmed ? "✓" : "?");
                ImGui.SameLine();
                bool open = ImGui.TreeNode($"{f.Title}  ({f.At:HH:mm:ss})##fn{i}");
                if (open)
                {
                    ImGui.TextWrapped(f.Detail);
                    if (!string.IsNullOrEmpty(f.Evidence))
                    {
                        ImGui.TextColored(Muted, "Evidence:");
                        ImGui.SetNextItemWidth(-1);
                        var ev = f.Evidence;
                        ImGui.InputTextMultiline($"##ev{i}", ref ev, 4096, new Vector2(-1, 60), ImGuiInputTextFlags.ReadOnly);
                    }
                    ImGui.TreePop();
                }
                ImGui.PopID();
            }
            ImGui.EndChild();
        }

        // ── Audit Report panel ─────────────────────────────────────────────────
        private string _reportText = "Click 'Generate Report' to compile all findings.";
        private void RenderReport()
        {
            if (ImGui.Button("Generate Report", new Vector2(150, 28)))
                _reportText = GenerateReport();
            ImGui.SameLine();
            if (ImGui.Button("Save + Open", new Vector2(120, 28)))
            {
                _reportText = GenerateReport();
                SaveReport(_reportText);
            }
            ImGui.SameLine();
            if (ImGui.Button("Copy##rpt", new Vector2(80, 28)))
                ImGui.SetClipboardText(_reportText);
            ImGui.Separator();
            ImGui.BeginChild("##rptprev", new Vector2(-1, -1), ImGuiChildFlags.Borders);
            ImGui.InputTextMultiline("##rpttext", ref _reportText, 1 << 20, new Vector2(-1,-1), ImGuiInputTextFlags.ReadOnly);
            ImGui.EndChild();
        }

        // ── UDP socket ─────────────────────────────────────────────────────────
        public bool SendRaw(byte[] data, string? targetIp = null, int targetPort = 0)
        {
            if (!_socketOpen) OpenSocket();
            if (_udp == null) return false;
            try
            {
                string ip   = targetIp   ?? _serverIp;
                int    port = targetPort > 0 ? targetPort : _serverPort;
                _udp.Send(data, data.Length, ip, port);
                return true;
            }
            catch (Exception ex)
            {
                _state.AddInGameLog($"[AUDIT] Send error: {ex.Message}");
                return false;
            }
        }

        private void OpenSocket()
        {
            try
            {
                _udp = new UdpClient();
                _udp.Client.ReceiveTimeout = 500;
                _socketOpen = true;
                _state.AddInGameLog($"[AUDIT] UDP socket open → {_serverIp}:{_serverPort}");
            }
            catch (Exception ex)
            {
                _state.AddInGameLog($"[AUDIT] Socket error: {ex.Message}");
            }
        }

        private void CloseSocket()
        {
            _udp?.Close();
            _udp = null;
            _socketOpen = false;
        }

        // ── Report generation ──────────────────────────────────────────────────
        private string GenerateReport()
        {
            var sb = new StringBuilder();
            sb.AppendLine("╔══════════════════════════════════════════════════════════╗");
            sb.AppendLine("║       HyForce Protocol Security Audit Report              ║");
            sb.AppendLine("╚══════════════════════════════════════════════════════════╝");
            sb.AppendLine($"Target     : {_serverIp}:{_serverPort}");
            sb.AppendLine($"Generated  : {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"Tool       : HyForce v11");
            sb.AppendLine();

            List<AuditFinding> findings;
            lock (_audit.Lock) findings = _audit.Findings.ToList();

            // Summary
            sb.AppendLine("─── EXECUTIVE SUMMARY ─────────────────────────────────────");
            sb.AppendLine($"  Total findings : {findings.Count}");
            foreach (AuditSeverity sev in Enum.GetValues<AuditSeverity>().Reverse())
            {
                int n = findings.Count(f => f.Severity == sev);
                if (n > 0) sb.AppendLine($"  {SevLabel[(int)sev],-8}: {n}");
            }
            sb.AppendLine();

            // Group by category
            foreach (var cat in findings.Select(f => f.Category).Distinct().OrderBy(x => x))
            {
                sb.AppendLine($"─── {cat.ToUpperInvariant()} ─────────────────────────────────────────");
                foreach (var f in findings.Where(x => x.Category == cat).OrderByDescending(x => x.Severity))
                {
                    sb.AppendLine($"  [{SevLabel[(int)f.Severity]}] {f.Title}");
                    sb.AppendLine($"  Time: {f.At:HH:mm:ss.fff}  Confirmed: {(f.Confirmed ? "YES" : "unconfirmed")}");
                    sb.AppendLine($"  {f.Detail}");
                    if (!string.IsNullOrEmpty(f.Evidence))
                        sb.AppendLine($"  Evidence: {f.Evidence.Substring(0, Math.Min(200, f.Evidence.Length))}...");
                    sb.AppendLine();
                }
            }

            // Recommendations
            sb.AppendLine("─── RECOMMENDATIONS ───────────────────────────────────────");
            if (findings.Any(f => f.Category == "Rate Limit" && f.Severity >= AuditSeverity.Medium))
                sb.AppendLine("  • Implement server-side rate limiting per client IP/session");
            if (findings.Any(f => f.Category == "Replay" && f.Confirmed))
                sb.AppendLine("  • Enable replay protection (sequence counter, timestamp window)");
            if (findings.Any(f => f.Category == "Fuzzer" && f.Severity >= AuditSeverity.High))
                sb.AppendLine("  • Harden packet parser — add length/type validation before processing");
            if (findings.Any(f => f.Category == "Session" && f.Confirmed))
                sb.AppendLine("  • Enforce short token lifetime + session binding (IP/port lock)");
            if (!findings.Any(f => f.Severity >= AuditSeverity.High))
                sb.AppendLine("  ✓ No high/critical findings — surface looks robust");

            sb.AppendLine();
            sb.AppendLine("══════════════════════════════════════════════════════════");
            sb.AppendLine("Generated by HyForce — for authorised security testing only");
            return sb.ToString();
        }

        private void SaveReport(string content)
        {
            try
            {
                Directory.CreateDirectory(_state.ExportDirectory);
                string path = Path.Combine(_state.ExportDirectory,
                    $"audit_report_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
                File.WriteAllText(path, content);
                _state.AddInGameLog($"[AUDIT] Report → {Path.GetFileName(path)}");
                try { System.Diagnostics.Process.Start("notepad.exe", path); } catch { }
            }
            catch (Exception ex) { _state.AddInGameLog($"[AUDIT] Save error: {ex.Message}"); }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // PANEL 1: Protocol Fuzzer
    // ═══════════════════════════════════════════════════════════════════════════
    internal class FuzzerPanel
    {
        private readonly AppState  _state;
        private readonly AuditState _audit;
        private readonly Func<byte[], string?, int, bool> _send;

        // Fuzz config
        private int  _fuzzCount     = 100;
        private int  _fuzzDelayMs   = 10;
        private bool _fuzzRunning   = false;
        private int  _fuzzSent      = 0;
        private int  _fuzzErrors    = 0;
        private CancellationTokenSource? _cts;

        // Template selection
        private int  _templateIdx  = 0;
        private string _customHex  = "c0000000 01 00 00 00 00";

        // Mutation modes (multi-select)
        private bool _mutBitFlip   = true;
        private bool _mutZero      = true;
        private bool _mutOversize  = true;
        private bool _mutUndersize = true;
        private bool _mutRandom    = true;
        private bool _mutBoundary  = true;

        private readonly List<string> _log = new();

        // Pre-built fuzz templates
        private static readonly (string Name, byte[] Base)[] Templates =
        {
            ("Short Header (min)",           new byte[]{0x40, 0x00, 0x00, 0x00, 0x00}),
            ("Short Header (all zeros)",     new byte[20]),
            ("Long Header QUIC v1 Initial",  new byte[]{0xC0,0x00,0x00,0x00,0x01,0x08,0,0,0,0,0,0,0,0,0x00,0x00,0x00,0x00,0x00,0x00}),
            ("Version Negotiation",          new byte[]{0x80,0x00,0x00,0x00,0x00,0x08,0,0,0,0,0,0,0,0,0x08,0,0,0,0,0,0,0,0,0xFF,0x00,0x00,0x01}),
            ("Oversized first byte=0xFF",    new byte[]{0xFF}),
            ("Empty packet",                 Array.Empty<byte>()),
            ("All 0xFF (512B)",              Enumerable.Repeat((byte)0xFF,512).ToArray()),
            ("Custom hex",                   Array.Empty<byte>()),
        };

        static readonly Vector4 Green  = new(0.2f, 1f, 0.4f, 1f);
        static readonly Vector4 Yellow = new(1f, 0.85f, 0.1f, 1f);
        static readonly Vector4 Red    = new(1f, 0.3f, 0.2f, 1f);
        static readonly Vector4 Muted  = new(0.55f,0.55f,0.55f,1f);
        static readonly Vector4 Accent = new(0.75f, 0.45f, 1f, 1f);

        public FuzzerPanel(AppState state, AuditState audit, Func<byte[], string?, int, bool> sendFn)
        { _state = state; _audit = audit; _send = sendFn; }

        public void Render(string ip, int port)
        {
            ImGui.TextColored(Accent, "Protocol Fuzzer — sends malformed/edge-case QUIC packets");
            ImGui.TextWrapped("Tests whether the server crashes, disconnects, or behaves incorrectly on invalid input. " +
                "None of these packets contain valid auth — they test the parser only.");
            ImGui.Separator();

            // Template picker
            string[] tnames = Templates.Select(t => t.Name).ToArray();
            ImGui.SetNextItemWidth(280);
            ImGui.Combo("Template##ft", ref _templateIdx, tnames, tnames.Length);
            if (_templateIdx == Templates.Length - 1) // custom
            {
                ImGui.SetNextItemWidth(-1);
                ImGui.InputText("Hex bytes (space-separated)##fhex", ref _customHex, 512);
            }

            ImGui.Spacing();
            ImGui.TextColored(Muted, "Mutation modes:");
            ImGui.Checkbox("Bit flip",    ref _mutBitFlip);   ImGui.SameLine();
            ImGui.Checkbox("Zero fill",   ref _mutZero);      ImGui.SameLine();
            ImGui.Checkbox("Oversize",    ref _mutOversize);  ImGui.SameLine();
            ImGui.Checkbox("Undersize",   ref _mutUndersize); ImGui.SameLine();
            ImGui.Checkbox("Full random", ref _mutRandom);    ImGui.SameLine();
            ImGui.Checkbox("Boundaries",  ref _mutBoundary);

            ImGui.Spacing();
            ImGui.SetNextItemWidth(100); ImGui.InputInt("Count##fc",    ref _fuzzCount);   _fuzzCount   = Math.Clamp(_fuzzCount,   1, 100000);
            ImGui.SameLine();
            ImGui.SetNextItemWidth(100); ImGui.InputInt("Delay ms##fd", ref _fuzzDelayMs); _fuzzDelayMs = Math.Max(0, _fuzzDelayMs);
            ImGui.SameLine();

            if (_fuzzRunning)
            {
                ImGui.TextColored(Yellow, $"Fuzzing... {_fuzzSent}/{_fuzzCount}  errors={_fuzzErrors}");
                ImGui.SameLine();
                if (ImGui.Button("Stop##fstop")) { _cts?.Cancel(); _fuzzRunning = false; }
            }
            else
            {
                if (ImGui.Button("▶ Start Fuzz", new Vector2(120, 28)))
                    StartFuzz(ip, port);
            }

            ImGui.Separator();
            ImGui.TextColored(Muted, "Sent mutations (last 200):");
            ImGui.BeginChild("##flog", new Vector2(-1, -1), ImGuiChildFlags.Borders);
            lock (_log)
            {
                foreach (var l in _log.TakeLast(200))
                    ImGui.TextUnformatted(l);
                if (_fuzzRunning) ImGui.SetScrollHereY(1f);
            }
            ImGui.EndChild();
        }

        private void StartFuzz(string ip, int port)
        {
            _fuzzSent = 0; _fuzzErrors = 0; _fuzzRunning = true;
            lock (_log) _log.Clear();
            _cts = new CancellationTokenSource();
            var token = _cts.Token;

            byte[] baseTemplate = _templateIdx == Templates.Length - 1
                ? ParseHex(_customHex)
                : Templates[_templateIdx].Base;

            Task.Run(() =>
            {
                var rng = new Random();
                var mutations = BuildMutations(baseTemplate, rng).Take(_fuzzCount).ToList();
                foreach (var (label, pkt) in mutations)
                {
                    if (token.IsCancellationRequested) break;
                    bool ok = _send(pkt, ip, port);
                    _fuzzSent++;
                    if (!ok) _fuzzErrors++;
                    string hexPreview = BitConverter.ToString(pkt.Take(16).ToArray()).Replace("-"," ").ToLower();
                    string logLine = $"[{_fuzzSent,5}] {label,-22} {pkt.Length,5}B  {hexPreview}";
                    lock (_log) { _log.Add(logLine); if (_log.Count > 2000) _log.RemoveAt(0); }
                    // Log potentially interesting mutations as findings
                    if (pkt.Length == 0 || pkt.Length > 1400)
                        _audit.Add(AuditSeverity.Info, "Fuzzer", $"Edge-case sent: {label}",
                            $"Sent {pkt.Length}B to {ip}:{port}", hexPreview);
                    if (_fuzzDelayMs > 0) Thread.Sleep(_fuzzDelayMs);
                }
                _fuzzRunning = false;
                _state.AddInGameLog($"[FUZZER] Done: {_fuzzSent} packets, {_fuzzErrors} send errors");
                _audit.Add(AuditSeverity.Info, "Fuzzer", "Fuzz run complete",
                    $"{_fuzzSent} mutations sent to {ip}:{port}. Check server logs for crashes/disconnects.");
            }, token);
        }

        private IEnumerable<(string, byte[])> BuildMutations(byte[] src, Random rng)
        {
            if (src.Length == 0) src = new byte[] { 0x40, 0x00, 0x00, 0x00 };
            while (true)
            {
                // Boundary values for first byte
                if (_mutBoundary)
                {
                    foreach (byte b in new byte[]{0x00,0x01,0x3F,0x40,0x7F,0x80,0xBF,0xC0,0xFF})
                    {
                        var p = src.ToArray(); p[0] = b;
                        yield return ($"boundary_fb=0x{b:X2}", p);
                    }
                }
                // Bit flips on each byte
                if (_mutBitFlip && src.Length > 0)
                {
                    int byteIdx = rng.Next(src.Length);
                    int bit     = rng.Next(8);
                    var p = src.ToArray(); p[byteIdx] ^= (byte)(1 << bit);
                    yield return ($"bitflip[{byteIdx}]b{bit}", p);
                }
                // Zero fills
                if (_mutZero)
                {
                    int start = rng.Next(src.Length);
                    int len   = rng.Next(1, Math.Max(2, src.Length - start));
                    var p = src.ToArray();
                    for (int i = start; i < start + len && i < p.Length; i++) p[i] = 0;
                    yield return ($"zerofill[{start}..{start+len}]", p);
                }
                // Oversize: append garbage
                if (_mutOversize)
                {
                    int extra = rng.Next(1, 1400);
                    var ext = new byte[extra]; rng.NextBytes(ext);
                    yield return ($"oversize+{extra}B", src.Concat(ext).ToArray());
                }
                // Undersize: truncate
                if (_mutUndersize && src.Length > 1)
                {
                    int newLen = rng.Next(1, src.Length);
                    yield return ($"undersize={newLen}B", src.Take(newLen).ToArray());
                }
                // Full random
                if (_mutRandom)
                {
                    int sz = rng.Next(1, 1400);
                    var p  = new byte[sz]; rng.NextBytes(p);
                    yield return ($"random{sz}B", p);
                }
                // Huge oversize (jumbo)
                if (_mutOversize)
                {
                    var jumbo = new byte[rng.Next(1401, 65000)];
                    rng.NextBytes(jumbo); jumbo[0] = src.Length > 0 ? src[0] : (byte)0x40;
                    yield return ($"jumbo{jumbo.Length}B", jumbo);
                }
            }
        }

        private static byte[] ParseHex(string hex)
        {
            hex = hex.Replace(" ","").Replace("-","").Trim();
            if (hex.Length % 2 != 0) hex = "0" + hex;
            try { return Convert.FromHexString(hex); } catch { return new byte[]{0x40,0,0,0}; }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // PANEL 2: Replay + Field Mutation
    // ═══════════════════════════════════════════════════════════════════════════
    internal class ReplayPanel
    {
        private readonly AppState          _state;
        private readonly PipeCaptureServer _pipe;
        private readonly AuditState        _audit;
        private readonly Func<byte[], string?, int, bool> _send;

        private int    _selectedIdx    = -1;
        private int    _replayCount    = 3;
        private int    _replayDelayMs  = 100;
        private bool   _mutateSeq      = false;
        private bool   _mutatePayload  = false;
        private bool   _encryptBefore  = false;
        private string _hexEditorBuf   = "";
        private string _mutFieldOffset = "0";
        private string _mutFieldValue  = "00";
        private int    _mutFieldLen    = 1;
        private readonly List<string> _log = new();

        static readonly Vector4 Green  = new(0.2f, 1f, 0.4f, 1f);
        static readonly Vector4 Yellow = new(1f, 0.85f, 0.1f, 1f);
        static readonly Vector4 Muted  = new(0.55f,0.55f,0.55f,1f);
        static readonly Vector4 Accent = new(0.75f, 0.45f, 1f, 1f);

        public ReplayPanel(AppState state, PipeCaptureServer pipe, AuditState audit,
            Func<byte[], string?, int, bool> sendFn)
        { _state = state; _pipe = pipe; _audit = audit; _send = sendFn; }

        public void Render(string ip, int port)
        {
            ImGui.TextColored(Accent, "Packet Replay + Field Mutation");
            ImGui.TextWrapped("Pick a captured packet, optionally mutate fields, then replay N times. " +
                "Tests whether the server validates packet content server-side (sequence counters, lengths, types, field ranges).");
            ImGui.Separator();

            // Left: packet picker
            ImGui.BeginChild("##rplist", new Vector2(320, 260), ImGuiChildFlags.Borders);
            var quic = _state.PacketLog.GetLast(200).Where(p => !p.IsTcp).ToList();
            ImGui.TextColored(Muted, $"{quic.Count} QUIC packets");
            for (int i = 0; i < quic.Count; i++)
            {
                var p = quic[i];
                string label = $"[{p.Timestamp:HH:mm:ss}] {p.DirStr} {p.RawBytes.Length}B";
                bool sel = _selectedIdx == i;
                if (ImGui.Selectable(label, sel))
                {
                    _selectedIdx = i;
                    _hexEditorBuf = BitConverter.ToString(p.RawBytes).Replace("-", " ").ToLower();
                }
            }
            ImGui.EndChild();
            ImGui.SameLine();

            // Right: editor + controls
            ImGui.BeginChild("##rpedit", new Vector2(-1, 260), ImGuiChildFlags.Borders);
            if (_selectedIdx >= 0 && _selectedIdx < quic.Count)
            {
                ImGui.TextColored(Green, $"Selected: {quic[_selectedIdx].RawBytes.Length}B");
                ImGui.SetNextItemWidth(-1);
                ImGui.InputTextMultiline("##hexed", ref _hexEditorBuf, 131072, new Vector2(-1, 140));

                ImGui.TextColored(Muted, "Field patch (before replay):");
                ImGui.SetNextItemWidth(80);  ImGui.InputText("Offset hex##rfo", ref _mutFieldOffset, 8);
                ImGui.SameLine();
                ImGui.SetNextItemWidth(120); ImGui.InputText("New bytes hex##rfv", ref _mutFieldValue, 32);
                ImGui.SameLine();
                if (ImGui.SmallButton("Patch##rfp"))
                {
                    _hexEditorBuf = PatchHex(_hexEditorBuf, _mutFieldOffset, _mutFieldValue);
                    _audit.Add(AuditSeverity.Info, "Replay", "Field patched",
                        $"Patched offset 0x{_mutFieldOffset} with {_mutFieldValue}");
                }
            }
            else
            {
                ImGui.TextColored(Muted, "Select a packet on the left.");
            }
            ImGui.EndChild();

            ImGui.Spacing();
            ImGui.SetNextItemWidth(80);  ImGui.InputInt("Times##rc",    ref _replayCount);   _replayCount   = Math.Clamp(_replayCount, 1, 10000);
            ImGui.SameLine();
            ImGui.SetNextItemWidth(80);  ImGui.InputInt("Delay ms##rd", ref _replayDelayMs); _replayDelayMs = Math.Max(0, _replayDelayMs);
            ImGui.SameLine();
            ImGui.Checkbox("Increment sequence##rs", ref _mutateSeq);
            ImGui.SameLine();
            ImGui.Checkbox("Encrypt##re", ref _encryptBefore);

            ImGui.Spacing();
            if (ImGui.Button("▶ Replay", new Vector2(120, 28)) && _selectedIdx >= 0 && _selectedIdx < quic.Count)
                DoReplay(ip, port, quic[_selectedIdx].RawBytes);
            ImGui.SameLine();
            if (ImGui.Button("▶ Rapid (no delay)", new Vector2(140, 28)) && _selectedIdx >= 0)
            {
                int saved = _replayDelayMs; _replayDelayMs = 0;
                DoReplay(ip, port, quic[_selectedIdx].RawBytes);
                _replayDelayMs = saved;
            }

            ImGui.Separator();
            ImGui.TextColored(Muted, "Replay log (last 100):");
            ImGui.BeginChild("##rplog", new Vector2(-1, -1), ImGuiChildFlags.Borders);
            lock (_log)
                foreach (var l in _log.TakeLast(100)) ImGui.TextUnformatted(l);
            ImGui.EndChild();
        }

        private void DoReplay(string ip, int port, byte[] original)
        {
            byte[] pkt = HexToBytesFromEditor(_hexEditorBuf, original);
            int count = _replayCount, delay = _replayDelayMs;
            bool encrypt = _encryptBefore;
            bool mutSeq  = _mutateSeq;
            lock (_log) _log.Clear();
            _audit.Add(AuditSeverity.Info, "Replay", "Replay started",
                $"Replaying {count}x {pkt.Length}B to {ip}:{port}  encrypt={encrypt}  mutSeq={mutSeq}");

            Task.Run(() =>
            {
                int sent = 0, errs = 0;
                for (int i = 0; i < count; i++)
                {
                    byte[] toSend = pkt.ToArray();
                    if (mutSeq && toSend.Length >= 5)
                    {
                        // Increment last 4 bytes as a big-endian counter (crude PN increment)
                        int pnOff = Math.Max(0, toSend.Length - 4);
                        uint pn = BitConverter.ToUInt32(toSend, pnOff);
                        pn++;
                        byte[] pnb = BitConverter.GetBytes(pn);
                        if (BitConverter.IsLittleEndian) Array.Reverse(pnb);
                        Buffer.BlockCopy(pnb, 0, toSend, pnOff, 4);
                    }
                    if (encrypt)
                    {
                        var res = PacketDecryptor.TryEncrypt(toSend, PacketDecryptor.PacketDirection.ClientToServer);
                        if (res.Success) toSend = res.EncryptedData;
                    }
                    bool ok = _send(toSend, ip, port);
                    if (!ok) errs++;
                    sent++;
                    string line = $"[{i+1,5}] {toSend.Length}B  ok={ok}";
                    lock (_log) { _log.Add(line); if (_log.Count > 2000) _log.RemoveAt(0); }
                    if (delay > 0) Thread.Sleep(delay);
                }
                _state.AddInGameLog($"[REPLAY] Done: {sent} sent, {errs} errors");
                if (errs == 0)
                    _audit.Add(AuditSeverity.Medium, "Replay", "Replay accepted by network",
                        $"All {sent} replayed packets were accepted at the socket level. " +
                        "Check server-side logs to confirm whether they were PROCESSED or rejected by the application layer.",
                        BitConverter.ToString(pkt.Take(16).ToArray()).Replace("-"," "));
            });
        }

        private static string PatchHex(string hexBuf, string offsetHex, string newBytesHex)
        {
            try
            {
                byte[] data = HexBufToBytes(hexBuf);
                int offset  = Convert.ToInt32(offsetHex.TrimStart('0','x','X'), 16);
                byte[] newB = Convert.FromHexString(newBytesHex.Replace(" ",""));
                for (int i = 0; i < newB.Length && offset + i < data.Length; i++)
                    data[offset + i] = newB[i];
                return BitConverter.ToString(data).Replace("-"," ").ToLower();
            }
            catch { return hexBuf; }
        }
        private static byte[] HexBufToBytes(string buf)
            => Convert.FromHexString(buf.Replace(" ","").Replace("\n","").Replace("\r","").Trim());
        private static byte[] HexToBytesFromEditor(string buf, byte[] fallback)
        { try { return HexBufToBytes(buf); } catch { return fallback; } }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // PANEL 3: Rate Limit / Flood Stress Tester
    // ═══════════════════════════════════════════════════════════════════════════
    internal class RateLimitPanel
    {
        private readonly AppState   _state;
        private readonly AuditState _audit;
        private readonly Func<byte[], string?, int, bool> _send;

        private int  _pps         = 100; // packets per second
        private int  _duration    = 10;  // seconds
        private bool _running     = false;
        private int  _sent        = 0;
        private int  _target      = 0;
        private CancellationTokenSource? _cts;
        private int  _floodMode   = 0; // 0=QUIC short, 1=QUIC Initial, 2=random, 3=single captured
        private string _resultSummary = "";

        static readonly Vector4 Yellow = new(1f, 0.85f, 0.1f, 1f);
        static readonly Vector4 Red    = new(1f, 0.3f, 0.2f, 1f);
        static readonly Vector4 Green  = new(0.2f, 1f, 0.4f, 1f);
        static readonly Vector4 Muted  = new(0.55f,0.55f,0.55f,1f);
        static readonly Vector4 Accent = new(0.75f, 0.45f, 1f, 1f);

        public RateLimitPanel(AppState state, AuditState audit, Func<byte[], string?, int, bool> sendFn)
        { _state = state; _audit = audit; _send = sendFn; }

        public void Render(string ip, int port)
        {
            ImGui.TextColored(Accent, "Rate Limit / Flood Stress Tester");
            ImGui.TextWrapped("Sends packets at a controlled rate to check if the server has rate limiting. " +
                "A server with no rate limiting is vulnerable to amplification and DoS. " +
                "Watch for disconnects, error responses, or server-side logs showing drops.");
            ImGui.Separator();

            string[] modes = { "QUIC Short Header (minimal)", "QUIC Initial (handshake flood)", "Random bytes", "Zeros" };
            ImGui.SetNextItemWidth(260); ImGui.Combo("Packet type##flm", ref _floodMode, modes, modes.Length);
            ImGui.SetNextItemWidth(100); ImGui.InputInt("Pkt/sec##fps",   ref _pps);      _pps      = Math.Clamp(_pps, 1, 100000);
            ImGui.SameLine();
            ImGui.SetNextItemWidth(80);  ImGui.InputInt("Duration s##fd", ref _duration); _duration = Math.Clamp(_duration, 1, 300);
            ImGui.SameLine();
            ImGui.TextColored(Muted, $"= {_pps * _duration:N0} total packets");

            ImGui.Spacing();
            if (_running)
            {
                float pct = _target > 0 ? (float)_sent / _target : 0f;
                ImGui.TextColored(Yellow, $"Sending... {_sent:N0}/{_target:N0}  ({pct*100:F1}%)");
                ImGui.SameLine();
                if (ImGui.Button("Stop##rlstop")) { _cts?.Cancel(); _running = false; }
            }
            else
            {
                if (ImGui.Button("▶ Start Flood Test", new Vector2(160, 28)))
                    StartFlood(ip, port);
            }

            if (!string.IsNullOrEmpty(_resultSummary))
            {
                ImGui.Spacing();
                ImGui.TextColored(Green, _resultSummary);
            }

            ImGui.Separator();
            ImGui.TextColored(Muted, "Instructions:");
            ImGui.TextWrapped(
                "1. Start test, then immediately watch your captured packet feed.\n" +
                "2. If server stops responding after N packets → rate limit exists at ~N pkt/s.\n" +
                "3. If server keeps responding → no rate limit detected (finding: Medium/High).\n" +
                "4. Look for ICMP unreachable / connection reset in your network capture.\n" +
                "5. Check server CPU / logs for spikes during the test window.");
        }

        private void StartFlood(string ip, int port)
        {
            _sent = 0; _target = _pps * _duration; _running = true; _resultSummary = "";
            _cts = new CancellationTokenSource();
            var token = _cts.Token;
            int mode = _floodMode, pps = _pps, duration = _duration;
            var rng  = new Random();
            _audit.Add(AuditSeverity.Info, "Rate Limit", "Flood test started",
                $"{pps} pkt/s for {duration}s = {_target} packets to {ip}:{port}  mode={mode}");

            Task.Run(async () =>
            {
                int intervalUs = 1_000_000 / pps; // microseconds between packets
                var sw = System.Diagnostics.Stopwatch.StartNew();
                int errors = 0;
                while (_sent < _target && !token.IsCancellationRequested)
                {
                    byte[] pkt = mode switch
                    {
                        0 => new byte[]{0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                        1 => new byte[]{0xC0,0x00,0x00,0x00,0x01,0x08,0,0,0,0,0,0,0,0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
                        2 => RandomBytes(rng, 32),
                        _ => new byte[32],
                    };
                    if (!_send(pkt, ip, port)) errors++;
                    _sent++;
                    // Rate limiting via spin-wait for high pps
                    long targetUs = (long)_sent * intervalUs;
                    while (sw.Elapsed.TotalMicroseconds < targetUs && !token.IsCancellationRequested)
                        Thread.SpinWait(10);
                }
                _running = false;
                double actualPps = _sent / Math.Max(sw.Elapsed.TotalSeconds, 0.001);
                _resultSummary = $"Done: {_sent:N0} packets in {sw.Elapsed.TotalSeconds:F1}s ({actualPps:N0} actual pkt/s)  errors={errors}";
                _state.AddInGameLog($"[FLOOD] {_resultSummary}");
                var sev = errors > _sent / 2 ? AuditSeverity.Medium : AuditSeverity.Info;
                _audit.Add(sev, "Rate Limit", "Flood test complete", _resultSummary + "\n" +
                    (errors > _sent / 4
                        ? "Server dropped/rejected many packets — rate limiting may be active."
                        : "Server accepted all packets at socket level — verify application-layer rate limiting in server logs."));
            }, token);
        }

        private static byte[] RandomBytes(Random rng, int size)
        { var b = new byte[size]; rng.NextBytes(b); return b; }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // PANEL 4: Session Token Replay
    // ═══════════════════════════════════════════════════════════════════════════
    internal class SessionReplayPanel
    {
        private readonly AppState          _state;
        private readonly PipeCaptureServer _pipe;
        private readonly AuditState        _audit;
        private readonly Func<byte[], string?, int, bool> _send;

        private readonly List<SessionSnapshot> _snapshots = new();
        private int    _selectedSnap = -1;
        private int    _replayDelay  = 500;
        private string _customToken  = "";
        private readonly List<string> _log = new();

        static readonly Vector4 Yellow = new(1f, 0.85f, 0.1f, 1f);
        static readonly Vector4 Green  = new(0.2f, 1f, 0.4f, 1f);
        static readonly Vector4 Muted  = new(0.55f,0.55f,0.55f,1f);
        static readonly Vector4 Accent = new(0.75f, 0.45f, 1f, 1f);
        static readonly Vector4 Red    = new(1f, 0.3f, 0.2f, 1f);

        private class SessionSnapshot
        {
            public DateTime CapturedAt { get; set; }
            public string   Label      { get; set; } = "";
            public byte[]   FirstPacket{ get; set; } = Array.Empty<byte>();
            public string   KeyHex     { get; set; } = "";
            public int      PacketCount{ get; set; }
        }

        public SessionReplayPanel(AppState state, PipeCaptureServer pipe, AuditState audit,
            Func<byte[], string?, int, bool> sendFn)
        { _state = state; _pipe = pipe; _audit = audit; _send = sendFn; }

        public void Render(string ip, int port)
        {
            ImGui.TextColored(Accent, "Session Token / Credential Replay");
            ImGui.TextWrapped(
                "Snapshots the current session (SSL keys + first packets) so you can later disconnect, " +
                "reconnect, and replay the OLD session to test whether the server invalidates old tokens. " +
                "A server that accepts old sessions has no replay protection.");
            ImGui.Separator();

            // Snapshot controls
            if (ImGui.Button("📸 Snapshot Current Session", new Vector2(220, 28)))
                TakeSnapshot();
            ImGui.SameLine();
            ImGui.TextColored(Muted, $"{_snapshots.Count} snapshot(s)");

            ImGui.Spacing();
            ImGui.TextColored(Muted, "Saved snapshots:");
            ImGui.BeginChild("##snaplist", new Vector2(300, 160), ImGuiChildFlags.Borders);
            for (int i = 0; i < _snapshots.Count; i++)
            {
                var sn = _snapshots[i];
                bool sel = _selectedSnap == i;
                if (ImGui.Selectable($"[{sn.CapturedAt:HH:mm:ss}] {sn.Label}##sn{i}", sel))
                    _selectedSnap = i;
            }
            ImGui.EndChild();
            ImGui.SameLine();
            ImGui.BeginChild("##snapdetail", new Vector2(-1, 160), ImGuiChildFlags.Borders);
            if (_selectedSnap >= 0 && _selectedSnap < _snapshots.Count)
            {
                var sn = _snapshots[_selectedSnap];
                ImGui.TextColored(Green, $"Captured: {sn.CapturedAt:HH:mm:ss}");
                ImGui.Text($"Packets in session: {sn.PacketCount}");
                ImGui.Text($"First packet: {sn.FirstPacket.Length}B");
                ImGui.TextColored(Muted, $"Key: {sn.KeyHex}");
            }
            else ImGui.TextColored(Muted, "Select a snapshot");
            ImGui.EndChild();

            ImGui.Spacing();
            ImGui.SetNextItemWidth(100); ImGui.InputInt("Replay delay ms##srd", ref _replayDelay);
            ImGui.SameLine();
            bool canReplay = _selectedSnap >= 0 && _selectedSnap < _snapshots.Count;
            if (!canReplay) ImGui.BeginDisabled();
            if (ImGui.Button("▶ Replay OLD Session Packets", new Vector2(230, 28)) && canReplay)
                ReplaySnapshot(_snapshots[_selectedSnap], ip, port);
            if (!canReplay) ImGui.EndDisabled();

            ImGui.Separator();
            ImGui.TextColored(Accent, "Test procedure:");
            ImGui.TextWrapped(
                "1. Connect Hytale to the test server normally.\n" +
                "2. Click 'Snapshot Current Session' to save keys + opening packets.\n" +
                "3. Disconnect from the server (quit the game or use /disconnect).\n" +
                "4. Wait 30–60 seconds (or server session timeout if known).\n" +
                "5. Click 'Replay OLD Session Packets' with the snapshot selected.\n" +
                "6. Watch the captured packet feed — did the server respond?  " +
                "   If yes → session replay works = FINDING (no token expiry / replay protection).\n" +
                "   If no  → server correctly rejected the old session.");

            ImGui.Separator();
            ImGui.TextColored(Muted, "Log:");
            ImGui.BeginChild("##srlog", new Vector2(-1,-1), ImGuiChildFlags.Borders);
            lock (_log) foreach (var l in _log.TakeLast(100)) ImGui.TextUnformatted(l);
            ImGui.EndChild();
        }

        private void TakeSnapshot()
        {
            var keys   = PacketDecryptor.DiscoveredKeys;
            var packets = _state.PacketLog.GetLast(200).Where(p => !p.IsTcp).ToList();
            var sn = new SessionSnapshot
            {
                CapturedAt  = DateTime.Now,
                Label        = $"{packets.Count}pkts  {keys.Count}keys",
                FirstPacket  = packets.FirstOrDefault()?.RawBytes ?? Array.Empty<byte>(),
                KeyHex       = keys.Count > 0 ? BitConverter.ToString(keys[0].Key.Take(8).ToArray()).Replace("-","") + "..." : "(none)",
                PacketCount  = packets.Count,
            };
            _snapshots.Add(sn);
            _audit.Add(AuditSeverity.Info, "Session", "Session snapshot taken",
                $"Captured {packets.Count} packets, {keys.Count} keys at {DateTime.Now:HH:mm:ss}");
            _state.AddInGameLog($"[SESSION] Snapshot: {packets.Count} pkts, {keys.Count} keys");
            lock (_log) _log.Add($"[{DateTime.Now:HH:mm:ss}] Snapshot: {sn.Label}");
        }

        private void ReplaySnapshot(SessionSnapshot sn, string ip, int port)
        {
            if (sn.FirstPacket.Length == 0)
            {
                _state.AddInGameLog("[SESSION] No first packet in snapshot");
                return;
            }
            lock (_log) _log.Clear();
            _audit.Add(AuditSeverity.Info, "Session", "Session replay started",
                $"Replaying snapshot from {sn.CapturedAt:HH:mm:ss} to {ip}:{port}");

            var packets = _state.PacketLog.GetLast(200)
                .Where(p => !p.IsTcp && p.RawBytes.Length > 0).ToList();
            int delay = _replayDelay;

            Task.Run(() =>
            {
                int sent = 0;
                // Send the snapshot's opening packet first
                _send(sn.FirstPacket, ip, port);
                lock (_log) _log.Add($"[{DateTime.Now:HH:mm:ss.fff}] Sent snapshot first packet ({sn.FirstPacket.Length}B)");
                Thread.Sleep(Math.Max(50, delay));

                // Then replay up to 10 more captured packets in order
                foreach (var p in packets.Take(10))
                {
                    _send(p.RawBytes, ip, port);
                    sent++;
                    lock (_log) _log.Add($"[{DateTime.Now:HH:mm:ss.fff}] [{sent}] {p.RawBytes.Length}B {p.DirStr}");
                    Thread.Sleep(delay);
                }
                _state.AddInGameLog($"[SESSION] Replay done: {sent+1} packets sent. Check capture for server responses.");
                _audit.Add(AuditSeverity.Medium, "Session", "Session replay packets sent",
                    $"Sent {sent+1} packets from old session to {ip}:{port}. " +
                    "If the server responded with game data, replay protection is MISSING.",
                    BitConverter.ToString(sn.FirstPacket.Take(16).ToArray()).Replace("-"," "));
            });
        }
    }
}
