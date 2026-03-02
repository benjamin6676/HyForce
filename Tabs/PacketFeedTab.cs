// FILE: Tabs/PacketFeedTab.cs - ENHANCED WITH DEEP ANALYSIS AND BYPASS FEATURES
using HyForce.Core;
using HyForce.Data;
using HyForce.Networking;
using HyForce.Protocol;
using HyForce.UI;
using HyForce.Utils;
using ImGuiNET;
using System.Numerics;
using System.Diagnostics;

namespace HyForce.Tabs;

public class PacketFeedTab : ITab
{
    public string Name => "Packet Feed";
    private readonly AppState _state;
    private PacketLogEntry? _selectedPacket;
    private string _filterOpcode = "";
    private bool _showOnlyCritical;
    private bool _showOnlyUnknown;
    private bool _autoScroll = true;
    private bool _showPatternAnalysis = false;

    // Filter toggles
    private bool _hideEncrypted = false;
    private bool _showOnlyEncrypted = false;
    private bool _hideQuic = false;
    private bool _showOnlyQuic = false;
    private bool _hideTcp = false;
    private bool _showOnlyTcp = false;

    // Analysis toggles
    private bool _showEntropyDetails = true;
    private bool _showTimingAnalysis = true;
    private bool _showMemoryStatus = true;

    public PacketFeedTab(AppState state)
    {
        _state = state;
    }

    public void Render()
    {
        var windowSize = ImGui.GetContentRegionAvail();

        float toolbarHeight = 70;
        float remainingHeight = Math.Max(0, windowSize.Y - toolbarHeight - 10);

        RenderToolbar();
        ImGui.Separator();

        var listWidth = Math.Min(windowSize.X * 0.6f, windowSize.X - 320);
        var detailsWidth = Math.Max(0, windowSize.X - listWidth - 20);

        ImGui.BeginChild("PacketList", new Vector2(listWidth, remainingHeight), ImGuiChildFlags.Borders);
        RenderPacketList();
        ImGui.EndChild();

        ImGui.SameLine();

        ImGui.BeginChild("PacketDetails", new Vector2(detailsWidth, remainingHeight), ImGuiChildFlags.Borders);
        RenderPacketDetails();
        ImGui.EndChild();
    }

    private void RenderToolbar()
    {
        float buttonHeight = 25;

        // Row 1: Basic filters
        ImGui.PushItemWidth(100);
        ImGui.InputText("Filter Opcode", ref _filterOpcode, 10);
        ImGui.SameLine();
        ImGui.Checkbox("Critical", ref _showOnlyCritical);
        ImGui.SameLine();
        ImGui.Checkbox("Unknown", ref _showOnlyUnknown);
        ImGui.SameLine();
        ImGui.Checkbox("Auto-scroll", ref _autoScroll);

        ImGui.SameLine();
        if (ImGui.Button("Clear", new Vector2(60, buttonHeight)))
        {
            _state.PacketLog.Clear();
        }

        // Row 2: Encryption/Protocol filters
        ImGui.NewLine();

        ImGui.Text("Show:"); ImGui.SameLine();

        if (ImGui.Button(_hideEncrypted ? "Show Encrypted" : "Hide Encrypted", new Vector2(110, buttonHeight)))
        {
            _hideEncrypted = !_hideEncrypted;
            if (_hideEncrypted) _showOnlyEncrypted = false;
        }
        ImGui.SameLine();

        if (ImGui.Button(_showOnlyEncrypted ? "All Packets" : "Only Encrypted", new Vector2(110, buttonHeight)))
        {
            _showOnlyEncrypted = !_showOnlyEncrypted;
            if (_showOnlyEncrypted) _hideEncrypted = false;
        }

        ImGui.SameLine();
        ImGui.Text("|"); ImGui.SameLine();

        if (ImGui.Button(_hideQuic ? "Show QUIC" : "Hide QUIC", new Vector2(90, buttonHeight)))
        {
            _hideQuic = !_hideQuic;
            if (_hideQuic) _showOnlyQuic = false;
        }
        ImGui.SameLine();

        if (ImGui.Button(_showOnlyQuic ? "All Protocols" : "Only QUIC", new Vector2(90, buttonHeight)))
        {
            _showOnlyQuic = !_showOnlyQuic;
            if (_showOnlyQuic)
            {
                _hideQuic = false;
                _hideTcp = false;
                _showOnlyTcp = false;
            }
        }
        ImGui.SameLine();

        if (ImGui.Button(_hideTcp ? "Show TCP" : "Hide TCP", new Vector2(80, buttonHeight)))
        {
            _hideTcp = !_hideTcp;
            if (_hideTcp) _showOnlyTcp = false;
        }
        ImGui.SameLine();

        if (ImGui.Button(_showOnlyTcp ? "All Protocols" : "Only TCP", new Vector2(80, buttonHeight)))
        {
            _showOnlyTcp = !_showOnlyTcp;
            if (_showOnlyTcp)
            {
                _hideQuic = false;
                _hideTcp = false;
                _showOnlyQuic = false;
            }
        }

        ImGui.SameLine();
        ImGui.Text("|"); ImGui.SameLine();

        if (ImGui.Button("Timing Analysis", new Vector2(100, buttonHeight)))
        {
            _showPatternAnalysis = true;
        }
    }

    private void RenderPacketList()
    {
        var contentAvail = ImGui.GetContentRegionAvail();

        var tableFlags = ImGuiTableFlags.Resizable | ImGuiTableFlags.RowBg |
                        ImGuiTableFlags.BordersInnerV | ImGuiTableFlags.ScrollY;

        if (ImGui.BeginTable("Packets", 6, tableFlags, contentAvail))
        {
            ImGui.TableSetupColumn("Time", ImGuiTableColumnFlags.WidthFixed, 80);
            ImGui.TableSetupColumn("Dir", ImGuiTableColumnFlags.WidthFixed, 40);
            ImGui.TableSetupColumn("Opcode", ImGuiTableColumnFlags.WidthFixed, 60);
            ImGui.TableSetupColumn("Name", ImGuiTableColumnFlags.WidthStretch);
            ImGui.TableSetupColumn("Size", ImGuiTableColumnFlags.WidthFixed, 60);
            ImGui.TableSetupColumn("Info", ImGuiTableColumnFlags.WidthFixed, 80);
            ImGui.TableHeadersRow();

            var packets = GetFilteredPackets();

            foreach (var pkt in packets)
            {
                ImGui.TableNextRow();

                bool isSelected = _selectedPacket == pkt;

                ImGui.TableSetColumnIndex(0);

                string selectableId = $"##pkt_{pkt.Timestamp.Ticks}_{pkt.GetHashCode()}";

                if (ImGui.Selectable(selectableId, isSelected,
                    ImGuiSelectableFlags.SpanAllColumns))
                {
                    _selectedPacket = pkt;
                }

                if (isSelected)
                {
                    ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg0,
                        ImGui.ColorConvertFloat4ToU32(new Vector4(0.2f, 0.4f, 0.8f, 0.4f)));
                }

                ImGui.SameLine();
                ImGui.Text(pkt.Timestamp.ToString("HH:mm:ss.fff"));

                ImGui.TableSetColumnIndex(1);
                var dirColor = pkt.Direction == PacketDirection.ClientToServer
                    ? new Vector4(0.3f, 0.8f, 0.3f, 1)
                    : new Vector4(0.8f, 0.5f, 0.2f, 1);
                ImGui.TextColored(dirColor, pkt.DirStr);

                ImGui.TableSetColumnIndex(2);
                var isKnown = OpcodeRegistry.IsKnownOpcode(pkt.OpcodeDecimal, pkt.Direction);
                var opcodeColor = isKnown ? new Vector4(1, 1, 1, 1) : new Vector4(1, 0.3f, 0.3f, 1);
                ImGui.TextColored(opcodeColor, $"0x{pkt.OpcodeDecimal:X4}");

                ImGui.TableSetColumnIndex(3);
                var info = OpcodeRegistry.GetInfo(pkt.OpcodeDecimal, pkt.Direction);
                var name = info?.Name ?? pkt.OpcodeName;
                if (name.Length > 30)
                    name = name[..27] + "...";
                ImGui.Text(name);

                ImGui.TableSetColumnIndex(4);
                ImGui.Text($"{pkt.ByteLength}B");

                ImGui.TableSetColumnIndex(5);
                if (pkt.IsCompressed)
                {
                    ImGui.TextColored(new Vector4(0.5f, 0.8f, 1, 1), "[C]");
                    ImGui.SameLine();
                }
                if (pkt.EncryptionHint == "encrypted")
                {
                    ImGui.TextColored(new Vector4(1, 0.3f, 0.3f, 1), "[E]");
                }
                if (!pkt.IsTcp)
                {
                    ImGui.TextColored(new Vector4(0.4f, 0.6f, 0.8f, 1), "[Q]");
                }
            }
            ImGui.EndTable();
        }

        if (_autoScroll && ImGui.GetScrollY() < ImGui.GetScrollMaxY())
            ImGui.SetScrollHereY(1.0f);
    }

    private List<PacketLogEntry> GetFilteredPackets()
    {
        var packets = _state.PacketLog.GetLast(500);
        return packets.Where(p =>
        {
            if (!string.IsNullOrEmpty(_filterOpcode) &&
                !p.OpcodeDecimal.ToString("X4").Contains(_filterOpcode, StringComparison.OrdinalIgnoreCase))
                return false;

            if (_showOnlyCritical)
            {
                var info = OpcodeRegistry.GetInfo(p.OpcodeDecimal, p.Direction);
                if (info?.IsCritical != true) return false;
            }

            if (_showOnlyUnknown && OpcodeRegistry.IsKnownOpcode(p.OpcodeDecimal, p.Direction))
                return false;

            bool isEncrypted = p.EncryptionHint == "encrypted";
            if (_hideEncrypted && isEncrypted) return false;
            if (_showOnlyEncrypted && !isEncrypted) return false;

            bool isQuic = !p.IsTcp;
            if (_hideQuic && isQuic) return false;
            if (_showOnlyQuic && !isQuic) return false;
            if (_hideTcp && p.IsTcp) return false;
            if (_showOnlyTcp && !p.IsTcp) return false;

            return true;
        }).ToList();
    }

    private void RenderPacketDetails()
    {
        if (_selectedPacket == null)
        {
            ImGui.TextColored(Theme.ColTextMuted, "Select a packet to view details");
            RenderGlobalAnalysis();
            return;
        }

        var pkt = _selectedPacket;

        // Header
        ImGui.TextColored(new Vector4(0.4f, 0.8f, 1, 1), pkt.OpcodeName);
        ImGui.SameLine();
        ImGui.TextColored(Theme.ColTextMuted, $"0x{pkt.OpcodeDecimal:X4}");
        ImGui.Separator();

        // Basic info
        ImGui.Text("Direction: "); ImGui.SameLine();
        var dirColor = pkt.Direction == PacketDirection.ClientToServer
            ? new Vector4(0.3f, 0.8f, 0.3f, 1)
            : new Vector4(0.8f, 0.5f, 0.2f, 1);
        ImGui.TextColored(dirColor, pkt.Direction.ToString());

        ImGui.Text($"Size: {pkt.ByteLength} bytes");
        ImGui.Text($"Protocol: {(pkt.IsTcp ? "TCP" : "UDP/QUIC")}");

        // Deep encryption analysis
        RenderDeepEncryptionAnalysis(pkt);

        // Memory bypass status
        RenderMemoryBypassStatus();

        // QUIC specific
        if (!pkt.IsTcp && pkt.QuicInfo != null)
        {
            RenderQuicAnalysis(pkt);
        }

        // Hex preview
        RenderHexPreview(pkt);

        // Export buttons
        ImGui.Separator();
        if (ImGui.Button("Copy Hex", new Vector2(100, 28)))
        {
            try { TextCopy.ClipboardService.SetText(pkt.RawHexPreview); } catch { }
        }
        ImGui.SameLine();
        if (ImGui.Button("Export This Packet", new Vector2(130, 28)))
        {
            ExportSinglePacket(pkt);
        }
        ImGui.SameLine();
        if (ImGui.Button("Export Full Analysis", new Vector2(140, 28)))
        {
            ExportDetailedPacketLog();
        }
    }

    private void RenderDeepEncryptionAnalysis(PacketLogEntry pkt)
    {
        ImGui.Separator();
        ImGui.TextColored(new Vector4(0.8f, 0.8f, 0.8f, 1), "Deep Encryption Analysis");

        double fullEntropy = 0, headerEntropy = 0, payloadEntropy = 0;
        byte[]? bytes = null;

        try
        {
            var hexString = pkt.RawHexPreview.Replace("-", "");
            if (hexString.Length % 2 == 0 && hexString.Length > 0)
            {
                bytes = Convert.FromHexString(hexString);
                fullEntropy = ByteUtils.CalculateEntropy(bytes);

                if (bytes.Length > 20)
                {
                    headerEntropy = ByteUtils.CalculateEntropy(bytes.Take(20).ToArray());
                    payloadEntropy = ByteUtils.CalculateEntropy(bytes.Skip(20).ToArray());
                }
            }
        }
        catch { }

        // Entropy display
        ImGui.Text($"Full Packet Entropy: {fullEntropy:F2}");
        if (bytes != null && bytes.Length > 20)
        {
            ImGui.Text($"Header (20B): {headerEntropy:F2}");
            ImGui.Text($"Payload (rest): {payloadEntropy:F2}");

            // Progress bars
            ImGui.ProgressBar((float)(fullEntropy / 8.0), new Vector2(200, 15), "Full");
            ImGui.ProgressBar((float)(headerEntropy / 8.0), new Vector2(200, 15), "Header");
            ImGui.ProgressBar((float)(payloadEntropy / 8.0), new Vector2(200, 15), "Payload");
        }

        // Verdict
        string verdict;
        Vector4 verdictColor;

        if (fullEntropy > 7.8)
        {
            verdict = "STRONG ENCRYPTION - Keys required";
            verdictColor = new Vector4(1, 0.2f, 0.2f, 1);
        }
        else if (fullEntropy > 7.0)
        {
            verdict = "WEAK ENCRYPTION / COMPRESSED - Possible to crack";
            verdictColor = new Vector4(1, 0.6f, 0.2f, 1);
        }
        else if (fullEntropy > 5.0)
        {
            verdict = "STRUCTURED DATA - Partially readable";
            verdictColor = new Vector4(0.2f, 0.8f, 0.2f, 1);
        }
        else
        {
            verdict = "PLAINTEXT / PROTOCOL HEADERS - Fully readable";
            verdictColor = new Vector4(0.2f, 1, 0.2f, 1);
        }

        ImGui.TextColored(verdictColor, $"Verdict: {verdict}");

        // Pattern detection
        if (bytes != null)
        {
            ImGui.Separator();
            ImGui.TextColored(new Vector4(0.6f, 0.8f, 1, 1), "Pattern Analysis");

            bool hasRepeating = bytes.GroupBy(b => b).Any(g => g.Count() > bytes.Length / 4);
            bool hasNulls = bytes.Any(b => b == 0);
            bool hasAscii = bytes.Any(b => b >= 32 && b <= 126);
            int uniqueBytes = bytes.Distinct().Count();

            ImGui.Text($"Unique bytes: {uniqueBytes}/{bytes.Length} ({100.0 * uniqueBytes / bytes.Length:F1}%)");
            ImGui.Text($"Repeating patterns: {(hasRepeating ? "YES" : "No")}");
            ImGui.Text($"Null bytes: {(hasNulls ? "YES" : "No")}");
            ImGui.Text($"ASCII content: {(hasAscii ? "YES" : "No")}");

            // Check for known opcodes in raw data
            if (bytes.Length >= 2)
            {
                for (int i = 0; i < Math.Min(10, bytes.Length - 1); i++)
                {
                    ushort testOpcode = (ushort)((bytes[i] << 8) | bytes[i + 1]);
                    var info = OpcodeRegistry.GetInfo(testOpcode, pkt.Direction);
                    if (info != null)
                    {
                        ImGui.TextColored(new Vector4(0.2f, 1, 0.4f, 1),
                            $"Possible opcode at offset {i}: 0x{testOpcode:X4} = {info.Name}");
                    }
                }
            }
        }
    }

    private void RenderMemoryBypassStatus()
    {
        ImGui.Separator();
        ImGui.TextColored(new Vector4(0.8f, 0.8f, 0.8f, 1), "Memory Bypass Status");

        int keyCount = PacketDecryptor.DiscoveredKeys.Count;
        bool hasKeys = keyCount > 0;

        if (hasKeys)
        {
            ImGui.TextColored(new Vector4(0.2f, 1, 0.2f, 1), $"Keys available: {keyCount}");
            ImGui.Text($"Successful decryptions: {PacketDecryptor.SuccessfulDecryptions}");
            ImGui.Text($"Failed attempts: {PacketDecryptor.FailedDecryptions}");
        }
        else
        {
            ImGui.TextColored(new Vector4(1, 0.3f, 0.3f, 1), "No keys available");
            ImGui.Text("Decryption bypass: FAILED");
            ImGui.TextColored(Theme.ColTextMuted, "Use Memory tab to find TLS keys");

            // Quick memory check
            var processes = Process.GetProcessesByName("Hytale");
            if (processes.Length > 0)
            {
                ImGui.TextColored(new Vector4(0.9f, 0.7f, 0.2f, 1),
                    $"Hytale running (PID: {processes[0].Id}) - Ready to attach");
            }
            else
            {
                ImGui.TextColored(new Vector4(0.5f, 0.5f, 0.5f, 1), "Hytale not running");
            }
        }
    }

    private void RenderQuicAnalysis(PacketLogEntry pkt)
    {
        ImGui.Separator();
        ImGui.TextColored(new Vector4(0.4f, 0.6f, 1, 1), "QUIC Protocol Analysis");

        if (pkt.QuicInfo != null)
        {
            ImGui.Text($"Header Type: {pkt.QuicInfo.HeaderType}");
            ImGui.Text($"Version: 0x{pkt.QuicInfo.Version:X8}");
            ImGui.Text($"Packet Number: {pkt.QuicInfo.PacketNumber}");

            if (pkt.QuicInfo.ClientConnectionId.Length > 0)
            {
                string cid = BitConverter.ToString(pkt.QuicInfo.ClientConnectionId.Take(8).ToArray());
                ImGui.Text($"Connection ID: {cid}");
            }
        }

        ImGui.TextColored(Theme.ColTextMuted, "QUIC uses TLS 1.3 encryption");
        ImGui.TextColored(Theme.ColTextMuted, "Payload is encrypted with session keys");
        ImGui.TextColored(Theme.ColTextMuted, "Need TLS keys from memory to decrypt");
    }

    private void RenderHexPreview(PacketLogEntry pkt)
    {
        ImGui.Separator();
        ImGui.TextColored(new Vector4(0.8f, 0.8f, 0.8f, 1), "Hex Preview");

        var hexLines = pkt.RawHexPreview.Split('-');
        for (int i = 0; i < hexLines.Length && i < 32; i += 8)
        {
            var line = string.Join(" ", hexLines.Skip(i).Take(8));
            var addr = (i * 3).ToString("X3");
            ImGui.TextColored(new Vector4(0.5f, 0.5f, 0.5f, 1), $"{addr}:");
            ImGui.SameLine();
            ImGui.Text(line);
        }
    }

    private void RenderGlobalAnalysis()
    {
        ImGui.Separator();
        ImGui.TextColored(new Vector4(0.4f, 0.8f, 1, 1), "Global Traffic Analysis");

        var packets = _state.PacketLog.GetLast(1000);

        if (!packets.Any())
        {
            ImGui.TextColored(Theme.ColTextMuted, "No packets captured yet");
            return;
        }

        // Timing analysis
        if (_showTimingAnalysis)
        {
            ImGui.TextColored(new Vector4(0.8f, 0.8f, 0.8f, 1), "Timing Patterns");

            var timing = packets
                .GroupBy(p => p.OpcodeDecimal)
                .Select(g => new {
                    Opcode = g.Key,
                    Name = g.First().OpcodeName,
                    Count = g.Count(),
                    AvgInterval = g.Count() > 1 ?
                        g.Zip(g.Skip(1), (a, b) => (b.Timestamp - a.Timestamp).TotalMilliseconds).Average() : 0,
                    TotalBytes = g.Sum(p => p.ByteLength),
                    IsEncrypted = g.All(p => p.EncryptionHint == "encrypted")
                })
                .OrderByDescending(x => x.Count)
                .Take(10);

            foreach (var t in timing)
            {
                string encMark = t.IsEncrypted ? "[E]" : "[C]";
                ImGui.Text($"0x{t.Opcode:X4} {encMark}: {t.Count} pkts, " +
                          $"{t.AvgInterval:F0}ms avg, {t.TotalBytes} bytes");
            }
        }

        // Memory status
        if (_showMemoryStatus)
        {
            ImGui.Separator();
            ImGui.TextColored(new Vector4(0.8f, 0.8f, 0.8f, 1), "Memory Scanner Status");

            int keys = PacketDecryptor.DiscoveredKeys.Count;
            ImGui.Text($"Keys found: {keys}");
            ImGui.Text($"Decryption attempts: {PacketDecryptor.FailedDecryptions}");

            if (keys == 0)
            {
                ImGui.TextColored(new Vector4(1, 0.6f, 0.2f, 1),
                    "TIP: Attach Memory Scanner to Hytale process");
                ImGui.TextColored(new Vector4(1, 0.6f, 0.2f, 1),
                    "Then click 'Find TLS Keys' or 'Enable SSL Keylog'");
            }
        }
    }

    private void ExportSinglePacket(PacketLogEntry pkt)
    {
        try
        {
            string filename = Path.Combine(_state.ExportDirectory,
                $"packet_{pkt.Timestamp:yyyyMMdd_HHmmss}_{pkt.OpcodeDecimal:X4}.txt");

            var sb = new System.Text.StringBuilder();
            sb.AppendLine("=== SINGLE PACKET EXPORT ===");
            sb.AppendLine($"Timestamp: {pkt.Timestamp:O}");
            sb.AppendLine($"Direction: {pkt.Direction}");
            sb.AppendLine($"Protocol: {(pkt.IsTcp ? "TCP" : "UDP/QUIC")}");
            sb.AppendLine($"Opcode: 0x{pkt.OpcodeDecimal:X4}");
            sb.AppendLine($"Name: {pkt.OpcodeName}");
            sb.AppendLine($"Size: {pkt.ByteLength} bytes");
            sb.AppendLine($"Encryption: {pkt.EncryptionHint}");
            sb.AppendLine($"Compression: {pkt.CompressionMethod}");
            sb.AppendLine();

            // Entropy
            try
            {
                var bytes = Convert.FromHexString(pkt.RawHexPreview.Replace("-", ""));
                double entropy = ByteUtils.CalculateEntropy(bytes);
                sb.AppendLine($"Entropy: {entropy:F2}");

                // Pattern analysis
                sb.AppendLine($"Unique bytes: {bytes.Distinct().Count()}");
                sb.AppendLine($"Null bytes: {bytes.Count(b => b == 0)}");
                sb.AppendLine($"ASCII bytes: {bytes.Count(b => b >= 32 && b <= 126)}");
            }
            catch { }

            sb.AppendLine();
            sb.AppendLine("=== RAW HEX ===");
            sb.AppendLine(pkt.RawHexPreview);

            File.WriteAllText(filename, sb.ToString());
            _state.AddInGameLog($"[EXPORT] Packet saved to {Path.GetFileName(filename)}");
        }
        catch (Exception ex)
        {
            _state.AddInGameLog($"[EXPORT] Error: {ex.Message}");
        }
    }

    private void ExportDetailedPacketLog()
    {
        try
        {
            string filename = Path.Combine(_state.ExportDirectory,
                $"detailed_analysis_{DateTime.Now:yyyyMMdd_HHmmss}.txt");

            var sb = new System.Text.StringBuilder();
            sb.AppendLine("=== HYFORCE DETAILED PACKET ANALYSIS ===");
            sb.AppendLine($"Export Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"Session Duration: {(_state.StartTime.HasValue ? (DateTime.Now - _state.StartTime.Value).ToString(@"hh\:mm\:ss") : "N/A")}");
            sb.AppendLine($"Total Packets: {_state.PacketLog.TotalPackets}");
            sb.AppendLine($"Total Bytes: {FormatBytes(_state.PacketLog.BytesSc + _state.PacketLog.BytesCs)}");
            sb.AppendLine($"Keys Available: {PacketDecryptor.DiscoveredKeys.Count}");
            sb.AppendLine();

            // Timing analysis
            sb.AppendLine("=== TIMING ANALYSIS ===");
            var packets = _state.PacketLog.GetAll().Take(2000).ToList();

            var timing = packets
                .GroupBy(p => p.OpcodeDecimal)
                .Select(g => new {
                    Opcode = g.Key,
                    Name = g.First().OpcodeName,
                    Count = g.Count(),
                    FirstSeen = g.Min(p => p.Timestamp),
                    LastSeen = g.Max(p => p.Timestamp),
                    AvgInterval = g.Count() > 1 ?
                        g.Zip(g.Skip(1), (a, b) => (b.Timestamp - a.Timestamp).TotalMilliseconds).Average() : 0,
                    MinInterval = g.Count() > 1 ?
                        g.Zip(g.Skip(1), (a, b) => (b.Timestamp - a.Timestamp).TotalMilliseconds).Min() : 0,
                    MaxInterval = g.Count() > 1 ?
                        g.Zip(g.Skip(1), (a, b) => (b.Timestamp - a.Timestamp).TotalMilliseconds).Max() : 0,
                    TotalBytes = g.Sum(p => p.ByteLength),
                    AvgSize = g.Average(p => p.ByteLength),
                    IsEncrypted = g.All(p => p.EncryptionHint == "encrypted"),
                    IsQuic = g.All(p => !p.IsTcp)
                })
                .OrderByDescending(x => x.Count);

            foreach (var t in timing)
            {
                sb.AppendLine();
                sb.AppendLine($"Opcode: 0x{t.Opcode:X4} ({t.Name})");
                sb.AppendLine($"  Count: {t.Count}");
                sb.AppendLine($"  Protocol: {(t.IsQuic ? "QUIC" : "TCP")}");
                sb.AppendLine($"  Encryption: {(t.IsEncrypted ? "Encrypted" : "Clear")}");
                sb.AppendLine($"  Total bytes: {t.TotalBytes}");
                sb.AppendLine($"  Avg size: {t.AvgSize:F1} bytes");
                sb.AppendLine($"  Avg interval: {t.AvgInterval:F2}ms");
                sb.AppendLine($"  Min/Max interval: {t.MinInterval:F2}ms / {t.MaxInterval:F2}ms");
                sb.AppendLine($"  Duration: {(t.LastSeen - t.FirstSeen).TotalSeconds:F1}s");
            }

            // Sample packets
            sb.AppendLine();
            sb.AppendLine("=== SAMPLE PACKETS (Last 50) ===");

            foreach (var pkt in packets.TakeLast(50))
            {
                sb.AppendLine();
                sb.AppendLine($"[{pkt.Timestamp:HH:mm:ss.fff}] {pkt.DirStr} 0x{pkt.OpcodeDecimal:X4} ({pkt.OpcodeName})");
                sb.AppendLine($"  Size: {pkt.ByteLength} bytes | {(pkt.IsTcp ? "TCP" : "QUIC")} | {pkt.EncryptionHint}");

                try
                {
                    var bytes = Convert.FromHexString(pkt.RawHexPreview.Replace("-", ""));
                    double entropy = ByteUtils.CalculateEntropy(bytes);
                    sb.AppendLine($"  Entropy: {entropy:F2}");

                    // Extract strings
                    var strings = ByteUtils.ExtractStrings(bytes, 4);
                    if (strings.Any())
                    {
                        sb.AppendLine($"  Strings: {string.Join(", ", strings.Take(5))}");
                    }
                }
                catch { }

                sb.AppendLine($"  HEX: {pkt.RawHexPreview}");
            }

            // Memory analysis
            sb.AppendLine();
            sb.AppendLine("=== MEMORY BYPASS ANALYSIS ===");
            sb.AppendLine($"Keys discovered: {PacketDecryptor.DiscoveredKeys.Count}");
            sb.AppendLine($"Successful decryptions: {PacketDecryptor.SuccessfulDecryptions}");
            sb.AppendLine($"Failed decryptions: {PacketDecryptor.FailedDecryptions}");

            foreach (var key in PacketDecryptor.DiscoveredKeys)
            {
                sb.AppendLine();
                sb.AppendLine($"Key Type: {key.Type}");
                sb.AppendLine($"Source: {key.Source}");
                sb.AppendLine($"Discovered: {key.DiscoveredAt}");
                if (key.MemoryAddress.HasValue)
                    sb.AppendLine($"Address: 0x{(ulong)key.MemoryAddress.Value:X}");
            }

            File.WriteAllText(filename, sb.ToString());
            _state.AddInGameLog($"[EXPORT] Full analysis saved: {Path.GetFileName(filename)}");

            // Try to open folder
            try
            {
                System.Diagnostics.Process.Start("explorer.exe", _state.ExportDirectory);
            }
            catch { }
        }
        catch (Exception ex)
        {
            _state.AddInGameLog($"[EXPORT] Error: {ex.Message}");
        }
    }

    private string FormatBytes(long bytes)
    {
        string[] suffixes = { "B", "KB", "MB", "GB" };
        int i = 0;
        double d = bytes;
        while (d >= 1024 && i < suffixes.Length - 1)
        {
            d /= 1024;
            i++;
        }
        return $"{d:F2} {suffixes[i]}";
    }
}