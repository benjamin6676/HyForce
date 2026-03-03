// FILE: Tabs/PacketFeedTab.cs - ENHANCED: Opcode exclusion, better filtering, performance
using HyForce.Core;
using HyForce.Data;
using HyForce.Networking;
using HyForce.Protocol;
using HyForce.UI;
using HyForce.Utils;
using ImGuiNET;
using System.Numerics;
using System.Diagnostics;
using System.Buffers.Binary;

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

    // ENHANCED: Opcode exclusion system
    private HashSet<ushort> _excludedOpcodes = new();
    private bool _showOpcodeFilterPanel = false;
    private string _opcodeFilterInput = "";
    private bool _excludeQuicHandshake = true; // Auto-hide 0x0000 spam

    // Analysis toggles
    private bool _showEntropyDetails = true;
    private bool _showTimingAnalysis = true;
    private bool _showMemoryStatus = true;

    // Performance throttling
    private DateTime _lastUiUpdate = DateTime.MinValue;
    private const int UI_UPDATE_MS = 100;
    private List<PacketLogEntry> _cachedPackets = new();
    private DateTime _lastPacketCacheUpdate = DateTime.MinValue;
    private int _frameCounter = 0;
    private const int SKIP_FRAMES = 2;

    // Quick preset filters
    private readonly Dictionary<string, ushort[]> _filterPresets = new()
    {
        ["QUIC Handshake Noise"] = new[] { (ushort)0x0000 },
        ["Keep-Alive"] = new[] { (ushort)0x05, (ushort)0x06 }, // Ping/Pong
        ["Movement"] = new[] { (ushort)0x6C },
        ["All Registry"] = Enumerable.Range(0x28, 0x1B).Select(i => (ushort)i).ToArray()
    };

    public PacketFeedTab(AppState state)
    {
        _state = state;

        // Auto-exclude QUIC handshake noise on startup
        if (_excludeQuicHandshake)
        {
            _excludedOpcodes.Add(0x0000);
        }
    }

    public void Render()
    {
        var windowSize = ImGui.GetContentRegionAvail();
        _frameCounter++;
        bool shouldSkipRender = (_frameCounter % (SKIP_FRAMES + 1)) != 0;
        var now = DateTime.Now;
        bool shouldUpdateCache = (now - _lastPacketCacheUpdate).TotalMilliseconds > UI_UPDATE_MS;

        float toolbarHeight = _showOpcodeFilterPanel ? 140 : 70;
        float remainingHeight = Math.Max(0, windowSize.Y - toolbarHeight - 10);

        RenderToolbar();
        ImGui.Separator();

        // ENHANCED: Collapsible opcode filter panel
        if (_showOpcodeFilterPanel)
        {
            RenderOpcodeFilterPanel();
            ImGui.Separator();
        }

        var listWidth = Math.Min(windowSize.X * 0.6f, windowSize.X - 320);
        var detailsWidth = Math.Max(0, windowSize.X - listWidth - 20);

        if (shouldUpdateCache)
        {
            _cachedPackets = GetFilteredPackets();
            _lastPacketCacheUpdate = now;
        }

        ImGui.BeginChild("PacketList", new Vector2(listWidth, remainingHeight), ImGuiChildFlags.Borders);
        RenderPacketList(shouldSkipRender);
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

        // ENHANCED: Toggle opcode filter panel
        if (ImGui.Button(_showOpcodeFilterPanel ? "Hide Filters" : "Opcode Filters", new Vector2(100, buttonHeight)))
        {
            _showOpcodeFilterPanel = !_showOpcodeFilterPanel;
        }

        ImGui.SameLine();
        if (ImGui.Button("Clear", new Vector2(60, buttonHeight)))
        {
            _state.PacketLog.Clear();
            _cachedPackets.Clear();
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

    // ENHANCED: New opcode filter panel
    private void RenderOpcodeFilterPanel()
    {
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.12f, 0.12f, 0.15f, 1f));
        ImGui.BeginChild("##opcode_filters", new Vector2(0, 60), ImGuiChildFlags.Borders);

        ImGui.TextColored(Theme.ColAccent, "Hide Specific Opcodes:");
        ImGui.SameLine();

        // Quick presets
        foreach (var preset in _filterPresets)
        {
            bool isActive = preset.Value.All(o => _excludedOpcodes.Contains(o));
            if (isActive)
                ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.8f, 0.3f, 0.2f, 1f));

            if (ImGui.Button(preset.Key, new Vector2(0, 22)))
            {
                if (isActive)
                {
                    // Remove all
                    foreach (var o in preset.Value) _excludedOpcodes.Remove(o);
                }
                else
                {
                    // Add all
                    foreach (var o in preset.Value) _excludedOpcodes.Add(o);
                }
            }

            if (isActive)
                ImGui.PopStyleColor();

            ImGui.SameLine();
        }

        // Manual input
        ImGui.SetNextItemWidth(80);
        ImGui.InputText("##opcode_input", ref _opcodeFilterInput, 6, ImGuiInputTextFlags.CharsHexadecimal);
        ImGui.SameLine();
        if (ImGui.Button("Hide", new Vector2(50, 22)) && ushort.TryParse(_opcodeFilterInput, System.Globalization.NumberStyles.HexNumber, null, out ushort hideOp))
        {
            _excludedOpcodes.Add(hideOp);
            _opcodeFilterInput = "";
        }
        ImGui.SameLine();
        if (ImGui.Button("Show", new Vector2(50, 22)) && ushort.TryParse(_opcodeFilterInput, System.Globalization.NumberStyles.HexNumber, null, out ushort showOp))
        {
            _excludedOpcodes.Remove(showOp);
            _opcodeFilterInput = "";
        }

        // Show current exclusions
        if (_excludedOpcodes.Any())
        {
            ImGui.SameLine();
            ImGui.Text("| Active filters: ");
            foreach (var op in _excludedOpcodes.Take(5))
            {
                ImGui.SameLine();
                ImGui.TextColored(Theme.ColDanger, $"0x{op:X4}");
                if (ImGui.IsItemClicked())
                {
                    _excludedOpcodes.Remove(op);
                }
                if (ImGui.IsItemHovered())
                    ImGui.SetTooltip("Click to remove");
            }
            if (_excludedOpcodes.Count > 5)
            {
                ImGui.SameLine();
                ImGui.TextColored(Theme.ColTextMuted, $"+{_excludedOpcodes.Count - 5} more");
            }
        }

        ImGui.EndChild();
        ImGui.PopStyleColor();
    }

    private void RenderPacketList(bool skipExpensiveOps)
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

            var packets = _cachedPackets;
            int maxRender = skipExpensiveOps ? 50 : 200;
            var packetsToRender = packets.Take(maxRender).ToList();

            foreach (var pkt in packetsToRender)
            {
                ImGui.TableNextRow();
                bool isSelected = _selectedPacket == pkt;
                ImGui.TableSetColumnIndex(0);

                string selectableId = $"##pkt_{pkt.Timestamp.Ticks}_{pkt.GetHashCode()}";
                if (ImGui.Selectable(selectableId, isSelected, ImGuiSelectableFlags.SpanAllColumns))
                {
                    _selectedPacket = pkt;
                }

                if (isSelected)
                {
                    ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg0,
                        ImGui.ColorConvertFloat4ToU32(new Vector4(0.2f, 0.4f, 0.8f, 0.4f)));
                }

                // ENHANCED: Right-click context menu with hide option
                if (ImGui.IsItemClicked(ImGuiMouseButton.Right))
                {
                    ImGui.OpenPopup($"ctx_{pkt.GetHashCode()}");
                }

                if (ImGui.BeginPopup($"ctx_{pkt.GetHashCode()}"))
                {
                    if (ImGui.MenuItem("Hide This Opcode"))
                    {
                        _excludedOpcodes.Add(pkt.OpcodeDecimal);
                    }
                    if (ImGui.MenuItem("Copy Hex"))
                    {
                        try { TextCopy.ClipboardService.SetText(pkt.RawHexPreview); } catch { }
                    }
                    if (ImGui.MenuItem("Export This Packet"))
                    {
                        ExportSinglePacket(pkt);
                    }
                    ImGui.EndPopup();
                }

                ImGui.SameLine();
                ImGui.Text(pkt.Timestamp.ToString("HH:mm:ss.fff"));

                ImGui.TableSetColumnIndex(1);
                var dirColor = pkt.Direction == PacketDirection.ClientToServer
                    ? new Vector4(0.3f, 0.8f, 0.3f, 1)
                    : new Vector4(0.8f, 0.5f, 0.2f, 1);
                ImGui.TextColored(dirColor, pkt.DirStr);

                ImGui.TableSetColumnIndex(2);
                ushort opcode = pkt.IsTcp ? pkt.OpcodeDecimal : (ushort)0;
                if (pkt.IsTcp && pkt.RawBytes.Length >= 4)
                {
                    opcode = (ushort)BinaryPrimitives.ReadUInt32LittleEndian(pkt.RawBytes.AsSpan(4, 4));
                }
                var isKnown = OpcodeRegistry.IsKnownOpcode(opcode, pkt.Direction);
                var opcodeColor = isKnown ? new Vector4(1, 1, 1, 1) : new Vector4(1, 0.3f, 0.3f, 1);

                // ENHANCED: Show excluded opcodes with strikethrough color
                if (_excludedOpcodes.Contains(opcode))
                    opcodeColor = new Vector4(0.5f, 0.5f, 0.5f, 1);

                ImGui.TextColored(opcodeColor, $"0x{opcode:X4}");

                ImGui.TableSetColumnIndex(3);
                var info = OpcodeRegistry.GetInfo(opcode, pkt.Direction);
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

            if (packets.Count > maxRender)
            {
                ImGui.TableNextRow();
                ImGui.TableSetColumnIndex(0);
                ImGui.TextColored(Theme.ColTextMuted, $"... {packets.Count - maxRender} more");
            }

            ImGui.EndTable();
        }

        if (_autoScroll && ImGui.GetScrollY() < ImGui.GetScrollMaxY())
            ImGui.SetScrollHereY(1.0f);
    }

    // ENHANCED: Updated filtering to include opcode exclusion
    private List<PacketLogEntry> GetFilteredPackets()
    {
        var packets = _state.PacketLog.GetLast(200);
        return packets.Where(p =>
        {
            // ENHANCED: Check excluded opcodes first
            if (_excludedOpcodes.Contains(p.OpcodeDecimal))
                return false;

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

    // ... (keep existing RenderPacketDetails, RenderDeepEncryptionAnalysis, etc.)
    // Include all the original methods from your file here

    private void RenderPacketDetails()
    {
        if (_selectedPacket == null)
        {
            ImGui.TextColored(Theme.ColTextMuted, "Select a packet to view details");
            RenderGlobalAnalysis();
            return;
        }

        var pkt = _selectedPacket;
        uint packetId = 0;
        uint packetLength = 0;

        if (pkt.IsTcp && pkt.RawBytes.Length >= 8)
        {
            packetLength = BinaryPrimitives.ReadUInt32LittleEndian(pkt.RawBytes.AsSpan(0, 4));
            packetId = BinaryPrimitives.ReadUInt32LittleEndian(pkt.RawBytes.AsSpan(4, 4));
        }

        ImGui.TextColored(new Vector4(0.4f, 0.8f, 1, 1), pkt.OpcodeName);
        ImGui.SameLine();
        ImGui.TextColored(Theme.ColTextMuted, $"0x{packetId:X4} (LE)");
        ImGui.Separator();

        ImGui.Text("Direction: "); ImGui.SameLine();
        var dirColor = pkt.Direction == PacketDirection.ServerToClient
            ? new Vector4(0.3f, 0.8f, 0.3f, 1)
            : new Vector4(0.8f, 0.5f, 0.2f, 1);
        ImGui.TextColored(dirColor, pkt.Direction.ToString());

        ImGui.Text($"Size: {pkt.ByteLength} bytes");
        if (pkt.IsTcp && packetLength > 0)
        {
            ImGui.Text($"Packet Length Field: {packetLength} bytes");
        }
        ImGui.Text($"Protocol: {(pkt.IsTcp ? "TCP" : "UDP/QUIC")}");

        RenderDeepEncryptionAnalysis(pkt);
        RenderMemoryBypassStatus();

        if (!pkt.IsTcp && pkt.QuicInfo != null)
        {
            RenderQuicAnalysis(pkt);
        }

        RenderHexPreview(pkt);

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

        // ENHANCED: Quick hide button
        ImGui.SameLine();
        if (ImGui.Button("Hide This Opcode", new Vector2(120, 28)))
        {
            _excludedOpcodes.Add(pkt.OpcodeDecimal);
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
            var hexString = pkt.RawHexPreview.Replace("-", "").Replace(" ", "");
            if (hexString.Length % 2 == 0 && hexString.Length > 0 && hexString.Length <= 4096)
            {
                bytes = Convert.FromHexString(hexString);
                fullEntropy = ByteUtils.CalculateEntropy(bytes);

                if (bytes.Length > 28)
                {
                    headerEntropy = ByteUtils.CalculateEntropy(bytes.Take(28).ToArray());
                    payloadEntropy = ByteUtils.CalculateEntropy(bytes.Skip(28).ToArray());
                }
            }
        }
        catch { }

        if (pkt.QuicInfo != null)
        {
            ImGui.TextColored(new Vector4(0.4f, 0.8f, 1, 1),
                $"QUIC Header: {pkt.QuicInfo.HeaderType}");

            if (!pkt.QuicInfo.IsLongHeader)
            {
                ImGui.TextColored(new Vector4(1, 0.6f, 0.2f, 1),
                    "⚠ Short Header - 1-RTT encrypted data");
                ImGui.TextColored(Theme.ColTextMuted,
                    "Requires correct packet number and key derivation");

                if (PacketDecryptor.DiscoveredKeys.Count > 0)
                {
                    var client1rtt = PacketDecryptor.DiscoveredKeys
                        .Where(k => k.Type == PacketDecryptor.EncryptionType.QUIC_Client1RTT)
                        .Count();
                    var server1rtt = PacketDecryptor.DiscoveredKeys
                        .Where(k => k.Type == PacketDecryptor.EncryptionType.QUIC_Server1RTT)
                        .Count();

                    ImGui.Text($"Available 1-RTT keys: Client={client1rtt}, Server={server1rtt}");
                }
            }
            else
            {
                ImGui.TextColored(new Vector4(0.2f, 0.8f, 0.4f, 1),
                    "✓ Long Header - Handshake/Initial traffic");
            }

            ImGui.Text($"Packet Number Length: {pkt.QuicInfo.PacketNumberLength} bytes");
        }

        ImGui.Text($"Full Packet Entropy: {fullEntropy:F2}");
        if (bytes != null && bytes.Length > 28)
        {
            ImGui.Text($"Header (28B): {headerEntropy:F2}");
            ImGui.Text($"Payload (rest): {payloadEntropy:F2}");

            ImGui.ProgressBar((float)(fullEntropy / 8.0), new Vector2(200, 15), "Full");
            ImGui.ProgressBar((float)(headerEntropy / 8.0), new Vector2(200, 15), "Header");
            ImGui.ProgressBar((float)(payloadEntropy / 8.0), new Vector2(200, 15), "Payload");
        }

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

        if (pkt.QuicInfo != null && !pkt.QuicInfo.IsLongHeader && PacketDecryptor.SuccessfulDecryptions == 0)
        {
            ImGui.Spacing();
            ImGui.TextColored(new Vector4(0.9f, 0.7f, 0.2f, 1),
                "Why decryption fails:");
            ImGui.BulletText("QUIC short headers use 1-RTT keys derived from TLS secrets");
            ImGui.BulletText("Your SSLKEYLOGFILE has TLS secrets, but derivation may be wrong");
            ImGui.BulletText("Hytale may use custom Netty QUIC codec with different key schedule");
            ImGui.BulletText("Packet number reconstruction from header protection failed");

            ImGui.TextColored(Theme.ColTextMuted,
                "Try: Ensure SSLKEYLOGFILE is set BEFORE Hytale starts");
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
            ImGui.TextColored(new Vector4(0.2f, 1, 0.2f, 1), $"✓ Keys available: {keyCount}");
            ImGui.Text($"Successful decryptions: {PacketDecryptor.SuccessfulDecryptions}");
            ImGui.Text($"Failed attempts: {PacketDecryptor.FailedDecryptions}");

            var keyTypes = PacketDecryptor.DiscoveredKeys
                .GroupBy(k => k.Type)
                .Select(g => $"{g.Key}: {g.Count()}");
            ImGui.TextColored(Theme.ColTextMuted, string.Join(", ", keyTypes));
        }
        else
        {
            ImGui.TextColored(new Vector4(1, 0.3f, 0.3f, 1), "✗ No keys available");
            ImGui.Text("Decryption bypass: FAILED");
            ImGui.TextColored(Theme.ColTextMuted, "Use Memory tab to find TLS keys");

            var processes = Process.GetProcessesByName("Hytale");
            if (processes.Length > 0)
            {
                ImGui.TextColored(new Vector4(0.9f, 0.7f, 0.2f, 1),
                    $"⚠ Hytale running (PID: {processes[0].Id}) - Ready to attach");
            }
            else
            {
                ImGui.TextColored(new Vector4(0.5f, 0.5f, 0.5f, 1), "○ Hytale not running");
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

        ImGui.TextColored(Theme.ColTextMuted, "Hytale uses Netty QUIC codec (incubator)");
        ImGui.TextColored(Theme.ColTextMuted, "TLS 1.3 with custom frame encoding");
        ImGui.TextColored(Theme.ColTextMuted, "Payload encrypted with AES-128-GCM or AES-256-GCM");
    }

    private void RenderHexPreview(PacketLogEntry pkt)
    {
        ImGui.Separator();
        ImGui.TextColored(new Vector4(0.8f, 0.8f, 0.8f, 1), "Hex Preview");

        var hexLines = pkt.RawHexPreview.Split('-');
        int maxLines = Math.Min(hexLines.Length, 16);

        for (int i = 0; i < maxLines; i += 8)
        {
            var line = string.Join(" ", hexLines.Skip(i).Take(8));
            var addr = (i * 3).ToString("X3");
            ImGui.TextColored(new Vector4(0.5f, 0.5f, 0.5f, 1), $"{addr}:");
            ImGui.SameLine();
            ImGui.Text(line);
        }

        if (hexLines.Length > maxLines)
        {
            ImGui.TextColored(Theme.ColTextMuted, $"... {hexLines.Length - maxLines} more bytes");
        }
    }

    private void RenderGlobalAnalysis()
    {
        ImGui.Separator();
        ImGui.TextColored(new Vector4(0.4f, 0.8f, 1, 1), "Global Traffic Analysis");

        var packets = _state.PacketLog.GetLast(500);

        if (!packets.Any())
        {
            ImGui.TextColored(Theme.ColTextMuted, "No packets captured yet");
            return;
        }

        if (_showTimingAnalysis && packets.Count < 1000)
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

            if (pkt.IsTcp && pkt.RawBytes.Length >= 8)
            {
                uint len = BinaryPrimitives.ReadUInt32LittleEndian(pkt.RawBytes.AsSpan(0, 4));
                uint id = BinaryPrimitives.ReadUInt32LittleEndian(pkt.RawBytes.AsSpan(4, 4));
                sb.AppendLine($"Length Field: {len} (LE)");
                sb.AppendLine($"Packet ID: 0x{id:X8} (LE)");
            }
            else
            {
                sb.AppendLine($"Opcode: 0x{pkt.OpcodeDecimal:X4}");
            }

            sb.AppendLine($"Name: {pkt.OpcodeName}");
            sb.AppendLine($"Size: {pkt.ByteLength} bytes");
            sb.AppendLine($"Encryption: {pkt.EncryptionHint}");
            sb.AppendLine($"Compression: {pkt.CompressionMethod}");
            sb.AppendLine();

            try
            {
                var bytes = Convert.FromHexString(pkt.RawHexPreview.Replace("-", ""));
                double entropy = ByteUtils.CalculateEntropy(bytes);
                sb.AppendLine($"Entropy: {entropy:F2}");
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
            var packets = _state.PacketLog.GetAll().Take(1000).ToList();

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