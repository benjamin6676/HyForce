// FILE: Tabs/PacketFeedTab.cs
// Layout: full-width packet table (# DIR PROTO OPCODE NAME SIZE STATUS CATEGORY)
//         + floating inspector popup window (detailed analysis, hex dump, entropy, strings)
//         + clean filter toolbar matching preview v2
using HyForce.Core;
using HyForce.Data;
using HyForce.Networking;
using HyForce.Protocol;
using HyForce.UI;
using HyForce.Utils;
using ImGuiNET;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Numerics;

namespace HyForce.Tabs;

public class PacketFeedTab : ITab
{
    public string Name => "Packets";

    // -- Core state ------------------------------------------------------------
    private readonly AppState         _state;
    private PacketLogEntry?           _selectedPacket;

    // Filter flags
    private string  _filterText       = "";
    private bool    _filterCS         = false;   // show only C->S
    private bool    _filterSC         = false;   // show only S->C
    private bool    _filterEncrypted  = false;   // show only encrypted
    private bool    _showOnlyUnknown  = false;
    private bool    _filterRegistry   = false;
    private bool    _showOpcodePanel  = false;
    private string  _opcodeFilterInput = "";
    private bool    _excludeHandshake = true;
    private HashSet<ushort> _excluded  = new();

    // Cache
    private List<PacketLogEntry> _cached        = new();
    private DateTime             _lastCache     = DateTime.MinValue;
    private const int            CACHE_MS       = 80;
    private int                  _frame;

    // Inspector popup state
    private bool    _showInspector   = false;
    private int     _inspSubTab      = 0;  // 0=Overview 1=Hex 2=Entropy 3=Strings 4=QUIC 5=Differ

    // Differ slots
    private PacketLogEntry? _differA, _differB;

    // Quick opcode presets
    private readonly Dictionary<string, ushort[]> _presets = new()
    {
        ["Handshake"]  = new[] { (ushort)0x0000 },
        ["Keep-Alive"] = new[] { (ushort)0x05, (ushort)0x06 },
        ["Movement"]   = new[] { (ushort)0x6C },
    };

    public PacketFeedTab(AppState state)
    {
        _state     = state;
        if (_excludeHandshake) _excluded.Add(0x0000);
    }

    // =========================================================================
    // RENDER ENTRY
    // =========================================================================
    public void Render()
    {
        _frame++;
        var now = DateTime.Now;
        if ((now - _lastCache).TotalMilliseconds > CACHE_MS)
        {
            _cached = BuildFilteredList();
            _lastCache = now;
        }

        var avail = ImGui.GetContentRegionAvail();

        RenderToolbar();
        if (_showOpcodePanel) RenderOpcodePanel();
        ImGui.Separator();

        float usedH   = _showOpcodePanel ? 100f : 62f;
        float tableH  = avail.Y - usedH - 32f;

        ImGui.BeginChild("##feed_list", new Vector2(0, tableH), ImGuiChildFlags.None);
        RenderPacketTable();
        ImGui.EndChild();

        RenderBottomBar();

        // -- Floating inspector popup -----------------------------------------
        if (_showInspector && _selectedPacket != null)
            RenderInspectorPopup();
    }

    // =========================================================================
    // TOOLBAR
    // =========================================================================
    private void RenderToolbar()
    {
        float bh = 24f;

        // Search box
        ImGui.PushStyleColor(ImGuiCol.FrameBg, Theme.ColBg3);
        ImGui.SetNextItemWidth(160f);
        ImGui.InputText("##filter", ref _filterText, 64);
        ImGui.PopStyleColor();
        if (ImGui.IsItemHovered()) ImGui.SetTooltip("Filter by opcode hex / name / direction");
        ImGui.SameLine(0, 8);

        // Filter toggle buttons (only lit when active)
        FilterToggle("C>S",      ref _filterCS,        bh, Theme.ColSuccess);       ImGui.SameLine(0, 4);
        FilterToggle("S>C",      ref _filterSC,        bh, Theme.ColAccent);        ImGui.SameLine(0, 4);
        FilterToggle("Encrypted",     ref _filterEncrypted, bh, Theme.ColDanger);        ImGui.SameLine(0, 4);
        FilterToggle("Unknown",       ref _showOnlyUnknown, bh, Theme.ColWarn);          ImGui.SameLine(0, 4);
        FilterToggle("Registry",      ref _filterRegistry,  bh, Theme.ColCatRegistry);   ImGui.SameLine(0, 4);

        // Filters panel toggle
        ImGui.PushStyleColor(ImGuiCol.Button, _showOpcodePanel ? Theme.ColAccentMid : Theme.ColBg3);
        ImGui.PushStyleColor(ImGuiCol.Text,   _showOpcodePanel ? Theme.ColAccent : Theme.ColTextMuted);
        if (ImGui.Button("Filters", new Vector2(58f, bh))) _showOpcodePanel = !_showOpcodePanel;
        ImGui.PopStyleColor(2);

        // Right: LIVE indicator + hotkey buttons
        float rightW = 290f;
        ImGui.SameLine(ImGui.GetContentRegionAvail().X + ImGui.GetCursorPosX() - rightW);

        bool live = _state.IsRunning;
        ImGui.PushStyleColor(ImGuiCol.Text, live ? Theme.ColSuccess : Theme.ColDanger);
        ImGui.Text(live ? ">> LIVE" : "-- IDLE");
        ImGui.PopStyleColor();
        if (ImGui.IsItemHovered()) ImGui.SetTooltip("Proxy running status");
        ImGui.SameLine(0, 10);

        long total = _state.PacketLog.TotalPackets;
        ImGui.TextColored(total > 0 ? new System.Numerics.Vector4(0.2f,1f,0.4f,1f) : Theme.ColTextMuted,
            $"{total:N0} pkts");
        ImGui.SameLine();
        ImGui.TextColored(Theme.ColTextMuted, $"| UDP:{_state.PacketLog.PacketsUdp:N0} TCP:{_state.PacketLog.PacketsTcp:N0}");
        ImGui.SameLine(0, 10);

        var acBg = new Vector4(Theme.ColAccent.X*.28f, Theme.ColAccent.Y*.28f, Theme.ColAccent.Z*.28f, 1f);
        ImGui.PushStyleColor(ImGuiCol.Button,  acBg);
        ImGui.PushStyleColor(ImGuiCol.Text,    Theme.ColAccent);
        ImGui.PushStyleColor(ImGuiCol.Border,  Theme.ColAccent with { W = .7f });
        if (ImGui.Button("F8: Capture", new Vector2(90f, bh))) { /* hotkey hint */ }
        ImGui.PopStyleColor(3);
        ImGui.SameLine(0, 4);

        var recBg = Theme.Current?.TabBg ?? Theme.ColBg3;
        ImGui.PushStyleColor(ImGuiCol.Button, recBg);
        ImGui.PushStyleColor(ImGuiCol.Text,   Theme.ColTextMuted);
        if (ImGui.Button("F9: Record",  new Vector2(82f, bh))) { /* hotkey hint */ }
        ImGui.PopStyleColor(2);
    }

    // =========================================================================
    // OPCODE EXCLUSION PANEL
    // =========================================================================
    private void RenderOpcodePanel()
    {
        ImGui.PushStyleColor(ImGuiCol.ChildBg, Theme.ColBg3);
        ImGui.BeginChild("##opc_panel", new Vector2(0, 54), ImGuiChildFlags.Borders);

        ImGui.TextColored(Theme.ColAccent, "Hide opcodes:"); ImGui.SameLine();
        foreach (var (k, v) in _presets)
        {
            bool active = v.All(o => _excluded.Contains(o));
            if (active) ImGui.PushStyleColor(ImGuiCol.Button, Theme.ColDanger);
            if (ImGui.Button(k, new Vector2(0, 20)))
            {
                if (active) foreach (var o in v) _excluded.Remove(o);
                else        foreach (var o in v) _excluded.Add(o);
            }
            if (active) ImGui.PopStyleColor();
            ImGui.SameLine();
        }

        ImGui.SetNextItemWidth(70);
        ImGui.InputText("##opchex", ref _opcodeFilterInput, 6, ImGuiInputTextFlags.CharsHexadecimal);
        ImGui.SameLine();
        if (ImGui.Button("Hide##o", new Vector2(40, 20)) && ParseHex(_opcodeFilterInput, out ushort ho))
        { _excluded.Add(ho); _opcodeFilterInput = ""; }
        ImGui.SameLine();
        if (ImGui.Button("Show##o", new Vector2(40, 20)) && ParseHex(_opcodeFilterInput, out ushort so))
        { _excluded.Remove(so); _opcodeFilterInput = ""; }

        if (_excluded.Any())
        {
            ImGui.SameLine();
            ImGui.TextColored(Theme.ColTextMuted, " hiding:");
            foreach (var op in _excluded.Take(6))
            {
                ImGui.SameLine();
                ImGui.TextColored(Theme.ColDanger, $"0x{op:X4}");
                if (ImGui.IsItemClicked()) _excluded.Remove(op);
                if (ImGui.IsItemHovered()) ImGui.SetTooltip("Click to unhide");
            }
            if (_excluded.Count > 6) { ImGui.SameLine(); ImGui.TextColored(Theme.ColTextMuted, $"+{_excluded.Count - 6}"); }
        }

        ImGui.EndChild();
        ImGui.PopStyleColor();
    }

    // =========================================================================
    // PACKET TABLE  --  # | DIR | PROTO | OPCODE | NAME | SIZE | STATUS | CATEGORY
    // =========================================================================
    private void RenderPacketTable()
    {
        var flags = ImGuiTableFlags.Resizable    | ImGuiTableFlags.ScrollY      |
                    ImGuiTableFlags.BordersInnerV | ImGuiTableFlags.RowBg        |
                    ImGuiTableFlags.SizingStretchProp;

        var avail = ImGui.GetContentRegionAvail();
        if (!ImGui.BeginTable("##pkttbl", 8, flags, avail)) return;

        ImGui.TableSetupScrollFreeze(0, 1);
        ImGui.TableSetupColumn("#",        ImGuiTableColumnFlags.WidthFixed,   44f);
        ImGui.TableSetupColumn("DIR",      ImGuiTableColumnFlags.WidthFixed,   42f);
        ImGui.TableSetupColumn("PROTO",    ImGuiTableColumnFlags.WidthFixed,   52f);
        ImGui.TableSetupColumn("OPCODE",   ImGuiTableColumnFlags.WidthFixed,   68f);
        ImGui.TableSetupColumn("NAME",     ImGuiTableColumnFlags.WidthStretch,  1f);
        ImGui.TableSetupColumn("SIZE",     ImGuiTableColumnFlags.WidthFixed,   52f);
        ImGui.TableSetupColumn("STATUS",   ImGuiTableColumnFlags.WidthFixed,   78f);
        ImGui.TableSetupColumn("CATEGORY", ImGuiTableColumnFlags.WidthFixed,   90f);
        ImGui.TableHeadersRow();

        long total = _state.PacketLog.TotalPackets;
        int  limit = 300;
        var  render = _cached.Take(limit).ToList();

        for (int i = 0; i < render.Count; i++)
        {
            var  pkt   = render[i];
            var  op    = pkt.OpcodeDecimal;
            bool enc   = pkt.EncryptionHint == "encrypted";
            bool cs    = pkt.Direction == PacketDirection.ClientToServer;
            var  cat   = GetCategory(pkt);
            var  cc    = CategoryColor(cat);
            bool isSel = _selectedPacket == pkt;

            ImGui.TableNextRow();

            // Row bg tints
            if (isSel)
                ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg0,
                    ImGui.ColorConvertFloat4ToU32(new Vector4(cc.X*.25f, cc.Y*.25f, cc.Z*.25f, .55f)));
            else if (enc)
                ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg0,
                    ImGui.ColorConvertFloat4ToU32(new Vector4(.05f,.05f,.05f,.9f)));

            // -- Col 0: row # with category strip ----------------------------
            ImGui.TableSetColumnIndex(0);
            if (ImGui.Selectable($"##sel{i}", isSel,
                ImGuiSelectableFlags.SpanAllColumns | ImGuiSelectableFlags.AllowOverlap,
                new Vector2(0, 17)))
            {
                _selectedPacket = pkt;
                if (!_showInspector) _showInspector = true;
            }

            // Right-click context menu
            if (ImGui.IsItemClicked(ImGuiMouseButton.Right))
                ImGui.OpenPopup($"##ctx{i}");
            if (ImGui.BeginPopup($"##ctx{i}"))
            {
                ImGui.TextColored(Theme.ColAccent, $"0x{op:X4}  {pkt.OpcodeName}");
                ImGui.Separator();
                if (ImGui.MenuItem("Inspect Packet"))   { _selectedPacket = pkt; _showInspector = true; }
                if (ImGui.MenuItem("Set as Differ A"))  _differA = pkt;
                if (ImGui.MenuItem("Set as Differ B"))  _differB = pkt;
                ImGui.Separator();
                if (ImGui.MenuItem("Hide This Opcode")) _excluded.Add(op);
                if (ImGui.MenuItem("Copy Hex"))
                    try { TextCopy.ClipboardService.SetText(pkt.RawHexPreview); } catch { }
                if (ImGui.MenuItem("Export Packet"))    ExportPacket(pkt);
                ImGui.Separator();
                ImGui.TextColored(cc, $"[#] {cat}");
                ImGui.EndPopup();
            }

            // Draw the actual cells after the invisible selectable
            ImGui.SameLine();
            ImGui.TextColored(cc, "|");   // left half-block as category strip
            ImGui.SameLine(0, 2);
            long rowNum = total - (_cached.Count - 1 - i);
            ImGui.TextColored(Theme.ColTextMuted, $"{rowNum}");

            // -- Col 1: DIR ---------------------------------------------------
            ImGui.TableSetColumnIndex(1);
            ImGui.TextColored(cs ? Theme.ColSuccess : Theme.ColAccent, cs ? "C>S" : "S>C");

            // -- Col 2: PROTO -------------------------------------------------
            ImGui.TableSetColumnIndex(2);
            ImGui.TextColored(pkt.IsTcp ? Theme.ColInfo : Theme.ColAccentDim,
                pkt.IsTcp ? "TCP" : "QUIC");

            // -- Col 3: OPCODE ------------------------------------------------
            ImGui.TableSetColumnIndex(3);
            ImGui.TextColored(enc ? Theme.ColTextMuted : cc, $"0x{op:X4}");

            // -- Col 4: NAME --------------------------------------------------
            ImGui.TableSetColumnIndex(4);
            string name = pkt.OpcodeName;
            if (name.Length > 30) name = name[..27] + "...";
            ImGui.TextColored(enc ? Theme.ColTextMuted : Theme.Current?.Text ?? Vector4.One, name);

            // -- Col 5: SIZE --------------------------------------------------
            ImGui.TableSetColumnIndex(5);
            ImGui.TextColored(Theme.ColTextMuted, $"{pkt.ByteLength}B");

            // -- Col 6: STATUS pill -------------------------------------------
            ImGui.TableSetColumnIndex(6);
            RenderStatusBadge(pkt);

            // -- Col 7: CATEGORY pill -----------------------------------------
            ImGui.TableSetColumnIndex(7);
            RenderCategoryPill(cat, cc);
        }

        if (_cached.Count > limit)
        {
            ImGui.TableNextRow();
            ImGui.TableSetColumnIndex(4);
            ImGui.TextColored(Theme.ColTextMuted, $"({_cached.Count - limit} more...)");
        }

        if (ImGui.GetScrollY() >= ImGui.GetScrollMaxY() - 4)
            ImGui.SetScrollHereY(1f);

        ImGui.EndTable();
    }

    // =========================================================================
    // BOTTOM BAR
    // =========================================================================
    private void RenderBottomBar()
    {
        var   pkt = _selectedPacket;
        float bh  = 22f;

        ImGui.Separator();
        ImGui.PushStyleColor(ImGuiCol.ChildBg, Theme.ColBg3);
        ImGui.BeginChild("##botbar", new Vector2(0, 28f), ImGuiChildFlags.None);

        if (pkt != null)
        {
            bool enc    = pkt.EncryptionHint == "encrypted";
            bool cs     = pkt.Direction == PacketDirection.ClientToServer;
            var  cc     = CategoryColor(GetCategory(pkt));
            var  dirCol = cs ? Theme.ColSuccess : Theme.ColAccent;

            ImGui.TextColored(Theme.ColTextMuted, "Pkt");   ImGui.SameLine(0, 4);
            ImGui.TextColored(Theme.ColAccent,    $"#{pkt.GetHashCode() & 0x7FFF:X4}"); ImGui.SameLine(0, 10);
            ImGui.TextColored(dirCol,             cs ? "C>S" : "S>C"); ImGui.SameLine(0, 10);
            ImGui.TextColored(Theme.ColTextMuted, "Opcode"); ImGui.SameLine(0, 4);
            ImGui.TextColored(cc,                 $"0x{pkt.OpcodeDecimal:X4}"); ImGui.SameLine(0, 10);
            ImGui.TextColored(Theme.ColTextMuted, "Size"); ImGui.SameLine(0, 4);
            ImGui.TextColored(Theme.Current?.Text ?? Vector4.One, $"{pkt.ByteLength}B"); ImGui.SameLine(0, 10);
            if (enc) ImGui.TextColored(Theme.ColDanger,  "[ENC]");
            else     ImGui.TextColored(Theme.ColSuccess, "[OK] ");

            // Right-side buttons
            const float RW = 380f;
            ImGui.SameLine(ImGui.GetContentRegionAvail().X + ImGui.GetCursorPosX() - RW);

            // Inspect (opens popup)
            bool inspOpen = _showInspector;
            ImGui.PushStyleColor(ImGuiCol.Button, inspOpen ? Theme.ColAccentMid : Theme.ColAccentDim);
            if (ImGui.Button(_showInspector ? ">> Inspector" : "   Inspector", new Vector2(90f, bh)))
                _showInspector = !_showInspector;
            ImGui.PopStyleColor();
            ImGui.SameLine(0, 4);

            ImGui.PushStyleColor(ImGuiCol.Button, Theme.ColDanger);
            if (ImGui.Button("Inject", new Vector2(56f, bh)))
                _state.AddInGameLog($"[INJECT] 0x{pkt.OpcodeDecimal:X4} -- not yet wired");
            ImGui.PopStyleColor();
            ImGui.SameLine(0, 4);

            bool aSet = _differA != null;
            ImGui.PushStyleColor(ImGuiCol.Button, aSet ? Theme.ColWarn : Theme.ColAccentDim);
            if (ImGui.Button(aSet ? "[A] Differ A" : "Differ A", new Vector2(74f, bh)))
                _differA = pkt;
            ImGui.PopStyleColor();
            ImGui.SameLine(0, 4);

            bool bSet    = _differB != null;
            bool hasDiff = aSet && bSet;
            ImGui.PushStyleColor(ImGuiCol.Button, bSet ? Theme.ColWarn : Theme.ColAccentDim);
            if (ImGui.Button(bSet ? "[B] Differ B" : "Differ B", new Vector2(74f, bh)))
                _differB = pkt;
            ImGui.PopStyleColor();
            ImGui.SameLine(0, 4);

            ImGui.PushStyleColor(ImGuiCol.Button, hasDiff ? Theme.ColAccentMid : Theme.ColBg3);
            ImGui.PushStyleColor(ImGuiCol.Text,   hasDiff ? Theme.ColAccent : Theme.ColTextMuted);
            if (ImGui.Button("Compare", new Vector2(74f, bh)) && hasDiff)
                ShowDiffer();
            ImGui.PopStyleColor(2);
        }
        else
        {
            ImGui.TextColored(Theme.ColTextMuted, "No packet selected -- click a row or right-click for options");
        }

        ImGui.EndChild();
        ImGui.PopStyleColor();
    }

    // =========================================================================
    // FLOATING INSPECTOR POPUP
    // =========================================================================
    private void RenderInspectorPopup()
    {
        var pkt = _selectedPacket!;
        var op  = pkt.OpcodeDecimal;
        var cat = GetCategory(pkt);
        var cc  = CategoryColor(cat);
        bool enc = pkt.EncryptionHint == "encrypted";
        bool cs  = pkt.Direction == PacketDirection.ClientToServer;

        var io = ImGui.GetIO();
        // Position: right side, below tab bar -- resizable, draggable
        ImGui.SetNextWindowSize(new Vector2(480f, 640f), ImGuiCond.FirstUseEver);
        ImGui.SetNextWindowPos(new Vector2(io.DisplaySize.X - 500f, 90f), ImGuiCond.FirstUseEver);
        ImGui.SetNextWindowSizeConstraints(new Vector2(360f, 300f), new Vector2(800f, io.DisplaySize.Y - 100f));

        // Color the window border with the category color
        ImGui.PushStyleColor(ImGuiCol.Border, cc with { W = .6f });
        ImGui.PushStyleColor(ImGuiCol.TitleBg,       Theme.Current?.ChildBg ?? Theme.ColBg3);
        ImGui.PushStyleColor(ImGuiCol.TitleBgActive,  new Vector4(cc.X*.2f, cc.Y*.2f, cc.Z*.2f, 1f));

        bool open = _showInspector;
        var wflags = ImGuiWindowFlags.NoCollapse;
        string wTitle = $"Inspector  0x{op:X4}  {pkt.OpcodeName}###inspector";

        if (ImGui.Begin(wTitle, ref open, wflags))
        {
            _showInspector = open;

            // -- Packet header strip -------------------------------------------
            ImGui.PushStyleColor(ImGuiCol.ChildBg,
                new Vector4(cc.X*.15f, cc.Y*.15f, cc.Z*.15f, .6f));
            ImGui.BeginChild("##insp_hdr", new Vector2(0, 48f), ImGuiChildFlags.Borders);

            ImGui.TextColored(cc, $"0x{op:X4}");
            ImGui.SameLine();
            ImGui.TextColored(Theme.Current?.Text ?? Vector4.One, pkt.OpcodeName);
            ImGui.SameLine();
            ImGui.TextColored(Theme.ColTextMuted, $"  #{pkt.GetHashCode() & 0x7FFF:X4}");

            ImGui.TextColored(cc, "[#]"); ImGui.SameLine();
            ImGui.TextColored(cc, cat);     ImGui.SameLine();
            ImGui.TextColored(Theme.ColTextMuted, "  |  "); ImGui.SameLine();
            ImGui.TextColored(pkt.IsTcp ? Theme.ColInfo : Theme.ColAccentDim,
                pkt.IsTcp ? "TCP" : "QUIC/UDP");
            ImGui.SameLine();
            ImGui.TextColored(Theme.ColTextMuted, "  |  "); ImGui.SameLine();
            ImGui.TextColored(cs ? Theme.ColSuccess : Theme.ColAccent, cs ? "Cli->Srv" : "Srv->Cli");

            ImGui.EndChild();
            ImGui.PopStyleColor();
            ImGui.Spacing();

            // -- Sub-tab bar ---------------------------------------------------
            string[] subTabs = { "Overview", "Hex Dump", "Entropy", "Strings", "QUIC", "Differ" };
            ImGui.PushStyleVar(ImGuiStyleVar.ItemSpacing,  new Vector2(2f, 0f));
            ImGui.PushStyleVar(ImGuiStyleVar.FramePadding, new Vector2(10f, 5f));
            for (int t = 0; t < subTabs.Length; t++)
            {
                bool sel = _inspSubTab == t;
                ImGui.PushStyleColor(ImGuiCol.Button,  sel ? Theme.ColAccentMid : Theme.ColBg3);
                ImGui.PushStyleColor(ImGuiCol.Text,    sel ? Theme.ColAccent    : Theme.ColTextMuted);
                if (ImGui.Button(subTabs[t])) _inspSubTab = t;
                ImGui.PopStyleColor(2);
                if (t < subTabs.Length - 1) ImGui.SameLine();
            }
            ImGui.PopStyleVar(2);
            ImGui.Separator();
            ImGui.Spacing();

            float subH = ImGui.GetContentRegionAvail().Y - 2f;
            ImGui.BeginChild("##insp_body", new Vector2(0, subH), ImGuiChildFlags.None);

            switch (_inspSubTab)
            {
                case 0: RenderInspOverview(pkt, op, enc, cs, cat, cc); break;
                case 1: RenderInspHexDump(pkt); break;
                case 2: RenderInspEntropy(pkt); break;
                case 3: RenderInspStrings(pkt); break;
                case 4: RenderInspQuic(pkt); break;
                case 5: RenderInspDiffer(); break;
            }

            ImGui.EndChild();
        }
        else
        {
            _showInspector = open;
        }

        ImGui.End();
        ImGui.PopStyleColor(3);
    }

    // -- Inspector sub-tabs ----------------------------------------------------

    private static void Row(string label, string val, Vector4? col = null)
    {
        ImGui.TextColored(Theme.ColTextMuted, label);
        ImGui.SameLine(120f);
        if (col.HasValue) ImGui.TextColored(col.Value, val);
        else ImGui.Text(val);
    }

    private void RenderInspOverview(PacketLogEntry pkt, ushort op, bool enc, bool cs,
                                     string cat, Vector4 cc)
    {
        Row("Direction",   cs ? "Client -> Server" : "Server -> Client",
            cs ? Theme.ColSuccess : Theme.ColAccent);
        Row("Timestamp",   pkt.Timestamp.ToString("HH:mm:ss.fff"));
        Row("Size",        $"{pkt.ByteLength} bytes  ({pkt.ByteLength / 1024.0:F2} KB)");
        Row("Protocol",    pkt.IsTcp ? "TCP (registry/login)" : "QUIC / UDP (gameplay)");
        Row("Opcode",      $"0x{op:X4}  (dec: {op})");
        Row("Category",    cat, cc);

        if (pkt.IsTcp && pkt.RawBytes.Length >= 8)
        {
            uint lenField = BinaryPrimitives.ReadUInt32LittleEndian(pkt.RawBytes.AsSpan(0, 4));
            uint idField  = BinaryPrimitives.ReadUInt32LittleEndian(pkt.RawBytes.AsSpan(4, 4));
            Row("Len field",  $"{lenField} bytes (LE u32)");
            Row("ID field",   $"0x{idField:X8}");
        }

        var info = OpcodeRegistry.GetInfo(op, pkt.Direction);
        if (info != null)
        {
            ImGui.Spacing();
            ImGui.TextColored(Theme.ColAccent, "Registry Info"); ImGui.Separator();
            Row("Name",     info.Name);
            Row("Critical", info.IsCritical ? "YES" : "no",
                info.IsCritical ? Theme.ColDanger : Theme.ColTextMuted);
            if (!string.IsNullOrEmpty(info.Description))
            {
                ImGui.TextColored(Theme.ColTextMuted, "Desc"); ImGui.SameLine(120f);
                ImGui.TextWrapped(info.Description);
            }
        }

        ImGui.Spacing();
        ImGui.TextColored(Theme.ColAccent, "Encryption"); ImGui.Separator();
        Row("Hint",        enc ? "ENCRYPTED" : "clear",
            enc ? Theme.ColDanger : Theme.ColSuccess);
        Row("Compression", pkt.CompressionMethod ?? "none");
        Row("EncHint raw", pkt.EncryptionHint);
        if (pkt.WasDecrypted) Row("Decrypted", "YES", Theme.ColSuccess);

        ImGui.Spacing();
        ImGui.TextColored(Theme.ColAccent, "Decryption Session"); ImGui.Separator();
        int keys = PacketDecryptor.DiscoveredKeys.Count;
        Row("Keys avail",  keys.ToString(), keys > 0 ? Theme.ColSuccess : Theme.ColDanger);
        Row("Dec total",   PacketDecryptor.SuccessfulDecryptions.ToString(), Theme.ColSuccess);
        Row("Fail total",  PacketDecryptor.FailedDecryptions.ToString(),
            PacketDecryptor.FailedDecryptions > 0 ? Theme.ColWarn : Theme.ColTextMuted);

        if (pkt.Fields?.Count > 0)
        {
            ImGui.Spacing();
            ImGui.TextColored(Theme.ColAccent, "Parsed Fields"); ImGui.Separator();
            foreach (var f in pkt.Fields.Take(20))
            {
                ImGui.TextColored(Theme.ColTextMuted, $"  [{f.Offset:X3}]"); ImGui.SameLine();
                ImGui.TextColored(cc, $" {f.Name}"); ImGui.SameLine();
                ImGui.TextColored(Theme.Current?.Text ?? Vector4.One, $"  = {f.DisplayValue}");
                ImGui.TextColored(Theme.ColTextMuted, $"       type: {f.Type}  len:{f.Length}  conf:{f.Confidence:P0}");
            }
            if (pkt.Fields.Count > 20)
                ImGui.TextColored(Theme.ColTextMuted, $"  ... +{pkt.Fields.Count - 20} more fields");
        }
    }

    private static void RenderInspHexDump(PacketLogEntry pkt)
    {
        byte[]? raw = pkt.RawBytes.Length > 0
            ? pkt.RawBytes
            : TryDecodeHex(pkt.RawHexPreview);

        if (raw == null || raw.Length == 0)
        {
            ImGui.TextColored(Theme.ColTextMuted, "  (no raw bytes available)");
            return;
        }

        ImGui.TextColored(Theme.ColTextMuted,
            $"  {raw.Length} bytes total  .  showing first {Math.Min(raw.Length, 512)}");
        ImGui.Separator();

        ImGui.PushStyleColor(ImGuiCol.ChildBg, Theme.Current?.TableBg ?? Theme.ColBg3);
        float dumpH = ImGui.GetContentRegionAvail().Y - 4f;
        ImGui.BeginChild("##hexdump", new Vector2(0, dumpH), ImGuiChildFlags.Borders);

        byte[] show = raw.Length > 512 ? raw[..512] : raw;
        int lw = 16;

        for (int row = 0; row < show.Length; row += lw)
        {
            // Offset
            ImGui.TextColored(Theme.ColTextMuted, $"{row:X4}:");
            ImGui.SameLine();

            // Hex bytes
            for (int col = 0; col < lw; col++)
            {
                int idx = row + col;
                if (idx >= show.Length)
                {
                    ImGui.TextColored(new Vector4(0,0,0,0), "   ");
                }
                else
                {
                    byte b = show[idx];
                    var bCol = b == 0             ? Theme.ColTextMuted
                             : b >= 32 && b < 127 ? Theme.ColSuccess
                             :                      Theme.ColAccent;
                    ImGui.TextColored(bCol, $"{b:X2}");
                }
                if (col < lw - 1) ImGui.SameLine(0, 2);
                if (col == 7)     { ImGui.SameLine(0, 6); }
            }

            ImGui.SameLine(0, 4);
            ImGui.TextColored(Theme.ColTextMuted, "|");
            ImGui.SameLine(0, 4);

            // ASCII
            for (int col = 0; col < lw; col++)
            {
                int idx = row + col;
                if (idx >= show.Length) break;
                char c = show[idx] >= 32 && show[idx] < 127 ? (char)show[idx] : '.';
                var aCol = c != '.' ? Theme.ColSuccess : Theme.ColTextMuted;
                ImGui.TextColored(aCol, c.ToString());
                if (col < lw - 1) ImGui.SameLine(0, 0);
            }
        }

        if (raw.Length > 512)
            ImGui.TextColored(Theme.ColTextMuted, $"\n  ... {raw.Length - 512} more bytes -- use Export to see full");

        ImGui.EndChild();
        ImGui.PopStyleColor();
    }

    private static void RenderInspEntropy(PacketLogEntry pkt)
    {
        byte[]? raw = pkt.RawBytes.Length > 0
            ? pkt.RawBytes
            : TryDecodeHex(pkt.RawHexPreview);

        if (raw == null || raw.Length == 0)
        { ImGui.TextColored(Theme.ColTextMuted, "  (no bytes)"); return; }

        double entropy = ByteUtils.CalculateEntropy(raw);
        string verdict = entropy > 7.5 ? "Strong encryption / compressed"
                       : entropy > 5.5 ? "Weak encryption / partially compressed"
                       : entropy > 3.5 ? "Structured binary data"
                       :                 "Plaintext / mostly headers";
        var barCol = entropy > 7.5 ? Theme.ColDanger
                   : entropy > 5.5 ? Theme.ColWarn
                   :                 Theme.ColSuccess;

        Row("Entropy",  $"{entropy:F4} bits/byte", barCol);
        Row("Verdict",  verdict, barCol);
        Row("Size",     $"{raw.Length} bytes");

        ImGui.Spacing();
        ImGui.TextColored(Theme.ColTextMuted, "Entropy bar (0..8):");
        ImGui.PushStyleColor(ImGuiCol.PlotHistogram, barCol);
        ImGui.ProgressBar((float)(entropy / 8.0), new Vector2(-1f, 14f), "");
        ImGui.PopStyleColor();

        ImGui.Spacing();
        ImGui.TextColored(Theme.ColAccent, "Byte Frequency Histogram"); ImGui.Separator();

        var freq = new float[256];
        foreach (var b in raw) freq[b]++;
        float fmax = freq.Max();
        if (fmax > 0) for (int i = 0; i < 256; i++) freq[i] /= fmax;

        // Show as 16-bucket nibble histogram
        var nibble = new float[16];
        for (int i = 0; i < 16; i++)
            for (int j = 0; j < 16; j++) nibble[i] += freq[i * 16 + j];
        float nmax = nibble.Max();
        if (nmax > 0) for (int i = 0; i < 16; i++) nibble[i] /= nmax;

        ImGui.PushStyleColor(ImGuiCol.PlotHistogram, Theme.ColAccent);
        ImGui.PlotHistogram("##bfreq", ref nibble[0], 16, 0, null, 0, 1f, new Vector2(-1f, 60f));
        ImGui.PopStyleColor();
        ImGui.TextColored(Theme.ColTextMuted, "  nibble 0x0-0xF frequency (normalized)");

        ImGui.Spacing();
        ImGui.TextColored(Theme.ColAccent, "Byte Statistics"); ImGui.Separator();
        int unique = raw.Distinct().Count();
        int nulls  = raw.Count(b => b == 0x00);
        int ascii  = raw.Count(b => b >= 32 && b <= 126);
        int high   = raw.Count(b => b >= 0x80);

        Row("Unique bytes",  $"{unique} / 256  ({unique * 100 / 256}%)",
            unique > 200 ? Theme.ColDanger : unique > 100 ? Theme.ColWarn : Theme.ColSuccess);
        Row("Null bytes",    $"{nulls}  ({nulls * 100 / Math.Max(1, raw.Length)}%)",
            nulls > raw.Length / 4 ? Theme.ColWarn : Theme.ColTextMuted);
        Row("ASCII printable",$"{ascii}  ({ascii * 100 / Math.Max(1, raw.Length)}%)",
            ascii > raw.Length / 2 ? Theme.ColSuccess : Theme.ColTextMuted);
        Row("High bytes",    $"{high}  ({high * 100 / Math.Max(1, raw.Length)}%)",
            high > raw.Length / 2 ? Theme.ColWarn : Theme.ColTextMuted);

        // Sliding window entropy
        if (raw.Length >= 32)
        {
            ImGui.Spacing();
            ImGui.TextColored(Theme.ColAccent, "Block Entropy (32-byte windows)"); ImGui.Separator();
            int windows = Math.Min(raw.Length / 32, 32);
            var wEnt = new float[windows];
            for (int w = 0; w < windows; w++)
                wEnt[w] = (float)(ByteUtils.CalculateEntropy(raw.Skip(w * 32).Take(32).ToArray()) / 8.0);
            ImGui.PushStyleColor(ImGuiCol.PlotLines, Theme.ColAccentMid);
            ImGui.PlotLines("##went", ref wEnt[0], windows, 0, null, 0f, 1f, new Vector2(-1f, 48f));
            ImGui.PopStyleColor();
            ImGui.TextColored(Theme.ColTextMuted, "  each point = 32-byte block  (high = encrypted)");
        }
    }

    private static void RenderInspStrings(PacketLogEntry pkt)
    {
        byte[]? raw = pkt.RawBytes.Length > 0
            ? pkt.RawBytes
            : TryDecodeHex(pkt.RawHexPreview);

        if (raw == null || raw.Length == 0)
        { ImGui.TextColored(Theme.ColTextMuted, "  (no bytes)"); return; }

        var strings = ByteUtils.ExtractStrings(raw, 4);
        ImGui.TextColored(Theme.ColTextMuted,
            $"  Found {strings.Count} embedded strings (min length 4)");
        ImGui.Separator();

        if (!strings.Any())
        {
            ImGui.TextColored(Theme.ColTextMuted, "  None found -- packet may be encrypted");
            return;
        }

        ImGui.PushStyleColor(ImGuiCol.ChildBg, Theme.Current?.TableBg ?? Theme.ColBg3);
        float strH = ImGui.GetContentRegionAvail().Y - 4f;
        ImGui.BeginChild("##strings", new Vector2(0, strH), ImGuiChildFlags.Borders);

        foreach (var s in strings)
        {
            ImGui.TextColored(Theme.ColSuccess, ">>"); ImGui.SameLine();
            ImGui.TextColored(Theme.Current?.Text ?? Vector4.One, $"\"{TruncStr(s, 60)}\"");
            if (ImGui.IsItemClicked())
                try { TextCopy.ClipboardService.SetText(s); } catch { }
            if (ImGui.IsItemHovered()) ImGui.SetTooltip($"Click to copy  ({s.Length} chars)");
        }

        ImGui.EndChild();
        ImGui.PopStyleColor();
    }

    private static void RenderInspQuic(PacketLogEntry pkt)
    {
        if (pkt.IsTcp)
        {
            ImGui.TextColored(Theme.ColTextMuted, "  This is a TCP packet -- no QUIC analysis");
            ImGui.Spacing();
            ImGui.TextColored(Theme.ColAccent, "TCP Frame"); ImGui.Separator();
            if (pkt.RawBytes.Length >= 8)
            {
                uint lenField = BinaryPrimitives.ReadUInt32LittleEndian(pkt.RawBytes.AsSpan(0, 4));
                uint idField  = BinaryPrimitives.ReadUInt32LittleEndian(pkt.RawBytes.AsSpan(4, 4));
                Row("Length field",  $"{lenField} bytes (LE u32)");
                Row("ID field",      $"0x{idField:X8}");
            }
            return;
        }

        if (pkt.QuicInfo == null)
        {
            ImGui.TextColored(Theme.ColTextMuted, "  QUIC header not parsed for this packet");
            return;
        }

        var q = pkt.QuicInfo;
        ImGui.TextColored(Theme.ColAccent, "QUIC Header"); ImGui.Separator();
        Row("Header type",  q.HeaderType);
        Row("Long header",  q.IsLongHeader ? "YES" : "NO",
            q.IsLongHeader ? Theme.ColSuccess : Theme.ColWarn);
        Row("Version",      $"0x{q.Version:X8}");

        if (q.IsLongHeader)
            ImGui.TextColored(Theme.ColSuccess, "  [OK] Long header (Initial/Handshake)");
        else
            ImGui.TextColored(Theme.ColWarn,    "  [!] Short header (1-RTT encrypted)");

        if (q.ClientConnectionId.Length > 0)
            Row("Client CID", BitConverter.ToString(q.ClientConnectionId.Take(8).ToArray()));

        ImGui.Spacing();
        ImGui.TextColored(Theme.ColAccent, "Decryption Hints"); ImGui.Separator();
        bool enc = pkt.EncryptionHint == "encrypted";
        Row("Encrypted",    enc ? "YES" : "NO", enc ? Theme.ColDanger : Theme.ColSuccess);
        Row("Keys known",   PacketDecryptor.DiscoveredKeys.Count.ToString(),
            PacketDecryptor.DiscoveredKeys.Count > 0 ? Theme.ColSuccess : Theme.ColDanger);
        Row("Decrypted",    pkt.WasDecrypted ? "YES" : "NO",
            pkt.WasDecrypted ? Theme.ColSuccess : Theme.ColTextMuted);
    }

    private void RenderInspDiffer()
    {
        ImGui.TextColored(Theme.ColAccent, "Packet Differ"); ImGui.Separator();

        void SlotRow(string label, PacketLogEntry? slot, System.Action<PacketLogEntry?> setSel)
        {
            ImGui.TextColored(Theme.ColTextMuted, label); ImGui.SameLine(80f);
            if (slot != null)
            {
                var c = CategoryColor(GetCategory(slot));
                ImGui.TextColored(c, $"0x{slot.OpcodeDecimal:X4}");
                ImGui.SameLine(); ImGui.TextColored(Theme.ColTextMuted, $" {slot.OpcodeName}");
                ImGui.SameLine(); ImGui.TextColored(Theme.ColTextMuted, $"  {slot.ByteLength}B");
                ImGui.SameLine(0, 8);
                if (ImGui.SmallButton($"Set cur##{label}"))  setSel(_selectedPacket);
                ImGui.SameLine();
                if (ImGui.SmallButton($"Clear##{label}"))    setSel(null);
            }
            else
            {
                ImGui.TextColored(Theme.ColTextMuted, "(not set)");
                ImGui.SameLine(0, 8);
                if (ImGui.SmallButton($"Set cur##{label}") && _selectedPacket != null) setSel(_selectedPacket);
            }
        }

        SlotRow("Slot A:", _differA, v => _differA = v);
        SlotRow("Slot B:", _differB, v => _differB = v);

        ImGui.Spacing();
        bool canDiff = _differA != null && _differB != null;
        ImGui.PushStyleColor(ImGuiCol.Button, canDiff ? Theme.ColAccentMid : Theme.ColBg3);
        ImGui.PushStyleColor(ImGuiCol.Text,   canDiff ? Theme.ColAccent    : Theme.ColTextMuted);
        if (ImGui.Button("Run Diff  A <-> B", new Vector2(-1f, 28f)) && canDiff)
            ShowDiffer();
        ImGui.PopStyleColor(2);

        if (!canDiff)
            ImGui.TextColored(Theme.ColTextMuted, "  Right-click rows or use bottom bar to set slots A and B.");

        // Inline diff preview
        if (canDiff)
        {
            byte[]? a = _differA!.RawBytes.Length > 0 ? _differA.RawBytes : TryDecodeHex(_differA.RawHexPreview);
            byte[]? b = _differB!.RawBytes.Length > 0 ? _differB.RawBytes : TryDecodeHex(_differB.RawHexPreview);
            if (a != null && b != null)
            {
                ImGui.Spacing();
                ImGui.TextColored(Theme.ColAccent, "Diff Preview"); ImGui.Separator();

                int common = Math.Min(a.Length, b.Length);
                int diffs  = 0;
                for (int i = 0; i < common; i++) if (a[i] != b[i]) diffs++;

                Row("A size",   $"{a.Length} bytes");
                Row("B size",   $"{b.Length} bytes");
                Row("Delta",    $"{b.Length - a.Length:+#;-#;0} bytes",
                    b.Length == a.Length ? Theme.ColSuccess : Theme.ColWarn);
                Row("Diffs",    $"{diffs} / {common} bytes ({diffs * 100 / Math.Max(1, common)}%)",
                    diffs == 0 ? Theme.ColSuccess : diffs > common / 2 ? Theme.ColDanger : Theme.ColWarn);

                ImGui.Spacing();
                ImGui.PushStyleColor(ImGuiCol.ChildBg, Theme.Current?.TableBg ?? Theme.ColBg3);
                float diffH = ImGui.GetContentRegionAvail().Y - 8f;
                ImGui.BeginChild("##diffprev", new Vector2(0, diffH), ImGuiChildFlags.Borders);

                int shown = 0;
                for (int i = 0; i < common && shown < 80; i++)
                {
                    if (a[i] != b[i])
                    {
                        ImGui.TextColored(Theme.ColTextMuted, $"  +{i:X4}:"); ImGui.SameLine();
                        ImGui.TextColored(Theme.ColSuccess, $" A={a[i]:X2}"); ImGui.SameLine();
                        ImGui.TextColored(Theme.ColDanger,  $" B={b[i]:X2}");
                        shown++;
                    }
                }
                if (diffs > 80)
                    ImGui.TextColored(Theme.ColTextMuted, $"  ... {diffs - 80} more diffs -- use Compare button to export all");

                ImGui.EndChild();
                ImGui.PopStyleColor();
            }
        }
    }

    // =========================================================================
    // DIFFER EXPORT
    // =========================================================================
    private void ShowDiffer()
    {
        if (_differA == null || _differB == null) return;
        byte[]? a = _differA.RawBytes.Length > 0 ? _differA.RawBytes : TryDecodeHex(_differA.RawHexPreview);
        byte[]? b = _differB.RawBytes.Length > 0 ? _differB.RawBytes : TryDecodeHex(_differB.RawHexPreview);
        if (a == null || b == null) return;

        var sb = new System.Text.StringBuilder();
        sb.AppendLine("=== HYFORCE PACKET DIFFER ===");
        sb.AppendLine($"A: 0x{_differA.OpcodeDecimal:X4} {_differA.Timestamp:HH:mm:ss.fff} ({a.Length}B)");
        sb.AppendLine($"B: 0x{_differB.OpcodeDecimal:X4} {_differB.Timestamp:HH:mm:ss.fff} ({b.Length}B)");
        sb.AppendLine($"Size delta: {b.Length - a.Length:+#;-#;0} bytes");
        sb.AppendLine();

        int common = Math.Min(a.Length, b.Length);
        int diffs  = 0;
        for (int i = 0; i < common; i++)
            if (a[i] != b[i]) { sb.AppendLine($"  +{i:X3}: A={a[i]:X2}  B={b[i]:X2}"); diffs++; }

        sb.AppendLine();
        sb.AppendLine($"Total differing bytes: {diffs}/{common}");

        try
        {
            string path = Path.Combine(_state.ExportDirectory,
                $"differ_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
            File.WriteAllText(path, sb.ToString());
            _state.AddInGameLog($"[DIFFER] Saved to {Path.GetFileName(path)}");
            Process.Start("notepad.exe", path);
        }
        catch { }
    }

    // =========================================================================
    // STATUS + CATEGORY BADGE HELPERS
    // =========================================================================
    private static void RenderStatusBadge(PacketLogEntry pkt)
    {
        bool enc   = pkt.EncryptionHint == "encrypted";
        bool known = OpcodeRegistry.IsKnownOpcode(pkt.OpcodeDecimal, pkt.Direction);

        Vector4 col; string label;
        if (enc)                          { col = new Vector4(.50f,.50f,.50f,1f); label = "ENC";   }
        else if (pkt.WasDecrypted&&known) { col = Theme.ColDanger;                label = "DEC";   }
        else if (known)                   { col = Theme.ColSuccess;               label = "PARSE"; }
        else                              { col = Theme.ColWarn;                  label = "RAW";   }

        var bgCol = new Vector4(col.X*.30f, col.Y*.30f, col.Z*.30f, 1f);
        ImGui.PushStyleColor(ImGuiCol.Button,        bgCol);
        ImGui.PushStyleColor(ImGuiCol.ButtonHovered, bgCol);
        ImGui.PushStyleColor(ImGuiCol.Text,          col);
        ImGui.PushStyleColor(ImGuiCol.Border,        col with { W = .7f });
        ImGui.PushStyleVar(ImGuiStyleVar.FramePadding,  new Vector2(5f, 1f));
        ImGui.PushStyleVar(ImGuiStyleVar.FrameRounding, 4f);
        ImGui.SmallButton(label);
        ImGui.PopStyleVar(2);
        ImGui.PopStyleColor(4);
    }

    private static void RenderCategoryPill(string cat, Vector4 cc)
    {
        var bgCol = new Vector4(cc.X*.32f, cc.Y*.32f, cc.Z*.32f, 1f);
        ImGui.PushStyleColor(ImGuiCol.Button,        bgCol);
        ImGui.PushStyleColor(ImGuiCol.ButtonHovered, bgCol);
        ImGui.PushStyleColor(ImGuiCol.Text,          cc);
        ImGui.PushStyleColor(ImGuiCol.Border,        cc with { W = .65f });
        ImGui.PushStyleVar(ImGuiStyleVar.FramePadding,  new Vector2(6f, 2f));
        ImGui.PushStyleVar(ImGuiStyleVar.FrameRounding, 8f);
        ImGui.SmallButton(cat);
        ImGui.PopStyleVar(2);
        ImGui.PopStyleColor(4);
    }

    // =========================================================================
    // FILTERING
    // =========================================================================
    private List<PacketLogEntry> BuildFilteredList()
    {
        return _state.PacketLog.GetLast(500).Where(p =>
        {
            if (_excluded.Contains(p.OpcodeDecimal)) return false;

            if (!string.IsNullOrEmpty(_filterText))
            {
                bool match =
                    p.OpcodeDecimal.ToString("X4").Contains(_filterText, StringComparison.OrdinalIgnoreCase) ||
                    p.OpcodeName.Contains(_filterText, StringComparison.OrdinalIgnoreCase) ||
                    p.DirStr.Contains(_filterText, StringComparison.OrdinalIgnoreCase);
                if (!match) return false;
            }

            bool enc = p.EncryptionHint == "encrypted";
            bool cs  = p.Direction == PacketDirection.ClientToServer;

            if (_filterCS       && !cs)  return false;
            if (_filterSC       && cs)   return false;
            if (_filterEncrypted && !enc) return false;
            if (_filterRegistry)
            {
                if (GetCategory(p) != "registry") return false;
            }
            if (_showOnlyUnknown && OpcodeRegistry.IsKnownOpcode(p.OpcodeDecimal, p.Direction))
                return false;

            return true;
        }).ToList();
    }

    // =========================================================================
    // CATEGORY MAPPING
    // =========================================================================
    private static string GetCategory(PacketLogEntry p)
    {
        var info = OpcodeRegistry.GetInfo(p.OpcodeDecimal, p.Direction);
        if (info != null) return info.Category switch
        {
            PacketCategory.Assets or PacketCategory.Setup       => "registry",
            PacketCategory.Movement or PacketCategory.Input     => "movement",
            PacketCategory.Combat                               => "combat",
            PacketCategory.Entities                             => "entity",
            PacketCategory.Inventory                            => "inventory",
            PacketCategory.Connection or PacketCategory.Authentication => "handshake",
            PacketCategory.World or PacketCategory.Blocks       => "world",
            _ => info.Category.ToString().ToLowerInvariant()
        };

        ushort op = p.OpcodeDecimal;
        if (op >= 0x28 && op <= 0x42)          return "registry";
        if (op is 0x6C or 0x6D or 0x6E)        return "movement";
        if (op is 0x60 or 0x61 or 0x62)        return "combat";
        if (op is 0x03 or 0x04)                return "chat";
        if (op == 0x0000)                       return "handshake";
        return "unknown";
    }

    private static Vector4 CategoryColor(string cat) => cat.ToLowerInvariant() switch
    {
        "registry"  => Theme.ColCatRegistry,
        "movement"  => Theme.ColCatMovement,
        "combat"    => Theme.ColCatCombat,
        "entity"    => Theme.ColCatEntity,
        "inventory" => Theme.ColCatInventory,
        "chat"      => Theme.ColCatChat,
        "handshake" => Theme.ColCatHandshake,
        _           => Theme.ColCatUnknown,
    };

    // =========================================================================
    // SMALL UI HELPERS
    // =========================================================================
    // FilterToggle: visible bordered pill — dim when off, bright when on
    private static void FilterToggle(string label, ref bool state, float h, Vector4 activeCol)
    {
        ImGui.PushStyleVar(ImGuiStyleVar.FrameRounding, 6f);
        if (state)
        {
            var bgOn = new Vector4(activeCol.X*.30f, activeCol.Y*.30f, activeCol.Z*.30f, 1f);
            ImGui.PushStyleColor(ImGuiCol.Button,        bgOn);
            ImGui.PushStyleColor(ImGuiCol.ButtonHovered, new Vector4(activeCol.X*.42f, activeCol.Y*.42f, activeCol.Z*.42f, 1f));
            ImGui.PushStyleColor(ImGuiCol.Text,          activeCol);
            ImGui.PushStyleColor(ImGuiCol.Border,        activeCol with { W = .9f });
        }
        else
        {
            var bgOff = Theme.Current?.TabBg ?? new Vector4(.10f,.09f,.09f,1f);
            ImGui.PushStyleColor(ImGuiCol.Button,        bgOff);
            ImGui.PushStyleColor(ImGuiCol.ButtonHovered, new Vector4(bgOff.X*1.5f, bgOff.Y*1.5f, bgOff.Z*1.5f, 1f));
            ImGui.PushStyleColor(ImGuiCol.Text,          Theme.ColTextMuted);
            ImGui.PushStyleColor(ImGuiCol.Border,        Theme.ColBorder);
        }
        if (ImGui.Button(label, new Vector2(0f, h))) state = !state;
        ImGui.PopStyleColor(4);
        ImGui.PopStyleVar();
    }

    private static void ColorStat(string label, string val, Vector4 col)
    {
        ImGui.TextColored(Theme.ColTextMuted, label);
        ImGui.TextColored(col, val);
    }

    private static string TruncStr(string s, int max) =>
        s.Length > max ? s[..(max - 1)] + "..." : s;

    private static bool ParseHex(string s, out ushort result) =>
        ushort.TryParse(s, System.Globalization.NumberStyles.HexNumber, null, out result);

    private static byte[]? TryDecodeHex(string hex)
    {
        try
        {
            hex = hex.Replace("-", "").Replace(" ", "");
            if (hex.Length % 2 != 0 || hex.Length == 0 || hex.Length > 8192) return null;
            return Convert.FromHexString(hex);
        }
        catch { return null; }
    }

    // =========================================================================
    // EXPORT
    // =========================================================================
    private void ExportPacket(PacketLogEntry pkt)
    {
        try
        {
            string path = Path.Combine(_state.ExportDirectory,
                $"pkt_{pkt.Timestamp:yyyyMMdd_HHmmss}_{pkt.OpcodeDecimal:X4}.txt");

            byte[]? bytes = pkt.RawBytes.Length > 0 ? pkt.RawBytes : TryDecodeHex(pkt.RawHexPreview);

            var sb = new System.Text.StringBuilder();
            sb.AppendLine("=== HYFORCE PACKET EXPORT ===");
            sb.AppendLine($"Timestamp:   {pkt.Timestamp:O}");
            sb.AppendLine($"Direction:   {pkt.Direction}");
            sb.AppendLine($"Protocol:    {(pkt.IsTcp ? "TCP" : "QUIC/UDP")}");
            sb.AppendLine($"Opcode:      0x{pkt.OpcodeDecimal:X4}  ({pkt.OpcodeName})");
            sb.AppendLine($"Size:        {pkt.ByteLength} bytes");
            sb.AppendLine($"Encryption:  {pkt.EncryptionHint}");
            sb.AppendLine($"Compression: {pkt.CompressionMethod ?? "none"}");
            sb.AppendLine($"Category:    {GetCategory(pkt)}");
            if (bytes != null)
            {
                double entropy = ByteUtils.CalculateEntropy(bytes);
                sb.AppendLine($"Entropy:     {entropy:F4}");
                sb.AppendLine($"Unique bytes:{bytes.Distinct().Count()}");
                var strs = ByteUtils.ExtractStrings(bytes, 4);
                if (strs.Any())
                    sb.AppendLine($"Strings:     {string.Join(", ", strs.Take(10))}");
            }
            sb.AppendLine();
            sb.AppendLine("=== HEX ===");
            sb.AppendLine(pkt.RawHexPreview);

            File.WriteAllText(path, sb.ToString());
            _state.AddInGameLog($"[EXPORT] {Path.GetFileName(path)}");
        }
        catch (Exception ex)
        {
            _state.AddInGameLog($"[EXPORT] Error: {ex.Message}");
        }
    }
}
