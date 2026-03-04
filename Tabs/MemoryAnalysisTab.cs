// FILE: Tabs/MemoryAnalysisTab.cs
// ============================================================
// Complete memory analysis UI tab integrating:
//   * LocalPlayer discovery + live field inspector
//   * Memory field list with value change highlighting
//   * Entity structure scan results
//   * Pointer graph visualizer
//   * Snapshot capture + diff viewer
//   * Structured memory log
//   * Memory dumper
//
// Tab layout (sub-tabs):
//   [Overview] [Fields] [Entities] [Pointer Graph] [Snapshots] [Log] [Dump]

using HyForce.Core;
using HyForce.Memory;
using HyForce.UI;
using ImGuiNET;
using System.Diagnostics;
using System.Numerics;
using System.Runtime.InteropServices;

namespace HyForce.Tabs;

public class MemoryAnalysisTab : ITab
{
    public string Name => "Memory";

    // -- Win32 --------------------------------------------------------------
    [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll")] static extern bool   CloseHandle(IntPtr h);
    private const int PROCESS_VM_READ       = 0x0010;
    private const int PROCESS_QUERY_INFORMATION = 0x0400;

    // -- State -------------------------------------------------------------
    private readonly AppState _state;

    // Process attach
    private IntPtr    _processHandle = IntPtr.Zero;
    private bool      _isAttached;
    private string    _processName = "HytaleClient";  // Hytale native client

    // Subsystems (created after attach)
    private SignatureScanner?   _scanner;
    private PointerWalker?      _walker;
    private StructureValidator? _validator;
    private MemoryLogger        _log     = new();
    private MemoryDumper?       _dumper;
    private SnapshotSystem?     _snapshots;
    private PointerGraph?       _graph;
    private LocalPlayerDiscovery? _discovery;
    private LocalPlayerMonitor?   _monitor;
    private EntityScanner?        _entityScanner;
    private MemoryFieldBatch      _fieldBatch = new(null!); // replaced after attach

    // UI state
    private int    _subTab        = 0;
    private bool   _autoRefresh   = true;
    private double _lastRefresh   = 0;
    private float  _refreshHz     = 10f;

    // Overview
    private string _discoverStatus = "Not started";
    private bool   _discovering    = false;

    // Fields panel
    private MemoryField? _selectedField;
    private string       _jumpAddrInput = "";

    // Entity scan
    private List<EntityRegionCandidate> _entityCandidates = new();
    private EntityRegionCandidate?      _selectedEntity;
    private bool                        _entityScanning = false;

    // Pointer graph
    private PointerGraphNode? _graphRoot;
    private string            _graphAddrInput = "";

    // Snapshots
    private MemorySnapshot? _snapA, _snapB;
    private string          _snapDiffText  = "";
    private string          _snapAddrInput = "";
    private string          _snapLenInput  = "256";

    // Dump
    private string _dumpAddrInput = "";
    private string _dumpLenInput  = "256";
    private string _dumpText      = "";

    // Log
    private bool _logAutoScroll = true;
    private string _logFilter   = "";

    public MemoryAnalysisTab(AppState state) { _state = state; }

    // -- Render entry ------------------------------------------------------

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();

        RenderAttachBar();
        ImGui.Separator();

        if (!_isAttached)
        {
            ImGui.Spacing();
            ImGui.TextColored(Theme.ColTextMuted, "Attach to a process to begin memory analysis.");
            return;
        }

        // Throttled refresh
        if (_autoRefresh && ImGui.GetTime() - _lastRefresh > 1.0 / _refreshHz)
        {
            _fieldBatch.TryRefresh();
            _lastRefresh = ImGui.GetTime();
        }

        // Sub-tab bar
        string[] tabs = { "Overview", "Fields", "Entities", "Ptr Graph", "Snapshots", "Log", "Dump" };
        if (ImGui.BeginTabBar("##mem_subtabs"))
        {
            for (int i = 0; i < tabs.Length; i++)
            {
                var flags = ImGuiTabItemFlags.None;
                bool open = true;
                if (ImGui.BeginTabItem(tabs[i], ref open, flags))
                {
                    _subTab = i;
                    float h = Math.Max(100, avail.Y - 60);
                    ImGui.BeginChild($"##mst_{i}", new Vector2(0, h), ImGuiChildFlags.None);
                    switch (i)
                    {
                        case 0: RenderOverview();    break;
                        case 1: RenderFields();      break;
                        case 2: RenderEntities();    break;
                        case 3: RenderPointerGraph(); break;
                        case 4: RenderSnapshots();   break;
                        case 5: RenderLog();         break;
                        case 6: RenderDump();        break;
                    }
                    ImGui.EndChild();
                    ImGui.EndTabItem();
                }
            }
            ImGui.EndTabBar();
        }
    }

    // -- Attach bar --------------------------------------------------------

    // -- Running process cache ----------------------------------------------
    private Process[] _procList       = Array.Empty<Process>();
    private DateTime  _lastProcScan   = DateTime.MinValue;
    private int       _selectedProcIdx = -1;

    private void RefreshProcList()
    {
        if ((DateTime.Now - _lastProcScan).TotalSeconds < 2) return;
        _lastProcScan = DateTime.Now;
        try
        {
            _procList = Process.GetProcesses()
                .Where(p => { try { return p.Id > 4; } catch { return false; } })
                .OrderBy(p => p.ProcessName).ToArray();
            for (int i = 0; i < _procList.Length; i++)
            {
                if (_procList[i].ProcessName.ToLower().Contains("hytale"))
                { _selectedProcIdx = i; _processName = _procList[i].ProcessName; break; }
            }
        }
        catch { }
    }

    private void RenderAttachBar()
    {
        if (_isAttached)
        {
            ImGui.TextColored(Theme.ColSuccess, "[*] ATTACHED");
            ImGui.SameLine(0,8);
            ImGui.TextColored(Theme.ColTextMuted, _processName);
            ImGui.SameLine(0,8);
            if (ImGui.Button("Detach", new Vector2(70,22))) Detach();
            ImGui.SameLine();
            ImGui.Checkbox("Auto-refresh", ref _autoRefresh);
            return;
        }

        RefreshProcList();

        // Highlight Hytale processes with a quick-attach button
        var hytaleProcs = _procList.Where(p => p.ProcessName.ToLower().Contains("hytale")).ToArray();
        if (hytaleProcs.Length > 0)
        {
            foreach (var hp in hytaleProcs)
            {
                ImGui.PushStyleColor(ImGuiCol.Button, Theme.ColAccentDim);
                if (ImGui.Button($"* Attach {hp.ProcessName} (PID {hp.Id})", new Vector2(0,22)))
                { _processName = hp.ProcessName; TryAttach(); }
                ImGui.PopStyleColor();
                ImGui.SameLine();
            }
            ImGui.NewLine();
        }
        else
        {
            ImGui.TextColored(Theme.ColDanger, "[ ] NOT ATTACHED");
            ImGui.SameLine(0,8);
            ImGui.TextColored(Theme.ColTextMuted, "HytaleClient.exe not found");
            ImGui.NewLine();
        }

        // Manual input
        ImGui.SetNextItemWidth(160);
        ImGui.InputText("##proc", ref _processName, 64);
        ImGui.SameLine();
        ImGui.PushStyleColor(ImGuiCol.Button, Theme.ColSuccess);
        if (ImGui.Button("Attach", new Vector2(60,22))) TryAttach();
        ImGui.PopStyleColor();
        ImGui.SameLine();
        if (ImGui.Button("Refresh", new Vector2(60,22))) _lastProcScan = DateTime.MinValue;

        // Process dropdown
        if (_procList.Length > 0)
        {
            ImGui.SameLine(0,10);
            ImGui.SetNextItemWidth(220);
            string preview = _selectedProcIdx >= 0 && _selectedProcIdx < _procList.Length
                ? $"{_procList[_selectedProcIdx].ProcessName} ({_procList[_selectedProcIdx].Id})"
                : "-- pick --";
            if (ImGui.BeginCombo("##pc", preview))
            {
                for (int i = 0; i < _procList.Length; i++)
                {
                    var p = _procList[i];
                    bool ht = p.ProcessName.ToLower().Contains("hytale");
                    if (ht) ImGui.PushStyleColor(ImGuiCol.Text, Theme.ColAccent);
                    string lbl; try { lbl = $"{p.ProcessName}  ({p.Id})"; } catch { lbl = $"? ({p.Id})"; }
                    if (ImGui.Selectable(lbl, i == _selectedProcIdx))
                    { _selectedProcIdx = i; _processName = p.ProcessName; }
                    if (ht) ImGui.PopStyleColor();
                }
                ImGui.EndCombo();
            }
            if (_selectedProcIdx >= 0 && _selectedProcIdx < _procList.Length)
            {
                ImGui.SameLine();
                ImGui.PushStyleColor(ImGuiCol.Button, Theme.ColAccentMid);
                if (ImGui.Button("Attach##sel", new Vector2(90,22))) TryAttach();
                ImGui.PopStyleColor();
            }
        }

        ImGui.SameLine();
        ImGui.Checkbox("Auto-refresh", ref _autoRefresh);
        ImGui.SameLine();
        ImGui.SetNextItemWidth(60);
        ImGui.SliderFloat("Hz", ref _refreshHz, 1f, 60f);
    }

    // -- Overview panel ----------------------------------------------------

    private void RenderOverview()
    {
        ImGui.Spacing();

        // LocalPlayer status card
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.1f, 0.15f, 0.12f, 1f));
        ImGui.BeginChild("##lp_card", new Vector2(0, 200), ImGuiChildFlags.Borders);
        ImGui.TextColored(Theme.ColSuccess, "LocalPlayer");
        ImGui.SameLine(ImGui.GetContentRegionAvail().X - 180);

        if (_discovering)
        {
            ImGui.TextColored(Theme.ColWarn, "[*] Scanning...");
        }
        else if (ImGui.Button("Discover Player", new Vector2(160, 26)))
        {
            StartPlayerDiscovery();
        }

        ImGui.Separator();

        var player = _monitor?.State;
        if (player == null || !player.IsValid)
        {
            ImGui.TextColored(Theme.ColTextMuted, _discoverStatus);
        }
        else
        {
            Col("Base Address", player.AddrHex);
            Col("Position",     player.PosStr);
            Col("Rotation",     player.RotStr);
            Col("Health",       player.HealthStr);
            Col("Name",         player.PlayerName);
            Col("Inventory",    $"0x{(ulong)player.InventoryPtr:X}");
            Col("Strategy",     player.DiscoveryStrategy);
            Col("Confidence",   $"{player.Confidence:P0}");

            ImGui.Spacing();
            if (ImGui.Button("Populate Field List", new Vector2(160, 26)))
            {
                _fieldBatch.PopulateFromPlayerState(player);
                _log.Info("[UI] Field list populated from LocalPlayer");
            }
            ImGui.SameLine();
            if (ImGui.Button("Take Snapshot", new Vector2(120, 26)))
                _snapshots?.Take(player.BaseAddress, 256, $"Player@{DateTime.Now:HHmmss}");
        }
        ImGui.EndChild();
        ImGui.PopStyleColor();

        ImGui.Spacing();

        // Quick stats row
        ImGui.BeginChild("##stats_row", new Vector2(0, 80), ImGuiChildFlags.None);
        StatCard("Regions",  _scanner == null ? "--" : "ready", new Vector4(0.3f, 0.5f, 0.9f, 1f));
        ImGui.SameLine();
        StatCard("Snapshots", (_snapshots?.Snapshots.Count ?? 0).ToString(), Theme.ColAccent);
        ImGui.SameLine();
        StatCard("Log Lines", _log.Count.ToString(), Theme.ColTextMuted);
        ImGui.SameLine();
        StatCard("Entities",  _entityCandidates.Count.ToString(), new Vector4(0.8f, 0.5f, 0.2f, 1f));
        ImGui.EndChild();
    }

    // -- Fields panel -----------------------------------------------------

    private void RenderFields()
    {
        var avail = ImGui.GetContentRegionAvail();

        // Toolbar
        if (ImGui.Button("Add Field...", new Vector2(100, 24)))
            ImGui.OpenPopup("##add_field");
        ImGui.SameLine();
        if (ImGui.Button("Clear All", new Vector2(80, 24)))  { _fieldBatch.Clear(); _selectedField = null; }
        ImGui.SameLine();
        ImGui.Text($"Changed: {_fieldBatch.ChangedCount} / {_fieldBatch.Fields.Count}");

        ImGui.Separator();

        // Add field popup
        if (ImGui.BeginPopup("##add_field"))
        {
            ImGui.SetNextItemWidth(200);
            ImGui.InputText("Address (hex)", ref _jumpAddrInput, 20);
            if (ImGui.Button("Add Float"))   AddFieldFromInput(FieldKind.Float,   4);
            ImGui.SameLine();
            if (ImGui.Button("Add Vec3"))    AddFieldFromInput(FieldKind.Vec3,    12);
            ImGui.SameLine();
            if (ImGui.Button("Add Int32"))   AddFieldFromInput(FieldKind.Int32,   4);
            ImGui.SameLine();
            if (ImGui.Button("Add Ptr64"))   AddFieldFromInput(FieldKind.Pointer, 8);
            ImGui.EndPopup();
        }

        // Two-column layout
        float leftW  = avail.X * 0.55f - 8;
        float rightW = avail.X * 0.45f - 8;

        ImGui.BeginChild("##field_list", new Vector2(leftW, avail.Y - 60), ImGuiChildFlags.Borders);
        RenderFieldList();
        ImGui.EndChild();

        ImGui.SameLine();

        ImGui.BeginChild("##field_detail", new Vector2(rightW, avail.Y - 60), ImGuiChildFlags.Borders);
        RenderFieldDetail();
        ImGui.EndChild();
    }

    private void RenderFieldList()
    {
        var tableFlags = ImGuiTableFlags.RowBg | ImGuiTableFlags.ScrollY |
                         ImGuiTableFlags.BordersInnerV | ImGuiTableFlags.Resizable;

        if (!ImGui.BeginTable("##fields_tbl", 4, tableFlags)) return;

        ImGui.TableSetupColumn("Name",    ImGuiTableColumnFlags.WidthStretch);
        ImGui.TableSetupColumn("Value",   ImGuiTableColumnFlags.WidthStretch);
        ImGui.TableSetupColumn("Changed", ImGuiTableColumnFlags.WidthFixed, 60);
        ImGui.TableSetupColumn("Addr",    ImGuiTableColumnFlags.WidthFixed, 130);
        ImGui.TableHeadersRow();

        foreach (var field in _fieldBatch.Fields)
        {
            ImGui.TableNextRow();
            bool sel = _selectedField == field;

            ImGui.TableSetColumnIndex(0);
            if (ImGui.Selectable(field.Name + "##" + field.Address, sel,
                ImGuiSelectableFlags.SpanAllColumns))
                _selectedField = field;

            // Highlight changed values in yellow
            var valColor = field.Changed ? Theme.ColWarn : new Vector4(1, 1, 1, 1);
            ImGui.TableSetColumnIndex(1);
            ImGui.TextColored(valColor, TruncateStr(field.DisplayValue, 28));

            ImGui.TableSetColumnIndex(2);
            if (field.Changed)
                ImGui.TextColored(Theme.ColWarn, "[*]");

            ImGui.TableSetColumnIndex(3);
            ImGui.TextColored(Theme.ColTextMuted, $"0x{(ulong)field.Address:X}");
        }
        ImGui.EndTable();
    }

    private void RenderFieldDetail()
    {
        if (_selectedField == null) { ImGui.TextColored(Theme.ColTextMuted, "Select a field"); return; }
        var f = _selectedField;

        ImGui.TextColored(Theme.ColAccent, f.Name);
        ImGui.Separator();

        Row("Address",    $"0x{(ulong)f.Address:X}");
        Row("Kind",       f.Kind.ToString());
        Row("Size",       $"{f.Size} bytes");
        Row("Value",      f.DisplayValue);
        Row("Raw",        f.HexPreview);
        Row("Changed",    f.Changed ? $"Yes (@ {f.LastChanged:HH:mm:ss.fff})" : "No");
        Row("Confidence", $"{f.Confidence:P0}");

        ImGui.Spacing();
        ImGui.Separator();
        ImGui.Text("Previous:");
        ImGui.TextColored(Theme.ColTextMuted,
            BitConverter.ToString(f.PrevBytes.Take(16).ToArray()).Replace("-", " "));

        if (f.Kind == FieldKind.Pointer)
        {
            ImGui.Spacing();
            if (ImGui.Button("Expand Pointer Children"))
            {
                if (_scanner != null)
                    f.ExpandPointer(_scanner);
            }
        }

        // Show children
        if (f.Children.Count > 0)
        {
            ImGui.Separator();
            ImGui.Text($"Children ({f.Children.Count}):");
            if (ImGui.BeginTable("##children_tbl", 3, ImGuiTableFlags.RowBg | ImGuiTableFlags.BordersInnerV))
            {
                ImGui.TableSetupColumn("Offset", ImGuiTableColumnFlags.WidthFixed, 80);
                ImGui.TableSetupColumn("Value",  ImGuiTableColumnFlags.WidthStretch);
                ImGui.TableSetupColumn("Hex",    ImGuiTableColumnFlags.WidthFixed, 120);
                ImGui.TableHeadersRow();
                foreach (var child in f.Children.Take(32))
                {
                    ImGui.TableNextRow();
                    ImGui.TableSetColumnIndex(0); ImGui.Text(child.Name);
                    ImGui.TableSetColumnIndex(1); ImGui.Text(TruncateStr(child.DisplayValue, 20));
                    ImGui.TableSetColumnIndex(2); ImGui.TextColored(Theme.ColTextMuted, child.HexPreview[..Math.Min(child.HexPreview.Length, 18)]);
                }
                ImGui.EndTable();
            }
        }

        // Action buttons
        ImGui.Spacing();
        if (ImGui.Button("Take Snapshot"))
            _snapshots?.Take(f.Address, f.Size, $"{f.Name}@{DateTime.Now:HHmmss}");
        ImGui.SameLine();
        if (ImGui.Button("Open Dump"))
        {
            _dumpAddrInput = $"{(ulong)f.Address:X}";
            _dumpLenInput  = "256";
            if (_dumper != null && _scanner != null)
                _dumpText = _dumper.StructDump(f.Address, 256);
        }
        ImGui.SameLine();
        if (ImGui.Button("Build Graph"))
        {
            _graphAddrInput = $"{(ulong)f.Address:X}";
            if (_graph != null)
                _graphRoot = _graph.Build(f.Address);
        }
    }

    // -- Entities panel ----------------------------------------------------

    private void RenderEntities()
    {
        if (ImGui.Button("Scan for Entity Structures", new Vector2(200, 28)))
            StartEntityScan();
        ImGui.SameLine();
        if (_entityScanning)
            ImGui.TextColored(Theme.ColWarn, "[*] Scanning...");
        else
            ImGui.Text($"{_entityCandidates.Count} candidates");

        ImGui.Separator();

        var avail = ImGui.GetContentRegionAvail();
        float leftW = avail.X * 0.5f - 8;

        ImGui.BeginChild("##ent_list", new Vector2(leftW, avail.Y - 50), ImGuiChildFlags.Borders);

        if (ImGui.BeginTable("##ent_tbl", 4, ImGuiTableFlags.RowBg | ImGuiTableFlags.ScrollY |
                             ImGuiTableFlags.BordersInnerV))
        {
            ImGui.TableSetupColumn("Address", ImGuiTableColumnFlags.WidthFixed, 140);
            ImGui.TableSetupColumn("Kind",    ImGuiTableColumnFlags.WidthFixed, 90);
            ImGui.TableSetupColumn("Ptrs",    ImGuiTableColumnFlags.WidthFixed, 50);
            ImGui.TableSetupColumn("Score",   ImGuiTableColumnFlags.WidthFixed, 60);
            ImGui.TableHeadersRow();

            foreach (var c in _entityCandidates)
            {
                ImGui.TableNextRow();
                bool sel = _selectedEntity == c;

                ImGui.TableSetColumnIndex(0);
                if (ImGui.Selectable(c.AddrHex + "##ent" + c.AddrHex, sel,
                    ImGuiSelectableFlags.SpanAllColumns))
                    _selectedEntity = c;

                ImGui.TableSetColumnIndex(1);
                var kindColor = c.Kind == EntityArrayKind.LargeArray ? Theme.ColSuccess
                              : c.Kind == EntityArrayKind.SmallArray  ? Theme.ColAccent
                              : Theme.ColTextMuted;
                ImGui.TextColored(kindColor, c.Kind.ToString());
                ImGui.TableSetColumnIndex(2); ImGui.Text(c.PointerCount.ToString());
                ImGui.TableSetColumnIndex(3);
                float sc = (float)c.Score;
                ImGui.ProgressBar(sc, new Vector2(-1, 14), $"{sc:P0}");
            }
            ImGui.EndTable();
        }
        ImGui.EndChild();

        ImGui.SameLine();

        ImGui.BeginChild("##ent_detail", new Vector2(avail.X - leftW - 12, avail.Y - 50), ImGuiChildFlags.Borders);
        if (_selectedEntity != null)
        {
            var e = _selectedEntity;
            ImGui.TextColored(Theme.ColAccent, "Entity Region Detail");
            ImGui.Separator();
            Row("Address",    e.AddrHex);
            Row("Kind",       e.Kind.ToString());
            Row("Pointers",   e.PointerCount.ToString());
            Row("Valid Obj%", $"{e.ValidObjectRatio:P0}");
            Row("Score",      e.ScoreStr);

            ImGui.Spacing();
            if (ImGui.Button("Add as Field (Pointer)") && _scanner != null)
            {
                var f = MemoryField.Ptr64($"EntityList@{e.AddrHex}", e.BaseAddress);
                f.Refresh(_scanner);
                _fieldBatch.Add(f);
            }
            ImGui.SameLine();
            if (ImGui.Button("Dump Region"))
            {
                _dumpAddrInput = $"{(ulong)e.BaseAddress:X}";
                _dumpLenInput  = $"{Math.Min(e.PointerCount * 8, 1024)}";
                if (_dumper != null)
                    _dumpText = _dumper.HexDump(e.BaseAddress, Math.Min(e.PointerCount * 8, 1024));
            }
        }
        else
        {
            ImGui.TextColored(Theme.ColTextMuted, "Select a candidate to inspect");
        }
        ImGui.EndChild();
    }

    // -- Pointer graph panel -----------------------------------------------

    private void RenderPointerGraph()
    {
        ImGui.SetNextItemWidth(200);
        ImGui.InputText("Address", ref _graphAddrInput, 20);
        ImGui.SameLine();
        if (ImGui.Button("Build Graph", new Vector2(100, 24)))
        {
            if (_graph != null && TryParseHex(_graphAddrInput, out ulong addr))
                _graphRoot = _graph.Build((IntPtr)addr);
        }
        ImGui.SameLine();
        if (ImGui.Button("Use Player") && _monitor?.State?.IsValid == true)
        {
            if (_graph != null)
                _graphRoot = _graph.Build(_monitor.State.BaseAddress);
        }

        ImGui.Separator();

        if (_graphRoot == null)
        {
            ImGui.TextColored(Theme.ColTextMuted, "No graph built yet. Enter an address and click Build.");
            return;
        }

        var avail = ImGui.GetContentRegionAvail();
        ImGui.BeginChild("##graph_view", new Vector2(0, avail.Y - 10), ImGuiChildFlags.Borders);
        RenderGraphNode(_graphRoot);
        ImGui.EndChild();
    }

    private void RenderGraphNode(PointerGraphNode node)
    {
        string indent = new string(' ', node.Depth * 3);
        var color = node.Depth == 0 ? Theme.ColAccent
                  : node.Depth == 1 ? Theme.ColSuccess
                  : Theme.ColTextMuted;

        bool open = ImGui.TreeNodeEx(
            $"{indent}{node.Label}  |  {node.PreviewHex}",
            node.Children.Count > 0
                ? ImGuiTreeNodeFlags.DefaultOpen
                : ImGuiTreeNodeFlags.Leaf);

        if (ImGui.IsItemClicked() && _scanner != null)
        {
            var f = MemoryField.Bytes(node.Label, node.Address, 32);
            f.Refresh(_scanner);
            _fieldBatch.Add(f);
        }
        if (ImGui.IsItemHovered())
            ImGui.SetTooltip($"Click to add to field list\n{node.AddrHex}");

        if (open)
        {
            foreach (var child in node.Children)
                RenderGraphNode(child);
            ImGui.TreePop();
        }
    }

    // -- Snapshots panel ---------------------------------------------------

    private void RenderSnapshots()
    {
        ImGui.SetNextItemWidth(160);
        ImGui.InputText("Address##snap", ref _snapAddrInput, 20);
        ImGui.SameLine();
        ImGui.SetNextItemWidth(80);
        ImGui.InputText("Length##snap", ref _snapLenInput, 10);
        ImGui.SameLine();
        if (ImGui.Button("Take Snapshot", new Vector2(120, 24)) && _snapshots != null)
        {
            if (TryParseHex(_snapAddrInput, out ulong addr) &&
                int.TryParse(_snapLenInput, out int len))
                _snapshots.Take((IntPtr)addr, len);
        }
        ImGui.SameLine();
        if (ImGui.Button("Use Player Addr") && _monitor?.State?.IsValid == true)
        {
            _snapAddrInput = $"{(ulong)_monitor.State.BaseAddress:X}";
            _snapLenInput  = "256";
        }

        ImGui.Separator();

        var avail = ImGui.GetContentRegionAvail();
        float topH = avail.Y * 0.35f;

        // Snapshot list
        ImGui.BeginChild("##snap_list", new Vector2(0, topH), ImGuiChildFlags.Borders);
        if (_snapshots != null)
        {
            foreach (var snap in _snapshots.Snapshots)
            {
                bool selA = _snapA == snap, selB = _snapB == snap;
                string label = $"{snap.Name}  ({snap.Length}B @ {snap.AddrHex})  {snap.Timestamp:HH:mm:ss}";

                if (selA) ImGui.PushStyleColor(ImGuiCol.Text, Theme.ColSuccess);
                if (selB) ImGui.PushStyleColor(ImGuiCol.Text, Theme.ColWarn);

                ImGui.Text(label);
                ImGui.SameLine(ImGui.GetContentRegionAvail().X - 140);

                if (ImGui.Button($"Set A##{snap.Timestamp.Ticks}")) _snapA = snap;
                ImGui.SameLine();
                if (ImGui.Button($"Set B##{snap.Timestamp.Ticks}")) _snapB = snap;
                ImGui.SameLine();
                if (ImGui.Button($"X##{snap.Timestamp.Ticks}"))     _snapshots.Remove(snap);

                if (selA || selB) ImGui.PopStyleColor();
            }
        }
        ImGui.EndChild();

        // Diff
        if (_snapA != null && _snapB != null && ImGui.Button("Compare A->B", new Vector2(120, 26)))
        {
            var diff = _snapshots!.Diff(_snapA, _snapB);
            _snapDiffText = _snapshots.FormatDiff(diff);
        }
        ImGui.SameLine();
        ImGui.Text($"A: {_snapA?.Name ?? "--"}  |  B: {_snapB?.Name ?? "--"}");

        ImGui.BeginChild("##diff_view", new Vector2(0, avail.Y - topH - 60), ImGuiChildFlags.Borders);
        if (!string.IsNullOrEmpty(_snapDiffText))
            ImGui.TextUnformatted(_snapDiffText);
        else
            ImGui.TextColored(Theme.ColTextMuted, "Select A and B snapshots then click Compare.");
        ImGui.EndChild();
    }

    // -- Log panel ---------------------------------------------------------

    private void RenderLog()
    {
        ImGui.SetNextItemWidth(200);
        ImGui.InputText("Filter##log", ref _logFilter, 64);
        ImGui.SameLine();
        ImGui.Checkbox("Auto-scroll##log", ref _logAutoScroll);
        ImGui.SameLine();
        if (ImGui.Button("Clear##log")) _log.Clear();
        ImGui.SameLine();
        if (ImGui.Button("Export##log"))
            _log.ExportToFile(Path.Combine(_state.ExportDirectory,
                $"memlog_{DateTime.Now:yyyyMMdd_HHmmss}.txt"));

        ImGui.Separator();

        var avail = ImGui.GetContentRegionAvail();
        ImGui.BeginChild("##log_view", new Vector2(0, avail.Y - 10), ImGuiChildFlags.Borders);

        var entries = _log.GetLast(500);
        foreach (var e in entries)
        {
            if (!string.IsNullOrEmpty(_logFilter) &&
                !e.Message.Contains(_logFilter, StringComparison.OrdinalIgnoreCase))
                continue;

            ImGui.TextColored(e.Color, e.Prefix);
            ImGui.SameLine();
            ImGui.Text(e.Message);
        }

        if (_logAutoScroll && ImGui.GetScrollY() < ImGui.GetScrollMaxY())
            ImGui.SetScrollHereY(1.0f);

        ImGui.EndChild();
    }

    // -- Dump panel --------------------------------------------------------

    private void RenderDump()
    {
        ImGui.SetNextItemWidth(160);
        ImGui.InputText("Address##dump", ref _dumpAddrInput, 20);
        ImGui.SameLine();
        ImGui.SetNextItemWidth(80);
        ImGui.InputText("Length##dump", ref _dumpLenInput, 10);
        ImGui.SameLine();
        if (ImGui.Button("Hex Dump", new Vector2(90, 24)) && _dumper != null)
        {
            if (TryParseHex(_dumpAddrInput, out ulong addr) &&
                int.TryParse(_dumpLenInput, out int len))
                _dumpText = _dumper.HexDump((IntPtr)addr, Math.Min(len, 16384));
        }
        ImGui.SameLine();
        if (ImGui.Button("Struct Dump", new Vector2(90, 24)) && _dumper != null)
        {
            if (TryParseHex(_dumpAddrInput, out ulong addr) &&
                int.TryParse(_dumpLenInput, out int len))
                _dumpText = _dumper.StructDump((IntPtr)addr, Math.Min(len, 1024));
        }
        ImGui.SameLine();
        if (ImGui.Button("Save to File") && _dumper != null)
        {
            if (TryParseHex(_dumpAddrInput, out ulong addr) &&
                int.TryParse(_dumpLenInput, out int len))
                _dumper.DumpToFile((IntPtr)addr, Math.Min(len, 16384), _state.ExportDirectory);
        }

        ImGui.Separator();

        var avail = ImGui.GetContentRegionAvail();
        ImGui.BeginChild("##dump_view", new Vector2(0, avail.Y - 10), ImGuiChildFlags.Borders);
        if (!string.IsNullOrEmpty(_dumpText))
            ImGui.TextUnformatted(_dumpText);
        else
            ImGui.TextColored(Theme.ColTextMuted, "Enter an address and click a dump button.");
        ImGui.EndChild();
    }

    // -- Attach / Detach ---------------------------------------------------

    private void TryAttach()
    {
        // Strip .exe if user typed it
        string clean = _processName.Replace(".exe","").Replace(".EXE","").Trim();
        var procs = Process.GetProcessesByName(clean);
        if (procs.Length == 0)
        {
            // Fuzzy fallback: match any process containing "hytale" or the typed name
            procs = Process.GetProcesses()
                .Where(p => { try { return p.ProcessName.ToLower().Contains("hytale") ||
                                         p.ProcessName.ToLower().Contains(clean.ToLower()); }
                              catch { return false; } })
                .ToArray();
        }
        if (procs.Length == 0)
        {
            _log.Warn($"[ATTACH] Process '{_processName}' not found. Is HytaleClient.exe running?");
            return;
        }

        var proc = procs[0];
        _processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, proc.Id);
        if (_processHandle == IntPtr.Zero)
        {
            _log.Error($"[ATTACH] OpenProcess failed. Run as Administrator.");
            return;
        }

        // Build subsystem graph
        _scanner       = new SignatureScanner(_processHandle, _log);
        _walker        = new PointerWalker(_scanner, _log);
        _validator     = new StructureValidator(_scanner);
        _dumper        = new MemoryDumper(_scanner, _log);
        _snapshots     = new SnapshotSystem(_scanner, _log);
        _graph         = new PointerGraph(_scanner, _log);
        _discovery     = new LocalPlayerDiscovery(_scanner, _walker, _validator, _log);
        _monitor       = new LocalPlayerMonitor(_discovery, _scanner, _log);
        _entityScanner = new EntityScanner(_scanner, _validator, _log);
        _fieldBatch    = new MemoryFieldBatch(_scanner) { RefreshHz = _refreshHz };

        _isAttached = true;
        _log.Info($"[ATTACH] Attached to {proc.ProcessName} (PID {proc.Id})");
    }

    private void Detach()
    {
        _monitor?.Stop();
        if (_processHandle != IntPtr.Zero) { CloseHandle(_processHandle); _processHandle = IntPtr.Zero; }
        _isAttached = false;
        _log.Info("[ATTACH] Detached");
    }

    // -- Discovery flow -----------------------------------------------------

    private void StartPlayerDiscovery()
    {
        if (_discovery == null || _discovering) return;
        _discovering = true;
        _discoverStatus = "Scanning...";

        Task.Run(() =>
        {
            try
            {
                var state = _discovery.Discover();
                if (state != null)
                {
                    _discoverStatus = $"Found @ {state.AddrHex} (conf={state.Confidence:P0})";
                    _monitor!.Start();
                    _fieldBatch.PopulateFromPlayerState(state);
                    _log.Info($"[UI] Player discovered, monitor started");
                }
                else
                {
                    _discoverStatus = "Not found -- try after joining a world";
                }
            }
            catch (Exception ex)
            {
                _discoverStatus = $"Error: {ex.Message}";
                _log.Error($"[DISCOVER] {ex.Message}");
            }
            finally { _discovering = false; }
        });
    }

    private void StartEntityScan()
    {
        if (_entityScanner == null || _entityScanning) return;
        _entityScanning = true;
        _entityCandidates.Clear();

        Task.Run(() =>
        {
            try { _entityCandidates = _entityScanner.Scan(200); }
            catch (Exception ex) { _log.Error($"[ENTITY] {ex.Message}"); }
            finally { _entityScanning = false; }
        });
    }

    // -- Helpers -----------------------------------------------------------

    private void AddFieldFromInput(FieldKind kind, int size)
    {
        if (_scanner == null || !TryParseHex(_jumpAddrInput, out ulong addr)) return;
        var f = new MemoryField
        {
            Name    = $"{kind}@0x{addr:X}",
            Address = (IntPtr)addr,
            Size    = size,
            Kind    = kind
        };
        f.Refresh(_scanner);
        _fieldBatch.Add(f);
        ImGui.CloseCurrentPopup();
    }

    private static bool TryParseHex(string s, out ulong result)
    {
        s = s.Replace("0x", "").Replace("0X", "").Trim();
        return ulong.TryParse(s, System.Globalization.NumberStyles.HexNumber, null, out result);
    }

    private static string TruncateStr(string s, int max) =>
        s.Length <= max ? s : s[..max] + "...";

    private static void Row(string label, string value)
    {
        ImGui.TextColored(Theme.ColTextMuted, label + ":");
        ImGui.SameLine(120);
        ImGui.Text(value);
    }

    private static void Col(string label, string value)
    {
        ImGui.TextColored(Theme.ColTextMuted, label + ":");
        ImGui.SameLine(120);
        ImGui.Text(value);
    }

    private static void StatCard(string label, string value, Vector4 color)
    {
        ImGui.BeginGroup();
        ImGui.BeginChild($"##sc_{label}", new Vector2(120, 60), ImGuiChildFlags.Borders);
        ImGui.TextColored(color, label);
        ImGui.TextColored(color, value);
        ImGui.EndChild();
        ImGui.EndGroup();
    }
}
