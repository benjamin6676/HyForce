// MemoryResearchTab.cs  v3
// Full memory research suite:
//   Entity Finder    — heap scan, real-time results table
//   Bookmarks        — star/favorite any hit, give it a label
//   Saved Scans      — re-run a scan by pointer path, auto-update values
//   Struct Viewer    — hex + float/double overlay for any hit
//   Client vs Packet — compares memory values to captured packet fields
//   Pattern Scan     — arbitrary hex pattern + presets
//   String Heap      — scan for ASCII strings, filter by keyword
//   Module Map       — list loaded DLLs
//   Notes            — exportable research notes

using HyForce.Core;
using HyForce.Networking;
using ImGuiNET;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Text.Json;

namespace HyForce.Tabs
{
    public class MemoryResearchTab : ITab
    {
        public string Name => "Memory Research";

        private readonly AppState _state;
        private readonly PipeCaptureServer _pipe;

        // ── Bookmarks ─────────────────────────────────────────────
        // A bookmarked hit has a user label and can be re-observed
        private readonly List<BookmarkedHit> _bookmarks = new();
        private string _bookmarkLabel = "";
        private readonly string _bookmarkFile;

        // ── Saved scans (pointer watch list) ──────────────────────
        // Each saved entry auto-refreshes: triggers a new memscan when DLL connects
        private readonly List<SavedScan> _savedScans = new();
        private bool _autoRefreshScans = true;
        private DateTime _lastAutoRefresh = DateTime.MinValue;

        // ── Pattern scanner ───────────────────────────────────────
        private string _patternHex = "3F 80 00 00";
        private string _stringFilter = "";
        private int _minStrLen = 5;

        // ── Sub-tab ───────────────────────────────────────────────
        private int _subTab = 0;
        private int _selectedHit = -1;
        private int _selectedBm = -1;

        // Notes editor
        private string _notes = DefaultNotes;

        public MemoryResearchTab(AppState state, PipeCaptureServer pipe)
        {
            _state = state;
            _pipe = pipe;
            _bookmarkFile = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "HyForce", "bookmarks.json");
            LoadBookmarks();
        }

        public void Render()
        {
            // Auto-refresh saved scans every 10s if DLL connected
            if (_autoRefreshScans && _pipe.DllConnected &&
                (DateTime.Now - _lastAutoRefresh).TotalSeconds > 10)
            {
                _pipe.MemScan();
                _lastAutoRefresh = DateTime.Now;
            }

            ImGui.TextColored(new Vector4(0.75f, 0.45f, 1f, 1f), "Memory Research");
            ImGui.SameLine();
            bool live = _pipe.DllConnected;
            ImGui.TextColored(live ? new Vector4(0.1f, 1f, 0.4f, 1f) : new Vector4(0.7f, 0.3f, 0.3f, 1f),
                live ? $"● DLL Live" : "○ DLL offline");
            ImGui.SameLine();
            if (ImGui.SmallButton("Scan Now"))
            { _pipe.MemHits.Clear(); _pipe.MemScan(); }
            ImGui.SameLine();
            ImGui.Checkbox("Auto-refresh 10s", ref _autoRefreshScans);
            ImGui.Separator();

            string[] tabs = { "Entity Finder", $"Bookmarks ({_bookmarks.Count})",
                              "Saved Scans", "Struct Viewer",
                              "Client↔Packet", "Pattern Scan",
                              "String Heap", "Module Map", "Notes", "Live Watch" };

            ImGui.SetNextItemWidth(-1);
            ImGui.BeginTabBar("##mrt");
            for (int i = 0; i < tabs.Length; i++)
                if (ImGui.BeginTabItem(tabs[i] + $"##mt{i}"))
                { _subTab = i; ImGui.EndTabItem(); }
            ImGui.EndTabBar();

            ImGui.Spacing();
            switch (_subTab)
            {
                case 0: RenderEntityFinder(); break;
                case 1: RenderBookmarks(); break;
                case 2: RenderSavedScans(); break;
                case 3: RenderStructViewer(); break;
                case 4: RenderClientVsPacket(); break;
                case 5: RenderPatternScan(); break;
                case 6: RenderStringHeap(); break;
                case 7: RenderModuleMap(); break;
                case 8: RenderNotes(); break;
                case 9: RenderLiveWatch(); break;
            }
        }

        // ─── Entity Finder ────────────────────────────────────────
        private void RenderEntityFinder()
        {
            ImGui.TextColored(Accent, "Entity / Player Struct Finder");
            ImGui.TextWrapped("Scans process memory for structs matching the pattern: [float health][float maxHP][double X][double Y][double Z][float vx][float vy][float vz]. NOTE: JVM heap objects move on GC. Re-scan periodically. If no hits: Hytale may use different struct layout — try Pattern Scan with known values.");
            ImGui.Spacing();

            ImGui.Text($"Results: {_pipe.MemHits.Count}");
            ImGui.SameLine();
            if (ImGui.SmallButton("Clear")) _pipe.MemHits.Clear();
            ImGui.SameLine();
            if (ImGui.SmallButton("Re-Scan")) { _pipe.MemHits.Clear(); _pipe.MemScan(); }
            ImGui.Separator();

            float tableH = ImGui.GetContentRegionAvail().Y - 4;
            if (ImGui.BeginTable("##ent", 8,
                ImGuiTableFlags.Borders | ImGuiTableFlags.RowBg |
                ImGuiTableFlags.ScrollY | ImGuiTableFlags.Resizable,
                new Vector2(-1, tableH)))
            {
                ImGui.TableSetupScrollFreeze(0, 1);
                ImGui.TableSetupColumn("★", ImGuiTableColumnFlags.WidthFixed, 24);
                ImGui.TableSetupColumn("#", ImGuiTableColumnFlags.WidthFixed, 28);
                ImGui.TableSetupColumn("Address", ImGuiTableColumnFlags.WidthFixed, 145);
                ImGui.TableSetupColumn("HP", ImGuiTableColumnFlags.WidthFixed, 90);
                ImGui.TableSetupColumn("X", ImGuiTableColumnFlags.WidthFixed, 90);
                ImGui.TableSetupColumn("Y", ImGuiTableColumnFlags.WidthFixed, 80);
                ImGui.TableSetupColumn("Z", ImGuiTableColumnFlags.WidthFixed, 90);
                ImGui.TableSetupColumn("Vel", ImGuiTableColumnFlags.WidthFixed, 100);
                ImGui.TableSetupColumn("Actions", ImGuiTableColumnFlags.WidthStretch);
                ImGui.TableHeadersRow();

                lock (_pipe.MemHits)
                {
                    var hits = _pipe.MemHits;
                    for (int i = 0; i < hits.Count; i++)
                    {
                        var h = hits[i];
                        bool sel = _selectedHit == i;
                        ImGui.TableNextRow();

                        // ★ bookmark button
                        ImGui.TableSetColumnIndex(0);
                        bool already = _bookmarks.Any(b => b.Address == h.Address);
                        if (already) ImGui.TextColored(Yellow, "★");
                        else if (ImGui.SmallButton($"+##bm{i}")) OpenBookmarkDialog(h);

                        ImGui.TableSetColumnIndex(1);
                        ImGui.Text($"{i}");

                        ImGui.TableSetColumnIndex(2);
                        if (ImGui.Selectable($"0x{h.Address:X14}##r{i}", sel,
                            ImGuiSelectableFlags.SpanAllColumns))
                            _selectedHit = i;

                        ImGui.TableSetColumnIndex(3);
                        float frac = h.MaxHealth > 0 ? h.Health / h.MaxHealth : 0;
                        var hc = frac > 0.6f ? Green : frac > 0.3f ? Yellow : Red;
                        ImGui.TextColored(hc, $"{h.Health:F0}/{h.MaxHealth:F0}");

                        ImGui.TableSetColumnIndex(4); ImGui.Text($"{h.X:F2}");
                        ImGui.TableSetColumnIndex(5); ImGui.Text($"{h.Y:F2}");
                        ImGui.TableSetColumnIndex(6); ImGui.Text($"{h.Z:F2}");

                        ImGui.TableSetColumnIndex(7);
                        float speed = MathF.Sqrt(h.VelX * h.VelX + h.VelY * h.VelY + h.VelZ * h.VelZ);
                        var vc = speed > 10f ? new Vector4(1f, 0.5f, 0.1f, 1f) : new Vector4(0.6f, 0.6f, 0.6f, 1f);
                        ImGui.TextColored(vc, $"{speed:F1}m/s");

                        ImGui.TableSetColumnIndex(8);
                        if (ImGui.SmallButton($"View##sv{i}"))
                        { _selectedHit = i; _subTab = 3; }
                        ImGui.SameLine();
                        if (ImGui.SmallButton($"Save##ss{i}")) AddSavedScan(h);
                        ImGui.SameLine();
                        if (ImGui.SmallButton($"Export##ex{i}")) ExportStruct(h);
                    }
                }
                ImGui.EndTable();
            }
        }

        // ─── Bookmarks ────────────────────────────────────────────
        private MemScanHit? _pendingBookmarkHit;
        private void OpenBookmarkDialog(MemScanHit h)
        {
            _pendingBookmarkHit = h;
            _bookmarkLabel = $"Entity @ {h.X:F0},{h.Y:F0},{h.Z:F0}  HP={h.Health:F0}";
        }

        private void RenderBookmarks()
        {
            ImGui.TextColored(Accent, "Bookmarked Memory Locations");
            ImGui.TextWrapped("Starred entities from the Entity Finder appear here. Each bookmark stores the base address and field snapshot. Use 'Refresh' to re-read current values from memory via the DLL.");
            ImGui.Spacing();

            // Pending bookmark dialog
            if (_pendingBookmarkHit != null)
            {
                ImGui.TextColored(Yellow, "New bookmark — enter label:");
                ImGui.SetNextItemWidth(400);
                ImGui.InputText("##bmlbl", ref _bookmarkLabel, 128);
                ImGui.SameLine();
                if (ImGui.Button("Save"))
                {
                    var bm = new BookmarkedHit
                    {
                        Address = _pendingBookmarkHit.Address,
                        Label = _bookmarkLabel,
                        Category = GuessCategory(_pendingBookmarkHit),
                        CreatedAt = DateTime.Now,
                        LastSeen = DateTime.Now,
                        LastHealth = _pendingBookmarkHit.Health,
                        LastMaxHP = _pendingBookmarkHit.MaxHealth,
                        LastX = _pendingBookmarkHit.X,
                        LastY = _pendingBookmarkHit.Y,
                        LastZ = _pendingBookmarkHit.Z,
                        StructBytes = _pendingBookmarkHit.StructBytes,
                    };
                    _bookmarks.Add(bm);
                    SaveBookmarks();
                    _pendingBookmarkHit = null;
                }
                ImGui.SameLine();
                if (ImGui.Button("Cancel")) _pendingBookmarkHit = null;
                ImGui.Separator();
            }

            if (_bookmarks.Count == 0)
            {
                ImGui.TextColored(Muted, "No bookmarks yet. Click ★ in Entity Finder to add one.");
                return;
            }

            // Group by category
            var groups = _bookmarks.GroupBy(b => b.Category).OrderBy(g => g.Key);
            foreach (var g in groups)
            {
                ImGui.TextColored(Accent, $"── {g.Key} ──");
                foreach (var bm in g.ToList())
                {
                    bool sel = (_selectedBm == _bookmarks.IndexOf(bm));
                    ImGui.PushID(bm.Address.GetHashCode());

                    // Inline editable label
                    string lbl = bm.Label;
                    ImGui.SetNextItemWidth(260);
                    if (ImGui.InputText("##bmedit", ref lbl, 128))
                    { bm.Label = lbl; SaveBookmarks(); }
                    ImGui.SameLine();

                    // Live values (updated when DLL returns a new scan hit with matching address)
                    var live = _pipe.MemHits.FirstOrDefault(h => h.Address == bm.Address);
                    if (live != null)
                    {
                        bm.LastHealth = live.Health; bm.LastMaxHP = live.MaxHealth;
                        bm.LastX = live.X; bm.LastY = live.Y; bm.LastZ = live.Z;
                        bm.LastSeen = DateTime.Now;
                    }

                    ImGui.TextColored(live != null ? Green : Muted,
                        $"HP {bm.LastHealth:F0}/{bm.LastMaxHP:F0}  ({bm.LastX:F1}, {bm.LastY:F1}, {bm.LastZ:F1})");
                    ImGui.SameLine();
                    ImGui.TextColored(Muted, $"0x{bm.Address:X14}");
                    ImGui.SameLine();

                    if (ImGui.SmallButton("View")) { _selectedBm = _bookmarks.IndexOf(bm); _subTab = 3; }
                    ImGui.SameLine();
                    if (ImGui.SmallButton("Delete"))
                    { _bookmarks.Remove(bm); SaveBookmarks(); ImGui.PopID(); break; }

                    ImGui.TextColored(Muted, $"  Created {bm.CreatedAt:HH:mm:ss}  Last seen {bm.LastSeen:HH:mm:ss}");
                    ImGui.PopID();
                    ImGui.Separator();
                }
            }

            ImGui.Spacing();
            if (ImGui.Button("Export All Bookmarks"))
                ExportBookmarks();
            ImGui.SameLine();
            if (ImGui.Button("Refresh All (re-scan)"))
            { _pipe.MemHits.Clear(); _pipe.MemScan(); }
        }

        // ─── Saved Scans ──────────────────────────────────────────
        private void AddSavedScan(MemScanHit h)
        {
            if (_savedScans.Any(s => s.Address == h.Address)) return;
            _savedScans.Add(new SavedScan
            {
                Address = h.Address,
                Name = $"Entity 0x{h.Address:X10}",
                Fields = new List<WatchField>
                {
                    new("Health",    0,  FieldType.Float32),
                    new("MaxHealth", 4,  FieldType.Float32),
                    new("X",         8,  FieldType.Float64),
                    new("Y",         16, FieldType.Float64),
                    new("Z",         24, FieldType.Float64),
                    new("VelX",      32, FieldType.Float32),
                    new("VelY",      36, FieldType.Float32),
                    new("VelZ",      40, FieldType.Float32),
                }
            });
        }

        private void RenderSavedScans()
        {
            ImGui.TextColored(Accent, "Saved Scan Watch List");
            ImGui.TextWrapped("Entities saved here get their values updated every time the DLL returns a scan hit with a matching address. NOTE: JVM GC moves objects — addresses become stale. Re-scan to find the new address, then update the entry.");
            ImGui.Spacing();

            ImGui.Checkbox("Auto-refresh on DLL connection", ref _autoRefreshScans);
            ImGui.SameLine();
            if (ImGui.SmallButton("Refresh All")) { _pipe.MemHits.Clear(); _pipe.MemScan(); }
            ImGui.Spacing();

            if (_savedScans.Count == 0)
            {
                ImGui.TextColored(Muted, "No saved scans. Click 'Save' on an entity in the Entity Finder.");
                return;
            }

            foreach (var scan in _savedScans.ToList())
            {
                // Update fields from latest scan hit
                var live = _pipe.MemHits.FirstOrDefault(h => h.Address == scan.Address);
                if (live?.StructBytes.Length >= 48)
                {
                    foreach (var f in scan.Fields)
                        f.Update(live.StructBytes);
                    scan.LastUpdate = DateTime.Now;
                    scan.Stale = false;
                }
                else if ((DateTime.Now - scan.LastUpdate).TotalSeconds > 30)
                    scan.Stale = true;

                string header = scan.Name +
                    (scan.Stale ? "  [STALE — address moved, re-scan]" : $"  (updated {scan.LastUpdate:HH:mm:ss})");
                bool open = ImGui.CollapsingHeader(header + $"##sc{scan.Address}");

                // Inline name edit
                ImGui.SameLine();
                if (ImGui.SmallButton($"✕##del{scan.Address}"))
                { _savedScans.Remove(scan); break; }

                if (!open) continue;

                ImGui.PushID((int)scan.Address);
                var name = scan.Name;
                if (ImGui.InputText("Name##sn", ref name, 64))
                    scan.Name = name;

                if (ImGui.BeginTable($"##wf{scan.Address}", 4,
                    ImGuiTableFlags.Borders | ImGuiTableFlags.RowBg))
                {
                    ImGui.TableSetupColumn("Field", ImGuiTableColumnFlags.WidthFixed, 100);
                    ImGui.TableSetupColumn("Offset", ImGuiTableColumnFlags.WidthFixed, 60);
                    ImGui.TableSetupColumn("Type", ImGuiTableColumnFlags.WidthFixed, 80);
                    ImGui.TableSetupColumn("Value", ImGuiTableColumnFlags.WidthStretch);
                    ImGui.TableHeadersRow();

                    foreach (var f in scan.Fields)
                    {
                        ImGui.TableNextRow();
                        ImGui.TableSetColumnIndex(0); ImGui.Text(f.Name);
                        ImGui.TableSetColumnIndex(1); ImGui.Text($"+{f.Offset:X2}");
                        ImGui.TableSetColumnIndex(2); ImGui.Text(f.Type.ToString());
                        ImGui.TableSetColumnIndex(3);
                        bool changed = f.HasChanged;
                        if (changed) ImGui.TableSetBgColor(ImGuiTableBgTarget.CellBg,
                            ImGui.ColorConvertFloat4ToU32(new Vector4(0.4f, 0.2f, 0f, 0.6f)));
                        ImGui.TextColored(changed ? Yellow : Vector4.One, f.ValueStr);
                    }
                    ImGui.EndTable();
                }

                // Add custom field
                ImGui.TextColored(Muted, "Add field: ");
                ImGui.SameLine();
                if (ImGui.SmallButton("+float32")) scan.Fields.Add(new WatchField($"f+{scan.Fields.Count * 4}", scan.Fields.Count * 4, FieldType.Float32));
                ImGui.SameLine();
                if (ImGui.SmallButton("+float64")) scan.Fields.Add(new WatchField($"d+{scan.Fields.Count * 8}", scan.Fields.Count * 8, FieldType.Float64));
                ImGui.SameLine();
                if (ImGui.SmallButton("+int32")) scan.Fields.Add(new WatchField($"i+{scan.Fields.Count * 4}", scan.Fields.Count * 4, FieldType.Int32));
                ImGui.SameLine();
                if (ImGui.SmallButton("+byte")) scan.Fields.Add(new WatchField($"b+{scan.Fields.Count}", scan.Fields.Count, FieldType.Byte));

                ImGui.PopID();
                ImGui.Spacing();
            }
        }

        // ─── Struct Viewer ────────────────────────────────────────
        private void RenderStructViewer()
        {
            // Show selected hit (from entity finder or bookmark)
            MemScanHit? hit = null;
            if (_selectedHit >= 0 && _selectedHit < _pipe.MemHits.Count)
                hit = _pipe.MemHits[_selectedHit];
            else if (_selectedBm >= 0 && _selectedBm < _bookmarks.Count)
            {
                var bm = _bookmarks[_selectedBm];
                hit = new MemScanHit
                {
                    Address = bm.Address,
                    Health = bm.LastHealth,
                    MaxHealth = bm.LastMaxHP,
                    X = bm.LastX,
                    Y = bm.LastY,
                    Z = bm.LastZ,
                    StructBytes = bm.StructBytes
                };
            }

            if (hit == null)
            {
                ImGui.TextColored(Muted, "Select an entry in Entity Finder or Bookmarks to view its struct here.");
                return;
            }

            ImGui.TextColored(Accent, $"Struct @ 0x{hit.Address:X14}");
            ImGui.SameLine();
            ImGui.TextColored(Muted, $"  {hit.StructBytes.Length} bytes  snapshot at {hit.FoundAt:HH:mm:ss}");
            ImGui.SameLine();
            if (ImGui.SmallButton("Export bin")) ExportStruct(hit);
            ImGui.Separator();

            if (ImGui.BeginTabBar("##sv2"))
            {
                if (ImGui.BeginTabItem("Hex Dump"))
                {
                    var sb = new StringBuilder();
                    byte[] b = hit.StructBytes;
                    for (int row = 0; row < b.Length; row += 16)
                    {
                        sb.Append($"  +{row:X4}  ");
                        for (int c = 0; c < 16; c++)
                        {
                            if (row + c < b.Length) sb.Append($"{b[row + c]:X2} ");
                            else sb.Append("   ");
                            if (c == 7) sb.Append(" ");
                        }
                        sb.Append("  ");
                        for (int c = 0; c < 16 && row + c < b.Length; c++)
                        { char ch = (char)b[row + c]; sb.Append(ch >= 0x20 && ch < 0x7F ? ch : '.'); }
                        sb.AppendLine();
                    }
                    var hexDump = sb.ToString();
                    ImGui.InputTextMultiline("##hexdump", ref hexDump, (uint)hexDump.Length + 1,
                        new Vector2(-1, -1), ImGuiInputTextFlags.ReadOnly);
                    ImGui.EndTabItem();
                }
                if (ImGui.BeginTabItem("Interpreted Fields"))
                {
                    byte[] b = hit.StructBytes;
                    if (ImGui.BeginTable("##interp", 4,
                        ImGuiTableFlags.Borders | ImGuiTableFlags.RowBg | ImGuiTableFlags.ScrollY))
                    {
                        ImGui.TableSetupColumn("Offset", ImGuiTableColumnFlags.WidthFixed, 60);
                        ImGui.TableSetupColumn("Hex", ImGuiTableColumnFlags.WidthFixed, 120);
                        ImGui.TableSetupColumn("float32", ImGuiTableColumnFlags.WidthFixed, 120);
                        ImGui.TableSetupColumn("float64", ImGuiTableColumnFlags.WidthStretch);
                        ImGui.TableHeadersRow();

                        for (int off = 0; off + 4 <= b.Length; off += 4)
                        {
                            ImGui.TableNextRow();
                            ImGui.TableSetColumnIndex(0); ImGui.Text($"+{off:X2}");
                            ImGui.TableSetColumnIndex(1);
                            string hex = off + 4 <= b.Length ? BitConverter.ToString(b, off, 4) : "";
                            ImGui.Text(hex);
                            ImGui.TableSetColumnIndex(2);
                            float f = off + 4 <= b.Length ? BitConverter.ToSingle(b, off) : 0;
                            if (!float.IsNaN(f) && !float.IsInfinity(f) && Math.Abs(f) < 1e9)
                                ImGui.TextColored(Yellow, $"{f:G6}");
                            else ImGui.TextColored(Muted, "---");
                            ImGui.TableSetColumnIndex(3);
                            if (off + 8 <= b.Length)
                            {
                                double d = BitConverter.ToDouble(b, off);
                                if (!double.IsNaN(d) && !double.IsInfinity(d) && Math.Abs(d) < 1e12)
                                    ImGui.TextColored(new Vector4(0.5f, 0.9f, 1f, 1f), $"{d:G10}");
                                else ImGui.TextColored(Muted, "---");
                            }
                        }
                        ImGui.EndTable();
                    }
                    ImGui.EndTabItem();
                }
                ImGui.EndTabBar();
            }
        }

        // ─── Client vs Packet ─────────────────────────────────────
        private void RenderClientVsPacket()
        {
            ImGui.TextColored(Accent, "Client Memory  ↔  Outgoing Packet Values");
            ImGui.TextWrapped("If what the client holds in memory differs from what it sends to the server, that's a server-trust vulnerability. Every mismatch is a potential finding.");
            ImGui.Spacing();

            lock (_pipe.MemHits)
            {
                if (_pipe.MemHits.Count == 0)
                { ImGui.TextColored(Muted, "Run entity scan first."); return; }

                var lp = _pipe.MemHits[0];
                ImGui.TextColored(new Vector4(0.4f, 0.9f, 1f, 1f), "First scan hit (local player candidate):");
                if (ImGui.BeginTable("##lpv", 2, ImGuiTableFlags.Borders))
                {
                    ImGui.TableSetupColumn("Field", ImGuiTableColumnFlags.WidthFixed, 120);
                    ImGui.TableSetupColumn("Memory Value", ImGuiTableColumnFlags.WidthStretch);
                    ImGui.TableHeadersRow();
                    void Row(string k, string v)
                    {
                        ImGui.TableNextRow();
                        ImGui.TableSetColumnIndex(0); ImGui.Text(k);
                        ImGui.TableSetColumnIndex(1); ImGui.Text(v);
                    }
                    Row("Address", $"0x{lp.Address:X14}");
                    Row("Health", $"{lp.Health:F3}  /  {lp.MaxHealth:F3}");
                    Row("Position", $"({lp.X:F4}, {lp.Y:F4}, {lp.Z:F4})");
                    Row("Scan time", lp.FoundAt.ToString("HH:mm:ss.fff"));
                    ImGui.EndTable();
                }
            }

            ImGui.Spacing();
            ImGui.TextColored(Muted, "Packet-side position values will appear here once decryption is working.");
            ImGui.TextColored(Muted, "The hook fires stats every 5s — watch STATS lines in the Log tab to confirm");
            ImGui.TextColored(Muted, "which hook variant (WSASendTo or sendto) is catching Hytale's traffic.");
            ImGui.Spacing();

            // Show recent packet count as proxy for whether capture is working
            ImGui.TextColored(new Vector4(0.5f, 0.9f, 0.5f, 1f),
                $"Packets captured so far: {_pipe.PacketCount}");
            if (_pipe.PacketCount == 0)
                ImGui.TextColored(Red, "0 packets — DLL hooks not firing. Check STATS in Log tab.");
            ImGui.TextColored(Red, "If all 4 fire counts are 0, Hytale may use IOCP (async I/O).");
            ImGui.TextColored(Red, "Next step: WinDivert capture (see Settings tab for setup guide).");
        }

        // ─── Pattern Scan ─────────────────────────────────────────
        private void RenderPatternScan()
        {
            ImGui.TextColored(Accent, "Byte Pattern Scanner");
            ImGui.TextWrapped("Know a value that exists in a struct (e.g. your exact HP = 87.5)? Convert it to hex and scan for it. Then watch which address changes when you take damage — that's the live struct.");
            ImGui.Spacing();

            ImGui.SetNextItemWidth(460);
            ImGui.InputText("Hex pattern##pat", ref _patternHex, 512);
            ImGui.SameLine();
            ImGui.TextColored(Muted, "space-separated, ?? = wildcard");

            ImGui.Spacing();
            ImGui.Text("Value → Hex converters:");
            float fIn = 0; double dIn = 0; int iIn = 0;
            ImGui.SetNextItemWidth(120); ImGui.InputFloat("float##fi", ref fIn);
            ImGui.SameLine();
            if (ImGui.SmallButton("Use##f"))
                _patternHex = BitConverter.ToString(BitConverter.GetBytes(fIn)).Replace('-', ' ');
            ImGui.SameLine(0, 20);
            ImGui.SetNextItemWidth(120); ImGui.InputDouble("double##di", ref dIn);
            ImGui.SameLine();
            if (ImGui.SmallButton("Use##d"))
                _patternHex = BitConverter.ToString(BitConverter.GetBytes(dIn)).Replace('-', ' ');
            ImGui.SameLine(0, 20);
            ImGui.SetNextItemWidth(120); ImGui.InputInt("int32##ii", ref iIn);
            ImGui.SameLine();
            if (ImGui.SmallButton("Use##i"))
                _patternHex = BitConverter.ToString(BitConverter.GetBytes(iIn)).Replace('-', ' ');

            ImGui.Spacing();
            ImGui.Text("Presets:");
            if (ImGui.SmallButton("float 1.0")) _patternHex = "3F 80 00 00";
            ImGui.SameLine();
            if (ImGui.SmallButton("float 100.0")) _patternHex = "42 C8 00 00";
            ImGui.SameLine();
            if (ImGui.SmallButton("\"Hytale\"")) _patternHex = "48 79 74 61 6C 65";
            ImGui.SameLine();
            if (ImGui.SmallButton("\"QUIC\"")) _patternHex = "51 55 49 43";
            ImGui.SameLine();
            if (ImGui.SmallButton("UUID pattern")) _patternHex = "?? ?? ?? ?? - ?? ?? - ?? ?? - ?? ?? - ?? ?? ?? ?? ?? ??";

            ImGui.Spacing();
            if (ImGui.Button("Trigger Scan", new Vector2(140, 28)))
            { _pipe.MemHits.Clear(); _pipe.MemScan(); _subTab = 0; }
            ImGui.SameLine();
            ImGui.TextColored(Muted, "→ results appear in Entity Finder tab");

            ImGui.Spacing();
            ImGui.Separator();
            ImGui.TextColored(Muted, "Workflow for finding unknown structs:");
            ImGui.TextColored(Muted, "  1. Note a known value (your HP = 87.5)");
            ImGui.TextColored(Muted, "  2. Enter it in the float converter → click Use");
            ImGui.TextColored(Muted, "  3. Scan, note all addresses found");
            ImGui.TextColored(Muted, "  4. Change the value in-game (take damage)");
            ImGui.TextColored(Muted, "  5. Re-scan with new value — surviving address = live struct");
            ImGui.TextColored(Muted, "  6. Inspect surrounding bytes in Struct Viewer");
            ImGui.TextColored(Muted, "  7. Map all fields → cross-reference with captured packets");
        }

        // ─── String Heap ──────────────────────────────────────────
        private void RenderStringHeap()
        {
            ImGui.TextColored(Accent, "String Heap Scanner");
            ImGui.TextWrapped("Finds ASCII strings in client memory. Useful for discovering internal server hostnames, auth tokens, debug strings, and protocol identifiers.");
            ImGui.Spacing();

            ImGui.SetNextItemWidth(280);
            ImGui.InputText("Filter##sf", ref _stringFilter, 128);
            ImGui.SameLine();
            ImGui.SetNextItemWidth(80);
            ImGui.InputInt("Min len", ref _minStrLen);
            _minStrLen = Math.Clamp(_minStrLen, 3, 256);
            ImGui.SameLine();
            if (ImGui.Button("Scan##strscan"))
            { _pipe.SendCommand("STRINGSCAN"); _pipe.MemScan(); }

            ImGui.Spacing();
            ImGui.TextColored(Muted, "Interesting findings to look for:");
            ImGui.TextColored(Muted, "  ● Internal IPs / hostnames  → dev/staging server exposure");
            ImGui.TextColored(Muted, "  ● 'admin' / 'debug' flags    → undocumented privilege levels");
            ImGui.TextColored(Muted, "  ● JWT tokens in cleartext    → auth token leakage");
            ImGui.TextColored(Muted, "  ● Error messages / stack paths → internal code layout");
            ImGui.TextColored(Muted, "  ● Encryption key-like strings  → critical if present");
            ImGui.TextColored(Muted, "Results appear in the Log tab as [DLL] lines.");
        }

        // ─── Module Map ───────────────────────────────────────────
        private void RenderModuleMap()
        {
            ImGui.TextColored(Accent, "Loaded Module Map");
            ImGui.TextWrapped("Shows DLLs loaded in the Hytale process. Identifies which crypto/network libraries are in use and their approximate base addresses.");
            ImGui.Spacing();
            if (ImGui.Button("Request Module List##ml"))
                _pipe.SendCommand("MODLIST");
            ImGui.Spacing();
            ImGui.TextColored(Muted, "Results appear in Log tab as [DLL] MODULE: entries.");
            ImGui.TextColored(Muted, "Look for: BoringSSL, OpenSSL, netty, libquiche, jvm.dll versions.");
        }

        // ─── Notes ────────────────────────────────────────────────
        private void RenderNotes()
        {
            ImGui.TextColored(Accent, "Research Notes");
            ImGui.SetNextItemWidth(-1);
            ImGui.InputTextMultiline("##notes", ref _notes, 16384,
                new Vector2(-1, ImGui.GetContentRegionAvail().Y - 32));
            if (ImGui.Button("Export Notes"))
            {
                try
                {
                    string path = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                        "HyForce", "Exports", $"notes_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
                    Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                    File.WriteAllText(path, _notes);
                    _state.AddInGameLog($"[MEM] Notes exported: {path}");
                }
                catch (Exception ex) { _state.AddInGameLog($"[MEM] {ex.Message}"); }
            }
        }

        // ─── Helpers ──────────────────────────────────────────────
        private static string GuessCategory(MemScanHit h)
        {
            if (h.Health > 0 && h.MaxHealth > 0 && h.MaxHealth >= h.Health)
                return h.MaxHealth > 200 ? "NPC/Entity" : "Player";
            return "Unknown";
        }

        private void ExportStruct(MemScanHit h)
        {
            try
            {
                string path = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "HyForce", "Exports", $"struct_0x{h.Address:X14}_{DateTime.Now:HHmmss}.bin");
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                File.WriteAllBytes(path, h.StructBytes);
                _state.AddInGameLog($"[MEM] Exported: {path}");
            }
            catch (Exception ex) { _state.AddInGameLog($"[MEM] {ex.Message}"); }
        }

        private void ExportBookmarks()
        {
            try
            {
                string path = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "HyForce", "Exports", $"bookmarks_{DateTime.Now:yyyyMMdd}.json");
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                File.WriteAllText(path, JsonSerializer.Serialize(_bookmarks, new JsonSerializerOptions { WriteIndented = true }));
                _state.AddInGameLog($"[MEM] Bookmarks exported: {path}");
            }
            catch (Exception ex) { _state.AddInGameLog($"[MEM] {ex.Message}"); }
        }

        private void LoadBookmarks()
        {
            try
            {
                if (File.Exists(_bookmarkFile))
                {
                    var loaded = JsonSerializer.Deserialize<List<BookmarkedHit>>(File.ReadAllText(_bookmarkFile));
                    if (loaded != null) { _bookmarks.Clear(); _bookmarks.AddRange(loaded); }
                }
            }
            catch { }
        }

        private void SaveBookmarks()
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(_bookmarkFile)!);
                File.WriteAllText(_bookmarkFile, JsonSerializer.Serialize(_bookmarks, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { }
        }

        // ─── Colours ──────────────────────────────────────────────
        static readonly Vector4 Accent = new(0.75f, 0.45f, 1f, 1f);
        static readonly Vector4 Yellow = new(1f, 0.85f, 0.1f, 1f);
        static readonly Vector4 Green = new(0.2f, 1f, 0.4f, 1f);
        static readonly Vector4 Red = new(1f, 0.3f, 0.2f, 1f);
        static readonly Vector4 Muted = new(0.55f, 0.55f, 0.55f, 1f);

        const string DefaultNotes = @"# HyForce Memory Research Notes\n\n## Entity Findings\n[Document entity struct addresses, field offsets, and what values the server trusts]\n\n## Packet-Memory Correlation\n[Note which packet fields correspond to which memory offsets]\n\n## Visibility Issues\n[Does client receive position data for hidden entities?]\n\n## Server Trust Issues\n[Which fields can be influenced client-side and accepted by server?]\n\n## Other Findings\n";


        // ─── Live Watch ───────────────────────────────────────────────
        private string _watchAddrStr = "";
        private int _watchMs = 250;

        private void RenderLiveWatch()
        {
            bool live = _pipe.DllConnected;
            ImGui.Spacing();
            ImGui.TextColored(live ? Green : Red, live ? "● DLL Connected — watch active" : "○ DLL Disconnected");
            ImGui.Separator();
            ImGui.Spacing();

            ImGui.Text("Watch Address (hex):");
            ImGui.SameLine();
            ImGui.SetNextItemWidth(160);
            ImGui.InputText("##waddr", ref _watchAddrStr, 20);
            ImGui.SameLine();
            ImGui.SetNextItemWidth(70);
            ImGui.InputInt("ms##wms", ref _watchMs);
            _watchMs = Math.Max(50, _watchMs);
            ImGui.SameLine();
            if (ImGui.Button("Start Watch") && live)
            {
                if (ulong.TryParse(_watchAddrStr.TrimStart('0', 'x', 'X'),
                    System.Globalization.NumberStyles.HexNumber, null, out ulong addr))
                    _pipe.MemWatch(addr, _watchMs);
                else
                    _state.AddInGameLog("[MEMWATCH] Invalid hex address");
            }
            ImGui.SameLine();
            if (ImGui.Button("Stop")) _pipe.MemWatchStop();
            ImGui.SameLine();
            ImGui.TextColored(Muted, $"{_pipe.MemWatchLog.Count} deltas");

            ImGui.Spacing();
            ImGui.Separator();
            ImGui.TextColored(Yellow, "Live snapshots (most recent first):");
            ImGui.Spacing();

            var log = _pipe.MemWatchLog;
            lock (log)
            {
                for (int i = log.Count - 1; i >= Math.Max(0, log.Count - 30); i--)
                {
                    var e = log[i];
                    ImGui.TextColored(Muted, $"{e.Timestamp:HH:mm:ss.fff}");
                    ImGui.SameLine(0, 8);

                    float frac = e.MaxHealth > 0 ? e.Health / e.MaxHealth : 0;
                    var hc = frac > 0.6f ? Green : frac > 0.3f ? Yellow : Red;
                    ImGui.TextColored(hc, $"HP {e.Health:F1}/{e.MaxHealth:F1}");
                    ImGui.SameLine(0, 8);
                    ImGui.Text($"({e.X:F1}, {e.Y:F1}, {e.Z:F1})");

                    if (e.Snapshot.Length >= 16)
                    {
                        var sb2 = new System.Text.StringBuilder();
                        for (int j = 0; j < Math.Min(16, e.Snapshot.Length); j++)
                            sb2.Append($"{e.Snapshot[j]:X2} ");
                        ImGui.SameLine(0, 8);
                        ImGui.TextColored(Muted, sb2.ToString().TrimEnd());
                    }
                }
            }
            if (log.Count == 0)
                ImGui.TextColored(Muted, "No data yet — bookmark an entity, copy its address, click Start Watch.");
        }

        // ─── Data types ───────────────────────────────────────────────
        public class BookmarkedHit
        {
            public ulong Address { get; set; }
            public string Label { get; set; } = "";
            public string Category { get; set; } = "Unknown";
            public DateTime CreatedAt { get; set; } = DateTime.Now;
            public DateTime LastSeen { get; set; } = DateTime.Now;
            public float LastHealth { get; set; }
            public float LastMaxHP { get; set; }
            public double LastX { get; set; }
            public double LastY { get; set; }
            public double LastZ { get; set; }
            public byte[] StructBytes { get; set; } = Array.Empty<byte>();
        }

        public enum FieldType { Byte, Int16, Int32, Int64, Float32, Float64 }

        public class WatchField
        {
            public string Name { get; set; }
            public int Offset { get; set; }
            public FieldType Type { get; set; }
            public string ValueStr { get; private set; } = "---";
            public string PrevStr { get; private set; } = "";
            public bool HasChanged => ValueStr != PrevStr;

            public WatchField(string name, int offset, FieldType type)
            { Name = name; Offset = offset; Type = type; }

            public void Update(byte[] buf)
            {
                PrevStr = ValueStr;
                if (Offset < 0 || Offset >= buf.Length) { ValueStr = "[OOB]"; return; }
                try
                {
                    ValueStr = Type switch
                    {
                        FieldType.Byte => $"{buf[Offset]}",
                        FieldType.Int16 => Offset + 2 <= buf.Length ? $"{BitConverter.ToInt16(buf, Offset)}" : "[OOB]",
                        FieldType.Int32 => Offset + 4 <= buf.Length ? $"{BitConverter.ToInt32(buf, Offset)}" : "[OOB]",
                        FieldType.Int64 => Offset + 8 <= buf.Length ? $"{BitConverter.ToInt64(buf, Offset)}" : "[OOB]",
                        FieldType.Float32 => Offset + 4 <= buf.Length ? $"{BitConverter.ToSingle(buf, Offset):G6}" : "[OOB]",
                        FieldType.Float64 => Offset + 8 <= buf.Length ? $"{BitConverter.ToDouble(buf, Offset):G10}" : "[OOB]",
                        _ => "?"
                    };
                }
                catch { ValueStr = "[ERR]"; }
            }
        }

        public class SavedScan
        {
            public ulong Address { get; set; }
            public string Name { get; set; } = "";
            public List<WatchField> Fields { get; set; } = new();
            public DateTime LastUpdate { get; set; } = DateTime.MinValue;
            public bool Stale { get; set; } = false;
        }
    }
}
