// Tabs/ItemFuzzerTab.cs  v17
// Registry-driven item spawner, fuzz runner, batch give, and export.

using HyForce.Core;
using HyForce.Networking;
using ImGuiNET;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text.Json;

namespace HyForce.Tabs;

public class ItemFuzzerTab : ITab
{
    public string Name => "Item Fuzzer";

    private readonly AppState          _state;
    private readonly PipeCaptureServer _pipe;
    private readonly ItemFuzzer        _fuzzer;
    private readonly InventoryTracker  _inventory;

    // Single give
    private string _giveIdHex    = "";
    private string _giveName     = "";
    private int    _giveSlot     = 0;
    private int    _giveCount    = 1;
    private bool   _useDrop      = false;
    private string _searchQuery  = "";

    // Fuzz
    private int    _fuzzModeIdx  = 0;
    private uint   _fuzzStart    = 1;
    private uint   _fuzzEnd      = 0x200;
    private int    _fuzzDelayMs  = 150;
    private bool   _fuzzScroll   = true;
    private static readonly string[] FuzzModeNames = { "Registry IDs", "Custom Range", "Full Range (1-0xFFFF)" };

    // Batch give — picked items
    private readonly List<(uint TypeId, string Name, int Count)> _batchList = new();
    private string _batchIdHex   = "";
    private int    _batchCount   = 1;

    // Log
    private readonly List<string> _log = new();
    private bool _logScroll = true;

    public ItemFuzzerTab(AppState state, PipeCaptureServer pipe)
    {
        _state     = state;
        _pipe      = pipe;
        _fuzzer    = state.ItemFuzzer;
        _inventory = state.InventoryTracker;
        _fuzzer.OnLog += line => { lock (_log) { _log.Add(line); if (_log.Count > 2000) _log.RemoveAt(0); } };
    }

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();

        // ── Status bar ───────────────────────────────────────────────────────
        ImGui.TextColored(new Vector4(1f, 0.85f, 0.3f, 1f),
            $"● Registry: {_inventory.RegistryEntries} defs   Inventory: {_inventory.Slots.Count} slots   Errors: {_inventory.ParseErrors}");
        if (_fuzzer.IsRunning)
        {
            ImGui.SameLine(0, 20);
            ImGui.TextColored(new Vector4(0.3f, 1f, 0.3f, 1f),
                $"FUZZING  {_fuzzer.Progress}/{_fuzzer.Total}  ({100f*_fuzzer.Progress/Math.Max(1,_fuzzer.Total):F0}%)");
        }
        ImGui.Separator();

        float leftW = 310f;

        // ── Left controls ────────────────────────────────────────────────────
        ImGui.BeginChild("fz_left", new Vector2(leftW, avail.Y - 4), ImGuiChildFlags.Borders);
        {
            if (ImGui.BeginTabBar("fz_left_tabs"))
            {
                if (ImGui.BeginTabItem("Give Item##gi"))     { RenderGivePanel();  ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Batch Give##bg"))    { RenderBatchPanel(); ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Fuzz##fuzz"))        { RenderFuzzPanel();  ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Export##fzexp"))     { RenderExportPanel();ImGui.EndTabItem(); }
                ImGui.EndTabBar();
            }
        }
        ImGui.EndChild();

        ImGui.SameLine();

        // ── Right: registry browser + fuzz results + log ─────────────────────
        float rightW = avail.X - leftW - 8;
        ImGui.BeginChild("fz_right", new Vector2(rightW, avail.Y - 4), ImGuiChildFlags.None);
        {
            if (ImGui.BeginTabBar("fz_right_tabs"))
            {
                if (ImGui.BeginTabItem("Registry##fzr")) { RenderRegistry(avail.Y - 50); ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Fuzz Results##fzres")) { RenderFuzzResults(avail.Y - 50); ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Log##fzlog"))    { RenderLog(avail.Y - 50); ImGui.EndTabItem(); }
                ImGui.EndTabBar();
            }
        }
        ImGui.EndChild();
    }

    private void RenderGivePanel()
    {
        ImGui.TextColored(new Vector4(1f, 0.85f, 0.3f, 1f), "GIVE ITEM");
        ImGui.TextDisabled("SetCreativeItem (0xAB) — places in slot.\nDropCreativeItem (0xAC) — drops at feet.");
        ImGui.Spacing();

        // Search registry
        ImGui.SetNextItemWidth(-1);
        if (ImGui.InputText("Search##gvsq", ref _searchQuery, 64))
        {
            var match = _inventory.Registry.Values
                .FirstOrDefault(d => d.Name.ToLower().Contains(_searchQuery.ToLower()));
            if (match != null) { _giveIdHex = match.TypeId.ToString("X"); _giveName = match.Name; }
        }
        if (!string.IsNullOrEmpty(_giveName)) ImGui.TextColored(new Vector4(0.5f,1f,0.5f,1f), $"  → {_giveName}");

        ImGui.SetNextItemWidth(-1); ImGui.InputText("Type ID (hex)##gvid", ref _giveIdHex, 16);
        ImGui.SetNextItemWidth(-1); ImGui.SliderInt("Slot##gvsl", ref _giveSlot, 0, 35);
        ImGui.SetNextItemWidth(-1); ImGui.InputInt("Count##gvcnt", ref _giveCount, 1);
        _giveCount = Math.Max(1, _giveCount);

        ImGui.Spacing();
        ImGui.Checkbox("Use DropCreativeItem (0xAC)##gvdrop", ref _useDrop);
        ImGui.Spacing();

        if (ImGui.Button("Give Item##gvbtn", new Vector2(-1, 32)))
        {
            if (uint.TryParse(_giveIdHex, System.Globalization.NumberStyles.HexNumber, null, out uint tid))
            {
                if (_useDrop) _fuzzer.DropItem(tid, _giveCount);
                else          _fuzzer.GiveItem(tid, _giveSlot, _giveCount);
            }
        }

        ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();

        // Quick-give named items from registry
        ImGui.TextDisabled("Quick-give from current inventory:");
        foreach (var slot in _inventory.Slots.Values.Where(s => !s.IsEmpty).Take(9))
        {
            if (ImGui.SmallButton($"[{slot.SlotIndex}] {slot.ItemName} x{slot.StackCount}##qg{slot.SlotIndex}"))
            {
                _fuzzer.GiveItem(slot.ItemTypeId, slot.SlotIndex, (int)slot.StackCount);
            }
        }
    }

    private void RenderBatchPanel()
    {
        ImGui.TextColored(new Vector4(0.5f, 0.85f, 1f, 1f), "BATCH GIVE");
        ImGui.TextDisabled("Build a list then give all at once.\nEach item goes into successive slots.");
        ImGui.Spacing();

        ImGui.SetNextItemWidth(120); ImGui.InputText("TypeID##bgtid", ref _batchIdHex, 12); ImGui.SameLine();
        ImGui.SetNextItemWidth(60);  ImGui.InputInt("x##bgcnt", ref _batchCount, 0); ImGui.SameLine();
        if (ImGui.SmallButton("Add##bgadd"))
        {
            if (uint.TryParse(_batchIdHex, System.Globalization.NumberStyles.HexNumber, null, out uint tid))
            {
                string name = _inventory.LookupName(tid);
                _batchList.Add((tid, name, _batchCount));
            }
        }
        ImGui.SameLine();
        if (ImGui.SmallButton("Clear##bgcl")) _batchList.Clear();

        ImGui.Separator();
        for (int i = 0; i < _batchList.Count; i++)
        {
            var (tid, name, cnt) = _batchList[i];
            ImGui.TextDisabled($"  [{i,2}] 0x{tid:X6}  {name}  x{cnt}");
            ImGui.SameLine();
            if (ImGui.SmallButton($"X##bgdel{i}")) { _batchList.RemoveAt(i); break; }
        }
        ImGui.Spacing();

        if (ImGui.Button("Give All##bgall", new Vector2(-1, 32)) && _batchList.Count > 0)
        {
            _fuzzer.GiveBatch(_batchList.Select(e => (e.TypeId, e.Count)));
        }

        // Add all registry items button
        ImGui.Spacing(); ImGui.Separator();
        ImGui.TextDisabled("Load entire registry into batch:");
        if (ImGui.Button("Load All Registry Items##bgall2", new Vector2(-1, 0)))
        {
            _batchList.Clear();
            foreach (var def in _inventory.Registry.Values.Take(36))
                _batchList.Add((def.TypeId, def.Name, 64));
        }
    }

    private void RenderFuzzPanel()
    {
        ImGui.TextColored(new Vector4(1f, 0.5f, 0.3f, 1f), "ITEM ID FUZZER");
        ImGui.TextDisabled("Iterates type IDs and sends SetCreativeItem.\nDiscovery: find hidden/unobtainable items.");
        ImGui.Spacing();

        ImGui.SetNextItemWidth(-1);
        ImGui.Combo("Mode##fzm", ref _fuzzModeIdx, FuzzModeNames, FuzzModeNames.Length);
        if (_fuzzModeIdx == 1)
        {
            int fs = (int)_fuzzStart, fe = (int)_fuzzEnd;
            ImGui.SetNextItemWidth(-1); if (ImGui.InputInt("Start##fzst", ref fs, 1)) _fuzzStart = (uint)Math.Max(1,fs);
            ImGui.SetNextItemWidth(-1); if (ImGui.InputInt("End##fzen",   ref fe, 1)) _fuzzEnd   = (uint)Math.Max((int)_fuzzStart+1, fe);
        }
        ImGui.SetNextItemWidth(-1);
        ImGui.SliderInt("Delay ms##fzdl", ref _fuzzDelayMs, 50, 2000);
        ImGui.TextDisabled($"  {(_fuzzModeIdx==0 ? _inventory.RegistryEntries : _fuzzModeIdx==1 ? (int)(_fuzzEnd-_fuzzStart+1) : 65535)} IDs to try");
        ImGui.Spacing();

        if (_fuzzer.IsRunning)
        {
            float pct = (float)_fuzzer.Progress / Math.Max(1, _fuzzer.Total);
            ImGui.ProgressBar(pct, new Vector2(-1, 0), $"{_fuzzer.Progress}/{_fuzzer.Total}");
            if (ImGui.Button("Stop Fuzz##fzstop", new Vector2(-1, 28))) _fuzzer.StopFuzz();
        }
        else
        {
            if (ImGui.Button("Start Fuzz##fzstart", new Vector2(-1, 32)))
            {
                FuzzMode mode = _fuzzModeIdx switch { 0 => FuzzMode.Registry, 2 => FuzzMode.RangeAll, _ => FuzzMode.RangeCustom };
                _fuzzer.StartFuzz(mode, _fuzzStart, _fuzzEnd, _fuzzDelayMs);
            }
        }
    }

    private void RenderExportPanel()
    {
        ImGui.TextColored(new Vector4(0.6f, 0.9f, 0.5f, 1f), "EXPORT");
        ImGui.TextDisabled("Export item registry or inventory snapshot to JSON.");
        ImGui.Spacing();

        if (ImGui.Button("Export Registry to JSON##expreg", new Vector2(-1, 0)))
        {
            try
            {
                var path = Path.Combine(_state.ExportDirectory, $"registry_{DateTime.Now:yyyyMMdd_HHmmss}.json");
                var data = _inventory.Registry.Values.OrderBy(d => d.TypeId)
                    .Select(d => new { typeId = d.TypeId, hex = $"0x{d.TypeId:X6}", name = d.Name })
                    .ToList();
                File.WriteAllText(path, JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true }));
                AddLog($"[EXPORT] Registry → {path}  ({data.Count} entries)");
            }
            catch (Exception ex) { AddLog($"[EXPORT-ERR] {ex.Message}"); }
        }

        ImGui.Spacing();
        if (ImGui.Button("Export Inventory to JSON##expinv", new Vector2(-1, 0)))
        {
            try
            {
                var path = Path.Combine(_state.ExportDirectory, $"inventory_{DateTime.Now:yyyyMMdd_HHmmss}.json");
                var data = _inventory.Slots.Values.Where(s => !s.IsEmpty).OrderBy(s => s.SlotIndex)
                    .Select(s => new { slot = s.SlotIndex, typeId = s.ItemTypeId, name = s.ItemName, count = s.StackCount, durability = s.Durability })
                    .ToList();
                File.WriteAllText(path, JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true }));
                AddLog($"[EXPORT] Inventory → {path}  ({data.Count} items)");
            }
            catch (Exception ex) { AddLog($"[EXPORT-ERR] {ex.Message}"); }
        }

        ImGui.Spacing();
        if (ImGui.Button("Export Fuzz Results to JSON##expfz", new Vector2(-1, 0)))
        {
            try
            {
                var path = Path.Combine(_state.ExportDirectory, $"fuzz_{DateTime.Now:yyyyMMdd_HHmmss}.json");
                var data = _fuzzer.Results.Select(r => new { typeId = r.TypeId, hex = $"0x{r.TypeId:X}", name = r.Name, accepted = r.Accepted })
                    .ToList();
                File.WriteAllText(path, JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true }));
                AddLog($"[EXPORT] Fuzz results → {path}  ({data.Count} entries)");
            }
            catch (Exception ex) { AddLog($"[EXPORT-ERR] {ex.Message}"); }
        }

        ImGui.Spacing();
        ImGui.TextDisabled($"Export dir: {_state.ExportDirectory}");
    }

    private void RenderRegistry(float h)
    {
        ImGui.SetNextItemWidth(-1); ImGui.InputText("Search##fzrsq", ref _searchQuery, 64);
        ImGui.Separator();
        var defs = _inventory.Registry.Values.OrderBy(d => d.TypeId).ToList();
        if (!string.IsNullOrEmpty(_searchQuery))
        {
            var f = _searchQuery.ToLower();
            defs = defs.Where(d => d.Name.ToLower().Contains(f) || d.TypeId.ToString("X").ToLower().Contains(f)).ToList();
        }
        ImGui.BeginChild("fz_reg", new Vector2(-1, h - 60), ImGuiChildFlags.None);
        if (ImGui.BeginTable("fzregtbl", 3, ImGuiTableFlags.Borders | ImGuiTableFlags.RowBg | ImGuiTableFlags.ScrollY))
        {
            ImGui.TableSetupColumn("Type ID", ImGuiTableColumnFlags.WidthFixed, 90);
            ImGui.TableSetupColumn("Name",    ImGuiTableColumnFlags.WidthStretch);
            ImGui.TableSetupColumn("Give",    ImGuiTableColumnFlags.WidthFixed, 50);
            ImGui.TableSetupScrollFreeze(0, 1);
            ImGui.TableHeadersRow();
            foreach (var d in defs.Take(3000))
            {
                ImGui.TableNextRow();
                ImGui.TableSetColumnIndex(0); ImGui.TextDisabled($"0x{d.TypeId:X6}");
                ImGui.TableSetColumnIndex(1); ImGui.TextUnformatted(d.Name);
                ImGui.TableSetColumnIndex(2);
                if (ImGui.SmallButton($"Give##rg{d.TypeId}"))
                    _fuzzer.GiveItem(d.TypeId, _giveSlot, _giveCount);
            }
            ImGui.EndTable();
        }
        ImGui.EndChild();
    }

    private void RenderFuzzResults(float h)
    {
        ImGui.TextDisabled($"{_fuzzer.Results.Count} results  ({_fuzzer.Results.Count(r => r.Accepted)} accepted)");
        ImGui.Separator();
        ImGui.BeginChild("fz_results", new Vector2(-1, h - 60), ImGuiChildFlags.None);
        if (ImGui.BeginTable("fzrestbl", 3, ImGuiTableFlags.Borders | ImGuiTableFlags.RowBg | ImGuiTableFlags.ScrollY))
        {
            ImGui.TableSetupColumn("TypeID",   ImGuiTableColumnFlags.WidthFixed, 80);
            ImGui.TableSetupColumn("Name",     ImGuiTableColumnFlags.WidthStretch);
            ImGui.TableSetupColumn("Status",   ImGuiTableColumnFlags.WidthFixed, 70);
            ImGui.TableSetupScrollFreeze(0, 1);
            ImGui.TableHeadersRow();
            var results = _fuzzer.Results.ToList();
            if (_fuzzScroll) results = results.TakeLast(500).ToList();
            foreach (var r in results)
            {
                ImGui.TableNextRow();
                ImGui.TableSetColumnIndex(0); ImGui.TextDisabled($"0x{r.TypeId:X4}");
                ImGui.TableSetColumnIndex(1); ImGui.TextUnformatted(r.Name);
                ImGui.TableSetColumnIndex(2);
                ImGui.TextColored(r.Accepted ? new Vector4(0.3f,0.9f,0.3f,1f) : new Vector4(0.9f,0.3f,0.3f,1f),
                    r.Accepted ? "Sent" : "Skip");
            }
            ImGui.EndTable();
        }
        ImGui.Checkbox("Show last 500 only##fzsc", ref _fuzzScroll);
        ImGui.EndChild();
    }

    private void RenderLog(float h)
    {
        ImGui.Checkbox("Auto-scroll##fzlsc", ref _logScroll);
        ImGui.SameLine(); if (ImGui.SmallButton("Clear##fzlcl")) lock (_log) _log.Clear();
        ImGui.Separator();
        ImGui.BeginChild("fz_log", new Vector2(-1, h - 60), ImGuiChildFlags.Borders);
        List<string> snap; lock (_log) snap = _log.ToList();
        foreach (var line in snap) ImGui.TextUnformatted(line);
        if (_logScroll && ImGui.GetScrollY() >= ImGui.GetScrollMaxY() - 5) ImGui.SetScrollHereY(1f);
        ImGui.EndChild();
    }

    private void AddLog(string msg)
    {
        var line = $"[{DateTime.Now:HH:mm:ss.fff}] {msg}";
        lock (_log) { _log.Add(line); if (_log.Count > 2000) _log.RemoveAt(0); }
    }
}
