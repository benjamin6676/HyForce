// Tabs/InventoryDumperTab.cs  v16
using HyForce.Core;
using HyForce.Networking;
using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;

namespace HyForce.Tabs;

public class InventoryDumperTab : ITab
{
    public string Name => "Inventory";

    private readonly InventoryTracker  _inv;
    private readonly PipeCaptureServer _pipe;

    private string _slotFilter  = "";
    private string _regFilter   = "";
    private bool   _showEmpty   = false;
    private bool   _showLog     = true;
    private bool   _logScroll   = true;
    private bool   _showRegistry = false;
    private int    _activeTab   = 0;

    private readonly List<string> _logDisplay = new();

    public InventoryDumperTab(InventoryTracker inv, PipeCaptureServer pipe)
    {
        _inv  = inv;
        _pipe = pipe;
        _inv.OnLog += line => {
            lock (_logDisplay) {
                _logDisplay.Add(line);
                if (_logDisplay.Count > 500) _logDisplay.RemoveAt(0);
            }
        };
    }

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();

        // ── Header ──────────────────────────────────────────────────────────
        ImGui.TextColored(new Vector4(1f, 0.85f, 0.3f, 1f),
            $"● Inventory: {_inv.Slots.Count} slots  |  Registry: {_inv.RegistryEntries} defs  |  Errors: {_inv.ParseErrors}");
        if (_inv.LastUpdate != DateTime.MinValue)
        {
            ImGui.SameLine(0, 20);
            ImGui.TextDisabled($"Last update: {(DateTime.UtcNow - _inv.LastUpdate).TotalSeconds:F1}s ago");
        }

        ImGui.SameLine();
        if (ImGui.Button("Clear Inventory")) _inv.Clear();
        ImGui.SameLine();
        if (ImGui.Button("Clear Registry")) _inv.ClearRegistry();
        ImGui.SameLine();
        if (ImGui.Button("Re-label Slots")) _inv.RelabelSlots();

        ImGui.Separator();

        // ── Tab switcher ─────────────────────────────────────────────────────
        if (ImGui.BeginTabBar("inv_tabs"))
        {
            if (ImGui.BeginTabItem("Inventory Slots##ivt"))
            {
                RenderSlots(avail);
                ImGui.EndTabItem();
            }
            if (ImGui.BeginTabItem("Item Registry##regt"))
            {
                RenderRegistry(avail);
                ImGui.EndTabItem();
            }
            if (ImGui.BeginTabItem("Parse Log##invlog"))
            {
                RenderLog(avail);
                ImGui.EndTabItem();
            }
            ImGui.EndTabBar();
        }
    }

    private void RenderSlots(System.Numerics.Vector2 avail)
    {
        ImGui.Checkbox("Show empty slots", ref _showEmpty); ImGui.SameLine();
        ImGui.SetNextItemWidth(200);
        ImGui.InputText("Filter##sf", ref _slotFilter, 128);
        ImGui.Separator();

        var slots = _inv.Slots.Values.OrderBy(s => s.SlotIndex).ToList();
        if (!_showEmpty)   slots = slots.Where(s => !s.IsEmpty).ToList();
        if (!string.IsNullOrEmpty(_slotFilter))
        {
            var f = _slotFilter.ToLower();
            slots = slots.Where(s =>
                s.ItemName.ToLower().Contains(f) ||
                s.SlotIndex.ToString().Contains(f) ||
                s.ItemTypeId.ToString("X").ToLower().Contains(f)).ToList();
        }

        ImGui.BeginChild("slot_table_wrap", new Vector2(-1, avail.Y - 80), ImGuiChildFlags.None);
        if (ImGui.BeginTable("slottable", 5,
            ImGuiTableFlags.Borders | ImGuiTableFlags.RowBg |
            ImGuiTableFlags.ScrollY | ImGuiTableFlags.Resizable))
        {
            ImGui.TableSetupColumn("Slot",      ImGuiTableColumnFlags.WidthFixed, 50);
            ImGui.TableSetupColumn("Item Name", ImGuiTableColumnFlags.WidthStretch);
            ImGui.TableSetupColumn("Type ID",   ImGuiTableColumnFlags.WidthFixed, 80);
            ImGui.TableSetupColumn("Stack",     ImGuiTableColumnFlags.WidthFixed, 55);
            ImGui.TableSetupColumn("Durability",ImGuiTableColumnFlags.WidthFixed, 80);
            ImGui.TableSetupScrollFreeze(0, 1);
            ImGui.TableHeadersRow();

            foreach (var s in slots)
            {
                ImGui.TableNextRow();
                Vector4 col = s.IsEmpty ? new Vector4(0.4f,0.4f,0.4f,1f) : new Vector4(0.9f,0.85f,0.5f,1f);

                ImGui.TableSetColumnIndex(0);
                ImGui.TextColored(new Vector4(0.6f, 0.6f, 0.6f, 1f), s.SlotIndex.ToString());

                ImGui.TableSetColumnIndex(1);
                ImGui.TextColored(col, s.IsEmpty ? "(empty)" : s.ItemName);

                ImGui.TableSetColumnIndex(2);
                ImGui.TextDisabled(s.IsEmpty ? "-" : $"0x{s.ItemTypeId:X}");

                ImGui.TableSetColumnIndex(3);
                ImGui.Text(s.IsEmpty ? "-" : s.StackCount.ToString());

                ImGui.TableSetColumnIndex(4);
                ImGui.TextDisabled(s.Durability == 0 ? "-" : s.Durability.ToString());
            }
            ImGui.EndTable();
        }
        ImGui.EndChild();
    }

    private void RenderRegistry(System.Numerics.Vector2 avail)
    {
        ImGui.SetNextItemWidth(200);
        ImGui.InputText("Filter##rrf", ref _regFilter, 128);
        ImGui.SameLine();
        ImGui.TextDisabled($"{_inv.RegistryEntries} total definitions");
        ImGui.Separator();

        var defs = _inv.Registry.Values.OrderBy(d => d.TypeId).ToList();
        if (!string.IsNullOrEmpty(_regFilter))
        {
            var f = _regFilter.ToLower();
            defs = defs.Where(d =>
                d.Name.ToLower().Contains(f) ||
                d.TypeId.ToString("X").ToLower().Contains(f)).ToList();
        }

        ImGui.BeginChild("reg_table_wrap", new Vector2(-1, avail.Y - 70), ImGuiChildFlags.None);
        if (ImGui.BeginTable("regtable", 2,
            ImGuiTableFlags.Borders | ImGuiTableFlags.RowBg | ImGuiTableFlags.ScrollY))
        {
            ImGui.TableSetupColumn("Type ID",  ImGuiTableColumnFlags.WidthFixed, 100);
            ImGui.TableSetupColumn("Name",     ImGuiTableColumnFlags.WidthStretch);
            ImGui.TableSetupScrollFreeze(0, 1);
            ImGui.TableHeadersRow();

            foreach (var d in defs.Take(2000)) // cap render at 2000 rows
            {
                ImGui.TableNextRow();
                ImGui.TableSetColumnIndex(0);
                ImGui.TextDisabled($"0x{d.TypeId:X6}");
                ImGui.TableSetColumnIndex(1);
                ImGui.TextUnformatted(d.Name);
            }
            ImGui.EndTable();
        }
        ImGui.EndChild();
    }

    private void RenderLog(System.Numerics.Vector2 avail)
    {
        ImGui.Checkbox("Auto-scroll##invlogsc", ref _logScroll);
        ImGui.Separator();
        ImGui.BeginChild("inv_log", new Vector2(-1, avail.Y - 60), ImGuiChildFlags.Borders);
        List<string> snap;
        lock (_logDisplay) snap = _logDisplay.ToList();
        foreach (var line in snap)
            ImGui.TextUnformatted(line);
        if (_logScroll && ImGui.GetScrollY() >= ImGui.GetScrollMaxY() - 5)
            ImGui.SetScrollHereY(1f);
        ImGui.EndChild();
    }
}
