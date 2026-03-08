// Tabs/ItemManagerTab.cs  v20
// One-stop shop for all item operations:
//   Give / take / swap individual slots
//   Fill hotbar / fill all from registry search
//   Loadout save / load (JSON preset of slots)
//   Drop all / clear inventory
//   Sort by name / typeId

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

public class ItemManagerTab : ITab
{
    public string Name => "Item Manager";

    private readonly AppState          _state;
    private readonly PipeCaptureServer _pipe;

    // Give
    private string _giveTypeHex = "00000001";
    private string _giveName    = "";
    private int    _giveSlot    = 0;
    private int    _giveCount   = 64;
    private string _regSearch   = "";

    // Take
    private int    _takeSlot = 0, _takeCount = 1;

    // Move
    private int    _moveSrc = 0, _moveDst = 1, _moveCount = 64;

    // Loadout
    private string _loadoutName = "Loadout 1";
    private string _loadoutPath = "";
    private int _selLoadout = -1;
    private int _selectedLoadout = -1;
    private readonly List<(string Name, List<(int Slot, uint TypeId, int Count)> Slots)> _loadouts = new();
    

    private bool _logScroll = true;
    private readonly List<string> _log = new();

    public ItemManagerTab(AppState state, PipeCaptureServer pipe)
    {
        _state = state; _pipe = pipe;
    }

   

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();
        float leftW = 330f;

        ImGui.TextDisabled($"Slots: {_state.InventoryTracker.Slots.Count}   Registry: {_state.InventoryTracker.Registry.Count} types");
        ImGui.Separator();

        ImGui.BeginChild("im_left", new Vector2(leftW, avail.Y-4), ImGuiChildFlags.Borders);
        {
            if (ImGui.BeginTabBar("im_left_tabs"))
            {
                if (ImGui.BeginTabItem("Give##img"))     { RenderGive();    ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Move/Take##imm")){ RenderMove();    ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Bulk##imb"))     { RenderBulk();    ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Loadouts##iml")) { RenderLoadouts();ImGui.EndTabItem(); }
                ImGui.EndTabBar();
            }
        }
        ImGui.EndChild();

        ImGui.SameLine();

        float rightW = avail.X - leftW - 8;
        ImGui.BeginChild("im_right", new Vector2(rightW, avail.Y-4), ImGuiChildFlags.None);
        {
            if (ImGui.BeginTabBar("im_right_tabs"))
            {
                if (ImGui.BeginTabItem("Inventory##imir")) { RenderInventory(avail.Y-50); ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Registry##imreg")) { RenderRegistry(avail.Y-50);  ImGui.EndTabItem(); }
                if (ImGui.BeginTabItem("Log##iml2"))       { RenderLog(avail.Y-50);        ImGui.EndTabItem(); }
                ImGui.EndTabBar();
            }
        }
        ImGui.EndChild();
    }

    private void RenderGive()
    {
        ImGui.TextColored(new Vector4(0.3f,1f,0.5f,1f), "GIVE ITEM");
        ImGui.SetNextItemWidth(-1); ImGui.InputText("TypeID (hex)##imgtid", ref _giveTypeHex, 16);
        if (!string.IsNullOrEmpty(_giveName)) ImGui.TextColored(new Vector4(0.5f,1f,0.5f,1f), $"  {_giveName}");
        ImGui.SetNextItemWidth(80); ImGui.InputInt("Slot##imgs", ref _giveSlot, 1); ImGui.SameLine();
        ImGui.SetNextItemWidth(80); ImGui.InputInt("Count##imgc", ref _giveCount, 1);
        _giveSlot = Math.Max(0,_giveSlot); _giveCount = Math.Max(1,_giveCount);

        if (ImGui.Button("Give Item##imgg", new Vector2(-1,28)))
        {
            if (uint.TryParse(_giveTypeHex, System.Globalization.NumberStyles.HexNumber, null, out uint tid))
            {
                _pipe.ForgeStream(ItemDuplicator.BuildSetCreativeItem((uint)_giveSlot, tid, (uint)_giveCount));
                AddLog($"[GIVE] 0x{tid:X} ×{_giveCount} → slot {_giveSlot}");
            }
        }

        ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();
        ImGui.TextColored(new Vector4(0.4f,0.85f,1f,1f), "QUICK FILL HOTBAR");
        ImGui.TextDisabled("Fills slots 0..8 with the selected item type.");
        if (ImGui.Button("Fill Hotbar##imgh", new Vector2(-1,0)))
        {
            if (uint.TryParse(_giveTypeHex, System.Globalization.NumberStyles.HexNumber, null, out uint tid2))
                for (int s = 0; s < 9; s++)
                    _pipe.ForgeStream(ItemDuplicator.BuildSetCreativeItem((uint)s, tid2, (uint)_giveCount));
        }
    }

    private void RenderMove()
    {
        ImGui.TextColored(new Vector4(1f,0.75f,0.3f,1f), "MOVE ITEM STACK");
        ImGui.TextDisabled("0xAF MoveItemStack — server validates normally.");
        ImGui.SetNextItemWidth(80); ImGui.InputInt("From##immsrc",ref _moveSrc,1); ImGui.SameLine();
        ImGui.SetNextItemWidth(80); ImGui.InputInt("To##immdst",ref _moveDst,1); ImGui.SameLine();
        ImGui.SetNextItemWidth(80); ImGui.InputInt("Count##immc",ref _moveCount,1);
        _moveSrc=Math.Max(0,_moveSrc); _moveDst=Math.Max(0,_moveDst); _moveCount=Math.Max(1,_moveCount);
        if (ImGui.Button("Move##immmv", new Vector2(-1,0)))
        {
            _pipe.ForgeStream(ItemDuplicator.BuildMoveItemStack((uint)_moveSrc,(uint)_moveDst,(uint)_moveCount));
            AddLog($"[MOVE] {_moveSrc}→{_moveDst} ×{_moveCount}");
        }

        ImGui.Spacing(); ImGui.Separator(); ImGui.Spacing();
        ImGui.TextColored(new Vector4(1f,0.4f,0.4f,1f), "DROP / CLEAR SLOT");
        ImGui.SetNextItemWidth(80); ImGui.InputInt("Slot##imts",ref _takeSlot,1); ImGui.SameLine();
        ImGui.SetNextItemWidth(80); ImGui.InputInt("Count##imtc",ref _takeCount,1);
        _takeSlot=Math.Max(0,_takeSlot); _takeCount=Math.Max(1,_takeCount);
        if (ImGui.Button("Drop Stack##imtdrop", new Vector2(-1,0)))
        {
            _pipe.ForgeStream(ItemDuplicator.BuildDropItemStack((uint)_takeSlot,(uint)_takeCount));
            AddLog($"[DROP] slot {_takeSlot} ×{_takeCount}");
        }
    }

    private void RenderBulk()
    {
        ImGui.TextColored(new Vector4(0.7f,0.4f,1f,1f), "BULK OPERATIONS");
        ImGui.Spacing();

        if (ImGui.Button("Drop All Items (slots 0-35)##imball", new Vector2(-1,28)))
        {
            for (int s = 0; s < 36; s++)
                _pipe.ForgeStream(ItemDuplicator.BuildDropItemStack((uint)s, 64));
            AddLog("[BULK] Dropped all 36 slots");
        }

        ImGui.Spacing();
        if (ImGui.Button("Fill Inventory with Debug Item##imbfill", new Vector2(-1,0)))
        {
            if (uint.TryParse(_giveTypeHex, System.Globalization.NumberStyles.HexNumber, null, out uint tid))
                for (int s = 0; s < 36; s++)
                    _pipe.ForgeStream(ItemDuplicator.BuildSetCreativeItem((uint)s, tid, 64));
        }

        ImGui.Spacing();
        if (ImGui.Button("Sort by TypeID (re-give ordered)##imbsort", new Vector2(-1,0)))
        {
            var sorted = _state.InventoryTracker.Slots.Values
                .OrderBy(s => s.ItemTypeId)
                .Select((s, i) => (slot: i, s.ItemTypeId, (uint)s.StackCount))
                .ToList();
            foreach (var (sl, tid2, cnt) in sorted)
                _pipe.ForgeStream(ItemDuplicator.BuildSetCreativeItem((uint)sl, tid2, cnt));
            AddLog($"[SORT] Re-gave {sorted.Count} slots sorted by TypeID");
        }
    }

    private void RenderLoadouts()
    {
        ImGui.TextColored(new Vector4(0.4f, 0.85f, 1f, 1f), "LOADOUT PRESETS");
        ImGui.TextDisabled("Save current inventory as a named preset to restore later.");

        ImGui.SetNextItemWidth(-1);
        ImGui.InputText("Name##imln", ref _loadoutName, 64);

        if (ImGui.Button("Save Current as Loadout##imlsv", new Vector2(-1, 0)))
        {
            // FIX: Use anonymous type with matching property names, or proper tuple
            var slots = _state.InventoryTracker.Slots.Values
                .Select(s => new { Slot = s.SlotIndex, TypeId = s.ItemTypeId, Count = (int)s.StackCount })
                .ToList();

            _loadouts.RemoveAll(l => l.Name == _loadoutName);

            // FIX: Create Loadout object properly instead of tuple
            var loadout = new InventoryLoadout
            {
                Name = _loadoutName,
                Slots = slots.Select(s => (s.Slot, s.TypeId, s.Count)).ToList()
            };

            _loadouts.Add((loadout.Name, loadout.Slots));
            AddLog($"[LOADOUT] Saved '{_loadoutName}' ({slots.Count} slots)");
        }

        ImGui.Spacing();
        ImGui.Separator();

        // FIX: Use ImGuiChildFlags.Border (not Borders)
        ImGui.BeginChild("im_lollist", new Vector2(-1, 128), ImGuiChildFlags.Borders);

        for (int i = 0; i < _loadouts.Count; i++)
        {
            // FIX: Rename 'sel' to 'isSelected' to avoid conflicts
            bool isSelected = _selectedLoadout == i;

            if (ImGui.Selectable($"{_loadouts[i].Name}  [{_loadouts[i].Slots.Count}]##imlo{i}", isSelected))
            {
                _selectedLoadout = isSelected ? -1 : i;
            }
        }

        ImGui.EndChild();
    }

    private void RenderInventory(float h)
    {
        ImGui.TextDisabled($"{_state.InventoryTracker.Slots.Count} slots");
        ImGui.Separator();
        ImGui.BeginChild("im_inv", new Vector2(-1, h-60),ImGuiChildFlags.Borders);
        if (ImGui.BeginTable("iminvtbl", 5, ImGuiTableFlags.Borders|ImGuiTableFlags.RowBg|ImGuiTableFlags.ScrollY))
        {
            ImGui.TableSetupColumn("Slot",  ImGuiTableColumnFlags.WidthFixed, 45);
            ImGui.TableSetupColumn("TypeID",ImGuiTableColumnFlags.WidthFixed, 80);
            ImGui.TableSetupColumn("Name",  ImGuiTableColumnFlags.WidthStretch);
            ImGui.TableSetupColumn("×",     ImGuiTableColumnFlags.WidthFixed, 50);
            ImGui.TableSetupColumn("Act",   ImGuiTableColumnFlags.WidthFixed, 70);
            ImGui.TableSetupScrollFreeze(0,1); ImGui.TableHeadersRow();

            foreach (var s in _state.InventoryTracker.Slots.Values.OrderBy(x=>x.SlotIndex))
            {
                ImGui.TableNextRow();
                ImGui.TableSetColumnIndex(0); ImGui.TextDisabled($"[{s.SlotIndex}]");
                ImGui.TableSetColumnIndex(1); ImGui.TextDisabled($"0x{s.ItemTypeId:X6}");
                ImGui.TableSetColumnIndex(2); ImGui.TextUnformatted(s.ItemName);
                ImGui.TableSetColumnIndex(3); ImGui.TextDisabled($"×{s.StackCount}");
                ImGui.TableSetColumnIndex(4);
                if (ImGui.SmallButton($"Give64##imig{s.SlotIndex}"))
                    _pipe.ForgeStream(ItemDuplicator.BuildSetCreativeItem((uint)s.SlotIndex, s.ItemTypeId, 64));
                ImGui.SameLine();
                if (ImGui.SmallButton($"Drop##imid{s.SlotIndex}"))
                    _pipe.ForgeStream(ItemDuplicator.BuildDropItemStack((uint)s.SlotIndex, (uint)s.StackCount));
            }
            ImGui.EndTable();
        }
        ImGui.EndChild();
    }

    private void RenderRegistry(float h)
    {
        ImGui.SetNextItemWidth(-1); ImGui.InputText("Search##imregsq",ref _regSearch,64);
        ImGui.Separator();
        var defs = _state.InventoryTracker.Registry.Values
            .Where(d => string.IsNullOrEmpty(_regSearch)
                || d.Name.ToLower().Contains(_regSearch.ToLower())
                || d.TypeId.ToString("X").ToLower().Contains(_regSearch.ToLower()))
            .OrderBy(d=>d.TypeId).ToList();
        ImGui.TextDisabled($"{defs.Count} items");
        ImGui.BeginChild("im_reg", new Vector2(-1, h-70), ImGuiChildFlags.None);
        if (ImGui.BeginTable("imregtbl", 3, ImGuiTableFlags.Borders|ImGuiTableFlags.RowBg|ImGuiTableFlags.ScrollY))
        {
            ImGui.TableSetupColumn("TypeID", ImGuiTableColumnFlags.WidthFixed, 80);
            ImGui.TableSetupColumn("Name",   ImGuiTableColumnFlags.WidthStretch);
            ImGui.TableSetupColumn("Action", ImGuiTableColumnFlags.WidthFixed, 90);
            ImGui.TableSetupScrollFreeze(0,1); ImGui.TableHeadersRow();
            foreach (var d in defs.Take(2000))
            {
                ImGui.TableNextRow();
                ImGui.TableSetColumnIndex(0); ImGui.TextDisabled($"0x{d.TypeId:X6}");
                ImGui.TableSetColumnIndex(1); ImGui.TextUnformatted(d.Name);
                ImGui.TableSetColumnIndex(2);
                if (ImGui.SmallButton($"Give##imrg{d.TypeId}"))
                {
                    _giveTypeHex = d.TypeId.ToString("X"); _giveName = d.Name;
                    _pipe.ForgeStream(ItemDuplicator.BuildSetCreativeItem((uint)_giveSlot, d.TypeId, (uint)_giveCount));
                    AddLog($"[GIVE] 0x{d.TypeId:X} {d.Name} → slot {_giveSlot}");
                }
                ImGui.SameLine();
                if (ImGui.SmallButton($"Sel##imrs{d.TypeId}"))
                { _giveTypeHex = d.TypeId.ToString("X"); _giveName = d.Name; }
            }
            ImGui.EndTable();
        }
        ImGui.EndChild();
    }

    private void RenderLog(float h)
    {
        ImGui.Checkbox("Auto-scroll##imlsc", ref _logScroll);
        ImGui.SameLine(); if (ImGui.SmallButton("Clear##imlcl")) lock(_log) _log.Clear();
        ImGui.Separator();
        ImGui.BeginChild("im_log_ch", new Vector2(-1, h-60), ImGuiChildFlags.Borders);
        List<string> snap; lock(_log) snap=_log.ToList();
        foreach(var line in snap) ImGui.TextUnformatted(line);
        if(_logScroll && ImGui.GetScrollY()>=ImGui.GetScrollMaxY()-5) ImGui.SetScrollHereY(1f);
        ImGui.EndChild();
    }

    private void AddLog(string msg)
    {
        var line = $"[{DateTime.Now:HH:mm:ss.fff}] {msg}";
        lock(_log) { _log.Add(line); if(_log.Count>500) _log.RemoveAt(0); }
    }
}
