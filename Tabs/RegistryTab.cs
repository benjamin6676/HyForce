using HyForce.Core;
using HyForce.Data;
using HyForce.Networking;
using HyForce.Protocol;
using HyForce.UI;
using ImGuiNET;
using System.Numerics;

namespace HyForce.Tabs;

public class RegistryTab : ITab
{
    public string Name => "Registry";

    private readonly AppState _state;
    private string _searchFilter = "";
    private int _selectedOpcode = -1;

    public RegistryTab(AppState state)
    {
        _state = state;
    }

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();

        ImGui.Spacing();
        ImGui.Text("  REGISTRY ANALYSIS  �  Item IDs & Player Names");
        ImGui.Separator();
        ImGui.Spacing();

        // Summary stats
        RenderSummary(avail.X);
        ImGui.Spacing();

        // Search
        ImGui.SetNextItemWidth(avail.X - 32);
        ImGui.InputText("Search", ref _searchFilter, 256);
        ImGui.Spacing();

        // Two columns
        float leftW = avail.X * 0.4f - 8;
        float rightW = avail.X * 0.6f - 8;

        ImGui.BeginChild("##reg_left", new Vector2(leftW, avail.Y - 200), ImGuiChildFlags.Borders);
        RenderOpcodeList(leftW);
        ImGui.EndChild();

        ImGui.SameLine(0, 8);

        ImGui.BeginChild("##reg_right", new Vector2(rightW, avail.Y - 200), ImGuiChildFlags.Borders);
        RenderDetails(rightW);
        ImGui.EndChild();
    }

    private void RenderSummary(float w)
    {
        bool regRx = RegistrySyncParser.RegistrySyncReceived;

        ImGui.Columns(4, "##reg_summary", false);

        ImGui.Text("RegistrySync:");
        ImGui.NextColumn();
        ImGui.Text(regRx ? "? RECEIVED" : "? NOT YET");
        ImGui.NextColumn();

        ImGui.Text("Items Found:");
        ImGui.NextColumn();
        ImGui.Text(RegistrySyncParser.NumericIdToName.Count.ToString());
        ImGui.NextColumn();

        ImGui.Columns(1);
    }

    private void RenderOpcodeList(float width)
    {
        ImGui.Text("Opcodes Seen (0x00-0x3F)");
        ImGui.Separator();

        foreach (var kv in RegistrySyncParser.OpcodeSeen.OrderBy(x => x.Key))
        {
            ushort opcode = kv.Key;
            int count = kv.Value;
            bool hasEntries = RegistrySyncParser.OpcodeEntryCount.TryGetValue(opcode, out int entries);

            bool selected = _selectedOpcode == opcode;

            string label = $"0x{opcode:X2}  �{count}";
            if (hasEntries && entries > 0)
                label += $"  [{entries} items]";

            if (ImGui.Selectable(label, selected))
                _selectedOpcode = opcode;
        }
    }

    private void RenderDetails(float width)
    {
        if (_selectedOpcode < 0)
        {
            ImGui.Text("Select an opcode to view details");
            return;
        }

        ushort opcode = (ushort)_selectedOpcode;

        ImGui.Text($"Opcode: 0x{opcode:X2}");
        ImGui.Text($"Name: {OpcodeRegistry.Label(opcode, Networking.PacketDirection.ServerToClient)}");
        ImGui.Text($"Protocol: TCP");  // Registry sync is always TCP
        ImGui.Separator();

        if (RegistrySyncParser.ParseLog.TryGetValue(opcode, out var log))
        {
            ImGui.Text($"Parse Result: {log}");
        }

        if (RegistrySyncParser.OpcodeEntryCount.TryGetValue(opcode, out int entries) && entries > 0)
        {
            ImGui.Spacing();
            ImGui.Text($"Entries: {entries}");

            var items = RegistrySyncParser.NumericIdToName
                .Where(x => x.Value.StartsWith(GetPrefixForOpcode(opcode)))
                .Take(50);

            ImGui.BeginChild("##items", new Vector2(width - 16, 200));
            foreach (var item in items)
            {
                ImGui.Text($"[{item.Key}] {item.Value}");
            }
            ImGui.EndChild();
        }
    }

    private string GetPrefixForOpcode(ushort opcode)
    {
        return opcode switch
        {
            0x10 => "Block_",
            0x11 => "Item_",
            0x12 => "Armor_",
            0x13 => "Weapon_",
            0x14 => "Tool_",
            0x15 => "Ingredient_",
            0x16 => "Ore_",
            0x17 => "Wood_",
            0x18 => "",
            _ => ""
        };
    }
}