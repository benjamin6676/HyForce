// FILE: Tabs/RegistryTab.cs
using HyForce.Core;
using HyForce.Protocol;
using ImGuiNET;
using System.Numerics;

namespace HyForce.Tabs;

public class RegistryTab : ITab
{
    private readonly AppState _state;
    private string _searchFilter = "";
    private int _selectedOpcode = -1;

    public string Name => "Registry";

    public RegistryTab(AppState state)
    {
        _state = state;
    }

    public void Render()
    {
        ImGui.BeginChild("Registry", new Vector2(0, 0), ImGuiChildFlags.None);

        ImGui.TextColored(new Vector4(0.4f, 0.8f, 1, 1), "Registry Sync Parser");
        ImGui.Separator();

        ImGui.Text($"RegistrySync Received: {(RegistrySyncParser.RegistrySyncReceived ? "YES" : "No")}");
        ImGui.Text($"Found at Opcode: 0x{RegistrySyncParser.FoundAtOpcode:X4}");
        ImGui.Text($"Items Parsed: {RegistrySyncParser.NumericIdToName.Count}");
        ImGui.Text($"String IDs: {RegistrySyncParser.StringIdToName.Count}");
        ImGui.Text($"Player Names: {RegistrySyncParser.PlayerNamesSeen.Count}");

        ImGui.Separator();

        ImGui.InputText("Search", ref _searchFilter, 100);

        if (RegistrySyncParser.OpcodeSeen.Count > 0)
        {
            ImGui.TextColored(new Vector4(1, 0.8f, 0.2f, 1), "Opcodes Seen:");

            foreach (var opcode in RegistrySyncParser.OpcodeSeen)
            {
                string label = $"0x{opcode:X4}";

                if (ImGui.Selectable(label, _selectedOpcode == opcode))
                {
                    _selectedOpcode = opcode;
                }
            }
        }

        if (RegistrySyncParser.NumericIdToName.Count > 0)
        {
            ImGui.Separator();
            ImGui.TextColored(new Vector4(0.2f, 1, 0.4f, 1), $"Items ({RegistrySyncParser.NumericIdToName.Count}):");

            var items = RegistrySyncParser.NumericIdToName;
            if (!string.IsNullOrEmpty(_searchFilter))
            {
                items = items.Where(i => i.Value.Contains(_searchFilter, StringComparison.OrdinalIgnoreCase))
                            .ToDictionary(i => i.Key, i => i.Value);
            }

            ImGui.BeginChild("ItemList", new Vector2(0, 200), ImGuiChildFlags.None);

            foreach (var item in items.Take(100))
            {
                ImGui.Text($"[{item.Key:X8}] {item.Value}");
            }

            ImGui.EndChild();
        }

        if (RegistrySyncParser.PlayerNamesSeen.Count > 0)
        {
            ImGui.Separator();
            ImGui.TextColored(new Vector4(0.2f, 1, 0.4f, 1), $"Players ({RegistrySyncParser.PlayerNamesSeen.Count}):");

            ImGui.BeginChild("PlayerList", new Vector2(0, 150), ImGuiChildFlags.None);

            foreach (var player in RegistrySyncParser.PlayerNamesSeen.Take(50))
            {
                ImGui.Text($"- {player}");
            }

            ImGui.EndChild();
        }

        ImGui.EndChild();
    }
}