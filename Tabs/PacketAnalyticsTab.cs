// FILE: Tabs/PacketAnalyticsTab.cs
using HyForce.Core;
using HyForce.Data;
using HyForce.Networking;
using HyForce.Protocol;
using ImGuiNET;
using System.Numerics;

namespace HyForce.Tabs;

public class PacketAnalyticsTab : ITab
{
    private readonly AppState _state;
    private List<PacketPattern> _patterns = new();
    private Dictionary<string, int> _patternMatches = new();

    public string Name => "Analytics";

    public PacketAnalyticsTab(AppState state)
    {
        _state = state;
        InitializePatterns();
    }

    private void InitializePatterns()
    {
        _patterns = new List<PacketPattern>
        {
            new PacketPattern
            {
                Name = "Registry Sync",
                Description = "Registry synchronization packets",
                Opcode = 0x0018,
                IsTcp = true,
                Direction = PacketDirection.ServerToClient
            },
            new PacketPattern
            {
                Name = "Player Movement",
                Description = "Player position updates",
                Opcode = 0x60B4,
                IsTcp = false,
                Direction = PacketDirection.ClientToServer
            },
            new PacketPattern
            {
                Name = "Large Packet",
                Description = "Packets larger than 1KB",
                MinSize = 1024,
                IsTcp = false
            }
        };
    }

    public void Render()
    {
        ImGui.BeginChild("Analytics", new Vector2(0, 0), ImGuiChildFlags.None);

        ImGui.TextColored(new Vector4(0.2f, 0.8f, 0.4f, 1), "Packet Analytics");
        ImGui.Separator();

        var packets = _state.PacketLog.GetAll();

        ImGui.Text($"Total Packets Analyzed: {packets.Count}");
        ImGui.Text($"Unique Opcodes: {_state.PacketLog.UniqueOpcodes}");
        ImGui.Text($"TCP Packets: {packets.Count(p => p.IsTcp)}");
        ImGui.Text($"UDP Packets: {packets.Count(p => !p.IsTcp)}");

        ImGui.Separator();

        if (ImGui.Button("Detect Patterns"))
        {
            DetectPatterns(packets);
        }

        ImGui.SameLine();
        if (ImGui.Button("Clear Results"))
        {
            _patternMatches.Clear();
        }

        if (_patternMatches.Count > 0)
        {
            ImGui.TextColored(new Vector4(0.4f, 0.8f, 1, 1), "Pattern Matches:");

            if (ImGui.BeginTable("PatternMatches", 2, ImGuiTableFlags.Borders | ImGuiTableFlags.RowBg))
            {
                ImGui.TableSetupColumn("Pattern", ImGuiTableColumnFlags.WidthStretch);
                ImGui.TableSetupColumn("Count", ImGuiTableColumnFlags.WidthFixed, 100);
                ImGui.TableHeadersRow();

                foreach (var match in _patternMatches.OrderByDescending(m => m.Value))
                {
                    ImGui.TableNextRow();
                    ImGui.TableNextColumn();
                    ImGui.Text(match.Key);
                    ImGui.TableNextColumn();
                    ImGui.Text(match.Value.ToString());
                }

                ImGui.EndTable();
            }
        }

        ImGui.Separator();
        ImGui.TextColored(new Vector4(1, 0.8f, 0.4f, 1), "Top Opcodes:");

        var topOpcodes = _state.PacketLog.GetOpcodeCounts().OrderByDescending(x => x.Value).Take(10);

        if (ImGui.BeginTable("TopOpcodes", 3, ImGuiTableFlags.Borders | ImGuiTableFlags.RowBg))
        {
            ImGui.TableSetupColumn("Opcode", ImGuiTableColumnFlags.WidthFixed, 80);
            ImGui.TableSetupColumn("Name", ImGuiTableColumnFlags.WidthStretch);
            ImGui.TableSetupColumn("Count", ImGuiTableColumnFlags.WidthFixed, 80);
            ImGui.TableHeadersRow();

            foreach (var kv in topOpcodes)
            {
                ImGui.TableNextRow();
                ImGui.TableNextColumn();
                ImGui.Text($"0x{kv.Key:X4}");
                ImGui.TableNextColumn();
                var name = OpcodeRegistry.Label(kv.Key, PacketDirection.ServerToClient);
                ImGui.Text(name);
                ImGui.TableNextColumn();
                ImGui.Text(kv.Value.ToString());
            }

            ImGui.EndTable();
        }

        ImGui.EndChild();
    }

    private void DetectPatterns(List<PacketLogEntry> packets)
    {
        _patternMatches.Clear();

        foreach (var pattern in _patterns)
        {
            int count = 0;
            foreach (var packet in packets)
            {
                byte[] rawData = new byte[0];

                if (pattern.Matches(packet, rawData))
                {
                    count++;
                }
            }

            if (count > 0)
            {
                _patternMatches[pattern.Name] = count;
            }
        }
    }
}