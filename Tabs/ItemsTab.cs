// FILE: Tabs/ItemsTab.cs
using HyForce.Core;
using HyForce.Protocol;
using HyForce.UI;
using ImGuiNET;
using System.Numerics;

namespace HyForce.Tabs;

public class ItemsTab : ITab
{
    public string Name => "Items";

    private readonly AppState _state;
    private string _searchFilter = "";
    private uint? _selectedItemId = null;
    private int _selectedOpcode = -1;

    public ItemsTab(AppState state)
    {
        _state = state;
    }

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();

        ImGui.Spacing();
        ImGui.Text("  ITEM DATABASE  --  Discovered Items & Registry");
        ImGui.Separator();
        ImGui.Spacing();

        // Search bar
        ImGui.SetNextItemWidth(300);
        ImGui.InputText("? Search Items", ref _searchFilter, 256);

        ImGui.SameLine();
        if (ImGui.Button("Export Items", new Vector2(120, 0)))
        {
            ExportItems();
        }

        ImGui.SameLine();
        ImGui.Text($"Total: {RegistrySyncParser.NumericIdToName.Count} items");

        ImGui.Spacing();
        ImGui.Separator();

        // Two column layout
        float leftWidth = avail.X * 0.4f - 8;
        float rightWidth = avail.X * 0.6f - 8;

        ImGui.BeginChild("##item_list", new Vector2(leftWidth, avail.Y - 100), ImGuiChildFlags.Borders);
        RenderItemList(leftWidth);
        ImGui.EndChild();

        ImGui.SameLine(0, 8);

        ImGui.BeginChild("##item_details", new Vector2(rightWidth, avail.Y - 100), ImGuiChildFlags.Borders);
        RenderItemDetails(rightWidth);
        ImGui.EndChild();
    }

    private void RenderItemList(float width)
    {
        var items = RegistrySyncParser.NumericIdToName
            .Where(x => string.IsNullOrEmpty(_searchFilter) ||
                       x.Value.Contains(_searchFilter, StringComparison.OrdinalIgnoreCase) ||
                       x.Key.ToString("X8").Contains(_searchFilter, StringComparison.OrdinalIgnoreCase))
            .OrderBy(x => x.Value)
            .ToList();

        ImGui.TextColored(Theme.ColAccent, "Discovered Items");
        ImGui.Separator();

        if (ImGui.BeginTable("##items_table", 2, ImGuiTableFlags.RowBg | ImGuiTableFlags.ScrollY | ImGuiTableFlags.BordersInnerH))
        {
            ImGui.TableSetupColumn("ID", ImGuiTableColumnFlags.WidthFixed, 80);
            ImGui.TableSetupColumn("Name", ImGuiTableColumnFlags.WidthStretch);
            ImGui.TableHeadersRow();

            foreach (var item in items)
            {
                ImGui.TableNextRow();

                bool isSelected = _selectedItemId == item.Key;
                if (isSelected)
                {
                    ImGui.TableSetBgColor(ImGuiTableBgTarget.RowBg0,
                        ImGui.ColorConvertFloat4ToU32(new Vector4(0.2f, 0.5f, 0.8f, 0.3f)));
                }

                ImGui.TableSetColumnIndex(0);
                ImGui.Text($"0x{item.Key:X8}");

                ImGui.TableSetColumnIndex(1);
                if (ImGui.Selectable(item.Value, isSelected, ImGuiSelectableFlags.SpanAllColumns))
                {
                    _selectedItemId = item.Key;
                }

                // Hover tooltip
                if (ImGui.IsItemHovered())
                {
                    ImGui.SetTooltip($"Click to view details\nNumeric ID: {item.Key}\nHex: 0x{item.Key:X8}");
                }
            }

            ImGui.EndTable();
        }
    }

    private void RenderItemDetails(float width)
    {
        if (_selectedItemId == null)
        {
            ImGui.TextColored(Theme.ColTextMuted, "Select an item to view details");
            return;
        }

        var itemId = _selectedItemId.Value;
        var itemName = RegistrySyncParser.NumericIdToName.TryGetValue(itemId, out var name) ? name : "Unknown";
        var stringId = RegistrySyncParser.StringIdToName.FirstOrDefault(x => x.Value == itemName).Key ?? "N/A";

        // Header
        ImGui.PushStyleColor(ImGuiCol.Text, Theme.ColAccent);
        ImGui.SetWindowFontScale(1.3f);
        ImGui.Text(itemName);
        ImGui.SetWindowFontScale(1.0f);
        ImGui.PopStyleColor();

        ImGui.TextColored(Theme.ColTextMuted, $"String ID: {stringId}");
        ImGui.Separator();

        // Info grid
        ImGui.Columns(2, "##item_info", false);

        ImGui.TextColored(Theme.ColTextMuted, "Numeric ID");
        ImGui.Text($"{itemId}");
        ImGui.NextColumn();

        ImGui.TextColored(Theme.ColTextMuted, "Hex ID");
        ImGui.Text($"0x{itemId:X8}");
        ImGui.NextColumn();

        ImGui.TextColored(Theme.ColTextMuted, "Category");
        ImGui.Text(GetItemCategory(itemName));
        ImGui.NextColumn();

        ImGui.TextColored(Theme.ColTextMuted, "First Seen");
        // Would need to track this
        ImGui.Text("Unknown");
        ImGui.NextColumn();

        ImGui.Columns(1);
        ImGui.Separator();

        // Actions
        ImGui.TextColored(Theme.ColAccent, "Actions");

        if (ImGui.Button("Copy Name", new Vector2(120, 28)))
        {
            CopyToClipboard(itemName);
        }
        ImGui.SameLine();

        if (ImGui.Button("Copy ID", new Vector2(120, 28)))
        {
            CopyToClipboard($"0x{itemId:X8}");
        }
        ImGui.SameLine();

        if (ImGui.Button("Copy C# Code", new Vector2(120, 28)))
        {
            CopyToClipboard($"public const uint {SanitizeName(itemName)} = 0x{itemId:X8};");
        }

        // Related packets
        ImGui.Spacing();
        ImGui.Separator();
        ImGui.TextColored(Theme.ColAccent, "Related Packets");

        var relatedPackets = FindPacketsWithItem(itemId);
        if (relatedPackets.Any())
        {
            ImGui.Text($"Found in {relatedPackets.Count} packets:");
            foreach (var pkt in relatedPackets.Take(10))
            {
                ImGui.Text($"  [{pkt.Timestamp:HH:mm:ss}] {pkt.OpcodeName} ({pkt.ByteLength} bytes)");
            }
        }
        else
        {
            ImGui.TextColored(Theme.ColTextMuted, "No packets found containing this item");
        }

        // Usage statistics
        ImGui.Spacing();
        ImGui.Separator();
        ImGui.TextColored(Theme.ColAccent, "Statistics");
        ImGui.Text("Times seen: N/A (tracking not implemented)");
        ImGui.Text("Last seen: N/A");
    }

    private string GetItemCategory(string itemName)
    {
        if (itemName.StartsWith("Armor_", StringComparison.OrdinalIgnoreCase)) return "Armor";
        if (itemName.StartsWith("Weapon_", StringComparison.OrdinalIgnoreCase)) return "Weapon";
        if (itemName.StartsWith("Tool_", StringComparison.OrdinalIgnoreCase)) return "Tool";
        if (itemName.StartsWith("Block_", StringComparison.OrdinalIgnoreCase)) return "Block";
        if (itemName.StartsWith("Ore_", StringComparison.OrdinalIgnoreCase)) return "Ore";
        if (itemName.StartsWith("Ingredient_", StringComparison.OrdinalIgnoreCase)) return "Ingredient";
        if (itemName.StartsWith("Plant_", StringComparison.OrdinalIgnoreCase)) return "Plant";
        if (itemName.StartsWith("Wood_", StringComparison.OrdinalIgnoreCase)) return "Wood";
        return "Other";
    }

    private string SanitizeName(string name)
    {
        return name.Replace(" ", "_").Replace("-", "_").Replace(".", "_");
    }

    private List<Data.PacketLogEntry> FindPacketsWithItem(uint itemId)
    {
        // Search packet log for packets containing this item ID
        var bytes = BitConverter.GetBytes(itemId);
        var hexPattern = BitConverter.ToString(bytes).Replace("-", "-");

        return _state.PacketLog.GetAll()
            .Where(p => p.RawHexPreview.Contains(hexPattern, StringComparison.OrdinalIgnoreCase))
            .ToList();
    }

    private void ExportItems()
    {
        try
        {
            Directory.CreateDirectory(_state.ExportDirectory);
            string filename = Path.Combine(_state.ExportDirectory,
                $"items_export_{DateTime.Now:yyyyMMdd_HHmmss}.txt");

            var sb = new System.Text.StringBuilder();
            sb.AppendLine("=== HYFORCE ITEM EXPORT ===");
            sb.AppendLine($"Export Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"Total Items: {RegistrySyncParser.NumericIdToName.Count}");
            sb.AppendLine();

            foreach (var item in RegistrySyncParser.NumericIdToName.OrderBy(x => x.Value))
            {
                sb.AppendLine($"0x{item.Key:X8} = {item.Value}");
            }

            File.WriteAllText(filename, sb.ToString());
            _state.AddInGameLog($"[SUCCESS] Items exported to {filename}");
        }
        catch (Exception ex)
        {
            _state.AddInGameLog($"[ERROR] Export failed: {ex.Message}");
        }
    }

    private void CopyToClipboard(string text)
    {
        try { TextCopy.ClipboardService.SetText(text); } catch { }
    }
}