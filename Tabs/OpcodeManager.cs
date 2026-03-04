// FILE: Tabs/OpcodeManager.cs - NEW: Centralized opcode filtering and management
using HyForce.Core;
using HyForce.Data;
using HyForce.Networking;
using HyForce.Protocol;
using HyForce.UI;
using ImGuiNET;
using System.Numerics;

namespace HyForce.Tabs;

public class OpcodeManager : ITab
{
    public string Name => "Opcodes";

    private readonly AppState _state;
    private string _searchFilter = "";
    private ushort? _selectedOpcode = null;
    private bool _showOnlyHidden = false;
    private bool _showOnlyFavorites = false;
    private HashSet<ushort> _hiddenOpcodes = new();
    private HashSet<ushort> _favoriteOpcodes = new();
    private Dictionary<ushort, string> _customNames = new();

    // Category filters
    private bool[] _categoryFilters = new bool[20];
    private string[] _categories = Enum.GetNames(typeof(PacketCategory));

    public OpcodeManager(AppState state)
    {
        _state = state;
        LoadSettings();
    }

    private void LoadSettings()
    {
        // Could load from config file
        _hiddenOpcodes.Add(0x0000); // Default hide QUIC noise
    }

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();

        ImGui.Spacing();
        ImGui.Text("  OPCODE MANAGER  -  Filter, Rename, and Organize");
        ImGui.Separator();
        ImGui.Spacing();

        // Toolbar
        RenderToolbar();

        ImGui.Spacing();

        // Two panel layout
        float leftWidth = avail.X * 0.4f - 8;
        float rightWidth = avail.X * 0.6f - 8;

        ImGui.BeginChild("##opcode_list", new Vector2(leftWidth, avail.Y - 80), ImGuiChildFlags.Borders);
        RenderOpcodeList(leftWidth);
        ImGui.EndChild();

        ImGui.SameLine();

        ImGui.BeginChild("##opcode_details", new Vector2(rightWidth, avail.Y - 80), ImGuiChildFlags.Borders);
        RenderOpcodeDetails(rightWidth);
        ImGui.EndChild();
    }

    private void RenderToolbar()
    {
        // Search
        ImGui.SetNextItemWidth(200);
        ImGui.InputText("? Search", ref _searchFilter, 256);

        ImGui.SameLine();
        ImGui.Checkbox("Hidden Only", ref _showOnlyHidden);
        ImGui.SameLine();
        ImGui.Checkbox("Favorites", ref _showOnlyFavorites);
        ImGui.SameLine();

        if (ImGui.Button("Export Filter List", new Vector2(120, 28)))
        {
            ExportFilterList();
        }

        ImGui.SameLine();
        if (ImGui.Button("Import", new Vector2(60, 28)))
        {
            ImportFilterList();
        }

        // Category filters
        ImGui.NewLine();
        ImGui.Text("Categories:");
        for (int i = 0; i < _categories.Length && i < 10; i++)
        {
            ImGui.SameLine();
            ImGui.Checkbox(_categories[i], ref _categoryFilters[i]);
        }
    }

    private void RenderOpcodeList(float width)
    {
        ImGui.TextColored(Theme.ColAccent, "All Opcodes");
        ImGui.Separator();

        // Get all seen opcodes from packet log
        var allOpcodes = _state.PacketLog.GetOpcodeCounts()
            .Select(kv => new { Opcode = kv.Key, Count = kv.Value })
            .ToList();

        // Add known opcodes that haven't been seen
        var knownOpcodes = OpcodeRegistry.C2S_Opcodes.Keys
            .Concat(OpcodeRegistry.S2C_Opcodes.Keys)
            .Distinct()
            .Where(o => !allOpcodes.Any(a => a.Opcode == o))
            .Select(o => new { Opcode = o, Count = 0 });

        allOpcodes = allOpcodes.Concat(knownOpcodes).OrderBy(x => x.Opcode).ToList();

        // Apply filters
        var filtered = allOpcodes.Where(o =>
        {
            if (_showOnlyHidden && !_hiddenOpcodes.Contains(o.Opcode))
                return false;
            if (_showOnlyFavorites && !_favoriteOpcodes.Contains(o.Opcode))
                return false;
            if (!string.IsNullOrEmpty(_searchFilter) &&
                !o.Opcode.ToString("X4").Contains(_searchFilter, StringComparison.OrdinalIgnoreCase))
                return false;
            return true;
        });

        if (ImGui.BeginTable("##opcodes", 4, ImGuiTableFlags.RowBg | ImGuiTableFlags.Borders | ImGuiTableFlags.ScrollY))
        {
            ImGui.TableSetupColumn("*", ImGuiTableColumnFlags.WidthFixed, 25);
            ImGui.TableSetupColumn("?", ImGuiTableColumnFlags.WidthFixed, 25);
            ImGui.TableSetupColumn("Opcode", ImGuiTableColumnFlags.WidthFixed, 60);
            ImGui.TableSetupColumn("Name", ImGuiTableColumnFlags.WidthStretch);
            ImGui.TableHeadersRow();

            foreach (var op in filtered)
            {
                ImGui.TableNextRow();
                bool isSelected = _selectedOpcode == op.Opcode;

                // Favorite star
                ImGui.TableSetColumnIndex(0);
                bool isFav = _favoriteOpcodes.Contains(op.Opcode);
                if (ImGui.Button(isFav ? "*" : "o"))
                {
                    if (isFav) _favoriteOpcodes.Remove(op.Opcode);
                    else _favoriteOpcodes.Add(op.Opcode);
                }

                // Visibility toggle
                ImGui.TableSetColumnIndex(1);
                bool isHidden = _hiddenOpcodes.Contains(op.Opcode);
                if (ImGui.Button(isHidden ? "?" : "?"))
                {
                    if (isHidden) _hiddenOpcodes.Remove(op.Opcode);
                    else _hiddenOpcodes.Add(op.Opcode);
                }

                // Opcode
                ImGui.TableSetColumnIndex(2);
                var color = isHidden ? Theme.ColTextMuted :
                           isSelected ? Theme.ColAccent :
                           new Vector4(1, 1, 1, 1);
                ImGui.TextColored(color, $"0x{op.Opcode:X4}");

                // Name
                ImGui.TableSetColumnIndex(3);
                var c2sInfo = OpcodeRegistry.GetInfo(op.Opcode, PacketDirection.ClientToServer);
                var s2cInfo = OpcodeRegistry.GetInfo(op.Opcode, PacketDirection.ServerToClient);
                var name = c2sInfo?.Name ?? s2cInfo?.Name ?? "Unknown";

                if (_customNames.TryGetValue(op.Opcode, out var customName))
                    name = customName;

                if (ImGui.Selectable($"{name} ({op.Count})", isSelected, ImGuiSelectableFlags.SpanAllColumns))
                {
                    _selectedOpcode = op.Opcode;
                }
            }

            ImGui.EndTable();
        }
    }

    private void RenderOpcodeDetails(float width)
    {
        if (_selectedOpcode == null)
        {
            ImGui.TextColored(Theme.ColTextMuted, "Select an opcode to view details");
            return;
        }

        var opcode = _selectedOpcode.Value;
        var c2sInfo = OpcodeRegistry.GetInfo(opcode, PacketDirection.ClientToServer);
        var s2cInfo = OpcodeRegistry.GetInfo(opcode, PacketDirection.ServerToClient);

        ImGui.TextColored(Theme.ColAccent, $"Opcode: 0x{opcode:X4}");
        ImGui.Separator();

        // Custom name
        string customName = _customNames.GetValueOrDefault(opcode, "");
        ImGui.InputText("Custom Name", ref customName, 64);
        if (!string.IsNullOrEmpty(customName))
            _customNames[opcode] = customName;
        else if (_customNames.ContainsKey(opcode))
            _customNames.Remove(opcode);

        // C2S Info
        if (c2sInfo != null)
        {
            ImGui.Spacing();
            ImGui.TextColored(new Vector4(0.3f, 0.8f, 0.3f, 1), "Client -> Server");
            ImGui.Text($"Name: {c2sInfo.Name}");
            ImGui.Text($"Category: {c2sInfo.Category}");
            ImGui.TextWrapped($"Description: {c2sInfo.Description}");
        }

        // S2C Info
        if (s2cInfo != null)
        {
            ImGui.Spacing();
            ImGui.TextColored(new Vector4(0.8f, 0.5f, 0.2f, 1), "Server -> Client");
            ImGui.Text($"Name: {s2cInfo.Name}");
            ImGui.Text($"Category: {s2cInfo.Category}");
            ImGui.TextWrapped($"Description: {s2cInfo.Description}");
        }

        // Stats
        var count = _state.PacketLog.CountForOpcode(opcode);
        ImGui.Spacing();
        ImGui.TextColored(Theme.ColAccent, $"Statistics");
        ImGui.Text($"Packets captured: {count}");

        // Actions
        ImGui.Spacing();
        ImGui.Separator();
        if (ImGui.Button("Hide This Opcode", new Vector2(120, 28)))
        {
            _hiddenOpcodes.Add(opcode);
        }
        ImGui.SameLine();
        if (ImGui.Button("Add to Favorites", new Vector2(120, 28)))
        {
            _favoriteOpcodes.Add(opcode);
        }
        ImGui.SameLine();
        if (ImGui.Button("Copy C# Const", new Vector2(120, 28)))
        {
            var name = c2sInfo?.Name ?? s2cInfo?.Name ?? $"Opcode_{opcode:X4}";
            CopyToClipboard($"public const ushort {name} = 0x{opcode:X4};");
        }
    }

    private void ExportFilterList()
    {
        try
        {
            var sb = new System.Text.StringBuilder();
            sb.AppendLine("=== HYFORCE OPCODE FILTERS ===");
            sb.AppendLine($"Export Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine();

            sb.AppendLine("[Hidden Opcodes]");
            foreach (var op in _hiddenOpcodes.OrderBy(x => x))
            {
                sb.AppendLine($"0x{op:X4}");
            }

            sb.AppendLine();
            sb.AppendLine("[Favorites]");
            foreach (var op in _favoriteOpcodes.OrderBy(x => x))
            {
                sb.AppendLine($"0x{op:X4}");
            }

            sb.AppendLine();
            sb.AppendLine("[Custom Names]");
            foreach (var kv in _customNames.OrderBy(x => x.Key))
            {
                sb.AppendLine($"0x{kv.Key:X4}={kv.Value}");
            }

            string filename = Path.Combine(_state.ExportDirectory,
                $"opcode_filters_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
            File.WriteAllText(filename, sb.ToString());

            _state.AddInGameLog($"[OPCODES] Filter list exported");
        }
        catch (Exception ex)
        {
            _state.AddInGameLog($"[ERROR] Export failed: {ex.Message}");
        }
    }

    private void ImportFilterList()
    {
        // Implementation for importing
        _state.AddInGameLog("[OPCODES] Import not yet implemented");
    }

    private void CopyToClipboard(string text)
    {
        try { TextCopy.ClipboardService.SetText(text); } catch { }
    }

    // Public API for other tabs to check if opcode is hidden
    public bool IsOpcodeHidden(ushort opcode) => _hiddenOpcodes.Contains(opcode);
    public IReadOnlySet<ushort> GetHiddenOpcodes() => _hiddenOpcodes;
}