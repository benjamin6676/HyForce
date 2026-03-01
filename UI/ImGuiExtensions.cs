using ImGuiNET;
using System.Numerics;

namespace HyForce.UI;

public static class ImGuiExtensions
{
    public static void TextCentered(string text)
    {
        var windowWidth = ImGui.GetWindowSize().X;
        var textWidth = ImGui.CalcTextSize(text).X;
        ImGui.SetCursorPosX((windowWidth - textWidth) * 0.5f);
        ImGui.Text(text);
    }

    public static void TextRight(string text, float? offset = null)
    {
        var windowWidth = ImGui.GetWindowSize().X;
        var textWidth = ImGui.CalcTextSize(text).X;
        var posX = offset ?? (windowWidth - textWidth - ImGui.GetStyle().ItemSpacing.X);
        ImGui.SetCursorPosX(posX);
        ImGui.Text(text);
    }

    // FIXED: Return value pattern instead of ref
    public static bool CheckboxWithLabel(string label, bool value, float labelWidth = 120)
    {
        ImGui.Text(label);
        ImGui.SameLine(labelWidth);
        bool newValue = value;
        ImGui.Checkbox($"##{label}", ref newValue);
        return newValue;
    }

    public static string InputTextWithLabel(string label, string value, uint maxLength, float labelWidth = 120)
    {
        ImGui.Text(label);
        ImGui.SameLine(labelWidth);
        string newValue = value;
        ImGui.InputText($"##{label}", ref newValue, maxLength);
        return newValue;
    }

    public static int InputIntWithLabel(string label, int value, float labelWidth = 120)
    {
        ImGui.Text(label);
        ImGui.SameLine(labelWidth);
        int newValue = value;
        ImGui.InputInt($"##{label}", ref newValue);
        return newValue;
    }

    public static void SpacedSeparator()
    {
        ImGui.Spacing();
        ImGui.Separator();
        ImGui.Spacing();
    }

    public static bool BeginChildPadded(string id, Vector2 size, ImGuiChildFlags flags = ImGuiChildFlags.None)
    {
        ImGui.PushStyleVar(ImGuiStyleVar.WindowPadding, new Vector2(12, 12));
        bool result = ImGui.BeginChild(id, size, flags);
        ImGui.PopStyleVar();
        return result;
    }

    public static void SetupTable(string id, string[] columns, ImGuiTableFlags flags = ImGuiTableFlags.None)
    {
        if (ImGui.BeginTable(id, columns.Length, flags | ImGuiTableFlags.Borders | ImGuiTableFlags.RowBg))
        {
            foreach (var col in columns)
            {
                ImGui.TableSetupColumn(col);
            }
            ImGui.TableHeadersRow();
        }
    }

    public static void DrawLine(Vector4 color, float thickness = 1.0f)
    {
        var drawList = ImGui.GetWindowDrawList();
        var start = ImGui.GetCursorScreenPos();
        var end = start + new Vector2(ImGui.GetContentRegionAvail().X, 0);
        drawList.AddLine(start, end, ImGui.ColorConvertFloat4ToU32(color), thickness);
        ImGui.Dummy(new Vector2(0, thickness));
    }

    public static void HoverTooltip(string text)
    {
        if (ImGui.IsItemHovered())
        {
            ImGui.SetTooltip(text);
        }
    }

    // FIXED: No ImGuiItemFlags.Disabled
    public static void ButtonDisabled(string label, Vector2 size, string reason)
    {
        ImGui.PushStyleVar(ImGuiStyleVar.Alpha, 0.5f);
        ImGui.Button(label, size);
        ImGui.PopStyleVar();

        if (ImGui.IsItemHovered() && !string.IsNullOrEmpty(reason))
        {
            ImGui.SetTooltip(reason);
        }
    }
}