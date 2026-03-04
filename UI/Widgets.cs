using ImGuiNET;
using System.Numerics;

namespace HyForce.UI;

public static class Widgets
{
    public static void SectionBox(string title, float width, float height, Action content)
    {
        ImGui.BeginGroup();
        ImGui.Text(title);
        ImGui.Separator();
        content();
        ImGui.EndGroup();
    }

    public static void StatusRow(string label, string value, bool ok)
    {
        ImGui.Text(label + ":");
        ImGui.SameLine(120);
        if (ok)
            ImGui.TextColored(Theme.ColSuccess, value);
        else
            ImGui.TextColored(Theme.ColTextMuted, value);
    }

    public static void MutedLabel(string text)
    {
        ImGui.PushStyleColor(ImGuiCol.Text, Theme.ColTextMuted);
        ImGui.Text(text);
        ImGui.PopStyleColor();
    }

    public static void BlueButton(string label, Action onClick)
    {
        ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.2f, 0.4f, 0.8f, 1f));
        if (ImGui.Button(label))
            onClick();
        ImGui.PopStyleColor();
    }

    public static void Pill(string text, Vector4 color)
    {
        ImGui.PushStyleColor(ImGuiCol.Button, color);
        ImGui.PushStyleColor(ImGuiCol.ButtonHovered, color);
        ImGui.PushStyleColor(ImGuiCol.ButtonActive, color);
        ImGui.Button(text);
        ImGui.PopStyleColor(3);
    }

    public static void PrimaryButton(string label, float width, float height, Action onClick)
    {
        ImGui.PushStyleColor(ImGuiCol.Button, Theme.ColAccent);
        if (ImGui.Button(label, new Vector2(width, height)))
            onClick();
        ImGui.PopStyleColor();
    }

    public static void DangerButton(string label, float width, float height, Action onClick)
    {
        ImGui.PushStyleColor(ImGuiCol.Button, Theme.ColDanger);
        if (ImGui.Button(label, new Vector2(width, height)))
            onClick();
        ImGui.PopStyleColor();
    }

    public static void SecondaryButton(string label, float width, float height, Action onClick)
    {
        ImGui.PushStyleColor(ImGuiCol.Button, Theme.ColBg3);
        if (ImGui.Button(label, new Vector2(width, height)))
            onClick();
        ImGui.PopStyleColor();
    }

    public static bool ToggleButton(string label, bool active, Vector2 size)
    {
        if (active)
            ImGui.PushStyleColor(ImGuiCol.Button, Theme.ColAccent);
        else
            ImGui.PushStyleColor(ImGuiCol.Button, Theme.ColBg3);

        bool clicked = ImGui.Button(label, size);
        ImGui.PopStyleColor();

        return clicked ? !active : active;
    }

    public static void Badge(string text, Vector4 color)
    {
        var padding = ImGui.GetStyle().FramePadding;
        var size = ImGui.CalcTextSize(text) + padding * 2;

        var drawList = ImGui.GetWindowDrawList();
        var pos = ImGui.GetCursorScreenPos();

        drawList.AddRectFilled(pos, pos + size, ImGui.ColorConvertFloat4ToU32(color), 3f);
        drawList.AddText(pos + padding, ImGui.ColorConvertFloat4ToU32(Vector4.One), text);

        ImGui.Dummy(size);
    }
}