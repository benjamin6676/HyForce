using ImGuiNET;
using System.Numerics;

namespace HyForce.UI;

public class Theme
{
    public static Vector4 ColAccent = new(0.2f, 0.6f, 1.0f, 1f);
    public static Vector4 ColAccentDim = new(0.1f, 0.3f, 0.5f, 1f);
    public static Vector4 ColAccentMid = new(0.15f, 0.45f, 0.75f, 1f);
    public static Vector4 ColWarn = new(0.9f, 0.7f, 0.2f, 1f);
    public static Vector4 ColDanger = new(0.9f, 0.3f, 0.2f, 1f);
    public static Vector4 ColSuccess = new(0.2f, 0.8f, 0.3f, 1f);
    public static Vector4 ColTextMuted = new(0.6f, 0.6f, 0.6f, 1f);
    public static Vector4 ColBg3 = new(0.15f, 0.15f, 0.15f, 1f);
    public static Vector4 ColBlue = new(0.3f, 0.5f, 0.9f, 1f);
    public static Vector4 ColBlueDim = new(0.15f, 0.25f, 0.45f, 1f);

    public void Apply()
    {
        var style = ImGui.GetStyle();
        var colors = style.Colors;

        // Dark theme base
        colors[(int)ImGuiCol.WindowBg] = new Vector4(0.1f, 0.1f, 0.12f, 1f);
        colors[(int)ImGuiCol.ChildBg] = new Vector4(0.08f, 0.08f, 0.1f, 1f);
        colors[(int)ImGuiCol.PopupBg] = new Vector4(0.12f, 0.12f, 0.14f, 1f);

        // Accent colors
        colors[(int)ImGuiCol.Header] = ColAccentDim;
        colors[(int)ImGuiCol.HeaderHovered] = ColAccentMid;
        colors[(int)ImGuiCol.HeaderActive] = ColAccent;

        colors[(int)ImGuiCol.Button] = ColAccentDim;
        colors[(int)ImGuiCol.ButtonHovered] = ColAccentMid;
        colors[(int)ImGuiCol.ButtonActive] = ColAccent;

        // Borders
        colors[(int)ImGuiCol.Border] = new Vector4(0.2f, 0.2f, 0.25f, 1f);
        colors[(int)ImGuiCol.BorderShadow] = new Vector4(0f, 0f, 0f, 0f);

        // Text
        colors[(int)ImGuiCol.Text] = new Vector4(0.9f, 0.9f, 0.9f, 1f);
        colors[(int)ImGuiCol.TextDisabled] = ColTextMuted;

        // Frame backgrounds
        colors[(int)ImGuiCol.FrameBg] = new Vector4(0.15f, 0.15f, 0.18f, 1f);
        colors[(int)ImGuiCol.FrameBgHovered] = new Vector4(0.2f, 0.2f, 0.25f, 1f);
        colors[(int)ImGuiCol.FrameBgActive] = new Vector4(0.25f, 0.25f, 0.3f, 1f);

        // Title bar
        colors[(int)ImGuiCol.TitleBg] = new Vector4(0.08f, 0.08f, 0.1f, 1f);
        colors[(int)ImGuiCol.TitleBgActive] = ColAccentDim;
        colors[(int)ImGuiCol.TitleBgCollapsed] = new Vector4(0.08f, 0.08f, 0.1f, 1f);

        // Tab - using only valid enum values for 1.91.6.1
        colors[(int)ImGuiCol.Tab] = new Vector4(0.12f, 0.12f, 0.15f, 1f);
        colors[(int)ImGuiCol.TabHovered] = ColAccentMid;
        colors[(int)ImGuiCol.TabSelected] = ColAccent;  // Changed from TabActive
        colors[(int)ImGuiCol.TabDimmed] = new Vector4(0.1f, 0.1f, 0.12f, 1f);  // Changed from TabUnfocused
        colors[(int)ImGuiCol.TabDimmedSelected] = ColAccentDim;  // Changed from TabUnfocusedActive

        // Scrollbar
        colors[(int)ImGuiCol.ScrollbarBg] = new Vector4(0.05f, 0.05f, 0.07f, 1f);
        colors[(int)ImGuiCol.ScrollbarGrab] = new Vector4(0.3f, 0.3f, 0.35f, 1f);
        colors[(int)ImGuiCol.ScrollbarGrabHovered] = new Vector4(0.4f, 0.4f, 0.45f, 1f);
        colors[(int)ImGuiCol.ScrollbarGrabActive] = ColAccent;

        // Menu bar
        colors[(int)ImGuiCol.MenuBarBg] = new Vector4(0.12f, 0.12f, 0.15f, 1f);

        // Separator
        colors[(int)ImGuiCol.Separator] = new Vector4(0.2f, 0.2f, 0.25f, 1f);
        colors[(int)ImGuiCol.SeparatorHovered] = ColAccentMid;
        colors[(int)ImGuiCol.SeparatorActive] = ColAccent;

        // Resize grip
        colors[(int)ImGuiCol.ResizeGrip] = ColAccentDim;
        colors[(int)ImGuiCol.ResizeGripHovered] = ColAccentMid;
        colors[(int)ImGuiCol.ResizeGripActive] = ColAccent;

        // Plot lines
        colors[(int)ImGuiCol.PlotLines] = ColAccent;
        colors[(int)ImGuiCol.PlotLinesHovered] = ColWarn;
        colors[(int)ImGuiCol.PlotHistogram] = ColAccent;
        colors[(int)ImGuiCol.PlotHistogramHovered] = ColWarn;

        // Style settings
        style.WindowRounding = 4f;
        style.ChildRounding = 4f;
        style.FrameRounding = 3f;
        style.PopupRounding = 4f;
        style.ScrollbarRounding = 6f;
        style.GrabRounding = 3f;
        style.TabRounding = 4f;

        style.WindowPadding = new Vector2(8, 8);
        style.FramePadding = new Vector2(6, 4);
        style.ItemSpacing = new Vector2(8, 4);
        style.ItemInnerSpacing = new Vector2(4, 4);

        style.ScrollbarSize = 14f;
        style.GrabMinSize = 10f;

        style.WindowBorderSize = 1f;
        style.ChildBorderSize = 1f;
        style.PopupBorderSize = 1f;
        style.FrameBorderSize = 0f;
        style.TabBorderSize = 0f;
    }
}