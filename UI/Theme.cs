using ImGuiNET;
using System.Numerics;
using System.Collections.Generic;

namespace HyForce.UI;

// -- Per-theme colour/style bundle ---------------------------------------------
public class ThemeDefinition
{
    public string Name  { get; init; } = "";
    public string Group { get; init; } = "Dark";

    public Vector4 WindowBg   { get; init; }
    public Vector4 ChildBg    { get; init; }
    public Vector4 PopupBg    { get; init; }
    public Vector4 TableBg    { get; init; }
    public Vector4 TableRowBg { get; init; }
    public Vector4 TableAltBg { get; init; }
    public Vector4 TabBg      { get; init; }
    public Vector4 InputBg    { get; init; }

    public Vector4 Accent    { get; init; }
    public Vector4 AccentDim { get; init; }
    public Vector4 AccentMid { get; init; }

    public Vector4 Success { get; init; }
    public Vector4 Warn    { get; init; }
    public Vector4 Danger  { get; init; }
    public Vector4 Info    { get; init; }

    public Vector4 Text      { get; init; }
    public Vector4 TextMuted { get; init; }
    public Vector4 TextDim   { get; init; }

    public Vector4 Border    { get; init; }
    public Vector4 Scrollbar { get; init; }
    public float   Rounding  { get; init; } = 2f;

    // Packet-category tint colours
    public Vector4 CatRegistry  { get; init; }
    public Vector4 CatMovement  { get; init; }
    public Vector4 CatCombat    { get; init; }
    public Vector4 CatEntity    { get; init; }
    public Vector4 CatInventory { get; init; }
    public Vector4 CatChat      { get; init; }
    public Vector4 CatHandshake { get; init; }
    public Vector4 CatUnknown   { get; init; }
}

// -- Central theme registry + static colour accessors ------------------------
public class Theme
{
    // Backward-compat statics (all tabs use these)
    public static Vector4 ColAccent      { get; private set; }
    public static Vector4 ColAccentDim   { get; private set; }
    public static Vector4 ColAccentMid   { get; private set; }
    public static Vector4 ColWarn        { get; private set; }
    public static Vector4 ColDanger      { get; private set; }
    public static Vector4 ColSuccess     { get; private set; }
    public static Vector4 ColInfo        { get; private set; }
    public static Vector4 ColTextMuted   { get; private set; }
    public static Vector4 ColBg3         { get; private set; }
    public static Vector4 ColBorder      { get; private set; }
    public static Vector4 ColBlue        => ColInfo;
    public static Vector4 ColBlueDim     { get; private set; }

    // Category colour statics
    public static Vector4 ColCatRegistry  { get; private set; }
    public static Vector4 ColCatMovement  { get; private set; }
    public static Vector4 ColCatCombat    { get; private set; }
    public static Vector4 ColCatEntity    { get; private set; }
    public static Vector4 ColCatInventory { get; private set; }
    public static Vector4 ColCatChat      { get; private set; }
    public static Vector4 ColCatHandshake { get; private set; }
    public static Vector4 ColCatUnknown   { get; private set; }

    public static string          CurrentThemeName { get; private set; } = "Carbon Red";
    public static ThemeDefinition Current          { get; private set; } = null!;

    // -- 8 built-in themes ----------------------------------------------------
    public static readonly Dictionary<string, ThemeDefinition> AllThemes = new()
    {
        ["Carbon Red"] = new() {
            Name="Carbon Red", Group="Dark",
            WindowBg=V(.067f,.063f,.063f), ChildBg=V(.078f,.074f,.071f), PopupBg=V(.100f,.094f,.090f),
            TableBg=V(.059f,.055f,.051f), TableRowBg=V(.082f,.078f,.074f), TableAltBg=V(.071f,.067f,.063f),
            TabBg=V(.086f,.082f,.078f), InputBg=V(.094f,.090f,.086f),
            Accent=V(1f,.267f,.200f), AccentDim=V(.302f,.082f,.063f), AccentMid=V(.416f,.102f,.078f),
            Success=V(.400f,.800f,.267f), Warn=V(1f,.667f,.133f), Danger=V(1f,.133f,0f), Info=V(.267f,.600f,1f),
            Text=V(.941f,.878f,.847f), TextMuted=V(.478f,.435f,.416f), TextDim=V(.310f,.282f,.267f),
            Border=V(.180f,.165f,.157f), Scrollbar=V(.239f,.165f,.157f), Rounding=2f,
            CatRegistry=V(1f,.533f,.400f), CatMovement=V(.267f,.600f,1f), CatCombat=V(1f,.267f,.200f),
            CatEntity=V(.267f,.800f,.533f), CatInventory=V(1f,.867f,.200f), CatChat=V(.533f,1f,.800f),
            CatHandshake=V(.533f,.400f,1f), CatUnknown=V(.353f,.290f,.267f) },

        ["Obsidian Ops"] = new() {
            Name="Obsidian Ops", Group="Dark",
            WindowBg=V(.039f,.039f,.047f), ChildBg=V(.051f,.051f,.063f), PopupBg=V(.067f,.067f,.082f),
            TableBg=V(.031f,.031f,.039f), TableRowBg=V(.051f,.051f,.067f), TableAltBg=V(.039f,.039f,.055f),
            TabBg=V(.051f,.051f,.063f), InputBg=V(.059f,.059f,.078f),
            Accent=V(0f,1f,.800f), AccentDim=V(0f,.302f,.239f), AccentMid=V(0f,.400f,.329f),
            Success=V(0f,1f,.600f), Warn=V(1f,.800f,0f), Danger=V(1f,.200f,.333f), Info=V(0f,.667f,1f),
            Text=V(.800f,1f,.910f), TextMuted=V(.302f,.541f,.459f), TextDim=V(.180f,.310f,.259f),
            Border=V(0f,1f,.800f,.100f), Scrollbar=V(0f,1f,.800f,.133f), Rounding=0f,
            CatRegistry=V(0f,1f,.800f), CatMovement=V(0f,.800f,1f), CatCombat=V(1f,.200f,.333f),
            CatEntity=V(.667f,1f,.400f), CatInventory=V(1f,.800f,0f), CatChat=V(.267f,1f,.667f),
            CatHandshake=V(.667f,.400f,1f), CatUnknown=V(.200f,.400f,.333f) },

        ["Midnight Purple"] = new() {
            Name="Midnight Purple", Group="Dark",
            WindowBg=V(.047f,.047f,.078f), ChildBg=V(.059f,.059f,.102f), PopupBg=V(.075f,.075f,.125f),
            TableBg=V(.039f,.039f,.071f), TableRowBg=V(.063f,.063f,.114f), TableAltBg=V(.051f,.051f,.094f),
            TabBg=V(.063f,.063f,.118f), InputBg=V(.075f,.075f,.125f),
            Accent=V(.600f,.400f,1f), AccentDim=V(.180f,.102f,.400f), AccentMid=V(.239f,.141f,.502f),
            Success=V(.267f,.867f,.533f), Warn=V(1f,.667f,.200f), Danger=V(1f,.267f,.400f), Info=V(.267f,.533f,1f),
            Text=V(.831f,.831f,.941f), TextMuted=V(.400f,.400f,.667f), TextDim=V(.247f,.247f,.400f),
            Border=V(.165f,.165f,.267f), Scrollbar=V(.239f,.141f,.502f), Rounding=3f,
            CatRegistry=V(.733f,.533f,1f), CatMovement=V(.400f,.600f,1f), CatCombat=V(1f,.267f,.400f),
            CatEntity=V(.267f,.867f,.667f), CatInventory=V(1f,.667f,.267f), CatChat=V(.533f,1f,.800f),
            CatHandshake=V(1f,.533f,.733f), CatUnknown=V(.267f,.267f,.478f) },

        ["Steel Blue"] = new() {
            Name="Steel Blue", Group="Dark",
            WindowBg=V(.055f,.067f,.090f), ChildBg=V(.071f,.094f,.125f), PopupBg=V(.086f,.114f,.157f),
            TableBg=V(.039f,.063f,.094f), TableRowBg=V(.063f,.094f,.125f), TableAltBg=V(.051f,.082f,.114f),
            TabBg=V(.067f,.094f,.125f), InputBg=V(.078f,.110f,.149f),
            Accent=V(.200f,.600f,1f), AccentDim=V(.051f,.180f,.302f), AccentMid=V(.102f,.251f,.439f),
            Success=V(.200f,.800f,.467f), Warn=V(1f,.733f,.200f), Danger=V(1f,.267f,.267f), Info=V(.200f,.800f,1f),
            Text=V(.784f,.847f,.910f), TextMuted=V(.333f,.400f,.467f), TextDim=V(.200f,.247f,.298f),
            Border=V(.118f,.180f,.267f), Scrollbar=V(.118f,.188f,.333f), Rounding=4f,
            CatRegistry=V(.533f,.533f,1f), CatMovement=V(.200f,.600f,1f), CatCombat=V(1f,.333f,.267f),
            CatEntity=V(.200f,.800f,.667f), CatInventory=V(1f,.733f,.200f), CatChat=V(.467f,1f,.800f),
            CatHandshake=V(.667f,.467f,1f), CatUnknown=V(.200f,.267f,.333f) },

        ["Toxic Green"] = new() {
            Name="Toxic Green", Group="Dark",
            WindowBg=V(.031f,.047f,.031f), ChildBg=V(.039f,.059f,.039f), PopupBg=V(.055f,.078f,.055f),
            TableBg=V(.024f,.039f,.024f), TableRowBg=V(.039f,.059f,.039f), TableAltBg=V(.031f,.051f,.031f),
            TabBg=V(.039f,.059f,.039f), InputBg=V(.051f,.075f,.051f),
            Accent=V(.267f,1f,.267f), AccentDim=V(.078f,.200f,.078f), AccentMid=V(.118f,.267f,.118f),
            Success=V(0f,1f,0f), Warn=V(.933f,1f,0f), Danger=V(1f,.133f,.200f), Info=V(.267f,1f,.933f),
            Text=V(.800f,.933f,.800f), TextMuted=V(.267f,.533f,.267f), TextDim=V(.157f,.302f,.157f),
            Border=V(.102f,.200f,.102f), Scrollbar=V(.118f,.267f,.118f), Rounding=0f,
            CatRegistry=V(.267f,1f,.267f), CatMovement=V(.267f,1f,.933f), CatCombat=V(1f,.133f,.200f),
            CatEntity=V(.667f,1f,.267f), CatInventory=V(.933f,1f,0f), CatChat=V(.267f,1f,.733f),
            CatHandshake=V(.667f,.267f,1f), CatUnknown=V(.133f,.400f,.133f) },

        ["Ember"] = new() {
            Name="Ember", Group="Warm",
            WindowBg=V(.067f,.047f,.031f), ChildBg=V(.086f,.059f,.039f), PopupBg=V(.110f,.075f,.051f),
            TableBg=V(.055f,.039f,.024f), TableRowBg=V(.082f,.059f,.039f), TableAltBg=V(.071f,.051f,.031f),
            TabBg=V(.078f,.055f,.035f), InputBg=V(.102f,.071f,.047f),
            Accent=V(1f,.533f,.133f), AccentDim=V(.302f,.145f,.031f), AccentMid=V(.416f,.208f,.063f),
            Success=V(.533f,.800f,.267f), Warn=V(1f,.800f,.133f), Danger=V(1f,.200f,.067f), Info=V(.267f,.667f,1f),
            Text=V(.941f,.847f,.722f), TextMuted=V(.502f,.376f,.251f), TextDim=V(.310f,.220f,.145f),
            Border=V(.239f,.157f,.063f), Scrollbar=V(.302f,.180f,.063f), Rounding=2f,
            CatRegistry=V(1f,.600f,.267f), CatMovement=V(.267f,.667f,1f), CatCombat=V(1f,.267f,.133f),
            CatEntity=V(.533f,.933f,.400f), CatInventory=V(1f,.800f,.133f), CatChat=V(.533f,1f,.800f),
            CatHandshake=V(.800f,.400f,1f), CatUnknown=V(.400f,.290f,.200f) },

        ["Slate"] = new() {
            Name="Slate", Group="Neutral",
            WindowBg=V(.102f,.118f,.141f), ChildBg=V(.118f,.133f,.161f), PopupBg=V(.133f,.153f,.184f),
            TableBg=V(.090f,.106f,.129f), TableRowBg=V(.114f,.133f,.157f), TableAltBg=V(.102f,.118f,.141f),
            TabBg=V(.110f,.125f,.153f), InputBg=V(.125f,.145f,.176f),
            Accent=V(.333f,.533f,.733f), AccentDim=V(.118f,.188f,.314f), AccentMid=V(.165f,.267f,.439f),
            Success=V(.267f,.733f,.467f), Warn=V(.867f,.667f,.200f), Danger=V(.800f,.200f,.267f), Info=V(.200f,.533f,.800f),
            Text=V(.816f,.847f,.878f), TextMuted=V(.416f,.471f,.533f), TextDim=V(.259f,.294f,.333f),
            Border=V(.180f,.208f,.251f), Scrollbar=V(.188f,.227f,.286f), Rounding=4f,
            CatRegistry=V(.467f,.600f,.800f), CatMovement=V(.333f,.533f,.733f), CatCombat=V(.800f,.200f,.267f),
            CatEntity=V(.267f,.733f,.533f), CatInventory=V(.867f,.667f,.200f), CatChat=V(.400f,.867f,.800f),
            CatHandshake=V(.600f,.400f,.800f), CatUnknown=V(.267f,.333f,.400f) },

        ["Rose Gold"] = new() {
            Name="Rose Gold", Group="Warm",
            WindowBg=V(.071f,.063f,.059f), ChildBg=V(.090f,.078f,.071f), PopupBg=V(.114f,.098f,.090f),
            TableBg=V(.059f,.051f,.047f), TableRowBg=V(.082f,.071f,.063f), TableAltBg=V(.071f,.063f,.055f),
            TabBg=V(.086f,.075f,.063f), InputBg=V(.102f,.086f,.078f),
            Accent=V(.933f,.467f,.467f), AccentDim=V(.302f,.125f,.125f), AccentMid=V(.427f,.180f,.180f),
            Success=V(.533f,.800f,.400f), Warn=V(1f,.733f,.267f), Danger=V(1f,.200f,.133f), Info=V(.533f,.667f,1f),
            Text=V(.941f,.878f,.863f), TextMuted=V(.533f,.400f,.400f), TextDim=V(.333f,.243f,.243f),
            Border=V(.239f,.176f,.165f), Scrollbar=V(.302f,.188f,.188f), Rounding=4f,
            CatRegistry=V(.933f,.533f,.533f), CatMovement=V(.533f,.667f,1f), CatCombat=V(1f,.267f,.200f),
            CatEntity=V(.533f,.933f,.600f), CatInventory=V(1f,.800f,.333f), CatChat=V(.600f,1f,.933f),
            CatHandshake=V(.800f,.533f,.933f), CatUnknown=V(.400f,.329f,.329f) },
    };

    // -- Helpers ---------------------------------------------------------------
    private static Vector4 V(float r, float g, float b, float a = 1f) => new(r, g, b, a);

    public static Vector4 CategoryColor(string cat) => cat.ToLowerInvariant() switch
    {
        "registry" or "items"     => ColCatRegistry,
        "movement" or "position"  => ColCatMovement,
        "combat"   or "damage"    => ColCatCombat,
        "entity"   or "spawn"     => ColCatEntity,
        "inventory"               => ColCatInventory,
        "chat"     or "message"   => ColCatChat,
        "handshake"               => ColCatHandshake,
        _                         => ColCatUnknown,
    };

    // -- Runtime switching -----------------------------------------------------
    public static void SwitchTo(string name)
    {
        if (!AllThemes.TryGetValue(name, out var def)) return;
        CurrentThemeName = name;
        Current = def;
        SyncStatics(def);
        PushToImGui(def);
    }

    private static void SyncStatics(ThemeDefinition d)
    {
        ColAccent      = d.Accent;
        ColAccentDim   = d.AccentDim;
        ColAccentMid   = d.AccentMid;
        ColWarn        = d.Warn;
        ColDanger      = d.Danger;
        ColSuccess     = d.Success;
        ColInfo        = d.Info;
        ColTextMuted   = d.TextMuted;
        ColBg3         = d.TableRowBg;
        ColBorder      = d.Border;
        ColBlueDim     = d.AccentDim;

        ColCatRegistry  = d.CatRegistry;
        ColCatMovement  = d.CatMovement;
        ColCatCombat    = d.CatCombat;
        ColCatEntity    = d.CatEntity;
        ColCatInventory = d.CatInventory;
        ColCatChat      = d.CatChat;
        ColCatHandshake = d.CatHandshake;
        ColCatUnknown   = d.CatUnknown;
    }

    // Called by HyForceApp.SetupImGuiStyle() and after SwitchTo()
    public void Apply() { if (Current == null) SwitchTo("Carbon Red"); else PushToImGui(Current); }

    private static void PushToImGui(ThemeDefinition d)
    {
        var style  = ImGui.GetStyle();
        var colors = style.Colors;

        colors[(int)ImGuiCol.WindowBg]              = d.WindowBg;
        colors[(int)ImGuiCol.ChildBg]               = d.ChildBg;
        colors[(int)ImGuiCol.PopupBg]               = d.PopupBg;

        colors[(int)ImGuiCol.TableHeaderBg]         = d.TabBg;
        colors[(int)ImGuiCol.TableBorderLight]       = d.Border;
        colors[(int)ImGuiCol.TableBorderStrong]      = d.Border;
        colors[(int)ImGuiCol.TableRowBg]             = d.TableRowBg;
        colors[(int)ImGuiCol.TableRowBgAlt]          = d.TableAltBg;

        colors[(int)ImGuiCol.Header]                = d.AccentDim;
        colors[(int)ImGuiCol.HeaderHovered]         = d.AccentMid;
        colors[(int)ImGuiCol.HeaderActive]          = d.Accent;

        // Buttons: neutral dark bg by default — let individual pushes override with accent
        var btnBg = new Vector4(d.ChildBg.X*1.3f, d.ChildBg.Y*1.3f, d.ChildBg.Z*1.3f, 1f);
        colors[(int)ImGuiCol.Button]                = btnBg;
        colors[(int)ImGuiCol.ButtonHovered]         = d.AccentDim;
        colors[(int)ImGuiCol.ButtonActive]          = d.AccentMid;

        colors[(int)ImGuiCol.CheckMark]             = d.Accent;
        colors[(int)ImGuiCol.SliderGrab]            = d.AccentMid;
        colors[(int)ImGuiCol.SliderGrabActive]      = d.Accent;

        colors[(int)ImGuiCol.Border]                = d.Border;
        colors[(int)ImGuiCol.BorderShadow]          = V(0,0,0,0);
        colors[(int)ImGuiCol.Text]                  = d.Text;
        colors[(int)ImGuiCol.TextDisabled]          = d.TextMuted;

        colors[(int)ImGuiCol.FrameBg]               = d.InputBg;
        colors[(int)ImGuiCol.FrameBgHovered]        = d.AccentDim;
        colors[(int)ImGuiCol.FrameBgActive]         = d.AccentMid;

        colors[(int)ImGuiCol.TitleBg]               = d.ChildBg;
        colors[(int)ImGuiCol.TitleBgActive]         = d.AccentDim;
        colors[(int)ImGuiCol.TitleBgCollapsed]      = d.ChildBg;

        colors[(int)ImGuiCol.Tab]                   = d.TabBg;
        colors[(int)ImGuiCol.TabHovered]            = d.AccentMid;
        colors[(int)ImGuiCol.TabSelected]           = d.Accent;
        colors[(int)ImGuiCol.TabDimmed]             = d.WindowBg;
        colors[(int)ImGuiCol.TabDimmedSelected]     = d.AccentDim;

        colors[(int)ImGuiCol.MenuBarBg]             = d.ChildBg;

        colors[(int)ImGuiCol.ScrollbarBg]           = d.WindowBg;
        colors[(int)ImGuiCol.ScrollbarGrab]         = d.Scrollbar;
        colors[(int)ImGuiCol.ScrollbarGrabHovered]  = d.AccentDim;
        colors[(int)ImGuiCol.ScrollbarGrabActive]   = d.Accent;

        colors[(int)ImGuiCol.Separator]             = d.Border;
        colors[(int)ImGuiCol.SeparatorHovered]      = d.AccentMid;
        colors[(int)ImGuiCol.SeparatorActive]       = d.Accent;

        colors[(int)ImGuiCol.ResizeGrip]            = d.AccentDim;
        colors[(int)ImGuiCol.ResizeGripHovered]     = d.AccentMid;
        colors[(int)ImGuiCol.ResizeGripActive]      = d.Accent;

        colors[(int)ImGuiCol.PlotLines]             = d.Accent;
        colors[(int)ImGuiCol.PlotLinesHovered]      = d.Warn;
        colors[(int)ImGuiCol.PlotHistogram]         = d.Accent;
        colors[(int)ImGuiCol.PlotHistogramHovered]  = d.Warn;

        // NavHighlight not available in this ImGui.NET build

        style.WindowRounding    = d.Rounding;
        style.ChildRounding     = d.Rounding;
        style.FrameRounding     = d.Rounding;
        style.PopupRounding     = d.Rounding;
        style.ScrollbarRounding = Math.Max(d.Rounding, 4f);
        style.GrabRounding      = d.Rounding;
        style.TabRounding       = d.Rounding;

        style.WindowPadding     = new Vector2(10, 8);
        style.FramePadding      = new Vector2(8, 4);
        style.ItemSpacing       = new Vector2(8, 5);
        style.CellPadding       = new Vector2(5, 3);
        style.ScrollbarSize     = 10f;
        style.GrabMinSize       = 8f;
        style.WindowBorderSize  = 1f;
        style.ChildBorderSize   = 1f;
        // FrameBorderSize=1 makes all buttons/inputs show a border — critical for visibility
        style.FrameBorderSize   = 1f;

        SyncStatics(d);
    }

    static Theme() { SwitchTo("Carbon Red"); }
}
