// FILE: Utils/GlobalHotkeys.cs
// Win32 global hotkeys — fire callbacks even when Hytale is the foreground window.
// Uses RegisterHotKey / PeekMessage polling (no hidden window required for Veldrid apps
// because Veldrid's SDL2 backend pumps a Win32 message queue internally).
//
// Default bindings (all configurable):
//   F8  — Trigger Action Correlator capture
//   F9  — Start session recording
//   F10 — Stop recording + save
//   F11 — Inject last packet (repeat last injection)

using System.Runtime.InteropServices;

namespace HyForce.Utils;

public class GlobalHotkeys : IDisposable
{
    // ── Win32 ──────────────────────────────────────────────────────────────
    [DllImport("user32.dll")] private static extern bool RegisterHotKey(IntPtr hWnd, int id, uint fsModifiers, uint vk);
    [DllImport("user32.dll")] private static extern bool UnregisterHotKey(IntPtr hWnd, int id);
    [DllImport("user32.dll")] private static extern bool PeekMessage(out MSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax, uint wRemoveMsg);

    private const uint WM_HOTKEY    = 0x0312;
    private const uint PM_REMOVE    = 0x0001;
    private const uint MOD_NONE     = 0x0000;
    private const uint MOD_ALT      = 0x0001;
    private const uint MOD_CTRL     = 0x0002;
    private const uint MOD_SHIFT    = 0x0004;
    private const uint VK_F8  = 0x77;
    private const uint VK_F9  = 0x78;
    private const uint VK_F10 = 0x79;
    private const uint VK_F11 = 0x7A;

    [StructLayout(LayoutKind.Sequential)]
    private struct MSG { public IntPtr hwnd; public uint message; public nuint wParam; public nint lParam; public uint time; public POINT pt; }
    [StructLayout(LayoutKind.Sequential)]
    private struct POINT { public int x; public int y; }

    // ── Binding registry ──────────────────────────────────────────────────
    private readonly Dictionary<int, HotkeyBinding> _bindings = new();
    private int _nextId = 100;
    private bool _disposed;

    // ── Public events ─────────────────────────────────────────────────────
    public event Action? OnCorrelatorCapture;
    public event Action? OnRecordStart;
    public event Action? OnRecordStop;
    public event Action? OnInjectRepeat;

    // ── Overlay notification ──────────────────────────────────────────────
    public string? OverlayMessage       { get; private set; }
    public float   OverlayMessageExpiry { get; private set; }

    // ── Current binding display ───────────────────────────────────────────
    public IReadOnlyDictionary<int, HotkeyBinding> Bindings => _bindings;

    public GlobalHotkeys()
    {
        RegisterDefault(VK_F8,  MOD_NONE, "Correlator Capture",  () => { ShowOverlay("● CAPTURING"); OnCorrelatorCapture?.Invoke(); });
        RegisterDefault(VK_F9,  MOD_NONE, "Start Recording",     () => { ShowOverlay("● RECORDING");  OnRecordStart?.Invoke(); });
        RegisterDefault(VK_F10, MOD_NONE, "Stop Recording",      () => { ShowOverlay("■ SAVED");      OnRecordStop?.Invoke(); });
        RegisterDefault(VK_F11, MOD_NONE, "Inject Repeat",       () => { ShowOverlay("⚡ INJECTING"); OnInjectRepeat?.Invoke(); });
    }

    // ── Polling (call once per render frame) ──────────────────────────────
    public void Poll()
    {
        // Drain WM_HOTKEY messages from the queue
        while (PeekMessage(out var msg, IntPtr.Zero, WM_HOTKEY, WM_HOTKEY, PM_REMOVE))
        {
            int id = (int)msg.wParam;
            if (_bindings.TryGetValue(id, out var binding))
            {
                try { binding.Callback?.Invoke(); }
                catch { /* Never crash the render loop */ }
            }
        }

        // Expire overlay
        if (OverlayMessage != null && ImGuiNET.ImGui.GetTime() > OverlayMessageExpiry)
            OverlayMessage = null;
    }

    // ── Rebind support ─────────────────────────────────────────────────────
    public bool Rebind(int id, uint newVk, uint newMod = MOD_NONE)
    {
        if (!_bindings.TryGetValue(id, out var binding)) return false;

        UnregisterHotKey(IntPtr.Zero, id);
        if (RegisterHotKey(IntPtr.Zero, id, newMod, newVk))
        {
            binding.Vk  = newVk;
            binding.Mod = newMod;
            return true;
        }
        // Re-register old binding on failure
        RegisterHotKey(IntPtr.Zero, id, binding.Mod, binding.Vk);
        return false;
    }

    // ── Overlay rendering (call from main render loop) ────────────────────
    public void RenderOverlay()
    {
        if (OverlayMessage == null) return;

        var io = ImGuiNET.ImGui.GetIO();
        ImGuiNET.ImGui.SetNextWindowPos(new System.Numerics.Vector2(20, 20),
            ImGuiNET.ImGuiCond.Always);
        ImGuiNET.ImGui.SetNextWindowBgAlpha(0.75f);
        ImGuiNET.ImGui.Begin("##hotkey_overlay",
            ImGuiNET.ImGuiWindowFlags.NoDecoration  |
            ImGuiNET.ImGuiWindowFlags.NoInputs       |
            ImGuiNET.ImGuiWindowFlags.NoSavedSettings|
            ImGuiNET.ImGuiWindowFlags.AlwaysAutoResize);
        ImGuiNET.ImGui.TextColored(new System.Numerics.Vector4(1f, 0.4f, 0.2f, 1f), OverlayMessage);
        ImGuiNET.ImGui.End();
    }

    // ── Internals ─────────────────────────────────────────────────────────
    private void RegisterDefault(uint vk, uint mod, string name, Action cb)
    {
        int id = _nextId++;
        bool ok = RegisterHotKey(IntPtr.Zero, id, mod, vk);
        _bindings[id] = new HotkeyBinding
        {
            Id       = id,
            Name     = name,
            Vk       = vk,
            Mod      = mod,
            Callback = cb,
            IsActive = ok
        };
    }

    private void ShowOverlay(string msg)
    {
        OverlayMessage       = msg;
        OverlayMessageExpiry = (float)(ImGuiNET.ImGui.GetTime() + 2.5);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        foreach (var id in _bindings.Keys)
            UnregisterHotKey(IntPtr.Zero, id);
        _bindings.Clear();
    }
}

public class HotkeyBinding
{
    public int      Id       { get; set; }
    public string   Name     { get; set; } = "";
    public uint     Vk       { get; set; }
    public uint     Mod      { get; set; }
    public Action?  Callback { get; set; }
    public bool     IsActive { get; set; }

    public string KeyDisplay => $"F{Vk - 0x6F}";  // F1=0x70, F8=0x77 etc.
}
