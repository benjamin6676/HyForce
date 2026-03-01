// FILE: Tabs/MemoryTab.cs - Hytale-specific version
using HyForce.Core;
using HyForce.UI;
using ImGuiNET;
using System.Diagnostics;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Text;

namespace HyForce.Tabs;

public class MemoryTab : ITab
{
    public string Name => "Memory";

    private readonly AppState _state;

    // Hytale process info
    private Process? _hytaleProcess;
    private IntPtr _processHandle = IntPtr.Zero;
    private bool _isAttached = false;
    private string _processName = "Hytale"; // Or "HytaleGame", "hytale"

    // Hytale-specific data
    private HytalePlayer? _localPlayer;
    private List<HytalePlayer> _nearbyPlayers = new();
    private List<HytaleEntity> _entities = new();
    private HytaleWorldInfo _worldInfo = new();

    // UI
    private bool _autoRefresh = false;
    private float _refreshInterval = 1.0f;
    private double _lastRefresh = 0;
    private int _selectedPlayer = -1;

    // Windows API
    [DllImport("kernel32.dll")]
    private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll")]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    private static extern IntPtr VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesWritten);

    private const int PROCESS_VM_READ = 0x0010;
    private const int PROCESS_VM_WRITE = 0x0020;
    private const int PROCESS_VM_OPERATION = 0x0008;
    private const int PROCESS_QUERY_INFORMATION = 0x0400;

    public MemoryTab(AppState state)
    {
        _state = state;
    }

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();

        ImGui.Spacing();
        ImGui.Text("  HYTALE MEMORY ANALYZER  —  Live Game Data");
        ImGui.Separator();
        ImGui.Spacing();

        // Top bar: Attachment status
        RenderAttachmentBar();

        ImGui.Spacing();
        ImGui.Separator();

        if (!_isAttached)
        {
            RenderNotAttachedMessage();
            return;
        }

        // Auto-refresh
        if (_autoRefresh && ImGui.GetTime() - _lastRefresh > _refreshInterval)
        {
            RefreshData();
            _lastRefresh = ImGui.GetTime();
        }

        // Main content
        float leftWidth = 350;
        float rightWidth = avail.X - leftWidth - 20;

        ImGui.BeginChild("##memory_left", new Vector2(leftWidth, avail.Y - 100), ImGuiChildFlags.Borders);
        RenderPlayerList(leftWidth);
        ImGui.EndChild();

        ImGui.SameLine();

        ImGui.BeginChild("##memory_right", new Vector2(rightWidth, avail.Y - 100), ImGuiChildFlags.Borders);
        RenderDetailsPanel(rightWidth);
        ImGui.EndChild();
    }

    private void RenderAttachmentBar()
    {
        ImGui.Text("Process: ");
        ImGui.SameLine();
        ImGui.SetNextItemWidth(150);
        ImGui.InputText("##procname", ref _processName, 64);

        ImGui.SameLine();

        if (!_isAttached)
        {
            ImGui.PushStyleColor(ImGuiCol.Button, Theme.ColSuccess);
            if (ImGui.Button("Attach to Hytale", new Vector2(150, 28)))
            {
                AttachToHytale();
            }
            ImGui.PopStyleColor();
        }
        else
        {
            ImGui.PushStyleColor(ImGuiCol.Button, Theme.ColDanger);
            if (ImGui.Button("Detach", new Vector2(100, 28)))
            {
                Detach();
            }
            ImGui.PopStyleColor();

            ImGui.SameLine();
            if (ImGui.Button("Refresh Now", new Vector2(100, 28)))
            {
                RefreshData();
            }

            ImGui.SameLine();
            ImGui.Checkbox("Auto", ref _autoRefresh);

            if (_autoRefresh)
            {
                ImGui.SameLine();
                ImGui.SetNextItemWidth(60);
                ImGui.InputFloat("s", ref _refreshInterval, 0.1f);
            }

            ImGui.SameLine();
            ImGui.TextColored(Theme.ColSuccess, $"✓ Attached to Hytale (PID: {_hytaleProcess?.Id})");
        }
    }

    private void RenderNotAttachedMessage()
    {
        ImGui.Spacing();
        ImGui.TextColored(Theme.ColAccent, "How to use Memory Analyzer:");
        ImGui.BulletText("Launch Hytale and connect to a server");
        ImGui.BulletText("Click 'Attach to Hytale'");
        ImGui.BulletText("The tool will scan for player data, entities, and world info");
        ImGui.BulletText("Use this to find encryption keys or packet structures");

        ImGui.Spacing();
        ImGui.TextColored(Theme.ColWarn, "Note: Run as Administrator for best results");

        ImGui.Spacing();
        if (ImGui.Button("Try Common Process Names", new Vector2(200, 32)))
        {
            TryCommonNames();
        }
    }

    private void RenderPlayerList(float width)
    {
        ImGui.TextColored(Theme.ColAccent, "Players");
        ImGui.Separator();

        // Local player first
        if (_localPlayer != null)
        {
            ImGui.PushStyleColor(ImGuiCol.Text, Theme.ColSuccess);
            if (ImGui.Selectable($"[YOU] {_localPlayer.Name}", _selectedPlayer == -1))
            {
                _selectedPlayer = -1;
            }
            ImGui.PopStyleColor();

            ImGui.SameLine();
            ImGui.TextColored(Theme.ColTextMuted, $"HP:{_localPlayer.Health:F0}");
        }

        // Other players
        for (int i = 0; i < _nearbyPlayers.Count; i++)
        {
            var player = _nearbyPlayers[i];
            if (ImGui.Selectable($"{player.Name}", _selectedPlayer == i))
            {
                _selectedPlayer = i;
            }

            ImGui.SameLine();
            ImGui.TextColored(Theme.ColTextMuted, $"Dist:{GetDistance(_localPlayer, player):F1}m");
        }

        ImGui.Spacing();
        ImGui.TextColored(Theme.ColAccent, $"Entities ({_entities.Count})");
        ImGui.Separator();

        foreach (var entity in _entities.Take(20))
        {
            ImGui.Text($"[{entity.Type}] {entity.Name}");
        }
    }

    private void RenderDetailsPanel(float width)
    {
        var player = _selectedPlayer == -1 ? _localPlayer :
                    (_selectedPlayer >= 0 && _selectedPlayer < _nearbyPlayers.Count) ?
                    _nearbyPlayers[_selectedPlayer] : null;

        if (player == null)
        {
            ImGui.TextColored(Theme.ColTextMuted, "Select a player to view details");
            return;
        }

        // Header
        ImGui.PushStyleColor(ImGuiCol.Text, Theme.ColAccent);
        ImGui.SetWindowFontScale(1.4f);
        ImGui.Text(player.Name);
        ImGui.SetWindowFontScale(1.0f);
        ImGui.PopStyleColor();

        if (player.IsLocalPlayer)
        {
            ImGui.SameLine();
            ImGui.TextColored(Theme.ColSuccess, "[LOCAL PLAYER]");
        }

        ImGui.Separator();

        // Stats in columns
        ImGui.Columns(2, "##player_stats", false);

        // Health
        ImGui.TextColored(Theme.ColTextMuted, "Health");
        ImGui.Text($"{player.Health:F0} / {player.MaxHealth:F0}");
        ImGui.ProgressBar(player.Health / player.MaxHealth, new Vector2(ImGui.GetColumnWidth() - 10, 16));
        ImGui.NextColumn();

        // Mana/Stamina
        ImGui.TextColored(Theme.ColTextMuted, "Mana/Stamina");
        ImGui.Text($"{player.Mana:F0} / {player.MaxMana:F0}");
        ImGui.ProgressBar(player.Mana / player.MaxMana, new Vector2(ImGui.GetColumnWidth() - 10, 16));
        ImGui.NextColumn();

        ImGui.Columns(1);
        ImGui.Separator();

        // Position & World
        ImGui.TextColored(Theme.ColAccent, "Position & World");

        ImGui.Text($"World Position:");
        ImGui.Text($"  X: {player.Position.X:F3}");
        ImGui.Text($"  Y: {player.Position.Y:F3}");
        ImGui.Text($"  Z: {player.Position.Z:F3}");

        ImGui.Text($"Chunk: {player.ChunkX}, {player.ChunkZ}");
        ImGui.Text($"Rotation: {player.Yaw:F1}° / {player.Pitch:F1}°");

        ImGui.Separator();

        // Inventory
        ImGui.TextColored(Theme.ColAccent, $"Inventory ({player.Inventory.Count} items)");

        if (ImGui.BeginTable("##inv", 3, ImGuiTableFlags.RowBg | ImGuiTableFlags.Borders))
        {
            ImGui.TableSetupColumn("Slot", ImGuiTableColumnFlags.WidthFixed, 40);
            ImGui.TableSetupColumn("Item", ImGuiTableColumnFlags.WidthStretch);
            ImGui.TableSetupColumn("Count", ImGuiTableColumnFlags.WidthFixed, 50);
            ImGui.TableHeadersRow();

            foreach (var item in player.Inventory.Take(20))
            {
                ImGui.TableNextRow();
                ImGui.TableSetColumnIndex(0);
                ImGui.Text($"{item.Slot}");
                ImGui.TableSetColumnIndex(1);
                ImGui.Text(item.Name);
                ImGui.TableSetColumnIndex(2);
                ImGui.Text($"{item.Count}");
            }
            ImGui.EndTable();
        }

        // Memory address
        ImGui.Separator();
        ImGui.TextColored(Theme.ColTextMuted, "Memory Address:");
        ImGui.Text($"0x{player.BaseAddress:X16}");

        if (ImGui.Button("Copy Address"))
        {
            CopyToClipboard($"0x{player.BaseAddress:X16}");
        }

        ImGui.SameLine();
        if (ImGui.Button("Watch Memory"))
        {
            // Open memory watcher
        }

        // Debug info for encryption bypass
        ImGui.Separator();
        ImGui.TextColored(Theme.ColWarn, "Encryption Analysis");

        if (player.EncryptionKey != null)
        {
            ImGui.TextColored(Theme.ColSuccess, "Found potential key!");
            ImGui.Text($"Key: {BitConverter.ToString(player.EncryptionKey)}");
        }
        else
        {
            ImGui.Text("No encryption key found in player data");
        }
    }

    private void AttachToHytale()
    {
        try
        {
            var processes = Process.GetProcessesByName(_processName);
            if (processes.Length == 0)
            {
                // Try variations
                var allProcesses = Process.GetProcesses();
                processes = allProcesses.Where(p =>
                    p.ProcessName.Contains("hytale", StringComparison.OrdinalIgnoreCase) ||
                    p.ProcessName.Contains("hyta", StringComparison.OrdinalIgnoreCase))
                    .ToArray();
            }

            if (processes.Length > 0)
            {
                _hytaleProcess = processes[0];
                _processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, _hytaleProcess.Id);

                if (_processHandle != IntPtr.Zero)
                {
                    _isAttached = true;
                    _state.AddInGameLog($"[MEMORY] Attached to Hytale (PID: {_hytaleProcess.Id})");

                    // Initial scan
                    RefreshData();
                }
                else
                {
                    _state.AddInGameLog($"[MEMORY] Failed to open process - Run as Administrator!");
                }
            }
            else
            {
                _state.AddInGameLog($"[MEMORY] Hytale process not found");
            }
        }
        catch (Exception ex)
        {
            _state.AddInGameLog($"[MEMORY] Error: {ex.Message}");
        }
    }

    private void TryCommonNames()
    {
        string[] names = { "Hytale", "hytale", "HytaleGame", "HytaleLauncher", "hyta" };
        foreach (var name in names)
        {
            var procs = Process.GetProcessesByName(name);
            if (procs.Length > 0)
            {
                _processName = name;
                AttachToHytale();
                return;
            }
        }
        _state.AddInGameLog("[MEMORY] No Hytale process found with common names");
    }

    private void Detach()
    {
        if (_processHandle != IntPtr.Zero)
        {
            CloseHandle(_processHandle);
            _processHandle = IntPtr.Zero;
        }
        _hytaleProcess = null;
        _isAttached = false;
        _localPlayer = null;
        _nearbyPlayers.Clear();
        _entities.Clear();
        _state.AddInGameLog("[MEMORY] Detached");
    }

    private void RefreshData()
    {
        if (_processHandle == IntPtr.Zero) return;

        try
        {
            // Scan for local player
            ScanForLocalPlayer();

            // Scan for other players
            ScanForOtherPlayers();

            // Scan for entities
            ScanForEntities();

            // Look for encryption keys
            ScanForEncryptionKeys();
        }
        catch (Exception ex)
        {
            _state.AddInGameLog($"[MEMORY] Refresh error: {ex.Message}");
        }
    }

    private void ScanForLocalPlayer()
    {
        // Hytale likely stores local player in a static pointer or global
        // Look for:
        // - Player name string
        // - Health/mana floats (100.0f, 50.0f, etc.)
        // - Position vector (3 floats)

        // This is a simplified scan - real implementation would use pattern scanning

        // Example pattern for player health (float)
        // 00 00 C8 42 = 100.0f
        // Look for this near position data and player name
    }

    private void ScanForOtherPlayers()
    {
        // Look for other player structures in memory
        // Usually stored in a linked list or array
    }

    private void ScanForEntities()
    {
        // NPCs, mobs, objects
    }

    private void ScanForEncryptionKeys()
    {
        // CRITICAL: Look for encryption keys
        // Hytale uses QUIC which means TLS 1.3 keys
        // Look for:
        // - 32-byte sequences (AES-256 keys)
        // - 16-byte sequences (AES-128 keys)
        // - Near QUIC-related strings

        // Search for "quic", "tls", "key" strings and check nearby memory
    }

    private float GetDistance(HytalePlayer? p1, HytalePlayer p2)
    {
        if (p1 == null) return 0;
        return Vector3.Distance(p1.Position, p2.Position);
    }

    private void CopyToClipboard(string text)
    {
        try { TextCopy.ClipboardService.SetText(text); } catch { }
    }

    public void Dispose()
    {
        Detach();
    }

    // Hytale-specific data structures
    private class HytalePlayer
    {
        public string Name = "Unknown";
        public IntPtr BaseAddress;
        public bool IsLocalPlayer = false;

        // Stats
        public float Health = 100;
        public float MaxHealth = 100;
        public float Mana = 100;
        public float MaxMana = 100;
        public int Level = 1;

        // Position
        public Vector3 Position;
        public float Yaw;
        public float Pitch;
        public int ChunkX => (int)(Position.X / 16);
        public int ChunkZ => (int)(Position.Z / 16);

        // Inventory
        public List<HytaleItem> Inventory = new();

        // Encryption
        public byte[]? EncryptionKey;
    }

    private class HytaleEntity
    {
        public string Type = "Unknown";
        public string Name = "Unknown";
        public Vector3 Position;
        public IntPtr Address;
    }

    private class HytaleItem
    {
        public int Slot;
        public string Name = "Unknown";
        public int Count;
        public uint ItemId;
    }

    private class HytaleWorldInfo
    {
        public string WorldName = "Unknown";
        public int Seed;
        public long Time;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }
}