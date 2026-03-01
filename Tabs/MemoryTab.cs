// FILE: Tabs/MemoryTab.cs - FIXED: NO FREEZE, AUTO-KEY EXTRACTION
using HyForce.Core;
using HyForce.Protocol;
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
    private Process? _hytaleProcess;
    private IntPtr _processHandle = IntPtr.Zero;
    private bool _isAttached = false;
    private string _processName = "Hytale";

    // Scanning state
    private string _scanValue = "";
    private string _scanPattern = "";
    private int _selectedScanType = 0;
    private List<MemoryResult> _scanResults = new();
    private List<MemoryResult> _filteredResults = new();
    private MemoryResult? _selectedAddress;
    private string _resultFilter = "";

    // Pointer map
    private Dictionary<IntPtr, List<IntPtr>> _pointerMap = new();

    // Live watch
    private List<WatchEntry> _watches = new();
    private bool _autoRefresh = true;
    private double _lastRefresh = 0;
    private float _refreshInterval = 0.5f;

    // Edit popup
    private bool _showEditPopup = false;
    private string _editValue = "";

    // FIXED: Add cancellation token for scans
    private CancellationTokenSource? _scanCts;

    // Windows API
    [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    [DllImport("kernel32.dll")] static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);
    [DllImport("kernel32.dll")] static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesWritten);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr hObject);
    [DllImport("kernel32.dll")] static extern IntPtr VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    private const int PROCESS_VM_READ = 0x0010;
    private const int PROCESS_VM_WRITE = 0x0020;
    private const int PROCESS_VM_OPERATION = 0x0008;
    private const int PROCESS_QUERY_INFORMATION = 0x0400;

    public MemoryTab(AppState state)
    {
        _state = state;
        // FIXED: Subscribe to event for menu-triggered scans
        _state.OnMemoryDataUpdated += OnQuickScanRequested;
    }

    private void OnQuickScanRequested()
    {
        // This will be called from menu - safe to call QuickScanPlayer
        if (_isAttached)
        {
            QuickScanPlayer();
        }
        else
        {
            _state.AddInGameLog("[MEMORY] Attach to process first before scanning!");
            // Auto-switch to this tab
            
        }
    }

    public void Render()
    {
        var avail = ImGui.GetContentRegionAvail();

        ImGui.Spacing();
        ImGui.Text("  ADVANCED MEMORY SCANNER  -  Find Player Data & Encryption Keys");
        ImGui.Separator();
        ImGui.Spacing();

        RenderAttachmentBar();

        if (!_isAttached)
        {
            RenderNotAttached();
            return;
        }

        // Auto-refresh watches
        if (_autoRefresh && ImGui.GetTime() - _lastRefresh > _refreshInterval)
        {
            RefreshWatches();
            _lastRefresh = ImGui.GetTime();
        }

        float leftWidth = Math.Min(400, avail.X * 0.4f);
        float rightWidth = Math.Max(0, avail.X - leftWidth - 20);

        ImGui.BeginChild("##scan_panel", new Vector2(leftWidth, avail.Y - 50), ImGuiChildFlags.Borders);
        RenderScanPanel(leftWidth);
        ImGui.EndChild();

        ImGui.SameLine();

        ImGui.BeginChild("##results_panel", new Vector2(rightWidth, avail.Y - 50), ImGuiChildFlags.Borders);
        RenderResultsPanel(rightWidth);
        ImGui.EndChild();

        if (_showEditPopup)
        {
            ImGui.OpenPopup("edit_value");
            _showEditPopup = false;
        }

        RenderEditPopup();
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
                AttachToProcess();
            ImGui.PopStyleColor();
        }
        else
        {
            ImGui.PushStyleColor(ImGuiCol.Button, Theme.ColDanger);
            if (ImGui.Button("Detach", new Vector2(100, 28)))
                Detach();
            ImGui.PopStyleColor();

            ImGui.SameLine();
            // FIXED: Disable button during scan
            bool scanning = _scanCts != null;
            if (scanning)
            {
                ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.5f, 0.5f, 0.5f, 1f));
                ImGui.Button("Scanning...", new Vector2(140, 28));
                ImGui.PopStyleColor();
            }
            else
            {
                if (ImGui.Button("Quick Scan Player", new Vector2(140, 28)))
                    QuickScanPlayer();
            }

            ImGui.SameLine();
            if (ImGui.Button("Find TLS Keys", new Vector2(120, 28)))
                ScanForTLSKeys();

            ImGui.SameLine();
            ImGui.Checkbox("Auto", ref _autoRefresh);
        }
    }

    private void RenderNotAttached()
    {
        ImGui.Spacing();
        ImGui.TextColored(Theme.ColAccent, "How to use:");
        ImGui.BulletText("Launch Hytale and connect to a server");
        ImGui.BulletText("Click 'Attach to Hytale'");
        ImGui.BulletText("Use 'Quick Scan Player' to find health/position");
        ImGui.BulletText("Use 'Find TLS Keys' for automatic decryption");

        ImGui.Spacing();
        ImGui.TextColored(Theme.ColWarn, "Run as Administrator for best results");

        ImGui.Spacing();
        ImGui.TextColored(Theme.ColDanger, "WARNING: Scans may take 5-10 seconds but won't freeze UI.");
    }

    private void RenderScanPanel(float width)
    {
        ImGui.TextColored(Theme.ColAccent, "Scan Configuration");
        ImGui.Separator();

        string[] scanTypes = { "Exact Value", "Pattern (AOB)", "String", "Float Range" };
        ImGui.Combo("Scan Type", ref _selectedScanType, scanTypes, scanTypes.Length);

        switch (_selectedScanType)
        {
            case 0:
                ImGui.InputText("Value", ref _scanValue, 64);
                break;
            case 1:
                ImGui.InputText("Pattern (hex)", ref _scanPattern, 256);
                ImGui.TextColored(Theme.ColTextMuted, "Example: 48 8B 05 ?? ?? ?? ??");
                break;
            case 2:
                ImGui.InputText("String", ref _scanValue, 64);
                break;
            case 3:
                ImGui.InputText("Min-Max", ref _scanValue, 64);
                ImGui.TextColored(Theme.ColTextMuted, "Example: 0-100");
                break;
        }

        ImGui.Spacing();

        bool scanning = _scanCts != null;
        if (scanning) ImGui.BeginDisabled();

        if (ImGui.Button("First Scan", new Vector2(100, 28)))
            PerformFirstScan();

        ImGui.SameLine();

        if (ImGui.Button("Next Scan", new Vector2(100, 28)))
            PerformNextScan();

        ImGui.SameLine();

        if (ImGui.Button("Reset", new Vector2(80, 28)))
        {
            _scanResults.Clear();
            _filteredResults.Clear();
            _scanCts?.Cancel();
            _scanCts = null;
        }

        if (scanning) ImGui.EndDisabled();

        ImGui.Spacing();
        ImGui.Separator();

        ImGui.InputText("Filter Results", ref _resultFilter, 64);
        ApplyFilter();

        ImGui.TextColored(Theme.ColAccent, $"Results: {_filteredResults.Count}");

        ImGui.BeginChild("##scan_results", new Vector2(0, 200), ImGuiChildFlags.Borders);

        for (int i = 0; i < Math.Min(_filteredResults.Count, 100); i++)
        {
            var result = _filteredResults[i];
            bool selected = _selectedAddress?.Address == result.Address;

            if (selected)
                ImGui.PushStyleColor(ImGuiCol.Text, Theme.ColAccent);

            string display = $"0x{(ulong)result.Address:X8} = {result.ValuePreview}";
            if (ImGui.Selectable(display, selected))
            {
                _selectedAddress = result;
            }

            if (selected)
                ImGui.PopStyleColor();

            if (ImGui.IsItemClicked(ImGuiMouseButton.Right))
                ImGui.OpenPopup($"ctx_{i}");

            if (ImGui.BeginPopup($"ctx_{i}"))
            {
                if (ImGui.MenuItem("Add to Watch"))
                    AddToWatch(result);
                if (ImGui.MenuItem("Copy Address"))
                    CopyToClipboard($"0x{(ulong)result.Address:X}");
                if (ImGui.MenuItem("Find Pointers to This"))
                    FindPointersTo(result.Address);
                if (ImGui.MenuItem("Use as Decryption Key"))
                    UseAsDecryptionKey(result);
                ImGui.EndPopup();
            }
        }
        ImGui.EndChild();

        ImGui.Spacing();
        ImGui.Separator();
        ImGui.TextColored(Theme.ColAccent, "Active Watches");

        ImGui.BeginChild("##watches", new Vector2(0, 150), ImGuiChildFlags.Borders);
        for (int i = 0; i < _watches.Count; i++)
        {
            var watch = _watches[i];
            ImGui.TextColored(Theme.ColTextMuted, watch.Name);
            ImGui.SameLine(120);

            var currentValue = ReadMemoryValue(watch.Address, watch.Type);

            if (currentValue != watch.LastValue)
            {
                ImGui.PushStyleColor(ImGuiCol.Text, Theme.ColWarn);
                ImGui.Text(currentValue);
                ImGui.PopStyleColor();
                _watches[i] = new WatchEntry
                {
                    Address = watch.Address,
                    Type = watch.Type,
                    Name = watch.Name,
                    LastValue = currentValue
                };
            }
            else
            {
                ImGui.Text(currentValue);
            }

            ImGui.SameLine();
            if (ImGui.Button($"X##{i}", new Vector2(20, 0)))
            {
                _watches.RemoveAt(i);
                i--;
            }
        }
        ImGui.EndChild();
    }

    private void RenderResultsPanel(float width)
    {
        if (_selectedAddress == null)
        {
            ImGui.TextColored(Theme.ColTextMuted, "Select an address to view details");
            return;
        }

        var addr = _selectedAddress.Value;

        ImGui.TextColored(Theme.ColAccent, $"Address: 0x{(ulong)addr.Address:X16}");
        ImGui.Separator();

        ImGui.Text("Memory Preview (Hex)");
        var bytes = ReadMemoryBytes(addr.Address, 256);
        if (bytes != null)
        {
            RenderHexViewer(bytes, addr.Address);
        }

        ImGui.Separator();

        ImGui.TextColored(Theme.ColAccent, "Type Interpretations");

        if (bytes != null && bytes.Length >= 8)
        {
            ImGui.Columns(2, "##types", false);

            ImGui.Text("Int32:");
            ImGui.NextColumn();
            ImGui.Text(BitConverter.ToInt32(bytes, 0).ToString());
            ImGui.NextColumn();

            ImGui.Text("Float:");
            ImGui.NextColumn();
            ImGui.Text(BitConverter.ToSingle(bytes, 0).ToString("F4"));
            ImGui.NextColumn();

            ImGui.Text("Double:");
            ImGui.NextColumn();
            ImGui.Text(BitConverter.ToDouble(bytes, 0).ToString("F6"));
            ImGui.NextColumn();

            ImGui.Text("Int64:");
            ImGui.NextColumn();
            ImGui.Text(BitConverter.ToInt64(bytes, 0).ToString());
            ImGui.NextColumn();

            ImGui.Columns(1);
        }

        ImGui.Separator();

        if (_pointerMap.ContainsKey(addr.Address))
        {
            ImGui.TextColored(Theme.ColAccent, "Pointers to this address:");
            foreach (var ptr in _pointerMap[addr.Address].Take(10))
            {
                ImGui.Text($"  0x{(ulong)ptr:X}");
            }
        }

        ImGui.Separator();
        if (ImGui.Button("Edit Value", new Vector2(100, 28)))
        {
            _showEditPopup = true;
        }

        ImGui.SameLine();
        if (ImGui.Button("Add Watch", new Vector2(100, 28)))
        {
            AddToWatch(addr);
        }

        ImGui.SameLine();
        if (ImGui.Button("Use as Key", new Vector2(100, 28)))
        {
            UseAsDecryptionKey(addr);
        }
    }

    private void RenderEditPopup()
    {
        if (ImGui.BeginPopupModal("edit_value", ref _showEditPopup, ImGuiWindowFlags.AlwaysAutoResize))
        {
            ImGui.Text($"Edit value at 0x{(ulong)_selectedAddress?.Address:X}");
            ImGui.InputText("New Value", ref _editValue, 64);

            if (ImGui.Button("Write", new Vector2(80, 28)))
            {
                if (_selectedAddress.HasValue)
                {
                    WriteMemoryValue(_selectedAddress.Value.Address, _editValue);
                }
                ImGui.CloseCurrentPopup();
            }

            ImGui.SameLine();
            if (ImGui.Button("Cancel", new Vector2(80, 28)))
            {
                ImGui.CloseCurrentPopup();
            }

            ImGui.EndPopup();
        }
    }

    private void RenderHexViewer(byte[] data, IntPtr baseAddr)
    {
        ImGui.BeginChild("##hex", new Vector2(0, 200), ImGuiChildFlags.Borders);

        for (int i = 0; i < data.Length; i += 16)
        {
            ImGui.TextColored(Theme.ColTextMuted, $"{(ulong)(baseAddr + i):X8}  ");
            ImGui.SameLine();

            for (int j = 0; j < 16 && i + j < data.Length; j++)
            {
                ImGui.Text($"{data[i + j]:X2} ");
                if (j < 15) ImGui.SameLine();
            }

            ImGui.SameLine();
            ImGui.Text(" |");
            ImGui.SameLine();

            for (int j = 0; j < 16 && i + j < data.Length; j++)
            {
                char c = (char)data[i + j];
                if (c < 32 || c > 126) c = '.';
                ImGui.Text(c.ToString());
                ImGui.SameLine();
            }
            ImGui.Text("|");
        }

        ImGui.EndChild();
    }

    // ==================== SCANNING METHODS - FIXED ====================

    private async void PerformFirstScan()
    {
        _scanCts = new CancellationTokenSource();
        var token = _scanCts.Token;

        _state.AddInGameLog("[MEMORY] Starting scan...");

        try
        {
            await Task.Run(() => DoFirstScan(token), token);
        }
        catch (OperationCanceledException)
        {
            _state.AddInGameLog("[MEMORY] Scan cancelled");
        }
        catch (Exception ex)
        {
            _state.AddInGameLog($"[MEMORY] Scan error: {ex.Message}");
        }
        finally
        {
            _scanCts = null;
        }
    }

    private void DoFirstScan(CancellationToken token)
    {
        _scanResults.Clear();

        if (_processHandle == IntPtr.Zero) return;

        var regions = GetReadableMemoryRegions();
        int scannedRegions = 0;
        int maxRegions = 50; // FIXED: Limit regions

        foreach (var region in regions.Take(maxRegions))
        {
            if (token.IsCancellationRequested) break;

            try
            {
                int bufferSize = (int)Math.Min(region.Size, 5_000_000);
                byte[] buffer = new byte[bufferSize];

                if (ReadProcessMemory(_processHandle, region.BaseAddress, buffer, buffer.Length, out int read))
                {
                    switch (_selectedScanType)
                    {
                        case 0: ScanExactValue(buffer, region.BaseAddress, _scanValue); break;
                        case 1: ScanPattern(buffer, region.BaseAddress, _scanPattern); break;
                        case 2: ScanString(buffer, region.BaseAddress, _scanValue); break;
                        case 3: ScanFloatRange(buffer, region.BaseAddress, _scanValue); break;
                    }
                }
                scannedRegions++;

                // FIXED: Yield periodically
                if (scannedRegions % 10 == 0)
                {
                    Thread.Sleep(1);
                }
            }
            catch { }
        }

        _filteredResults = new List<MemoryResult>(_scanResults);
        _state.AddInGameLog($"[MEMORY] Scanned {scannedRegions} regions, found {_scanResults.Count} results");
    }

    private void PerformNextScan()
    {
        if (_scanResults.Count == 0) return;

        var newResults = new List<MemoryResult>();

        foreach (var result in _scanResults)
        {
            var currentValue = ReadMemoryValue(result.Address, result.Type);
            if (MatchesScan(currentValue, _scanValue))
            {
                var updatedResult = result;
                updatedResult.ValuePreview = currentValue;
                newResults.Add(updatedResult);
            }
        }

        _scanResults = newResults;
        _filteredResults = new List<MemoryResult>(_scanResults);
        _state.AddInGameLog($"[MEMORY] Filtered to {_scanResults.Count} results");
    }

    private void ApplyFilter()
    {
        if (string.IsNullOrEmpty(_resultFilter))
        {
            _filteredResults = new List<MemoryResult>(_scanResults);
            return;
        }

        _filteredResults = _scanResults.Where(r =>
            r.ValuePreview.Contains(_resultFilter, StringComparison.OrdinalIgnoreCase) ||
            ((ulong)r.Address).ToString("X").Contains(_resultFilter, StringComparison.OrdinalIgnoreCase)
        ).ToList();
    }

    private void ScanExactValue(byte[] buffer, IntPtr baseAddr, string value)
    {
        if (int.TryParse(value, out int intVal))
        {
            byte[] searchBytes = BitConverter.GetBytes(intVal);
            for (int i = 0; i < buffer.Length - 4; i += 4)
            {
                if (buffer[i] == searchBytes[0] && buffer[i + 1] == searchBytes[1] &&
                    buffer[i + 2] == searchBytes[2] && buffer[i + 3] == searchBytes[3])
                {
                    _scanResults.Add(new MemoryResult
                    {
                        Address = baseAddr + i,
                        Type = ScanValueType.Int32,
                        ValuePreview = intVal.ToString()
                    });
                }
            }
        }

        if (float.TryParse(value, out float floatVal))
        {
            byte[] searchBytes = BitConverter.GetBytes(floatVal);
            for (int i = 0; i < buffer.Length - 4; i++)
            {
                if (buffer[i] == searchBytes[0] && buffer[i + 1] == searchBytes[1] &&
                    buffer[i + 2] == searchBytes[2] && buffer[i + 3] == searchBytes[3])
                {
                    _scanResults.Add(new MemoryResult
                    {
                        Address = baseAddr + i,
                        Type = ScanValueType.Float,
                        ValuePreview = floatVal.ToString("F4")
                    });
                }
            }
        }
    }

    private void ScanPattern(byte[] buffer, IntPtr baseAddr, string pattern)
    {
        var patternBytes = new List<byte?>();
        foreach (var part in pattern.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if (part == "??" || part == "?")
                patternBytes.Add(null);
            else if (byte.TryParse(part, System.Globalization.NumberStyles.HexNumber, null, out byte b))
                patternBytes.Add(b);
        }

        if (patternBytes.Count == 0) return;

        for (int i = 0; i < buffer.Length - patternBytes.Count; i++)
        {
            bool match = true;
            for (int j = 0; j < patternBytes.Count; j++)
            {
                if (patternBytes[j].HasValue && buffer[i + j] != patternBytes[j].Value)
                {
                    match = false;
                    break;
                }
            }

            if (match)
            {
                _scanResults.Add(new MemoryResult
                {
                    Address = baseAddr + i,
                    Type = ScanValueType.Bytes,
                    ValuePreview = $"Pattern +{i:X}"
                });
            }
        }
    }

    private void ScanString(byte[] buffer, IntPtr baseAddr, string str)
    {
        var strBytes = Encoding.UTF8.GetBytes(str);

        for (int i = 0; i < buffer.Length - strBytes.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < strBytes.Length; j++)
            {
                if (buffer[i + j] != strBytes[j])
                {
                    match = false;
                    break;
                }
            }

            if (match)
            {
                _scanResults.Add(new MemoryResult
                {
                    Address = baseAddr + i,
                    Type = ScanValueType.String,
                    ValuePreview = $"\"{str}\""
                });
            }
        }
    }

    private void ScanFloatRange(byte[] buffer, IntPtr baseAddr, string range)
    {
        var parts = range.Split('-');
        if (parts.Length != 2) return;

        if (!float.TryParse(parts[0], out float min)) return;
        if (!float.TryParse(parts[1], out float max)) return;

        for (int i = 0; i < buffer.Length - 4; i += 4)
        {
            float val = BitConverter.ToSingle(buffer, i);
            if (val >= min && val <= max && !float.IsNaN(val) && !float.IsInfinity(val))
            {
                _scanResults.Add(new MemoryResult
                {
                    Address = baseAddr + i,
                    Type = ScanValueType.Float,
                    ValuePreview = val.ToString("F4")
                });
            }
        }
    }

    // FIXED: Quick scan with timeout and background execution
    private async void QuickScanPlayer()
    {
        if (!_isAttached) return;

        _scanCts = new CancellationTokenSource();
        var token = _scanCts.Token;

        _state.AddInGameLog("[MEMORY] Quick scanning for player health (value: 100)...");

        try
        {
            await Task.Run(() => DoQuickScan(token), token);
        }
        catch (OperationCanceledException)
        {
            _state.AddInGameLog("[MEMORY] Quick scan cancelled");
        }
        catch (Exception ex)
        {
            _state.AddInGameLog($"[MEMORY] Quick scan error: {ex.Message}");
        }
        finally
        {
            _scanCts = null;
        }
    }

    private void DoQuickScan(CancellationToken token)
    {
        _scanResults.Clear();
        _scanValue = "100";
        _selectedScanType = 0;

        var regions = GetReadableMemoryRegions().Where(r => r.Size < 100_000_000);
        int scanned = 0;

        foreach (var region in regions.Take(30)) // FIXED: Limit to 30 regions
        {
            if (token.IsCancellationRequested) break;

            try
            {
                byte[] buffer = new byte[(int)Math.Min(region.Size, 1_000_000)];
                if (ReadProcessMemory(_processHandle, region.BaseAddress, buffer, buffer.Length, out int read))
                {
                    ScanExactValue(buffer, region.BaseAddress, "100");
                }
                scanned++;

                // FIXED: Yield every 5 regions
                if (scanned % 5 == 0)
                {
                    Thread.Sleep(1);
                }
            }
            catch { }
        }

        _filteredResults = new List<MemoryResult>(_scanResults);
        _state.AddInGameLog($"[MEMORY] Quick scan complete: {scanned} regions, {_scanResults.Count} results for value '100'");
    }

    // NEW: Scan for TLS 1.3 keys automatically
    private async void ScanForTLSKeys()
    {
        if (!_isAttached) return;

        _scanCts = new CancellationTokenSource();
        var token = _scanCts.Token;

        _state.AddInGameLog("[MEMORY] Scanning for TLS 1.3 secrets...");

        try
        {
            await Task.Run(() => DoTLSScan(token), token);
        }
        catch (OperationCanceledException)
        {
            _state.AddInGameLog("[MEMORY] TLS scan cancelled");
        }
        catch (Exception ex)
        {
            _state.AddInGameLog($"[MEMORY] TLS scan error: {ex.Message}");
        }
        finally
        {
            _scanCts = null;
        }
    }

    private void DoTLSScan(CancellationToken token)
    {
        int keysFound = 0;
        var regions = GetReadableMemoryRegions().Where(r => r.Size < 50_000_000);

        foreach (var region in regions.Take(20))
        {
            if (token.IsCancellationRequested) break;

            try
            {
                byte[] buffer = new byte[(int)Math.Min(region.Size, 2_000_000)];
                if (!ReadProcessMemory(_processHandle, region.BaseAddress, buffer, buffer.Length, out int read))
                    continue;

                // Look for high-entropy 32-byte sequences (TLS 1.3 secrets)
                for (int i = 0; i < buffer.Length - 32; i += 16)
                {
                    double entropy = CalculateEntropy(buffer, i, 32);

                    // TLS secrets have high entropy (>7.5) and specific patterns
                    if (entropy > 7.8 && entropy < 7.99)
                    {
                        // Check if surrounded by lower entropy (isolated high entropy = likely key)
                        double before = CalculateEntropy(buffer, Math.Max(0, i - 32), 32);
                        double after = CalculateEntropy(buffer, Math.Min(buffer.Length - 32, i + 64), 32);

                        if (before < 6 && after < 6)
                        {
                            var keyBytes = new byte[32];
                            Array.Copy(buffer, i, keyBytes, 0, 32);

                            // Auto-add as decryption key
                            PacketDecryptor.AddKey(new PacketDecryptor.EncryptionKey
                            {
                                Key = keyBytes,
                                IV = new byte[12],
                                Type = PacketDecryptor.EncryptionType.AES256GCM,
                                Source = "Memory Scan (TLS)",
                                MemoryAddress = region.BaseAddress + i
                            });

                            keysFound++;

                            // Only add first 5 keys to avoid duplicates
                            if (keysFound >= 5) break;
                        }
                    }
                }

                if (keysFound >= 5) break;
            }
            catch { }
        }

        _state.AddInGameLog($"[AUTO-DECRYPT] Found {keysFound} potential TLS keys and added to decryption!");
    }

    private void UseAsDecryptionKey(MemoryResult result)
    {
        var bytes = ReadMemoryBytes(result.Address, 32);
        if (bytes == null) return;

        PacketDecryptor.AddKey(new PacketDecryptor.EncryptionKey
        {
            Key = bytes,
            IV = new byte[12],
            Type = PacketDecryptor.EncryptionType.AES256GCM,
            Source = $"Manual: 0x{(ulong)result.Address:X}",
            MemoryAddress = result.Address
        });

        _state.AddInGameLog($"[AUTO-DECRYPT] Added 32 bytes from 0x{(ulong)result.Address:X} as decryption key");
    }

    private void FindPointersTo(IntPtr target)
    {
        _pointerMap[target] = new List<IntPtr>();

        var regions = GetReadableMemoryRegions();
        byte[] targetBytes = BitConverter.GetBytes((long)target);

        foreach (var region in regions.Take(20))
        {
            try
            {
                byte[] buffer = new byte[(int)Math.Min(region.Size, 5_000_000)];
                if (ReadProcessMemory(_processHandle, region.BaseAddress, buffer, buffer.Length, out int read))
                {
                    for (int i = 0; i < buffer.Length - 8; i += 8)
                    {
                        long val = BitConverter.ToInt64(buffer, i);
                        if ((IntPtr)val == target)
                        {
                            _pointerMap[target].Add(region.BaseAddress + i);
                        }
                    }
                }
            }
            catch { }
        }

        _state.AddInGameLog($"[MEMORY] Found {_pointerMap[target].Count} pointers to 0x{(ulong)target:X}");
    }

    private List<MemoryRegion> GetReadableMemoryRegions()
    {
        var regions = new List<MemoryRegion>();
        IntPtr addr = IntPtr.Zero;
        MEMORY_BASIC_INFORMATION mbi;

        while (VirtualQueryEx(_processHandle, addr, out mbi, (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>()) != IntPtr.Zero)
        {
            if (mbi.State == 0x1000 && (mbi.Protect & 0x04) != 0)
            {
                regions.Add(new MemoryRegion
                {
                    BaseAddress = mbi.BaseAddress,
                    Size = (long)mbi.RegionSize
                });
            }

            addr = mbi.BaseAddress + (int)mbi.RegionSize;
        }

        return regions;
    }

    private byte[]? ReadMemoryBytes(IntPtr address, int size)
    {
        byte[] buffer = new byte[size];
        if (ReadProcessMemory(_processHandle, address, buffer, size, out int read))
            return buffer;
        return null;
    }

    private string ReadMemoryValue(IntPtr address, ScanValueType type)
    {
        var bytes = ReadMemoryBytes(address, 16);
        if (bytes == null) return "???";

        try
        {
            return type switch
            {
                ScanValueType.Int32 => BitConverter.ToInt32(bytes, 0).ToString(),
                ScanValueType.Float => BitConverter.ToSingle(bytes, 0).ToString("F4"),
                ScanValueType.Int64 => BitConverter.ToInt64(bytes, 0).ToString(),
                ScanValueType.Double => BitConverter.ToDouble(bytes, 0).ToString("F6"),
                ScanValueType.String => Encoding.UTF8.GetString(bytes.TakeWhile(b => b != 0).ToArray()),
                _ => BitConverter.ToString(bytes.Take(8).ToArray())
            };
        }
        catch
        {
            return "err";
        }
    }

    private void WriteMemoryValue(IntPtr address, string value)
    {
        byte[]? bytes = null;

        if (int.TryParse(value, out int intVal))
            bytes = BitConverter.GetBytes(intVal);
        else if (float.TryParse(value, out float floatVal))
            bytes = BitConverter.GetBytes(floatVal);
        else if (long.TryParse(value, out long longVal))
            bytes = BitConverter.GetBytes(longVal);

        if (bytes != null)
        {
            WriteProcessMemory(_processHandle, address, bytes, bytes.Length, out int written);
            _state.AddInGameLog($"[MEMORY] Wrote {bytes.Length} bytes to 0x{(ulong)address:X}");
        }
    }

    private void AddToWatch(MemoryResult result)
    {
        if (!_watches.Any(w => w.Address == result.Address))
        {
            _watches.Add(new WatchEntry
            {
                Address = result.Address,
                Type = result.Type,
                Name = result.ValuePreview.Length > 15 ? result.ValuePreview[..15] + "..." : result.ValuePreview,
                LastValue = result.ValuePreview
            });
        }
    }

    private void RefreshWatches()
    {
        var updatedWatches = new List<WatchEntry>();
        foreach (var watch in _watches)
        {
            var currentValue = ReadMemoryValue(watch.Address, watch.Type);
            updatedWatches.Add(new WatchEntry
            {
                Address = watch.Address,
                Type = watch.Type,
                Name = watch.Name,
                LastValue = currentValue
            });
        }
        _watches = updatedWatches;
    }

    private double CalculateEntropy(byte[] data, int offset, int length)
    {
        var freq = new int[256];
        for (int i = 0; i < length && offset + i < data.Length; i++)
            freq[data[offset + i]]++;

        double entropy = 0;
        for (int i = 0; i < 256; i++)
        {
            if (freq[i] == 0) continue;
            double p = (double)freq[i] / length;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    private bool MatchesScan(string current, string scanValue)
    {
        return current.Contains(scanValue) || current == scanValue;
    }

    private void AttachToProcess()
    {
        try
        {
            var processes = Process.GetProcessesByName(_processName);
            if (processes.Length == 0)
            {
                processes = Process.GetProcesses()
                    .Where(p => p.ProcessName.ToLower().Contains("hytale"))
                    .ToArray();
            }

            if (processes.Length > 0)
            {
                _hytaleProcess = processes[0];
                _processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, false, _hytaleProcess.Id);

                if (_processHandle != IntPtr.Zero)
                {
                    _isAttached = true;
                    _state.AddInGameLog($"[MEMORY] Attached to {_hytaleProcess.ProcessName} (PID: {_hytaleProcess.Id})");

                    // Auto-scan for TLS keys on attach
                    ScanForTLSKeys();
                }
                else
                {
                    _state.AddInGameLog($"[MEMORY] Failed to open process. Run as Administrator!");
                }
            }
            else
            {
                _state.AddInGameLog($"[MEMORY] Process '{_processName}' not found");
            }
        }
        catch (Exception ex)
        {
            _state.AddInGameLog($"[MEMORY] Error: {ex.Message}");
        }
    }

    private void Detach()
    {
        if (_processHandle != IntPtr.Zero)
            CloseHandle(_processHandle);

        _hytaleProcess = null;
        _processHandle = IntPtr.Zero;
        _isAttached = false;
        _scanResults.Clear();
        _watches.Clear();
        _pointerMap.Clear();
        _scanCts?.Cancel();
        _scanCts = null;
    }

    private void CopyToClipboard(string text)
    {
        try { TextCopy.ClipboardService.SetText(text); } catch { }
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

    private struct MemoryRegion
    {
        public IntPtr BaseAddress;
        public long Size;
    }

    private struct MemoryResult
    {
        public IntPtr Address;
        public ScanValueType Type;
        public string ValuePreview;
    }

    private class WatchEntry
    {
        public IntPtr Address;
        public ScanValueType Type;
        public string Name = "";
        public string LastValue = "";
    }

    private enum ScanValueType
    {
        Int32, Float, Int64, Double, String, Bytes
    }
}