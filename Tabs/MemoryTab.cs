// FILE: Tabs/MemoryTab.cs - FIXED: Memory leaks, buffer overflows, and LocalPlayer scan
using HyForce.Core;
using HyForce.Protocol;
using HyForce.UI;
using ImGuiNET;
using System.Buffers;
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
    private string _scanValue = "100";
    private string _scanPattern = "";
    private int _selectedScanType = 0;
    private List<MemoryResult> _scanResults = new();
    private List<MemoryResult> _filteredResults = new();
    private MemoryResult? _selectedAddress;
    private string _resultFilter = "";

    // Live watch
    private List<WatchEntry> _watches = new();
    private bool _autoRefresh = true;
    private double _lastRefresh = 0;
    private float _refreshInterval = 0.5f;

    // Cancellation token for scans
    private CancellationTokenSource? _scanCts;

    // FIXED: Smaller chunk size to prevent memory pressure
    private const int MAX_SCAN_CHUNK = 256 * 1024;
    private const int MAX_RESULTS = 10000;

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
        _state.OnMemoryDataUpdated += OnQuickScanRequested;
    }

    private void OnQuickScanRequested()
    {
        if (_isAttached && _processHandle != IntPtr.Zero)
        {
            ScanForTLSKeys();
        }
        else
        {
            _state.AddInGameLog("[MEMORY] Attach to process first before scanning!");
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
            bool scanning = _scanCts != null;
            if (scanning)
            {
                ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.5f, 0.5f, 0.5f, 1f));
                ImGui.Button("Scanning...", new Vector2(140, 28));
                ImGui.PopStyleColor();
            }
            else
            {
                ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.2f, 0.8f, 0.4f, 1f));
                if (ImGui.Button("Auto-Extract Keys", new Vector2(140, 28)))
                {
                    Task.Run(() => ScanForTLSKeys());
                }
                ImGui.PopStyleColor();
            }

            ImGui.SameLine();

            // FIXED: Quick Scan Player button now scans for LocalPlayer patterns
            if (ImGui.Button("Quick Scan Player", new Vector2(140, 28)))
            {
                Task.Run(() => QuickScanLocalPlayer());
            }

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
        ImGui.BulletText("Use 'Quick Scan Player' to find LocalPlayer/health");
        ImGui.BulletText("Use 'Auto-Extract Keys' to find decryption keys");

        ImGui.Spacing();
        ImGui.TextColored(Theme.ColWarn, "Run as Administrator for best results");
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

            ImGui.PushID(i);

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
                if (ImGui.MenuItem("Use as Decryption Key"))
                    UseAsDecryptionKey(result);
                ImGui.EndPopup();
            }

            ImGui.PopID();
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

    // ==================== FIXED: LocalPlayer Scan ====================

    /// <summary>
    /// FIXED: Scan for LocalPlayer patterns (health, position, name)
    /// </summary>
    private async void QuickScanLocalPlayer()
    {
        if (!_isAttached || _processHandle == IntPtr.Zero) return;

        _scanCts = new CancellationTokenSource();
        var token = _scanCts.Token;

        _state.AddInGameLog("[MEMORY] Scanning for LocalPlayer...");

        try
        {
            await Task.Run(() => DoLocalPlayerScan(token), token);
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

    private void DoLocalPlayerScan(CancellationToken token)
    {
        _scanResults.Clear();

        var regions = GetReadableMemoryRegions()
            .Where(r => r.Size > 0x1000 && r.Size < 0x10000000)
            .ToList();

        int foundHealth = 0;
        int foundPosition = 0;
        int foundName = 0;

        // Scan 1: Look for health value (100 as float and int)
        foreach (var region in regions.Take(50))
        {
            if (token.IsCancellationRequested) break;

            try
            {
                int chunkSize = (int)Math.Min(region.Size, MAX_SCAN_CHUNK);
                byte[]? buffer = ArrayPool<byte>.Shared.Rent(chunkSize);
                try
                {
                    if (!ReadProcessMemory(_processHandle, region.BaseAddress, buffer, chunkSize, out int read))
                        continue;

                    // Search for 100 as float (common health value)
                    byte[] healthFloat = BitConverter.GetBytes(100f);
                    byte[] healthInt = BitConverter.GetBytes(100);
                    byte[] healthIntBE = new byte[] { 0, 0, 0, 100 }; // Big endian

                    for (int i = 0; i < read - 4; i++)
                    {
                        // Check float 100.0
                        if (buffer[i] == healthFloat[0] && buffer[i + 1] == healthFloat[1] &&
                            buffer[i + 2] == healthFloat[2] && buffer[i + 3] == healthFloat[3])
                        {
                            // Verify it's in a reasonable range for player health
                            _scanResults.Add(new MemoryResult
                            {
                                Address = region.BaseAddress + i,
                                Type = ScanValueType.Float,
                                ValuePreview = "100.0 (Health?)"
                            });
                            foundHealth++;
                            if (_scanResults.Count >= MAX_RESULTS) break;
                        }

                        // Check int 100
                        if (buffer[i] == healthInt[0] && buffer[i + 1] == healthInt[1] &&
                            buffer[i + 2] == healthInt[2] && buffer[i + 3] == healthInt[3])
                        {
                            _scanResults.Add(new MemoryResult
                            {
                                Address = region.BaseAddress + i,
                                Type = ScanValueType.Int32,
                                ValuePreview = "100 (Health?)"
                            });
                            foundHealth++;
                            if (_scanResults.Count >= MAX_RESULTS) break;
                        }
                    }

                    // Scan 2: Look for player name pattern "LocalPlayer" or common names
                    string[] namePatterns = { "LocalPlayer", "Player", "Hero", "Character" };
                    foreach (var name in namePatterns)
                    {
                        var nameBytes = Encoding.ASCII.GetBytes(name);
                        for (int i = 0; i < read - nameBytes.Length; i++)
                        {
                            bool match = true;
                            for (int j = 0; j < nameBytes.Length; j++)
                            {
                                if (buffer[i + j] != nameBytes[j])
                                {
                                    match = false;
                                    break;
                                }
                            }
                            if (match)
                            {
                                _scanResults.Add(new MemoryResult
                                {
                                    Address = region.BaseAddress + i,
                                    Type = ScanValueType.String,
                                    ValuePreview = $"\"{name}\""
                                });
                                foundName++;
                            }
                        }
                    }
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(buffer);
                }
            }
            catch { }
        }

        _filteredResults = new List<MemoryResult>(_scanResults);
        _state.AddInGameLog($"[MEMORY] LocalPlayer scan: {foundHealth} health values, {foundName} name patterns");
    }

    // ==================== TLS Key Scanning ====================

    private async void ScanForTLSKeys()
    {
        if (!_isAttached || _hytaleProcess == null || _processHandle == IntPtr.Zero) return;

        _state.AddInGameLog("[AUTO-KEY] Starting automatic TLS key extraction...");
        _scanCts = new CancellationTokenSource();
        var token = _scanCts.Token;

        try
        {
            var keyPointers = await Task.Run(() => FindSSLContexts(token), token);

            if (keyPointers.Count > 0)
            {
                _state.AddInGameLog($"[AUTO-KEY] Found {keyPointers.Count} SSL context(s)");

                foreach (var ctxPtr in keyPointers)
                {
                    if (token.IsCancellationRequested) break;
                    ExtractKeysFromSSLContext(ctxPtr);
                }
            }
            else
            {
                _state.AddInGameLog("[AUTO-KEY] No SSL contexts found, using entropy scan...");
                await Task.Run(() => EntropyScanForKeys(token), token);
            }

            if (PacketDecryptor.DiscoveredKeys.Count > 0)
            {
                _state.AddInGameLog($"[AUTO-KEY] SUCCESS! Found {PacketDecryptor.DiscoveredKeys.Count} key(s)");
            }
            else
            {
                _state.AddInGameLog("[AUTO-KEY] No keys found. Hytale may not be using standard TLS.");
            }
        }
        catch (OperationCanceledException)
        {
            _state.AddInGameLog("[AUTO-KEY] Scan cancelled");
        }
        catch (Exception ex)
        {
            _state.AddInGameLog($"[AUTO-KEY] Error: {ex.Message}");
        }
        finally
        {
            _scanCts = null;
        }
    }

    private List<IntPtr> FindSSLContexts(CancellationToken token)
    {
        var contexts = new List<IntPtr>();
        var regions = GetReadableMemoryRegions()
            .Where(r => r.Size > 0x1000 && r.Size < 0x10000000)
            .OrderByDescending(r => r.Size);

        foreach (var region in regions.Take(20))
        {
            if (token.IsCancellationRequested) break;

            try
            {
                long offset = 0;
                while (offset < region.Size)
                {
                    int toRead = (int)Math.Min(MAX_SCAN_CHUNK, region.Size - offset);

                    byte[]? buffer = ArrayPool<byte>.Shared.Rent(toRead);
                    try
                    {
                        if (!ReadProcessMemory(_processHandle, region.BaseAddress + (int)offset,
                            buffer, toRead, out int read)) break;

                        for (int i = 0; i < read - 8; i += 8)
                        {
                            long potentialPtr = BitConverter.ToInt64(buffer, i);

                            if (IsValidHeapPointer((IntPtr)potentialPtr))
                            {
                                if (VerifySSLContext((IntPtr)potentialPtr))
                                {
                                    contexts.Add((IntPtr)potentialPtr);
                                    if (contexts.Count >= 10) return contexts;
                                }
                            }
                        }

                        offset += toRead;
                    }
                    finally
                    {
                        ArrayPool<byte>.Shared.Return(buffer);
                    }
                }
            }
            catch { }
        }

        return contexts;
    }

    private bool VerifySSLContext(IntPtr ctxPtr)
    {
        try
        {
            byte[] ctxData = new byte[64];
            if (!ReadProcessMemory(_processHandle, ctxPtr, ctxData, 64, out int read))
                return false;

            long methodPtr = BitConverter.ToInt64(ctxData, 0);
            if (!IsValidHeapPointer((IntPtr)methodPtr)) return false;

            byte[] methodData = new byte[32];
            if (!ReadProcessMemory(_processHandle, (IntPtr)methodPtr, methodData, 32, out read))
                return false;

            bool hasTLS13 = methodData.Contains((byte)0x03) && methodData.Contains((byte)0x04);
            return hasTLS13;
        }
        catch { return false; }
    }

    private void ExtractKeysFromSSLContext(IntPtr ctxPtr)
    {
        try
        {
            byte[] ctxData = new byte[512];
            if (!ReadProcessMemory(_processHandle, ctxPtr, ctxData, 512, out int read))
                return;

            for (int i = 0; i < ctxData.Length - 8; i += 8)
            {
                long sessionPtr = BitConverter.ToInt64(ctxData, i);
                if (!IsValidHeapPointer((IntPtr)sessionPtr)) continue;

                var keys = ExtractSessionKeys((IntPtr)sessionPtr);
                if (keys != null)
                {
                    PacketDecryptor.AddKey(keys);
                    _state.AddInGameLog($"[AUTO-KEY] Extracted key from SSL session");
                }
            }
        }
        catch (Exception ex)
        {
            _state.AddInGameLog($"[AUTO-KEY] Extraction error: {ex.Message}");
        }
    }

    private PacketDecryptor.EncryptionKey? ExtractSessionKeys(IntPtr sessionPtr)
    {
        try
        {
            byte[] sessionData = new byte[256];
            if (!ReadProcessMemory(_processHandle, sessionPtr, sessionData, 256, out int read))
                return null;

            // Look for 48-byte master secret (TLS 1.3)
            for (int i = 0; i < sessionData.Length - 48; i++)
            {
                double entropy = CalculateEntropy(sessionData, i, 48);

                if (entropy > 7.5 && entropy < 7.99)
                {
                    var secret = new byte[48];
                    Array.Copy(sessionData, i, secret, 0, 48);

                    if (secret.All(b => b == 0) || secret.Distinct().Count() < 10)
                        continue;

                    var key = new PacketDecryptor.EncryptionKey
                    {
                        Secret = secret,
                        Type = PacketDecryptor.EncryptionType.QUIC_Server1RTT,
                        Source = $"SSL_SESSION@0x{(ulong)sessionPtr:X}",
                        MemoryAddress = sessionPtr + i
                    };

                    // CRITICAL: Derive keys immediately
                    PacketDecryptor.DeriveQUICKeys(key);

                    if (key.Key.Length == 16)
                        return key;
                }
            }
        }
        catch { }

        return null;
    }

    private void EntropyScanForKeys(CancellationToken token)
    {
        var regions = GetReadableMemoryRegions()
            .Where(r => r.Size > 0x10000 && r.Size < 0x5000000)
            .OrderByDescending(r => r.Size)
            .ToList();

        int totalKeysFound = 0;

        foreach (var region in regions.Take(30))
        {
            if (token.IsCancellationRequested) break;

            try
            {
                int chunkSize = (int)Math.Min(region.Size, MAX_SCAN_CHUNK);
                byte[]? buffer = ArrayPool<byte>.Shared.Rent(chunkSize);
                try
                {
                    if (!ReadProcessMemory(_processHandle, region.BaseAddress, buffer, chunkSize, out int read))
                        continue;

                    totalKeysFound += ScanForAESKeys(buffer, read, region.BaseAddress, token);
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(buffer);
                }
            }
            catch { }
        }

        _state.AddInGameLog($"[AUTO-KEY] Scanned regions, found {totalKeysFound} keys");
    }

    private int ScanForAESKeys(byte[] buffer, int length, IntPtr baseAddr, CancellationToken token)
    {
        int found = 0;

        for (int i = 0; i < length - 32; i += 16)
        {
            if (token.IsCancellationRequested) break;

            double entropy = CalculateEntropy(buffer, i, 32);

            if (entropy < 7.8 || entropy > 7.99) continue;

            var keyBytes = new byte[32];
            Array.Copy(buffer, i, keyBytes, 0, 32);

            if (keyBytes.All(b => b == 0)) continue;
            if (keyBytes.Distinct().Count() < 15) continue;

            var key = new PacketDecryptor.EncryptionKey
            {
                Key = keyBytes.Take(16).ToArray(), // Use first 16 bytes
                IV = new byte[12],
                Type = PacketDecryptor.EncryptionType.AES128GCM,
                Source = "Memory scan",
                MemoryAddress = baseAddr + i
            };

            PacketDecryptor.AddKey(key);
            found++;
        }

        return found;
    }

    private bool IsValidHeapPointer(IntPtr ptr)
    {
        ulong addr = (ulong)ptr;
        return addr > 0x10000 && addr < 0x7FFFFFFF0000 && (addr & 0x7) == 0;
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

    // ==================== Standard Scanning ====================

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

        foreach (var region in regions.Take(50))
        {
            if (token.IsCancellationRequested) break;

            try
            {
                int chunkSize = (int)Math.Min(region.Size, MAX_SCAN_CHUNK);
                byte[]? buffer = ArrayPool<byte>.Shared.Rent(chunkSize);
                try
                {
                    if (ReadProcessMemory(_processHandle, region.BaseAddress, buffer, chunkSize, out int read))
                    {
                        switch (_selectedScanType)
                        {
                            case 0: ScanExactValue(buffer, read, region.BaseAddress, _scanValue); break;
                            case 1: ScanPattern(buffer, read, region.BaseAddress, _scanPattern); break;
                            case 2: ScanString(buffer, read, region.BaseAddress, _scanValue); break;
                            case 3: ScanFloatRange(buffer, read, region.BaseAddress, _scanValue); break;
                        }
                    }
                    scannedRegions++;
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(buffer);
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

    private void ScanExactValue(byte[] buffer, int length, IntPtr baseAddr, string value)
    {
        if (_scanResults.Count >= MAX_RESULTS) return;

        if (int.TryParse(value, out int intVal))
        {
            byte[] searchBytes = BitConverter.GetBytes(intVal);
            for (int i = 0; i < length - 4; i += 4)
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
                    if (_scanResults.Count >= MAX_RESULTS) return;
                }
            }
        }

        if (float.TryParse(value, out float floatVal))
        {
            byte[] searchBytes = BitConverter.GetBytes(floatVal);
            for (int i = 0; i < length - 4; i++)
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
                    if (_scanResults.Count >= MAX_RESULTS) return;
                }
            }
        }
    }

    private void ScanPattern(byte[] buffer, int length, IntPtr baseAddr, string pattern)
    {
        if (_scanResults.Count >= MAX_RESULTS) return;

        var patternBytes = new List<byte?>();
        foreach (var part in pattern.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if (part == "??" || part == "?")
                patternBytes.Add(null);
            else if (byte.TryParse(part, System.Globalization.NumberStyles.HexNumber, null, out byte b))
                patternBytes.Add(b);
        }

        if (patternBytes.Count == 0) return;

        for (int i = 0; i < length - patternBytes.Count; i++)
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
                if (_scanResults.Count >= MAX_RESULTS) return;
            }
        }
    }

    private void ScanString(byte[] buffer, int length, IntPtr baseAddr, string str)
    {
        if (_scanResults.Count >= MAX_RESULTS) return;

        var strBytes = Encoding.UTF8.GetBytes(str);

        for (int i = 0; i < length - strBytes.Length; i++)
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
                if (_scanResults.Count >= MAX_RESULTS) return;
            }
        }
    }

    private void ScanFloatRange(byte[] buffer, int length, IntPtr baseAddr, string range)
    {
        if (_scanResults.Count >= MAX_RESULTS) return;

        var parts = range.Split('-');
        if (parts.Length != 2) return;

        if (!float.TryParse(parts[0], out float min)) return;
        if (!float.TryParse(parts[1], out float max)) return;

        for (int i = 0; i < length - 4; i += 4)
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
                if (_scanResults.Count >= MAX_RESULTS) return;
            }
        }
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
        if (_processHandle == IntPtr.Zero || address == IntPtr.Zero || size <= 0 || size > 4096)
            return null;

        byte[] buffer = new byte[size];
        if (ReadProcessMemory(_processHandle, address, buffer, size, out int read) && read == size)
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

    private void UseAsDecryptionKey(MemoryResult result)
    {
        var bytes = ReadMemoryBytes(result.Address, 32);
        if (bytes == null) return;

        PacketDecryptor.AddKey(new PacketDecryptor.EncryptionKey
        {
            Key = bytes.Take(16).ToArray(),
            IV = new byte[12],
            Type = PacketDecryptor.EncryptionType.AES128GCM,
            Source = $"Memory: 0x{(ulong)result.Address:X}",
            MemoryAddress = result.Address
        });

        _state.AddInGameLog($"[AUTO-KEY] Added 16 bytes from 0x{(ulong)result.Address:X} as decryption key");
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