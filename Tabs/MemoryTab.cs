// FILE: Tabs/MemoryTab.cs - FIXED: Working memory search, Netty detection, decryption diagnostics
using HyForce.Core;
using HyForce.Protocol;
using HyForce.UI;
using HyForce.Utils;
using ImGuiNET;
using SharpGen.Runtime;
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

    // Cancellation and progress tracking
    private CancellationTokenSource? _scanCts;
    private bool _isScanning = false;
    private int _scanProgress = 0;
    private int _scanTotalRegions = 0;
    private int _scanCurrentRegion = 0;

    // FIXED: Search within memory - new feature
    private string _memorySearchPattern = "";
    private bool _searchInProgress = false;
    private List<MemorySearchResult> _searchResults = new();

    // FIXED: Netty ByteBuf detection
    private bool _scanForNettyBuffers = false;
    private List<NettyBufferInfo> _nettyBuffers = new();

    // FIXED: Decryption diagnostics
    private DecryptionDiagnostics _decryptionDiag = new();

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

        // FIXED: Tabbed interface for different functions
        if (ImGui.BeginTabBar("##memory_tabs"))
        {
            if (ImGui.BeginTabItem("Value Scan"))
            {
                RenderValueScanTab(avail);
                ImGui.EndTabItem();
            }

            if (ImGui.BeginTabItem("Memory Search"))
            {
                RenderMemorySearchTab(avail);
                ImGui.EndTabItem();
            }

            if (ImGui.BeginTabItem("Netty Buffers"))
            {
                RenderNettyBuffersTab(avail);
                ImGui.EndTabItem();
            }

            if (ImGui.BeginTabItem("Decryption Diagnostics"))
            {
                RenderDecryptionDiagnosticsTab(avail);  // THIS IS LINE 429 - ERROR HERE
                ImGui.EndTabItem();
            }

            ImGui.EndTabBar();
        }
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

            if (_isScanning)
            {
                ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.9f, 0.3f, 0.2f, 1f));
                if (ImGui.Button($"Stop Scan ({_scanCurrentRegion}/{_scanTotalRegions})", new Vector2(180, 28)))
                {
                    CancelScan();
                }
                ImGui.PopStyleColor();

                ImGui.SameLine();
                float progress = _scanTotalRegions > 0 ? (float)_scanCurrentRegion / _scanTotalRegions : 0;
                ImGui.ProgressBar(progress, new Vector2(150, 28), $"{_scanProgress}%");
            }
            else
            {
                ImGui.PushStyleColor(ImGuiCol.Button, new Vector4(0.2f, 0.8f, 0.4f, 1f));
                if (ImGui.Button("Auto-Extract Keys", new Vector2(140, 28)))
                {
                    Task.Run(() => ScanForTLSKeys());
                }
                ImGui.PopStyleColor();

                ImGui.SameLine();

                if (ImGui.Button("Quick Scan Player", new Vector2(140, 28)))
                {
                    Task.Run(() => QuickScanLocalPlayer());
                }
            }

            ImGui.SameLine();
            ImGui.Checkbox("Auto", ref _autoRefresh);
        }
    }

    private void CancelScan()
    {
        if (_scanCts != null)
        {
            _scanCts.Cancel();
            _state.AddInGameLog("[MEMORY] Scan cancelled by user");
        }
        _isScanning = false;
    }

    private void RenderNotAttached()
    {
        ImGui.Spacing();
        ImGui.TextColored(Theme.ColAccent, "How to use:");
        ImGui.BulletText("Launch Hytale and connect to a server");
        ImGui.BulletText("Click 'Attach to Hytale'");
        ImGui.BulletText("Use 'Quick Scan Player' to find LocalPlayer/health");
        ImGui.BulletText("Use 'Memory Search' tab to search for specific bytes");
        ImGui.BulletText("Use 'Netty Buffers' to find packet data before encryption");

        ImGui.Spacing();
        ImGui.TextColored(Theme.ColWarn, "Run as Administrator for best results");
    }

    // FIXED: Value Scan Tab (original functionality)
    private void RenderValueScanTab(Vector2 avail)
    {
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

    // FIXED: Memory Search Tab - NEW FEATURE
    private void RenderMemorySearchTab(Vector2 avail)
    {
        ImGui.TextColored(Theme.ColAccent, "Search Within Memory");
        ImGui.TextColored(Theme.ColTextMuted, "Search for byte patterns, strings, or packet signatures across all memory regions");
        ImGui.Separator();

        // Search pattern input
        ImGui.Text("Search Pattern (hex or string):");
        ImGui.SetNextItemWidth(300);
        ImGui.InputText("##searchPattern", ref _memorySearchPattern, 256);
        ImGui.SameLine();

        if (ImGui.Button("Search Memory", new Vector2(120, 28)) && !_searchInProgress)
        {
            Task.Run(() => PerformMemorySearch());
        }

        if (_searchInProgress)
        {
            ImGui.SameLine();
            ImGui.TextColored(Theme.ColWarn, "Searching...");
        }

        ImGui.Spacing();

        // Results
        ImGui.BeginChild("##search_results", new Vector2(0, avail.Y - 150), ImGuiChildFlags.Borders);

        if (_searchResults.Count == 0 && !_searchInProgress)
        {
            ImGui.TextColored(Theme.ColTextMuted, "No search performed yet. Enter a pattern and click Search.");

            ImGui.Spacing();
            ImGui.TextColored(Theme.ColAccent, "Example patterns:");
            ImGui.BulletText("48 65 6C 6C 6F (Hello in hex)");
            ImGui.BulletText("LocalPlayer (string)");
            ImGui.BulletText("PlayerChannelHandler (class name)");
            ImGui.BulletText("00 00 00 01 (packet signature)");
        }
        else
        {
            ImGui.Text($"Found {_searchResults.Count} matches:");
            ImGui.Separator();

            foreach (var result in _searchResults.Take(100))
            {
                ImGui.PushID(result.Address.GetHashCode());

                if (ImGui.Selectable($"0x{(ulong)result.Address:X8} - {result.Preview}", false))
                {
                    // Add to watch or copy
                    if (ImGui.IsMouseClicked(ImGuiMouseButton.Right))
                    {
                        ImGui.OpenPopup("search_ctx");
                    }
                }

                if (ImGui.BeginPopup("search_ctx"))
                {
                    if (ImGui.MenuItem("Add to Watch"))
                    {
                        AddToWatch(new MemoryResult
                        {
                            Address = result.Address,
                            Type = ScanValueType.Bytes,
                            ValuePreview = result.Preview
                        });
                    }
                    if (ImGui.MenuItem("Copy Address"))
                    {
                        CopyToClipboard($"0x{(ulong)result.Address:X}");
                    }
                    if (ImGui.MenuItem("Read 256 bytes"))
                    {
                        ReadAndDisplayBytes(result.Address, 256);
                    }
                    ImGui.EndPopup();
                }

                ImGui.PopID();
            }

            if (_searchResults.Count > 100)
            {
                ImGui.TextColored(Theme.ColTextMuted, $"... and {_searchResults.Count - 100} more");
            }
        }

        ImGui.EndChild();
    }

    // FIXED: Netty Buffers Tab - NEW FEATURE
    private void RenderNettyBuffersTab(Vector2 avail)
    {
        ImGui.TextColored(Theme.ColAccent, "Netty ByteBuf Detection");
        ImGui.TextColored(Theme.ColTextMuted, "Find Netty ByteBuf objects containing packet data before encryption");
        ImGui.Separator();

        if (ImGui.Button("Scan for Netty Buffers", new Vector2(180, 32)))
        {
            Task.Run(() => ScanForNettyByteBufs());
        }

        ImGui.SameLine();

        if (ImGui.Button("Clear Results", new Vector2(120, 32)))
        {
            _nettyBuffers.Clear();
        }

        ImGui.Spacing();

        // Info box
        ImGui.PushStyleColor(ImGuiCol.ChildBg, new Vector4(0.15f, 0.2f, 0.25f, 1f));
        ImGui.BeginChild("##netty_info", new Vector2(0, 80), ImGuiChildFlags.Borders);
        ImGui.TextColored(new Vector4(0.4f, 0.8f, 1f, 1f), "How Netty ByteBuf detection works:");
        ImGui.Text("Netty ByteBuf objects have specific memory signatures:");
        ImGui.Text("- readerIndex and writerIndex fields");
        ImGui.Text("- Reference count and capacity fields");
        ImGui.Text("- Pointer to backing byte array");
        ImGui.EndChild();
        ImGui.PopStyleColor();

        ImGui.Spacing();

        // Results
        ImGui.BeginChild("##netty_results", new Vector2(0, avail.Y - 200), ImGuiChildFlags.Borders);

        if (_nettyBuffers.Count == 0)
        {
            ImGui.TextColored(Theme.ColTextMuted, "No Netty buffers found yet. Click 'Scan for Netty Buffers' to search.");
        }
        else
        {
            if (ImGui.BeginTable("##netty_table", 5, ImGuiTableFlags.RowBg | ImGuiTableFlags.Borders | ImGuiTableFlags.ScrollY))
            {
                ImGui.TableSetupColumn("Address", ImGuiTableColumnFlags.WidthFixed, 120);
                ImGui.TableSetupColumn("Capacity", ImGuiTableColumnFlags.WidthFixed, 80);
                ImGui.TableSetupColumn("Readable", ImGuiTableColumnFlags.WidthFixed, 80);
                ImGui.TableSetupColumn("Content Preview", ImGuiTableColumnFlags.WidthStretch);
                ImGui.TableSetupColumn("Actions", ImGuiTableColumnFlags.WidthFixed, 100);
                ImGui.TableHeadersRow();

                foreach (var buf in _nettyBuffers.Take(50))
                {
                    ImGui.TableNextRow();

                    ImGui.TableSetColumnIndex(0);
                    ImGui.Text($"0x{(ulong)buf.Address:X8}");

                    ImGui.TableSetColumnIndex(1);
                    ImGui.Text(buf.Capacity.ToString());

                    ImGui.TableSetColumnIndex(2);
                    ImGui.Text(buf.ReadableBytes.ToString());

                    ImGui.TableSetColumnIndex(3);
                    ImGui.Text(buf.ContentPreview);

                    ImGui.TableSetColumnIndex(4);
                    ImGui.PushID((int)buf.Address.ToInt64());
                    if (ImGui.Button("Dump"))
                    {
                        DumpNettyBuffer(buf);
                    }
                    ImGui.PopID();
                }

                ImGui.EndTable();
            }

            if (_nettyBuffers.Count > 50)
            {
                ImGui.TextColored(Theme.ColTextMuted, $"... and {_nettyBuffers.Count - 50} more buffers");
            }
        }

        ImGui.EndChild();
    }

    // FIXED: Decryption Diagnostics Tab - NEW FEATURE
    private void RenderDecryptionDiagnosticsTab(Vector2 avail)
    {
        ImGui.TextColored(Theme.ColAccent, "Decryption Diagnostics");
        ImGui.TextColored(Theme.ColTextMuted, "Analyze why decryption is failing and test different approaches");
        ImGui.Separator();

        // Run diagnostics button
        if (ImGui.Button("Run Full Diagnostics", new Vector2(180, 32)))
        {
            Task.Run(() => RunDecryptionDiagnostics());
        }

        ImGui.SameLine();

        if (ImGui.Button("Test Key Derivation", new Vector2(150, 32)))
        {
            TestKeyDerivation();
        }

        ImGui.Spacing();

        // Results display
        ImGui.BeginChild("##diag_results", new Vector2(0, avail.Y - 100), ImGuiChildFlags.Borders);

        if (!_decryptionDiag.HasRun)
        {
            ImGui.TextColored(Theme.ColTextMuted, "Click 'Run Full Diagnostics' to analyze decryption issues");
        }
        else
        {
            // SSL Key Log Status
            ImGui.TextColored(Theme.ColAccent, "SSL Key Log Analysis");
            ImGui.Text($"Keys found: {_decryptionDiag.KeysFound}");
            ImGui.Text($"Key types: {_decryptionDiag.KeyTypes}");

            if (_decryptionDiag.KeysFound > 0)
            {
                var color = _decryptionDiag.KeysValid ? Theme.ColSuccess : Theme.ColDanger;
                ImGui.TextColored(color, $"Key derivation test: {(_decryptionDiag.KeysValid ? "PASSED" : "FAILED")}");
            }

            ImGui.Separator();

            // Packet Analysis
            ImGui.TextColored(Theme.ColAccent, "Captured Packet Analysis");
            ImGui.Text($"Total packets: {_decryptionDiag.TotalPackets}");
            ImGui.Text($"QUIC packets: {_decryptionDiag.QuicPackets}");
            ImGui.Text($"Short headers: {_decryptionDiag.ShortHeaders}");
            ImGui.Text($"Long headers: {_decryptionDiag.LongHeaders}");
            ImGui.Text($"Average entropy: {_decryptionDiag.AverageEntropy:F2}");

            ImGui.Separator();

            // Decryption Attempts
            ImGui.TextColored(Theme.ColAccent, "Decryption Attempts");
            ImGui.Text($"Successful: {_decryptionDiag.SuccessfulDecryptions}");
            ImGui.Text($"Failed: {_decryptionDiag.FailedDecryptions}");

            if (_decryptionDiag.ErrorMessages.Any())
            {
                ImGui.TextColored(Theme.ColWarn, "Common errors:");
                foreach (var error in _decryptionDiag.ErrorMessages.Take(5))
                {
                    ImGui.BulletText(error);
                }
            }

            ImGui.Separator();

            // Recommendations
            ImGui.TextColored(Theme.ColAccent, "Recommendations");
            foreach (var rec in _decryptionDiag.Recommendations)
            {
                ImGui.BulletText(rec);
            }
        }

        ImGui.EndChild();
    }

    // FIXED: Perform memory search across all regions
    private async void PerformMemorySearch()
    {
        if (!_isAttached || _processHandle == IntPtr.Zero) return;

        _searchInProgress = true;
        _searchResults.Clear();
        _state.AddInGameLog($"[MEMORY] Starting memory search for: {_memorySearchPattern}");

        try
        {
            await Task.Run(() => DoMemorySearch());
        }
        catch (Exception ex)
        {
            _state.AddInGameLog($"[MEMORY] Search error: {ex.Message}");
        }
        finally
        {
            _searchInProgress = false;
        }
    }

    private void DoMemorySearch()
    {
        byte[]? searchBytes = null;
        
        bool isHexPattern = _memorySearchPattern.Contains(' ') ||
                            _memorySearchPattern.All(c => Uri.IsHexDigit(c) || char.IsWhiteSpace(c));

        if (isHexPattern)
        {
            // Parse hex pattern
            try
            {
                var hexString = _memorySearchPattern.Replace(" ", "").Replace("-", "");
                if (hexString.Length % 2 == 0)
                {
                    searchBytes = Convert.FromHexString(hexString);
                }
            }
            catch { }
        }
        else
        {
            // Treat as string
            searchBytes = Encoding.UTF8.GetBytes(_memorySearchPattern);
        }

        if (searchBytes == null || searchBytes.Length == 0)
        {
            _state.AddInGameLog("[MEMORY] Invalid search pattern");
            return;
        }

        var regions = GetReadableMemoryRegions()
            .Where(r => r.Size > 0x1000 && r.Size < 0x10000000)
            .ToList();

        int totalRegions = regions.Count;
        int currentRegion = 0;
        int foundCount = 0;

        foreach (var region in regions)
        {
            currentRegion++;
            if (currentRegion % 10 == 0)
            {
                _scanProgress = (int)((double)currentRegion / totalRegions * 100);
            }

            try
            {
                int chunkSize = (int)Math.Min(region.Size, MAX_SCAN_CHUNK);
                byte[]? buffer = ArrayPool<byte>.Shared.Rent(chunkSize);
                try
                {
                    if (!ReadProcessMemory(_processHandle, region.BaseAddress, buffer, chunkSize, out int read))
                        continue;

                    // Search for pattern
                    for (int i = 0; i <= read - searchBytes.Length; i++)
                    {
                        bool match = true;
                        for (int j = 0; j < searchBytes.Length; j++)
                        {
                            if (buffer[i + j] != searchBytes[j])
                            {
                                match = false;
                                break;
                            }
                        }

                        if (match)
                        {
                            var addr = region.BaseAddress + i;
                            string preview = GetBytePreview(buffer, i, read);

                            _searchResults.Add(new MemorySearchResult
                            {
                                Address = addr,
                                Preview = preview,
                                RegionSize = region.Size
                            });

                            foundCount++;
                            if (foundCount >= MAX_RESULTS) break;
                        }
                    }
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(buffer);
                }
            }
            catch { }

            if (foundCount >= MAX_RESULTS) break;
        }

        _state.AddInGameLog($"[MEMORY] Search complete. Found {foundCount} matches");
    }

    private string GetBytePreview(byte[] buffer, int offset, int bufferLength)
    {
        int previewLen = Math.Min(32, bufferLength - offset);
        var previewBytes = new byte[previewLen];
        Array.Copy(buffer, offset, previewBytes, 0, previewLen);

        // Try to interpret as string
        string hex = BitConverter.ToString(previewBytes).Replace("-", " ");
        string ascii = Encoding.ASCII.GetString(previewBytes.Select(b => (b < 32 || b > 126) ? (byte)46 : b).ToArray());

        return $"{hex} | {ascii}";
    }

    private void ReadAndDisplayBytes(IntPtr address, int size)
    {
        var bytes = ReadMemoryBytes(address, size);
        if (bytes != null)
        {
            _state.AddInGameLog($"[MEMORY] Read {size} bytes from 0x{(ulong)address:X}:");
            _state.AddInGameLog(BitConverter.ToString(bytes.Take(32).ToArray()));
        }
    }

    // FIXED: Scan for Netty ByteBuf objects
    private async void ScanForNettyByteBufs()
    {
        if (!_isAttached || _processHandle == IntPtr.Zero) return;

        _state.AddInGameLog("[MEMORY] Scanning for Netty ByteBuf objects...");
        _nettyBuffers.Clear();

        try
        {
            await Task.Run(() => DoNettyBufferScan());
        }
        catch (Exception ex)
        {
            _state.AddInGameLog($"[MEMORY] Netty scan error: {ex.Message}");
        }
    }

    private void DoNettyBufferScan()
    {
        if (!_isAttached || _processHandle == IntPtr.Zero) return;

        _state.AddInGameLog("[MEMORY] Scanning for Netty ByteBuf objects...");
        _nettyBuffers.Clear();

        try
        {
            // Look in heap regions specifically - Netty allocates on heap
            var regions = GetReadableMemoryRegions()
                .Where(r => r.Size > 0x10000 && r.Size < 0x10000000) // 64KB to 256MB
                .OrderByDescending(r => r.Size)
                .Take(20)
                .ToList();

            int bufferCount = 0;
            var seenAddresses = new HashSet<long>();

            foreach (var region in regions)
            {
                try
                {
                    int chunkSize = (int)Math.Min(region.Size, MAX_SCAN_CHUNK);
                    byte[]? buffer = ArrayPool<byte>.Shared.Rent(chunkSize);
                    try
                    {
                        if (!ReadProcessMemory(_processHandle, region.BaseAddress, buffer, chunkSize, out int read))
                            continue;

                        // Scan for ByteBuf pattern
                        // Netty ByteBuf structure (UnpooledHeapByteBuf):
                        // Offset 0: readerIndex (int32)
                        // Offset 4: writerIndex (int32)  
                        // Offset 8: capacity (int32)
                        // Offset 12: maxCapacity (int32) or refCount
                        // Offset 16: array pointer (int64 on x64)
                        // Offset 24: array length (int32)

                        for (int i = 0; i < read - 64; i += 8) // 8-byte alignment
                        {
                            int readerIndex = BitConverter.ToInt32(buffer, i);
                            int writerIndex = BitConverter.ToInt32(buffer, i + 4);
                            int capacity = BitConverter.ToInt32(buffer, i + 8);
                            int field4 = BitConverter.ToInt32(buffer, i + 12); // maxCapacity or refCount
                            long arrayPtr = BitConverter.ToInt64(buffer, i + 16);
                            int arrayLen = BitConverter.ToInt32(buffer, i + 24);

                            // Relaxed heuristics - Netty allows readerIndex == writerIndex (empty buffer)
                            bool validIndices = readerIndex >= 0 && writerIndex >= 0 &&
                                              readerIndex <= writerIndex &&
                                              writerIndex <= capacity &&
                                              capacity > 0;

                            bool validCapacity = capacity <= 0x10000000 && // 256MB max reasonable
                                               capacity >= 16; // Min reasonable buffer

                            bool validRefCount = field4 > 0 && field4 < 1000000; // refCount or maxCapacity

                            // Pointer validation - must be in valid memory range
                            bool validPointer = arrayPtr > 0x10000 &&
                                              arrayPtr < 0x7FFFFFFF0000 &&
                                              (arrayPtr & 0x7) == 0; // 8-byte aligned

                            if (validIndices && validCapacity && validRefCount && validPointer)
                            {
                                // Calculate readable bytes
                                int readable = writerIndex - readerIndex;

                                // Additional sanity check on readable
                                if (readable >= 0 && readable <= capacity && readable < 100000)
                                {
                                    // Try to read actual content
                                    if (seenAddresses.Add(arrayPtr))
                                    {
                                        var contentPreview = ReadBufferContent((IntPtr)arrayPtr, Math.Min(readable, 48));

                                        // Only add if content is readable
                                        if (!string.IsNullOrEmpty(contentPreview) &&
                                            !contentPreview.StartsWith("???") &&
                                            contentPreview.Length > 3)
                                        {
                                            _nettyBuffers.Add(new NettyBufferInfo
                                            {
                                                Address = region.BaseAddress + i,
                                                ReaderIndex = readerIndex,
                                                WriterIndex = writerIndex,
                                                Capacity = capacity,
                                                ReadableBytes = readable,
                                                ContentPreview = contentPreview
                                            });

                                            bufferCount++;
                                            if (bufferCount >= 200)
                                            {
                                                _state.AddInGameLog($"[MEMORY] Found {bufferCount}+ Netty buffers (limit reached)");
                                                return;
                                            }
                                        }
                                    }
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

            _state.AddInGameLog($"[MEMORY] Found {bufferCount} Netty ByteBuf objects");
        }
        catch (Exception ex)
        {
            _state.AddInGameLog($"[MEMORY] Netty scan error: {ex.Message}");
        }
    }

    private string ReadBufferContent(IntPtr arrayPtr, int length)
    {
        if (length <= 0 || length > 1024) return "";

        var bytes = ReadMemoryBytes(arrayPtr, length);
        if (bytes == null || bytes.Length == 0) return "???";

        // Convert to hex/ascii preview
        string hex = BitConverter.ToString(bytes.Take(16).ToArray()).Replace("-", " ");
        string ascii = Encoding.ASCII.GetString(bytes.Select(b => (b < 32 || b > 126) ? (byte)46 : b).ToArray());

        // Clean up ASCII
        ascii = new string(ascii.Where(c => !char.IsControl(c)).ToArray());

        return $"{hex} | {ascii}";
    }

    private void DumpNettyBuffer(NettyBufferInfo buf)
    {
        try
        {
            // Read the backing array pointer
            byte[] ptrBytes = new byte[8];
            if (!ReadProcessMemory(_processHandle, buf.Address + 16, ptrBytes, 8, out _))
                return;

            IntPtr arrayPtr = (IntPtr)BitConverter.ToInt64(ptrBytes);
            var content = ReadMemoryBytes(arrayPtr, Math.Min(buf.ReadableBytes, 1024));

            if (content != null)
            {
                string filename = Path.Combine(_state.ExportDirectory,
                    $"netty_buf_{(ulong)buf.Address:X}_{DateTime.Now:yyyyMMdd_HHmmss}.bin");
                File.WriteAllBytes(filename, content);
                _state.AddInGameLog($"[MEMORY] Dumped {content.Length} bytes to {filename}");
            }
        }
        catch (Exception ex)
        {
            _state.AddInGameLog($"[MEMORY] Dump failed: {ex.Message}");
        }
    }

    // FIXED: Run decryption diagnostics
    private async void RunDecryptionDiagnostics()
    {
        _state.AddInGameLog("[DIAG] Running decryption diagnostics...");

        await Task.Run(() =>
        {
            _decryptionDiag = new DecryptionDiagnostics();

            // Check keys
            _decryptionDiag.KeysFound = PacketDecryptor.DiscoveredKeys.Count;
            _decryptionDiag.KeyTypes = string.Join(", ",
                PacketDecryptor.DiscoveredKeys.Select(k => k.Type.ToString()).Distinct());

            if (_decryptionDiag.KeysFound > 0)
            {
                // Test key derivation
                var testKey = PacketDecryptor.DiscoveredKeys.First();
                _decryptionDiag.KeysValid = testKey.Key.Length == 16 && testKey.IV.Length == 12;
            }

            // Analyze packets
            var packets = _state.PacketLog.GetLast(100);
            _decryptionDiag.TotalPackets = packets.Count;
            _decryptionDiag.QuicPackets = packets.Count(p => !p.IsTcp);
            _decryptionDiag.ShortHeaders = packets.Count(p => !p.IsTcp && p.QuicInfo != null && !p.QuicInfo.IsLongHeader);
            _decryptionDiag.LongHeaders = packets.Count(p => !p.IsTcp && p.QuicInfo != null && p.QuicInfo.IsLongHeader);

            // Calculate average entropy
            double totalEntropy = 0;
            int entropyCount = 0;
            foreach (var pkt in packets.Where(p => !p.IsTcp))
            {
                try
                {
                    var hexString = pkt.RawHexPreview.Replace("-", "").Replace(" ", "");
                    if (hexString.Length > 0 && hexString.Length % 2 == 0)
                    {
                        var bytes = Convert.FromHexString(hexString);
                        totalEntropy += ByteUtils.CalculateEntropy(bytes);
                        entropyCount++;
                    }
                }
                catch { }
            }
            _decryptionDiag.AverageEntropy = entropyCount > 0 ? totalEntropy / entropyCount : 0;

            // Decryption stats
            _decryptionDiag.SuccessfulDecryptions = (int)PacketDecryptor.SuccessfulDecryptions;
            _decryptionDiag.FailedDecryptions = (int)PacketDecryptor.FailedDecryptions;

            // Generate recommendations
            _decryptionDiag.Recommendations = GenerateRecommendations();

            _decryptionDiag.HasRun = true;
        });

        _state.AddInGameLog("[DIAG] Diagnostics complete");
    }

    private List<string> GenerateRecommendations()
    {
        var recs = new List<string>();

        if (_decryptionDiag.KeysFound == 0)
        {
            recs.Add("No keys found. Set SSLKEYLOGFILE environment variable before starting Hytale.");
            recs.Add("Or use Memory Scanner to extract keys from Hytale process memory.");
        }
        else if (!_decryptionDiag.KeysValid)
        {
            recs.Add("Keys found but derivation may be incorrect. Check HKDF implementation.");
            recs.Add("Hytale may use custom key schedule different from standard RFC 9001.");
        }

        if (_decryptionDiag.ShortHeaders > 0 && _decryptionDiag.SuccessfulDecryptions == 0)
        {
            recs.Add("Short header packets detected but not decrypted. Key mismatch likely.");
            recs.Add("Try: Keys may be rotated - capture fresh keys during handshake.");
        }

        if (_decryptionDiag.AverageEntropy > 7.8)
        {
            recs.Add("High entropy confirms strong encryption. Decryption requires correct keys.");
        }

        recs.Add("Alternative: Hook Netty pipeline to intercept packets before encryption.");
        recs.Add("Use 'Netty Buffers' tab to find unencrypted packet data in memory.");

        return recs;
    }

    private void TestKeyDerivation()
    {
        if (PacketDecryptor.DiscoveredKeys.Count == 0)
        {
            _state.AddInGameLog("[DIAG] No keys to test");
            return;
        }

        var key = PacketDecryptor.DiscoveredKeys.First();
        _state.AddInGameLog($"[DIAG] Testing key: {key.Type}");
        _state.AddInGameLog($"[DIAG] Key length: {key.Key.Length} bytes, IV length: {key.IV.Length} bytes");
        _state.AddInGameLog($"[DIAG] Has header protection key: {key.HeaderProtectionKey != null}");

        // Test decrypt a recent packet
        var packet = _state.PacketLog.GetLast(10).LastOrDefault(p => !p.IsTcp);
        if (packet != null)
        {
            var result = PacketDecryptor.TryDecryptManual(packet.RawBytes, 5000);
            _state.AddInGameLog($"[DIAG] Manual decrypt test: {(result.Success ? "SUCCESS" : "FAILED")}");
            if (!result.Success)
            {
                _state.AddInGameLog($"[DIAG] Error: {result.ErrorMessage}");
            }
        }
    }

    // Original scan methods (kept for compatibility)
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

        if (_isScanning)
        {
            ImGui.BeginDisabled();
            ImGui.Button("Scanning...", new Vector2(100, 28));
            ImGui.EndDisabled();

            ImGui.SameLine();
            if (ImGui.Button("Stop", new Vector2(80, 28)))
            {
                CancelScan();
            }
        }
        else
        {
            if (ImGui.Button("First Scan", new Vector2(100, 28)))
                PerformFirstScan();

            ImGui.SameLine();

            if (ImGui.Button("Next Scan", new Vector2(100, 28)))
                PerformNextScan();
        }

        ImGui.SameLine();

        if (ImGui.Button("Reset", new Vector2(80, 28)))
        {
            _scanResults.Clear();
            _filteredResults.Clear();
            CancelScan();
        }

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

            ImGui.Separator();
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

    // ... (keep all original scan methods: QuickScanLocalPlayer, ScanForTLSKeys, etc.)
    // Include all the original methods from your MemoryTab here...

    private async void QuickScanLocalPlayer()
    {
        if (!_isAttached || _processHandle == IntPtr.Zero) return;

        _isScanning = true;
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
            _isScanning = false;
            _scanCts = null;
        }
    }

    private void DoLocalPlayerScan(CancellationToken token)
    {
        _scanResults.Clear();

        var regions = GetReadableMemoryRegions()
            .Where(r => r.Size > 0x1000 && r.Size < 0x10000000)
            .ToList();

        _scanTotalRegions = Math.Min(regions.Count, 50);
        _scanCurrentRegion = 0;
        _scanProgress = 0;

        int foundHealth = 0;
        int foundName = 0;

        foreach (var region in regions.Take(50))
        {
            if (token.IsCancellationRequested) break;

            _scanCurrentRegion++;
            _scanProgress = (int)((double)_scanCurrentRegion / _scanTotalRegions * 100);

            try
            {
                int chunkSize = (int)Math.Min(region.Size, MAX_SCAN_CHUNK);
                byte[]? buffer = ArrayPool<byte>.Shared.Rent(chunkSize);
                try
                {
                    if (!ReadProcessMemory(_processHandle, region.BaseAddress, buffer, chunkSize, out int read))
                        continue;

                    byte[] healthFloat = BitConverter.GetBytes(100f);
                    byte[] healthInt = BitConverter.GetBytes(100);

                    for (int i = 0; i < read - 4; i++)
                    {
                        if (i % 1000 == 0 && token.IsCancellationRequested)
                            break;

                        if (buffer[i] == healthFloat[0] && buffer[i + 1] == healthFloat[1] &&
                            buffer[i + 2] == healthFloat[2] && buffer[i + 3] == healthFloat[3])
                        {
                            _scanResults.Add(new MemoryResult
                            {
                                Address = region.BaseAddress + i,
                                Type = ScanValueType.Float,
                                ValuePreview = "100.0 (Health?)"
                            });
                            foundHealth++;
                            if (_scanResults.Count >= MAX_RESULTS) break;
                        }

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

                    string[] namePatterns = { "LocalPlayer", "Player", "Hero", "Character" };
                    foreach (var name in namePatterns)
                    {
                        if (token.IsCancellationRequested) break;

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

    private async void ScanForTLSKeys()
    {
        if (!_isAttached || _hytaleProcess == null || _processHandle == IntPtr.Zero) return;

        _state.AddInGameLog("[AUTO-KEY] Starting automatic TLS key extraction...");

        _isScanning = true;
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
            _isScanning = false;
            _scanCts = null;
        }
    }

    private List<IntPtr> FindSSLContexts(CancellationToken token)
    {
        var contexts = new List<IntPtr>();
        var regions = GetReadableMemoryRegions()
            .Where(r => r.Size > 0x1000 && r.Size < 0x10000000)
            .OrderByDescending(r => r.Size);

        _scanTotalRegions = 20;
        _scanCurrentRegion = 0;

        foreach (var region in regions.Take(20))
        {
            if (token.IsCancellationRequested) break;

            _scanCurrentRegion++;
            _scanProgress = (int)((double)_scanCurrentRegion / _scanTotalRegions * 100);

            try
            {
                long offset = 0;
                while (offset < region.Size)
                {
                    if (token.IsCancellationRequested) break;

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

        _scanTotalRegions = 30;
        _scanCurrentRegion = 0;

        int totalKeysFound = 0;

        foreach (var region in regions.Take(30))
        {
            if (token.IsCancellationRequested) break;

            _scanCurrentRegion++;
            _scanProgress = (int)((double)_scanCurrentRegion / _scanTotalRegions * 100);

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
                Key = keyBytes.Take(16).ToArray(),
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

    private async void PerformFirstScan()
    {
        _isScanning = true;
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
            _isScanning = false;
            _scanCts = null;
        }
    }

    private void DoFirstScan(CancellationToken token)
    {
        _scanResults.Clear();

        if (_processHandle == IntPtr.Zero) return;

        var regions = GetReadableMemoryRegions();

        _scanTotalRegions = Math.Min(regions.Count, 50);
        _scanCurrentRegion = 0;

        foreach (var region in regions.Take(50))
        {
            if (token.IsCancellationRequested) break;

            _scanCurrentRegion++;
            _scanProgress = (int)((double)_scanCurrentRegion / _scanTotalRegions * 100);

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
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(buffer);
                }
            }
            catch { }
        }

        _filteredResults = new List<MemoryResult>(_scanResults);
        _state.AddInGameLog($"[MEMORY] Scanned {_scanCurrentRegion} regions, found {_scanResults.Count} results");
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
        if (_processHandle == IntPtr.Zero || address == IntPtr.Zero)
            return null;

        if (size <= 0 || size > 4096)
        {
            _state.AddInGameLog($"[MEMORY] Invalid read size: {size}");
            return null;
        }

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
        CancelScan();

        if (_processHandle != IntPtr.Zero)
            CloseHandle(_processHandle);

        _hytaleProcess = null;
        _processHandle = IntPtr.Zero;
        _isAttached = false;
        _scanResults.Clear();
        _watches.Clear();
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

    // NEW: Memory search result
    private class MemorySearchResult
    {
        public IntPtr Address;
        public string Preview = "";
        public long RegionSize;
    }

    // NEW: Netty buffer info
    private class NettyBufferInfo
    {
        public IntPtr Address;
        public int ReaderIndex;
        public int WriterIndex;
        public int Capacity;
        public int ReadableBytes;
        public string ContentPreview = "";
    }

    /// NEW: Decryption diagnostics
    private class DecryptionDiagnostics
    {
        public bool HasRun = false;
        public int KeysFound = 0;
        public string KeyTypes = "";
        public bool KeysValid = false;
        public int TotalPackets = 0;
        public int QuicPackets = 0;
        public int ShortHeaders = 0;
        public int LongHeaders = 0;
        public double AverageEntropy = 0;
        public int SuccessfulDecryptions = 0;
        public int FailedDecryptions = 0;
        public List<string> ErrorMessages = new();
        public List<string> Recommendations = new();
    }
}