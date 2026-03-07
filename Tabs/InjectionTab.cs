// FILE: .\Tabs\InjectionTab.cs
// COMPLETE FILE - Replace entire contents

using HyForce.Core;
using HyForce.Networking;
using ImGuiNET;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace HyForce.Tabs
{
    public class InjectionTab : ITab
    {
        public string Name => "Injection";

        private readonly AppState _state;
        private readonly PipeCaptureServer _pipe;

        // ── Process list ──────────────────────────────────────────────
        private List<(int pid, string name, bool is64)> _procs = new();
        private int _selProc = -1;
        private string _procFilter = "";
        private DateTime _lastRefresh = DateTime.MinValue;

        // ── DLL list ──────────────────────────────────────────────────
        private string[] _dllPaths = Array.Empty<string>();
        private string[] _dllNames = Array.Empty<string>();
        private int _selDll = 0;
        private readonly string _dllFolder;

        // ── Status ────────────────────────────────────────────────────
        private string _injectStatus = "";
        private Vector4 _injectColor = new Vector4(0.6f, 0.6f, 0.6f, 1f);
        private bool _injected = false;
        private int _injectedPid = -1;
        private IntPtr _hInjectedModule = IntPtr.Zero;
        private HyForce.Networking.WinDivertCapture? _winDivert;

        // ── Ejection watchdog ─────────────────────────────────────────
        private System.Timers.Timer? _ejectWatchdog;
        private bool _forceEjectOnClose = true;
        private bool _autoEjectOnDisconnect = false;
        private bool shouldReset;

        // ── P/Invoke ──────────────────────────────────────────────────
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint acc, bool inh, int pid);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAllocEx(IntPtr p, IntPtr a, uint sz, uint t, uint pr);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr p, IntPtr a, byte[] b, uint sz, out uint w);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateRemoteThread(IntPtr p, IntPtr a, uint s, IntPtr f, IntPtr pa, uint fl, out uint tid);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint WaitForSingleObject(IntPtr h, uint ms);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr h);
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr m, string n);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr GetModuleHandleW(string n);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetEnvironmentVariable(string lpName, string lpValue);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool IsWow64Process(IntPtr h, out bool wow64);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint dwFreeType);

        const uint MEM_RELEASE = 0x8000;

        // NEW: For DLL ejection
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool FreeLibrary(IntPtr hModule);
        [DllImport("psapi.dll", SetLastError = true)]
        static extern bool EnumProcessModules(IntPtr hProcess, [Out] IntPtr[] lphModule, uint cb, out uint lpcbNeeded);
        [DllImport("psapi.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        static extern uint GetModuleBaseNameA(IntPtr hProcess, IntPtr hModule, [Out] byte[] lpBaseName, uint nSize);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetExitCodeThread(IntPtr hThread, out uint lpExitCode);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool TerminateThread(IntPtr hThread, uint dwExitCode);

        private const uint PROCESS_ALL = 0x1F0FFF;
        private const uint PROCESS_QUERY_LIMITED = 0x1000;
        private const uint PROCESS_CREATE_THREAD = 0x0002;
        private const uint PROCESS_VM_OPERATION = 0x0008;
        private const uint PROCESS_VM_WRITE = 0x0020;
        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_RESERVE = 0x2000;
        private const uint PAGE_READWRITE = 0x04;

        public InjectionTab(AppState state, PipeCaptureServer pipe)
        {
            _state = state;
            _pipe = pipe;
            _dllFolder = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "HyForce", "DLLs");
            Directory.CreateDirectory(_dllFolder);
            RefreshDlls();
            RefreshProcs();

            // Setup ejection watchdog
            SetupEjectionWatchdog();
        }

        private void SetupEjectionWatchdog()
        {
            _ejectWatchdog = new System.Timers.Timer(2000);
            _ejectWatchdog.Elapsed += (s, e) =>
            {
                if (!_injected || _injectedPid < 0) return;

                // Don't run checks immediately after injection
                if (_pipe.TimeSinceConnected.TotalSeconds < 3) return;

                Task.Run(async () =>
                {
                    try
                    {
                        // Check if process still exists
                        bool processExists = false;
                        try
                        {
                            using var proc = Process.GetProcessById(_injectedPid);
                            processExists = !proc.HasExited;
                        }
                        catch (ArgumentException)
                        {
                            processExists = false;
                        }

                        if (!processExists)
                        {
                            _state.AddInGameLog($"[EJECT] Target process {_injectedPid} exited");
                            ResetInjectionState();
                            return;
                        }

                        // Only check for disconnect if we've been connected before
                        // AND enough time has passed since last packet
                        if (_autoEjectOnDisconnect && !_pipe.DllConnected &&
                            _pipe.DllConnectedAt != DateTime.MinValue &&
                            (DateTime.Now - _pipe.LastPacket).TotalSeconds > 15)
                        {
                            _state.AddInGameLog("[EJECT] DLL connection lost, auto-ejecting");
                            await ForceEjectDllAsync();
                        }
                    }
                    catch { /* ignore */ }
                });
            };
            _ejectWatchdog.AutoReset = true;
            _ejectWatchdog.Start();
        }

        private void ResetInjectionState()
        {
            _injected = false;
            _injectedPid = -1;
            _hInjectedModule = IntPtr.Zero;
            _injectStatus = "";
            _pipe.ResetConnection(); // Reset pipe state too
        }

        public void OnApplicationClosing()
        {
            if (_forceEjectOnClose && _injected)
            {
                _state.AddInGameLog("[EJECT] Application closing - auto-ejecting");
                _ = ForceEjectDllAsync();
            }

            _ejectWatchdog?.Stop();
            _ejectWatchdog?.Dispose();
        }
        public void Render()
        {
            // ── Header ───────────────────────────────────────────────
            ImGui.TextColored(new Vector4(0.4f, 0.8f, 1f, 1f), "DLL Injection  —  WinSock Capture");
            ImGui.Separator();
            ImGui.Spacing();

            // ── Pipe status banner ────────────────────────────────────
            RenderPipeStatus();
            ImGui.Spacing();
            ImGui.Separator();
            ImGui.Spacing();

            // ── Ejection Controls (NEW) ───────────────────────────────
            RenderEjectionControls();
            ImGui.Spacing();
            ImGui.Separator();
            ImGui.Spacing();

            // ── Step 1: DLL ───────────────────────────────────────────
            ImGui.TextColored(new Vector4(0.9f, 0.8f, 0.3f, 1f), "Step 1 — DLL");
            ImGui.Text($"Folder: {_dllFolder}");
            ImGui.SameLine();
            if (ImGui.SmallButton("Open##f"))
                try { Process.Start("explorer.exe", _dllFolder); } catch { }
            ImGui.SameLine();
            if (ImGui.SmallButton("Refresh##d")) RefreshDlls();

            if (_dllNames.Length == 0)
            {
                ImGui.TextColored(new Vector4(1f, 0.4f, 0.2f, 1f),
                    "No DLLs found. Build HyForceHook.dll (see build.bat) and paste it here.");
            }
            else
            {
                ImGui.SetNextItemWidth(420);
                ImGui.Combo("##dll", ref _selDll, _dllNames, _dllNames.Length);
                if (_selDll < _dllPaths.Length)
                {
                    var fi = new FileInfo(_dllPaths[_selDll]);
                    ImGui.TextColored(new Vector4(0.55f, 0.55f, 0.55f, 1f),
                        $"  {fi.Length / 1024}KB  —  {fi.LastWriteTime:yyyy-MM-dd HH:mm:ss}");
                }
            }

            ImGui.Spacing();
            ImGui.Separator();
            ImGui.Spacing();

            // ── Step 2: Process ──────────────────────────────────────
            ImGui.TextColored(new Vector4(0.9f, 0.8f, 0.3f, 1f), "Step 2 — Process");
            ImGui.TextColored(new Vector4(0.6f, 0.6f, 0.6f, 1f),
                "All processes shown. Hytale/Java highlighted green.");

            if ((DateTime.Now - _lastRefresh).TotalSeconds > 4) RefreshProcs();

            ImGui.SetNextItemWidth(260);
            if (ImGui.InputText("Filter##pf", ref _procFilter, 64))
            { /* filter applied during render */ }
            ImGui.SameLine();
            if (ImGui.SmallButton("Refresh##p")) RefreshProcs();

            var filtered = string.IsNullOrEmpty(_procFilter)
                ? _procs
                : _procs.Where(p => p.name.Contains(_procFilter, StringComparison.OrdinalIgnoreCase)).ToList();

            if (ImGui.BeginListBox("##procs", new Vector2(530, 140)))
            {
                for (int i = 0; i < filtered.Count; i++)
                {
                    var (pid, pname, is64) = filtered[i];
                    bool sel = (_selProc == _procs.IndexOf(filtered[i]));

                    bool highlight = pname.Contains("hytale", StringComparison.OrdinalIgnoreCase)
                                  || pname.Contains("java", StringComparison.OrdinalIgnoreCase)
                                  || pname.Contains("javaw", StringComparison.OrdinalIgnoreCase);

                    if (highlight) ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(0.3f, 1f, 0.5f, 1f));

                    string arch = is64 ? "x64" : "x86";
                    if (ImGui.Selectable($"[{pid,6}] {arch}  {pname}##pi{i}", sel))
                        _selProc = _procs.IndexOf(filtered[i]);

                    if (highlight) ImGui.PopStyleColor();
                }
                ImGui.EndListBox();
            }

            if (_selProc >= 0 && _selProc < _procs.Count)
            {
                var (_, pn, is64) = _procs[_selProc];
                if (!is64)
                    ImGui.TextColored(new Vector4(1f, 0.5f, 0.1f, 1f),
                        $"  ⚠ {pn} appears to be 32-bit. DLL must also be 32-bit or injection will fail.");
            }

            ImGui.Spacing();
            ImGui.Separator();
            ImGui.Spacing();
            // ── Step 3: Inject ───────────────────────────────────────
            ImGui.TextColored(new Vector4(0.9f, 0.8f, 0.3f, 1f), "Step 3 — Inject");

            bool ready = !_injected
                      && _selProc >= 0 && _selProc < _procs.Count
                      && _dllPaths.Length > 0 && _selDll < _dllPaths.Length;

            if (!ready) ImGui.BeginDisabled();
            if (ImGui.Button("  Inject DLL  ", new Vector2(140, 32)))
            {
                _ = DoInjectAsync();
            }
            if (!ready) ImGui.EndDisabled();
            

            if (_injected)
            {
                ImGui.SameLine();
                ImGui.TextColored(new Vector4(0.2f, 1f, 0.4f, 1f), $"  Injected into PID {_injectedPid}");
                ImGui.SameLine();
                if (ImGui.SmallButton("Reset##inj"))
                { _injected = false; _injectedPid = -1; _injectStatus = ""; }
            }

            ImGui.Spacing();
            if (!string.IsNullOrEmpty(_injectStatus))
                ImGui.TextColored(_injectColor, _injectStatus);

            // ── Pipe diagnostics ─────────────────────────────────────
            ImGui.Spacing();
            ImGui.Separator();
            ImGui.Spacing();
            ImGui.TextColored(new Vector4(0.9f, 0.8f, 0.3f, 1f), "Pipe Diagnostics");
            ImGui.Text($"  HyForcePipe server:     {(_pipe.IsRunning ? "running" : "stopped")}");
            ImGui.Text($"  DLL connected:          {(_pipe.DllConnected ? "YES" : "no")}");
            ImGui.Text($"  Packets received:       {_pipe.PacketCount}");
            if (_pipe.LastPacket != DateTime.MinValue)
                ImGui.Text($"  Last packet:            {_pipe.LastPacket:HH:mm:ss.fff}");
            ImGui.Text($"  DLL status:             {_pipe.DllStatus}");

            if (ImGui.SmallButton("Send PING")) _pipe.SendCommand("PING");
            ImGui.SameLine();
            if (ImGui.SmallButton("Get STATS")) _pipe.SendCommand("STATS");
            ImGui.SameLine();
            if (ImGui.SmallButton("PCAP Start"))
            {
                string pcapPath = System.IO.Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "HyForce", "Exports", $"cap_{DateTime.Now:yyyyMMdd_HHmmss}.pcap");
                System.IO.Directory.CreateDirectory(System.IO.Path.GetDirectoryName(pcapPath)!);
                _pipe.SendCommand($"PCAP_START {pcapPath}");
            }
            ImGui.SameLine();
            if (ImGui.SmallButton("PCAP Stop")) _pipe.SendCommand("PCAP_STOP");
            ImGui.SameLine();
            if (ImGui.SmallButton("Quiche Probe"))
            {
                _pipe.QuicheProbe();
                _state.AddInGameLog("[QUICHE] Probe sent — scanning loaded modules for quiche stream hooks");
            }

            ImGui.Spacing();
            ImGui.Separator();
            if (ImGui.CollapsingHeader("Build & workflow instructions"))
                RenderHelp();

            if (ImGui.CollapsingHeader("Windivert guide"))
                RenderWinDivertHelp();

            ImGui.Spacing();
            ImGui.Separator();
            ImGui.Spacing();
            ImGui.TextColored(new Vector4(0.9f, 0.8f, 0.3f, 1f), "WinDivert Kernel Capture");
            if (_winDivert == null || !_winDivert.IsRunning)
            {
                if (ImGui.Button("Start WinDivert Capture", new Vector2(160, 32)))
                {
                    _winDivert = new HyForce.Networking.WinDivertCapture(_state);
                    _winDivert.OnPacket += pkt => _state.OnHookPacket(pkt);
                    bool ok = _winDivert.Start();
                    if (!ok)
                    {
                        _state.AddInGameLog("[WINDIVERT] Failed - ensure you're running as Administrator");
                    }
                }
                ImGui.SameLine();
                ImGui.TextColored(new Vector4(0.6f, 0.6f, 0.6f, 1f), "Requires Admin + WinDivert.dll");
            }
            else
            {
                ImGui.TextColored(new Vector4(0.2f, 1f, 0.4f, 1f), $"● WinDivert Active - {_winDivert.PacketCount} packets");
                ImGui.SameLine();
                if (ImGui.SmallButton("Stop")) _winDivert.Stop();
            }
        }

        private void RenderEjectionControls()
        {
            ImGui.TextColored(new Vector4(0.9f, 0.4f, 0.4f, 1f), "⚠ DLL Ejection Control");

            if (!_injected)
            {
                ImGui.TextColored(new Vector4(0.5f, 0.5f, 0.5f, 1f), "No DLL currently injected");

                ImGui.Checkbox("Auto-eject on menu close", ref _forceEjectOnClose);
                ImGui.Checkbox("Auto-eject on disconnect", ref _autoEjectOnDisconnect);
            }
            else
            {
                ImGui.TextColored(new Vector4(1f, 0.3f, 0.3f, 1f),
                    $"● DLL ACTIVE in PID {_injectedPid}");

                ImGui.SameLine();
                if (ImGui.Button("🛑 EJECT DLL", new Vector2(120, 28)))
                {
                    Task.Run(() => EjectDll());
                }

                ImGui.SameLine();
                if (ImGui.Button("💀 FORCE EJECT", new Vector2(120, 28)))
                {
                    Task.Run(() => ForceEjectDllAsync());
                }

                if (ImGui.IsItemHovered())
                    ImGui.SetTooltip("Force eject using FreeLibrary - use if graceful eject fails");

                if (_hInjectedModule != IntPtr.Zero)
                {
                    ImGui.TextColored(new Vector4(0.6f, 0.6f, 0.6f, 1f),
                        $"Module handle: 0x{_hInjectedModule:X}");
                }

                ImGui.Checkbox("Auto-eject on menu close", ref _forceEjectOnClose);
                ImGui.Checkbox("Auto-eject on pipe disconnect", ref _autoEjectOnDisconnect);
            }
        }

        private void RenderPipeStatus()
        {
            if (_pipe.DllConnected)
            {
                ImGui.TextColored(new Vector4(0.1f, 1f, 0.4f, 1f),
                    $"● HOOK LIVE — {_pipe.PacketCount} packets captured from inside Hytale");
            }
            else if (_pipe.IsRunning)
            {
                ImGui.TextColored(new Vector4(0.9f, 0.7f, 0.1f, 1f),
                    "◌ Pipe server running — inject the DLL then this banner turns green");
            }
            else
            {
                ImGui.TextColored(new Vector4(0.8f, 0.2f, 0.2f, 1f), "● Pipe server not running");
                if (ImGui.SmallButton("Start pipe server")) _pipe.Start();
            }
        }

        private async Task DoInjectAsync()
        {
            if (_selProc < 0 || _selProc >= _procs.Count) return;
            if (_selDll < 0 || _selDll >= _dllPaths.Length) return;

            var (pid, pname, _) = _procs[_selProc];
            string dllPath = Path.GetFullPath(_dllPaths[_selDll]);

            if (!File.Exists(dllPath))
            {
                SetStatus($"DLL not found: {dllPath}", 1f, 0.3f, 0.3f);
                return;
            }

            SetStatus($"Injecting into {pname} (PID {pid})…", 0.9f, 0.7f, 0.2f);
            _state.AddInGameLog($"[INJECT] → {pname} ({pid})  |  {Path.GetFileName(dllPath)}");

            try
            {
                var result = await Task.Run(() =>
                {
                    try
                    {
                        IntPtr hProc = OpenProcess(PROCESS_ALL, false, pid);
                        if (hProc == IntPtr.Zero)
                            return new InjectResult { Success = false, Warning = false, Error = $"OpenProcess failed (err {Marshal.GetLastWin32Error()}). Try running HyForce as Administrator." };

                        try
                        {
                            byte[] pathBytes = System.Text.Encoding.Unicode.GetBytes(dllPath + "\0");
                            IntPtr mem = VirtualAllocEx(hProc, IntPtr.Zero,
                                (uint)pathBytes.Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                            if (mem == IntPtr.Zero)
                                return new InjectResult { Success = false, Warning = false, Error = $"VirtualAllocEx failed (err {Marshal.GetLastWin32Error()})" };

                            if (!WriteProcessMemory(hProc, mem, pathBytes, (uint)pathBytes.Length, out _))
                            {
                                VirtualFreeEx(hProc, mem, 0, MEM_RELEASE);
                                return new InjectResult { Success = false, Warning = false, Error = $"WriteProcessMemory failed (err {Marshal.GetLastWin32Error()})" };
                            }

                            IntPtr k32 = GetModuleHandleW("kernel32.dll");
                            IntPtr loadLib = GetProcAddress(k32, "LoadLibraryW");
                            if (loadLib == IntPtr.Zero)
                                return new InjectResult { Success = false, Warning = false, Error = "LoadLibraryW not found in kernel32" };

                            uint tid;
                            IntPtr hThread = CreateRemoteThread(hProc, IntPtr.Zero, 0, loadLib, mem, 0, out tid);
                            if (hThread == IntPtr.Zero)
                                return new InjectResult { Success = false, Warning = false, Error = $"CreateRemoteThread failed (err {Marshal.GetLastWin32Error()})" };

                            // Use shorter timeout or don't wait at all
                            uint waitRes = WaitForSingleObject(hThread, 500); // 500ms max

                            CloseHandle(hThread);
                            VirtualFreeEx(hProc, mem, 0, MEM_RELEASE);

                            if (waitRes == 0x102) // WAIT_TIMEOUT
                                return new InjectResult { Success = true, Warning = true, Error = "Timeout - DLL may still be initializing" };
                            else if (waitRes == 0) // WAIT_OBJECT_0
                                return new InjectResult { Success = true, Warning = false, Error = null };
                            else
                                return new InjectResult { Success = false, Warning = false, Error = $"Wait failed (result {waitRes})" };
                        }
                        finally
                        {
                            CloseHandle(hProc);
                        }
                    }
                    catch (Exception ex)
                    {
                        return new InjectResult { Success = false, Warning = false, Error = $"Exception: {ex.Message}" };
                    }
                });

                // Update UI on main thread
                if (result.Success)
                {
                    _injected = true;
                    _injectedPid = pid;
                    if (result.Warning)
                    {
                        SetStatus($"DLL injected (timeout - may still be connecting)", 0.9f, 0.6f, 0.2f);
                        _state.AddInGameLog($"[INJECT] ⚠ Timeout - DLL may still initialize");
                    }
                    else
                    {
                        SetStatus($"✓ Injected into {pname} ({pid})", 0.2f, 1f, 0.4f);
                        _state.AddInGameLog($"[INJECT] ✓ Success — {pname} ({pid})");
                    }
                    _state.AddInGameLog("[INJECT] Watch the pipe banner - turns green when DLL connects");
                }
                else
                {
                    SetStatus($"✗ {result.Error}", 1f, 0.2f, 0.2f);
                    _state.AddInGameLog($"[INJECT] FAIL: {result.Error}");
                }
            }
            catch (Exception ex)
            {
                SetStatus($"✗ {ex.Message}", 1f, 0.2f, 0.2f);
                _state.AddInGameLog($"[INJECT] FAIL: {ex.Message}");
            }
        }

        // Helper class for result - add this inside InjectionTab class
        private class InjectResult
        {
            public bool Success { get; set; }
            public bool Warning { get; set; }
            public string Error { get; set; }
        }

        private void RefreshProcs()
        {
            _lastRefresh = DateTime.Now;
            var list = new List<(int, string, bool)>();

            foreach (var p in Process.GetProcesses())
            {
                IntPtr hProc = IntPtr.Zero; // Track handle for cleanup
                try
                {
                    bool is64 = true;
                    try
                    {
                        // Open with minimal rights for IsWow64Process
                        hProc = OpenProcess(0x1000, false, p.Id); // PROCESS_QUERY_LIMITED_INFORMATION
                        if (hProc != IntPtr.Zero)
                        {
                            if (IsWow64Process(hProc, out bool wow64))
                            {
                                if (wow64) is64 = false;
                            }
                        }
                    }
                    catch { /* ignore - assume 64-bit */ }
                    finally
                    {
                        // ALWAYS close handle
                        if (hProc != IntPtr.Zero)
                            CloseHandle(hProc);
                    }

                    string pname = p.ProcessName.ToLowerInvariant();
                    bool isHytaleJava = (pname.Contains("java") || pname.Contains("javaw"))
                        && p.WorkingSet64 > 100 * 1024 * 1024;

                    list.Add((p.Id, p.ProcessName, is64));
                }
                catch { /* ignore processes we can't access */ }
                finally
                {
                    // ALWAYS dispose Process object
                    p.Dispose();
                }
            }

            _procs = list
                .OrderByDescending(x =>
                {
                    string name = x.Item2.ToLowerInvariant();
                    if ((name.Contains("java") || name.Contains("javaw")) &&
                        Process.GetProcessById(x.Item1).WorkingSet64 > 200 * 1024 * 1024)
                        return 3;
                    if (name.Contains("hytale")) return 2;
                    if (name.Contains("java")) return 1;
                    return 0;
                })
                .ThenBy(x => x.Item2)
                .ToList();
        }

        private void RefreshDlls()
        {
            if (!Directory.Exists(_dllFolder))
            { _dllPaths = Array.Empty<string>(); _dllNames = Array.Empty<string>(); return; }
            _dllPaths = Directory.GetFiles(_dllFolder, "*.dll");
            _dllNames = _dllPaths.Select(Path.GetFileName).ToArray()!;
            if (_selDll >= _dllNames.Length) _selDll = 0;
        }

        private void SetStatus(string msg, float r, float g, float b)
        { _injectStatus = msg; _injectColor = new Vector4(r, g, b, 1f); }

        private void EjectDll()
        {
            if (!_injected || _injectedPid < 0)
            {
                SetStatus("No DLL to eject", 1f, 0.3f, 0.3f);
                return;
            }

            SetStatus($"Ejecting from PID {_injectedPid}...", 0.9f, 0.7f, 0.2f);
            _state.AddInGameLog($"[EJECT] Graceful eject from PID {_injectedPid}");

            try
            {
                IntPtr hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_LIMITED,
                    false, _injectedPid);

                if (hProc == IntPtr.Zero)
                {
                    SetStatus("Target process not accessible, cleaning up state", 0.9f, 0.5f, 0.2f);
                    ResetInjectionState();
                    return;
                }

                IntPtr hKernel32 = GetModuleHandleW("kernel32.dll");
                IntPtr pFreeLibrary = GetProcAddress(hKernel32, "FreeLibrary");

                IntPtr hModule = FindModuleInProcess(hProc, Path.GetFileName(_dllPaths[_selDll]));

                if (hModule == IntPtr.Zero)
                {
                    SetStatus("DLL not found in target process (may already be unloaded)", 0.9f, 0.5f, 0.2f);
                    CloseHandle(hProc);
                    ResetInjectionState();
                    return;
                }

                uint tid;
                IntPtr hThread = CreateRemoteThread(hProc, IntPtr.Zero, 0, pFreeLibrary, hModule, 0, out tid);

                if (hThread == IntPtr.Zero)
                {
                    SetStatus($"CreateRemoteThread failed: {Marshal.GetLastWin32Error()}", 1f, 0.2f, 0.2f);
                    CloseHandle(hProc);
                    return;
                }

                uint waitResult = WaitForSingleObject(hThread, 5000);

                if (waitResult == 0x102)
                {
                    SetStatus("Ejection timed out, trying force eject...", 1f, 0.5f, 0.2f);
                    TerminateThread(hThread, 1);
                    CloseHandle(hThread);
                    CloseHandle(hProc);
                    ForceEjectDllAsync();
                    return;
                }

                uint exitCode;
                if (GetExitCodeThread(hThread, out exitCode) && exitCode != 0)
                {
                    SetStatus($"✓ DLL ejected successfully (FreeLibrary returned {exitCode})", 0.2f, 1f, 0.4f);
                    _state.AddInGameLog($"[EJECT] Success - DLL unloaded from PID {_injectedPid}");
                }
                else
                {
                    SetStatus("FreeLibrary returned 0, DLL may still be loaded", 1f, 0.5f, 0.2f);
                }

                CloseHandle(hThread);
                CloseHandle(hProc);

                _pipe.SendCommand("STOP");
                Thread.Sleep(100);

                ResetInjectionState();
            }
            catch (Exception ex)
            {
                SetStatus($"Ejection error: {ex.Message}", 1f, 0.2f, 0.2f);
                _state.AddInGameLog($"[EJECT] Error: {ex.Message}");
            }
        }

        private async Task ForceEjectDllAsync()
        {
            await Task.Run(() =>
            {
                try
                {
                    _pipe.SendCommand("STOP");
                    Thread.Sleep(200);
                }
                catch { }
            });

            // Update UI state on main thread
            ResetInjectionState();
        }

        private IntPtr FindModuleInProcess(IntPtr hProcess, string moduleName)
        {
            IntPtr[] modules = new IntPtr[1024];
            uint cbNeeded;

            if (!EnumProcessModules(hProcess, modules, (uint)(modules.Length * IntPtr.Size), out cbNeeded))
                return IntPtr.Zero;

            int numModules = (int)(cbNeeded / IntPtr.Size);
            byte[] nameBuffer = new byte[256];

            for (int i = 0; i < numModules; i++)
            {
                uint len = GetModuleBaseNameA(hProcess, modules[i], nameBuffer, (uint)nameBuffer.Length);
                if (len > 0)
                {
                    string name = System.Text.Encoding.ASCII.GetString(nameBuffer, 0, (int)len);
                    if (name.Equals(moduleName, StringComparison.OrdinalIgnoreCase))
                    {
                        return modules[i];
                    }
                }
            }

            return IntPtr.Zero;
        }

        

        private void RenderWinDivertHelp()
        {
            if (ImGui.CollapsingHeader("WinDivert Setup Guide"))
            {
                ImGui.PushTextWrapPos(ImGui.GetContentRegionAvail().X);
                ImGui.TextColored(new Vector4(0.7f, 0.7f, 0.7f, 1f), @"
                    1. DOWNLOAD WinDivert:
                        https://reqrypt.org/windivert.html

                    2. EXTRACT these files next to HyForce.exe:
                       - WinDivert.dll (user-mode library)
                       - WinDivert.sys (32-bit driver)
                       - WinDivert64.sys (64-bit driver)

                    3. RUN HyForce as Administrator:
                       Right-click HyForce.exe → 'Run as administrator'
                       (Required for kernel driver access)

                    4. JOIN a Hytale server - packets appear automatically

                    TROUBLESHOOTING:
                    - 'Failed to open WinDivert handle' = Not running as Admin
                    - 'WinDivert.dll not found' = DLL not in correct location
                    - 0 packets after joining server = Check Windows Firewall isn't blocking
");
                ImGui.PopTextWrapPos();
            }
        }

        private static void RenderHelp()
        {
            ImGui.PushTextWrapPos(ImGui.GetContentRegionAvail().X);
            ImGui.TextColored(new Vector4(0.7f, 0.7f, 0.7f, 1f), @"
BUILD HyForceHook.dll
  1. Open the HyForceHook\ folder (next to this .exe).
  2. Open 'x64 Native Tools Command Prompt for VS 20xx'
     (Search 'x64 Native Tools' in Windows start menu)
     -- OR install MinGW-w64 (https://www.mingw-w64.org) and add its bin\ to PATH.
  3. cd into HyForceHook\, run:  build.bat
  4. Copy HyForceHook.dll to:  %APPDATA%\HyForce\DLLs\
     (click 'Open' button above to open that folder)

WORKFLOW
  1. Start HyForce.  Pipe servers start automatically.
  2. Start Hytale and log in / join a server.
  3. In the process list above, select the Hytale process.
     It will be highlighted green. Use the filter box to type 'hytale'.
  4. Select HyForceHook.dll in Step 1.
  5. Click 'Inject DLL'.
  6. The pipe banner turns green within ~1 second if it worked.
  7. Every UDP packet Hytale sends/receives now appears in the Packet Feed tab.

TROUBLESHOOTING
  - 'OpenProcess failed': right-click HyForce.exe → Run as Administrator
  - 'Remote thread timed out': the DLL crashed — check architecture (x64 vs x86)
  - Pipe stays yellow after inject: send PING and watch the log tab for a PONG reply
  - 32-bit Hytale: rebuild DLL as 32-bit:
      MSVC: cl /O2 /LD HyForceHook.c /Fe:HyForceHook32.dll ws2_32.lib
      gcc:  gcc -O2 -shared -m32 -o HyForceHook32.dll HyForceHook.c -lws2_32

HOOK FIRE STATS (important for diagnosing 0 packets)
  Click 'Get STATS' button. The DLL replies with counts like:
    WSASendTo:0 sendto:142 WSARecvFrom:0 recvfrom:99
  If sendto/recvfrom > 0 but packets not showing: check packet size filter (fixed in v22).
  If ALL counts are 0: Hytale uses IOCP (async I/O) — DLL hooks don't intercept it.

WINDIVERT FALLBACK (if DLL hooks show 0 fires)
  WinDivert is a kernel-level packet capture driver — catches ALL UDP regardless
  of whether the app uses WSASendTo, sendto, or async IOCP.
  
  Setup:
    1. Download WinDivert from: https://reqrypt.org/windivert.html
    2. Extract WinDivert.dll + WinDivert.sys + WinDivert64.sys to HyForce folder
    3. Run HyForce as Administrator (WinDivert needs admin)
    4. WinDivert capture appears automatically in Packet Feed
       (HyForce will attempt WinDivert if DLL packet count stays at 0 after 30s)
");
            ImGui.PopTextWrapPos();
        }
    }
}