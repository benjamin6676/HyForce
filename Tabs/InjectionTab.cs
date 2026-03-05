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
using System.Threading.Tasks;

namespace HyForce.Tabs
{
    public class InjectionTab : ITab
    {
        public string Name => "Injection";
        private readonly AppState _state;
        private PipeCaptureServer? _pipeServer;

        private List<(int pid, string name)> _processes = new();
        private int _selectedProc = -1;
        private DateTime _lastRefresh = DateTime.MinValue;

        private string[] _dllPaths = Array.Empty<string>();
        private string[] _dllNames = Array.Empty<string>();
        private int _selectedDll = 0;
        private string _dllFolder = "";

        private string _status = "";
        private Vector4 _statusColor = new(0.6f, 0.6f, 0.6f, 1f);
        private bool _injected = false;
        private int _injectedPid = -1;
        private bool _pipeActive = false;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualAllocEx(IntPtr proc, IntPtr addr, uint size, uint type, uint protect);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr proc, IntPtr addr, byte[] buf, uint size, out uint written);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateRemoteThread(IntPtr proc, IntPtr attr, uint stack, IntPtr fn, IntPtr param, uint flags, out uint tid);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr handle, uint ms);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr module, string procName);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr GetModuleHandleW(string name);

        private const uint PROCESS_ALL    = 0x1F0FFF;
        private const uint MEM_COMMIT     = 0x1000;
        private const uint MEM_RESERVE    = 0x2000;
        private const uint PAGE_READWRITE = 0x04;

        public InjectionTab(AppState state)
        {
            _state = state;
            _dllFolder = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "HyForce", "DLLs");
            Directory.CreateDirectory(_dllFolder);
            RefreshDllList();

            _pipeServer = new PipeCaptureServer(state);
            _pipeServer.OnPacketReceived += pkt =>
            {
                state.OnHookPacket(pkt);
                _pipeActive = true;
            };
            _pipeServer.Start();
        }

        public void Render()
        {
            ImGui.TextColored(new Vector4(0.4f, 0.8f, 1f, 1f), "DLL Injection  —  WinSock Hook");
            ImGui.SameLine();
            ImGui.TextColored(new Vector4(0.5f, 0.5f, 0.5f, 1f),
                "(captures packets inside Hytale JVM — no proxy needed)");
            ImGui.Separator();
            ImGui.Spacing();

            bool pipeConnected = _pipeServer?.IsRunning == true && _pipeActive;
            if (pipeConnected)
                ImGui.TextColored(new Vector4(0.1f, 1f, 0.4f, 1f),
                    $"HOOK ACTIVE — {_pipeServer!.PacketsReceived} packets captured via pipe");
            else if (_pipeServer?.IsRunning == true)
                ImGui.TextColored(new Vector4(0.9f, 0.7f, 0.1f, 1f),
                    "Pipe server running — waiting for DLL to connect...");
            else
                ImGui.TextColored(new Vector4(0.7f, 0.2f, 0.2f, 1f), "Pipe server not running");

            ImGui.Spacing();

            // ── Step 1: DLL folder ──
            ImGui.TextColored(new Vector4(0.8f, 0.8f, 0.4f, 1f), "Step 1 — Place DLLs");
            ImGui.Text($"Drop DLL files into:  {_dllFolder}");
            ImGui.SameLine();
            if (ImGui.SmallButton("Open Folder"))
                try { Process.Start("explorer.exe", _dllFolder); } catch { }
            ImGui.SameLine();
            if (ImGui.SmallButton("Refresh##dlls")) RefreshDllList();

            ImGui.Spacing();
            if (_dllNames.Length == 0)
            {
                ImGui.TextColored(new Vector4(0.8f, 0.4f, 0.2f, 1f),
                    "No DLLs found — build HyForceHook.dll and copy it here.");
            }
            else
            {
                ImGui.Text($"Available DLLs ({_dllNames.Length}):");
                ImGui.SetNextItemWidth(420);
                ImGui.Combo("##dll", ref _selectedDll, _dllNames, _dllNames.Length);
                if (_selectedDll >= 0 && _selectedDll < _dllPaths.Length)
                {
                    var fi = new FileInfo(_dllPaths[_selectedDll]);
                    ImGui.TextColored(new Vector4(0.5f, 0.5f, 0.5f, 1f),
                        $"  {fi.Length / 1024}KB   {fi.LastWriteTime:HH:mm:ss}");
                }
            }

            ImGui.Spacing();
            ImGui.Separator();
            ImGui.Spacing();

            // ── Step 2: process list ──
            ImGui.TextColored(new Vector4(0.8f, 0.8f, 0.4f, 1f), "Step 2 — Select Process");
            if ((DateTime.Now - _lastRefresh).TotalSeconds > 3) RefreshProcesses();

            if (ImGui.BeginListBox("##procs", new Vector2(520, 130)))
            {
                for (int i = 0; i < _processes.Count; i++)
                {
                    var (pid, pname) = _processes[i];
                    bool sel    = _selectedProc == i;
                    bool isJava = pname.StartsWith("java",   StringComparison.OrdinalIgnoreCase)
                               || pname.StartsWith("hytale", StringComparison.OrdinalIgnoreCase);
                    if (isJava) ImGui.PushStyleColor(ImGuiCol.Text, new Vector4(0.4f, 1f, 0.6f, 1f));
                    if (ImGui.Selectable($"[{pid,6}]  {pname}##p{i}", sel))
                        _selectedProc = i;
                    if (isJava) ImGui.PopStyleColor();
                }
                ImGui.EndListBox();
            }
            ImGui.SameLine();
            if (ImGui.Button("Refresh\nList", new Vector2(72, 40))) RefreshProcesses();

            ImGui.Spacing();
            ImGui.Separator();
            ImGui.Spacing();

            // ── Step 3: Inject ──
            ImGui.TextColored(new Vector4(0.8f, 0.8f, 0.4f, 1f), "Step 3 — Inject");
            bool canInject = !_injected
                          && _selectedProc >= 0 && _selectedProc < _processes.Count
                          && _dllPaths.Length > 0 && _selectedDll < _dllPaths.Length;

            if (!canInject && !_injected) ImGui.BeginDisabled();

            if (!_injected)
            {
                if (ImGui.Button("  Inject DLL  ", new Vector2(140, 34)))
                    Task.Run(DoInject);
            }
            else
            {
                ImGui.TextColored(new Vector4(0.1f, 1f, 0.4f, 1f),
                    $"Injected into PID {_injectedPid}");
                ImGui.SameLine();
                if (ImGui.Button("Clear status"))
                {
                    _injected = false; _injectedPid = -1;
                    _pipeActive = false; _status = "";
                }
            }

            if (!canInject && !_injected) ImGui.EndDisabled();

            ImGui.Spacing();
            if (!string.IsNullOrEmpty(_status))
                ImGui.TextColored(_statusColor, _status);

            ImGui.Spacing();
            ImGui.Separator();
            ImGui.Spacing();

            // ── How-to ──
            if (ImGui.CollapsingHeader("Build instructions & workflow"))
            {
                ImGui.PushTextWrapPos(ImGui.GetContentRegionAvail().X);
                ImGui.TextColored(new Vector4(0.75f, 0.75f, 0.75f, 1f),
@"BUILD HyForceHook.dll
  1. Open the HyForceHook\ folder alongside this .exe.
  2. Open 'x64 Native Tools Command Prompt for VS 20xx'
     (or use MinGW-w64 with gcc in PATH).
  3. Run:  build.bat
  4. Copy HyForceHook.dll to %APPDATA%\HyForce\DLLs\

WORKFLOW (no proxy needed)
  1. Start HyForce.
  2. Start Hytale and connect to a server.
  3. Select the java/javaw process in the list above.
  4. Select HyForceHook.dll in the dropdown.
  5. Click 'Inject DLL'.
  6. Pipe banner turns green — ALL future packets are captured.
  7. Go to Decryption tab — keys and packets now come from the same
     TLS session so decryption should succeed.

WHY THIS BEATS THE PROXY
  The proxy requires Hytale to connect THROUGH it.  If you start the game
  before HyForce, the captured packets come from a different TLS session
  than the logged keys — they never match.  The DLL hooks WinSock inside
  the JVM so there is no timing dependency at all.");
                ImGui.PopTextWrapPos();
            }
        }

        private void DoInject()
        {
            if (_selectedProc < 0 || _selectedProc >= _processes.Count) return;
            if (_selectedDll < 0 || _selectedDll >= _dllPaths.Length) return;

            var (pid, pname) = _processes[_selectedProc];
            string dllPath   = Path.GetFullPath(_dllPaths[_selectedDll]);

            if (!File.Exists(dllPath))
            { SetStatus($"DLL not found: {dllPath}", 1f, 0.3f, 0.3f); return; }

            SetStatus($"Injecting into {pname} (PID {pid})...", 0.9f, 0.7f, 0.2f);
            _state.AddInGameLog($"[INJECT] Targeting {pname} ({pid}) | {Path.GetFileName(dllPath)}");

            try
            {
                IntPtr hProc = OpenProcess(PROCESS_ALL, false, pid);
                if (hProc == IntPtr.Zero)
                    throw new Exception($"OpenProcess error {Marshal.GetLastWin32Error()}");

                byte[] pathBytes = System.Text.Encoding.Unicode.GetBytes(dllPath + "\0");
                IntPtr mem = VirtualAllocEx(hProc, IntPtr.Zero,
                    (uint)pathBytes.Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (mem == IntPtr.Zero)
                    throw new Exception($"VirtualAllocEx error {Marshal.GetLastWin32Error()}");

                if (!WriteProcessMemory(hProc, mem, pathBytes, (uint)pathBytes.Length, out _))
                    throw new Exception($"WriteProcessMemory error {Marshal.GetLastWin32Error()}");

                IntPtr kernel32 = GetModuleHandleW("kernel32.dll");
                IntPtr loadLib  = GetProcAddress(kernel32, "LoadLibraryW");
                if (loadLib == IntPtr.Zero)
                    throw new Exception("LoadLibraryW not found");

                IntPtr hThread = CreateRemoteThread(
                    hProc, IntPtr.Zero, 0, loadLib, mem, 0, out _);
                if (hThread == IntPtr.Zero)
                    throw new Exception($"CreateRemoteThread error {Marshal.GetLastWin32Error()}");

                WaitForSingleObject(hThread, 5000);
                CloseHandle(hThread);
                CloseHandle(hProc);

                _injected    = true;
                _injectedPid = pid;
                SetStatus($"Injected into {pname} ({pid}) — pipe should connect shortly.", 0.2f, 1f, 0.4f);
                _state.AddInGameLog($"[INJECT] Success — {pname} ({pid})");
            }
            catch (Exception ex)
            {
                SetStatus($"Injection failed: {ex.Message}", 1f, 0.2f, 0.2f);
                _state.AddInGameLog($"[INJECT] FAIL: {ex.Message}");
            }
        }

        private void RefreshProcesses()
        {
            _lastRefresh = DateTime.Now;
            var list = new List<(int, string)>();
            foreach (var p in Process.GetProcesses())
            {
                try { list.Add((p.Id, p.ProcessName)); } catch { }
                finally { p.Dispose(); }
            }
            _processes = list
                .OrderByDescending(x =>
                    x.Item2.StartsWith("java",   StringComparison.OrdinalIgnoreCase) ||
                    x.Item2.StartsWith("hytale", StringComparison.OrdinalIgnoreCase))
                .ThenBy(x => x.Item2)
                .ToList();
        }

        private void RefreshDllList()
        {
            if (!Directory.Exists(_dllFolder))
            { _dllPaths = Array.Empty<string>(); _dllNames = Array.Empty<string>(); return; }
            _dllPaths = Directory.GetFiles(_dllFolder, "*.dll");
            _dllNames = _dllPaths.Select(Path.GetFileName).ToArray()!;
            if (_selectedDll >= _dllNames.Length) _selectedDll = 0;
        }

        private void SetStatus(string msg, float r, float g, float b)
        { _status = msg; _statusColor = new Vector4(r, g, b, 1f); }
    }
}
