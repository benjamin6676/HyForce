// MemoryToggleSystem.cs
// Modular, named, hotkey-bound memory value toggles.
// Each toggle: name, address, type, value to write, hotkey, favorite flag,
//              on/off state, change log, repeat interval.
//
// Pipe commands it emits:
//   MEMWRITE_F32 <addr> <val>
//   MEMWRITE_F64 <addr> <val>
//   MEMWRITE_I32 <addr> <val>
//   MEMREAD <addr> 8      → confirms value was written
//   FLYMODE <addr> 1/0

using HyForce.Networking;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading;

namespace HyForce.Core
{
    public enum ToggleValueType { Float32, Float64, Int32, Byte, FlyMode }

    public class MemoryToggleEntry
    {
        public Guid   Id           { get; set; } = Guid.NewGuid();
        public string Name         { get; set; } = "New Toggle";
        public string AddressHex   { get; set; } = "";
        public ToggleValueType ValueType { get; set; } = ToggleValueType.Float32;

        // The value written when toggle is ON
        public double WriteValue   { get; set; } = 100.0;
        // Hotkey as string e.g. "F8", "X", "F1"
        public string HotkeyStr    { get; set; } = "";
        public bool   Favorite     { get; set; } = false;
        public bool   Enabled      { get; set; } = false;          // currently ON
        public bool   AutoRepeat   { get; set; } = false;          // keep writing every RepeatMs
        public int    RepeatMs     { get; set; } = 200;
        public bool   LogChanges   { get; set; } = true;

        // Runtime (not serialised)
        [System.Text.Json.Serialization.JsonIgnore]
        public List<ToggleLogEntry> ChangeLog { get; } = new();
        [System.Text.Json.Serialization.JsonIgnore]
        public string LastReadHex  { get; set; } = "?";
        [System.Text.Json.Serialization.JsonIgnore]
        public DateTime LastWriteAt{ get; set; } = DateTime.MinValue;
        [System.Text.Json.Serialization.JsonIgnore]
        public bool Dirty          { get; set; } = false; // UI changed something

        public ulong ParseAddress()
        {
            string s = AddressHex.TrimStart('0', 'x', 'X').Trim();
            return ulong.TryParse(s, System.Globalization.NumberStyles.HexNumber, null, out var v) ? v : 0;
        }
    }

    public class ToggleLogEntry
    {
        public DateTime Timestamp  { get; set; } = DateTime.Now;
        public string   Action     { get; set; } = "";   // "WRITE", "READ_CONFIRM", "MISMATCH"
        public string   Details    { get; set; } = "";
    }

    // ─── Hotkey registration (Win32 RegisterHotKey) ─────────────────────────
    public static class HotkeyParser
    {
        // Returns (VK, MOD) — MOD always 0 for simple keys
        public static (uint vk, uint mod) Parse(string s)
        {
            if (string.IsNullOrWhiteSpace(s)) return (0, 0);
            s = s.Trim().ToUpperInvariant();
            if (s.StartsWith("F") && int.TryParse(s[1..], out int fn) && fn >= 1 && fn <= 24)
                return ((uint)(0x6F + fn), 0); // VK_F1 = 0x70
            if (s.Length == 1 && s[0] >= 'A' && s[0] <= 'Z')
                return ((uint)s[0], 0);
            // Named keys
            return s switch
            {
                "INS"    or "INSERT"   => (0x2D, 0),
                "DEL"    or "DELETE"   => (0x2E, 0),
                "HOME"                 => (0x24, 0),
                "END"                  => (0x23, 0),
                "PGUP"                 => (0x21, 0),
                "PGDN"                 => (0x22, 0),
                "NUMPAD0"              => (0x60, 0),
                "NUMPAD1"              => (0x61, 0),
                "NUMPAD2"              => (0x62, 0),
                "NUMPAD3"              => (0x63, 0),
                "NUMPAD4"              => (0x64, 0),
                "NUMPAD5"              => (0x65, 0),
                "NUMPAD6"              => (0x66, 0),
                "NUMPAD7"              => (0x67, 0),
                "NUMPAD8"              => (0x68, 0),
                "NUMPAD9"              => (0x69, 0),
                _                     => (0, 0)
            };
        }
    }

    public class MemoryToggleSystem : IDisposable
    {
        private readonly AppState          _state;
        private readonly PipeCaptureServer _pipe;
        private readonly List<MemoryToggleEntry> _toggles = new();
        private readonly object _lock = new();
        private readonly string _saveFile;
        private Thread?  _repeatThread;
        private Thread?  _hotkeyThread;
        private volatile bool _running = true;

        // Win32 hotkey registration (message-only window approach)
        [DllImport("user32.dll")] static extern bool RegisterHotKey(IntPtr hWnd, int id, uint fsModifiers, uint vk);
        [DllImport("user32.dll")] static extern bool UnregisterHotKey(IntPtr hWnd, int id);
        [DllImport("user32.dll")] static extern int GetMessage(out MSG msg, IntPtr hWnd, uint min, uint max);
        [DllImport("user32.dll")] static extern void TranslateMessage(ref MSG msg);
        [DllImport("user32.dll")] static extern IntPtr DispatchMessage(ref MSG msg);
        [DllImport("user32.dll")] static extern IntPtr CreateWindowExW(uint dwExStyle, string lpClassName,
            string lpWindowName, uint dwStyle, int x, int y, int nWidth, int nHeight,
            IntPtr hWndParent, IntPtr hMenu, IntPtr hInstance, IntPtr lpParam);
        [DllImport("user32.dll")] static extern bool DestroyWindow(IntPtr hWnd);

        [StructLayout(LayoutKind.Sequential)]
        struct MSG { public IntPtr hwnd; public uint message; public IntPtr wParam; public IntPtr lParam; public uint time; public int ptX, ptY; }
        const uint WM_HOTKEY = 0x0312;
        const IntPtr HWND_MESSAGE = (IntPtr)(-3);

        private IntPtr _msgWnd = IntPtr.Zero;
        private readonly Dictionary<int, Guid> _hotkeyIdMap = new();
        private int _nextHotkeyId = 1000;

        public IReadOnlyList<MemoryToggleEntry> Toggles { get { lock(_lock) return _toggles.AsReadOnly(); } }

        public MemoryToggleSystem(AppState state, PipeCaptureServer pipe)
        {
            _state = state;
            _pipe  = pipe;
            _saveFile = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "HyForce", "toggles.json");
            Load();
            _repeatThread = new Thread(RepeatLoop) { IsBackground = true, Name = "HyForce-ToggleRepeat" };
            _repeatThread.Start();
            _hotkeyThread = new Thread(HotkeyLoop)  { IsBackground = true, Name = "HyForce-ToggleHotkey" };
            _hotkeyThread.Start();
        }

        // ── CRUD ────────────────────────────────────────────────────────────
        public MemoryToggleEntry AddToggle()
        {
            var e = new MemoryToggleEntry { Name = $"Toggle {_toggles.Count + 1}" };
            lock (_lock) _toggles.Add(e);
            Save();
            return e;
        }

        public void RemoveToggle(Guid id)
        {
            lock (_lock)
            {
                var t = _toggles.Find(x => x.Id == id);
                if (t != null) { UnregisterToggleHotkey(t); _toggles.Remove(t); }
            }
            Save();
        }

        public void UpdateToggle(MemoryToggleEntry t)
        {
            // Re-register hotkey if it changed
            UnregisterToggleHotkey(t);
            RegisterToggleHotkey(t);
            Save();
        }

        // ── Toggle ON/OFF ────────────────────────────────────────────────────
        public void SetEnabled(MemoryToggleEntry t, bool on)
        {
            t.Enabled = on;
            if (on) WriteValue(t);
            _state.AddInGameLog($"[TOGGLE] {t.Name} → {(on ? "ON" : "OFF")}");
            if (t.LogChanges)
                t.ChangeLog.Add(new ToggleLogEntry { Action = on ? "ENABLE" : "DISABLE",
                    Details = $"addr=0x{t.ParseAddress():X} val={t.WriteValue}" });
        }

        // ── Write ────────────────────────────────────────────────────────────
        public void WriteValue(MemoryToggleEntry t)
        {
            ulong addr = t.ParseAddress();
            if (addr == 0) { _state.AddInGameLog($"[TOGGLE] {t.Name}: invalid address"); return; }

            string cmd = t.ValueType switch
            {
                ToggleValueType.Float32 => $"MEMWRITE_F32 {addr:X} {(float)t.WriteValue:G9}",
                ToggleValueType.Float64 => $"MEMWRITE_F64 {addr:X} {t.WriteValue:G17}",
                ToggleValueType.Int32   => $"MEMWRITE_I32 {addr:X} {(int)t.WriteValue}",
                ToggleValueType.Byte    => $"MEMWRITE_I32 {addr:X} {(int)t.WriteValue & 0xFF}",
                ToggleValueType.FlyMode => $"FLYMODE {addr:X} 1",
                _                       => ""
            };
            if (!string.IsNullOrEmpty(cmd))
            {
                _pipe.SendCommand(cmd);
                t.LastWriteAt = DateTime.Now;
                if (t.LogChanges)
                    t.ChangeLog.Add(new ToggleLogEntry
                    {
                        Action  = "WRITE",
                        Details = $"cmd={cmd}"
                    });
            }

            // Schedule a read-back to confirm
            ThreadPool.QueueUserWorkItem(_ =>
            {
                Thread.Sleep(80);
                ReadBack(t);
            });
        }

        public void ReadBack(MemoryToggleEntry t)
        {
            ulong addr = t.ParseAddress();
            if (addr == 0) return;
            _pipe.SendCommand($"MEMREAD {addr:X} 8");
        }

        // Called by PipeCaptureServer when MSG_MEMREAD arrives
        public void OnMemReadResult(ulong addr, byte[] data)
        {
            lock (_lock)
            {
                foreach (var t in _toggles)
                {
                    if (t.ParseAddress() != addr) continue;
                    string hex = BitConverter.ToString(data).Replace("-", " ");
                    t.LastReadHex = hex;
                    // Verify value matches
                    bool match = false;
                    if (data.Length >= 4 && t.ValueType == ToggleValueType.Float32)
                    {
                        float actual = BitConverter.ToSingle(data, 0);
                        match = Math.Abs(actual - (float)t.WriteValue) < 0.01f;
                    }
                    else if (data.Length >= 8 && t.ValueType == ToggleValueType.Float64)
                    {
                        double actual = BitConverter.ToDouble(data, 0);
                        match = Math.Abs(actual - t.WriteValue) < 0.0001;
                    }
                    else if (data.Length >= 4 && t.ValueType == ToggleValueType.Int32)
                    {
                        int actual = BitConverter.ToInt32(data, 0);
                        match = actual == (int)t.WriteValue;
                    }

                    if (t.LogChanges)
                        t.ChangeLog.Add(new ToggleLogEntry
                        {
                            Action  = match ? "READ_CONFIRM" : "MISMATCH",
                            Details = $"raw=[{hex}]  match={match}"
                        });
                    break;
                }
            }
        }

        // ── Repeat loop: re-writes enabled auto-repeat toggles ───────────────
        private void RepeatLoop()
        {
            while (_running)
            {
                Thread.Sleep(50);
                lock (_lock)
                {
                    foreach (var t in _toggles)
                    {
                        if (!t.Enabled || !t.AutoRepeat) continue;
                        if ((DateTime.Now - t.LastWriteAt).TotalMilliseconds >= t.RepeatMs)
                            WriteValue(t);
                    }
                }
            }
        }

        // ── Hotkey message loop ──────────────────────────────────────────────
        private void HotkeyLoop()
        {
            // Create message-only window to receive WM_HOTKEY
            try
            {
                _msgWnd = CreateWindowExW(0, "STATIC", "HyForceHK", 0, 0, 0, 0, 0,
                    HWND_MESSAGE, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            }
            catch { return; }

            // Register all existing hotkeys
            lock (_lock)
                foreach (var t in _toggles)
                    RegisterToggleHotkey(t);

            while (_running)
            {
                int r = GetMessage(out MSG msg, _msgWnd, 0, 0);
                if (r == 0 || r == -1) break;
                if (msg.message == WM_HOTKEY)
                {
                    int hkId = (int)msg.wParam;
                    lock (_lock)
                    {
                        if (_hotkeyIdMap.TryGetValue(hkId, out Guid id))
                        {
                            var t = _toggles.Find(x => x.Id == id);
                            if (t != null) SetEnabled(t, !t.Enabled);
                        }
                    }
                }
                TranslateMessage(ref msg);
                DispatchMessage(ref msg);
            }

            if (_msgWnd != IntPtr.Zero) { DestroyWindow(_msgWnd); _msgWnd = IntPtr.Zero; }
        }

        private void RegisterToggleHotkey(MemoryToggleEntry t)
        {
            if (string.IsNullOrWhiteSpace(t.HotkeyStr) || _msgWnd == IntPtr.Zero) return;
            var (vk, mod) = HotkeyParser.Parse(t.HotkeyStr);
            if (vk == 0) return;
            int id = _nextHotkeyId++;
            if (RegisterHotKey(_msgWnd, id, mod, vk))
                _hotkeyIdMap[id] = t.Id;
        }

        private void UnregisterToggleHotkey(MemoryToggleEntry t)
        {
            foreach (var kv in new Dictionary<int,Guid>(_hotkeyIdMap))
            {
                if (kv.Value == t.Id)
                {
                    if (_msgWnd != IntPtr.Zero) UnregisterHotKey(_msgWnd, kv.Key);
                    _hotkeyIdMap.Remove(kv.Key);
                }
            }
        }

        // ── Persistence ──────────────────────────────────────────────────────
        public void Save()
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(_saveFile)!);
                lock (_lock)
                    File.WriteAllText(_saveFile,
                        JsonSerializer.Serialize(_toggles, new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { }
        }

        private void Load()
        {
            try
            {
                if (!File.Exists(_saveFile)) return;
                var loaded = JsonSerializer.Deserialize<List<MemoryToggleEntry>>(File.ReadAllText(_saveFile));
                if (loaded != null) { lock(_lock) { _toggles.Clear(); _toggles.AddRange(loaded); } }
            }
            catch { }
        }

        // ── Export summary for diagnostics ──────────────────────────────────
        public string ExportSummary()
        {
            var sb = new StringBuilder();
            lock (_lock)
            {
                sb.AppendLine($"=== Memory Toggles ({_toggles.Count}) ===");
                foreach (var t in _toggles)
                {
                    sb.AppendLine($"  [{(t.Favorite?"★":" ")}] {t.Name}");
                    sb.AppendLine($"    addr=0x{t.ParseAddress():X}  type={t.ValueType}  val={t.WriteValue}");
                    sb.AppendLine($"    hotkey={t.HotkeyStr}  enabled={t.Enabled}  autoRepeat={t.AutoRepeat}");
                    sb.AppendLine($"    lastWrite={t.LastWriteAt:HH:mm:ss.fff}  lastRead=[{t.LastReadHex}]");
                    sb.AppendLine($"    changeLog ({t.ChangeLog.Count} entries):");
                    foreach (var l in t.ChangeLog)
                        sb.AppendLine($"      {l.Timestamp:HH:mm:ss.fff} [{l.Action}] {l.Details}");
                }
            }
            return sb.ToString();
        }

        public void Dispose()
        {
            _running = false;
            if (_msgWnd != IntPtr.Zero) DestroyWindow(_msgWnd);
        }
    }
}
