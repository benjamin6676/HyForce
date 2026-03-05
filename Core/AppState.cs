// FILE: Core/AppState.cs - FIXED: Removed duplicate TryAutoDecryptPackets
using HyForce.Data;
using HyForce.Networking;
using HyForce.Protocol;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using static HyForce.PacketDecryptor;

namespace HyForce.Core;

public class AppState : IDisposable
{
    private static readonly Lazy<AppState> _instance = new(() => new AppState());
    public static AppState Instance => _instance.Value;

    public Config Config { get; } = new();
    public UdpProxy UdpProxy { get; }

    // FIX 2: Add TcpProxy property
    public TcpProxy TcpProxy { get; }

    public PacketLog PacketLog { get; }
    public Networking.DllPipeServer DllPipeServer { get; }
    public TestLog Log { get; }
    public PlayerItemDatabase Database { get; }

    public string TargetHost { get; set; } = "127.0.0.1";
    public int TargetPort { get; set; } = 5520;
    public int ListenPort { get; set; } = 5521;

    public bool IsRunning => UdpProxy.IsRunning || TcpProxy.IsRunning;
    public DateTime? StartTime { get; private set; }

    public long TotalPackets => PacketLog.TotalPackets;
    public long UdpPackets => PacketLog.PacketsUdp;
    // FIX 2: Add TcpPackets property
    public long TcpPackets => PacketLog.PacketsTcp;

    public ConcurrentBag<SecurityEvent> SecurityEvents { get; } = new();
    public bool ShowAboutWindow;

    public List<string> InGameLog { get; } = new();
    public const int MaxInGameLogLines = 1000;

    // ExportDirectory: defaults to %APPDATA%\HyForce\Exports (user-configurable in Settings)
    public string ExportDirectory { get; set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "HyForce", "Exports");
    // Working keys are sent to this file located in  ( %APPDATA%\HyForce )
    public string WorkingHytaleKeysPath => Path.Combine(
    Path.GetDirectoryName(PermanentKeyLogPath)!,
    "HytaleKeys.log");

    // SessionLogPath: auto-created per-session, dual-write with in-game log
    public string SessionLogPath { get; private set; } = string.Empty;
    private readonly object _sessionLogLock = new();

    public event PacketReceivedHandler? OnPacketReceived;
    public event Action? OnSecurityEvent;
    public event Action? OnMemoryDataUpdated;
    public event Action? OnKeysUpdated;

    private System.Timers.Timer? _autoDecryptTimer;
    private FileSystemWatcher? _sslKeyWatcher;
    private DateTime _lastKeyLoadTime     = DateTime.MinValue;
    private DateTime _sessionStartTime    = DateTime.MinValue;  // used for system key log import window
    private long     _sysKeyLogPosition   = 0;                  // file position for incremental reads
    private readonly object _keyLoadLock = new();
    private readonly Queue<string> _pendingKeyFiles = new();
    private readonly System.Timers.Timer _retryTimer;
    private readonly PacketReceivedHandler _packetHandlerDelegate;
    // FIX 2: Add TCP packet handler delegate
    private readonly PacketReceivedHandler _tcpPacketHandlerDelegate;
    private string? _activeKeyLogFile = null;

    // ── Permanent key log fields ──────────────────────────────────────────
    public  string PermanentKeyLogPath { get; private set; } = "";
    private long   _permFileReadPos    = 0;
    private bool   _permanentLogReady  = false;
    public  bool   NeedsFirstTimeSetup => !_permanentLogReady;

    public AppState()
    {
        DllPipeServer = new Networking.DllPipeServer(this);
        Log = new TestLog();
        UdpProxy = new UdpProxy(Log);
        // FIX 2: Initialize TcpProxy
        TcpProxy = new TcpProxy(Log);
        PacketLog = new PacketLog(10000);
        Database = new PlayerItemDatabase();

        _packetHandlerDelegate = HandlePacket;
        UdpProxy.OnPacket += _packetHandlerDelegate;

        // FIX 2: Subscribe to TCP packets
        _tcpPacketHandlerDelegate = HandlePacket;
        TcpProxy.OnPacket += _tcpPacketHandlerDelegate;

        Directory.CreateDirectory(ExportDirectory);
        // Create session log file immediately
        SessionLogPath = Path.Combine(ExportDirectory,
            $"hyforce_session_{DateTime.Now:yyyyMMdd_HHmmss}.log");

        SetupAutoDecryption();

        _retryTimer = new System.Timers.Timer(2000);
        _retryTimer.Elapsed += (s, e) => ProcessPendingKeyFiles();
        _retryTimer.AutoReset = true;
        _retryTimer.Start();

        // Permanent key log -- runs immediately so keys are ready before any UI interaction
        InitPermanentKeyLog();
    }

    public string? GetActiveKeyLogFile()
    {
        return _activeKeyLogFile;
    }

    // =========================================================================
    // PERMANENT KEY LOG  -- set-once / watch-forever
    // =========================================================================
    // Design:
    //   SSLKEYLOGFILE is written ONCE at User scope to a fixed path.
    //   From then on, every Hytale launch writes there automatically.
    //   HyForce watches the file from startup: keys arrive with zero manual steps.
    //   Only one-time requirement: restart Hytale once after the very first
    //   HyForce launch so the JVM picks up the new env var.

    private void InitPermanentKeyLog()
    {
        try
        {
            // ── Use a FIXED path in %APPDATA%\HyForce  ──────────────────────────────
            // This is INDEPENDENT of ExportDirectory so it never breaks when the user
            // changes the export folder in Settings. The JVM env-var always points here.
            string hyforceAppData = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "HyForce");
            Directory.CreateDirectory(hyforceAppData);
            PermanentKeyLogPath = Path.Combine(hyforceAppData, "sslkeys_permanent.log");

            string? existingUser = Environment.GetEnvironmentVariable("SSLKEYLOGFILE", EnvironmentVariableTarget.User);
            string? existingMachine = Environment.GetEnvironmentVariable("SSLKEYLOGFILE", EnvironmentVariableTarget.Machine);

            bool pointingAtOurs =
                string.Equals(existingUser, PermanentKeyLogPath, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(existingMachine, PermanentKeyLogPath, StringComparison.OrdinalIgnoreCase);

            if (!pointingAtOurs)
            {
                // Override: always force the permanent path even if something else was set before
                try
                {
                    Environment.SetEnvironmentVariable("SSLKEYLOGFILE", PermanentKeyLogPath, EnvironmentVariableTarget.User);
                    bool wasOldSession = existingUser?.Contains("sslkeys_session") == true;
                    if (wasOldSession)
                        AddInGameLog("[AUTOKEY] Cleared old session log pointer -> now using permanent log");
                    else
                        AddInGameLog("[AUTOKEY] Set SSLKEYLOGFILE -> sslkeys_permanent.log (User scope)");
                    AddInGameLog("[AUTOKEY] *** Restart Hytale ONCE to activate. After that: fully automatic. ***");
                    _permanentLogReady = false;
                }
                catch
                {
                    try
                    {
                        Environment.SetEnvironmentVariable("SSLKEYLOGFILE", PermanentKeyLogPath, EnvironmentVariableTarget.Machine);
                        AddInGameLog("[AUTOKEY] Set SSLKEYLOGFILE at Machine scope.");
                        _permanentLogReady = false;
                    }
                    catch (Exception ex2)
                    {
                        AddInGameLog($"[AUTOKEY] Cannot set env var ({ex2.Message}) -- run as Admin once.");
                    }
                }
            }
            else
            {
                _permanentLogReady = true;
                AddInGameLog("[AUTOKEY] Permanent key log already active -- fully automatic.");
            }

            Environment.SetEnvironmentVariable("SSLKEYLOGFILE", PermanentKeyLogPath, EnvironmentVariableTarget.Process);

            if (!File.Exists(PermanentKeyLogPath))
                File.WriteAllText(PermanentKeyLogPath, "# HyForce permanent SSL key log\r\n");

            // Watch our permanent log
            StartPermanentKeyWatcher();

            // ALSO watch the real system sslkeys.log live — Hytale may be writing there right now
            WatchAllKnownKeyFiles();

            Task.Run(async () =>
            {
                await Task.Delay(1200);
                // Import all existing key files immediately
                await ImportAllKnownKeyFiles();
                // Then also scan the permanent log
                ImportPermanentKeyLogFull("startup");
            });
        }
        catch (Exception ex)
        {
            AddInGameLog($"[AUTOKEY] Init error: {ex.Message}");
        }
    }

    // Set up FileSystemWatchers for all known key file locations
    private readonly List<FileSystemWatcher> _extraWatchers = new();

    private void WatchAllKnownKeyFiles()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var candidates = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            Path.Combine(home, "sslkeys.log"),
            Path.Combine(ExportDirectory, "sslkeys.log"),
        };

        // Also watch whatever SSLKEYLOGFILE currently points to
        foreach (var scope in new[] { EnvironmentVariableTarget.Machine, EnvironmentVariableTarget.User, EnvironmentVariableTarget.Process })
        {
            string? v = Environment.GetEnvironmentVariable("SSLKEYLOGFILE", scope);
            if (!string.IsNullOrEmpty(v)) candidates.Add(v);
        }

        foreach (var filePath in candidates)
        {
            if (string.IsNullOrEmpty(filePath)) continue;
            if (string.Equals(filePath, PermanentKeyLogPath, StringComparison.OrdinalIgnoreCase)) continue;

            try
            {
                string? dir  = Path.GetDirectoryName(filePath);
                string? file = Path.GetFileName(filePath);
                if (string.IsNullOrEmpty(dir) || string.IsNullOrEmpty(file)) continue;
                if (!Directory.Exists(dir)) continue;

                // Track position per file
                long pos = File.Exists(filePath) ? new FileInfo(filePath).Length : 0;

                var watcher = new FileSystemWatcher(dir)
                {
                    Filter              = file,
                    NotifyFilter        = NotifyFilters.LastWrite | NotifyFilters.Size,
                    EnableRaisingEvents = true
                };

                // Capture for closure
                string capturedPath = filePath;
                long   capturedPos  = pos;

                watcher.Changed += (_, _e) =>
                {
                    if ((DateTime.Now - _lastKeyLoadTime).TotalMilliseconds < 400) return;
                    _lastKeyLoadTime = DateTime.Now;
                    Task.Run(() =>
                    {
                        int added = ImportKeyFileIncremental(capturedPath, ref capturedPos);
                        if (added > 0)
                        {
                            AddInGameLog($"[AUTOKEY] Live +{added} key(s) from {Path.GetFileName(capturedPath)}");
                            OnKeysUpdated?.Invoke();
                        }
                    });
                };

                _extraWatchers.Add(watcher);
                if (File.Exists(filePath))
                    AddInGameLog($"[AUTOKEY] Watching {Path.GetFileName(filePath)} for live keys");
            }
            catch { /* skip files we can't watch */ }
        }
    }

    // Incremental read of any key file (not just permanent log)
    private int ImportKeyFileIncremental(string filePath, ref long position)
    {
        try
        {
            if (!File.Exists(filePath)) return 0;
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            if (fs.Length < position) position = 0;
            if (fs.Length == position) return 0;
            fs.Seek(position, SeekOrigin.Begin);
            using var rdr = new System.IO.StreamReader(fs, System.Text.Encoding.ASCII, leaveOpen: true);
            int added = 0;
            string? ln;
            while ((ln = rdr.ReadLine()) != null)
            {
                if (string.IsNullOrWhiteSpace(ln) || ln.StartsWith("#")) continue;
                if (!IsHytaleQuicKey(ln)) continue;
                var key = ParseSSLKeyLogLine(ln, filePath);
                if (key != null) { PacketDecryptor.AddKey(key); added++; }
            }
            position = fs.Length;
            return added;
        }
        catch { return 0; }
    }

    // Scan every plausible SSLKEYLOGFILE location and import QUIC keys from them
    private async Task ImportAllKnownKeyFiles()
    {
        var candidates = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // 1. Current user/machine env var (the real system log)
        foreach (var scope in new[] { EnvironmentVariableTarget.Machine, EnvironmentVariableTarget.User, EnvironmentVariableTarget.Process })
        {
            string? v = Environment.GetEnvironmentVariable("SSLKEYLOGFILE", scope);
            if (!string.IsNullOrEmpty(v)) candidates.Add(v);
        }

        // 2. Common hardcoded fallback locations
        string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        candidates.Add(Path.Combine(home, "sslkeys.log"));
        candidates.Add(Path.Combine(ExportDirectory, "sslkeys.log"));
        candidates.Add(PermanentKeyLogPath);

        int totalAdded = 0;
        foreach (var path in candidates)
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) continue;
            if (string.Equals(path, PermanentKeyLogPath, StringComparison.OrdinalIgnoreCase)) continue; // handled separately

            int added = ImportKeyFileOnce(path);
            if (added > 0)
            {
                AddInGameLog($"[AUTOKEY] Found {added} QUIC key(s) in {Path.GetFileName(path)}");
                totalAdded += added;
            }
        }

        if (totalAdded > 0)
        {
            AddInGameLog($"[AUTOKEY] Total from existing files: {totalAdded} key(s)");
            OnKeysUpdated?.Invoke();
            _permanentLogReady = true;
        }
    }

    // Import all QUIC keys from a file once (no position tracking)
    private int ImportKeyFileOnce(string filePath)
    {
        try
        {
            List<string> lines;
            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            using (var rdr = new System.IO.StreamReader(fs))
            {
                lines = new List<string>();
                string? ln;
                while ((ln = rdr.ReadLine()) != null)
                    if (!string.IsNullOrWhiteSpace(ln) && !ln.StartsWith("#"))
                        lines.Add(ln);
            }

            int added = 0;
            foreach (var line in lines)
            {
                if (!IsHytaleQuicKey(line)) continue;
                var key = ParseSSLKeyLogLine(line, filePath);
                if (key != null) { PacketDecryptor.AddKey(key); added++; }
            }
            return added;
        }
        catch { return 0; }
    }

    // Call this when you successfully decrypt a packet
    public void PromoteKeyToWorking(EncryptionKey key)
    {
        try
        {
            // Check if already in working file
            if (File.Exists(WorkingHytaleKeysPath))
            {
                var existing = File.ReadAllText(WorkingHytaleKeysPath);
                string keyLine = FormatKeyLine(key);
                if (existing.Contains(keyLine.Split(' ')[1])) // Check client random
                    return; // Already there
            }

            // Append to working keys file
            File.AppendAllText(WorkingHytaleKeysPath,
                $"# Promoted at {DateTime.Now:yyyy-MM-dd HH:mm:ss}\r\n" +
                FormatKeyLine(key) + "\r\n");

            AddInGameLog($"[KEYS] Promoted {key.Type} key to HytaleKeys.log");
        }
        catch (Exception ex)
        {
            AddInGameLog($"[KEYS] Promote failed: {ex.Message}");
        }
    }

    private string FormatKeyLine(EncryptionKey key)
    {
        string label = key.Type switch
        {
            EncryptionType.QUIC_Client1RTT => "CLIENT_TRAFFIC_SECRET_0",
            EncryptionType.QUIC_Server1RTT => "SERVER_TRAFFIC_SECRET_0",
            EncryptionType.QUIC_ClientHandshake => "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            EncryptionType.QUIC_ServerHandshake => "SERVER_HANDSHAKE_TRAFFIC_SECRET",
            _ => "UNKNOWN"
        };

        // Generate fake client_random from key hash (or store original)
        string clientRandom = Convert.ToHexString(
            SHA256.HashData(key.Secret).Take(32).ToArray()).ToLower();

        string secret = Convert.ToHexString(key.Secret).ToLower();

        return $"{label} {clientRandom} {secret}";
    }


    private void StartPermanentKeyWatcher()
    {
        try
        {
            _sslKeyWatcher?.Dispose();

            string dir  = Path.GetDirectoryName(PermanentKeyLogPath)!;
            string file = Path.GetFileName(PermanentKeyLogPath)!;

            _sslKeyWatcher = new FileSystemWatcher(dir)
            {
                Filter              = file,
                NotifyFilter        = NotifyFilters.LastWrite | NotifyFilters.Size,
                EnableRaisingEvents = true
            };

            // Debounced: JVM flushes in bursts; only process once per 400ms
            _sslKeyWatcher.Changed += (_, _e) =>
            {
                if ((DateTime.Now - _lastKeyLoadTime).TotalMilliseconds < 400) return;
                _lastKeyLoadTime = DateTime.Now;
                Task.Run(ImportPermanentKeyLogIncremental);
            };

            AddInGameLog($"[AUTOKEY] Watching {file}");
        }
        catch (Exception ex)
        {
            AddInGameLog($"[AUTOKEY] Watcher error: {ex.Message}");
        }
    }

    // Full scan: used on startup and manual re-import
    private void ImportPermanentKeyLogFull(string reason)
    {
        try
        {
            if (!File.Exists(PermanentKeyLogPath)) return;

            List<string> lines;
            using (var fs = new FileStream(PermanentKeyLogPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                using var rdr = new System.IO.StreamReader(fs);
                lines = new List<string>();
                string? ln;
                while ((ln = rdr.ReadLine()) != null)
                    if (!string.IsNullOrWhiteSpace(ln) && !ln.StartsWith("#"))
                        lines.Add(ln);
                _permFileReadPos = fs.Length;
            }

            int added = 0;
            foreach (var line in lines)
            {
                if (!IsHytaleQuicKey(line)) continue;
                var key = ParseSSLKeyLogLine(line, PermanentKeyLogPath);
                if (key != null) { PacketDecryptor.AddKey(key); added++; }
            }

            if (added > 0)
            {
                AddInGameLog($"[AUTOKEY] {reason}: {added} QUIC key(s) loaded");
                OnKeysUpdated?.Invoke();
                _permanentLogReady = true;
            }
            else if (lines.Count > 0)
            {
                AddInGameLog($"[AUTOKEY] {reason}: {lines.Count} lines, 0 QUIC keys -- Hytale may not be running yet");
            }
        }
        catch (Exception ex) { Log.Warn($"[AUTOKEY] Full import: {ex.Message}", "AutoKey"); }
    }

    // Incremental scan: only reads new bytes appended since last read
    private void ImportPermanentKeyLogIncremental()
    {
        try
        {
            if (!File.Exists(PermanentKeyLogPath)) return;

            int added = 0;
            using (var fs = new FileStream(PermanentKeyLogPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                if (fs.Length < _permFileReadPos) { _permFileReadPos = 0; } // file was cleared
                if (fs.Length == _permFileReadPos) return;                  // nothing new

                fs.Seek(_permFileReadPos, SeekOrigin.Begin);
                using var rdr = new System.IO.StreamReader(fs, System.Text.Encoding.ASCII, leaveOpen: true);
                string? ln;
                while ((ln = rdr.ReadLine()) != null)
                {
                    if (string.IsNullOrWhiteSpace(ln) || ln.StartsWith("#")) continue;
                    if (!IsHytaleQuicKey(ln)) continue;
                    var key = ParseSSLKeyLogLine(ln, PermanentKeyLogPath);
                    if (key != null) { PacketDecryptor.AddKey(key); added++; }
                }
                _permFileReadPos = fs.Length;
            }

            if (added > 0)
            {
                AddInGameLog($"[AUTOKEY] Live: +{added} new QUIC key(s)");
                OnKeysUpdated?.Invoke();
                _permanentLogReady = true;
            }
        }
        catch (Exception ex) { Log.Warn($"[AUTOKEY] Incremental: {ex.Message}", "AutoKey"); }
    }

    // Public: UI "Re-Import" button
    public void ForceReImportKeys()
    {
        _permFileReadPos = 0;
        PacketDecryptor.ClearKeys();
        ImportPermanentKeyLogFull("manual re-import");
    }

    /// <summary>
    /// Called by PipeCaptureServer when HyForceHook.dll forwards a captured packet.
    /// Bypasses the UDP proxy entirely — packets come directly from inside the JVM.
    /// </summary>
    public void OnHookPacket(CapturedPacket packet)
    {
        if (packet?.RawBytes == null || packet.RawBytes.Length < 20) return;
        PacketLog.Add(packet);
        _packetHandlerDelegate?.Invoke(packet);  
    }

    // Public: UI "Clear Log" button -- wipes file and memory keys
    public void ClearPermanentKeyLog()
    {
        try
        {
            PacketDecryptor.ClearKeys();
            _permFileReadPos = 0;
            File.WriteAllText(PermanentKeyLogPath, "# HyForce permanent SSL key log - cleared\r\n");
            AddInGameLog("[AUTOKEY] Permanent log cleared.");
        }
        catch (Exception ex) { AddInGameLog($"[AUTOKEY] Clear error: {ex.Message}"); }
    }

    // =========================================================================
    // Add manual prepare method for UI
    public void PrepareFreshKeyLogManual()
    {
        try
        {
            // Generate session-specific filename
            string sessionId = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            string keyLogPath = Path.Combine(ExportDirectory, $"sslkeys_session_{sessionId}.log");

            // Ensure directory exists
            Directory.CreateDirectory(ExportDirectory);

            // Create empty file (this triggers file watcher)
            File.WriteAllText(keyLogPath, $"# HyForce Session {sessionId}\r\n");

            // CRITICAL: Set for THIS PROCESS ONLY - Hytale must be restarted to pick this up
            Environment.SetEnvironmentVariable("SSLKEYLOGFILE", keyLogPath, EnvironmentVariableTarget.Process);

            // Also try User scope for persistence
            try
            {
                Environment.SetEnvironmentVariable("SSLKEYLOGFILE", keyLogPath, EnvironmentVariableTarget.User);
            }
            catch { /* May not have permissions */ }

            // Track this as the active file
            _activeKeyLogFile = keyLogPath;

            AddInGameLog($"[KEYLOG] Fresh key log ready: {Path.GetFileName(keyLogPath)}");
            AddInGameLog("[KEYLOG] >>> RESTART HYTALE NOW <<<");
            AddInGameLog("[KEYLOG] (Env var changes only take effect on process start)");

            // Setup watcher for this specific file
            SetupSessionKeyWatcher(keyLogPath);
        }
        catch (Exception ex)
        {
            AddInGameLog($"[KEYLOG] Error: {ex.Message}");
        }
    }



    private void QueueKeyFileLoad(string path)
    {
        lock (_pendingKeyFiles)
        {
            if (!_pendingKeyFiles.Contains(path))
            {
                _pendingKeyFiles.Enqueue(path);
            }
        }
    }

    private void ProcessPendingKeyFiles()
    {
        lock (_pendingKeyFiles)
        {
            int count = _pendingKeyFiles.Count;
            for (int i = 0; i < count; i++)
            {
                if (_pendingKeyFiles.Count == 0) break;
                string path = _pendingKeyFiles.Dequeue();
                if (!TryLoadKeysFromFileInternal(path))
                {
                    if (!path.Contains("|retry5"))
                    {
                        int retryCount = 0;
                        if (path.Contains("|retry"))
                        {
                            int.TryParse(path.Split("|retry")[1], out retryCount);
                        }
                        if (retryCount < 5)
                        {
                            string retryPath = path.Split("|retry")[0] + $"|retry{retryCount + 1}";
                            _pendingKeyFiles.Enqueue(retryPath);
                        }
                        else
                        {
                            AddInGameLog($"[KEYS] Gave up on {Path.GetFileName(path)} after 5 attempts");
                        }
                    }
                }
            }
        }
    }

    // FIXED: Single SetupAutoDecryption method with 30 second interval
    private void SetupAutoDecryption()
    {
        _autoDecryptTimer = new System.Timers.Timer(60000); // 60 seconds - very conservative
        _autoDecryptTimer.Elapsed += (s, e) =>
        {
            // CRITICAL FIX: Only auto-decrypt if we have keys AND proxy is running
            if (PacketDecryptor.AutoDecryptEnabled &&
                PacketDecryptor.DiscoveredKeys.Count > 0 &&
                IsRunning &&
                UdpProxy.ActiveSessions > 0)
            {
                // Run on thread pool to avoid blocking
                Task.Run(() => TryAutoDecryptPackets());
            }
        };
        _autoDecryptTimer.AutoReset = true;
        // DON'T start here - start in Start() method
    }

    // FIXED: Single TryAutoDecryptPackets method - less aggressive
    private void TryAutoDecryptPackets()
    {
        if (!PacketDecryptor.AutoDecryptEnabled) return;
        if (PacketDecryptor.DiscoveredKeys.Count == 0) return;

        // CRITICAL FIX: Only process a few packets at a time
        var recentPackets = PacketLog.GetLast(3); // REDUCED from 10 to 3
        int decrypted = 0;

        foreach (var pkt in recentPackets)
        {
            if (pkt.EncryptionHint == "encrypted" && pkt.RawBytes.Length > 100)
            {
                // Use non-blocking decrypt
                var result = PacketDecryptor.TryDecrypt(pkt.RawBytes);
                if (result.Success) decrypted++;
            }
        }

        if (decrypted > 0)
        {
            AddInGameLog($"[AUTO-DECRYPT] Decrypted {decrypted} packets");
            OnKeysUpdated?.Invoke();
        }
    }

    public IEnumerable<string> GetRecentLog(int count = 100)
    {
        lock (InGameLog)
            return InGameLog.TakeLast(count).ToList();
    }

    public void AddInGameLog(string message)
    {
        var stamped = $"[{DateTime.Now:HH:mm:ss}] {message}";
        // ── Write to in-game log buffer ──
        lock (InGameLog)
        {
            InGameLog.Add(stamped);
            while (InGameLog.Count > MaxInGameLogLines)
                InGameLog.RemoveAt(0);
        }
        // ── Dual-write to session log file (always-on, never lose logs) ──
        if (!string.IsNullOrEmpty(SessionLogPath))
        {
            lock (_sessionLogLock)
            {
                try { File.AppendAllText(SessionLogPath, stamped + "\n"); }
                catch { /* never crash from log write failure */ }
            }
        }
    }


    public void Start()
    {
        if (IsRunning) return;

        _sessionStartTime = DateTime.Now;
        AddInGameLog("[SESSION] === Starting Capture Session ===");
        AddInGameLog($"[SESSION] Live log: {SessionLogPath}");

        // Tag all recently-loaded keys as current session, prioritize in decryption
        PacketDecryptor.MarkSessionStart();
        AddInGameLog($"[SESSION] Current-session keys marked for priority decryption");

        // ── KEY PRESERVATION: Do NOT clear keys or overwrite SSLKEYLOGFILE ──
        // Keys loaded from the permanent log are still valid. Hytale writes to
        // PermanentKeyLogPath (which SSLKEYLOGFILE points to). The watcher set
        // up in InitPermanentKeyLog() handles all new keys automatically.
        // We just need to re-import in case Hytale wrote new entries recently.
        int keysBefore = PacketDecryptor.DiscoveredKeys.Count;
        AddInGameLog($"[SESSION] Preserving {keysBefore} existing key(s)");
        Task.Run(async () =>
        {
            await Task.Delay(800);
            ImportPermanentKeyLogFull("session-start re-scan");
            await ImportAllKnownKeyFiles();
        });

        // Start proxies — Hytale uses QUIC/UDP ONLY (confirmed from protocol docs)
        // TCP proxy is disabled: adds overhead and can interfere with QUIC connections
        // int tcpListenPort = ListenPort + 1;
        // TcpProxy.Start("0.0.0.0", tcpListenPort, TargetHost, TargetPort);
        // Thread.Sleep(50);
        UdpProxy.Start("0.0.0.0", ListenPort, TargetHost, TargetPort);
        // IP isolation: only accept packets from our target server
        UdpProxy.FilterToServerIp = TargetHost;
        AddInGameLog($"[SESSION] UDP-only mode | IP filter: {TargetHost}");

        StartTime = DateTime.Now;
        _autoDecryptTimer?.Start();
        PacketDecryptor.StartAutoDecrypt();

        // Auto-copy server address
        try
        {
            string connectString = $"127.0.0.1:{ListenPort}";
            TextCopy.ClipboardService.SetText(connectString);
            AddInGameLog($"[AUTO-COPY] {connectString} copied to clipboard!");
        }
        catch (Exception ex)
        {
            Log.Warn($"Failed to copy: {ex.Message}", "System");
        }
    }

    private void SetupSessionKeyWatcher(string specificFilePath)
    {
        try
        {
            // Stop old watcher if exists
            _sslKeyWatcher?.Dispose();

            string? directory = Path.GetDirectoryName(specificFilePath);
            string? fileName = Path.GetFileName(specificFilePath);

            if (string.IsNullOrEmpty(directory) || string.IsNullOrEmpty(fileName))
                return;

            _sslKeyWatcher = new FileSystemWatcher(directory)
            {
                Filter = fileName, // Watch ONLY our specific session file
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.CreationTime,
                EnableRaisingEvents = true
            };

            _sslKeyWatcher.Changed += (s, e) =>
            {
                if ((DateTime.Now - _lastKeyLoadTime).TotalSeconds > 1)
                {
                    AddInGameLog($"[KEYS] Session file updated");
                    QueueKeyFileLoad(e.FullPath);
                    _lastKeyLoadTime = DateTime.Now;
                }
            };

            AddInGameLog("[KEYS] Watching session file for new keys");
        }
        catch (Exception ex)
        {
            Log.Warn($"[KEYS] Watcher setup failed: {ex.Message}", "System");
        }
    }

    private void ScanSessionKeyFile(string sessionFilePath)
    {
        try
        {
            if (!File.Exists(sessionFilePath))
            {
                AddInGameLog($"[KEYS] Session file not found: {Path.GetFileName(sessionFilePath)}");
                return;
            }

            var fileInfo = new FileInfo(sessionFilePath);
            var content = File.ReadAllText(sessionFilePath);
            var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries)
                              .Where(l => !string.IsNullOrWhiteSpace(l) && !l.StartsWith("#"))
                              .ToList();

            AddInGameLog($"[KEYS] Scanning {Path.GetFileName(sessionFilePath)} ({fileInfo.Length} bytes, {lines.Count} data lines)");

            int keysAdded = 0;
            int lineNum = 0;

            foreach (var line in lines)
            {
                lineNum++;

                // Debug: show first few lines
                if (lineNum <= 3)
                {
                    AddInGameLog($"[KEYS-DEBUG] Line {lineNum}: {line.Substring(0, Math.Min(60, line.Length))}...");
                }

                if (!IsHytaleQuicKey(line))
                {
                    if (lineNum <= 3) AddInGameLog($"[KEYS-DEBUG]   -> Filtered out (not QUIC key)");
                    continue;
                }

                var key = ParseSSLKeyLogLine(line, sessionFilePath);
                if (key != null)
                {
                    PacketDecryptor.AddKey(key);
                    keysAdded++;
                    AddInGameLog($"[KEYS] Added {key.Type} key ({key.Secret?.Length * 8} bits)");
                }
                else if (lineNum <= 3)
                {
                    AddInGameLog($"[KEYS-DEBUG]   -> Parse failed");
                }
            }

            AddInGameLog($"[KEYS] Scan complete: {keysAdded} keys added from {lines.Count} lines");

            if (keysAdded > 0)
            {
                OnKeysUpdated?.Invoke();
            }
        }
        catch (Exception ex)
        {
            AddInGameLog($"[KEYS] Scan error: {ex.Message}");
        }
    }

    private bool IsHytaleQuicKey(string line)
    {
        // Hytale uses QUIC which produces these specific labels
        // Be more permissive - check for any QUIC/TLS 1.3 key labels
        string[] quicLabels =
        {
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        "CLIENT_TRAFFIC_SECRET_0",
        "SERVER_TRAFFIC_SECRET_0",
        "CLIENT_TRAFFIC_SECRET_1",  // Added - some implementations use _1
        "SERVER_TRAFFIC_SECRET_1",
        "CLIENT_EARLY_TRAFFIC_SECRET",
        "EXPORTER_SECRET",
        "EARLY_EXPORTER_SECRET"
    };

        var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 3) return false;

        // Check if it starts with any QUIC label (case insensitive)
        return quicLabels.Any(label =>
            parts[0].Equals(label, StringComparison.OrdinalIgnoreCase));
    }

    public void ClearKeyLogFile()
    {
        try
        {
            // Get the system-wide key log file path
            string? systemKeyLog = Environment.GetEnvironmentVariable("SSLKEYLOGFILE", EnvironmentVariableTarget.Machine)
                ?? Environment.GetEnvironmentVariable("SSLKEYLOGFILE", EnvironmentVariableTarget.User)
                ?? Environment.GetEnvironmentVariable("SSLKEYLOGFILE", EnvironmentVariableTarget.Process);

            // Also check common locations
            string[] possiblePaths =
            {
            systemKeyLog,
            Path.Combine(ExportDirectory, "sslkeys.log"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "sslkeys.log"),
            @"C:\Users\benja\source\repos\HyForce\Exported logs\sslkeys.log"
        };

            foreach (var path in possiblePaths.Where(p => !string.IsNullOrEmpty(p)).Distinct())
            {
                if (string.IsNullOrEmpty(path)) continue;

                try
                {
                    if (File.Exists(path))
                    {
                        // Try to clear it using multiple strategies
                        bool cleared = TryClearFile(path);

                        if (cleared)
                        {
                            AddInGameLog($"[KEYLOG] Cleared: {Path.GetFileName(path)}");
                        }
                        else
                        {
                            // If can't clear, rename it
                            string backupPath = path + ".backup." + DateTime.Now.ToString("yyyyMMdd_HHmmss");
                            File.Move(path, backupPath);
                            AddInGameLog($"[KEYLOG] Renamed locked file to {Path.GetFileName(backupPath)}");
                        }
                    }

                    // Create fresh empty file with header
                    File.WriteAllText(path, "# SSL Key Log - Fresh session started by HyForce\r\n");
                }
                catch (Exception ex)
                {
                    Log.Warn($"[KEYS] Could not clear {path}: {ex.Message}", "System");
                }
            }

            Log.Info("[KEYS] All key log files cleared/reset", "System");
        }
        catch (Exception ex)
        {
            AddInGameLog($"[KEYLOG] Clear operation warning: {ex.Message}");
        }
    }

    private bool TryClearFile(string path)
    {
        try
        {
            // Strategy 1: FileShare.ReadWrite
            using (var fs = new FileStream(path, FileMode.OpenOrCreate, FileAccess.Write, FileShare.ReadWrite))
            {
                fs.SetLength(0);
                using (var writer = new StreamWriter(fs))
                {
                    writer.WriteLine("# SSL Key Log - Cleared by HyForce");
                }
            }
            return true;
        }
        catch
        {
            try
            {
                // Strategy 2: Delete and recreate
                File.Delete(path);
                File.WriteAllText(path, "# SSL Key Log - Fresh start\r\n");
                return true;
            }
            catch
            {
                return false;
            }
        }
    }

    private void ScanSpecificKeyFile(string specificPath)
    {
        try
        {
            if (File.Exists(specificPath))
            {
                var age = DateTime.Now - new FileInfo(specificPath).LastWriteTime;
                AddInGameLog($"[KEYS] Loading from current session ({age.TotalSeconds:F0}s old)");
                QueueKeyFileLoad(specificPath);
            }
            else
            {
                AddInGameLog("[KEYS] Session key file not found yet - will retry");
            }
        }
        catch (Exception ex)
        {
            Log.Warn($"[KEYS] Scan failed: {ex.Message}", "System");
        }
    }

    private PacketDecryptor.EncryptionKey? ParseSSLKeyLogLine(string line, string source)
    {
        try
        {
            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 3)
            {
                Log.Warn($"Parse failed: only {parts.Length} parts", "Keys");
                return null;
            }

            string label = parts[0];

            // Double-check it's a QUIC label we want
            if (!IsHytaleQuicKey(line))
            {
                Log.Warn($"Parse failed: not a QUIC key label", "Keys");
                return null;
            }

            byte[] clientRandom;
            byte[] secret;

            try
            {
                clientRandom = Convert.FromHexString(parts[1]);
                secret = Convert.FromHexString(parts[2]);
            }
            catch (FormatException ex)
            {
                Log.Warn($"Hex decode failed: {ex.Message}", "Keys");
                return null;
            }

            // Validate lengths
            if (clientRandom.Length != 32)
            {
                Log.Warn($"Unexpected client_random length: {clientRandom.Length} bytes", "Keys");
            }

            // 32B = AES-128/SHA-256, 48B = AES-256/SHA-384
            if (secret.Length != 32 && secret.Length != 48)
            {
                Log.Warn($"Unusual secret length: {secret.Length}B (expected 32 or 48)", "Keys");
            }

            // Determine key type based on label
            var keyType = label.ToUpper() switch
            {
                "CLIENT_TRAFFIC_SECRET_0" => PacketDecryptor.EncryptionType.QUIC_Client1RTT,
                "SERVER_TRAFFIC_SECRET_0" => PacketDecryptor.EncryptionType.QUIC_Server1RTT,
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET" => PacketDecryptor.EncryptionType.QUIC_ClientHandshake,
                "SERVER_HANDSHAKE_TRAFFIC_SECRET" => PacketDecryptor.EncryptionType.QUIC_ServerHandshake,
                "CLIENT_EARLY_TRAFFIC_SECRET" => PacketDecryptor.EncryptionType.QUIC_Client0RTT,
                "EXPORTER_SECRET" => PacketDecryptor.EncryptionType.QUIC_Client1RTT,
                _ => PacketDecryptor.EncryptionType.QUIC_Client1RTT
            };

            var key = new PacketDecryptor.EncryptionKey
            {
                Secret = secret,
                Type = keyType,
                Source = source,
                DiscoveredAt = DateTime.Now
            };

            // Derive actual QUIC keys from TLS secret
            PacketDecryptor.DeriveQUICKeys(key);

            if (key.Key.Length == 0)
            {
                Log.Warn("Key derivation failed - empty key produced", "Keys");
                return null;
            }

            Log.Success($"Parsed {label} ({secret.Length * 8} bits) -> {keyType}", "Keys");
            return key;
        }
        catch (Exception ex)
        {
            Log.Warn($"Parse error: {ex.Message}", "Keys");
            return null;
        }
    }

    private void DebugSSLKeyLogParsing(string line)
    {
        Console.WriteLine($"[KEY-PARSE] Raw line: {line.Substring(0, Math.Min(60, line.Length))}...");

        var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 3)
        {
            Console.WriteLine($"[KEY-PARSE] XX Invalid format: only {parts.Length} parts");
            return;
        }

        string label = parts[0];
        Console.WriteLine($"[KEY-PARSE] Label: '{label}'");

        // Only debug QUIC-relevant labels
        if (!label.Contains("TRAFFIC_SECRET") && !label.Contains("EXPORTER") && !label.Contains("HANDSHAKE"))
        {
            return;
        }

        try
        {
            byte[] clientRandom = Convert.FromHexString(parts[1]);
            byte[] secret = Convert.FromHexString(parts[2]);

            Console.WriteLine($"[KEY-PARSE] Client random: {clientRandom.Length} bytes ({BitConverter.ToString(clientRandom.Take(8).ToArray())}...)");
            Console.WriteLine($"[KEY-PARSE] Secret: {secret.Length} bytes ({secret.Length * 8} bits) - {BitConverter.ToString(secret.Take(8).ToArray())}...");

            // 32B = AES-128/SHA-256 (Hytale standard), 48B = AES-256/SHA-384
            string sn = secret.Length == 32 ? "OK AES-128 (Hytale)" : secret.Length == 48 ? "OK AES-256" : $"(!) unusual ({secret.Length}B)";
            Console.WriteLine($"[KEY-PARSE] {sn}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[KEY-PARSE] XX Parse error: {ex.Message}");
        }
    }

    private void TryEnableSSLKeyLogFile()
    {
        try
        {
            string keyLogPath = Path.Combine(ExportDirectory, "sslkeys.log");

            // Set for current process
            Environment.SetEnvironmentVariable("SSLKEYLOGFILE", keyLogPath, EnvironmentVariableTarget.Process);

            AddInGameLog($"[AUTO-DECRYPT] SSLKEYLOGFILE set to: {keyLogPath}");
            AddInGameLog($"[AUTO-DECRYPT] IMPORTANT: Restart Hytale if running!");

            // Check for existing keys
            var existingLogs = Directory.GetFiles(ExportDirectory, "*.log")
                .Where(f => f.Contains("key", StringComparison.OrdinalIgnoreCase) ||
                           f.Contains("ssl", StringComparison.OrdinalIgnoreCase));

            foreach (var log in existingLogs)
            {
                AddInGameLog($"[AUTO-DECRYPT] Found existing key log: {Path.GetFileName(log)}");
                QueueKeyFileLoad(log);
            }
        }
        catch (Exception ex)
        {
            Log.Warn($"SSLKEYLOGFILE setup failed: {ex.Message}", "System");
        }
    }

    public void TryLoadKeysFromFile(string path)
    {
        QueueKeyFileLoad(path);
    }

    private bool TryLoadKeysFromFileInternal(string path)
    {
        string actualPath = path.Split("|retry")[0];
        int retryCount = 0;
        const int MAX_RETRIES = 5;

        while (retryCount < MAX_RETRIES)
        {
            try
            {
                if (!File.Exists(actualPath)) return true;

                int keysAdded = 0;
                int linesProcessed = 0;
                int keysFiltered = 0;

                using (var fs = new FileStream(actualPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                using (var reader = new StreamReader(fs))
                {
                    string? line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        linesProcessed++;

                        // FILTER: Only process Hytale QUIC keys
                        if (!IsHytaleQuicKey(line))
                        {
                            if (!string.IsNullOrWhiteSpace(line) && !line.StartsWith("#"))
                                keysFiltered++;
                            continue;
                        }

                        var key = ParseSSLKeyLogLine(line, actualPath);
                        if (key != null)
                        {
                            PacketDecryptor.AddKey(key);
                            keysAdded++;
                        }
                    }
                }

                if (keysAdded > 0)
                {
                    AddInGameLog($"[KEYS] {keysAdded} Hytale keys from {Path.GetFileName(actualPath)}");
                    if (keysFiltered > 0)
                    {
                        AddInGameLog($"[KEYS] Filtered {keysFiltered} non-QUIC keys (browsers/other apps)");
                    }
                    OnKeysUpdated?.Invoke();
                    return true;
                }
                else if (keysFiltered > 0)
                {
                    AddInGameLog($"[KEYS] No Hytale keys yet (filtered {keysFiltered} browser keys)");
                    return true;
                }
                return true;
            }
            catch (IOException ex) when (IsFileLocked(ex))
            {
                retryCount++;
                if (retryCount >= MAX_RETRIES) return false;
                Thread.Sleep(100 * retryCount);
            }
            catch (Exception ex)
            {
                AddInGameLog($"[KEYS] Load error: {ex.Message}");
                return true;
            }
        }
        return false;
    }

    private static bool IsFileLocked(IOException exception)
    {
        int errorCode = exception.HResult & 0xFFFF;
        return errorCode == 32 || errorCode == 33;
    }

    public void RefreshAllKeys()
    {
        AddInGameLog("[KEYS] Refreshing keys...");

        // Get current session file
        string? currentLog = Environment.GetEnvironmentVariable("SSLKEYLOGFILE", EnvironmentVariableTarget.Process);

        if (!string.IsNullOrEmpty(currentLog) && File.Exists(currentLog))
        {
            ScanSessionKeyFile(currentLog); // Use new method
        }
        else
        {
            // Fallback: look for any session file
            var sessionFiles = Directory.GetFiles(ExportDirectory, "sslkeys_session_*.log")
                .OrderByDescending(f => new FileInfo(f).LastWriteTime)
                .FirstOrDefault();

            if (sessionFiles != null)
            {
                ScanSessionKeyFile(sessionFiles);
            }
        }

        OnKeysUpdated?.Invoke();
    }

    // -------------------------------------------------------------------------
    // Import keys from the SYSTEM-WIDE SSLKEYLOGFILE incrementally:
    // Only reads entries added AFTER session start (by tracking file position).
    // This solves the problem where the session-specific file stays empty because
    // Hytale was not restarted after SSLKEYLOGFILE was set.
    public void LoadSystemKeyLogNow()
    {
        // Candidates in priority order
        string?[] candidates =
        {
            Environment.GetEnvironmentVariable("SSLKEYLOGFILE", EnvironmentVariableTarget.Machine),
            Environment.GetEnvironmentVariable("SSLKEYLOGFILE", EnvironmentVariableTarget.User),
            Environment.GetEnvironmentVariable("SSLKEYLOGFILE", EnvironmentVariableTarget.Process),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "sslkeys.log"),
            Path.Combine(ExportDirectory, "sslkeys.log"),
        };

        string? sysFile = candidates.FirstOrDefault(p => !string.IsNullOrEmpty(p) && File.Exists(p));
        if (sysFile == null)
        {
            AddInGameLog("[SYSKEYS] No system SSLKEYLOGFILE found");
            return;
        }

        AddInGameLog($"[SYSKEYS] Reading from: {Path.GetFileName(sysFile)}");

        try
        {
            using var fs     = new FileStream(sysFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            long fileLen     = fs.Length;

            // If session just started, read from the current end (only future entries)
            // If _sysKeyLogPosition == 0 this is first call - start from beginning
            // of content that was written AFTER sessionStartTime (approximate: last 10 min)
            if (_sysKeyLogPosition == 0)
            {
                // Read whole file but only accept entries newer than session start
                _sysKeyLogPosition = 0;
                AddInGameLog($"[SYSKEYS] First import - scanning full file for recent entries");
            }
            else if (_sysKeyLogPosition > fileLen)
            {
                // File was truncated/rotated
                _sysKeyLogPosition = 0;
                AddInGameLog("[SYSKEYS] File rotated, re-scanning from start");
            }

            fs.Seek(_sysKeyLogPosition, SeekOrigin.Begin);
            using var reader = new StreamReader(fs, System.Text.Encoding.ASCII, leaveOpen: true);
            var lines = new List<string>();
            string? line;
            while ((line = reader.ReadLine()) != null)
                if (!string.IsNullOrWhiteSpace(line) && !line.StartsWith("#"))
                    lines.Add(line);

            _sysKeyLogPosition = fs.Position;

            AddInGameLog($"[SYSKEYS] Found {lines.Count} key lines");

            int added = 0;
            foreach (var kLine in lines)
            {
                if (!IsHytaleQuicKey(kLine)) continue;
                var key = ParseSSLKeyLogLine(kLine, sysFile);
                if (key != null) { PacketDecryptor.AddKey(key); added++; }
            }

            AddInGameLog($"[SYSKEYS] Added {added} QUIC keys from system log");
            if (added > 0) OnKeysUpdated?.Invoke();
        }
        catch (Exception ex)
        {
            AddInGameLog($"[SYSKEYS] Error: {ex.Message}");
        }
    }

    public KeyStatus GetKeyStatus()
    {
        return new KeyStatus
        {
            TotalKeys = PacketDecryptor.DiscoveredKeys.Count,
            SuccessfulDecryptions = PacketDecryptor.SuccessfulDecryptions,
            FailedDecryptions = PacketDecryptor.FailedDecryptions,
            SkippedDecryptions = PacketDecryptor.SkippedDecryptions,  // NEW
            KeySources = PacketDecryptor.DiscoveredKeys.Select(k => k.Source).Distinct().ToList(),
            LastKeyAdded = PacketDecryptor.DiscoveredKeys.Any()
                ? PacketDecryptor.DiscoveredKeys.Max(k => k.DiscoveredAt)
                : (DateTime?)null
        };
    }



    public void Stop()
    {
        UdpProxy.Stop();
        // FIX 2: Stop TCP proxy too
        TcpProxy.Stop();
        StartTime = null;
        _autoDecryptTimer?.Stop();
        PacketDecryptor.StopAutoDecrypt();
        Log.Info("[HyForce] Proxy stopped", "System");
        AddInGameLog("Proxy stopped");
    }

    private void HandlePacket(CapturedPacket packet)
    {
        PacketLog.Add(packet);
        AnalyzePacket(packet);
        Database.ProcessPacket(packet);
        OnPacketReceived?.Invoke(packet);

        if (PacketDecryptor.FailedDecryptions > 100 &&
            PacketDecryptor.DiscoveredKeys.Count == 0 &&
            _autoDecryptTimer?.Enabled == true)
        {
            TriggerMemoryScan();
        }
    }

    private void AnalyzePacket(CapturedPacket packet)
    {
        if (packet.RawBytes.Length > Config.AnomalyThresholdSize)
        {
            LogSecurityEvent("Anomaly", "Oversized packet detected", new Dictionary<string, object>
            {
                ["size"] = packet.RawBytes.Length,
                ["opcode"] = packet.Opcode,
                ["direction"] = packet.Direction.ToString()
            });
        }

        if (packet.Opcode > 0x1000 && packet.Direction == Networking.PacketDirection.ClientToServer)
        {
            LogSecurityEvent("Anomaly", "Suspicious C2S opcode", new Dictionary<string, object>
            {
                ["opcode"] = packet.Opcode,
                ["size"] = packet.RawBytes.Length
            });
        }
    }

    public void LogSecurityEvent(string category, string message, Dictionary<string, object> metadata)
    {
        var evt = new SecurityEvent
        {
            Timestamp = DateTime.Now,
            Category = category,
            Message = message,
            Metadata = metadata
        };
        SecurityEvents.Add(evt);
        Log.Security(message, category, metadata);
        AddInGameLog($"[{category}] {message}");
        OnSecurityEvent?.Invoke();
    }

    public void TriggerMemoryScan()
    {
        OnMemoryDataUpdated?.Invoke();
    }

    public void ClearAll()
    {
        PacketLog.Clear();
        Database.Clear();
        SecurityEvents.Clear();
        Log.Clear();
        lock (InGameLog) InGameLog.Clear();
        PacketDecryptor.ClearKeys();
        Log.Info("[HyForce] All data cleared", "System");
        AddInGameLog("All data cleared");
    }

    public string GenerateDiagnostics()
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("+------------------------------------------------------------------------------+");
        sb.AppendLine("                    HYFORCE V22-ENHANCED - TCP+UDP MODE                        ");
        sb.AppendLine("+------------------------------------------------------------------------------+");
        sb.AppendLine();
        sb.AppendLine($"Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"Session Duration: {(StartTime.HasValue ? FormatDuration(DateTime.Now - StartTime.Value) : "Not running")}");
        sb.AppendLine();

        sb.AppendLine("-------------------------------------------------------------------------------");
        sb.AppendLine("                              SYSTEM INFORMATION                               ");
        sb.AppendLine("-------------------------------------------------------------------------------");
        sb.AppendLine($"OS: {Environment.OSVersion}");
        sb.AppendLine($".NET Version: {Environment.Version}");
        sb.AppendLine($"Machine: {Environment.MachineName}");
        sb.AppendLine($"Processor Count: {Environment.ProcessorCount}");
        sb.AppendLine();

        sb.AppendLine("-------------------------------------------------------------------------------");
        sb.AppendLine("                                CONFIGURATION                                  ");
        sb.AppendLine("-------------------------------------------------------------------------------");
        sb.AppendLine($"Mode: TCP+UDP (Hytale Registry + Gameplay)");
        sb.AppendLine($"Target: {TargetHost}:{TargetPort}");
        sb.AppendLine($"UDP Listen: 0.0.0.0:{ListenPort}");
        sb.AppendLine($"TCP Listen: 0.0.0.0:{ListenPort + 1}");
        sb.AppendLine($"Export Path: {ExportDirectory}");
        sb.AppendLine();

        sb.AppendLine("-------------------------------------------------------------------------------");
        sb.AppendLine("                                PROXY STATUS                                   ");
        sb.AppendLine("-------------------------------------------------------------------------------");
        sb.AppendLine($"UDP Proxy: {(UdpProxy.IsRunning ? "RUNNING " : "STOPPED")}");
        sb.AppendLine($"  - Status: {UdpProxy.StatusMessage}");
        sb.AppendLine($"  - Active Sessions: {UdpProxy.ActiveSessions}");
        sb.AppendLine($"  - Total Clients: {UdpProxy.TotalClients}");
        sb.AppendLine();
        // FIX 2: Add TCP proxy status to diagnostics
        sb.AppendLine($"TCP Proxy: {(TcpProxy.IsRunning ? "RUNNING " : "STOPPED")}");
        sb.AppendLine($"  - Status: {TcpProxy.StatusMessage}");
        sb.AppendLine($"  - Active Connections: {TcpProxy.ActiveSessions}");
        sb.AppendLine($"  - Total Connections: {TcpProxy.TotalConnections}");
        sb.AppendLine();

        sb.AppendLine("-------------------------------------------------------------------------------");
        sb.AppendLine("                              TRAFFIC STATISTICS                               ");
        sb.AppendLine("-------------------------------------------------------------------------------");
        sb.AppendLine($"Total Packets: {TotalPackets:N0}");
        sb.AppendLine($"  TCP: {TcpPackets:N0} ({FormatBytes(PacketLog.BytesTcp)} bytes) - Registry/Login");
        sb.AppendLine($"  UDP: {UdpPackets:N0} ({FormatBytes(PacketLog.BytesUdp)} bytes) - Gameplay");
        sb.AppendLine();
        sb.AppendLine($"Bytes Total: {FormatBytes(PacketLog.BytesSc + PacketLog.BytesCs)}");
        sb.AppendLine($"  Server->Client: {FormatBytes(PacketLog.BytesSc)}");
        sb.AppendLine($"  Client->Server: {FormatBytes(PacketLog.BytesCs)}");
        sb.AppendLine();
        sb.AppendLine($"Unique Opcodes: {PacketLog.UniqueOpcodes}");
        sb.AppendLine();

        sb.AppendLine("-------------------------------------------------------------------------------");
        sb.AppendLine("                             DECRYPTION STATUS                                 ");
        sb.AppendLine("-------------------------------------------------------------------------------");
        sb.AppendLine($"Keys Available: {PacketDecryptor.DiscoveredKeys.Count}");
        sb.AppendLine($"Successful Decryptions: {PacketDecryptor.SuccessfulDecryptions}");
        sb.AppendLine($"Failed Decryptions: {PacketDecryptor.FailedDecryptions}");

        if (PacketDecryptor.DiscoveredKeys.Any())
        {
            sb.AppendLine();
            sb.AppendLine("Key Sources:");
            foreach (var source in PacketDecryptor.DiscoveredKeys.Select(k => k.Source).Distinct())
            {
                var count = PacketDecryptor.DiscoveredKeys.Count(k => k.Source == source);
                sb.AppendLine($"  - {source}: {count} keys");
            }
        }
        sb.AppendLine();

        sb.AppendLine("-------------------------------------------------------------------------------");
        sb.AppendLine("                                TOP 20 OPCODES                                 ");
        sb.AppendLine("-------------------------------------------------------------------------------");
        var topOpcodes = PacketLog.GetOpcodeCounts().OrderByDescending(x => x.Value).Take(20);
        foreach (var kv in topOpcodes)
        {
            var name = Protocol.OpcodeRegistry.Label(kv.Key, Networking.PacketDirection.ServerToClient);
            var pct = TotalPackets > 0 ? (kv.Value / (double)TotalPackets * 100) : 0;
            sb.AppendLine($"  0x{kv.Key:X4} ({name,-20}): {kv.Value,6} packets ({pct:F1}%)");
        }
        sb.AppendLine();

        sb.AppendLine("-------------------------------------------------------------------------------");
        sb.AppendLine("                               PLAYER DATABASE                                 ");
        sb.AppendLine("-------------------------------------------------------------------------------");
        sb.AppendLine($"Unique Items: {Database.Items.Count:N0}");
        sb.AppendLine($"Unique Players: {Database.Players.Count:N0}");
        sb.AppendLine();

        sb.AppendLine("-------------------------------------------------------------------------------");
        sb.AppendLine("                               SECURITY EVENTS                                 ");
        sb.AppendLine("-------------------------------------------------------------------------------");
        sb.AppendLine($"Total Events: {SecurityEvents.Count:N0}");
        var categories = SecurityEvents.GroupBy(e => e.Category).Select(g => $"{g.Key}: {g.Count()}");
        sb.AppendLine($"By Category: {string.Join(", ", categories)}");
        sb.AppendLine();

        sb.AppendLine("--- Recent Events (Last 20) ---");
        foreach (var evt in SecurityEvents.OrderByDescending(e => e.Timestamp).Take(20))
        {
            sb.AppendLine($"[{evt.Timestamp:HH:mm:ss}] [{evt.Category,-12}] {evt.Message}");
            if (evt.Metadata.Any())
            {
                foreach (var meta in evt.Metadata.Take(5))
                {
                    sb.AppendLine($"    {meta.Key}: {meta.Value}");
                }
            }
        }
        sb.AppendLine();

        sb.AppendLine("-------------------------------------------------------------------------------");
        sb.AppendLine("                                IN-GAME LOG                                    ");
        sb.AppendLine("-------------------------------------------------------------------------------");
        lock (InGameLog)
        {
            foreach (var line in InGameLog.TakeLast(50))
            {
                sb.AppendLine(line);
            }
        }
        sb.AppendLine();

        sb.AppendLine("-------------------------------------------------------------------------------");
        sb.AppendLine("                           END OF DIAGNOSTICS REPORT                           ");
        sb.AppendLine("-------------------------------------------------------------------------------");

        return sb.ToString();
    }

    public string ExportPacketLog()
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("=== HYFORCE PACKET LOG EXPORT ===");
        sb.AppendLine($"Export Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"Total Packets: {TotalPackets:N0}");
        sb.AppendLine();

        var packets = PacketLog.GetAll();
        foreach (var pkt in packets)
        {
            sb.AppendLine($"[{pkt.Timestamp:HH:mm:ss.fff}] {pkt.DirStr} {(pkt.IsTcp ? "TCP" : "UDP")} " +
                $"0x{pkt.OpcodeDecimal:X4} ({pkt.OpcodeName}) {pkt.ByteLength} bytes " +
                $"[{pkt.CompressionMethod}] [{(pkt.EncryptionHint == "encrypted" ? "ENC" : "CLR")}]");

            if (pkt.ByteLength <= 256 && !string.IsNullOrEmpty(pkt.RawHexPreview))
            {
                sb.AppendLine($"  HEX: {pkt.RawHexPreview}");
            }
        }

        return sb.ToString();
    }

    public void ExportDiagnostics()
    {
        try
        {
            Directory.CreateDirectory(ExportDirectory);
            string report = GenerateDiagnostics();
            string filename = Path.Combine(ExportDirectory,
                $"hyforce_diagnostics_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
            File.WriteAllText(filename, report);
            Log.Success($"Diagnostics exported to {filename}", "Export");
            AddInGameLog($"[SUCCESS] Diagnostics exported to {filename}");
        }
        catch (Exception ex)
        {
            Log.Error($"Export failed: {ex.Message}", "Export");
            AddInGameLog($"[ERROR] Export failed: {ex.Message}");
        }
    }

    public void ExportPacketLogToFile()
    {
        try
        {
            Directory.CreateDirectory(ExportDirectory);
            string report = ExportPacketLog();
            string filename = Path.Combine(ExportDirectory,
                $"hyforce_packets_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
            File.WriteAllText(filename, report);
            Log.Success($"Packet log exported to {filename}", "Export");
            AddInGameLog($"[SUCCESS] Packet log exported to {filename}");
        }
        catch (Exception ex)
        {
            Log.Error($"Export failed: {ex.Message}", "Export");
            AddInGameLog($"[ERROR] Export failed: {ex.Message}");
        }
    }

    public void ExportAllLogs()
    {
        try
        {
            Directory.CreateDirectory(ExportDirectory);
            string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            string basePath = Path.Combine(ExportDirectory, $"hyforce_full_export_{timestamp}");
            Directory.CreateDirectory(basePath);

            File.WriteAllText(Path.Combine(basePath, "diagnostics.txt"), GenerateDiagnostics());
            File.WriteAllText(Path.Combine(basePath, "packets.txt"), ExportPacketLog());

            lock (InGameLog)
            {
                File.WriteAllLines(Path.Combine(basePath, "ingame_log.txt"), InGameLog);
            }

            var securitySb = new System.Text.StringBuilder();
            securitySb.AppendLine("=== SECURITY EVENTS ===");
            foreach (var evt in SecurityEvents.OrderBy(e => e.Timestamp))
            {
                securitySb.AppendLine($"[{evt.Timestamp:yyyy-MM-dd HH:mm:ss}] [{evt.Category}] {evt.Message}");
                foreach (var meta in evt.Metadata)
                {
                    securitySb.AppendLine($"    {meta.Key}: {meta.Value}");
                }
            }
            File.WriteAllText(Path.Combine(basePath, "security_events.txt"), securitySb.ToString());

            if (Protocol.RegistrySyncParser.NumericIdToName.Count > 0)
            {
                var itemsSb = new System.Text.StringBuilder();
                itemsSb.AppendLine("=== ITEMS ===");
                foreach (var item in Protocol.RegistrySyncParser.NumericIdToName.OrderBy(x => x.Key))
                {
                    itemsSb.AppendLine($"{item.Key:X8} = {item.Value}");
                }
                File.WriteAllText(Path.Combine(basePath, "items.txt"), itemsSb.ToString());
            }

            if (Protocol.RegistrySyncParser.PlayerNamesSeen.Count > 0)
            {
                File.WriteAllLines(Path.Combine(basePath, "players.txt"), Protocol.RegistrySyncParser.PlayerNamesSeen);
            }

            if (PacketDecryptor.DiscoveredKeys.Count > 0)
            {
                var keysSb = new System.Text.StringBuilder();
                keysSb.AppendLine("=== ENCRYPTION KEYS ===");
                foreach (var key in PacketDecryptor.DiscoveredKeys)
                {
                    keysSb.AppendLine($"Type: {key.Type}");
                    keysSb.AppendLine($"Source: {key.Source}");
                    keysSb.AppendLine($"Key: {Convert.ToHexString(key.Key)}");
                    if (key.MemoryAddress.HasValue)
                        keysSb.AppendLine($"Address: 0x{(ulong)key.MemoryAddress.Value:X}");
                    keysSb.AppendLine();
                }
                File.WriteAllText(Path.Combine(basePath, "encryption_keys.txt"), keysSb.ToString());
            }

            AddInGameLog($"[SUCCESS] Full export completed to {basePath}");

            try
            {
                System.Diagnostics.Process.Start("explorer.exe", basePath);
            }
            catch { }
        }
        catch (Exception ex)
        {
            AddInGameLog($"[ERROR] Full export failed: {ex.Message}");
        }
    }

    private string FormatBytes(long bytes)
    {
        string[] suffixes = { "B", "KB", "MB", "GB" };
        int i = 0;
        double d = bytes;
        while (d >= 1024 && i < suffixes.Length - 1)
        {
            d /= 1024;
            i++;
        }
        return $"{d:F2} {suffixes[i]}";
    }

    private string FormatDuration(TimeSpan duration)
    {
        if (duration.TotalHours >= 1)
            return $"{(int)duration.TotalHours}h {duration.Minutes}m";
        if (duration.TotalMinutes >= 1)
            return $"{duration.Minutes}m {duration.Seconds}s";
        return $"{duration.Seconds}s";
    }

    public void Dispose()
    {
        // Clear keys but don't clear file (might be needed for debugging)
        try
        {
            // Optional: Clear key log on close
            // ClearKeyLogFile(); 
        }
        catch { }

        UdpProxy.OnPacket -= _packetHandlerDelegate;
        TcpProxy.OnPacket -= _tcpPacketHandlerDelegate;

        Stop();
        _autoDecryptTimer?.Dispose();
        _sslKeyWatcher?.Dispose();
        foreach (var w in _extraWatchers) { try { w.Dispose(); } catch { } }
        _extraWatchers.Clear();
        _retryTimer?.Dispose();

        GC.SuppressFinalize(this);
    }
}

// In AppState.cs, update the KeyStatus class:

public class KeyStatus
{
    public int TotalKeys { get; set; }
    public long SuccessfulDecryptions { get; set; }  // Changed from int
    public long FailedDecryptions { get; set; }      // Changed from int
    public List<string> KeySources { get; set; } = new();
    public DateTime? LastKeyAdded { get; set; }
    public long SkippedDecryptions { get; set; }     // NEW
}