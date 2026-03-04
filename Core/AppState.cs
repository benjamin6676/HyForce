// FILE: Core/AppState.cs - FIXED: Removed duplicate TryAutoDecryptPackets
using HyForce.Data;
using HyForce.Networking;
using HyForce.Protocol;
using System.Collections.Concurrent;
using System.IO;

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

    public string ExportDirectory { get; set; } = @"C:\\Users\\benja\\source\\repos\\HyForce\\Exported logs";

    public event PacketReceivedHandler? OnPacketReceived;
    public event Action? OnSecurityEvent;
    public event Action? OnMemoryDataUpdated;
    public event Action? OnKeysUpdated;

    private System.Timers.Timer? _autoDecryptTimer;
    private FileSystemWatcher? _sslKeyWatcher;
    private DateTime _lastKeyLoadTime = DateTime.MinValue;
    private readonly object _keyLoadLock = new();
    private readonly Queue<string> _pendingKeyFiles = new();
    private readonly System.Timers.Timer _retryTimer;
    private readonly PacketReceivedHandler _packetHandlerDelegate;
    // FIX 2: Add TCP packet handler delegate
    private readonly PacketReceivedHandler _tcpPacketHandlerDelegate;
    private string? _activeKeyLogFile = null;

    public AppState()
    {
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



        SetupAutoDecryption();
        // SetupSSLKeyWatcher();        // REMOVED - now done in Start()
        // ScanAndLoadExistingKeys();   // REMOVED - now done in Start() with session-specific file
        // Only scan existing if not starting fresh session
        // ScanForExistingSessionFiles(); // Optional - implement if needed

        _retryTimer = new System.Timers.Timer(2000);
        _retryTimer.Elapsed += (s, e) => ProcessPendingKeyFiles();
        _retryTimer.AutoReset = true;
        _retryTimer.Start();
    }

    public string? GetActiveKeyLogFile()
    {
        return _activeKeyLogFile;
    }

    // Add manual prepare method for UI
    public void PrepareFreshKeyLogManual()
    {
        ClearKeyLogFile();

        string sessionId = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        string keyLogPath = Path.Combine(ExportDirectory, $"sslkeys_session_{sessionId}.log");

        _activeKeyLogFile = keyLogPath;
        Environment.SetEnvironmentVariable("SSLKEYLOGFILE", keyLogPath, EnvironmentVariableTarget.Process);

        try
        {
            Environment.SetEnvironmentVariable("SSLKEYLOGFILE", keyLogPath, EnvironmentVariableTarget.User);
        }
        catch { }

        File.WriteAllText(keyLogPath, $"# HyForce Session {sessionId} - Prepared manually\r\n");

        AddInGameLog($"[KEYLOG] Fresh key log ready: {Path.GetFileName(keyLogPath)}");
        AddInGameLog("[KEYLOG] >>> START HYTALE NOW <<<");
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

    public void AddInGameLog(string message)
    {
        lock (InGameLog)
        {
            InGameLog.Add($"[{DateTime.Now:HH:mm:ss}] {message}");
            while (InGameLog.Count > MaxInGameLogLines)
                InGameLog.RemoveAt(0);
        }
    }


    public void Start()
    {
        if (IsRunning) return;

        AddInGameLog("[SESSION] === Starting Fresh Session ===");

        // Clear old files
        ClearKeyLogFile();

        // Create fresh session file
        string sessionId = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        string sessionKeyLog = Path.Combine(ExportDirectory, $"sslkeys_session_{sessionId}.log");

        // TRACK THIS FILE
        _activeKeyLogFile = sessionKeyLog;

        // Set environment variables
        Environment.SetEnvironmentVariable("SSLKEYLOGFILE", sessionKeyLog, EnvironmentVariableTarget.Process);
        try { Environment.SetEnvironmentVariable("SSLKEYLOGFILE", sessionKeyLog, EnvironmentVariableTarget.User); } catch { }

        // Create file
        File.WriteAllText(sessionKeyLog, $"# HyForce Session {sessionId}\r\n");

        AddInGameLog($"[SESSION] Fresh key log: {Path.GetFileName(sessionKeyLog)}");

        // Clear old keys
        PacketDecryptor.ClearKeys();

        // Setup watcher for ONLY this file
        SetupSessionKeyWatcher(sessionKeyLog);

        AddInGameLog("[SESSION] >>> START HYTALE NOW <<<");
        AddInGameLog("[SESSION] Keys will be filtered for QUIC/Hytale only");

        // Start proxies
        int tcpListenPort = ListenPort + 1;
        TcpProxy.Start("0.0.0.0", tcpListenPort, TargetHost, TargetPort);
        Thread.Sleep(50);
        UdpProxy.Start("0.0.0.0", ListenPort, TargetHost, TargetPort);

        StartTime = DateTime.Now;
        _autoDecryptTimer?.Start();
        PacketDecryptor.StartAutoDecrypt();

        // Auto-copy
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

        // Delayed key scan - only our session file
        Task.Run(async () =>
        {
            await Task.Delay(5000);
            ScanSessionKeyFile(sessionKeyLog);
        });
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
            AddInGameLog($"[KEYS] Scanning {Path.GetFileName(sessionFilePath)} ({fileInfo.Length} bytes)");

            int keysAdded = 0;
            int linesChecked = 0;
            int quicLinesFound = 0;

            using (var fs = new FileStream(sessionFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            using (var reader = new StreamReader(fs))
            {
                string? line;
                while ((line = reader.ReadLine()) != null)
                {
                    linesChecked++;

                    if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#"))
                        continue;

                    // Debug: show first few lines
                    if (linesChecked <= 5)
                    {
                        AddInGameLog($"[KEYS-DEBUG] Line {linesChecked}: {line.Substring(0, Math.Min(50, line.Length))}...");
                    }

                    if (IsHytaleQuicKey(line))
                    {
                        quicLinesFound++;
                        var key = ParseSSLKeyLogLine(line, sessionFilePath);
                        if (key != null)
                        {
                            PacketDecryptor.AddKey(key);
                            keysAdded++;
                            AddInGameLog($"[KEYS] Added {key.Type} key");
                        }
                    }
                }
            }

            AddInGameLog($"[KEYS] Scanned {linesChecked} lines, found {quicLinesFound} QUIC entries, added {keysAdded} keys");

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
        // Browsers produce CLIENT_RANDOM, CLIENT_TRAFFIC_SECRET, etc. for TLS
        string[] quicLabels =
        {
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        "CLIENT_TRAFFIC_SECRET_0",
        "SERVER_TRAFFIC_SECRET_0",
        "CLIENT_EARLY_TRAFFIC_SECRET",
        "EXPORTER_SECRET"
    };

        // Must start with a QUIC label and have 3 parts (label + client_random + secret)
        var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 3) return false;

        return quicLabels.Any(label => parts[0].Equals(label, StringComparison.OrdinalIgnoreCase));
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
            if (parts.Length < 3) return null;

            string label = parts[0];

            // Double-check it's a QUIC label we want
            if (!IsHytaleQuicKey(line)) return null;

            byte[] clientRandom = Convert.FromHexString(parts[1]);
            byte[] secret = Convert.FromHexString(parts[2]);

            // Validate lengths
            if (clientRandom.Length != 32)
            {
                Log.Warn($"Unexpected client_random length: {clientRandom.Length} bytes", "Keys");
            }

            if (secret.Length != 32 && secret.Length != 48)
            {
                Log.Warn($"Unusual secret length: {secret.Length}B (expected 32 or 48)", "Keys");
            }

            // Determine key type based on label
            var keyType = label switch
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

            Log.Success($"Parsed {label} ({secret.Length * 8} bits) -> {keyType}", "Keys");
            return key;
        }
        catch (FormatException ex)
        {
            Log.Warn($"Hex decode failed: {ex.Message}", "Keys");
            return null;
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

        if (packet.Opcode > 0x1000 && packet.Direction == PacketDirection.ClientToServer)
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
            var name = Protocol.OpcodeRegistry.Label(kv.Key, PacketDirection.ServerToClient);
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