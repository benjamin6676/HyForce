// FILE: Core/AppState.cs - FIXED: UDP-ONLY WITH AUTO-DECRYPTION
using HyForce.Data;
using HyForce.Networking;
using HyForce.Protocol;
using System.Collections.Concurrent;

namespace HyForce.Core;

public class AppState : IDisposable
{
    private static readonly Lazy<AppState> _instance = new(() => new AppState());
    public static AppState Instance => _instance.Value;

    public Config Config { get; } = new();
    public UdpProxy UdpProxy { get; }

    public PacketLog PacketLog { get; }
    public TestLog Log { get; }
    public PlayerItemDatabase Database { get; }

    public string TargetHost { get; set; } = "127.0.0.1";
    public int TargetPort { get; set; } = 5520;
    public int ListenPort { get; set; } = 5521;

    public bool IsRunning => UdpProxy.IsRunning;
    public DateTime? StartTime { get; private set; }

    public long TotalPackets => PacketLog.TotalPackets;
    // REMOVED: TcpPackets - not used in UDP-only mode
    public long UdpPackets => PacketLog.PacketsUdp;

    public ConcurrentBag<SecurityEvent> SecurityEvents { get; } = new();
    public bool ShowAboutWindow;

    public List<string> InGameLog { get; } = new();
    public const int MaxInGameLogLines = 1000;

    public string ExportDirectory { get; set; } = @"C:\Users\benja\source\repos\HyForce\Exported logs";

    public event PacketReceivedHandler? OnPacketReceived;
    public event Action? OnSecurityEvent;

    // FIXED: Made this a proper event with public accessor
    public event Action? OnMemoryDataUpdated;

    // Auto-decryption timer
    private System.Timers.Timer? _autoDecryptTimer;

    public AppState()
    {
        Log = new TestLog();
        UdpProxy = new UdpProxy(Log);
        PacketLog = new PacketLog(10000);
        Database = new PlayerItemDatabase();

        UdpProxy.OnPacket += HandlePacket;
        Directory.CreateDirectory(ExportDirectory);

        // Setup auto-decryption attempts
        SetupAutoDecryption();
    }

    private void SetupAutoDecryption()
    {
        // Try to decrypt packets automatically every 5 seconds
        _autoDecryptTimer = new System.Timers.Timer(5000);
        _autoDecryptTimer.Elapsed += (s, e) =>
        {
            TryAutoDecryptPackets();
        };
        _autoDecryptTimer.AutoReset = true;
    }

    private void TryAutoDecryptPackets()
    {
        if (PacketDecryptor.DiscoveredKeys.Count == 0) return;

        // Auto-decrypt recent packets
        var recentPackets = PacketLog.GetLast(100);
        int decrypted = 0;

        foreach (var pkt in recentPackets)
        {
            if (pkt.EncryptionHint == "encrypted" && pkt.RawBytes.Length > 16)
            {
                var result = PacketDecryptor.TryDecrypt(pkt.RawBytes);
                if (result.Success)
                {
                    decrypted++;
                }
            }
        }

        if (decrypted > 0)
        {
            AddInGameLog($"[AUTO-DECRYPT] Decrypted {decrypted} packets automatically");
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

        UdpProxy.Start("0.0.0.0", ListenPort, TargetHost, TargetPort);
        StartTime = DateTime.Now;
        _autoDecryptTimer?.Start();

        Log.Info($"[HyForce] Started - UDP Proxy on 0.0.0.0:{ListenPort}", "System");
        Log.Info($"[HyForce] Forwarding to {TargetHost}:{TargetPort}", "System");
        Log.Info($"[HyForce] Hytale uses UDP/QUIC only - no TCP needed", "System");

        AddInGameLog($"UDP Proxy started on 127.0.0.1:{ListenPort}");
        AddInGameLog($"Connect Hytale to 127.0.0.1:{ListenPort}");

        // AUTO-COPY IP TO CLIPBOARD
        try
        {
            string connectString = $"127.0.0.1:{ListenPort}";
            TextCopy.ClipboardService.SetText(connectString);
            AddInGameLog($"[AUTO-COPY] {connectString} copied to clipboard!");
            Log.Success($"Connect address copied to clipboard: {connectString}", "System");
        }
        catch (Exception ex)
        {
            Log.Warn($"Failed to copy to clipboard: {ex.Message}", "System");
        }

        // AUTO-ATTEMPT SSLKEYLOGFILE
        TryEnableSSLKeyLogFile();
    }

    private void TryEnableSSLKeyLogFile()
    {
        try
        {
            // Set environment variable for Hytale process if it reads it
            string keyLogPath = Path.Combine(ExportDirectory, "sslkeys.log");
            Environment.SetEnvironmentVariable("SSLKEYLOGFILE", keyLogPath);
            AddInGameLog($"[AUTO-DECRYPT] SSLKEYLOGFILE set to: {keyLogPath}");

            // Also try to find existing key log files
            var existingLogs = Directory.GetFiles(ExportDirectory, "*.log")
                .Where(f => f.Contains("key", StringComparison.OrdinalIgnoreCase) ||
                           f.Contains("ssl", StringComparison.OrdinalIgnoreCase));

            foreach (var log in existingLogs)
            {
                AddInGameLog($"[AUTO-DECRYPT] Found existing key log: {Path.GetFileName(log)}");
                TryLoadKeysFromFile(log);
            }
        }
        catch (Exception ex)
        {
            Log.Warn($"SSLKEYLOGFILE setup failed: {ex.Message}", "System");
        }
    }

    public void TryLoadKeysFromFile(string path)
    {
        try
        {
            if (!File.Exists(path)) return;

            var lines = File.ReadAllLines(path);
            int keysAdded = 0;

            foreach (var line in lines)
            {
                // Parse SSLKEYLOGFILE format: CLIENT_HANDSHAKE_TRAFFIC_SECRET <client_random> <secret>
                if (line.StartsWith("CLIENT_TRAFFIC_SECRET_0") ||
                    line.StartsWith("SERVER_TRAFFIC_SECRET_0") ||
                    line.StartsWith("CLIENT_HANDSHAKE_TRAFFIC_SECRET"))
                {
                    var parts = line.Split(' ');
                    if (parts.Length >= 3)
                    {
                        var secret = Convert.FromHexString(parts[2]);
                        if (secret.Length == 32 || secret.Length == 48) // AES-256-GCM or ChaCha20
                        {
                            PacketDecryptor.AddKey(new PacketDecryptor.EncryptionKey
                            {
                                Key = secret,
                                IV = new byte[12],
                                Type = secret.Length == 32 ?
                                    PacketDecryptor.EncryptionType.AES256GCM :
                                    PacketDecryptor.EncryptionType.ChaCha20Poly1305,
                                Source = $"SSLKEYLOGFILE: {Path.GetFileName(path)}"
                            });
                            keysAdded++;
                        }
                    }
                }
            }

            if (keysAdded > 0)
            {
                AddInGameLog($"[AUTO-DECRYPT] Loaded {keysAdded} keys from {Path.GetFileName(path)}");
            }
        }
        catch (Exception ex)
        {
            AddInGameLog($"[AUTO-DECRYPT] Failed to load keys: {ex.Message}");
        }
    }

    public void Stop()
    {
        UdpProxy.Stop();
        StartTime = null;
        _autoDecryptTimer?.Stop();
        Log.Info("[HyForce] Proxy stopped", "System");
        AddInGameLog("Proxy stopped");
    }

    private void HandlePacket(CapturedPacket packet)
    {
        PacketLog.Add(packet);
        AnalyzePacket(packet);
        Database.ProcessPacket(packet);
        OnPacketReceived?.Invoke(packet);
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

    // FIXED: Public method to trigger memory scan from menu
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
        Log.Info("[HyForce] All data cleared", "System");
        AddInGameLog("All data cleared");
    }

    public string GenerateDiagnostics()
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("+------------------------------------------------------------------------------+");
        sb.AppendLine("                    HYFORCE V22-ENHANCED - UDP-ONLY MODE                       ");
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
        sb.AppendLine($"Mode: UDP-ONLY (Hytale uses QUIC/UDP)");
        sb.AppendLine($"Target: {TargetHost}:{TargetPort}");
        sb.AppendLine($"Listen: 0.0.0.0:{ListenPort}");
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

        sb.AppendLine("-------------------------------------------------------------------------------");
        sb.AppendLine("                              TRAFFIC STATISTICS                               ");
        sb.AppendLine("-------------------------------------------------------------------------------");
        sb.AppendLine($"Total Packets: {TotalPackets:N0}");
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
            sb.AppendLine($"[{pkt.Timestamp:HH:mm:ss.fff}] {pkt.DirStr} UDP " +
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
        Stop();
        UdpProxy.OnPacket -= HandlePacket;
        _autoDecryptTimer?.Dispose();
    }
}