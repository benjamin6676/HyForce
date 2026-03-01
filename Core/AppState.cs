// FILE: Core/AppState.cs
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

    public TcpProxy TcpProxy { get; }
    public UdpProxy UdpProxy { get; }

    public PacketLog PacketLog { get; }
    public TestLog Log { get; }
    public PlayerItemDatabase Database { get; }

    public string TargetHost { get; set; } = "127.0.0.1";
    public int TargetPort { get; set; } = 5520;
    public bool UseUnifiedPort { get; set; } = true;
    public int UnifiedPort { get; set; } = 5521;
    public int TcpListenPort { get; set; } = 5521;
    public int UdpListenPort { get; set; } = 5521;

    public bool IsRunning => TcpProxy.IsRunning || UdpProxy.IsRunning;
    public DateTime? StartTime { get; private set; }

    public long TotalPackets => PacketLog.TotalPackets;
    public long TcpPackets => PacketLog.PacketsTcp;
    public long UdpPackets => PacketLog.PacketsUdp;

    public ConcurrentBag<SecurityEvent> SecurityEvents { get; } = new();

    public bool ShowAboutWindow;

    public List<string> InGameLog { get; } = new();
    public const int MaxInGameLogLines = 1000;

    public string ExportDirectory { get; set; } = @"C:\Users\benja\source\repos\HyForce\Exported logs";

    public event Action? OnPacketReceived;
    public event Action? OnSecurityEvent;

    public event Action? OnMemoryDataUpdated;

    public AppState()
    {
        Log = new TestLog();
        TcpProxy = new TcpProxy(Log);
        UdpProxy = new UdpProxy(Log);
        PacketLog = new PacketLog(10000);
        Database = new PlayerItemDatabase();

        TcpProxy.OnPacket += HandlePacket;
        UdpProxy.OnPacket += HandlePacket;

        Directory.CreateDirectory(ExportDirectory);
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

        int tcpPort = UseUnifiedPort ? UnifiedPort : TcpListenPort;
        int udpPort = UseUnifiedPort ? UnifiedPort : UdpListenPort;

        TcpProxy.Start("127.0.0.1", tcpPort, TargetHost, TargetPort);

        Thread.Sleep(200);

        UdpProxy.Start("127.0.0.1", udpPort, TargetHost, TargetPort);

        StartTime = DateTime.Now;

        Log.Info($"[HyForce] Started - Mode: {(UseUnifiedPort ? "Unified" : "Separate")} Port", "System");
        Log.Info($"[HyForce] TCP Port: {tcpPort} (RegistrySync)", "System");
        Log.Info($"[HyForce] UDP Port: {udpPort} (QUIC Gameplay)", "System");
        Log.Info($"[HyForce] Connect Hytale to 127.0.0.1:{tcpPort}", "System");

        AddInGameLog($"Proxies started on 127.0.0.1:{tcpPort}");
        AddInGameLog("Connect Hytale client to 127.0.0.1:" + tcpPort);
    }

    public void Stop()
    {
        TcpProxy.Stop();
        UdpProxy.Stop();
        StartTime = null;
        Log.Info("[HyForce] Proxies stopped", "System");
        AddInGameLog("Proxies stopped");
    }

    private void HandlePacket(CapturedPacket packet)
    {
        PacketLog.Add(packet);
        AnalyzePacket(packet);
        Database.ProcessPacket(packet);
        OnPacketReceived?.Invoke();
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

        if (packet.IsTcp && packet.Direction == PacketDirection.ServerToClient)
        {
            if (packet.Opcode == OpcodeRegistry.RegistryOpcode ||
                (packet.Opcode >= 0x28 && packet.Opcode <= 0x3F))
            {
                LogSecurityEvent("Registry", $"RegistrySync detected: 0x{packet.Opcode:X2}", new Dictionary<string, object>
                {
                    ["opcode"] = packet.Opcode,
                    ["size"] = packet.RawBytes.Length
                });
            }
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
        sb.AppendLine("╔══════════════════════════════════════════════════════════════════════════════╗");
        sb.AppendLine("║                    HYFORCE V22-ENHANCED - FULL DIAGNOSTICS REPORT            ║");
        sb.AppendLine("╚══════════════════════════════════════════════════════════════════════════════╝");
        sb.AppendLine();
        sb.AppendLine($"Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"Session Duration: {(StartTime.HasValue ? FormatDuration(DateTime.Now - StartTime.Value) : "Not running")}");
        sb.AppendLine();

        sb.AppendLine("═══════════════════════════════════════════════════════════════════════════════");
        sb.AppendLine("                              SYSTEM INFORMATION                               ");
        sb.AppendLine("═══════════════════════════════════════════════════════════════════════════════");
        sb.AppendLine($"OS: {Environment.OSVersion}");
        sb.AppendLine($".NET Version: {Environment.Version}");
        sb.AppendLine($"Machine: {Environment.MachineName}");
        sb.AppendLine($"Processor Count: {Environment.ProcessorCount}");
        sb.AppendLine();

        sb.AppendLine("═══════════════════════════════════════════════════════════════════════════════");
        sb.AppendLine("                                CONFIGURATION                                  ");
        sb.AppendLine("═══════════════════════════════════════════════════════════════════════════════");
        sb.AppendLine($"Mode: {(UseUnifiedPort ? "Unified Port" : "Separate Ports")}");
        sb.AppendLine($"Target: {TargetHost}:{TargetPort}");
        sb.AppendLine($"Listen: 127.0.0.1:{UnifiedPort}");
        sb.AppendLine($"Export Path: {ExportDirectory}");
        sb.AppendLine();

        sb.AppendLine("═══════════════════════════════════════════════════════════════════════════════");
        sb.AppendLine("                                PROXY STATUS                                   ");
        sb.AppendLine("═══════════════════════════════════════════════════════════════════════════════");
        sb.AppendLine($"TCP Proxy: {(TcpProxy.IsRunning ? "RUNNING ✓" : "STOPPED")}");
        sb.AppendLine($"  - Status: {TcpProxy.StatusMessage}");
        sb.AppendLine($"  - Active Sessions: {TcpProxy.ActiveSessions}");
        sb.AppendLine($"  - Total Connections: {TcpProxy.TotalConnections}");
        sb.AppendLine();
        sb.AppendLine($"UDP Proxy: {(UdpProxy.IsRunning ? "RUNNING ✓" : "STOPPED")}");
        sb.AppendLine($"  - Status: {UdpProxy.StatusMessage}");
        sb.AppendLine($"  - Active Sessions: {UdpProxy.ActiveSessions}");
        sb.AppendLine($"  - Total Clients: {UdpProxy.TotalClients}");
        sb.AppendLine();

        sb.AppendLine("═══════════════════════════════════════════════════════════════════════════════");
        sb.AppendLine("                              TRAFFIC STATISTICS                               ");
        sb.AppendLine("═══════════════════════════════════════════════════════════════════════════════");
        sb.AppendLine($"Total Packets: {TotalPackets:N0}");
        sb.AppendLine($"  TCP: {TcpPackets:N0} ({FormatBytes(PacketLog.BytesTcp)} bytes) - Registry/Login");
        sb.AppendLine($"  UDP: {UdpPackets:N0} ({FormatBytes(PacketLog.BytesUdp)} bytes) - Gameplay");
        sb.AppendLine();
        sb.AppendLine($"Bytes Total: {FormatBytes(PacketLog.BytesSc + PacketLog.BytesCs)}");
        sb.AppendLine($"  Server→Client: {FormatBytes(PacketLog.BytesSc)}");
        sb.AppendLine($"  Client→Server: {FormatBytes(PacketLog.BytesCs)}");
        sb.AppendLine();
        sb.AppendLine($"Unique Opcodes: {PacketLog.UniqueOpcodes}");
        sb.AppendLine();

        sb.AppendLine("═══════════════════════════════════════════════════════════════════════════════");
        sb.AppendLine("                                TOP 20 OPCODES                                 ");
        sb.AppendLine("═══════════════════════════════════════════════════════════════════════════════");
        var topOpcodes = PacketLog.GetOpcodeCounts().OrderByDescending(x => x.Value).Take(20);
        foreach (var kv in topOpcodes)
        {
            var name = OpcodeRegistry.Label(kv.Key, PacketDirection.ServerToClient);
            var pct = TotalPackets > 0 ? (kv.Value / (double)TotalPackets * 100) : 0;
            sb.AppendLine($"  0x{kv.Key:X4} ({name,-20}): {kv.Value,6} packets ({pct:F1}%)");
        }
        sb.AppendLine();

        sb.AppendLine("═══════════════════════════════════════════════════════════════════════════════");
        sb.AppendLine("                                REGISTRY DATA                                  ");
        sb.AppendLine("═══════════════════════════════════════════════════════════════════════════════");
        sb.AppendLine($"RegistrySync Received: {RegistrySyncParser.RegistrySyncReceived}");
        sb.AppendLine($"Found at Opcode: 0x{RegistrySyncParser.FoundAtOpcode:X4}");
        sb.AppendLine();
        sb.AppendLine($"Items Parsed: {RegistrySyncParser.NumericIdToName.Count:N0}");
        sb.AppendLine($"String IDs: {RegistrySyncParser.StringIdToName.Count:N0}");
        sb.AppendLine($"Player Names: {RegistrySyncParser.PlayerNamesSeen.Count:N0}");
        sb.AppendLine($"Total Entries: {RegistrySyncParser.TotalParsed}");
        sb.AppendLine();

        if (RegistrySyncParser.NumericIdToName.Count > 0)
        {
            sb.AppendLine("--- Sample Items (First 50) ---");
            foreach (var item in RegistrySyncParser.NumericIdToName.Take(50))
            {
                sb.AppendLine($"  [{item.Key:X8}] {item.Value}");
            }
            sb.AppendLine();
        }

        if (RegistrySyncParser.PlayerNamesSeen.Count > 0)
        {
            sb.AppendLine("--- Detected Players ---");
            foreach (var player in RegistrySyncParser.PlayerNamesSeen.Take(50))
            {
                sb.AppendLine($"  - {player}");
            }
            sb.AppendLine();
        }

        sb.AppendLine("═══════════════════════════════════════════════════════════════════════════════");
        sb.AppendLine("                               PLAYER DATABASE                                 ");
        sb.AppendLine("═══════════════════════════════════════════════════════════════════════════════");
        sb.AppendLine($"Unique Items: {Database.Items.Count:N0}");
        sb.AppendLine($"Unique Players: {Database.Players.Count:N0}");
        sb.AppendLine();

        sb.AppendLine("═══════════════════════════════════════════════════════════════════════════════");
        sb.AppendLine("                               SECURITY EVENTS                                 ");
        sb.AppendLine("═══════════════════════════════════════════════════════════════════════════════");
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

        sb.AppendLine("═══════════════════════════════════════════════════════════════════════════════");
        sb.AppendLine("                                IN-GAME LOG                                    ");
        sb.AppendLine("═══════════════════════════════════════════════════════════════════════════════");
        lock (InGameLog)
        {
            foreach (var line in InGameLog.TakeLast(50))
            {
                sb.AppendLine(line);
            }
        }
        sb.AppendLine();

        sb.AppendLine("═══════════════════════════════════════════════════════════════════════════════");
        sb.AppendLine("                           END OF DIAGNOSTICS REPORT                           ");
        sb.AppendLine("═══════════════════════════════════════════════════════════════════════════════");

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
            sb.AppendLine($"[{pkt.Timestamp:HH:mm:ss.fff}] {pkt.DirStr} {pkt.ProtoStr} " +
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

            if (RegistrySyncParser.NumericIdToName.Count > 0)
            {
                var itemsSb = new System.Text.StringBuilder();
                itemsSb.AppendLine("=== ITEMS ===");
                foreach (var item in RegistrySyncParser.NumericIdToName.OrderBy(x => x.Key))
                {
                    itemsSb.AppendLine($"{item.Key:X8} = {item.Value}");
                }
                File.WriteAllText(Path.Combine(basePath, "items.txt"), itemsSb.ToString());
            }

            if (RegistrySyncParser.PlayerNamesSeen.Count > 0)
            {
                File.WriteAllLines(Path.Combine(basePath, "players.txt"), RegistrySyncParser.PlayerNamesSeen);
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
        TcpProxy.OnPacket -= HandlePacket;
        UdpProxy.OnPacket -= HandlePacket;
    }
}