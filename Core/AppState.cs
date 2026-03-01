using HyForce.Data;
using HyForce.Networking;
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

    public string ExportDirectory { get; set; } = @"C:\Users\benja\source\repos\HyForce";

    public event Action? OnPacketReceived;
    public event Action? OnSecurityEvent;

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

        // IMPORTANT: Use 127.0.0.1 for localhost binding to ensure Hytale can connect
        TcpProxy.Start("127.0.0.1", tcpPort, TargetHost, TargetPort);
        UdpProxy.Start("0.0.0.0", udpPort, TargetHost, TargetPort);

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
            if (packet.Opcode == Protocol.OpcodeRegistry.RegistryOpcode ||
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
        sb.AppendLine("╔══════════════════════════════════════════════════════════════╗");
        sb.AppendLine("║           HYFORCE V22-ENHANCED - DIAGNOSTICS REPORT          ║");
        sb.AppendLine("╚══════════════════════════════════════════════════════════════╝");
        sb.AppendLine();
        sb.AppendLine($"Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine();

        sb.AppendLine("─── CONFIGURATION ───");
        sb.AppendLine($"Mode: {(UseUnifiedPort ? "Unified Port" : "Separate Ports")}");
        sb.AppendLine($"Target: {TargetHost}:{TargetPort}");
        sb.AppendLine();

        sb.AppendLine("─── PROXY STATUS ───");
        sb.AppendLine($"TCP Proxy: {(TcpProxy.IsRunning ? "RUNNING ✓" : "STOPPED")}");
        sb.AppendLine($"UDP Proxy: {(UdpProxy.IsRunning ? "RUNNING ✓" : "STOPPED")}");
        sb.AppendLine($"TCP Sessions: {TcpProxy.ActiveSessions}");
        sb.AppendLine($"UDP Sessions: {UdpProxy.ActiveSessions}");
        sb.AppendLine();

        sb.AppendLine("─── TRAFFIC STATISTICS ───");
        sb.AppendLine($"Total Packets: {TotalPackets:N0}");
        sb.AppendLine($"  TCP: {TcpPackets:N0} (Registry/Login)");
        sb.AppendLine($"  UDP: {UdpPackets:N0} (Gameplay)");
        sb.AppendLine($"Unique Opcodes: {PacketLog.UniqueOpcodes}");
        sb.AppendLine();

        sb.AppendLine("─── REGISTRY DATA ───");
        sb.AppendLine($"RegistrySync Received: {Protocol.RegistrySyncParser.RegistrySyncReceived}");
        sb.AppendLine($"Items Parsed: {Protocol.RegistrySyncParser.NumericIdToName.Count:N0}");
        sb.AppendLine($"Players Seen: {Protocol.RegistrySyncParser.PlayerNamesSeen.Count:N0}");
        sb.AppendLine();

        sb.AppendLine("─── SECURITY EVENTS ───");
        sb.AppendLine($"Total Events: {SecurityEvents.Count:N0}");
        var categories = SecurityEvents.GroupBy(e => e.Category).Select(g => $"{g.Key}: {g.Count()}");
        sb.AppendLine($"By Category: {string.Join(", ", categories)}");
        sb.AppendLine();

        sb.AppendLine("─── RECENT EVENTS ───");
        foreach (var evt in SecurityEvents.TakeLast(10))
        {
            sb.AppendLine($"[{evt.Timestamp:HH:mm:ss}] [{evt.Category}] {evt.Message}");
        }

        return sb.ToString();
    }

    public string ExportPacketLog()
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("=== HYFORCE PACKET LOG ===");
        sb.AppendLine($"Export Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine();

        var packets = PacketLog.GetAll();
        foreach (var pkt in packets)
        {
            sb.AppendLine($"[{pkt.Timestamp:HH:mm:ss}] {pkt.DirStr} {pkt.ProtoStr} " +
                $"0x{pkt.OpcodeDecimal:X2} ({pkt.OpcodeName}) {pkt.ByteLength} bytes " +
                $"[{pkt.CompressionMethod}]");
        }

        return sb.ToString();
    }

    public void Dispose()
    {
        Stop();
        TcpProxy.OnPacket -= HandlePacket;
        UdpProxy.OnPacket -= HandlePacket;
    }
}