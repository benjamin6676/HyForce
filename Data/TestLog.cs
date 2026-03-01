namespace HyForce.Data;

public class TestLog
{
    private const int MaxLines = 5000;
    private readonly List<LogEntry> _entries = new(MaxLines + 64);
    private readonly object _lock = new();
    private int _version;

    public enum LogLevel { DEBUG, INFO, SUCCESS, WARNING, ERROR, SECURITY, PACKET }

    public class LogEntry
    {
        public DateTime Timestamp { get; set; }
        public LogLevel Level { get; set; }
        public string Category { get; set; } = "";
        public string Message { get; set; } = "";
        public Dictionary<string, object>? Metadata { get; set; }
    }

    public int Version
    {
        get { lock (_lock) return _version; }
    }

    public string[] GetLines()
    {
        lock (_lock)
        {
            return _entries.Select(e =>
                $"[{e.Timestamp:HH:mm:ss}] [{e.Level}] [{e.Category}] {e.Message}")
                .ToArray();
        }
    }

    public void Clear()
    {
        lock (_lock)
        {
            _entries.Clear();
            _version++;
        }
    }

    public void Debug(string msg, string category = "General") => Append(LogLevel.DEBUG, category, msg);
    public void Info(string msg, string category = "General") => Append(LogLevel.INFO, category, msg);
    public void Success(string msg, string category = "General") => Append(LogLevel.SUCCESS, category, msg);
    public void Warn(string msg, string category = "General") => Append(LogLevel.WARNING, category, msg);
    public void Error(string msg, string category = "General") => Append(LogLevel.ERROR, category, msg);

    public void Security(string msg, string category, Dictionary<string, object> metadata)
    {
        Append(LogLevel.SECURITY, category, msg, metadata);
    }

    public void Packet(string direction, ushort opcode, string proto, int size, string analysis)
    {
        var meta = new Dictionary<string, object>
        {
            ["direction"] = direction,
            ["opcode"] = opcode,
            ["protocol"] = proto,
            ["size"] = size
        };
        Append(LogLevel.PACKET, "PacketCapture", $"[{direction}] 0x{opcode:X2} {proto} {size}B - {analysis}", meta);
    }

    private void Append(LogLevel level, string category, string message, Dictionary<string, object>? metadata = null)
    {
        lock (_lock)
        {
            _entries.Add(new LogEntry
            {
                Timestamp = DateTime.Now,
                Level = level,
                Category = category,
                Message = message,
                Metadata = metadata
            });

            if (_entries.Count > MaxLines)
                _entries.RemoveRange(0, _entries.Count - MaxLines);

            _version++;
        }
    }

    public List<LogEntry> GetEntries()
    {
        lock (_lock) return new List<LogEntry>(_entries);
    }

    public List<LogEntry> GetByLevel(LogLevel level)
    {
        lock (_lock) return _entries.Where(e => e.Level == level).ToList();
    }

    public string ExportAnalysisLog()
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("=== HYFORCE - ANALYSIS LOG ===");
        sb.AppendLine($"Export Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine();

        lock (_lock)
        {
            var security = _entries.Where(e => e.Level == LogLevel.SECURITY).ToList();
            if (security.Any())
            {
                sb.AppendLine("--- SECURITY EVENTS ---");
                foreach (var evt in security)
                {
                    sb.AppendLine($"[{evt.Timestamp:HH:mm:ss}] [{evt.Category}] {evt.Message}");
                    if (evt.Metadata != null)
                        foreach (var kvp in evt.Metadata)
                            sb.AppendLine($"    {kvp.Key}: {kvp.Value}");
                }
                sb.AppendLine();
            }

            sb.AppendLine("--- FULL LOG ---");
            foreach (var entry in _entries)
            {
                string levelStr = entry.Level.ToString().PadRight(8);
                sb.AppendLine($"[{entry.Timestamp:HH:mm:ss}] [{levelStr}] [{entry.Category}] {entry.Message}");
            }
        }

        return sb.ToString();
    }

    public string GetText()
    {
        lock (_lock)
            return string.Join("\n", _entries.Select(e =>
                $"[{e.Timestamp:HH:mm:ss}] [{e.Level}] [{e.Category}] {e.Message}"));
    }
}