namespace HyForce.Data;

public class SecurityEvent
{
    public DateTime Timestamp { get; set; }
    public string Category { get; set; } = "";
    public string Message { get; set; } = "";
    public string Description => Message; // Alias for compatibility
    public Dictionary<string, object> Metadata { get; set; } = new();
    public SecuritySeverity Severity { get; set; } = SecuritySeverity.Info;
}

public enum SecuritySeverity
{
    Debug,
    Info,
    Warning,
    Error,
    Critical
}