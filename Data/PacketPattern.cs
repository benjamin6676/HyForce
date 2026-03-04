// FILE: Data/PacketPattern.cs
using HyForce.Networking;

namespace HyForce.Data;

public class PacketPattern
{
    public ushort Opcode { get; set; }
    public string PacketName { get; set; } = "";
    public int Count { get; set; }
    public int AvgSize { get; set; }
    public PacketDirection Direction { get; set; }
    public bool IsPeriodic { get; set; }
    public double PeriodMs { get; set; }
    public bool IsBurst { get; set; }
    public double RatePerSecond { get; set; }
}