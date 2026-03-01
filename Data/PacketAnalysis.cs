// FILE: Data/PacketAnalysis.cs
using System.Collections.Generic;

namespace HyForce.Data;

public class PacketAnalysis
{
    public ushort Opcode { get; set; }
    public string OpcodeHex { get; set; } = "";
    public string PacketName { get; set; } = "Unknown";
    public PacketCategory Category { get; set; }
    public string Description { get; set; } = "";
    public bool IsCritical { get; set; }
    public int PayloadOffset { get; set; }
    public int PayloadLength { get; set; }
    public Dictionary<string, string> Fields { get; set; } = new();
    public double Entropy { get; set; }
    public bool EncryptionLikely { get; set; }
    public bool IsRegistrySync { get; set; }
    public string CompressionHint { get; set; } = "";
    public string QuicHeaderType { get; set; } = "";
    public string QuicVersion { get; set; } = "";
}