// FILE: Networking/QuicHeaderInfo.cs
namespace HyForce.Networking;

public enum QuicHeaderType
{
    Initial,
    Handshake,
    ZeroRtt,
    OneRtt,
    Retry,
    VersionNegotiation,
    Unknown
}

public class QuicHeaderInfo
{
    public bool IsLongHeader { get; set; }
    public uint Version { get; set; }
    public byte[]? DestinationConnectionId { get; set; }
    public byte[]? SourceConnectionId { get; set; }
    public uint PacketNumber { get; set; }
    public ulong TokenLength { get; set; }
    public ulong Length { get; set; }

    public string HeaderType => IsLongHeader ? "Long" : "Short";

    public QuicHeaderType DetailedHeaderType => IsLongHeader switch
    {
        true when Version == 0 => QuicHeaderType.VersionNegotiation,
        true when (DestinationConnectionId?.Length > 0) => QuicHeaderType.Initial,
        _ => IsLongHeader ? QuicHeaderType.Handshake : QuicHeaderType.OneRtt
    };
}