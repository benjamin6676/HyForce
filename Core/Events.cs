using HyForce.Data;
using HyForce.Networking;

namespace HyForce.Core;

public delegate void PacketHandler(CapturedPacket packet);
public delegate void LogHandler(string message, string category);
public delegate void SecurityEventHandler(SecurityEvent evt);