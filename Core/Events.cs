using HyForce.Data;
using HyForce.Networking;

namespace HyForce.Core;

// RENAMED from PacketHandler to PacketReceivedHandler to avoid ambiguity
public delegate void PacketReceivedHandler(CapturedPacket packet);
public delegate void LogHandler(string message, string category);
public delegate void SecurityEventHandler(SecurityEvent evt);