using HyForce.Core;
using HyForce.Data;
using HyForce.Networking;
using System;
using System.Collections.Generic;

namespace HyForce.Protocol
{
    /// <summary>
    /// SIMPLIFIED PacketHandler - No blocking, no lag
    /// </summary>
    public class PacketHandler
    {
        private readonly AppState _state;
        private readonly HashSet<ushort> _interestingOpcodes = new();

        public PacketHandler(AppState state)
        {
            _state = state;
        }

        /// <summary>
        /// Process packet - FAST, no blocking
        /// </summary>
        public void ProcessPacket(CapturedPacket packet)
        {
            try
            {
                // Quick log - no complex operations
                if (PacketDecryptor.DebugMode)
                {
                    Console.WriteLine($"[PACKET] {packet.SequenceId} - {packet.RawBytes.Length}b - 0x{packet.Opcode:X4}");
                }

                // Only attempt decryption if auto-decrypt is enabled AND we have keys
                if (PacketDecryptor.AutoDecryptEnabled && PacketDecryptor.DiscoveredKeys.Count > 0)
                {
                    // Quick check if encrypted
                    if (packet.RawBytes.Length > 20 && (packet.RawBytes[0] & 0x80) == 0)
                    {
                        // Try decrypt - this is async and has timeout
                        var result = PacketDecryptor.TryDecrypt(packet.RawBytes);

                        if (result?.Success == true && result.DecryptedData != null)
                        {
                            _state.AddInGameLog($"[DECRYPT] {packet.Opcode:X4} OK ({result.DecryptedData.Length}b)");
                        }
                        else if (PacketDecryptor.DebugMode)
                        {
                            Console.WriteLine($"[DECRYPT] {packet.Opcode:X4} FAIL");
                        }
                    }
                }
            }
            catch
            {
                // Silently fail - don't crash the game
            }
        }
    }
}