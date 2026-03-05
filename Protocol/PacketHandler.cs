using HyForce.Core;
using HyForce.Data;
using HyForce.Networking;
using System;
using System.Collections.Generic;
using System.IO;

namespace HyForce.Protocol
{
    /// <summary>
    /// PacketHandler v16 — fully non-blocking.
    /// Auto-decrypt is processed on a dedicated background worker (never the UI thread).
    /// </summary>
    public class PacketHandler
    {
        private readonly AppState _state;
        private volatile int _decryptSuccesses;
        private volatile int _decryptFailures;

        public int DecryptSuccesses => _decryptSuccesses;
        public int DecryptFailures  => _decryptFailures;

        public PacketHandler(AppState state)
        {
            _state = state;

            // Wire up the background decrypt result event
            PacketDecryptor.OnDecrypted -= HandleDecrypted; // safety: remove first
            PacketDecryptor.OnDecrypted += HandleDecrypted;
        }

        /// <summary>
        /// Called from the OnDecrypted background event — NOT on UI thread.
        /// </summary>
        private void HandleDecrypted(byte[] encrypted, byte[] decrypted)
        {
            System.Threading.Interlocked.Increment(ref _decryptSuccesses);
            _state.AddInGameLog($"[DECRYPT] ✓ {decrypted.Length}B decrypted");

            // Future: parse Hytale frames from decrypted bytes here
        }

        /// <summary>
        /// Process packet — ALWAYS returns immediately, zero blocking.
        /// </summary>
        public void ProcessPacket(CapturedPacket packet)
        {
            try
            {
                if (packet?.RawBytes == null || packet.RawBytes.Length < 20) return;

                // Short header 1-RTT = post-handshake gameplay packets
                bool isShortHeader = (packet.RawBytes[0] & 0x80) == 0;
                if (!isShortHeader) return; // skip long-header (handshake etc.)

                if (PacketDecryptor.AutoDecryptEnabled && PacketDecryptor.DiscoveredKeys.Count > 0)
                {
                    // Enqueue for background worker — never blocks here
                    var result = PacketDecryptor.TryDecrypt(packet.RawBytes);
                    if (!result.Success &&
                        result.Error != null &&
                        !result.Error.StartsWith("Queued") &&
                        !result.Error.StartsWith("Auto-decrypt disabled"))
                    {
                        System.Threading.Interlocked.Increment(ref _decryptFailures);
                    }
                }
            }
            catch { }
        }
    }
}
