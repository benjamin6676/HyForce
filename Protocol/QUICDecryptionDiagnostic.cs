// QUICDecryptionDiagnostic.cs
// Deep diagnostic tool for QUIC packet decryption failures.
// Shows exactly what each step produces so we can pinpoint the real failure.

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace HyForce
{
    public static class QUICDecryptionDiagnostic
    {
        public class DiagResult
        {
            public bool Success { get; set; }
            public string Summary { get; set; } = "";
            public List<string> Steps  { get; set; } = new();
            public List<string> Errors { get; set; } = new();

            public string Full => string.Join("\n", Steps.Concat(Errors));
        }

        /// <summary>
        /// Diagnose a single raw QUIC packet against all loaded keys.
        /// Returns a verbose step-by-step report.
        /// </summary>
        public static DiagResult DiagnosePacket(byte[] packet)
        {
            var r = new DiagResult();

            if (packet == null || packet.Length < 20)
            {
                r.Errors.Add($"[DIAG] Packet too short: {packet?.Length ?? 0} bytes (need >= 20)");
                r.Summary = "Packet too short";
                return r;
            }

            byte firstByte = packet[0];
            bool isLong    = (firstByte & 0x80) != 0;
            r.Steps.Add($"[DIAG] === QUIC Packet Diagnostic ===");
            r.Steps.Add($"[DIAG] Length : {packet.Length} bytes");
            r.Steps.Add($"[DIAG] First  : 0x{firstByte:X2}  ({(isLong ? "Long" : "Short")} header)");
            r.Steps.Add($"[DIAG] Hex[0..15]: {Hex(packet, 0, Math.Min(16, packet.Length))}");

            if (isLong)
            {
                int off = 1;
                uint version = BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(off)); off += 4;
                r.Steps.Add($"[DIAG] Version : 0x{version:X8}");
                byte dcidLen = packet[off++];
                r.Steps.Add($"[DIAG] DCID Len: {dcidLen}");
                if (dcidLen > 0 && off + dcidLen <= packet.Length)
                    r.Steps.Add($"[DIAG] DCID    : {Hex(packet, off, dcidLen)}");
            }
            else
            {
                r.Steps.Add($"[DIAG] Short header — Fixed={((firstByte>>6)&1)} Spin={((firstByte>>5)&1)} KP={(firstByte>>2)&1} PN_len={(firstByte&3)+1}");
            }

            // Collect all valid keys
            var keys = PacketDecryptor.DiscoveredKeys.Where(k => k.IsValid).ToList();
            r.Steps.Add($"[DIAG] Keys available: {keys.Count}");

            if (keys.Count == 0)
            {
                r.Errors.Add("[DIAG] No valid keys — load sslkeys_permanent.log first");
                r.Summary = "No keys";
                return r;
            }

            // Show first key's derived values for inspection
            var k0 = keys.First();
            r.Steps.Add($"[DIAG] Key[0] type  : {k0.Type}");
            r.Steps.Add($"[DIAG] Key[0] secret : {Hex(k0.Secret)}");
            r.Steps.Add($"[DIAG] Key[0] key    : {Hex(k0.Key)}");
            r.Steps.Add($"[DIAG] Key[0] iv     : {Hex(k0.IV)}");
            r.Steps.Add($"[DIAG] Key[0] hp     : {Hex(k0.HeaderProtectionKey)}");

            // Try all keys with DCID 0..20
            bool anySuccess = false;
            foreach (var key in keys.Take(10))
            {
                for (int dcid = 0; dcid <= 20; dcid++)
                {
                    var result = DiagnoseOneAttempt(packet, key, dcid, r.Steps);
                    if (result)
                    {
                        r.Success = true;
                        anySuccess = true;
                        r.Summary = $"SUCCESS: {key.Type} DCID={dcid}";
                        r.Steps.Add($"[DIAG] ✓ DECRYPTED with key={key.Type} dcid={dcid}");
                        return r;
                    }
                }
            }

            if (!anySuccess)
            {
                r.Steps.Add("[DIAG] All attempts failed. Likely causes:");
                r.Steps.Add("[DIAG]   1. Keys from a different TLS session (wrong client_random)");
                r.Steps.Add("[DIAG]   2. Packet is still handshake-phase (needs different key type)");
                r.Steps.Add("[DIAG]   3. Netty QUIC using non-standard DCID or HP algorithm");
                r.Summary = "All attempts failed";
            }

            return r;
        }

        private static bool DiagnoseOneAttempt(byte[] packet, PacketDecryptor.EncryptionKey key, int dcidLen, List<string> steps)
        {
            try
            {
                byte firstByte = packet[0];
                bool isLong    = (firstByte & 0x80) != 0;

                int pnOffset, sampleOffset;
                if (isLong)
                {
                    int off = 1 + 4; // skip first byte + version
                    byte dcidLenByte = packet[off++];
                    off += dcidLenByte; // skip DCID
                    byte scidLen = packet[off++];
                    off += scidLen;    // skip SCID
                    if ((firstByte & 0x30) == 0x00) // Initial packet has token
                    {
                        int tokenLen = (int)ReadVarInt(packet, ref off);
                        off += tokenLen;
                    }
                    ReadVarInt(packet, ref off); // length field
                    pnOffset = off;
                }
                else
                {
                    pnOffset = 1 + dcidLen;
                }

                sampleOffset = pnOffset + 4;
                if (packet.Length < sampleOffset + 16) return false;

                byte[] sample = packet.Skip(sampleOffset).Take(16).ToArray();
                byte[] mask   = AesEcbEncrypt(key.HeaderProtectionKey, sample);

                byte unprotectedFirst = isLong
                    ? (byte)(firstByte ^ (mask[0] & 0x0F))
                    : (byte)((firstByte & 0xE0) | ((firstByte & 0x1F) ^ (mask[0] & 0x1F)));

                int pnLen = (unprotectedFirst & 0x03) + 1;
                byte[] pn = new byte[pnLen];
                for (int i = 0; i < pnLen; i++) pn[i] = (byte)(packet[pnOffset + i] ^ mask[i + 1]);

                int payloadOffset = pnOffset + pnLen;
                int payloadLen    = packet.Length - payloadOffset;
                if (payloadLen < 16) return false;

                byte[] nonce = (byte[])key.IV.Clone();
                for (int i = 0; i < pnLen; i++) nonce[11 - i] ^= pn[pnLen - 1 - i];

                byte[] aad = packet.Take(payloadOffset).ToArray();
                aad[0] = unprotectedFirst;
                for (int i = 0; i < pnLen; i++) aad[pnOffset + i] = pn[i];

                byte[] ciphertext = packet.Skip(payloadOffset).Take(payloadLen - 16).ToArray();
                byte[] tag        = packet.Skip(packet.Length - 16).ToArray();
                byte[] plaintext  = new byte[ciphertext.Length];

                using var aes = new AesGcm(key.Key, 16);
                aes.Decrypt(nonce, ciphertext, tag, plaintext, aad);

                // Validate: first byte of plaintext should be a QUIC frame type (0x00-0x1F common)
                bool plausible = plaintext.Length > 0 && plaintext[0] <= 0x40;
                if (plausible)
                    steps.Add($"[DIAG] ✓ Plaintext[0..7]: {Hex(plaintext, 0, Math.Min(8, plaintext.Length))}");
                return plausible;
            }
            catch { return false; }
        }

        private static byte[] AesEcbEncrypt(byte[] key, byte[] data)
        {
            using var aes = Aes.Create();
            aes.Key     = key;
            aes.Mode    = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            using var enc = aes.CreateEncryptor();
            byte[] out_ = new byte[16];
            enc.TransformBlock(data, 0, 16, out_, 0);
            return out_;
        }

        private static long ReadVarInt(byte[] data, ref int offset)
        {
            if (offset >= data.Length) return 0;
            byte first = data[offset];
            int  len   = 1 << (first >> 6);
            long value = first & 0x3F;
            for (int i = 1; i < len && offset + i < data.Length; i++)
                value = (value << 8) | data[offset + i];
            offset += len;
            return value;
        }

        private static string Hex(byte[] b, int offset = 0, int count = -1)
        {
            if (b == null) return "(null)";
            if (count < 0) count = b.Length - offset;
            count = Math.Min(count, b.Length - offset);
            return Convert.ToHexString(b, offset, count).ToLower();
        }

        // ── RFC 9001 Appendix A.1 self-test ────────────────────────────────
        public static List<string> RunRFC9001SelfTest()
        {
            var lines = new List<string>();
            lines.Add("[SELFTEST] RFC 9001 Appendix A.1 key derivation:");

            // Official test vector from RFC 9001 Appendix A.1
            // RFC 9001 Appendix A.1: client_initial_secret (32 bytes = 64 hex chars)
            var secret = Convert.FromHexString(
                "c00cf151ca5be075ed0ebfb5c80323c4" +
                "2d6b7db67881289af4008f1f6c357aea");// CORRECT per full RFC 9001 A.1 derivation);

            var key = new PacketDecryptor.EncryptionKey
            {
                Secret = secret,
                Type   = PacketDecryptor.EncryptionType.QUIC_Client1RTT,
                Source = "RFC9001-A1"
            };
            PacketDecryptor.DeriveQUICKeys(key);

            bool kOk = key.Key?.SequenceEqual(Convert.FromHexString("1f369613dd76d5467730efcbe3b1a22d")) == true;
            bool iOk = key.IV?.SequenceEqual(Convert.FromHexString("fa044b2f42a3fd3b46fb255c")) == true;
            bool hOk = key.HeaderProtectionKey?.SequenceEqual(Convert.FromHexString("9f50449e04a0e810283a1e9933adedd2")) == true;

            lines.Add($"[SELFTEST]   Key : {(key.Key != null ? Hex(key.Key) : "null")}");
            lines.Add($"[SELFTEST]   Exp : 1f369613dd76d5467730efcbe3b1a22d  → {(kOk ? "✓ PASS" : "✗ FAIL")}");
            lines.Add($"[SELFTEST]   IV  : {(key.IV != null ? Hex(key.IV) : "null")}");
            lines.Add($"[SELFTEST]   Exp : fa044b2f42a3fd3b46fb255c           → {(iOk ? "✓ PASS" : "✗ FAIL")}");
            lines.Add($"[SELFTEST]   HP  : {(key.HeaderProtectionKey != null ? Hex(key.HeaderProtectionKey) : "null")}");
            lines.Add($"[SELFTEST]   Exp : 9f50449e04a0e810283a1e9933adedd2  → {(hOk ? "✓ PASS" : "✗ FAIL")}");
            lines.Add(kOk && iOk && hOk
                ? "[SELFTEST] ✓ HKDF derivation is correct (RFC 8446 with 'tls13 ' prefix)"
                : "[SELFTEST] ✗ HKDF BROKEN — keys will never decrypt");

            return lines;
        }

        private static string Hex(byte[]? b) =>
            b == null ? "(null)" : Convert.ToHexString(b).ToLower();

        // ── Initial Packet Analyzer ────────────────────────────────────────
        /// <summary>
        /// Parse a QUIC Initial packet (Long Header, type 0x00) and extract DCID.
        /// Returns null if packet is not a valid Initial packet.
        /// </summary>
        public static InitialPacketInfo? ParseInitialPacket(byte[] packet)
        {
            if (packet == null || packet.Length < 7) return null;
            byte first = packet[0];
            if ((first & 0x80) == 0) return null; // must be long header
            int type = (first & 0x30) >> 4;
            // Initial = 0x00, 0-RTT = 0x01, Handshake = 0x02, Retry = 0x03
            if (type != 0x00) return null;

            int off = 1;
            uint version = BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(off)); off += 4;

            byte dcidLen = packet[off++];
            if (off + dcidLen > packet.Length) return null;
            byte[] dcid = packet.Skip(off).Take(dcidLen).ToArray(); off += dcidLen;

            byte scidLen = packet[off++];
            if (off + scidLen > packet.Length) return null;
            byte[] scid = packet.Skip(off).Take(scidLen).ToArray(); off += scidLen;

            return new InitialPacketInfo
            {
                Version     = version,
                DCID        = dcid,
                SCID        = scid,
                DCIDHex     = dcid.Length > 0 ? Convert.ToHexString(dcid).ToLower() : "(empty)",
                SCIDHex     = scid.Length > 0 ? Convert.ToHexString(scid).ToLower() : "(empty)",
                IsClientSent = dcidLen >= 8, // servers respond with DCID = client's chosen SCID
            };
        }

        public class InitialPacketInfo
        {
            public uint    Version  { get; set; }
            public byte[]  DCID     { get; set; }
            public byte[]  SCID     { get; set; }
            public string  DCIDHex  { get; set; }
            public string  SCIDHex  { get; set; }
            public bool    IsClientSent { get; set; }
        }

        /// <summary>
        /// Scan a list of packets for the Initial packet, extract DCID,
        /// and log a recommendation for which sslkeys entry to try.
        /// </summary>
        public static List<string> AnalyzeFirstPackets(IEnumerable<byte[]> packets)
        {
            var lines = new List<string>();
            lines.Add("[SESSIONDIAG] Scanning for QUIC Initial packet...");

            int i = 0;
            foreach (var pkt in packets.Take(100))
            {
                if (pkt == null || pkt.Length < 8) { i++; continue; }

                byte first = pkt[0];
                bool isLong = (first & 0x80) != 0;
                int  type   = (first & 0x30) >> 4;

                lines.Add($"[SESSIONDIAG] Pkt#{i}: {pkt.Length}B  {(isLong ? "Long" : "Short")} hdr" +
                          (isLong ? $" type={type}" : "") +
                          $"  first=0x{first:X2}");

                if (isLong && type == 0)
                {
                    var info = ParseInitialPacket(pkt);
                    if (info != null)
                    {
                        lines.Add($"[SESSIONDIAG] ✓ Initial packet found at pkt#{i}:");
                        lines.Add($"[SESSIONDIAG]   QUIC version: 0x{info.Version:X8}");
                        lines.Add($"[SESSIONDIAG]   DCID ({info.DCID.Length}B): {info.DCIDHex}");
                        lines.Add($"[SESSIONDIAG]   SCID ({info.SCID.Length}B): {info.SCIDHex}");
                        lines.Add($"[SESSIONDIAG]   After handshake, 1-RTT DCID length = {info.SCID.Length} bytes");
                        lines.Add($"[SESSIONDIAG]   → Try TryDecryptShortHeader with dcidLen={info.SCID.Length}");
                        break;
                    }
                }
                i++;
                if (i >= 20) break;
            }

            if (!lines.Any(l => l.Contains("Initial packet found")))
            {
                lines.Add("[SESSIONDIAG] No Initial packet in first 20 — proxy started after handshake?");
                lines.Add("[SESSIONDIAG] Cannot determine DCID length from capture.");
                lines.Add("[SESSIONDIAG] Recommendation: connect WITH HyForce running so Initial is captured.");
            }
            return lines;
        }
    }
}
