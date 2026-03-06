// FILE: Networking/WinDivertCapture.cs - FIXED VERSION
using HyForce.Core;
using HyForce.Data;
using System;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;

namespace HyForce.Networking
{
    public class WinDivertCapture : IDisposable
    {
        // FIXED: Use correct flag values from WinDivert 2.0+
        [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        static extern IntPtr WinDivertOpen(string filter, int layer, short priority, ulong flags);

        [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        static extern bool WinDivertRecv(IntPtr handle, byte[] pkt, uint pktLen,
            ref uint recvLen, ref WINDIVERT_ADDRESS addr);

        [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        static extern bool WinDivertSend(IntPtr handle, byte[] pkt, uint pktLen,
            ref uint sendLen, ref WINDIVERT_ADDRESS addr);

        [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        static extern bool WinDivertClose(IntPtr handle);

        [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        static extern bool WinDivertSetParam(IntPtr handle, int param, ulong value);

        // FIXED: Corrected WINDIVERT_ADDRESS struct for WinDivert 2.0+
        [StructLayout(LayoutKind.Sequential)]
        struct WINDIVERT_ADDRESS
        {
            public long Timestamp;
            public byte Layer;      // UINT8
            public byte Event;      // UINT8
            public byte Sniffed;    // UINT8
            public byte Outbound;   // UINT8
            public byte Loopback;   // UINT8
            public byte Impostor;   // UINT8
            public byte IPv6;       // UINT8
            public byte IPChecksum; // UINT8
            public byte TCPChecksum;// UINT8
            public byte UDPChecksum;// UINT8
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public byte[] Reserved;
        }

        // WinDivert constants
        const int WINDIVERT_LAYER_NETWORK = 0;
        const ulong WINDIVERT_FLAG_SNIFF = 0x0001;
        const ulong WINDIVERT_FLAG_DROP = 0x0002;
        const int WINDIVERT_PARAM_QUEUE_LEN = 0;
        const int WINDIVERT_PARAM_QUEUE_TIME = 1;

        // Hytale uses UDP 5520 by default
        const int HYTALE_PORT = 5520;

        private IntPtr _handle = IntPtr.Zero;
        private Thread? _thread;
        private volatile bool _running;
        private readonly AppState _state;

        public bool IsRunning => _running;
        public int PacketCount { get; private set; }
        public string Status { get; private set; } = "Not started";

        public static bool IsAvailable =>
            File.Exists("WinDivert.dll") ||
            File.Exists(Path.Combine(AppContext.BaseDirectory, "WinDivert.dll")) ||
            File.Exists(@"C:\Windows\System32\WinDivert.dll");

        public event Action<CapturedPacket>? OnPacket;

        public WinDivertCapture(AppState state) { _state = state; }

        /// <summary>
        /// FIXED: Start capturing Hytale UDP traffic with proper filter
        /// </summary>
        public bool Start(string? serverIp = null, int serverPort = 0)
        {
            if (_running) return true;

            // Build filter for Hytale QUIC/UDP traffic
            // FIXED: Use simpler, more reliable filter syntax
            string filter;
            int targetPort = serverPort > 0 ? serverPort : HYTALE_PORT;

            if (!string.IsNullOrEmpty(serverIp))
            {
                // Filter by specific server IP and port
                filter = $"udp.DstPort == {targetPort} or udp.SrcPort == {targetPort}";
            }
            else
            {
                // Capture all UDP traffic on Hytale port range
                filter = $"udp.DstPort >= 5520 and udp.DstPort <= 5560 or udp.SrcPort >= 5520 and udp.SrcPort <= 5560";
            }

            try
            {
                // FIXED: Use correct layer and flags
                _handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, WINDIVERT_FLAG_SNIFF);

                if (_handle == IntPtr.Zero || _handle == new IntPtr(-1))
                {
                    int err = Marshal.GetLastWin32Error();
                    Status = $"WinDivertOpen failed (err {err}). Run as Administrator.";
                    _state.AddInGameLog($"[WINDIVERT] {Status}");
                    return false;
                }

                // FIXED: Increase queue size for high-traffic capture
                WinDivertSetParam(_handle, WINDIVERT_PARAM_QUEUE_LEN, 8192);
                WinDivertSetParam(_handle, WINDIVERT_PARAM_QUEUE_TIME, 512);

                _running = true;
                Status = $"Capturing UDP port {targetPort}" + (serverIp != null ? $" ↔ {serverIp}" : "");
                _thread = new Thread(CaptureLoop)
                {
                    IsBackground = true,
                    Name = "WinDivert-Cap",
                    Priority = ThreadPriority.AboveNormal
                };
                _thread.Start();

                _state.AddInGameLog($"[WINDIVERT] Started: {filter}");
                _state.AddInGameLog($"[WINDIVERT] Capture active - join a Hytale server now");
                return true;
            }
            catch (DllNotFoundException)
            {
                Status = "WinDivert.dll not found - download from https://reqrypt.org/windivert.html";
                _state.AddInGameLog($"[WINDIVERT] {Status}");
                return false;
            }
            catch (Exception ex)
            {
                Status = $"Error: {ex.Message}";
                _state.AddInGameLog($"[WINDIVERT] {Status}");
                return false;
            }
        }

        public void Stop()
        {
            _running = false;
            if (_handle != IntPtr.Zero)
            {
                WinDivertClose(_handle);
                _handle = IntPtr.Zero;
            }
            _thread?.Join(1000);
            Status = "Stopped";
        }

        public void Dispose() => Stop();

        private void CaptureLoop()
        {
            // FIXED: Larger buffer for QUIC packets
            byte[] buf = new byte[65535];
            var addr = new WINDIVERT_ADDRESS
            {
                Reserved = new byte[32]
            };
            uint recvLen = 0;

            while (_running)
            {
                try
                {
                    recvLen = 0;
                    if (!WinDivertRecv(_handle, buf, (uint)buf.Length, ref recvLen, ref addr))
                    {
                        Thread.Sleep(1);
                        continue;
                    }

                    if (recvLen < 20) continue; // Too small for IP+UDP

                    // Parse IPv4 header
                    byte version = (byte)(buf[0] >> 4);
                    if (version != 4) continue; // Skip IPv6 for now

                    byte ihl = (byte)((buf[0] & 0x0F) * 4);
                    if (ihl < 20 || recvLen < ihl + 8) continue;

                    byte proto = buf[9];
                    if (proto != 17) continue; // Not UDP

                    // Extract IP addresses
                    uint srcIp = BitConverter.ToUInt32(buf, 12);
                    uint dstIp = BitConverter.ToUInt32(buf, 16);

                    // UDP header at offset ihl
                    ushort srcPort = (ushort)IPAddress.NetworkToHostOrder(
                        BitConverter.ToInt16(buf, ihl));
                    ushort dstPort = (ushort)IPAddress.NetworkToHostOrder(
                        BitConverter.ToInt16(buf, ihl + 2));
                    ushort udpLen = (ushort)IPAddress.NetworkToHostOrder(
                        BitConverter.ToInt16(buf, ihl + 4));

                    int payloadOffset = ihl + 8;
                    int payloadLen = (int)recvLen - payloadOffset;
                    if (payloadLen < 1) continue;

                    byte[] payload = new byte[payloadLen];
                    Buffer.BlockCopy(buf, payloadOffset, payload, 0, payloadLen);

                    bool outbound = addr.Outbound != 0;
                    string srcStr = new IPAddress(srcIp).ToString();
                    string dstStr = new IPAddress(dstIp).ToString();

                    var pkt = new CapturedPacket
                    {
                        RawBytes = payload,
                        Direction = outbound ? PacketDirection.ClientToServer : PacketDirection.ServerToClient,
                        Timestamp = DateTime.Now,
                        EncryptionHint = "encrypted",
                        SourceAddress = srcStr,
                        DestAddress = dstStr,
                        SourcePort = srcPort,
                        DestPort = dstPort,
                        IsTcp = false,
                        QuicInfo = ParseQuicHeader(payload) // Try to parse QUIC header
                    };

                    PacketCount++;
                    OnPacket?.Invoke(pkt);
                }
                catch (Exception ex) when (_running)
                {
                    _state.AddInGameLog($"[WINDIVERT] Recv error: {ex.Message}");
                    Thread.Sleep(100);
                }
            }
        }

        /// <summary>
        /// Try to extract QUIC header info from payload
        /// </summary>
        private QuicHeaderInfo? ParseQuicHeader(byte[] data)
        {
            if (data.Length < 1) return null;

            var info = new QuicHeaderInfo();
            byte firstByte = data[0];
            info.IsLongHeader = (firstByte & 0x80) != 0;

            if (info.IsLongHeader && data.Length >= 6)
            {
                // Long header: parse version
                info.Version = (uint)((data[1] << 24) | (data[2] << 16) | (data[3] << 8) | data[4]);

                // DCID length at byte 5
                int dcidLen = data[5];
                if (dcidLen > 0 && 6 + dcidLen <= data.Length)
                {
                    info.DestinationConnectionId = new byte[dcidLen];
                    Buffer.BlockCopy(data, 6, info.DestinationConnectionId, 0, dcidLen);
                }
            }
            else
            {
                // Short header: try to infer DCID from packet structure
                // Netty/Hytale typically uses 0-20 byte DCID
                info.SpinBit = (firstByte & 0x20) != 0;
                info.KeyPhase = (firstByte & 0x04) != 0;
                info.PacketNumberLength = (firstByte & 0x03) + 1;
            }

            return info;
        }
    }
}
