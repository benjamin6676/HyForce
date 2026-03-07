// DiagnosticsCollector.cs — Collects every observable signal in HyForce into one export.
// Covers: decryption, memory scan, memory toggles, packet feed, DLL hooks,
//         pipe health, key log, session, module list, string heap, exploit results,
//         timing anomalies, sequence gaps, in-game log, system info.
// Designed to be sent to an AI / developer for root-cause analysis.

using HyForce.Core;
using HyForce.Networking;
using HyForce.Protocol;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HyForce.Diagnostics
{
    public static class DiagnosticsCollector
    {
        // ── Entry point ──────────────────────────────────────────────────────
        public static async Task<string> CollectAsync(
            AppState state,
            PipeCaptureServer pipe,
            MemoryToggleManager? toggleMgr = null,
            int maxPackets = 20,
            int maxLogLines = 500)
        {
            return await Task.Run(() => Collect(state, pipe, toggleMgr, maxPackets, maxLogLines));
        }

        public static string Collect(
            AppState state,
            PipeCaptureServer pipe,
            MemoryToggleManager? toggleMgr = null,
            int maxPackets = 20,
            int maxLogLines = 500,
            IReadOnlyList<HyForce.Tabs.ToggleEntry>? valueToggles = null)
        {
            var sb = new StringBuilder();
            var now = DateTime.Now;

            Header(sb, now);
            SystemInfo(sb);
            PipeHealth(sb, pipe);
            DecryptionSection(sb, state);
            KeyLogSection(sb, state);
            PacketFeedSection(sb, state, maxPackets);
            MemoryScanSection(sb, pipe);
            MemoryTogglesSection(sb, toggleMgr);
            ValueTogglesSection(sb, valueToggles);
            MemoryReadResults(sb, pipe);
            ModuleSection(sb, pipe);
            StringHeapSection(sb, pipe);
            TimingSection(sb, pipe);
            SeqAnomalySection(sb, pipe);
            ExploitSection(sb, pipe);
            PlaintextSection(sb, pipe);
            InGameLogSection(sb, state, maxLogLines);
            Footer(sb, now);

            return sb.ToString();
        }

        // ── Save to disk + open ──────────────────────────────────────────────
        public static string SaveAndOpen(string content, string exportDir)
        {
            try
            {
                Directory.CreateDirectory(exportDir);
                string path = Path.Combine(exportDir, $"hyforce_diag_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
                File.WriteAllText(path, content);
                try { Process.Start("notepad.exe", path); } catch { }
                return path;
            }
            catch (Exception ex) { return $"[ERROR saving: {ex.Message}]"; }
        }

        // ── Sections ─────────────────────────────────────────────────────────

        private static void Header(StringBuilder sb, DateTime now)
        {
            sb.AppendLine("╔══════════════════════════════════════════════════════════════════╗");
            sb.AppendLine("║           HyForce v11  —  Full Diagnostics Export                ║");
            sb.AppendLine("╚══════════════════════════════════════════════════════════════════╝");
            sb.AppendLine($"Generated : {now:yyyy-MM-dd HH:mm:ss.fff}");
            sb.AppendLine($"Host      : {Environment.MachineName}  ({Environment.OSVersion})");
            sb.AppendLine($"Process   : {Process.GetCurrentProcess().ProcessName}  PID={Process.GetCurrentProcess().Id}");
            sb.AppendLine();
        }

        private static void SystemInfo(StringBuilder sb)
        {
            Section(sb, "SYSTEM INFO");
            try
            {
                sb.AppendLine($"  OS         : {Environment.OSVersion}");
                sb.AppendLine($"  64-bit OS  : {Environment.Is64BitOperatingSystem}");
                sb.AppendLine($"  .NET       : {Environment.Version}");
                sb.AppendLine($"  CPU cores  : {Environment.ProcessorCount}");
                sb.AppendLine($"  WorkingSet : {Environment.WorkingSet / 1024 / 1024} MB");
                sb.AppendLine($"  TickCount  : {Environment.TickCount64} ms");

                // Check HytaleClient.exe running
                var hytale = Process.GetProcessesByName("HytaleClient").FirstOrDefault();
                if (hytale != null)
                    sb.AppendLine($"  HytaleClient.exe : PID={hytale.Id}  WorkingSet={hytale.WorkingSet64/1024/1024}MB  Started={hytale.StartTime:HH:mm:ss}");
                else
                    sb.AppendLine($"  HytaleClient.exe : *** NOT FOUND ***  (DLL injection will fail)");

                sb.AppendLine($"  SSLKEYLOGFILE (user)    : {Environment.GetEnvironmentVariable("SSLKEYLOGFILE", EnvironmentVariableTarget.User) ?? "(not set)"}");
                sb.AppendLine($"  SSLKEYLOGFILE (process) : {Environment.GetEnvironmentVariable("SSLKEYLOGFILE", EnvironmentVariableTarget.Process) ?? "(not set)"}");
            }
            catch (Exception ex) { sb.AppendLine($"  [ERROR] {ex.Message}"); }
            sb.AppendLine();
        }

        private static void PipeHealth(StringBuilder sb, PipeCaptureServer pipe)
        {
            Section(sb, "PIPE / DLL CONNECTION");
            sb.AppendLine($"  IsRunning      : {pipe.IsRunning}");
            sb.AppendLine($"  DllConnected   : {pipe.DllConnected}");
            sb.AppendLine($"  ConnectedAt    : {(pipe.DllConnectedAt == DateTime.MinValue ? "never" : pipe.DllConnectedAt.ToString("HH:mm:ss"))}");
            sb.AppendLine($"  PacketsCaptured: {pipe.PacketCount}");
            sb.AppendLine($"  DllStatus      : {pipe.DllStatus}");
            sb.AppendLine($"  MemHits        : {pipe.MemHits.Count}");
            sb.AppendLine($"  Modules found  : {pipe.Modules.Count}");
            sb.AppendLine($"  Strings found  : {pipe.Strings.Count}");
            sb.AppendLine($"  Gadgets found  : {pipe.Gadgets.Count}");
            sb.AppendLine($"  TimingEntries  : {pipe.TimingLog.Count}");
            sb.AppendLine($"  SeqAnomalies   : {pipe.SeqAnomalies.Count}");
            sb.AppendLine($"  PlaintextPkts  : {pipe.PlaintextPackets.Count}");
            sb.AppendLine();

            if (!pipe.DllConnected)
                sb.AppendLine("  ⚠ DLL not connected. Inject HyForceHook.dll into HytaleClient.exe first.");
            if (pipe.PacketCount == 0 && pipe.DllConnected)
                sb.AppendLine("  ⚠ DLL connected but 0 packets — hooks may not be firing (try STATS command).");
            sb.AppendLine();
        }

        private static void DecryptionSection(StringBuilder sb, AppState state)
        {
            Section(sb, "DECRYPTION STATUS");
            try
            {
                var stats = PacketDecryptor.GetDebugStats();
                sb.AppendLine($"  Keys loaded       : {stats["TotalKeys"]}");
                sb.AppendLine($"  Connections       : {stats["TotalKeys"]}");
                sb.AppendLine($"  Successful decrypts: {stats["SuccessfulDecryptions"]}");
                sb.AppendLine($"  Failed decrypts   : {stats["FailedDecryptions"]}");
                sb.AppendLine($"  HP-filtered       : {stats["SkippedDecryptions"]}");
                double rate = Convert.ToDouble(stats["SuccessRate"]);
                sb.AppendLine($"  Success rate      : {rate:F1}%");
                sb.AppendLine($"  Label format      : {PacketDecryptor.CurrentLabelFormat}");
                sb.AppendLine($"  AutoDecrypt       : {PacketDecryptor.AutoDecryptEnabled}");
                sb.AppendLine($"  DebugMode         : {PacketDecryptor.DebugMode}");
                sb.AppendLine($"  Dead connections  : {PacketDecryptor.DeadConnectionCount}");
                sb.AppendLine($"  Queue depth       : {PacketDecryptor.QueueDepth}");
                sb.AppendLine();

                // Diagnosis
                int keys  = Convert.ToInt32(stats["TotalKeys"]);
                int ok   = Convert.ToInt32(stats["SuccessfulDecryptions"]);
                int fail = Convert.ToInt32(stats["FailedDecryptions"]);
                if (keys == 0)
                    sb.AppendLine("  ⚠ No keys — SSLKEYLOGFILE may not be set, or Hytale hasn't connected yet.");
                else if (ok == 0 && fail > 200)
                    sb.AppendLine("  ⚠ Session mismatch — keys are from a different TLS session than captured packets.");
                else if (ok > 0)
                    sb.AppendLine("  ✓ Decryption working.");

                sb.AppendLine();
                sb.AppendLine("  Active keys:");
                foreach (var k in PacketDecryptor.DiscoveredKeys.Take(30))
                {
                    string kh  = k.Key != null ? Convert.ToHexString(k.Key).Substring(0, Math.Min(16, k.Key.Length * 2)) : "null";
                    string ivh = k.IV  != null ? Convert.ToHexString(k.IV ).Substring(0, Math.Min(12, k.IV.Length  * 2)) : "null";
                    sb.AppendLine($"    [{k.Type}] key={kh}... iv={ivh} added={k.DiscoveredAt:HH:mm:ss} src={k.Source}");
                }
                if (PacketDecryptor.DiscoveredKeys.Count > 30)
                    sb.AppendLine($"    ... +{PacketDecryptor.DiscoveredKeys.Count - 30} more");
            }
            catch (Exception ex) { sb.AppendLine($"  [ERROR] {ex.Message}"); }
            sb.AppendLine();
        }

        private static void KeyLogSection(StringBuilder sb, AppState state)
        {
            Section(sb, "SSL KEY LOG FILE");
            try
            {
                string path = state.PermanentKeyLogPath;
                sb.AppendLine($"  Path : {path}");
                if (File.Exists(path))
                {
                    var lines = File.ReadAllLines(path);
                    int client = lines.Count(l => l.StartsWith("CLIENT_TRAFFIC_SECRET_0"));
                    int server = lines.Count(l => l.StartsWith("SERVER_TRAFFIC_SECRET_0"));
                    sb.AppendLine($"  Lines         : {lines.Length}");
                    sb.AppendLine($"  CLIENT secrets: {client}");
                    sb.AppendLine($"  SERVER secrets: {server}");
                    sb.AppendLine($"  File size     : {new FileInfo(path).Length / 1024} KB");
                    sb.AppendLine($"  Last modified : {File.GetLastWriteTime(path):HH:mm:ss}");
                    sb.AppendLine("  Last 4 lines:");
                    foreach (var l in lines.TakeLast(4))
                        sb.AppendLine($"    {l}");
                }
                else
                    sb.AppendLine("  ⚠ File does not exist.");
            }
            catch (Exception ex) { sb.AppendLine($"  [ERROR] {ex.Message}"); }
            sb.AppendLine();
        }

        private static void PacketFeedSection(StringBuilder sb, AppState state, int maxPackets)
        {
            Section(sb, $"PACKET FEED (last {maxPackets} QUIC packets)");
            try
            {
                var all  = state.PacketLog.GetLast(1000);
                var quic = all.Where(p => !p.IsTcp).TakeLast(maxPackets).ToList();
                var tcp  = all.Where(p =>  p.IsTcp).ToList();
                sb.AppendLine($"  Total packets in log : {all.Count}");
                sb.AppendLine($"  QUIC packets         : {all.Count(p => !p.IsTcp)}");
                sb.AppendLine($"  TCP  packets         : {tcp.Count}");
                sb.AppendLine($"  Decrypted (QUIC)     : {all.Count(p => !p.IsTcp )}");
                sb.AppendLine();

                if (quic.Count == 0)
                {
                    sb.AppendLine("  ⚠ No QUIC packets captured. Is Hytale running and connected?");
                }
                else
                {
                    sb.AppendLine($"  {"#",-4} {"Dir",-4} {"Size",-6} {"Enc",-5} {"Decrypted",-9} {"Time",-12} {"First16 hex"}");
                    sb.AppendLine(new string('-', 90));
                    for (int i = 0; i < quic.Count; i++)
                    {
                        var p = quic[i];
                        bool dec = false;
                        string first16 = Convert.ToHexString(p.RawBytes.Take(16).ToArray()).ToLower();
                        string encHint = p.RawBytes.Length > 0 ? ((p.RawBytes[0] & 0x80) != 0 ? "Long" : "Shrt") : "?";
                        sb.AppendLine($"  {i,-4} {(p.DirStr),-4} {p.RawBytes.Length,-6} {encHint,-5} {(dec ? "YES" : "no"),-9} {p.Timestamp:HH:mm:ss.fff,-12} {first16}");
                        // (decrypted bytes accessible via DecryptionTab if needed)
                    }
                }
            }
            catch (Exception ex) { sb.AppendLine($"  [ERROR] {ex.Message}"); }
            sb.AppendLine();
        }

        private static void MemoryScanSection(StringBuilder sb, PipeCaptureServer pipe)
        {
            Section(sb, "MEMORY SCAN RESULTS");
            var hits = pipe.MemHits.ToList();
            sb.AppendLine($"  Hits found: {hits.Count}");
            sb.AppendLine();
            if (hits.Count == 0)
            {
                sb.AppendLine("  ⚠ No memory hits. Possible causes:");
                sb.AppendLine("    • DLL not injected into HytaleClient.exe");
                sb.AppendLine("    • Entity struct layout differs from expected pattern");
                sb.AppendLine("    • Try MEMSCAN_BROAD for relaxed scan");
                sb.AppendLine("    • Hytale may use ECS (struct-of-arrays), not AoS — fields may not be contiguous");
            }
            else
            {
                sb.AppendLine($"  {"#",-4} {"Address",-18} {"HP",-12} {"MaxHP",-12} {"X",-12} {"Y",-10} {"Z",-12} {"Speed",-8} {"Found"}");
                sb.AppendLine(new string('-', 100));
                for (int i = 0; i < hits.Count; i++)
                {
                    var h = hits[i];
                    float spd = MathF.Sqrt(h.VelX*h.VelX + h.VelY*h.VelY + h.VelZ*h.VelZ);
                    sb.AppendLine($"  {i,-4} 0x{h.Address:X14}  {h.Health,-12:F2} {h.MaxHealth,-12:F2} {h.X,-12:F3} {h.Y,-10:F3} {h.Z,-12:F3} {spd,-8:F2} {h.FoundAt:HH:mm:ss}");
                    if (h.StructBytes.Length > 0)
                    {
                        sb.Append($"       Bytes[0..{Math.Min(h.StructBytes.Length, 56)}]: ");
                        sb.AppendLine(Convert.ToHexString(h.StructBytes.Take(56).ToArray()).ToLower());
                    }
                }
            }
            sb.AppendLine();
        }

        private static void MemoryTogglesSection(StringBuilder sb, MemoryToggleManager? mgr)
        {
            Section(sb, "MEMORY TOGGLES");
            if (mgr == null) { sb.AppendLine("  (MemoryToggleManager not wired)"); sb.AppendLine(); return; }
            sb.AppendLine($"  Total toggles: {mgr.Toggles.Count}");
            sb.AppendLine($"  Active        : {mgr.Toggles.Count(t => t.Active)}");
            sb.AppendLine();
            foreach (var t in mgr.Toggles.OrderByDescending(t => t.Favorited))
            {
                sb.AppendLine($"  [{(t.Favorited?"★":" ")}] [{(t.Active?"ACTIVE":"  off")}] {t.Category}/{t.Name}");
                sb.AppendLine($"       Addr={0x0:X}  Addr=0x{t.Address:X14}  Type={t.DataType}  Value={t.ValueStr}  Interval={t.IntervalMs}ms");
                sb.AppendLine($"       Hotkey={t.HotkeyLabel}  Writes={t.WriteCount}  LastRead={t.LastReadValue}  LastWrite={t.LastWriteAt:HH:mm:ss}");
                if (t.Notes.Length > 0) sb.AppendLine($"       Notes: {t.Notes}");
                if (t.ChangeLog.Count > 0)
                {
                    sb.AppendLine($"       Change log (last 10):");
                    foreach (var e in t.ChangeLog.TakeLast(10))
                        sb.AppendLine($"         [{e.Timestamp:HH:mm:ss.fff}] {e.PrevValue} → {e.NewValue}  src={e.Source}  applied={e.WasApplied}");
                }
                sb.AppendLine();
            }
        }

        private static void ValueTogglesSection(StringBuilder sb,
            IReadOnlyList<HyForce.Tabs.ToggleEntry>? toggles)
        {
            Section(sb, "VALUE TOGGLES (hotkey-bound)");
            if (toggles == null || toggles.Count == 0)
            { sb.AppendLine("  No value toggles defined in ValueToggleTab."); sb.AppendLine(); return; }
            sb.AppendLine($"  Total: {toggles.Count}  Active: {toggles.Count(t => t.Active)}");
            sb.AppendLine();
            foreach (var t in toggles.OrderByDescending(x => x.Favorite))
            {
                sb.AppendLine($"  [{(t.Favorite?"★":" ")}] [{(t.Active?"ACTIVE":"  off")}] {t.Name}");
                sb.AppendLine($"       Addr=0x{t.Address:X}  Type={t.ValueType}  TargetVal={t.TargetValue}");
                sb.AppendLine($"       Mode={t.Mode}  HotkeyVK=0x{t.HotkeyVk:X2}  Slot={t.FreezeSlot}");
                if (t.ChangeLog.Count > 0)
                {
                    sb.AppendLine($"       Change log ({t.ChangeLog.Count} entries, last 20):");
                    foreach (var l in t.ChangeLog.TakeLast(20))
                        sb.AppendLine($"         {l}");
                }
                sb.AppendLine();
            }
        }

        private static void MemoryReadResults(StringBuilder sb, PipeCaptureServer pipe)
        {
            Section(sb, "RECENT MEMORY READS (MEMREAD responses)");
            var results = pipe.MemReadResults.TakeLast(20).ToList();
            if (results.Count == 0) { sb.AppendLine("  (none)"); sb.AppendLine(); return; }
            foreach (var r in results)
            {
                sb.Append($"  [{r.ReadAt:HH:mm:ss.fff}] 0x{r.Address:X14} ({r.Data.Length}B): ");
                sb.AppendLine(Convert.ToHexString(r.Data.Take(32).ToArray()).ToLower());
                if (r.Data.Length >= 4)
                {
                    sb.Append($"    → f32[0]={r.AsF32():G6}");
                    if (r.Data.Length >= 8) sb.Append($"  f64[0]={r.AsF64():G10}");
                    if (r.Data.Length >= 4) sb.Append($"  i32[0]={r.AsI32()}");
                    sb.AppendLine();
                }
            }
            sb.AppendLine();
        }

        private static void ModuleSection(StringBuilder sb, PipeCaptureServer pipe)
        {
            Section(sb, "LOADED MODULES (from DLL)");
            var mods = pipe.Modules.ToList();
            if (mods.Count == 0) { sb.AppendLine("  (none — send MODLIST command)"); sb.AppendLine(); return; }
            foreach (var m in mods)
                sb.AppendLine($"  0x{m.BaseAddress:X14}  {m.Size,10}  {m.Name}");
            sb.AppendLine();
        }

        private static void StringHeapSection(StringBuilder sb, PipeCaptureServer pipe)
        {
            Section(sb, "STRING HEAP SCAN (interesting strings)");
            var strings = pipe.Strings.ToList();
            if (strings.Count == 0) { sb.AppendLine("  (none — run String Scan)"); sb.AppendLine(); return; }
            // Show only interesting ones (IPs, tokens, known keywords)
            var interesting = strings.Where(s =>
                s.Text.Contains('.') || s.Text.Contains("hytale", StringComparison.OrdinalIgnoreCase) ||
                s.Text.Contains("quic", StringComparison.OrdinalIgnoreCase) ||
                s.Text.Contains("auth", StringComparison.OrdinalIgnoreCase) ||
                s.Text.Length > 30).Take(50).ToList();
            sb.AppendLine($"  Total: {strings.Count}  Shown (interesting): {interesting.Count}");
            foreach (var s in interesting)
                sb.AppendLine($"  0x{s.Address:X14}  {s.Text}");
            sb.AppendLine();
        }

        private static void TimingSection(StringBuilder sb, PipeCaptureServer pipe)
        {
            Section(sb, "TIMING LOG (last 20 entries)");
            var entries = pipe.TimingLog.TakeLast(20).ToList();
            if (entries.Count == 0) { sb.AppendLine("  (none)"); sb.AppendLine(); return; }
            foreach (var e in entries)
                sb.AppendLine($"  [us={e.TimestampUs}] dir={e.Dir}  len={e.Length}B");
            sb.AppendLine();
        }

        private static void SeqAnomalySection(StringBuilder sb, PipeCaptureServer pipe)
        {
            Section(sb, "SEQUENCE ANOMALIES");
            var anom = pipe.SeqAnomalies.TakeLast(20).ToList();
            if (anom.Count == 0) { sb.AppendLine("  (none detected — good sign)"); sb.AppendLine(); return; }
            foreach (var a in anom) sb.AppendLine($"  {a}");
            sb.AppendLine();
        }

        private static void ExploitSection(StringBuilder sb, PipeCaptureServer pipe)
        {
            Section(sb, "EXPLOIT PROBE RESULTS");
            var gadgets = pipe.Gadgets.ToList();
            if (gadgets.Count == 0) { sb.AppendLine("  (none — run Exploit Probe)"); sb.AppendLine(); return; }
            foreach (var g in gadgets)
                sb.AppendLine($"  0x{g.Address:X14}  type=0x{g.GadgetType:X2}  {g.Description}  found={g.FoundAt:HH:mm:ss}");
            sb.AppendLine();
        }

        private static void PlaintextSection(StringBuilder sb, PipeCaptureServer pipe)
        {
            Section(sb, "PRE-ENCRYPTION PLAINTEXT (quiche/ssl hooks)");
            List<PlaintextEntry> pkts;
            lock (pipe.PlaintextLock) pkts = pipe.PlaintextPackets.TakeLast(10).ToList();
            if (pkts.Count == 0) { sb.AppendLine("  (none — needs BoringSSL/quiche hooks active)"); sb.AppendLine(); return; }
            foreach (var p in pkts)
            {
                sb.AppendLine($"  [{p.Timestamp:HH:mm:ss.fff}] {p.Direction}  {p.Data.Length}B  {p.RemoteAddr}");
                sb.AppendLine($"    Hex: {Convert.ToHexString(p.Data.Take(64).ToArray()).ToLower()}");
                try { sb.AppendLine($"    ASCII: {System.Text.Encoding.ASCII.GetString(p.Data.Take(64).ToArray()).Replace('\0', '.')}");
                } catch { }
            }
            sb.AppendLine();
        }

        private static void InGameLogSection(StringBuilder sb, AppState state, int maxLines)
        {
            Section(sb, $"IN-GAME LOG (last {maxLines} lines)");
            try
            {
                var log = state.GetRecentLog(maxLines);
                foreach (var l in log) sb.AppendLine($"  {l}");
            }
            catch (Exception ex) { sb.AppendLine($"  [ERROR] {ex.Message}"); }
            sb.AppendLine();
        }

        private static void Footer(StringBuilder sb, DateTime start)
        {
            sb.AppendLine("══════════════════════════════════════════════════════════════════");
            sb.AppendLine($"Export completed in {(DateTime.Now - start).TotalMilliseconds:F0}ms");
            sb.AppendLine("Send this file to the developer or paste into an AI chat for analysis.");
            sb.AppendLine("══════════════════════════════════════════════════════════════════");
        }

        private static void Section(StringBuilder sb, string title)
        {
            sb.AppendLine($"┌─── {title} ───");
        }
    }
}
