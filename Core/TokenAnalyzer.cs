// Core/TokenAnalyzer.cs  v19
// Decodes AuthToken (0x02) and ConnectAccept (0x03) session tokens.
// Attempts to detect:
//   - UUID format (16 bytes)
//   - HMAC-SHA256 (32 bytes)
//   - JWT-style base64 (variable length, dot-separated)
//   - Raw timestamp + nonce patterns
//
// Replay analysis:
//   - Compares tokens across captured sessions to detect reuse
//   - Builds a modified copy with patched nonce/timestamp bytes for
//     forced replay injection via ReplaySetup

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace HyForce.Core;

public enum TokenKind { Unknown, UUID, HMAC32, JWT, TimestampNonce, Custom }

public class TokenAnalysis
{
    public TokenKind  Kind           { get; set; }
    public string     Description    { get; set; } = "";
    public string     HexDump        { get; set; } = "";
    public string     AsciiDump      { get; set; } = "";
    public byte[]     Raw            { get; set; } = Array.Empty<byte>();
    public DateTime   CapturedAt     { get; set; } = DateTime.UtcNow;
    public bool       IsBase64       { get; set; }
    public bool       HasTimestamp   { get; set; }
    public long       TimestampUtc   { get; set; }
    public bool       IsReuse        { get; set; }   // same bytes as prior session
    public List<string> Notes        { get; } = new();
}

public class TokenAnalyzer
{
    private readonly List<TokenAnalysis> _history = new();
    private readonly List<string>        _log     = new();
    private readonly object              _logLock = new();

    public IReadOnlyList<TokenAnalysis> History => _history;
    public IReadOnlyList<string> Log { get { lock (_logLock) return _log.ToList(); } }
    public event Action<string>? OnLog;

    public TokenAnalysis Analyze(byte[] raw, string source)
    {
        var ta = new TokenAnalysis
        {
            Raw        = raw,
            HexDump    = BitConverter.ToString(raw).Replace("-", " "),
            AsciiDump  = SafeAscii(raw),
            CapturedAt = DateTime.UtcNow
        };

        // Check for exact duplicate
        ta.IsReuse = _history.Any(h => h.Raw.SequenceEqual(raw));
        if (ta.IsReuse) ta.Notes.Add("⚠ IDENTICAL to a previous session token — possible replay target");

        // Classify
        if (raw.Length == 16)
        {
            ta.Kind = TokenKind.UUID;
            ta.Description = "16-byte UUID";
            ta.Notes.Add($"UUID form: {FormatUuid(raw)}");
        }
        else if (raw.Length == 32)
        {
            ta.Kind = TokenKind.HMAC32;
            ta.Description = "32-byte HMAC/hash";
            ta.Notes.Add("Likely HMAC-SHA256 or SHA-256 hash — brute-force unlikely");
        }
        else
        {
            // Try JWT detection (base64url with dots)
            string asStr = Encoding.ASCII.GetString(raw.Where(b => b >= 0x20 && b < 0x7F).ToArray());
            if (asStr.Contains('.') && asStr.Length > 10)
            {
                ta.Kind      = TokenKind.JWT;
                ta.IsBase64  = true;
                ta.Description = "JWT-style token";
                var parts = asStr.Split('.');
                ta.Notes.Add($"JWT segments: {parts.Length}");
                if (parts.Length >= 2)
                {
                    try
                    {
                        string padded = parts[1].PadRight(parts[1].Length + (4-parts[1].Length%4)%4, '=');
                        byte[] payload = Convert.FromBase64String(padded.Replace('-','+').Replace('_','/'));
                        string json = Encoding.UTF8.GetString(payload);
                        ta.Notes.Add($"Payload: {json[..Math.Min(200, json.Length)]}");
                    }
                    catch { ta.Notes.Add("Payload: could not decode"); }
                }
            }
            else
            {
                ta.Kind = TokenKind.Custom;
                ta.Description = $"{raw.Length}B custom token";
            }
        }

        // Timestamp scan: look for 8-byte Unix timestamp (seconds since 1970)
        for (int i = 0; i + 8 <= raw.Length; i += 4)
        {
            long ts = BitConverter.ToInt64(raw, i);
            var dt = DateTimeOffset.FromUnixTimeSeconds(ts);
            if (dt.Year >= 2020 && dt.Year <= 2030)
            {
                ta.HasTimestamp = true;
                ta.TimestampUtc = ts;
                ta.Notes.Add($"Possible timestamp at offset {i}: {dt:yyyy-MM-dd HH:mm:ss} UTC");
                break;
            }
        }

        AddLog($"[TOKEN] {source}: {ta.Description}  {raw.Length}B  reuse={ta.IsReuse}");
        foreach (var n in ta.Notes) AddLog($"  {n}");

        _history.Add(ta);
        if (_history.Count > 20) _history.RemoveAt(0);
        return ta;
    }

    /// <summary>
    /// Build a copy of the token with the 8-byte timestamp field patched to now.
    /// Returns null if no timestamp found.
    /// </summary>
    public byte[]? BuildReplayWithFreshTimestamp(TokenAnalysis ta)
    {
        if (!ta.HasTimestamp) return null;
        byte[] copy = (byte[])ta.Raw.Clone();
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        byte[] nowBytes = BitConverter.GetBytes(now);
        // find original timestamp offset
        for (int i = 0; i + 8 <= copy.Length; i += 4)
        {
            if (BitConverter.ToInt64(copy, i) == ta.TimestampUtc)
            {
                nowBytes.CopyTo(copy, i);
                AddLog($"[TOKEN] Patched timestamp at offset {i}: {ta.TimestampUtc} → {now}");
                return copy;
            }
        }
        return null;
    }

    public void Clear() { _history.Clear(); AddLog("[TOKEN] Cleared"); }

    private static string FormatUuid(byte[] b) =>
        $"{BitConverter.ToString(b, 0, 4)}-{BitConverter.ToString(b, 4, 2)}-{BitConverter.ToString(b, 6, 2)}-{BitConverter.ToString(b, 8, 2)}-{BitConverter.ToString(b, 10, 6)}".Replace("-","");

    private static string SafeAscii(byte[] b) =>
        new string(b.Select(x => (x >= 0x20 && x < 0x7F) ? (char)x : '.').ToArray());

    private void AddLog(string msg)
    {
        var line = $"[{DateTime.Now:HH:mm:ss.fff}] {msg}";
        lock (_logLock) { _log.Add(line); if (_log.Count > 500) _log.RemoveAt(0); }
        OnLog?.Invoke(line);
    }
}
