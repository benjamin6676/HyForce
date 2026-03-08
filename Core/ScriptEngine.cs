// Core/ScriptEngine.cs  v20
// Executes .hfscript files — line-by-line command sequences with extras:
//
//   SLEEP <ms>                 — wait N milliseconds
//   LOOP <n>                   — repeat next block N times (0 = infinite until STOP)
//   ENDLOOP                    — end of loop block
//   VAR <name> <value>         — set a named variable
//   IF <var> == <value>        — conditional block
//   ENDIF                      — end conditional
//   LABEL <name>               — define a jump target
//   GOTO <name>                — unconditional jump to label
//   PRINT <message>            — log a message to the script output
//   # comment                  — ignored
//
// All other lines are passed directly to the pipe as commands
// (TELEPORT, SEND_CHAT, FORGE_STREAM, BLOCK_PLACE, ITEM_SPAM_START, etc.)

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace HyForce.Core;

public class ScriptEngine
{
    private readonly List<string>               _log         = new();
    private readonly object                     _logLock     = new();
    private CancellationTokenSource?            _cts;
    private readonly Dictionary<string, string> _vars        = new();

    public bool   IsRunning     { get; private set; }
    public int    LineNumber    { get; private set; }
    public string CurrentLine   { get; private set; } = "";
    public string ScriptName    { get; private set; } = "";
    public int    CommandsSent  { get; private set; }

    // Wired from AppState — sends a command string to the pipe
    public Action<string>? SendCommand { get; set; }

    public IReadOnlyList<string> Log { get { lock (_logLock) return _log.ToList(); } }
    public event Action<string>? OnLog;

    // ── Run from text ─────────────────────────────────────────────────────
    public void RunText(string script, string name = "inline")
    {
        if (IsRunning) { AddLog("[SCRIPT] Already running — stop first"); return; }
        ScriptName = name;
        _cts = new CancellationTokenSource();
        var tok = _cts.Token;
        var lines = script.Split('\n').Select(l => l.TrimEnd('\r')).ToArray();
        _ = ExecuteAsync(lines, tok);
    }

    public void RunFile(string path)
    {
        if (!File.Exists(path)) { AddLog($"[SCRIPT] File not found: {path}"); return; }
        RunText(File.ReadAllText(path), Path.GetFileName(path));
    }

    public void Stop() { _cts?.Cancel(); IsRunning = false; AddLog("[SCRIPT] Stopped"); }

    // ── Executor ──────────────────────────────────────────────────────────
    private async Task ExecuteAsync(string[] lines, CancellationToken tok)
    {
        IsRunning    = true;
        LineNumber   = 0;
        CommandsSent = 0;
        _vars.Clear();
        AddLog($"[SCRIPT] Running '{ScriptName}'  {lines.Length} lines");

        var ip = new InstructionPointer(lines);
        try
        {
            while (ip.HasMore && !tok.IsCancellationRequested)
            {
                string raw = ip.Current;
                ip.Advance();
                LineNumber = ip.Position;

                string line = SubstituteVars(raw.Trim());
                if (string.IsNullOrEmpty(line) || line.StartsWith('#')) continue;

                CurrentLine = line;

                if (line.StartsWith("SLEEP ", StringComparison.OrdinalIgnoreCase))
                {
                    int ms = int.Parse(line[6..].Trim());
                    await Task.Delay(Math.Min(ms, 30000), tok);
                }
                else if (line.StartsWith("PRINT ", StringComparison.OrdinalIgnoreCase))
                {
                    AddLog($"[SCRIPT L{LineNumber}] {line[6..]}");
                }
                else if (line.StartsWith("VAR ", StringComparison.OrdinalIgnoreCase))
                {
                    var parts = line[4..].Split(' ', 2);
                    if (parts.Length == 2) _vars[parts[0]] = parts[1];
                }
                else if (line.StartsWith("LOOP ", StringComparison.OrdinalIgnoreCase))
                {
                    int n = int.Parse(line[5..].Trim());
                    var block = ip.ReadBlock("ENDLOOP");
                    for (int i = 0; (n == 0 || i < n) && !tok.IsCancellationRequested; i++)
                    {
                        await ExecuteAsync(block, tok);
                        if (n == 0) { AddLog($"[SCRIPT] Loop iteration {i+1}"); }
                    }
                }
                else if (line.StartsWith("IF ", StringComparison.OrdinalIgnoreCase))
                {
                    var block = ip.ReadBlock("ENDIF");
                    if (EvalCondition(line[3..].Trim()))
                        await ExecuteAsync(block, tok);
                }
                else if (line.StartsWith("GOTO ", StringComparison.OrdinalIgnoreCase))
                {
                    string label = line[5..].Trim();
                    ip.JumpToLabel(label);
                }
                else if (line.StartsWith("LABEL ", StringComparison.OrdinalIgnoreCase))
                {
                    // Labels are registered on first pass; skip at runtime
                }
                else
                {
                    // Pass to pipe
                    SendCommand?.Invoke(line);
                    CommandsSent++;
                    AddLog($"[SCRIPT L{LineNumber}] → {line}");
                }
            }
            AddLog($"[SCRIPT] '{ScriptName}' done  {CommandsSent} commands");
        }
        catch (OperationCanceledException) { AddLog($"[SCRIPT] '{ScriptName}' cancelled at L{LineNumber}"); }
        catch (Exception ex)               { AddLog($"[SCRIPT] ERROR L{LineNumber}: {ex.Message}"); }
        finally { IsRunning = false; }
    }

    private string SubstituteVars(string line)
    {
        foreach (var kv in _vars) line = line.Replace($"${{{kv.Key}}}", kv.Value);
        return line;
    }

    private bool EvalCondition(string cond)
    {
        // Only supports: <var> == <value>  and  <var> != <value>
        if (cond.Contains("=="))
        {
            var parts = cond.Split("==", 2);
            string lhs = SubstituteVars(parts[0].Trim());
            string rhs = parts[1].Trim();
            return lhs == rhs;
        }
        if (cond.Contains("!="))
        {
            var parts = cond.Split("!=", 2);
            string lhs = SubstituteVars(parts[0].Trim());
            string rhs = parts[1].Trim();
            return lhs != rhs;
        }
        return false;
    }

    private void AddLog(string msg)
    {
        var line = $"[{DateTime.Now:HH:mm:ss.fff}] {msg}";
        lock (_logLock) { _log.Add(line); if (_log.Count > 2000) _log.RemoveAt(0); }
        OnLog?.Invoke(line);
    }

    // ── Instruction pointer helper ────────────────────────────────────────
    private class InstructionPointer
    {
        private readonly string[] _lines;
        private int _pos;
        private readonly Dictionary<string, int> _labels = new();

        public int     Position => _pos;
        public string  Current  => _lines[_pos];
        public bool    HasMore  => _pos < _lines.Length;

        public InstructionPointer(string[] lines)
        {
            _lines = lines;
            // Pre-scan labels
            for (int i = 0; i < lines.Length; i++)
            {
                string t = lines[i].Trim();
                if (t.StartsWith("LABEL ", StringComparison.OrdinalIgnoreCase))
                    _labels[t[6..].Trim()] = i;
            }
        }

        public void Advance() => _pos++;

        public string[] ReadBlock(string endKeyword)
        {
            var block = new List<string>();
            int depth = 0;
            while (_pos < _lines.Length)
            {
                string t = _lines[_pos].Trim();
                _pos++;
                if (string.Equals(t, endKeyword, StringComparison.OrdinalIgnoreCase) && depth == 0)
                    break;
                if (t.StartsWith("LOOP ", StringComparison.OrdinalIgnoreCase)) depth++;
                if (string.Equals(t, "ENDLOOP", StringComparison.OrdinalIgnoreCase) && depth > 0) depth--;
                block.Add(t);
            }
            return block.ToArray();
        }

        public void JumpToLabel(string label)
        {
            if (_labels.TryGetValue(label, out int pos)) _pos = pos;
        }
    }
}
