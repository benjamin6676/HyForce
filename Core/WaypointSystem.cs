// Core/WaypointSystem.cs  v20
// Named waypoint bookmarks + ordered route execution.
// Routes are sent to the C hook which handles the actual inject_movement calls.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace HyForce.Core;

public class Waypoint
{
    public string Name   { get; set; } = "";
    public float  X      { get; set; }
    public float  Y      { get; set; }
    public float  Z      { get; set; }
    public string Notes  { get; set; } = "";
    public DateTime SavedAt { get; set; } = DateTime.UtcNow;
    public override string ToString() => $"{Name}  ({X:F0},{Y:F0},{Z:F0})";
}

public class WaypointRoute
{
    public string           Name       { get; set; } = "Route";
    public List<Waypoint>   Points     { get; set; } = new();
    public int              DelayMs    { get; set; } = 1000;
    public bool             Loop       { get; set; } = false;
    public DateTime         CreatedAt  { get; set; } = DateTime.UtcNow;
}

public class WaypointSystem
{
    private readonly List<Waypoint>      _bookmarks = new();
    private readonly List<WaypointRoute> _routes    = new();
    private readonly List<string>        _log       = new();
    private readonly object              _logLock   = new();
    private CancellationTokenSource?     _runCts;

    public bool  IsRunning      { get; private set; }
    public int   CurrentPoint   { get; private set; }
    public string? RunningRoute { get; private set; }

    public IReadOnlyList<Waypoint>      Bookmarks => _bookmarks;
    public IReadOnlyList<WaypointRoute> Routes    => _routes;
    public IReadOnlyList<string>        Log { get { lock (_logLock) return _log.ToList(); } }
    public event Action<string>? OnLog;

    // Callbacks wired from AppState
    public Action<float,float,float>? TeleportTo { get; set; }  // calls pipe.Teleport

    // ── Bookmarks ─────────────────────────────────────────────────────────
    public void AddBookmark(string name, float x, float y, float z, string notes = "")
    {
        _bookmarks.RemoveAll(b => b.Name == name);   // replace if exists
        _bookmarks.Add(new Waypoint { Name=name, X=x, Y=y, Z=z, Notes=notes });
        if (_bookmarks.Count > 500) _bookmarks.RemoveAt(0);
        AddLog($"[WP] Bookmark '{name}' saved  ({x:F0},{y:F0},{z:F0})");
    }

    public void DeleteBookmark(string name) { _bookmarks.RemoveAll(b => b.Name == name); }

    public void TeleportToBookmark(string name)
    {
        var b = _bookmarks.FirstOrDefault(x => x.Name == name);
        if (b == null) { AddLog($"[WP] Bookmark '{name}' not found"); return; }
        TeleportTo?.Invoke(b.X, b.Y, b.Z);
        AddLog($"[WP] Teleported to bookmark '{name}'  ({b.X:F0},{b.Y:F0},{b.Z:F0})");
    }

    // ── Routes ────────────────────────────────────────────────────────────
    public WaypointRoute CreateRoute(string name) =>
        _routes.FirstOrDefault(r => r.Name == name) ?? new WaypointRoute { Name = name }.Also(r => _routes.Add(r));

    public void DeleteRoute(string name) => _routes.RemoveAll(r => r.Name == name);

    public async Task RunRoute(WaypointRoute route, CancellationToken tok = default)
    {
        if (IsRunning) { AddLog("[WP] Already running a route"); return; }
        IsRunning    = true;
        RunningRoute = route.Name;
        AddLog($"[WP] Running route '{route.Name}'  {route.Points.Count} points  delay={route.DelayMs}ms  loop={route.Loop}");

        try
        {
            do
            {
                for (int i = 0; i < route.Points.Count && !tok.IsCancellationRequested; i++)
                {
                    CurrentPoint = i;
                    var p = route.Points[i];
                    TeleportTo?.Invoke(p.X, p.Y, p.Z);
                    AddLog($"[WP] → [{i+1}/{route.Points.Count}] '{p.Name}'  ({p.X:F0},{p.Y:F0},{p.Z:F0})");
                    await Task.Delay(route.DelayMs, tok);
                }
            } while (route.Loop && !tok.IsCancellationRequested);

            AddLog($"[WP] Route '{route.Name}' complete");
        }
        catch (OperationCanceledException) { AddLog("[WP] Route cancelled"); }
        finally { IsRunning = false; RunningRoute = null; }
    }

    public void StartRoute(WaypointRoute route)
    {
        _runCts = new CancellationTokenSource();
        _ = RunRoute(route, _runCts.Token);
    }

    public void StopRoute() { _runCts?.Cancel(); IsRunning = false; }

    // ── Persistence ────────────────────────────────────────────────────────
    public void SaveToJson(string path)
    {
        var data = new { Bookmarks = _bookmarks, Routes = _routes };
        File.WriteAllText(path, JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true }));
        AddLog($"[WP] Saved {_bookmarks.Count} bookmarks + {_routes.Count} routes → {path}");
    }

    public void LoadFromJson(string path)
    {
        var json = File.ReadAllText(path);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        if (root.TryGetProperty("Bookmarks", out var bArr))
        {
            foreach (var b in bArr.EnumerateArray())
            {
                _bookmarks.Add(new Waypoint {
                    Name = b.GetProperty("Name").GetString() ?? "",
                    X    = b.GetProperty("X").GetSingle(),
                    Y    = b.GetProperty("Y").GetSingle(),
                    Z    = b.GetProperty("Z").GetSingle(),
                    Notes= b.TryGetProperty("Notes", out var n) ? n.GetString()??""  : ""
                });
            }
        }
        AddLog($"[WP] Loaded {_bookmarks.Count} bookmarks from {Path.GetFileName(path)}");
    }

    public void Clear() { _bookmarks.Clear(); _routes.Clear(); AddLog("[WP] Cleared"); }

    private void AddLog(string msg)
    {
        var line = $"[{DateTime.Now:HH:mm:ss.fff}] {msg}";
        lock (_logLock) { _log.Add(line); if (_log.Count > 500) _log.RemoveAt(0); }
        OnLog?.Invoke(line);
    }
}

internal static class ObjectExtensions
{
    public static T Also<T>(this T obj, Action<T> action) { action(obj); return obj; }
}
