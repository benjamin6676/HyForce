// Core/TimeWeatherController.cs  v19
// Manages spoofed time and weather state.
// Delivers fake 0x92 UpdateTime / 0x95 UpdateWeather S2C frames to the
// game app on a timer without any real server involvement.
//
// Time ticks: Hytale likely uses uint32 ticks (0 = dawn, full cycle TBD).
// Weather types: 0=clear, 1=rain, 2=thunder (guessed from opcode captures).

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace HyForce.Core;

public enum WeatherType : uint { Clear = 0, Rain = 1, Thunder = 2 }

public class TimeWeatherController
{
    // Callback to deliver a command to the pipe
    public Action<string>? SendPipeCommand { get; set; }

    private CancellationTokenSource? _timeCts;
    private readonly List<string>    _log     = new();
    private readonly object          _logLock = new();

    public bool   IsTimeLocked    { get; private set; }
    public uint   LockedTimeTicks { get; private set; }
    public bool   IsTimeRunning   { get; private set; }
    public uint   CurrentTick     { get; private set; }
    public float  TimeSpeed       { get; private set; } = 1.0f;
    public WeatherType CurrentWeather { get; private set; }

    public IReadOnlyList<string> Log { get { lock (_logLock) return _log.ToList(); } }
    public event Action<string>? OnLog;

    // Known time presets (approximate tick values)
    public static readonly (string Name, uint Ticks)[] TimePresets =
    {
        ("Dawn",      0),
        ("Morning",   2000),
        ("Noon",      6000),
        ("Afternoon", 9000),
        ("Dusk",      12000),
        ("Night",     14000),
        ("Midnight",  18000),
    };

    // ── One-shot set ────────────────────────────────────────────────────
    public void SetTime(uint ticks)
    {
        CurrentTick = ticks;
        SendPipeCommand?.Invoke($"TIME_SET {ticks}");
        AddLog($"[TIME] Set to {ticks} ticks");
    }

    public void SetWeather(WeatherType w)
    {
        CurrentWeather = w;
        SendPipeCommand?.Invoke($"WEATHER_SET {(uint)w}");
        AddLog($"[WEATHER] Set to {w}");
    }

    // ── Lock (freeze) ────────────────────────────────────────────────────
    public void LockTime(uint ticks, int resendIntervalMs = 5000)
    {
        StopTimeAdvance();
        LockedTimeTicks = ticks;
        IsTimeLocked    = true;
        _timeCts = new CancellationTokenSource();
        var tok  = _timeCts.Token;
        IsTimeRunning   = true;
        AddLog($"[TIME] Locked at {ticks} ticks  resend every {resendIntervalMs}ms");

        Task.Run(async () =>
        {
            while (!tok.IsCancellationRequested)
            {
                SendPipeCommand?.Invoke($"TIME_SET {ticks}");
                await Task.Delay(resendIntervalMs, tok);
            }
            IsTimeRunning = false;
        }, tok);
    }

    // ── Advance (accelerated time-lapse) ─────────────────────────────────
    public void StartTimeAdvance(float speed = 10f, int tickIntervalMs = 200)
    {
        StopTimeAdvance();
        TimeSpeed     = speed;
        IsTimeLocked  = false;
        IsTimeRunning = true;
        _timeCts = new CancellationTokenSource();
        var tok  = _timeCts.Token;
        AddLog($"[TIME] Advancing at {speed}x  interval={tickIntervalMs}ms");

        Task.Run(async () =>
        {
            while (!tok.IsCancellationRequested)
            {
                CurrentTick = (uint)((CurrentTick + (uint)(speed * tickIntervalMs / 50)) % 24000);
                SendPipeCommand?.Invoke($"TIME_SET {CurrentTick}");
                await Task.Delay(tickIntervalMs, tok);
            }
            IsTimeRunning = false;
        }, tok);
    }

    public void StopTimeAdvance()
    {
        _timeCts?.Cancel();
        IsTimeLocked  = false;
        IsTimeRunning = false;
        AddLog("[TIME] Advance stopped");
    }

    private void AddLog(string msg)
    {
        var line = $"[{DateTime.Now:HH:mm:ss.fff}] {msg}";
        lock (_logLock) { _log.Add(line); if (_log.Count > 500) _log.RemoveAt(0); }
        OnLog?.Invoke(line);
    }
}
