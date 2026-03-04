using System.Collections.Concurrent;

namespace HyForce.Networking;

public class SessionManager<T> where T : class
{
    private readonly ConcurrentDictionary<string, T> _sessions = new();

    public int Count => _sessions.Count;
    public int TotalSessions { get; private set; }

    public event Action<T>? OnSessionAdded;
    public event Action<T>? OnSessionRemoved;

    public bool TryAdd(string key, T session)
    {
        if (_sessions.TryAdd(key, session))
        {
            TotalSessions++;
            OnSessionAdded?.Invoke(session);
            return true;
        }
        return false;
    }

    public bool TryRemove(string key, out T? session)
    {
        if (_sessions.TryRemove(key, out session))
        {
            OnSessionRemoved?.Invoke(session);
            return true;
        }
        return false;
    }

    public bool TryGet(string key, out T? session)
    {
        return _sessions.TryGetValue(key, out session);
    }

    public IEnumerable<T> GetAll()
    {
        return _sessions.Values;
    }

    public void Clear()
    {
        _sessions.Clear();
    }
}