/*
 * HyForceHook.dll — WinSock packet capture hook for Hytale (JVM / Netty QUIC)
 *
 * Build (requires Visual Studio Developer Command Prompt or MinGW-w64):
 *   MSVC:   cl.exe /O2 /LD HyForceHook.c /Fe:HyForceHook.dll ws2_32.lib
 *   MinGW:  gcc -O2 -shared -o HyForceHook.dll HyForceHook.c -lws2_32
 *
 * What it does:
 *   - Hooks WSASendTo and WSARecvFrom in ws2_32.dll using inline JMP patches
 *   - Forwards raw UDP packets to HyForce via named pipe \\.\pipe\HyForcePipe
 *   - No MinHook or Detours dependency
 *
 * Pipe message format (little-endian):
 *   [1B  direction : 0=Client->Server, 1=Server->Client]
 *   [4B  data_len  : uint32]
 *   [NB  packet    : raw QUIC bytes]
 *   [4B  remote_ip : IPv4 network-order]
 *   [2B  remote_port: uint16 network-order]
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdint.h>

#pragma comment(lib, "ws2_32.lib")

/* ── Pipe IPC ──────────────────────────────────────────────── */
#define PIPE_NAME   L"\\\\.\\pipe\\HyForcePipe"
#define MAX_PKT_LEN  65535

static HANDLE g_pipe    = INVALID_HANDLE_VALUE;
static HANDLE g_mutex   = NULL;
static volatile BOOL g_active = FALSE;
static HANDLE g_connect_thread = NULL;

/* ── Function pointer types ─────────────────────────────────── */
typedef int (WSAAPI *WSASendTo_fn)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD,
    const struct sockaddr*, int, LPWSAOVERLAPPED,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *WSARecvFrom_fn)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD,
    struct sockaddr*, LPINT, LPWSAOVERLAPPED,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE);

static WSASendTo_fn  orig_WSASendTo  = NULL;
static WSARecvFrom_fn orig_WSARecvFrom = NULL;

/* ── Trampoline storage (14 bytes saved per function) ────────── */
static BYTE saved_SendTo [14];
static BYTE saved_RecvFrom[14];

/* ── Write absolute JMP (x64 FF25 trampoline, 14 bytes) ────── */
static void write_jmp(LPVOID target, LPVOID hook_fn) {
    DWORD old;
    VirtualProtect(target, 14, PAGE_EXECUTE_READWRITE, &old);
    BYTE *p = (BYTE*)target;
    /* FF 25 00 00 00 00 [8-byte abs addr] */
    p[0] = 0xFF; p[1] = 0x25;
    *(DWORD*)(p + 2) = 0;
    *(uint64_t*)(p + 6) = (uint64_t)hook_fn;
    VirtualProtect(target, 14, old, &old);
    FlushInstructionCache(GetCurrentProcess(), target, 14);
}

static void restore_fn(LPVOID target, BYTE *saved) {
    DWORD old;
    VirtualProtect(target, 14, PAGE_EXECUTE_READWRITE, &old);
    memcpy(target, saved, 14);
    VirtualProtect(target, 14, old, &old);
    FlushInstructionCache(GetCurrentProcess(), target, 14);
}

/* ── Send packet data to HyForce ─────────────────────────────── */
static void pipe_send(uint8_t dir, const uint8_t *data, int len,
                      uint32_t ip, uint16_t port)
{
    if (g_pipe == INVALID_HANDLE_VALUE || len <= 0 || len > MAX_PKT_LEN) return;

    int total = 1 + 4 + len + 4 + 2;
    uint8_t *buf = (uint8_t*)_alloca(total);
    if (!buf) return;

    buf[0] = dir;
    *(uint32_t*)(buf + 1)       = (uint32_t)len;
    memcpy(buf + 5, data, len);
    *(uint32_t*)(buf + 5 + len)     = ip;
    *(uint16_t*)(buf + 5 + len + 4) = port;

    WaitForSingleObject(g_mutex, 100);
    DWORD written = 0;
    if (!WriteFile(g_pipe, buf, total, &written, NULL)) {
        /* Pipe broken — close so reconnect thread can retry */
        CloseHandle(g_pipe);
        g_pipe = INVALID_HANDLE_VALUE;
    }
    ReleaseMutex(g_mutex);
}

/* ── Hook: WSASendTo ─────────────────────────────────────────── */
static int WSAAPI hook_WSASendTo(
    SOCKET s, LPWSABUF bufs, DWORD nbufs, LPDWORD sent, DWORD flags,
    const struct sockaddr *to, int tolen,
    LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cb)
{
    /* Temporarily remove our hook so we can call the real function */
    restore_fn(orig_WSASendTo, saved_SendTo);
    int ret = WSASendTo(s, bufs, nbufs, sent, flags, to, tolen, ov, cb);
    write_jmp(orig_WSASendTo, hook_WSASendTo);

    if (ret == 0 && nbufs > 0 && bufs[0].buf && bufs[0].len > 0) {
        uint32_t ip = 0; uint16_t port = 0;
        if (to && tolen >= (int)sizeof(struct sockaddr_in)) {
            const struct sockaddr_in *sin = (const struct sockaddr_in*)to;
            if (sin->sin_family == AF_INET) {
                ip   = sin->sin_addr.s_addr;
                port = sin->sin_port;
            }
        }
        pipe_send(0, (uint8_t*)bufs[0].buf, (int)bufs[0].len, ip, port);
    }
    return ret;
}

/* ── Hook: WSARecvFrom ───────────────────────────────────────── */
static int WSAAPI hook_WSARecvFrom(
    SOCKET s, LPWSABUF bufs, DWORD nbufs, LPDWORD recvd, LPDWORD flags,
    struct sockaddr *from, LPINT fromlen,
    LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cb)
{
    restore_fn(orig_WSARecvFrom, saved_RecvFrom);
    int ret = WSARecvFrom(s, bufs, nbufs, recvd, flags, from, fromlen, ov, cb);
    write_jmp(orig_WSARecvFrom, hook_WSARecvFrom);

    if (ret == 0 && recvd && *recvd > 0 && nbufs > 0 && bufs[0].buf) {
        uint32_t ip = 0; uint16_t port = 0;
        if (from && fromlen && *fromlen >= (int)sizeof(struct sockaddr_in)) {
            const struct sockaddr_in *sin = (const struct sockaddr_in*)from;
            if (sin->sin_family == AF_INET) {
                ip   = sin->sin_addr.s_addr;
                port = sin->sin_port;
            }
        }
        pipe_send(1, (uint8_t*)bufs[0].buf, (int)*recvd, ip, port);
    }
    return ret;
}

/* ── Pipe reconnect thread ──────────────────────────────────── */
static DWORD WINAPI pipe_connect_loop(LPVOID unused) {
    (void)unused;
    while (g_active) {
        if (g_pipe == INVALID_HANDLE_VALUE) {
            HANDLE h = CreateFileW(PIPE_NAME, GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                OPEN_EXISTING, 0, NULL);
            if (h != INVALID_HANDLE_VALUE) {
                DWORD mode = PIPE_READMODE_BYTE;
                SetNamedPipeHandleState(h, &mode, NULL, NULL);
                WaitForSingleObject(g_mutex, INFINITE);
                g_pipe = h;
                ReleaseMutex(g_mutex);
            }
        }
        Sleep(500);
    }
    return 0;
}

/* ── DllMain ─────────────────────────────────────────────────── */
BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved) {
    (void)hInst; (void)reserved;

    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hInst);

        g_mutex = CreateMutexW(NULL, FALSE, NULL);
        if (!g_mutex) return FALSE;

        /* Resolve real WinSock functions */
        HMODULE ws2 = GetModuleHandleW(L"ws2_32.dll");
        if (!ws2) ws2 = LoadLibraryW(L"ws2_32.dll");
        if (!ws2) return FALSE;

        orig_WSASendTo   = (WSASendTo_fn)  GetProcAddress(ws2, "WSASendTo");
        orig_WSARecvFrom = (WSARecvFrom_fn) GetProcAddress(ws2, "WSARecvFrom");
        if (!orig_WSASendTo || !orig_WSARecvFrom) return FALSE;

        /* Save original bytes and install hooks */
        memcpy(saved_SendTo,  orig_WSASendTo,  14);
        memcpy(saved_RecvFrom,orig_WSARecvFrom, 14);
        write_jmp(orig_WSASendTo,  hook_WSASendTo);
        write_jmp(orig_WSARecvFrom,hook_WSARecvFrom);

        g_active = TRUE;
        g_connect_thread = CreateThread(NULL, 0, pipe_connect_loop, NULL, 0, NULL);

    } else if (reason == DLL_PROCESS_DETACH) {
        g_active = FALSE;

        /* Restore originals */
        if (orig_WSASendTo)   restore_fn(orig_WSASendTo,  saved_SendTo);
        if (orig_WSARecvFrom) restore_fn(orig_WSARecvFrom, saved_RecvFrom);

        if (g_pipe != INVALID_HANDLE_VALUE) { CloseHandle(g_pipe); g_pipe = INVALID_HANDLE_VALUE; }
        if (g_mutex) { CloseHandle(g_mutex); g_mutex = NULL; }
        if (g_connect_thread) {
            WaitForSingleObject(g_connect_thread, 2000);
            CloseHandle(g_connect_thread);
        }
    }
    return TRUE;
}
