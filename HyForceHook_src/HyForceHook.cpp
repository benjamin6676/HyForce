// HyForceHook.cpp
// ================================================================================
// HyForce UDP Capture Hook DLL
// Injects into Hytale.exe and hooks WSASendTo / WSARecvFrom in ws2_32.dll.
// Streams raw UDP packet data to HyForce via named pipe \\.\pipe\HyForceCapture.
//
// Build (MSVC x64, from VS Developer Command Prompt):
//   cl /LD /O2 /EHsc HyForceHook.cpp /link ws2_32.lib /out:HyForceHook.dll
//
// Build (MinGW-w64 x64):
//   g++ -shared -m64 -O2 -o HyForceHook.dll HyForceHook.cpp -lws2_32 -mwindows
//
// Build (MinGW-w64 with MinHook for safer hooking):
//   g++ -shared -m64 -O2 -o HyForceHook.dll HyForceHook.cpp MinHook.x64.lib -lws2_32
//   (Download MinHook from https://github.com/TsudaKageyu/minhook/releases)
//
// Without MinHook we use a simpler IAT (Import Address Table) patch.
// This works for Java's JVM since it imports ws2_32 normally.
// ================================================================================

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <psapi.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")

// ── Config ────────────────────────────────────────────────────────────────────
#define PIPE_NAME       L"\\\\.\\pipe\\HyForceCapture"
#define SERVER_IP_FILTER 0  // 0 = capture all UDP; set to server IP (network byte order) to filter
#define MAX_PKT_SIZE    65535

// ── Global state ─────────────────────────────────────────────────────────────
static HANDLE   g_pipe       = INVALID_HANDLE_VALUE;
static HANDLE   g_pipeMutex  = NULL;
static volatile bool g_active = false;

// Original function pointers (for IAT hook)
typedef int (WSAAPI* PFN_WSASendTo)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD,
    const struct sockaddr*, int, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI* PFN_WSARecvFrom)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD,
    struct sockaddr*, LPINT, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI* PFN_sendto)(SOCKET, const char*, int, int,
    const struct sockaddr*, int);
typedef int (WSAAPI* PFN_recvfrom)(SOCKET, char*, int, int,
    struct sockaddr*, int*);

static PFN_WSASendTo  orig_WSASendTo  = nullptr;
static PFN_WSARecvFrom orig_WSARecvFrom = nullptr;
static PFN_sendto      orig_sendto     = nullptr;
static PFN_recvfrom    orig_recvfrom   = nullptr;

// ── Pipe write ────────────────────────────────────────────────────────────────
// Packet header (17 bytes):
//   [0]     direction: 0=C→S  1=S→C
//   [1..4]  data length (uint32 LE)
//   [5..8]  src IP (uint32 BE = network order)
//   [9..10] src port (uint16 BE)
//   [11..14] dst IP (uint32 BE)
//   [15..16] dst port (uint16 BE)
static void SendPacket(uint8_t dir, uint32_t srcIp, uint16_t srcPort,
                       uint32_t dstIp, uint16_t dstPort,
                       const uint8_t* data, uint32_t len)
{
    if (g_pipe == INVALID_HANDLE_VALUE || !g_active) return;
    if (len == 0 || len > MAX_PKT_SIZE) return;

    // Filter: only forward UDP to/from Hytale game server
    // Port 5520 is the known Hytale game port
    if (srcPort != 5520 && dstPort != 5520 &&
        srcPort != 5521 && dstPort != 5521) return;

    uint8_t hdr[17];
    hdr[0] = dir;
    *(uint32_t*)(hdr + 1)  = len;
    *(uint32_t*)(hdr + 5)  = srcIp;
    *(uint16_t*)(hdr + 9)  = srcPort;
    *(uint32_t*)(hdr + 11) = dstIp;
    *(uint16_t*)(hdr + 15) = dstPort;

    WaitForSingleObject(g_pipeMutex, INFINITE);
    DWORD written;
    BOOL ok1 = WriteFile(g_pipe, hdr, sizeof(hdr), &written, NULL);
    BOOL ok2 = WriteFile(g_pipe, data, len, &written, NULL);
    ReleaseMutex(g_pipeMutex);

    if (!ok1 || !ok2)
    {
        // Pipe broke — try reconnect
        g_active = false;
    }
}

// ── Hook: WSASendTo ──────────────────────────────────────────────────────────
static int WSAAPI Hook_WSASendTo(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent, DWORD dwFlags, const struct sockaddr* lpTo,
    int iTolen, LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    // Call original first
    int result = orig_WSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent,
        dwFlags, lpTo, iTolen, lpOverlapped, lpCompletionRoutine);

    if (result == 0 && lpBuffers && lpBuffers->buf && lpTo)
    {
        // Flatten scatter buffers into single block
        DWORD total = 0;
        for (DWORD i = 0; i < dwBufferCount; i++) total += lpBuffers[i].len;
        if (total > 0 && total <= MAX_PKT_SIZE)
        {
            uint8_t* flat = (uint8_t*)_malloca(total);
            if (flat)
            {
                DWORD off = 0;
                for (DWORD i = 0; i < dwBufferCount; i++)
                {
                    memcpy(flat + off, lpBuffers[i].buf, lpBuffers[i].len);
                    off += lpBuffers[i].len;
                }
                auto* dst = (const struct sockaddr_in*)lpTo;
                uint32_t dstIp   = dst->sin_addr.s_addr;
                uint16_t dstPort = ntohs(dst->sin_port);

                // Get local port for src
                struct sockaddr_in local{}; int localLen = sizeof(local);
                getsockname(s, (struct sockaddr*)&local, &localLen);
                uint32_t srcIp   = local.sin_addr.s_addr;
                uint16_t srcPort = ntohs(local.sin_port);

                SendPacket(0, srcIp, srcPort, dstIp, dstPort, flat, total);
                _freea(flat);
            }
        }
    }
    return result;
}

// ── Hook: WSARecvFrom ────────────────────────────────────────────────────────
static int WSAAPI Hook_WSARecvFrom(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, struct sockaddr* lpFrom,
    LPINT lpFromlen, LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    int result = orig_WSARecvFrom(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd,
        lpFlags, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine);

    if (result == 0 && lpNumberOfBytesRecvd && *lpNumberOfBytesRecvd > 0 &&
        lpBuffers && lpBuffers->buf && lpFrom)
    {
        // Flatten recv buffers
        DWORD total = 0;
        for (DWORD i = 0; i < dwBufferCount; i++) total += lpBuffers[i].len;
        DWORD actual = min(total, *lpNumberOfBytesRecvd);
        if (actual > 0 && actual <= MAX_PKT_SIZE)
        {
            uint8_t* flat = (uint8_t*)_malloca(actual);
            if (flat)
            {
                DWORD off = 0;
                for (DWORD i = 0; i < dwBufferCount && off < actual; i++)
                {
                    DWORD chunk = min(lpBuffers[i].len, actual - off);
                    memcpy(flat + off, lpBuffers[i].buf, chunk);
                    off += chunk;
                }
                auto* src = (const struct sockaddr_in*)lpFrom;
                uint32_t srcIp   = src->sin_addr.s_addr;
                uint16_t srcPort = ntohs(src->sin_port);

                struct sockaddr_in local{}; int localLen = sizeof(local);
                getsockname(s, (struct sockaddr*)&local, &localLen);
                uint32_t dstIp   = local.sin_addr.s_addr;
                uint16_t dstPort = ntohs(local.sin_port);

                SendPacket(1, srcIp, srcPort, dstIp, dstPort, flat, actual);
                _freea(flat);
            }
        }
    }
    return result;
}

// ── Hook: sendto (fallback for some Java NIO paths) ─────────────────────────
static int WSAAPI Hook_sendto(SOCKET s, const char* buf, int len, int flags,
    const struct sockaddr* to, int tolen)
{
    int result = orig_sendto(s, buf, len, flags, to, tolen);
    if (result > 0 && buf && to)
    {
        auto* dst = (const struct sockaddr_in*)to;
        struct sockaddr_in local{}; int ll = sizeof(local);
        getsockname(s, (struct sockaddr*)&local, &ll);
        SendPacket(0, local.sin_addr.s_addr, ntohs(local.sin_port),
                   dst->sin_addr.s_addr, ntohs(dst->sin_port),
                   (const uint8_t*)buf, (uint32_t)result);
    }
    return result;
}

// ── Hook: recvfrom ───────────────────────────────────────────────────────────
static int WSAAPI Hook_recvfrom(SOCKET s, char* buf, int len, int flags,
    struct sockaddr* from, int* fromlen)
{
    int result = orig_recvfrom(s, buf, len, flags, from, fromlen);
    if (result > 0 && buf && from)
    {
        auto* src = (const struct sockaddr_in*)from;
        struct sockaddr_in local{}; int ll = sizeof(local);
        getsockname(s, (struct sockaddr*)&local, &ll);
        SendPacket(1, src->sin_addr.s_addr, ntohs(src->sin_port),
                   local.sin_addr.s_addr, ntohs(local.sin_port),
                   (const uint8_t*)buf, (uint32_t)result);
    }
    return result;
}

// ── IAT Hook helper ──────────────────────────────────────────────────────────
// Walks the IAT of all loaded modules and patches a named import.
static bool PatchIAT(const char* moduleName, const char* funcName, void* newFunc, void** oldFunc)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    // Fallback: just patch the main module's IAT
    HMODULE hMain = GetModuleHandleA(NULL);
    if (!hMain) return false;

    auto* dosHdr = (IMAGE_DOS_HEADER*)hMain;
    auto* ntHdr  = (IMAGE_NT_HEADERS*)((uint8_t*)hMain + dosHdr->e_lfanew);
    auto& impDir = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!impDir.VirtualAddress) return false;

    auto* impDesc = (IMAGE_IMPORT_DESCRIPTOR*)((uint8_t*)hMain + impDir.VirtualAddress);
    bool patched = false;

    for (; impDesc->Name; impDesc++)
    {
        const char* dllName = (const char*)((uint8_t*)hMain + impDesc->Name);
        if (_stricmp(dllName, moduleName) != 0) continue;

        auto* thunk    = (IMAGE_THUNK_DATA*)((uint8_t*)hMain + impDesc->FirstThunk);
        auto* origThunk = (IMAGE_THUNK_DATA*)((uint8_t*)hMain + impDesc->OriginalFirstThunk);

        for (int i = 0; thunk[i].u1.Function; i++)
        {
            if (origThunk[i].u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
            auto* impByName = (IMAGE_IMPORT_BY_NAME*)((uint8_t*)hMain + origThunk[i].u1.AddressOfData);
            if (_stricmp((char*)impByName->Name, funcName) != 0) continue;

            void** pFunc = (void**)&thunk[i].u1.Function;
            if (oldFunc) *oldFunc = *pFunc;

            DWORD oldProt;
            VirtualProtect(pFunc, sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProt);
            *pFunc = newFunc;
            VirtualProtect(pFunc, sizeof(void*), oldProt, &oldProt);

            patched = true;
            break;
        }
        if (patched) break;
    }

    if (hSnapshot != INVALID_HANDLE_VALUE) CloseHandle(hSnapshot);
    return patched;
}

#include <tlhelp32.h>

// Patch IAT across all loaded modules
static void PatchAllModulesIAT(const char* targetDll, const char* funcName,
                                void* newFunc, void** origOut)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    MODULEENTRY32 me{}; me.dwSize = sizeof(me);

    // Store first original we find
    *origOut = GetProcAddress(GetModuleHandleA(targetDll), funcName);

    if (snap == INVALID_HANDLE_VALUE) return;
    if (!Module32First(snap, &me)) { CloseHandle(snap); return; }
    do {
        void* dummy = nullptr;
        PatchIAT(targetDll, funcName, newFunc, &dummy);
    } while (Module32Next(snap, &me));
    CloseHandle(snap);
}

// ── Pipe reconnect thread ─────────────────────────────────────────────────────
static DWORD WINAPI PipeThread(LPVOID)
{
    while (true)
    {
        // Try to connect to HyForce pipe
        HANDLE h = CreateFileW(PIPE_NAME, GENERIC_WRITE, 0, NULL,
                               OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE)
        {
            WaitForSingleObject(g_pipeMutex, INFINITE);
            if (g_pipe != INVALID_HANDLE_VALUE) CloseHandle(g_pipe);
            g_pipe = h;
            g_active = true;
            ReleaseMutex(g_pipeMutex);
            // Notify via OutputDebugString
            OutputDebugStringA("[HyForceHook] Connected to HyForce pipe\n");
        }
        else
        {
            g_active = false;
            OutputDebugStringA("[HyForceHook] Waiting for HyForce pipe...\n");
        }
        Sleep(2000); // retry every 2 seconds
    }
    return 0;
}

// ── DllMain ───────────────────────────────────────────────────────────────────
BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hMod);

        // Create mutex for pipe writes
        g_pipeMutex = CreateMutexA(NULL, FALSE, NULL);

        // Hook ws2_32.dll socket functions in all loaded modules' IATs
        PatchAllModulesIAT("ws2_32.dll", "WSASendTo",   (void*)Hook_WSASendTo,   (void**)&orig_WSASendTo);
        PatchAllModulesIAT("ws2_32.dll", "WSARecvFrom", (void*)Hook_WSARecvFrom, (void**)&orig_WSARecvFrom);
        PatchAllModulesIAT("ws2_32.dll", "sendto",      (void*)Hook_sendto,      (void**)&orig_sendto);
        PatchAllModulesIAT("ws2_32.dll", "recvfrom",    (void*)Hook_recvfrom,    (void**)&orig_recvfrom);

        // Start pipe connection thread
        CreateThread(NULL, 0, PipeThread, NULL, 0, NULL);

        OutputDebugStringA("[HyForceHook] Loaded — hooks installed\n");
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        g_active = false;
        if (g_pipe != INVALID_HANDLE_VALUE) CloseHandle(g_pipe);
    }
    return TRUE;
}

// ── Exports (optional — for manual mapping approaches) ───────────────────────
extern "C" __declspec(dllexport) void HyForceHook_GetVersion(char* buf, int len)
{
    strncpy_s(buf, len, "HyForceHook v1.0 — UDP capture for Hytale QUIC", len - 1);
}
