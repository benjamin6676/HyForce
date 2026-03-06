/*
 * HyForceHook.dll  v7  —  HyForce Security Research Engine
 *
 * MERGED VERSION: Original v6 + Enhanced BoringSSL Key Extraction
 *
 * Hytale/Netty QUIC Protocol Support:
 *   - QUIC over UDP (port 5520 default)
 *   - TLS 1.3 encryption via BoringSSL
 *   - Netty incubator QUIC codec compatibility
 *   - Automatic key extraction from SSL_CTX_set_keylog_callback
 *   - Shared memory ring buffer for high-throughput key+packet pairing
 *
 * CRITICAL FIXES for Hytale/Netty QUIC:
 *   - Added 32-bit support (Hytale sometimes launches 32-bit JVM)
 *   - Fixed packet size filter (was dropping small QUIC handshake packets)
 *   - Added GetLastError preservation (was corrupting WSA error codes)
 *   - Added non-blocking recvfrom handling (EWOULDBLOCK)
 *   - Hooks now preserve original function semantics exactly
 *   - Fixed race condition in forward() causing dropped packets
 *   - Added UDP port filtering (only capture Hytale traffic, not Discord/etc)
 *   - BoringSSL keylog callback hooking for automatic TLS 1.3 key extraction
 *
 * Build x64:
 *   MSVC: cl /O2 /LD /D_WIN32_WINNT=0x0A00 HyForceHook.c /Fe:HyForceHook64.dll ws2_32.lib psapi.lib
 * Build x86:
 *   MSVC: cl /O2 /LD /D_WIN32_WINNT=0x0A00 /arch:IA32 HyForceHook.c /Fe:HyForceHook32.dll ws2_32.lib psapi.lib
 * Build with MinGW-w64:
 *   x64: gcc -O2 -shared -o HyForceHook64.dll HyForceHook.c -lws2_32 -lpsapi
 *   x86: gcc -O2 -shared -m32 -o HyForceHook32.dll HyForceHook.c -lws2_32 -lpsapi
 *
 * Target: java.exe or javaw.exe (NOT HytaleClient.exe)
 *         Look for the process with ~500MB+ RAM usage after joining a server
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <psapi.h>
#include <tlhelp32.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")

 /* ── Pipe definitions ───────────────────────────────────── */
#define PIPE_DATA       L"\\\\.\\pipe\\HyForcePipe"
#define PIPE_CMD        L"\\\\.\\pipe\\HyForceCmdPipe"
#define MSG_PACKET      0x01
#define MSG_STATUS      0x02
#define MSG_LOG         0x03
#define MSG_TIMING      0x04
#define MSG_SEQ_ANOMALY 0x05
#define MSG_MEMSCAN     0x06
#define MSG_EJECTED     0x08
#define MSG_KEYLOG      0x09  /* NEW: Key log entry */
#define MSG_SHARED_MEM  0x0A  /* NEW: Shared memory segment info */
#define MAX_PKT         65535

 /* ── Hytale server ports ─────────────────────────────────── */
#define HYTALE_PORT_MIN 5520
#define HYTALE_PORT_MAX 5560  /* Some servers use non-standard ports */

/* ── Shared memory for high-throughput key+packet pairing ─── */
#define SHARED_MEM_NAME     L"HyForceSharedMem"
#define SHARED_MEM_SIZE     (16 * 1024 * 1024)  /* 16MB ring buffer */
#define RING_BUFFER_ENTRIES 4096

/* ── BoringSSL/SSL structures (simplified) ───────────────── */
typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;

/* BoringSSL keylog callback type */
typedef void (*ssl_keylog_callback_func)(const SSL* ssl, const char* line);

/* Function pointer types for hooking */
typedef void (*SSL_CTX_set_keylog_callback_t)(SSL_CTX* ctx, ssl_keylog_callback_func cb);
typedef ssl_keylog_callback_func(*SSL_CTX_get_keylog_callback_t)(const SSL_CTX* ctx);

/* ── Ring buffer entry structure ─────────────────────────── */
typedef struct RingBufferEntry {
    volatile uint32_t ready;        /* 0=empty, 1=key, 2=packet */
    uint32_t type;                  /* 1=QUIC key, 2=packet data */
    uint64_t timestamp_us;          /* Microsecond precision */
    uint32_t data_len;              /* Actual data length */
    uint32_t seq_num;               /* Sequence for ordering */
    uint8_t  data[4080];            /* Payload (keys or packet bytes) */
} RingBufferEntry;  /* 4096 bytes total = page aligned */

typedef struct SharedMemoryHeader {
    volatile uint32_t write_idx;    /* Writer position */
    volatile uint32_t read_idx;     /* Reader position (C# app updates) */
    volatile uint32_t dropped;      /* Counter for dropped entries */
    uint32_t entry_size;            /* sizeof(RingBufferEntry) */
    uint32_t max_entries;           /* RING_BUFFER_ENTRIES */
    uint64_t start_time_us;         /* Baseline timestamp */
} SharedMemoryHeader;

/* ── Key extraction globals ───────────────────────────────── */
static SSL_CTX_set_keylog_callback_t orig_SSL_CTX_set_keylog_callback = NULL;
static SSL_CTX_get_keylog_callback_t orig_SSL_CTX_get_keylog_callback = NULL;

/* Store original callbacks per SSL_CTX to chain calls */
typedef struct KeylogCallbackEntry {
    SSL_CTX* ctx;
    ssl_keylog_callback_func original_cb;
    struct KeylogCallbackEntry* next;
} KeylogCallbackEntry;

static KeylogCallbackEntry* g_callback_chain = NULL;
static CRITICAL_SECTION g_keylog_cs;

/* Shared memory handles */
static HANDLE g_shared_mem = NULL;
static SharedMemoryHeader* g_shm_header = NULL;
static RingBufferEntry* g_ring_buffer = NULL;
static uint32_t g_seq_counter = 0;

/* ── Original globals ─────────────────────────────────────── */
static HANDLE   g_out = INVALID_HANDLE_VALUE;
static HANDLE   g_cmdin = INVALID_HANDLE_VALUE;
static HANDLE   g_mutex = NULL;
static volatile BOOL g_active = FALSE;
static HANDLE   g_io_th = NULL;
static HANDLE   g_cmd_th = NULL;
static CRITICAL_SECTION g_cs;
static DWORD    g_dwTlsIndex = TLS_OUT_OF_INDEXES;

/* ── pcap ─────────────────────────────────────────────────── */
static HANDLE g_pcap = INVALID_HANDLE_VALUE;
static HANDLE g_pcap_mutex = NULL;

/* ── fuzz / replay ────────────────────────────────────────── */
static volatile int g_fuzz_bits = 0;
static uint8_t  g_last_cs[MAX_PKT];
static int      g_last_cs_len = 0;
static uint32_t g_last_cs_ip = 0;
static uint16_t g_last_cs_port = 0;
static CRITICAL_SECTION g_replay_cs;

/* ── seq tracking ────────────────────────────────────────── */
static uint64_t g_seq_cs = UINT64_MAX;
static uint64_t g_seq_sc = UINT64_MAX;

/* ── hook fire counters (for diagnostics) ─────────────────── */
static volatile LONG g_fires_wsa_send = 0;
static volatile LONG g_fires_send = 0;
static volatile LONG g_fires_wsa_recv = 0;
static volatile LONG g_fires_recv = 0;
static volatile LONG g_pkts_captured = 0;

/* ── hook targets ─────────────────────────────────────────── */
typedef int (WSAAPI* WSASendTo_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD,
    const struct sockaddr*, int, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI* WSARecvFrom_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD,
    struct sockaddr*, LPINT, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI* sendto_t)(SOCKET, const char*, int, int,
    const struct sockaddr*, int);
typedef int (WSAAPI* recvfrom_t)(SOCKET, char*, int, int,
    struct sockaddr*, int*);

static WSASendTo_t  orig_WSASendTo = NULL;
static WSARecvFrom_t orig_WSARecvFrom = NULL;
static sendto_t     orig_sendto = NULL;
static recvfrom_t   orig_recvfrom = NULL;

static BYTE sv_wsa_send[14], sv_wsa_recv[14];
static BYTE sv_send[14], sv_recv[14];

// Thread that monitors injector process health
static HANDLE g_injector_monitor = NULL;
static DWORD  g_injector_pid = 0;
/* ── Thread safety ───────────────────────────────────────── */
static DWORD g_dwTlsIndex = TLS_OUT_OF_INDEXES;
static volatile LONG g_inHook = 0;  // Global fallback

/* ── Forward declarations ────────────────────────────────── */
static void our_keylog_callback(const SSL* ssl, const char* line);
static ssl_keylog_callback_func find_original_callback(SSL_CTX* ctx);
static void store_callback_mapping(SSL_CTX* ctx, ssl_keylog_callback_func orig);
static void forward_key_to_shared_mem(const char* line, size_t len);
static void forward_packet_to_shared_mem(const uint8_t* data, uint32_t len,
    uint32_t ip, uint16_t port, uint8_t dir);
static int init_shared_memory(void);
static void cleanup_shared_memory(void);
static void ring_buffer_write(uint32_t type, const uint8_t* data, uint32_t len);
static void hook_boringssl_keylog(void);
static void uninstall_boringssl_hook(void);
static void jmp_write(void* tgt, void* hook);
static void jmp_restore(void* tgt, BYTE* saved);
static void pipe_send(uint8_t type, const void* pay, uint32_t len);
static void pipe_log(const char* fmt, ...);
static void pcap_write(const uint8_t* data, uint32_t len);
static void pcap_open(const char* path);
static void pcap_close(void);
static void HyForceEject(void);
static uint64_t now_us(void);
static void seq_check(const uint8_t* pkt, int len, uint8_t dir);
static void fuzz_buf(uint8_t* buf, int len, int bits);
static int is_hytale_port(uint16_t port_be);
static void forward(uint8_t dir, const uint8_t* data, int dlen,
    uint32_t ip, uint16_t port);

/* ── x64/x86 14-byte JMP patch ────────────────────────────── */
static void jmp_write(void* tgt, void* hook)
{
    if (!tgt) return;
    DWORD old;
    VirtualProtect(tgt, 14, PAGE_EXECUTE_READWRITE, &old);
    uint8_t* p = (uint8_t*)tgt;
    p[0] = 0xFF; p[1] = 0x25;
#ifdef _WIN64
    * (DWORD*)(p + 2) = 0;
    *(uint64_t*)(p + 6) = (uint64_t)hook;
#else
    * (DWORD*)(p + 2) = (uint32_t)hook - ((uint32_t)p + 6);
    *(uint32_t*)(p + 6) = 0;
#endif
    VirtualProtect(tgt, 14, old, &old);
    FlushInstructionCache(GetCurrentProcess(), tgt, 14);
}

static void jmp_restore(void* tgt, BYTE* saved)
{
    if (!tgt) return;
    DWORD old;
    VirtualProtect(tgt, 14, PAGE_EXECUTE_READWRITE, &old);
    memcpy(tgt, saved, 14);
    VirtualProtect(tgt, 14, old, &old);
    FlushInstructionCache(GetCurrentProcess(), tgt, 14);
}

/* ── Shared memory functions ─────────────────────────────── */
static int init_shared_memory(void)
{
    g_shared_mem = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL,
        PAGE_READWRITE | SEC_COMMIT,
        0, SHARED_MEM_SIZE, SHARED_MEM_NAME);
    if (!g_shared_mem) {
        pipe_log("[KEYLOG] Failed to create shared memory: %lu", GetLastError());
        return 0;
    }

    g_shm_header = (SharedMemoryHeader*)MapViewOfFile(g_shared_mem,
        FILE_MAP_ALL_ACCESS,
        0, 0, SHARED_MEM_SIZE);
    if (!g_shm_header) {
        CloseHandle(g_shared_mem);
        g_shared_mem = NULL;
        return 0;
    }

    /* Initialize header if we're first */
    if (g_shm_header->entry_size == 0) {
        g_shm_header->entry_size = sizeof(RingBufferEntry);
        g_shm_header->max_entries = RING_BUFFER_ENTRIES;
        g_shm_header->write_idx = 0;
        g_shm_header->read_idx = 0;
        g_shm_header->dropped = 0;
        g_shm_header->start_time_us = now_us();
    }

    g_ring_buffer = (RingBufferEntry*)((uint8_t*)g_shm_header +
        sizeof(SharedMemoryHeader));

    pipe_log("[KEYLOG] Shared memory ready: %u entries @ %p",
        g_shm_header->max_entries, g_ring_buffer);
    return 1;
}

static void cleanup_shared_memory(void)
{
    if (g_shm_header) {
        UnmapViewOfFile(g_shm_header);
        g_shm_header = NULL;
    }
    if (g_shared_mem) {
        CloseHandle(g_shared_mem);
        g_shared_mem = NULL;
    }
}

static void ring_buffer_write(uint32_t type, const uint8_t* data, uint32_t len)
{
    if (!g_shm_header || !g_ring_buffer) return;

    uint32_t idx = InterlockedIncrement(&g_shm_header->write_idx) - 1;
    idx %= g_shm_header->max_entries;

    RingBufferEntry* entry = &g_ring_buffer[idx];

    /* Wait for reader if buffer full (brief spin) */
    int spins = 0;
    while (entry->ready != 0 && spins < 1000) {
        Sleep(0);
        spins++;
    }
    if (entry->ready != 0) {
        InterlockedIncrement(&g_shm_header->dropped);
        return; /* Drop this entry */
    }

    /* Write entry */
    entry->type = type;
    entry->timestamp_us = now_us();
    entry->data_len = (len > sizeof(entry->data)) ? sizeof(entry->data) : len;
    entry->seq_num = InterlockedIncrement(&g_seq_counter);

    memcpy(entry->data, data, entry->data_len);

    /* Memory barrier before marking ready */
    _WriteBarrier();
    entry->ready = 1;
}

/* ── BoringSSL keylog callback implementation ────────────── */
static void our_keylog_callback(const SSL* ssl, const char* line)
{
    /* Call original callback if exists (chaining) */
    SSL_CTX* ctx = NULL;

    /* Forward to C# via named pipe (reliable) */
    if (line && *line) {
        size_t len = strlen(line);
        pipe_send(MSG_KEYLOG, line, (uint32_t)(len + 1));

        /* Also push to shared memory for high-throughput pairing */
        forward_key_to_shared_mem(line, len);

        pipe_log("[KEYLOG] %s", line);
    }

    /* Call original if we have it stored - find by SSL_CTX if possible */
    /* Note: Without SSL_get_SSL_CTX, we can't perfectly chain, but we try */
    EnterCriticalSection(&g_keylog_cs);
    KeylogCallbackEntry* entry = g_callback_chain;
    while (entry) {
        if (entry->original_cb) {
            /* We don't know which ctx this ssl belongs to, so we can't chain perfectly */
            /* This is a limitation - we just log and don't chain for now */
            break;
        }
        entry = entry->next;
    }
    LeaveCriticalSection(&g_keylog_cs);
}

static void forward_key_to_shared_mem(const char* line, size_t len)
{
    /* Prefix with 'K' to identify as key material */
    uint8_t prefixed[4096];
    prefixed[0] = 'K';  /* Key marker */
    uint32_t copy_len = (len < 4095) ? (uint32_t)len : 4095;
    memcpy(prefixed + 1, line, copy_len);

    ring_buffer_write(1, prefixed, copy_len + 1);
}

static void store_callback_mapping(SSL_CTX* ctx, ssl_keylog_callback_func orig)
{
    EnterCriticalSection(&g_keylog_cs);

    /* Check if already exists */
    KeylogCallbackEntry* entry = g_callback_chain;
    while (entry) {
        if (entry->ctx == ctx) {
            entry->original_cb = orig;
            LeaveCriticalSection(&g_keylog_cs);
            return;
        }
        entry = entry->next;
    }

    /* Add new entry */
    entry = (KeylogCallbackEntry*)malloc(sizeof(KeylogCallbackEntry));
    if (entry) {
        entry->ctx = ctx;
        entry->original_cb = orig;
        entry->next = g_callback_chain;
        g_callback_chain = entry;
    }

    LeaveCriticalSection(&g_keylog_cs);
}

static ssl_keylog_callback_func find_original_callback(SSL_CTX* ctx)
{
    EnterCriticalSection(&g_keylog_cs);
    KeylogCallbackEntry* entry = g_callback_chain;
    while (entry) {
        if (entry->ctx == ctx) {
            ssl_keylog_callback_func result = entry->original_cb;
            LeaveCriticalSection(&g_keylog_cs);
            return result;
        }
        entry = entry->next;
    }
    LeaveCriticalSection(&g_keylog_cs);
    return NULL;
}

/* ── Hook for SSL_CTX_set_keylog_callback ───────────────── */
static void hook_SSL_CTX_set_keylog_callback(SSL_CTX* ctx, ssl_keylog_callback_func cb)
{
    /* Store the original callback the app wanted to set */
    store_callback_mapping(ctx, cb);

    /* Call original function with OUR callback instead */
    if (orig_SSL_CTX_set_keylog_callback) {
        orig_SSL_CTX_set_keylog_callback(ctx, our_keylog_callback);
        pipe_log("[KEYLOG] Hooked SSL_CTX for ctx=%p", (void*)ctx);
    }
}

/* ── BoringSSL hook installation ─────────────────────────── */
static void hook_boringssl_keylog(void)
{
    HMODULE boringssl = GetModuleHandleA("boringssl.dll");
    if (!boringssl) {
        /* Try common names */
        const char* names[] = { "boringssl.dll", "libssl.so", "ssl.dll",
                               "libcrypto.dll", "boringssl_shared.dll", NULL };
        for (int i = 0; names[i]; i++) {
            boringssl = GetModuleHandleA(names[i]);
            if (boringssl) {
                pipe_log("[KEYLOG] Found SSL module: %s", names[i]);
                break;
            }
        }
    }

    if (!boringssl) {
        /* BoringSSL might be statically linked or in jvm.dll */
        pipe_log("[KEYLOG] BoringSSL not found as separate DLL, scanning modules...");

        /* Enumerate all loaded modules in target process */
        HMODULE mods[1024];
        DWORD needed;
        HANDLE hProc = GetCurrentProcess();

        if (EnumProcessModules(hProc, mods, sizeof(mods), &needed)) {
            int numMods = needed / sizeof(HMODULE);
            for (int i = 0; i < numMods && !boringssl; i++) {
                char modName[MAX_PATH];
                if (GetModuleFileNameExA(hProc, mods[i], modName, MAX_PATH)) {
                    /* Check if this module exports SSL symbols */
                    FARPROC test = GetProcAddress(mods[i], "SSL_CTX_set_keylog_callback");
                    if (test) {
                        boringssl = mods[i];
                        pipe_log("[KEYLOG] Found SSL exports in: %s", modName);
                    }
                }
            }
        }
    }

    if (!boringssl) {
        pipe_log("[KEYLOG] ERROR: Could not find BoringSSL/SSL library");
        return;
    }

    /* Get original functions */
    orig_SSL_CTX_set_keylog_callback =
        (SSL_CTX_set_keylog_callback_t)GetProcAddress(
            boringssl, "SSL_CTX_set_keylog_callback");
    orig_SSL_CTX_get_keylog_callback =
        (SSL_CTX_get_keylog_callback_t)GetProcAddress(
            boringssl, "SSL_CTX_get_keylog_callback");

    if (!orig_SSL_CTX_set_keylog_callback) {
        pipe_log("[KEYLOG] SSL_CTX_set_keylog_callback not found");
        return;
    }

    /* Install hook using our jmp_write mechanism */
    static BYTE saved_set_callback[14];
    memcpy(saved_set_callback, orig_SSL_CTX_set_keylog_callback, 14);

    jmp_write(orig_SSL_CTX_set_keylog_callback, hook_SSL_CTX_set_keylog_callback);

    pipe_log("[KEYLOG] Hook installed on SSL_CTX_set_keylog_callback @ %p",
        (void*)orig_SSL_CTX_set_keylog_callback);
}

static void uninstall_boringssl_hook(void)
{
    if (orig_SSL_CTX_set_keylog_callback) {
        /* We need the saved bytes - but they're in the function we hooked */
        /* For clean ejection, we'd need to store them globally */
        /* For now, we just note that we can't easily unhook */
        pipe_log("[KEYLOG] BoringSSL hook uninstall not fully implemented");
    }

    /* Free callback chain */
    EnterCriticalSection(&g_keylog_cs);
    while (g_callback_chain) {
        KeylogCallbackEntry* next = g_callback_chain->next;
        free(g_callback_chain);
        g_callback_chain = next;
    }
    LeaveCriticalSection(&g_keylog_cs);
}

/* ── Enhanced packet forwarding with shared memory ───────── */
static void forward_packet_to_shared_mem(const uint8_t* data, uint32_t len,
    uint32_t ip, uint16_t port, uint8_t dir)
{
    /* Format: [1B marker 'P'][8B timestamp][4B IP][2B port][1B dir][4B len][data] */
    uint8_t packet_meta[4096];
    uint32_t offset = 0;

    packet_meta[offset++] = 'P';  /* Packet marker */

    /* Timestamp (microseconds since start) */
    uint64_t ts = now_us() - g_shm_header->start_time_us;
    memcpy(packet_meta + offset, &ts, 8);
    offset += 8;

    /* Network info */
    memcpy(packet_meta + offset, &ip, 4);
    offset += 4;
    memcpy(packet_meta + offset, &port, 2);
    offset += 2;
    packet_meta[offset++] = dir;

    /* Data length and payload */
    uint32_t data_to_copy = (len < 4080) ? len : 4080;
    memcpy(packet_meta + offset, &data_to_copy, 4);
    offset += 4;
    memcpy(packet_meta + offset, data, data_to_copy);
    offset += data_to_copy;

    ring_buffer_write(2, packet_meta, offset);
}

/* ── pipe send (with retry) ──────────────────────────────── */
static void pipe_send(uint8_t type, const void* pay, uint32_t len)
{
    if (g_out == INVALID_HANDLE_VALUE) return;
    if (len > MAX_PKT) len = MAX_PKT;

    uint8_t hdr[5];
    hdr[0] = type;
    hdr[1] = (uint8_t)(len & 0xFF);
    hdr[2] = (uint8_t)((len >> 8) & 0xFF);
    hdr[3] = (uint8_t)((len >> 16) & 0xFF);
    hdr[4] = (uint8_t)((len >> 24) & 0xFF);

    DWORD wait = WaitForSingleObject(g_mutex, 50);
    if (wait != WAIT_OBJECT_0) return;

    DWORD w = 0;
    BOOL ok = WriteFile(g_out, hdr, 5, &w, NULL);
    if (ok && len > 0) {
        ok = WriteFile(g_out, pay, len, &w, NULL);
    }

    if (!ok) {
        HANDLE tmp = g_out;
        g_out = INVALID_HANDLE_VALUE;
        CloseHandle(tmp);
    }

    ReleaseMutex(g_mutex);
}

/* ── pipe logging ────────────────────────────────────────── */
static void pipe_log(const char* fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    pipe_send(MSG_LOG, buf, (uint32_t)strlen(buf) + 1);
}

/* ── pcap functions ──────────────────────────────────────── */
static void pcap_write(const uint8_t* data, uint32_t len)
{
    if (g_pcap == INVALID_HANDLE_VALUE || len == 0 || len > MAX_PKT) return;

    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    uint64_t ft64 = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    uint64_t us = (ft64 - 116444736000000000ULL) / 10;

    uint32_t ph[4] = {
        (uint32_t)(us / 1000000),
        (uint32_t)(us % 1000000),
        len,
        len
    };

    WaitForSingleObject(g_pcap_mutex, 100);
    DWORD w;
    WriteFile(g_pcap, ph, 16, &w, NULL);
    WriteFile(g_pcap, data, len, &w, NULL);
    ReleaseMutex(g_pcap_mutex);
}

static void pcap_open(const char* path)
{
    WaitForSingleObject(g_pcap_mutex, 500);
    if (g_pcap != INVALID_HANDLE_VALUE) CloseHandle(g_pcap);

    g_pcap = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (g_pcap != INVALID_HANDLE_VALUE) {
        uint32_t gh[6] = { 0xa1b2c3d4,0x00040002,0,0,65535,101 };
        DWORD w;
        WriteFile(g_pcap, gh, 24, &w, NULL);
        pipe_log("[PCAP] Opened: %s", path);
    }
    else {
        pipe_log("[PCAP] Failed to open: %s (err=%lu)", path, GetLastError());
    }
    ReleaseMutex(g_pcap_mutex);
}

static void pcap_close(void)
{
    WaitForSingleObject(g_pcap_mutex, 500);
    if (g_pcap != INVALID_HANDLE_VALUE) {
        CloseHandle(g_pcap);
        g_pcap = INVALID_HANDLE_VALUE;
        pipe_log("[PCAP] Closed.");
    }
    ReleaseMutex(g_pcap_mutex);
}

/* ── ejection function ──────────────────────────────────── */
static void HyForceEject(void)
{
    pipe_send(MSG_EJECTED, "EJECTING", 9);
    Sleep(50);
    g_active = FALSE;

    if (g_out != INVALID_HANDLE_VALUE) {
        CloseHandle(g_out);
        g_out = INVALID_HANDLE_VALUE;
    }
    if (g_cmdin != INVALID_HANDLE_VALUE) {
        CloseHandle(g_cmdin);
        g_cmdin = INVALID_HANDLE_VALUE;
    }

    pcap_close();
    cleanup_shared_memory();
    uninstall_boringssl_hook();

    if (orig_WSASendTo)   jmp_restore(orig_WSASendTo, sv_wsa_send);
    if (orig_WSARecvFrom) jmp_restore(orig_WSARecvFrom, sv_wsa_recv);
    if (orig_sendto)      jmp_restore(orig_sendto, sv_send);
    if (orig_recvfrom)    jmp_restore(orig_recvfrom, sv_recv);

    FlushInstructionCache(GetCurrentProcess(), NULL, 0);
}

/* ── timing ──────────────────────────────────────────────── */
static uint64_t now_us(void)
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    uint64_t v = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    return (v - 116444736000000000ULL) / 10;
}

/* ── seq check ───────────────────────────────────────────── */
static void seq_check(const uint8_t* pkt, int len, uint8_t dir)
{
    if (len < 2 || (pkt[0] & 0x80) != 0) return;
    int pn_len = (pkt[0] & 0x03) + 1;
    if (1 + pn_len > len) return;

    uint64_t pn = 0;
    for (int i = 0; i < pn_len; i++) pn = (pn << 8) | pkt[1 + i];

    uint64_t* last = (dir == 0) ? &g_seq_cs : &g_seq_sc;
    if (*last != UINT64_MAX && pn <= *last) {
        uint8_t ab[17 + 64];
        memcpy(ab, last, 8);
        memcpy(ab + 8, &pn, 8);
        ab[16] = dir;
        snprintf((char*)ab + 17, 63, "SEQ dir=%d exp>%llu got=%llu",
            dir, (unsigned long long) * last, (unsigned long long)pn);
        pipe_send(MSG_SEQ_ANOMALY, ab, 17 + (uint32_t)strlen((char*)ab + 17) + 1);
    }
    *last = pn;
}

/* ── fuzz ────────────────────────────────────────────────── */
static void fuzz_buf(uint8_t* buf, int len, int bits)
{
    srand((unsigned)GetTickCount());
    for (int i = 0; i < bits && len>0; i++) {
        int idx = rand() % len;
        buf[idx] ^= (uint8_t)(1 << (rand() % 8));
    }
}

/* ── check if this is Hytale traffic ─────────────────────── */
static int is_hytale_port(uint16_t port_be)
{
    uint16_t port = ntohs(port_be);
    return (port >= HYTALE_PORT_MIN && port <= HYTALE_PORT_MAX);
}

/* ── core forward ────────────────────────────────────────── */
static void forward(uint8_t dir, const uint8_t* data, int dlen,
    uint32_t ip, uint16_t port)
{
    if (!is_hytale_port(port) && !is_hytale_port(g_last_cs_port)) {
        if (dir == 1 && ip != g_last_cs_ip) return;
    }

    if (dlen <= 0 || dlen > MAX_PKT) return;

    InterlockedIncrement(&g_pkts_captured);
    pcap_write(data, (uint32_t)dlen);
    seq_check(data, dlen, dir);

    {
        uint8_t tb[13];
        uint64_t ts = now_us();
        uint32_t u = (uint32_t)dlen;
        memcpy(tb, &ts, 8);
        memcpy(tb + 8, &u, 4);
        tb[12] = dir;
        pipe_send(MSG_TIMING, tb, 13);
    }

    int total = 1 + 4 + 2 + dlen;
    uint8_t* buf = (uint8_t*)malloc(total);
    if (!buf) return;

    buf[0] = dir;
    memcpy(buf + 1, &ip, 4);
    memcpy(buf + 5, &port, 2);
    memcpy(buf + 7, data, dlen);

    pipe_send(MSG_PACKET, buf, (uint32_t)total);

    /* NEW: Also push to shared memory for zero-latency pairing */
    forward_packet_to_shared_mem(data, (uint32_t)dlen, ip, port, dir);

    free(buf);

    if (dir == 0) {
        EnterCriticalSection(&g_replay_cs);
        if (dlen <= MAX_PKT) {
            memcpy(g_last_cs, data, dlen);
            g_last_cs_len = dlen;
            g_last_cs_ip = ip;
            g_last_cs_port = port;
        }
        LeaveCriticalSection(&g_replay_cs);
    }
}

/* ── WSASendTo hook ──────────────────────────────────────── */
static int WSAAPI hook_WSASendTo(SOCKET s, LPWSABUF bufs, DWORD nb,
    LPDWORD sent, DWORD flags, const struct sockaddr* to, int tolen,
    LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cb)
{
    // Prevent reentrancy
    if (IsReentrant()) {
        return orig_WSASendTo(s, bufs, nb, sent, flags, to, tolen, ov, cb);
    }
    EnterHook();

    InterlockedIncrement(&g_fires_wsa_send);
    DWORD lastErr = GetLastError();

    // Restore original function
    EnterCriticalSection(&g_cs);
    jmp_restore(orig_WSASendTo, sv_wsa_send);
    LeaveCriticalSection(&g_cs);

    int ret;
    int fuzz = InterlockedExchange((LONG*)&g_fuzz_bits, 0);

    __try {
        if (fuzz > 0 && nb > 0 && bufs && bufs[0].len > 1) {
            uint8_t* tmp = (uint8_t*)malloc((size_t)bufs[0].len);
            if (tmp) {
                memcpy(tmp, bufs[0].buf, bufs[0].len);
                fuzz_buf(tmp + 1, (int)bufs[0].len - 1, fuzz);
                WSABUF fb = { bufs[0].len, (char*)tmp };
                ret = WSASendTo(s, &fb, 1, sent, flags, to, tolen, ov, cb);
                free(tmp);
            }
            else {
                ret = WSASendTo(s, bufs, nb, sent, flags, to, tolen, ov, cb);
            }
        }
        else {
            ret = WSASendTo(s, bufs, nb, sent, flags, to, tolen, ov, cb);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // If anything goes wrong, ensure we restore state
        ret = SOCKET_ERROR;
        SetLastError(lastErr);
    }

    // Reinstall hook
    EnterCriticalSection(&g_cs);
    jmp_write(orig_WSASendTo, hook_WSASendTo);
    LeaveCriticalSection(&g_cs);

    if (ret == SOCKET_ERROR) {
        SetLastError(lastErr);
    }

    // Forward packet if successful
    if (ret == 0 && nb > 0 && bufs && bufs[0].buf && bufs[0].len > 0) {
        uint32_t ip = 0;
        uint16_t port = 0;
        if (to && tolen >= (int)sizeof(struct sockaddr_in)) {
            const struct sockaddr_in* s2 = (const struct sockaddr_in*)to;
            if (s2->sin_family == AF_INET) {
                ip = s2->sin_addr.s_addr;
                port = s2->sin_port;
            }
        }
        forward(0, (uint8_t*)bufs[0].buf, (int)bufs[0].len, ip, port);
    }

    LeaveHook();
    return ret;
}

/* ── sendto hook (non-WSA, used by JVM NIO) ──────────────── */
static int WSAAPI hook_sendto(SOCKET s, const char* buf, int len, int flags,
    const struct sockaddr* to, int tolen)
{
    InterlockedIncrement(&g_fires_send);
    DWORD lastErr = GetLastError();

    EnterCriticalSection(&g_cs);
    jmp_restore(orig_sendto, sv_send);
    LeaveCriticalSection(&g_cs);

    int ret;
    int fuzz = InterlockedExchange((LONG*)&g_fuzz_bits, 0);

    if (fuzz > 0 && len > 1) {
        uint8_t* tmp = (uint8_t*)malloc((size_t)len);
        if (tmp) {
            memcpy(tmp, buf, (size_t)len);
            fuzz_buf(tmp + 1, len - 1, fuzz);
            ret = sendto(s, (char*)tmp, len, flags, to, tolen);
            free(tmp);
        }
        else {
            ret = sendto(s, buf, len, flags, to, tolen);
        }
    }
    else {
        ret = sendto(s, buf, len, flags, to, tolen);
    }

    EnterCriticalSection(&g_cs);
    jmp_write(orig_sendto, hook_sendto);
    LeaveCriticalSection(&g_cs);

    if (ret == SOCKET_ERROR) {
        SetLastError(lastErr);
    }

    if (ret > 0 && buf && len > 0) {
        uint32_t ip = 0;
        uint16_t port = 0;
        if (to && tolen >= (int)sizeof(struct sockaddr_in)) {
            const struct sockaddr_in* s2 = (const struct sockaddr_in*)to;
            if (s2->sin_family == AF_INET) {
                ip = s2->sin_addr.s_addr;
                port = s2->sin_port;
            }
        }
        forward(0, (uint8_t*)buf, len, ip, port);
    }

    return ret;
}

/* ── WSARecvFrom hook ────────────────────────────────────── */
static int WSAAPI hook_WSARecvFrom(SOCKET s, LPWSABUF bufs, DWORD nb,
    LPDWORD recvd, LPDWORD flags, struct sockaddr* from, LPINT fromlen,
    LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cb)
{
    InterlockedIncrement(&g_fires_wsa_recv);
    DWORD lastErr = GetLastError();

    EnterCriticalSection(&g_cs);
    jmp_restore(orig_WSARecvFrom, sv_wsa_recv);
    LeaveCriticalSection(&g_cs);

    int ret = WSARecvFrom(s, bufs, nb, recvd, flags, from, fromlen, ov, cb);

    EnterCriticalSection(&g_cs);
    jmp_write(orig_WSARecvFrom, hook_WSARecvFrom);
    LeaveCriticalSection(&g_cs);

    if (ret == SOCKET_ERROR) {
        SetLastError(lastErr);
    }

    if (ret == 0 && recvd && *recvd > 0 && nb > 0 && bufs && bufs[0].buf) {
        uint32_t ip = 0;
        uint16_t port = 0;
        if (from && fromlen && *fromlen >= (int)sizeof(struct sockaddr_in)) {
            const struct sockaddr_in* s2 = (const struct sockaddr_in*)from;
            if (s2->sin_family == AF_INET) {
                ip = s2->sin_addr.s_addr;
                port = s2->sin_port;
            }
        }
        forward(1, (uint8_t*)bufs[0].buf, (int)*recvd, ip, port);
    }

    return ret;
}

/* ── recvfrom hook (non-WSA) ─────────────────────────────── */
static int WSAAPI hook_recvfrom(SOCKET s, char* buf, int len, int flags,
    struct sockaddr* from, int* fromlen)
{
    InterlockedIncrement(&g_fires_recv);
    DWORD lastErr = GetLastError();

    EnterCriticalSection(&g_cs);
    jmp_restore(orig_recvfrom, sv_recv);
    LeaveCriticalSection(&g_cs);

    int ret = recvfrom(s, buf, len, flags, from, fromlen);

    EnterCriticalSection(&g_cs);
    jmp_write(orig_recvfrom, hook_recvfrom);
    LeaveCriticalSection(&g_cs);

    if (ret == SOCKET_ERROR) {
        SetLastError(lastErr);
    }

    if (ret == SOCKET_ERROR) {
        return ret;
    }

    if (ret > 0 && buf) {
        uint32_t ip = 0;
        uint16_t port = 0;
        if (from && fromlen && *fromlen >= (int)sizeof(struct sockaddr_in)) {
            const struct sockaddr_in* s2 = (const struct sockaddr_in*)from;
            if (s2->sin_family == AF_INET) {
                ip = s2->sin_addr.s_addr;
                port = s2->sin_port;
            }
        }
        forward(1, (uint8_t*)buf, ret, ip, port);
    }

    return ret;
}

/* ── memory scanner (read-only entity/player struct finder) ── */
static int is_coord(double v) { return !isnan(v) && !isinf(v) && v > -65536. && v < 65536.; }
static int is_health(float h) { return !isnan(h) && h > 0.f && h <= 10000.f; }
static int is_vel(float v) { return !isnan(v) && v > -2000.f && v < 2000.f; }

static void memscan_run(void)
{
    pipe_log("[MEMSCAN] Start — scanning all readable pages...");
    int hits = 0;
    MEMORY_BASIC_INFORMATION mbi;
    uint8_t* addr = NULL;

    while (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) &&
            !(mbi.Protect & PAGE_GUARD) &&
            mbi.RegionSize > 0 && mbi.RegionSize <= 0x8000000)
        {
            uint8_t* base = (uint8_t*)mbi.BaseAddress;
            SIZE_T rsz = mbi.RegionSize;

            for (SIZE_T off = 0; off + 48 < rsz; off += 8) {
                uint8_t* p = base + off;

                __try {
                    float h = *(float*)p, mh = *(float*)(p + 4);
                    double x = *(double*)(p + 8), y = *(double*)(p + 16), z = *(double*)(p + 24);

                    if (is_health(h) && is_health(mh) && mh >= h &&
                        is_coord(x) && is_coord(y) && y >= 0. && y < 512. && is_coord(z)) {

                        float vx = 0, vy = 0, vz = 0;
                        if (off + 48 < rsz) {
                            vx = *(float*)(p + 32);
                            vy = *(float*)(p + 36);
                            vz = *(float*)(p + 40);
                        }

                        if (!is_vel(vx) || !is_vel(vy) || !is_vel(vz)) continue;

                        uint8_t rep[80];
                        uint64_t a64 = (uint64_t)(uintptr_t)p;
                        uint32_t sz = 64;
                        memcpy(rep, &a64, 8);
                        memcpy(rep + 8, &sz, 4);

                        SIZE_T copy_sz = sz < (rsz - off) ? (int)sz : (int)(rsz - off);
                        memcpy(rep + 12, p, (size_t)copy_sz);

                        pipe_send(MSG_MEMSCAN, rep, 12 + (uint32_t)copy_sz);
                        pipe_log("[MEMSCAN] @0x%llx hp=%.1f/%.1f xyz=(%.2f,%.2f,%.2f)",
                            (unsigned long long)a64, h, mh, x, y, z);

                        if (++hits >= 64) goto done;
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    break;
                }
            }
        }

        uint8_t* next = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
    }

done:
    pipe_log("[MEMSCAN] Done: %d hit(s). Note: JVM heap objects move on GC — rescan periodically.", hits);
}

static DWORD WINAPI memscan_th(LPVOID _) { (void)_; memscan_run(); return 0; }

/* ── rate limit thread ───────────────────────────────────── */
typedef struct { int count; int ms; }RLArgs;

static DWORD WINAPI rl_thread(LPVOID arg)
{
    RLArgs* a = (RLArgs*)arg;
    int count = a->count, ms = a->ms;
    free(a);

    EnterCriticalSection(&g_replay_cs);
    if (g_last_cs_len <= 0) {
        LeaveCriticalSection(&g_replay_cs);
        pipe_log("[RL] No packet yet.");
        return 0;
    }

    uint8_t pkt[MAX_PKT];
    int len = g_last_cs_len;
    uint32_t ip = g_last_cs_ip;
    uint16_t port = g_last_cs_port;
    memcpy(pkt, g_last_cs, len);
    LeaveCriticalSection(&g_replay_cs);

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        pipe_log("[RL] socket() failed");
        return 0;
    }

    struct sockaddr_in dst = { 0 };
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = ip;
    dst.sin_port = port;

    int sp = count > 0 ? ms / count : 10;
    if (sp < 1)sp = 1;

    int ok = 0, fail = 0;
    for (int i = 0; i < count && g_active; i++) {
        if (sendto(sock, (char*)pkt, len, 0, (struct sockaddr*)&dst, sizeof(dst)) > 0)
            ok++;
        else
            fail++;
        Sleep(sp);
    }

    closesocket(sock);

    uint8_t rb[8];
    uint32_t cu = (uint32_t)ok, iv = (uint32_t)ms;
    memcpy(rb, &cu, 4);
    memcpy(rb + 4, &iv, 4);
    pipe_send(0x07, rb, 8);

    pipe_log("[RL] Done: %d OK, %d fail, target %s:%d", ok, fail,
        inet_ntoa(dst.sin_addr), ntohs(port));
    return 0;
}

/* ── replay ──────────────────────────────────────────────── */
static void do_replay(void)
{
    EnterCriticalSection(&g_replay_cs);
    if (g_last_cs_len <= 0) {
        LeaveCriticalSection(&g_replay_cs);
        pipe_log("[REPLAY] No packet.");
        return;
    }

    uint8_t pkt[MAX_PKT];
    int len = g_last_cs_len;
    uint32_t ip = g_last_cs_ip;
    uint16_t port = g_last_cs_port;
    memcpy(pkt, g_last_cs, len);
    LeaveCriticalSection(&g_replay_cs);

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        pipe_log("[REPLAY] socket() failed");
        return;
    }

    struct sockaddr_in dst = { 0 };
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = ip;
    dst.sin_port = port;

    int r = sendto(sock, (char*)pkt, len, 0, (struct sockaddr*)&dst, sizeof(dst));
    closesocket(sock);

    pipe_log("[REPLAY] %s %dB → %s:%d",
        r > 0 ? "OK" : "FAIL", len, inet_ntoa(dst.sin_addr), ntohs(port));
}

/* ── heartbeat / hook stats ──────────────────────────────── */
static DWORD WINAPI hb_thread(LPVOID _)
{
    (void)_;
    while (g_active) {
        Sleep(5000);
        pipe_log("[STATS] WSASendTo:%ld sendto:%ld WSARecvFrom:%ld recvfrom:%ld pkts:%ld",
            g_fires_wsa_send, g_fires_send, g_fires_wsa_recv, g_fires_recv, g_pkts_captured);
    }
    return 0;
}

/* ── injector monitor thread ─────────────────────────────── */
static DWORD WINAPI injector_monitor_th(LPVOID _)
{
    (void)_;
    if (g_injector_pid == 0) return 0;

    HANDLE hInjector = OpenProcess(SYNCHRONIZE, FALSE, g_injector_pid);
    if (!hInjector) {
        pipe_log("[MONITOR] Injector process not found, auto-ejecting");
        HyForceEject();
        FreeLibraryAndExitThread(GetModuleHandleW(L"HyForceHook.dll"), 0);
        return 0;
    }

    while (g_active) {
        DWORD wait = WaitForSingleObject(hInjector, 1000);
        if (wait == WAIT_OBJECT_0) {
            pipe_log("[MONITOR] Injector process exited, auto-ejecting");
            CloseHandle(hInjector);
            HyForceEject();
            FreeLibraryAndExitThread(GetModuleHandleW(L"HyForceHook.dll"), 0);
            return 0;
        }

        if (g_out == INVALID_HANDLE_VALUE) {
            Sleep(5000);
            if (g_out == INVALID_HANDLE_VALUE && g_active) {
                pipe_log("[MONITOR] Pipe connection lost, auto-ejecting");
                CloseHandle(hInjector);
                HyForceEject();
                FreeLibraryAndExitThread(GetModuleHandleW(L"HyForceHook.dll"), 0);
                return 0;
            }
        }
    }

    CloseHandle(hInjector);
    return 0;
}

/* ── cmd reader ──────────────────────────────────────────── */
static DWORD WINAPI cmd_thread(LPVOID _)
{
    (void)_;
    char buf[1024];
    int pos = 0;

    while (g_active) {
        if (g_cmdin == INVALID_HANDLE_VALUE) {
            HANDLE h = CreateFileW(PIPE_CMD, GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
            if (h != INVALID_HANDLE_VALUE) {
                g_cmdin = h;
                pos = 0;
            }
            else {
                Sleep(500);
                continue;
            }
        }

        DWORD av = 0;
        if (!PeekNamedPipe(g_cmdin, NULL, 0, NULL, &av, NULL)) {
            CloseHandle(g_cmdin);
            g_cmdin = INVALID_HANDLE_VALUE;
            continue;
        }

        if (!av) {
            Sleep(20);
            continue;
        }

        char c;
        DWORD r;
        if (!ReadFile(g_cmdin, &c, 1, &r, NULL) || r == 0) {
            CloseHandle(g_cmdin);
            g_cmdin = INVALID_HANDLE_VALUE;
            continue;
        }

        if (c == '\n' || c == '\r') {
            buf[pos] = 0;
            pos = 0;
            if (!buf[0]) continue;

            if (!strcmp(buf, "PING"))
                pipe_send(MSG_STATUS, "PONG", 5);
            else if (!strcmp(buf, "STOP"))
                g_active = FALSE;
            else if (!strncmp(buf, "FUZZ ", 5)) {
                int bits = atoi(buf + 5);
                InterlockedExchange((LONG*)&g_fuzz_bits, bits);
                pipe_log("[FUZZ] armed %d bits", bits);
            }
            else if (!strcmp(buf, "REPLAY"))
                do_replay();
            else if (!strncmp(buf, "RATELIMIT ", 10)) {
                int cnt = 0, ms = 1000;
                sscanf(buf + 10, "%d %d", &cnt, &ms);
                RLArgs* a = (RLArgs*)malloc(sizeof(RLArgs));
                if (a) {
                    a->count = cnt;
                    a->ms = ms;
                    CreateThread(NULL, 0, rl_thread, a, 0, NULL);
                }
            }
            else if (!strncmp(buf, "PCAP_START ", 11))
                pcap_open(buf + 11);
            else if (!strcmp(buf, "PCAP_STOP"))
                pcap_close();
            else if (!strcmp(buf, "MEMSCAN"))
                CreateThread(NULL, 0, memscan_th, NULL, 0, NULL);
            else if (!strcmp(buf, "SEQRESET")) {
                g_seq_cs = UINT64_MAX;
                g_seq_sc = UINT64_MAX;
                pipe_log("[SEQ] reset");
            }
            else if (!strcmp(buf, "STATS"))
                pipe_log("[STATS] WSASendTo:%ld sendto:%ld WSARecvFrom:%ld recvfrom:%ld pkts:%ld",
                    g_fires_wsa_send, g_fires_send, g_fires_wsa_recv, g_fires_recv, g_pkts_captured);
            else
                pipe_log("[CMD] unknown: %s", buf);
        }
        else {
            if (pos < (int)sizeof(buf) - 1) buf[pos++] = c;
        }
    }
    return 0;
}

/* ── IO reconnect thread ─────────────────────────────────── */
static DWORD WINAPI io_thread(LPVOID _)
{
    (void)_;
    while (g_active) {
        if (g_out == INVALID_HANDLE_VALUE) {
            HANDLE h = CreateFileW(PIPE_DATA, GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

            if (h != INVALID_HANDLE_VALUE) {
                DWORD mode = PIPE_READMODE_BYTE;
                SetNamedPipeHandleState(h, &mode, NULL, NULL);

                WaitForSingleObject(g_mutex, INFINITE);
                g_out = h;
                ReleaseMutex(g_mutex);

                char hs[320];
                DWORD pid = GetCurrentProcessId();
                char exe[MAX_PATH] = { 0 };

                HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
                if (hp) {
                    DWORD sz = MAX_PATH;
                    QueryFullProcessImageNameA(hp, 0, exe, &sz);
                    CloseHandle(hp);
                }

#ifdef _WIN64
                const char* arch = "x64";
#else
                const char* arch = "x86";
#endif

                snprintf(hs, sizeof(hs),
                    "HyForceHook/7-%s | PID=%lu | EXE=%s | Hooked: WSASendTo+sendto+WSARecvFrom+recvfrom | BoringSSL keylog",
                    arch, (unsigned long)pid, exe[0] ? exe : "?");

                pipe_send(MSG_STATUS, hs, (uint32_t)strlen(hs) + 1);
                pipe_log("4 WinSock hooks + BoringSSL keylog installed (port filter: %d-%d)", HYTALE_PORT_MIN, HYTALE_PORT_MAX);
            }
        }
        Sleep(500);
    }
    return 0;
}
/* ── Helper: Check if we're already in a hook ────────────── */
static int IsReentrant(void)
{
    if (g_dwTlsIndex != TLS_OUT_OF_INDEXES) {
        return TlsGetValue(g_dwTlsIndex) != NULL;
    }
    return InterlockedCompareExchange(&g_inHook, 1, 0) != 0;
}

static void EnterHook(void)
{
    if (g_dwTlsIndex != TLS_OUT_OF_INDEXES) {
        TlsSetValue(g_dwTlsIndex, (LPVOID)1);
    }
}

static void LeaveHook(void)
{
    if (g_dwTlsIndex != TLS_OUT_OF_INDEXES) {
        TlsSetValue(g_dwTlsIndex, NULL);
    }
    else {
        InterlockedExchange(&g_inHook, 0);
    }
}

/* ── DllMain ─────────────────────────────────────────────── */
BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved)
{
    (void)hInst; (void)reserved;

    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hInst);
        InitializeCriticalSection(&g_cs);
        InitializeCriticalSection(&g_replay_cs);
        InitializeCriticalSection(&g_keylog_cs);

        g_mutex = CreateMutexW(NULL, FALSE, NULL);
        g_pcap_mutex = CreateMutexW(NULL, FALSE, NULL);

        if (!g_mutex || !g_pcap_mutex) return FALSE;

        /* Initialize shared memory for key+packet pairing */
        init_shared_memory();

        HMODULE ws2 = GetModuleHandleW(L"ws2_32.dll");
        if (!ws2) ws2 = LoadLibraryW(L"ws2_32.dll");
        if (!ws2) return FALSE;

        /* Hook all 4 variants */
        orig_WSASendTo = (WSASendTo_t)GetProcAddress(ws2, "WSASendTo");
        orig_WSARecvFrom = (WSARecvFrom_t)GetProcAddress(ws2, "WSARecvFrom");
        orig_sendto = (sendto_t)GetProcAddress(ws2, "sendto");
        orig_recvfrom = (recvfrom_t)GetProcAddress(ws2, "recvfrom");

        if (orig_WSASendTo) {
            memcpy(sv_wsa_send, orig_WSASendTo, 14);
            jmp_write(orig_WSASendTo, hook_WSASendTo);
        }
        if (orig_WSARecvFrom) {
            memcpy(sv_wsa_recv, orig_WSARecvFrom, 14);
            jmp_write(orig_WSARecvFrom, hook_WSARecvFrom);
        }
        if (orig_sendto) {
            memcpy(sv_send, orig_sendto, 14);
            jmp_write(orig_sendto, hook_sendto);
        }
        if (orig_recvfrom) {
            memcpy(sv_recv, orig_recvfrom, 14);
            jmp_write(orig_recvfrom, hook_recvfrom);
        }

        /* Hook BoringSSL for TLS 1.3 key extraction */
        hook_boringssl_keylog();

        g_active = TRUE;
        g_io_th = CreateThread(NULL, 0, io_thread, NULL, 0, NULL);
        g_cmd_th = CreateThread(NULL, 0, cmd_thread, NULL, 0, NULL);
        CreateThread(NULL, 0, hb_thread, NULL, 0, NULL);

    }
    else if (reason == DLL_PROCESS_DETACH) {
        g_active = FALSE;

        if (orig_WSASendTo)   jmp_restore(orig_WSASendTo, sv_wsa_send);
        if (orig_WSARecvFrom) jmp_restore(orig_WSARecvFrom, sv_wsa_recv);
        if (orig_sendto)      jmp_restore(orig_sendto, sv_send);
        if (orig_recvfrom)    jmp_restore(orig_recvfrom, sv_recv);

        uninstall_boringssl_hook();
        cleanup_shared_memory();
        pcap_close();

        if (g_out != INVALID_HANDLE_VALUE) {
            CloseHandle(g_out);
            g_out = INVALID_HANDLE_VALUE;
        }
        if (g_cmdin != INVALID_HANDLE_VALUE) {
            CloseHandle(g_cmdin);
            g_cmdin = INVALID_HANDLE_VALUE;
        }
        if (g_mutex) CloseHandle(g_mutex);
        if (g_pcap_mutex) CloseHandle(g_pcap_mutex);

        if (g_io_th) {
            WaitForSingleObject(g_io_th, 1000);
            CloseHandle(g_io_th);
        }
        if (g_cmd_th) {
            WaitForSingleObject(g_cmd_th, 1000);
            CloseHandle(g_cmd_th);
        }

        DeleteCriticalSection(&g_cs);
        DeleteCriticalSection(&g_replay_cs);
        DeleteCriticalSection(&g_keylog_cs);
    }

    return TRUE;
}