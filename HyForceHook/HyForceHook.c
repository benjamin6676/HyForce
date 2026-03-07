/*
 * HyForceHook.dll  v9  —  HyForce Security Research Engine
 *
 * Build x64 MSVC:
 *   cl /O2 /LD /D_WIN32_WINNT=0x0A00 HyForceHook.c /Fe:HyForceHook.dll ws2_32.lib psapi.lib iphlpapi.lib advapi32.lib
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <psapi.h>
#include <tlhelp32.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")

 /* ── Message types ───────────────────────────────────────── */
#define MSG_PACKET      0x01
#define MSG_STATUS      0x02
#define MSG_LOG         0x03
#define MSG_TIMING      0x04
#define MSG_SEQ_ANOMALY 0x05
#define MSG_MEMSCAN     0x06
#define MSG_RATELIMIT   0x07
#define MSG_EJECTED     0x08
#define MSG_KEYLOG      0x09
#define MSG_MEMWATCH    0x0B
#define MSG_STRINGSCAN  0x10
#define MSG_MODINFO     0x11
#define MSG_GADGET      0x12
#define MSG_EXPLOIT     0x13
#define MSG_PROCDUMP    0x14

/* ── Pipe names ──────────────────────────────────────────── */
#define PIPE_DATA  L"\\\\.\\pipe\\HyForcePipe"
#define PIPE_CMD   L"\\\\.\\pipe\\HyForceCmdPipe"
#define MAX_PKT    65535

/* ── Port filter ─────────────────────────────────────────── */
#define HYTALE_PORT_MIN 5520
#define HYTALE_PORT_MAX 5560

/* ── Shared memory ───────────────────────────────────────── */
#define SHM_NAME            L"HyForceSharedMem"
#define SHM_SIZE            (16*1024*1024)
#define SHM_RING_ENTRIES    4096

/* ── BoringSSL types ─────────────────────────────────────── */
typedef struct ssl_st     SSL;
typedef struct ssl_ctx_st SSL_CTX;
typedef void (*ssl_keylog_cb_t)(const SSL*, const char*);
typedef void (*SSL_set_kl_t)(SSL_CTX*, ssl_keylog_cb_t);
typedef ssl_keylog_cb_t(*SSL_get_kl_t)(const SSL_CTX*);

/* ── Ring buffer ─────────────────────────────────────────── */
typedef struct {
    volatile uint32_t ready;
    uint32_t type;
    uint64_t ts_us;
    uint32_t data_len;
    uint32_t seq;
    uint8_t  data[4080];
} RingEntry;

typedef struct {
    volatile uint32_t write_idx, read_idx, dropped;
    uint32_t entry_size, max_entries;
    uint64_t start_us;
} ShmHeader;

/* ── BoringSSL callback chain ────────────────────────────── */
typedef struct KE_s { SSL_CTX* ctx; ssl_keylog_cb_t orig; struct KE_s* next; } KE;

/* ── IOCP / overlapped tracking ─────────────────────────── */
#define MAX_OVL 512
typedef struct {
    LPOVERLAPPED         ov;
    char* buf;
    int                  bufsz;
    struct sockaddr_in   peer;
    volatile int         used;
} OvlEntry;

/* ── Globals ─────────────────────────────────────────────── */
static SSL_set_kl_t  g_ssl_set = NULL;
static SSL_get_kl_t  g_ssl_get = NULL;
static KE* g_kchain = NULL;
static CRITICAL_SECTION g_kcs;
static char  g_kring[32][256];
static int   g_kring_head = 0;
static BYTE  sv_ssl[14];

static HANDLE   g_shm_h = NULL;
static ShmHeader* g_shm = NULL;
static RingEntry* g_ring = NULL;
static uint32_t  g_seq = 0;

static HANDLE   g_out = INVALID_HANDLE_VALUE;
static HANDLE   g_cmdin = INVALID_HANDLE_VALUE;
static HANDLE   g_mutex = NULL;
static volatile BOOL g_active = FALSE;
static HANDLE   g_io_th = NULL;
static HANDLE   g_cmd_th = NULL;
static CRITICAL_SECTION g_cs;

static DWORD g_tls_idx = TLS_OUT_OF_INDEXES;

static HANDLE g_pcap = INVALID_HANDLE_VALUE;
static HANDLE g_pcap_mutex = NULL;

static volatile int g_fuzz_bits = 0;
static uint8_t  g_last_cs[MAX_PKT];
static int      g_last_cs_len = 0;
static uint32_t g_last_cs_ip = 0;
static uint16_t g_last_cs_port = 0;
static CRITICAL_SECTION g_replay_cs;

static uint64_t g_seq_cs = UINT64_MAX;
static uint64_t g_seq_sc = UINT64_MAX;

static volatile LONG g_fires_wsa_send = 0, g_fires_send = 0;
static volatile LONG g_fires_wsa_recv = 0, g_fires_recv = 0;
static volatile LONG g_pkts_captured = 0;

static volatile uint64_t g_watch_addr = 0;
static volatile int      g_watch_ms = 0;
static HANDLE            g_watch_th = NULL;

static DWORD g_injector_pid = 0;
static volatile BOOL g_pipe_connected = FALSE;

static OvlEntry         g_ovl[MAX_OVL];
static CRITICAL_SECTION g_ovl_cs;

/* Hook function-pointer types */
typedef int (WSAAPI* WSASendTo_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, const struct sockaddr*, int, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI* WSARecvFrom_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, struct sockaddr*, LPINT, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI* sendto_t)(SOCKET, const char*, int, int, const struct sockaddr*, int);
typedef int (WSAAPI* recvfrom_t)(SOCKET, char*, int, int, struct sockaddr*, int*);
typedef BOOL(WINAPI* GQCS_t)(HANDLE, LPDWORD, PULONG_PTR, LPOVERLAPPED*, DWORD);

static WSASendTo_t   orig_WSASendTo = NULL;
static WSARecvFrom_t orig_WSARecvFrom = NULL;
static sendto_t      orig_sendto = NULL;
static recvfrom_t    orig_recvfrom = NULL;
static GQCS_t        orig_GQCS = NULL;

static BYTE sv_wsa_send[14], sv_wsa_recv[14], sv_send[14], sv_recv[14], sv_gqcs[14];

/* ── Forward declarations ────────────────────────────────── */
static int      IsReentrant(void);
static void     EnterHook(void);
static void     LeaveHook(void);
static void     pipe_send(uint8_t type, const void* pay, uint32_t len);
static void     pipe_log(const char* fmt, ...);
static void     forward(uint8_t dir, const uint8_t* data, int dlen, uint32_t ip, uint16_t port);
static void     jmp_write(void* tgt, void* hook);
static void     jmp_restore(void* tgt, BYTE* saved);
static void     fuzz_buf(uint8_t* buf, int len, int bits);
static void     seq_check(const uint8_t* pkt, int len, uint8_t dir);
static void     pcap_write(const uint8_t* data, uint32_t len);
static void     pcap_open(const char* path);
static void     pcap_close(void);
static void     HyForceEject(void);
static void     shm_write(uint32_t type, const uint8_t* data, uint32_t len);
static void     forward_key_to_shm(const char* line, size_t len);
static void     forward_pkt_to_shm(const uint8_t* d, uint32_t len, uint32_t ip, uint16_t port, uint8_t dir);
static uint64_t now_us(void);
static int      is_hytale_port(uint16_t port_be);
static int      is_coord(double v);
static int      is_health(float h);
static int      is_vel(float v);
static void     ovl_register(LPOVERLAPPED ov, char* buf, int bufsz, struct sockaddr_in* peer);
static void     ovl_fire(LPOVERLAPPED ov, DWORD bytes);
static void     ovl_free(LPOVERLAPPED ov);
static void     do_replay(void);
static void     memscan_run(void);
static void     stringscan_run(void);
static void     modlist_run(void);
static void     threadlist_run(void);
static void     gadgetscan_run(void);
static void     exploitprobe_run(void);
static void     sockenum_run(void);
static void     pktforge_run(const char* hexstr);
static void     procdump_run(uint64_t addr, uint32_t size);
static void     portscan_run(int lo, int hi);
static void     hook_boringssl(void);
static void     unhook_boringssl(void);
static void     hook_SSL_CTX_set_kl(SSL_CTX* ctx, ssl_keylog_cb_t cb);
static void     store_kchain(SSL_CTX* ctx, ssl_keylog_cb_t orig);

/* ── Reentrancy ──────────────────────────────────────────── */
static int IsReentrant(void) {
    return g_tls_idx != TLS_OUT_OF_INDEXES && TlsGetValue(g_tls_idx) != NULL;
}
static void EnterHook(void) { if (g_tls_idx != TLS_OUT_OF_INDEXES) TlsSetValue(g_tls_idx, (LPVOID)1); }
static void LeaveHook(void) { if (g_tls_idx != TLS_OUT_OF_INDEXES) TlsSetValue(g_tls_idx, NULL); }

/* ── JMP patch ───────────────────────────────────────────── */
static void jmp_write(void* tgt, void* hook) {
    if (!tgt) return;
    DWORD old;
    VirtualProtect(tgt, 14, PAGE_EXECUTE_READWRITE, &old);
    uint8_t* p = (uint8_t*)tgt;
#ifdef _WIN64
    p[0] = 0xFF; p[1] = 0x25; *(DWORD*)(p + 2) = 0;
    *(uint64_t*)(p + 6) = (uint64_t)(uintptr_t)hook;
#else
    p[0] = 0xE9; *(DWORD*)(p + 1) = (DWORD)((uint8_t*)hook - p - 5);
#endif
    VirtualProtect(tgt, 14, old, &old);
    FlushInstructionCache(GetCurrentProcess(), tgt, 14);
}

static void jmp_restore(void* tgt, BYTE* saved) {
    if (!tgt) return;
    DWORD old;
    VirtualProtect(tgt, 14, PAGE_EXECUTE_READWRITE, &old);
    memcpy(tgt, saved, 14);
    VirtualProtect(tgt, 14, old, &old);
    FlushInstructionCache(GetCurrentProcess(), tgt, 14);
}

/* ── Shared memory ───────────────────────────────────────── */
static int init_shm(void) {
    g_shm_h = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL,
        PAGE_READWRITE | SEC_COMMIT, 0, SHM_SIZE, SHM_NAME);
    if (!g_shm_h) return 0;
    g_shm = (ShmHeader*)MapViewOfFile(g_shm_h, FILE_MAP_ALL_ACCESS, 0, 0, SHM_SIZE);
    if (!g_shm) { CloseHandle(g_shm_h); g_shm_h = NULL; return 0; }
    if (g_shm->entry_size == 0) {
        g_shm->entry_size = sizeof(RingEntry); g_shm->max_entries = SHM_RING_ENTRIES;
        g_shm->write_idx = 0; g_shm->read_idx = 0; g_shm->dropped = 0;
        g_shm->start_us = now_us();
    }
    g_ring = (RingEntry*)((uint8_t*)g_shm + sizeof(ShmHeader));
    return 1;
}

static void cleanup_shm(void) {
    if (g_shm) { UnmapViewOfFile(g_shm); g_shm = NULL; }
    if (g_shm_h) { CloseHandle(g_shm_h);  g_shm_h = NULL; }
}

static void shm_write(uint32_t type, const uint8_t* data, uint32_t len) {
    if (!g_shm || !g_ring) return;
    uint32_t idx = InterlockedIncrement((LONG*)&g_shm->write_idx) - 1;
    idx %= g_shm->max_entries;
    RingEntry* e = &g_ring[idx];
    int sp = 0; while (e->ready && sp++ < 1000) Sleep(0);
    if (e->ready) { InterlockedIncrement((LONG*)&g_shm->dropped); return; }
    e->type = type; e->ts_us = now_us();
    e->data_len = (len > (uint32_t)sizeof(e->data)) ? (uint32_t)sizeof(e->data) : len;
    e->seq = InterlockedIncrement((LONG*)&g_seq);
    memcpy(e->data, data, e->data_len);
    _WriteBarrier(); e->ready = 1;
}

/* ── BoringSSL keylog ────────────────────────────────────── */
static void our_keylog_cb(const SSL* ssl, const char* line) {
    (void)ssl;
    if (!line || !*line) return;
    size_t len = strlen(line);
    pipe_send(MSG_KEYLOG, line, (uint32_t)(len + 1));
    forward_key_to_shm(line, len);
    EnterCriticalSection(&g_kcs);
    strncpy(g_kring[g_kring_head & 31], line, 255);
    g_kring[g_kring_head & 31][255] = '\0';
    g_kring_head++;
    LeaveCriticalSection(&g_kcs);
}

static void store_kchain(SSL_CTX* ctx, ssl_keylog_cb_t orig) {
    EnterCriticalSection(&g_kcs);
    KE* e = g_kchain;
    while (e) { if (e->ctx == ctx) { e->orig = orig; goto done; } e = e->next; }
    e = (KE*)malloc(sizeof(KE)); if (e) { e->ctx = ctx; e->orig = orig; e->next = g_kchain; g_kchain = e; }
done:
    LeaveCriticalSection(&g_kcs);
}

static void hook_SSL_CTX_set_kl(SSL_CTX* ctx, ssl_keylog_cb_t cb) {
    store_kchain(ctx, cb);
    if (g_ssl_set) g_ssl_set(ctx, our_keylog_cb);
}

static void hook_boringssl(void) {
    const char* names[] = {
        "boringssl.dll","boringssl_shared.dll",
        "ssl.dll","libssl.dll","libcrypto.dll",
        "ssleay32.dll","libeay32.dll",
        NULL
    };
    HMODULE mod = NULL;
    int i;

    for (i = 0; names[i] && !mod; i++) {
        mod = GetModuleHandleA(names[i]);
    }

    if (!mod) {
        HMODULE mods[1024]; DWORD need;
        if (EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &need)) {
            int n = (int)(need / sizeof(HMODULE));
            for (i = 0; i < n; i++) {
                if (GetProcAddress(mods[i], "SSL_CTX_set_keylog_callback") ||
                    GetProcAddress(mods[i], "SSL_new")) {
                    mod = mods[i];
                    break;
                }
            }
        }
    }

    if (!mod) return;

    g_ssl_set = (SSL_set_kl_t)GetProcAddress(mod, "SSL_CTX_set_keylog_callback");
    if (!g_ssl_set) g_ssl_set = (SSL_set_kl_t)GetProcAddress(mod, "ssl_log_secret");

    if (!g_ssl_set) return;

    g_ssl_get = (SSL_get_kl_t)GetProcAddress(mod, "SSL_CTX_get_keylog_callback");

    memcpy(sv_ssl, (void*)g_ssl_set, 14);
    jmp_write((void*)g_ssl_set, hook_SSL_CTX_set_kl);
}

static void unhook_boringssl(void) {
    EnterCriticalSection(&g_kcs);
    while (g_kchain) { KE* nx = g_kchain->next; free(g_kchain); g_kchain = nx; }
    LeaveCriticalSection(&g_kcs);
}

static void forward_key_to_shm(const char* line, size_t len) {
    if (!g_shm) return;
    uint8_t buf[4096]; buf[0] = 'K';
    uint32_t n = (uint32_t)((len < 4095) ? len : 4095);
    memcpy(buf + 1, line, n); shm_write(1, buf, n + 1);
}

static void forward_pkt_to_shm(const uint8_t* data, uint32_t len, uint32_t ip, uint16_t port, uint8_t dir) {
    if (!g_shm) return;
    uint8_t meta[4096]; uint32_t off = 0;
    meta[off++] = 'P';
    uint64_t ts = now_us() - g_shm->start_us;
    memcpy(meta + off, &ts, 8); off += 8;
    memcpy(meta + off, &ip, 4); off += 4;
    memcpy(meta + off, &port, 2); off += 2;
    meta[off++] = dir;
    uint32_t cp = (len < 4080) ? len : 4080;
    memcpy(meta + off, &cp, 4); off += 4;
    memcpy(meta + off, data, cp); off += cp;
    shm_write(2, meta, off);
}

/* ── Pipe I/O ────────────────────────────────────────────── */
static void pipe_send(uint8_t type, const void* pay, uint32_t len) {
    if (g_out == INVALID_HANDLE_VALUE || !g_pipe_connected) return;
    if (len > MAX_PKT) len = MAX_PKT;
    uint8_t hdr[5] = { type,(uint8_t)(len & 0xFF),(uint8_t)((len >> 8) & 0xFF),
                    (uint8_t)((len >> 16) & 0xFF),(uint8_t)((len >> 24) & 0xFF) };
    if (WaitForSingleObject(g_mutex, 50) != WAIT_OBJECT_0) return;
    DWORD w; BOOL ok = WriteFile(g_out, hdr, 5, &w, NULL);
    if (ok && len > 0) ok = WriteFile(g_out, pay, len, &w, NULL);
    if (!ok) {
        HANDLE tmp = g_out;
        g_out = INVALID_HANDLE_VALUE;
        g_pipe_connected = FALSE;
        CloseHandle(tmp);
    }
    ReleaseMutex(g_mutex);
}

static void pipe_log(const char* fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, 511, fmt, ap);
    va_end(ap);
    pipe_send(MSG_LOG, buf, (uint32_t)strlen(buf) + 1);
}

/* ── PCAP ────────────────────────────────────────────────── */
static void pcap_write(const uint8_t* data, uint32_t len) {
    if (g_pcap == INVALID_HANDLE_VALUE || !len || len > MAX_PKT) return;
    FILETIME ft; GetSystemTimeAsFileTime(&ft);
    uint64_t us = (((uint64_t)ft.dwHighDateTime << 32 | ft.dwLowDateTime) - 116444736000000000ULL) / 10;
    uint32_t ph[4] = { (uint32_t)(us / 1000000),(uint32_t)(us % 1000000),len,len };
    WaitForSingleObject(g_pcap_mutex, 100);
    DWORD w; WriteFile(g_pcap, ph, 16, &w, NULL); WriteFile(g_pcap, data, len, &w, NULL);
    ReleaseMutex(g_pcap_mutex);
}

static void pcap_open(const char* path) {
    WaitForSingleObject(g_pcap_mutex, 500);
    if (g_pcap != INVALID_HANDLE_VALUE) { CloseHandle(g_pcap); g_pcap = INVALID_HANDLE_VALUE; }
    g_pcap = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_pcap != INVALID_HANDLE_VALUE) {
        uint32_t gh[6] = { 0xa1b2c3d4,0x00040002,0,0,65535,101 }; DWORD w;
        WriteFile(g_pcap, gh, 24, &w, NULL);
    }
    ReleaseMutex(g_pcap_mutex);
}

static void pcap_close(void) {
    WaitForSingleObject(g_pcap_mutex, 500);
    if (g_pcap != INVALID_HANDLE_VALUE) { CloseHandle(g_pcap); g_pcap = INVALID_HANDLE_VALUE; }
    ReleaseMutex(g_pcap_mutex);
}

/* ── Eject ───────────────────────────────────────────────── */
static void HyForceEject(void) {
    pipe_send(MSG_EJECTED, "EJECTING", 9); Sleep(50); g_active = FALSE;
    if (orig_WSASendTo)   jmp_restore(orig_WSASendTo, sv_wsa_send);
    if (orig_WSARecvFrom) jmp_restore(orig_WSARecvFrom, sv_wsa_recv);
    if (orig_sendto)      jmp_restore(orig_sendto, sv_send);
    if (orig_recvfrom)    jmp_restore(orig_recvfrom, sv_recv);
    if (orig_GQCS)        jmp_restore(orig_GQCS, sv_gqcs);
    FlushInstructionCache(GetCurrentProcess(), NULL, 0);
    pcap_close(); cleanup_shm(); unhook_boringssl();
    if (g_out != INVALID_HANDLE_VALUE) { CloseHandle(g_out); g_out = INVALID_HANDLE_VALUE; }
    if (g_cmdin != INVALID_HANDLE_VALUE) { CloseHandle(g_cmdin); g_cmdin = INVALID_HANDLE_VALUE; }
}

/* ── Timing ──────────────────────────────────────────────── */
static uint64_t now_us(void) {
    FILETIME ft; GetSystemTimeAsFileTime(&ft);
    uint64_t v = (uint64_t)ft.dwHighDateTime << 32 | ft.dwLowDateTime;
    return (v - 116444736000000000ULL) / 10;
}

/* ── Seq check ───────────────────────────────────────────── */
static void seq_check(const uint8_t* pkt, int len, uint8_t dir) {
    if (len < 2 || (pkt[0] & 0x80)) return;
    int pn_len = (pkt[0] & 0x03) + 1; if (1 + pn_len > len) return;
    uint64_t pn = 0; int i;
    for (i = 0; i < pn_len; i++) pn = (pn << 8) | pkt[1 + i];
    uint64_t* last = (dir == 0) ? &g_seq_cs : &g_seq_sc;
    if (*last != UINT64_MAX && pn <= *last) {
        uint8_t ab[80]; memcpy(ab, last, 8); memcpy(ab + 8, &pn, 8); ab[16] = dir;
        snprintf((char*)ab + 17, 62, "SEQ dir=%d exp>%llu got=%llu",
            dir, (unsigned long long) * last, (unsigned long long)pn);
        pipe_send(MSG_SEQ_ANOMALY, ab, 17 + (uint32_t)strlen((char*)ab + 17) + 1);
    }
    *last = pn;
}

/* ── Fuzz ────────────────────────────────────────────────── */
static void fuzz_buf(uint8_t* buf, int len, int bits) {
    if (len <= 0) return;
    srand((unsigned)GetTickCount());
    int i;
    for (i = 0; i < bits; i++) buf[rand() % len] ^= (uint8_t)(1 << (rand() % 8));
}

/* ── Port check ──────────────────────────────────────────── */
static int is_hytale_port(uint16_t port_be) {
    uint16_t p = ntohs(port_be);
    return p >= HYTALE_PORT_MIN && p <= HYTALE_PORT_MAX;
}

/* ── Core forward ────────────────────────────────────────── */
static void forward(uint8_t dir, const uint8_t* data, int dlen, uint32_t ip, uint16_t port) {
    if (!is_hytale_port(port) && !(dir == 1 && ip == g_last_cs_ip)) return;
    if (dlen <= 0 || dlen > MAX_PKT) return;
    InterlockedIncrement(&g_pkts_captured);
    pcap_write(data, (uint32_t)dlen); seq_check(data, dlen, dir);
    uint8_t tb[13]; uint64_t ts = now_us(); uint32_t u = (uint32_t)dlen;
    memcpy(tb, &ts, 8); memcpy(tb + 8, &u, 4); tb[12] = dir; pipe_send(MSG_TIMING, tb, 13);
    int tot = 7 + dlen; uint8_t* buf = (uint8_t*)malloc((size_t)tot); if (!buf) return;
    buf[0] = dir; memcpy(buf + 1, &ip, 4); memcpy(buf + 5, &port, 2); memcpy(buf + 7, data, dlen);
    pipe_send(MSG_PACKET, buf, (uint32_t)tot);
    forward_pkt_to_shm(data, (uint32_t)dlen, ip, port, dir);
    free(buf);
    if (dir == 0) {
        EnterCriticalSection(&g_replay_cs);
        if (dlen <= MAX_PKT) {
            memcpy(g_last_cs, data, (size_t)dlen);
            g_last_cs_len = dlen; g_last_cs_ip = ip; g_last_cs_port = port;
        }
        LeaveCriticalSection(&g_replay_cs);
    }
}

/* ── IOCP pending-op table ───────────────────────────────── */
static void ovl_register(LPOVERLAPPED ov, char* buf, int bufsz, struct sockaddr_in* peer) {
    if (!ov) return;
    EnterCriticalSection(&g_ovl_cs);
    int i;
    for (i = 0; i < MAX_OVL; i++) {
        if (!g_ovl[i].used) {
            g_ovl[i].ov = ov; g_ovl[i].buf = buf; g_ovl[i].bufsz = bufsz;
            if (peer) memcpy(&g_ovl[i].peer, peer, sizeof(struct sockaddr_in));
            else     memset(&g_ovl[i].peer, 0, sizeof(struct sockaddr_in));
            g_ovl[i].used = 1; break;
        }
    }
    LeaveCriticalSection(&g_ovl_cs);
}

static void ovl_fire(LPOVERLAPPED ov, DWORD bytes) {
    if (!ov || !bytes) return;
    EnterCriticalSection(&g_ovl_cs);
    int i;
    for (i = 0; i < MAX_OVL; i++) {
        if (g_ovl[i].used && g_ovl[i].ov == ov) {
            char* buf = g_ovl[i].buf; int bufsz = g_ovl[i].bufsz;
            struct sockaddr_in peer = g_ovl[i].peer;
            g_ovl[i].used = 0;
            LeaveCriticalSection(&g_ovl_cs);
            if (buf && bytes > 0 && bytes <= (DWORD)bufsz) {
                uint32_t ip = peer.sin_addr.s_addr;
                uint16_t port = peer.sin_port;
                forward(1, (uint8_t*)buf, (int)bytes, ip, port);
            }
            return;
        }
    }
    LeaveCriticalSection(&g_ovl_cs);
}

static void ovl_free(LPOVERLAPPED ov) {
    if (!ov) return;
    EnterCriticalSection(&g_ovl_cs);
    int i;
    for (i = 0; i < MAX_OVL; i++) {
        if (g_ovl[i].used && g_ovl[i].ov == ov) { g_ovl[i].used = 0; break; }
    }
    LeaveCriticalSection(&g_ovl_cs);
}

/* ── Hooks ───────────────────────────────────────────────── */
static int WSAAPI hook_WSASendTo(SOCKET s, LPWSABUF bufs, DWORD nb, LPDWORD sent, DWORD flags,
    const struct sockaddr* to, int tolen, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cb)
{
    if (IsReentrant()) return orig_WSASendTo(s, bufs, nb, sent, flags, to, tolen, ov, cb);
    EnterHook(); InterlockedIncrement(&g_fires_wsa_send); DWORD se = GetLastError();
    EnterCriticalSection(&g_cs); jmp_restore(orig_WSASendTo, sv_wsa_send); LeaveCriticalSection(&g_cs);
    int ret; int fuzz = InterlockedExchange((LONG*)&g_fuzz_bits, 0);
    if (fuzz > 0 && nb > 0 && bufs && bufs[0].len > 1) {
        uint8_t* tmp = (uint8_t*)malloc(bufs[0].len);
        if (tmp) {
            memcpy(tmp, bufs[0].buf, bufs[0].len); fuzz_buf(tmp + 1, (int)bufs[0].len - 1, fuzz);
            WSABUF fb = { bufs[0].len,(char*)tmp }; ret = WSASendTo(s, &fb, 1, sent, flags, to, tolen, ov, cb); free(tmp);
        }
        else ret = WSASendTo(s, bufs, nb, sent, flags, to, tolen, ov, cb);
    }
    else ret = WSASendTo(s, bufs, nb, sent, flags, to, tolen, ov, cb);
    EnterCriticalSection(&g_cs); jmp_write(orig_WSASendTo, hook_WSASendTo); LeaveCriticalSection(&g_cs);
    if (ret != SOCKET_ERROR) SetLastError(se);
    DWORD _le = GetLastError();
    int _sent_ok = (ret == 0) || (ret == SOCKET_ERROR && _le == WSA_IO_PENDING);
    if (_sent_ok && nb > 0 && bufs && bufs[0].buf && bufs[0].len > 0) {
        uint32_t ip = 0; uint16_t port = 0;
        if (to && tolen >= (int)sizeof(struct sockaddr_in)) {
            const struct sockaddr_in* sa = (const struct sockaddr_in*)to;
            if (sa->sin_family == AF_INET) { ip = sa->sin_addr.s_addr; port = sa->sin_port; }
        }
        forward(0, (uint8_t*)bufs[0].buf, (int)bufs[0].len, ip, port);
    }
    LeaveHook(); return ret;
}

static int WSAAPI hook_sendto(SOCKET s, const char* buf, int len, int flags,
    const struct sockaddr* to, int tolen)
{
    if (IsReentrant()) return orig_sendto(s, buf, len, flags, to, tolen);
    EnterHook(); InterlockedIncrement(&g_fires_send); DWORD se = GetLastError();
    EnterCriticalSection(&g_cs); jmp_restore(orig_sendto, sv_send); LeaveCriticalSection(&g_cs);
    int ret; int fuzz = InterlockedExchange((LONG*)&g_fuzz_bits, 0);
    if (fuzz > 0 && len > 1) {
        uint8_t* tmp = (uint8_t*)malloc((size_t)len);
        if (tmp) {
            memcpy(tmp, buf, (size_t)len); fuzz_buf(tmp + 1, len - 1, fuzz);
            ret = sendto(s, (char*)tmp, len, flags, to, tolen); free(tmp);
        }
        else ret = sendto(s, buf, len, flags, to, tolen);
    }
    else ret = sendto(s, buf, len, flags, to, tolen);
    EnterCriticalSection(&g_cs); jmp_write(orig_sendto, hook_sendto); LeaveCriticalSection(&g_cs);
    if (ret != SOCKET_ERROR) SetLastError(se);
    if (ret > 0 && buf && len > 0) {
        uint32_t ip = 0; uint16_t port = 0;
        if (to && tolen >= (int)sizeof(struct sockaddr_in)) {
            const struct sockaddr_in* sa = (const struct sockaddr_in*)to;
            if (sa->sin_family == AF_INET) { ip = sa->sin_addr.s_addr; port = sa->sin_port; }
        }
        forward(0, (uint8_t*)buf, len, ip, port);
    }
    LeaveHook(); return ret;
}

static int WSAAPI hook_WSARecvFrom(SOCKET s, LPWSABUF bufs, DWORD nb, LPDWORD recvd, LPDWORD flags,
    struct sockaddr* from, LPINT fromlen, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cb)
{
    if (IsReentrant()) return orig_WSARecvFrom(s, bufs, nb, recvd, flags, from, fromlen, ov, cb);
    EnterHook(); InterlockedIncrement(&g_fires_wsa_recv); DWORD se = GetLastError();
    EnterCriticalSection(&g_cs); jmp_restore(orig_WSARecvFrom, sv_wsa_recv); LeaveCriticalSection(&g_cs);
    if (ov && nb > 0 && bufs && bufs[0].buf) {
        struct sockaddr_in tmp_peer = { 0 };
        if (from && fromlen && *fromlen >= (int)sizeof(struct sockaddr_in))
            memcpy(&tmp_peer, from, sizeof(struct sockaddr_in));
        ovl_register(ov, bufs[0].buf, (int)bufs[0].len, &tmp_peer);
    }
    int ret = orig_WSARecvFrom(s, bufs, nb, recvd, flags, from, fromlen, ov, cb);
    EnterCriticalSection(&g_cs); jmp_write(orig_WSARecvFrom, hook_WSARecvFrom); LeaveCriticalSection(&g_cs);
    if (ret != SOCKET_ERROR) SetLastError(se);
    if (ret == 0 && recvd && *recvd > 0 && nb > 0 && bufs && bufs[0].buf) {
        if (ov) ovl_free(ov);
        uint32_t ip = 0; uint16_t port = 0;
        if (from && fromlen && *fromlen >= (int)sizeof(struct sockaddr_in)) {
            const struct sockaddr_in* sa = (const struct sockaddr_in*)from;
            if (sa->sin_family == AF_INET) { ip = sa->sin_addr.s_addr; port = sa->sin_port; }
        }
        forward(1, (uint8_t*)bufs[0].buf, (int)*recvd, ip, port);
    }
    else if (ret == SOCKET_ERROR && GetLastError() != WSA_IO_PENDING && ov) {
        ovl_free(ov);
    }
    LeaveHook(); return ret;
}

static int WSAAPI hook_recvfrom(SOCKET s, char* buf, int len, int flags,
    struct sockaddr* from, int* fromlen)
{
    if (IsReentrant()) return orig_recvfrom(s, buf, len, flags, from, fromlen);
    EnterHook(); InterlockedIncrement(&g_fires_recv); DWORD se = GetLastError();
    EnterCriticalSection(&g_cs); jmp_restore(orig_recvfrom, sv_recv); LeaveCriticalSection(&g_cs);
    int ret = orig_recvfrom(s, buf, len, flags, from, fromlen);
    EnterCriticalSection(&g_cs); jmp_write(orig_recvfrom, hook_recvfrom); LeaveCriticalSection(&g_cs);
    if (ret == SOCKET_ERROR) { SetLastError(se); LeaveHook(); return ret; }
    if (ret > 0 && buf) {
        uint32_t ip = 0; uint16_t port = 0;
        if (from && fromlen && *fromlen >= (int)sizeof(struct sockaddr_in)) {
            const struct sockaddr_in* sa = (const struct sockaddr_in*)from;
            if (sa->sin_family == AF_INET) { ip = sa->sin_addr.s_addr; port = sa->sin_port; }
        }
        forward(1, (uint8_t*)buf, ret, ip, port);
    }
    LeaveHook(); return ret;
}

/* ── IOCP hook ───────────────────────────────────────────── */
static BOOL WINAPI hook_GQCS(HANDLE iocp, LPDWORD bytes, PULONG_PTR key,
    LPOVERLAPPED* ppOv, DWORD timeout)
{
    EnterCriticalSection(&g_cs); jmp_restore(orig_GQCS, sv_gqcs); LeaveCriticalSection(&g_cs);
    BOOL ret = orig_GQCS(iocp, bytes, key, ppOv, timeout);
    EnterCriticalSection(&g_cs); jmp_write(orig_GQCS, hook_GQCS); LeaveCriticalSection(&g_cs);
    if (ret && ppOv && *ppOv && bytes && *bytes > 0) {
        ovl_fire(*ppOv, *bytes);
    }
    return ret;
}

/* ── Memory helpers ──────────────────────────────────────── */
static int is_coord(double v) { return !isnan(v) && !isinf(v) && v > -65536.0 && v < 65536.0; }
static int is_health(float h) { return !isnan(h) && h > 0.0f && h <= 10000.0f; }
static int is_vel(float v) { return !isnan(v) && v > -2000.0f && v < 2000.0f; }

/* ── MEMSCAN ─────────────────────────────────────────────── */
static void memscan_run(void) {
    int hits = 0;
    MEMORY_BASIC_INFORMATION mbi;
    uint8_t* addr = NULL;
    while (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        uint8_t* next = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;
        if (mbi.State != MEM_COMMIT || mbi.RegionSize < 65536 || mbi.RegionSize>256 * 1024 * 1024 ||
            (mbi.Protect & PAGE_GUARD) || (mbi.Protect & PAGE_NOACCESS) ||
            !(mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE)))
        {
            addr = next; continue;
        }
        uint8_t* base = (uint8_t*)mbi.BaseAddress; SIZE_T rsz = mbi.RegionSize;
        __try {
            SIZE_T off;
            for (off = 0; off + 56 <= rsz; off += 4) {
                uint8_t* p = base + off;
                float h = *(float*)(p + 0), mh = *(float*)(p + 4);
                if (!is_health(h) || !is_health(mh) || mh < h) continue;
                double x = *(double*)(p + 8), y = *(double*)(p + 16), z = *(double*)(p + 24);
                if (!is_coord(x) || !is_coord(y) || y < 0.0 || y>512.0 || !is_coord(z)) continue;
                float vx = *(float*)(p + 32), vy = *(float*)(p + 36), vz = *(float*)(p + 40);
                if (!is_vel(vx) || !is_vel(vy) || !is_vel(vz)) continue;
                uint8_t rep[76]; uint64_t a64 = (uint64_t)(uintptr_t)p; uint32_t sz = 56;
                memcpy(rep, &a64, 8); memcpy(rep + 8, &sz, 4);
                SIZE_T cp = (sz < (uint32_t)(rsz - off)) ? sz : (SIZE_T)(rsz - off);
                memcpy(rep + 12, p, cp);
                pipe_send(MSG_MEMSCAN, rep, (uint32_t)(12 + cp));
                if (++hits >= 64) goto memscan_done;
                off += 52;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        addr = next;
    }
memscan_done:;
}

static DWORD WINAPI memscan_th(LPVOID _) { (void)_; memscan_run(); return 0; }

/* ── STRINGSCAN ──────────────────────────────────────────── */
#define MIN_STR_LEN 8
static void stringscan_run(void) {
    int count = 0;
    MEMORY_BASIC_INFORMATION mbi;
    uint8_t* addr = NULL;
    while (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        uint8_t* next = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;
        if (mbi.State != MEM_COMMIT || mbi.RegionSize < 4096 || mbi.RegionSize>256 * 1024 * 1024 ||
            (mbi.Protect & PAGE_GUARD) || (mbi.Protect & PAGE_NOACCESS) ||
            !(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)))
        {
            addr = next; continue;
        }
        uint8_t* base = (uint8_t*)mbi.BaseAddress; SIZE_T rsz = mbi.RegionSize;
        __try {
            uint8_t* start = NULL; int slen = 0;
            SIZE_T i;
            for (i = 0; i < rsz; i++) {
                unsigned char c = base[i];
                int printable = (c >= 0x20 && c < 0x7F) || c == 0x09 || c == 0x0A || c == 0x0D;
                if (printable) {
                    if (!start) { start = base + i; slen = 0; }
                    slen++;
                }
                else {
                    if (start && slen >= MIN_STR_LEN) {
                        uint8_t pay[12 + 256]; uint64_t a = (uint64_t)(uintptr_t)start;
                        uint32_t sl = (uint32_t)(slen < 256 ? slen : 256);
                        memcpy(pay, &a, 8); memcpy(pay + 8, &sl, 4); memcpy(pay + 12, start, (size_t)sl);
                        pipe_send(MSG_STRINGSCAN, pay, 12 + sl);
                        if (++count >= 2000) goto stringscan_done;
                    }
                    start = NULL; slen = 0;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        addr = next;
    }
stringscan_done:;
}

static DWORD WINAPI stringscan_th(LPVOID _) { (void)_; stringscan_run(); return 0; }

/* ── MODLIST ─────────────────────────────────────────────── */
static void modlist_run(void) {
    HMODULE mods[1024]; DWORD need;
    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &need)) return;
    int n = (int)(need / sizeof(HMODULE)); int i;
    for (i = 0; i < n; i++) {
        char nm[MAX_PATH] = { 0 };
        MODULEINFO mi = { 0 };
        GetModuleFileNameExA(GetCurrentProcess(), mods[i], nm, MAX_PATH);
        GetModuleInformation(GetCurrentProcess(), mods[i], &mi, sizeof(mi));
        uint8_t pay[12 + MAX_PATH];
        uint64_t base = (uint64_t)(uintptr_t)mi.lpBaseOfDll;
        uint32_t sz = (uint32_t)mi.SizeOfImage;
        memcpy(pay, &base, 8); memcpy(pay + 8, &sz, 4);
        const char* fname = strrchr(nm, '\\'); fname = fname ? fname + 1 : nm;
        uint32_t namelen = (uint32_t)strlen(fname) + 1;
        if (namelen > MAX_PATH) namelen = MAX_PATH;
        memcpy(pay + 12, fname, namelen);
        pipe_send(MSG_MODINFO, pay, 12 + namelen);
    }
}

static DWORD WINAPI modlist_th(LPVOID _) { (void)_; modlist_run(); return 0; }

/* ── THREADLIST ──────────────────────────────────────────── */
static void threadlist_run(void) {
    DWORD pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te; te.dwSize = sizeof(te);
    int count = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            HANDLE ht = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            uint64_t start = 0;
            if (ht) {
                typedef LONG(NTAPI* NtQIT_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
                static NtQIT_t NtQIT = NULL;
                if (!NtQIT) NtQIT = (NtQIT_t)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                    "NtQueryInformationThread");
                if (NtQIT) NtQIT(ht, 9, &start, sizeof(start), NULL);
                CloseHandle(ht);
            }
            count++;
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
}

static DWORD WINAPI threadlist_th(LPVOID _) { (void)_; threadlist_run(); return 0; }

/* ── GADGETSCAN ──────────────────────────────────────────── */
#define GT_CALL_RAX   0x01
#define GT_JMP_RAX    0x02
#define GT_CALL_RSP   0x03
#define GT_JMP_RSP    0x04
#define GT_POP_RET    0x05
#define GT_RET        0x06
#define GT_NOP_SLED   0x07
#define GT_INT3       0x08
#define GT_SYSCALL    0x09
#define GT_SYSENTER   0x0A

static void gadgetscan_run(void) {
    int count = 0;
    MEMORY_BASIC_INFORMATION mbi;
    uint8_t* addr = NULL;
    while (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        uint8_t* next = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;
        if (mbi.State != MEM_COMMIT || mbi.RegionSize < 4096 ||
            (mbi.Protect & PAGE_GUARD) || (mbi.Protect & PAGE_NOACCESS) ||
            !(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
        {
            addr = next; continue;
        }
        uint8_t* base = (uint8_t*)mbi.BaseAddress; SIZE_T rsz = mbi.RegionSize;
        __try {
            SIZE_T i;
            for (i = 0; i + 1 < rsz && count < 2000; i++) {
                uint8_t b0 = base[i], b1 = (i + 1 < rsz ? base[i + 1] : 0);
                uint8_t gtype = 0; char desc[64] = "";
                if (b0 == 0xFF && b1 == 0xD0) { gtype = GT_CALL_RAX; strcpy(desc, "call rax"); }
                else if (b0 == 0xFF && b1 == 0xE0) { gtype = GT_JMP_RAX; strcpy(desc, "jmp rax"); }
                else if (b0 == 0xFF && b1 == 0xD4) { gtype = GT_CALL_RSP; strcpy(desc, "call rsp"); }
                else if (b0 == 0xFF && b1 == 0xE4) { gtype = GT_JMP_RSP; strcpy(desc, "jmp rsp"); }
                else if ((b0 & 0xF8) == 0x58 && b1 == 0xC3) {
                    gtype = GT_POP_RET;
                    snprintf(desc, sizeof(desc), "pop r%d; ret", (int)(b0 & 7));
                }
                else if (b0 == 0x0F && b1 == 0x05) { gtype = GT_SYSCALL; strcpy(desc, "syscall"); }
                else if (b0 == 0x0F && b1 == 0x34) { gtype = GT_SYSENTER; strcpy(desc, "sysenter"); }
                else if (b0 == 0xCC) { gtype = GT_INT3; strcpy(desc, "int3 breakpoint"); }
                else if (b0 == 0x90) {
                    int sled = 1;
                    while (i + sled < rsz && base[i + sled] == 0x90 && sled < 64) sled++;
                    if (sled >= 8) {
                        gtype = GT_NOP_SLED;
                        snprintf(desc, sizeof(desc), "NOP sled x%d", sled);
                        i += sled - 1;
                    }
                }
                if (gtype) {
                    uint64_t ga = (uint64_t)(uintptr_t)(base + i);
                    uint8_t pay[9 + 64]; memcpy(pay, &ga, 8); pay[8] = gtype;
                    uint32_t dlen = (uint32_t)strlen(desc) + 1;
                    if (dlen > 64) dlen = 64;
                    memcpy(pay + 9, desc, dlen);
                    pipe_send(MSG_GADGET, pay, 9 + dlen);
                    count++;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        addr = next;
    }
}

static DWORD WINAPI gadgetscan_th(LPVOID _) { (void)_; gadgetscan_run(); return 0; }

/* ── EXPLOITPROBE ────────────────────────────────────────── */
static void exploitprobe_run(void) {
    char out[2048]; int pos = 0;
    pos += snprintf(out + pos, (int)sizeof(out) - pos, "[EXPLOIT PROBE RESULTS]\n");

    void* rwx = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    pos += snprintf(out + pos, (int)sizeof(out) - pos,
        "RWX alloc (DEP bypass): %s\n", rwx ? "POSSIBLE (no strict DEP)" : "BLOCKED (DEP enforced)");
    if (rwx) VirtualFree(rwx, 0, MEM_RELEASE);

    void* a1 = VirtualAlloc((void*)0x70000000, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    void* a2 = VirtualAlloc((void*)0x70000000, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    int aslr_ok = (a1 != a2) || (a1 == (void*)0) || (a2 == (void*)0);
    pos += snprintf(out + pos, (int)sizeof(out) - pos,
        "ASLR hint repeat: %s\n", aslr_ok ? "working (addresses differ)" : "WARN — same address returned");
    if (a1) VirtualFree(a1, 0, MEM_RELEASE);
    if (a2) VirtualFree(a2, 0, MEM_RELEASE);

    HANDLE htok = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &htok)) {
        TOKEN_MANDATORY_LABEL tml = { 0 }; DWORD sz = 0;
        GetTokenInformation(htok, TokenIntegrityLevel, NULL, 0, &sz);
        if (sz > 0) {
            void* buf = malloc(sz);
            if (buf && GetTokenInformation(htok, TokenIntegrityLevel, buf, sz, &sz)) {
                TOKEN_MANDATORY_LABEL* ptml = (TOKEN_MANDATORY_LABEL*)buf;
                DWORD rid = *GetSidSubAuthority(ptml->Label.Sid,
                    *GetSidSubAuthorityCount(ptml->Label.Sid) - 1);
                const char* lname = "Unknown";
                if (rid < 0x1000) lname = "Untrusted";
                else if (rid < 0x2000) lname = "Low";
                else if (rid < 0x3000) lname = "Medium";
                else if (rid < 0x4000) lname = "High (Elevated)";
                else if (rid == 0x4000) lname = "System";
                else                lname = "Protected";
                pos += snprintf(out + pos, (int)sizeof(out) - pos, "Integrity level: %s (RID=0x%lX)\n", lname, (unsigned long)rid);
            }
            free(buf);
        }
        CloseHandle(htok);
    }

    typedef LONG(NTAPI* NtQIP_t)(HANDLE, DWORD, PVOID, ULONG, PULONG);
    NtQIP_t NtQIP = (NtQIP_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    if (NtQIP) {
        DWORD depFlags = 0;
        if (NtQIP(GetCurrentProcess(), 34, &depFlags, sizeof(depFlags), NULL) == 0) {
            int dep_enabled = !(depFlags & 0x02);
            pos += snprintf(out + pos, (int)sizeof(out) - pos,
                "DEP policy (ExecuteFlags=0x%lX): %s\n", (unsigned long)depFlags,
                dep_enabled ? "ENABLED" : "DISABLED");
        }
    }

    BOOL inJob = FALSE;
    IsProcessInJob(GetCurrentProcess(), NULL, &inJob);
    pos += snprintf(out + pos, (int)sizeof(out) - pos, "Job object: %s\n", inJob ? "YES (sandboxed)" : "No");

    HMODULE self = GetModuleHandleW(NULL);
    if (self) {
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)self;
        IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((uint8_t*)self + dos->e_lfanew);
        DWORD guard = 0;
        __try { guard = nt->OptionalHeader.DllCharacteristics; }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        int cfg = (guard & 0x4000) != 0;
        pos += snprintf(out + pos, (int)sizeof(out) - pos, "CFG (DllChar=0x%04X): %s\n",
            (unsigned)guard, cfg ? "ENABLED" : "disabled");
    }

    pipe_send(MSG_EXPLOIT, out, (uint32_t)(pos + 1));
}

static DWORD WINAPI exploitprobe_th(LPVOID _) { (void)_; exploitprobe_run(); return 0; }

/* ── SOCKENUM ────────────────────────────────────────────── */
static void sockenum_run(void) {
    DWORD sz = 0;
    GetExtendedUdpTable(NULL, &sz, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (!sz) return;
    void* tbl = malloc(sz);
    if (!tbl) return;
    if (GetExtendedUdpTable(tbl, &sz, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        MIB_UDPTABLE_OWNER_PID* ut = (MIB_UDPTABLE_OWNER_PID*)tbl;
        DWORD myPid = GetCurrentProcessId();
        DWORD i;
        for (i = 0; i < ut->dwNumEntries; i++) {
            if (ut->table[i].dwOwningPid != myPid) continue;
        }
    }
    free(tbl);
}

/* ── PKTFORGE ────────────────────────────────────────────── */
static void pktforge_run(const char* hexstr) {
    uint8_t pkt[MAX_PKT]; int plen = 0;
    const char* p = hexstr;
    while (*p && *(p + 1) && plen < MAX_PKT) {
        char hi = *p++, lo = *p++;
        while (hi == ' ' || hi == ':' || hi == '-') { hi = lo; lo = *p ? *p++ : 0; }
        if (!lo) break;
        unsigned h = (hi >= '0' && hi <= '9') ? hi - '0' : (hi >= 'a' && hi <= 'f') ? hi - 'a' + 10 : (hi >= 'A' && hi <= 'F') ? hi - 'A' + 10 : 255u;
        unsigned l = (lo >= '0' && lo <= '9') ? lo - '0' : (lo >= 'a' && lo <= 'f') ? lo - 'a' + 10 : (lo >= 'A' && lo <= 'F') ? lo - 'A' + 10 : 255u;
        if (h > 15 || l > 15) break;
        pkt[plen++] = (uint8_t)((h << 4) | l);
    }
    if (plen <= 0) return;

    EnterCriticalSection(&g_replay_cs);
    if (g_last_cs_ip == 0 || g_last_cs_port == 0) {
        LeaveCriticalSection(&g_replay_cs);
        return;
    }
    uint32_t ip = g_last_cs_ip; uint16_t port = g_last_cs_port;
    LeaveCriticalSection(&g_replay_cs);

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) return;
    struct sockaddr_in dst = { 0 }; dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = ip; dst.sin_port = port;
    sendto(sock, (char*)pkt, plen, 0, (struct sockaddr*)&dst, sizeof(dst));
    closesocket(sock);
}

/* ── PROCDUMP ────────────────────────────────────────────── */
static void procdump_run(uint64_t addr, uint32_t size) {
    if (!addr || size == 0 || size > 65536) return;
    void* ptr = (void*)(uintptr_t)addr;
    uint8_t* pay = (uint8_t*)malloc(12 + size);
    if (!pay) return;
    memcpy(pay, &addr, 8); memcpy(pay + 8, &size, 4);
    BOOL ok = FALSE;
    __try { memcpy(pay + 12, ptr, (size_t)size); ok = TRUE; }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    if (ok) pipe_send(MSG_PROCDUMP, pay, 12 + size);
    free(pay);
}

/* ── PORTSCAN ────────────────────────────────────────────── */
typedef struct { int lo; int hi; }PSArgs;
static DWORD WINAPI portscan_th(LPVOID arg) {
    PSArgs* a = (PSArgs*)arg; int lo = a->lo, hi = a->hi; free(a);
    EnterCriticalSection(&g_replay_cs);
    uint32_t ip = g_last_cs_ip;
    LeaveCriticalSection(&g_replay_cs);
    if (!ip) return 0;
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) return 0;
    u_long nb = 1; ioctlsocket(sock, FIONBIO, &nb);
    struct sockaddr_in laddr = { 0 }; laddr.sin_family = AF_INET; laddr.sin_port = 0;
    bind(sock, (struct sockaddr*)&laddr, sizeof(laddr));
    int open_count = 0;
    int p;
    for (p = lo; p <= hi && g_active; p++) {
        struct sockaddr_in dst = { 0 }; dst.sin_family = AF_INET; dst.sin_addr.s_addr = ip;
        dst.sin_port = htons((uint16_t)p);
        uint8_t probe[4] = { 0x00,0x00,0x00,0x01 };
        sendto(sock, (char*)probe, 4, 0, (struct sockaddr*)&dst, sizeof(dst));
        Sleep(2);
        char resp[32]; struct sockaddr_in from = { 0 }; int fl = sizeof(from);
        int r = (int)recvfrom(sock, resp, sizeof(resp), 0, (struct sockaddr*)&from, &fl);
        if (r > 0) open_count++;
    }
    closesocket(sock);
    return 0;
}

/* ── Memory watch thread ─────────────────────────────────── */
static DWORD WINAPI memwatch_th(LPVOID _) {
    (void)_; uint8_t prev[64] = { 0 }; int first = 1;
    while (g_active && g_watch_addr && g_watch_ms > 0) {
        Sleep((DWORD)g_watch_ms);
        if (!g_watch_addr) break;
        uint8_t cur[64] = { 0 };
        __try { memcpy(cur, (void*)(uintptr_t)g_watch_addr, 64); }
        __except (EXCEPTION_EXECUTE_HANDLER) { break; }
        if (first || memcmp(cur, prev, 64) != 0) {
            uint8_t pay[72]; memcpy(pay, &g_watch_addr, 8); memcpy(pay + 8, cur, 64);
            pipe_send(MSG_MEMWATCH, pay, 72); memcpy(prev, cur, 64); first = 0;
        }
    }
    return 0;
}

/* ── Rate limit thread ───────────────────────────────────── */
typedef struct { int count; int ms; }RLArgs;
static DWORD WINAPI rl_thread(LPVOID arg) {
    RLArgs* a = (RLArgs*)arg; int count = a->count, ms = a->ms; free(a);
    EnterCriticalSection(&g_replay_cs);
    if (g_last_cs_len <= 0) { LeaveCriticalSection(&g_replay_cs); return 0; }
    uint8_t pkt[MAX_PKT]; int len = g_last_cs_len; uint32_t ip = g_last_cs_ip; uint16_t port = g_last_cs_port;
    memcpy(pkt, g_last_cs, (size_t)len); LeaveCriticalSection(&g_replay_cs);
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) return 0;
    struct sockaddr_in dst = { 0 }; dst.sin_family = AF_INET; dst.sin_addr.s_addr = ip; dst.sin_port = port;
    int sp = (count > 0 && ms > count) ? ms / count : 10; if (sp < 1)sp = 1;
    int i;
    for (i = 0; i < count && g_active; i++) {
        sendto(sock, (char*)pkt, len, 0, (struct sockaddr*)&dst, sizeof(dst));
        Sleep((DWORD)sp);
    }
    closesocket(sock);
    return 0;
}

/* ── Replay ──────────────────────────────────────────────── */
static void do_replay(void) {
    EnterCriticalSection(&g_replay_cs);
    if (g_last_cs_len <= 0) { LeaveCriticalSection(&g_replay_cs); return; }
    uint8_t pkt[MAX_PKT]; int len = g_last_cs_len; uint32_t ip = g_last_cs_ip; uint16_t port = g_last_cs_port;
    memcpy(pkt, g_last_cs, (size_t)len); LeaveCriticalSection(&g_replay_cs);
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) return;
    struct sockaddr_in dst = { 0 }; dst.sin_family = AF_INET; dst.sin_addr.s_addr = ip; dst.sin_port = port;
    sendto(sock, (char*)pkt, len, 0, (struct sockaddr*)&dst, sizeof(dst));
    closesocket(sock);
}

/* ── Heartbeat ───────────────────────────────────────────── */
static DWORD WINAPI hb_thread(LPVOID _) {
    (void)_;
    while (g_active) {
        Sleep(5000); if (!g_active) break;
        pipe_log("[STATS] WSASendTo:%ld sendto:%ld WSARecvFrom:%ld recvfrom:%ld pkts:%ld",
            g_fires_wsa_send, g_fires_send, g_fires_wsa_recv, g_fires_recv, g_pkts_captured);
    }
    return 0;
}

/* ── Command thread ──────────────────────────────────────── */
static DWORD WINAPI cmd_thread(LPVOID _) {
    (void)_; char buf[1024]; int pos = 0;
    while (g_active) {
        if (g_cmdin == INVALID_HANDLE_VALUE) {
            HANDLE h = CreateFileW(PIPE_CMD, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL, OPEN_EXISTING, 0, NULL);
            if (h != INVALID_HANDLE_VALUE) { g_cmdin = h; pos = 0; }
            else { Sleep(500); continue; }
        }
        DWORD av = 0;
        if (!PeekNamedPipe(g_cmdin, NULL, 0, NULL, &av, NULL)) {
            CloseHandle(g_cmdin); g_cmdin = INVALID_HANDLE_VALUE; continue;
        }
        if (!av) { Sleep(20); continue; }
        char c; DWORD r;
        if (!ReadFile(g_cmdin, &c, 1, &r, NULL) || r == 0) {
            CloseHandle(g_cmdin); g_cmdin = INVALID_HANDLE_VALUE; continue;
        }
        if (c == '\n' || c == '\r') {
            buf[pos] = '\0'; pos = 0; if (!buf[0]) continue;
            if (!strcmp(buf, "PING"))    pipe_send(MSG_STATUS, "PONG", 5);
            else if (!strcmp(buf, "STOP"))    g_active = FALSE;
            else if (!strcmp(buf, "EJECT"))   HyForceEject();
            else if (!strcmp(buf, "MEMSCAN")) CreateThread(NULL, 0, memscan_th, NULL, 0, NULL);
            else if (!strcmp(buf, "STRINGSCAN")) CreateThread(NULL, 0, stringscan_th, NULL, 0, NULL);
            else if (!strcmp(buf, "MODLIST")) CreateThread(NULL, 0, modlist_th, NULL, 0, NULL);
            else if (!strcmp(buf, "THREADLIST")) CreateThread(NULL, 0, threadlist_th, NULL, 0, NULL);
            else if (!strcmp(buf, "GADGETSCAN")) CreateThread(NULL, 0, gadgetscan_th, NULL, 0, NULL);
            else if (!strcmp(buf, "EXPLOITPROBE")) CreateThread(NULL, 0, exploitprobe_th, NULL, 0, NULL);
            else if (!strcmp(buf, "SOCKENUM")) sockenum_run();
            else if (!strcmp(buf, "REPLAY"))  do_replay();
            else if (!strcmp(buf, "PCAP_STOP")) pcap_close();
            else if (!strcmp(buf, "SEQRESET")) { g_seq_cs = g_seq_sc = UINT64_MAX; }
            else if (!strcmp(buf, "STATS"))
                pipe_log("[STATS] WSASendTo:%ld sendto:%ld WSARecvFrom:%ld recvfrom:%ld pkts:%ld",
                    g_fires_wsa_send, g_fires_send, g_fires_wsa_recv, g_fires_recv, g_pkts_captured);
            else if (!strcmp(buf, "KEYLOG_FLUSH")) {
                EnterCriticalSection(&g_kcs);
                int n = (g_kring_head < 32) ? g_kring_head : 32; int i;
                for (i = n - 1; i >= 0; i--) {
                    int idx = (g_kring_head - 1 - i) & 31;
                    if (g_kring[idx][0])
                        pipe_send(MSG_KEYLOG, g_kring[idx], (uint32_t)strlen(g_kring[idx]) + 1);
                }
                LeaveCriticalSection(&g_kcs);
            }
            else if (!strcmp(buf, "MEMWATCH_STOP")) { g_watch_addr = 0; g_watch_ms = 0; }
            else if (!strncmp(buf, "FUZZ ", 5)) {
                int bits = atoi(buf + 5); InterlockedExchange((LONG*)&g_fuzz_bits, bits);
            }
            else if (!strncmp(buf, "PCAP_START ", 11)) pcap_open(buf + 11);
            else if (!strncmp(buf, "RATELIMIT ", 10)) {
                int cnt = 0, ms = 1000; sscanf(buf + 10, "%d %d", &cnt, &ms);
                RLArgs* a = (RLArgs*)malloc(sizeof(RLArgs));
                if (a) { a->count = cnt; a->ms = ms; CreateThread(NULL, 0, rl_thread, a, 0, NULL); }
            }
            else if (!strncmp(buf, "INJPID ", 7)) {
                g_injector_pid = (DWORD)atoi(buf + 7);
            }
            else if (!strncmp(buf, "MEMWATCH ", 9)) {
                uint64_t waddr = 0; int wms = 250;
                sscanf(buf + 9, "%llx %d", (unsigned long long*) & waddr, &wms);
                g_watch_addr = waddr; g_watch_ms = wms;
                if (g_watch_th) { WaitForSingleObject(g_watch_th, 500); CloseHandle(g_watch_th); }
                g_watch_th = CreateThread(NULL, 0, memwatch_th, NULL, 0, NULL);
            }
            else if (!strncmp(buf, "PKTFORGE ", 9))  pktforge_run(buf + 9);
            else if (!strncmp(buf, "PROCDUMP ", 9)) {
                uint64_t addr = 0; uint32_t size = 0;
                sscanf(buf + 9, "%llx %u", (unsigned long long*) & addr, &size);
                procdump_run(addr, size);
            }
            else if (!strncmp(buf, "PORTSCAN ", 9)) {
                int lo = 5520, hi = 5560; sscanf(buf + 9, "%d %d", &lo, &hi);
                PSArgs* a = (PSArgs*)malloc(sizeof(PSArgs));
                if (a) { a->lo = lo; a->hi = hi; CreateThread(NULL, 0, portscan_th, a, 0, NULL); }
            }
        }
        else { if (pos < (int)sizeof(buf) - 1) buf[pos++] = c; }
    }
    return 0;
}

/* ── IO reconnect thread ─────────────────────────────────── */
static DWORD WINAPI io_thread(LPVOID _) {
    (void)_;

    /* Wait for pipe server to be ready */
    Sleep(1000);

    while (g_active) {
        /* Try to connect to data pipe */
        if (g_out == INVALID_HANDLE_VALUE) {
            HANDLE h = CreateFileW(PIPE_DATA, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

            if (h == INVALID_HANDLE_VALUE && GetLastError() == ERROR_PIPE_BUSY) {
                WaitNamedPipeW(PIPE_DATA, 5000);
                h = CreateFileW(PIPE_DATA, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
            }

            if (h != INVALID_HANDLE_VALUE) {
                DWORD mode = PIPE_READMODE_BYTE;
                SetNamedPipeHandleState(h, &mode, NULL, NULL);

                WaitForSingleObject(g_mutex, INFINITE);
                g_out = h;
                g_pipe_connected = TRUE;
                ReleaseMutex(g_mutex);

                /* Send initial status */
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
                    "HyForceHook/9-%s PID=%lu EXE=%s | "
                    "Hooks:4xWinSock+GQCS+BoringSSL | IOCP+STRINGSCAN+MODLIST+GADGETSCAN+EXPLOIT",
                    arch, (unsigned long)pid, exe[0] ? exe : "?");

                pipe_send(MSG_STATUS, hs, (uint32_t)strlen(hs) + 1);
            }
        }

        /* Check if pipe is still valid */
        if (g_out != INVALID_HANDLE_VALUE) {
            DWORD bytes_avail = 0;
            BOOL ok = PeekNamedPipe(g_out, NULL, 0, NULL, &bytes_avail, NULL);
            if (!ok && GetLastError() == ERROR_BROKEN_PIPE) {
                WaitForSingleObject(g_mutex, INFINITE);
                CloseHandle(g_out);
                g_out = INVALID_HANDLE_VALUE;
                g_pipe_connected = FALSE;
                ReleaseMutex(g_mutex);
            }
        }

        Sleep(500);
    }
    return 0;
}

/* ── Injector monitor ────────────────────────────────────── */
static DWORD WINAPI injector_monitor_th(LPVOID _) {
    (void)_;
    int i;
    for (i = 0; i < 20 && g_injector_pid == 0 && g_active; i++) Sleep(500);
    if (!g_injector_pid) return 0;
    HANDLE hInj = OpenProcess(SYNCHRONIZE, FALSE, g_injector_pid);
    if (!hInj) return 0;
    while (g_active) {
        if (WaitForSingleObject(hInj, 1000) == WAIT_OBJECT_0) {
            CloseHandle(hInj);
            HyForceEject();
            FreeLibraryAndExitThread(GetModuleHandleW(L"HyForceHook.dll"), 0);
            return 0;
        }
    }
    CloseHandle(hInj);
    return 0;
}

/* ── DllMain ─────────────────────────────────────────────── */
BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved) {
    (void)reserved;
    (void)hInst;

    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hInst);

        /* Initialize critical sections first */
        InitializeCriticalSection(&g_cs);
        InitializeCriticalSection(&g_replay_cs);
        InitializeCriticalSection(&g_kcs);
        InitializeCriticalSection(&g_ovl_cs);

        /* Create mutexes */
        g_mutex = CreateMutexW(NULL, FALSE, NULL);
        g_pcap_mutex = CreateMutexW(NULL, FALSE, NULL);
        if (!g_mutex || !g_pcap_mutex) return FALSE;

        /* TLS for reentrancy */
        g_tls_idx = TlsAlloc();

        /* Init structures */
        memset(g_ovl, 0, sizeof(g_ovl));
        init_shm();

        /* Set SSL keylog environment BEFORE any network init */
        SetEnvironmentVariableA("SSLKEYLOGFILE", "C:\\temp\\ssl_keys.log");

        /* Load ws2_32 */
        HMODULE ws2 = GetModuleHandleW(L"ws2_32.dll");
        if (!ws2) ws2 = LoadLibraryW(L"ws2_32.dll");
        if (!ws2) return FALSE;

        /* Get original function addresses */
        orig_WSASendTo = (WSASendTo_t)GetProcAddress(ws2, "WSASendTo");
        orig_WSARecvFrom = (WSARecvFrom_t)GetProcAddress(ws2, "WSARecvFrom");
        orig_sendto = (sendto_t)GetProcAddress(ws2, "sendto");
        orig_recvfrom = (recvfrom_t)GetProcAddress(ws2, "recvfrom");

        /* Install hooks */
        if (orig_WSASendTo) { memcpy(sv_wsa_send, orig_WSASendTo, 14); jmp_write(orig_WSASendTo, hook_WSASendTo); }
        if (orig_WSARecvFrom) { memcpy(sv_wsa_recv, orig_WSARecvFrom, 14); jmp_write(orig_WSARecvFrom, hook_WSARecvFrom); }
        if (orig_sendto) { memcpy(sv_send, orig_sendto, 14); jmp_write(orig_sendto, hook_sendto); }
        if (orig_recvfrom) { memcpy(sv_recv, orig_recvfrom, 14); jmp_write(orig_recvfrom, hook_recvfrom); }

        /* Hook GQCS for IOCP */
        HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
        if (k32) {
            orig_GQCS = (GQCS_t)GetProcAddress(k32, "GetQueuedCompletionStatus");
            if (orig_GQCS) { memcpy(sv_gqcs, orig_GQCS, 14); jmp_write(orig_GQCS, hook_GQCS); }
        }

        /* Hook BoringSSL */
        hook_boringssl();

        /* Start threads */
        g_active = TRUE;
        g_io_th = CreateThread(NULL, 0, io_thread, NULL, 0, NULL);
        g_cmd_th = CreateThread(NULL, 0, cmd_thread, NULL, 0, NULL);
        CreateThread(NULL, 0, hb_thread, NULL, 0, NULL);
        CreateThread(NULL, 0, injector_monitor_th, NULL, 0, NULL);

    }
    else if (reason == DLL_PROCESS_DETACH) {
        g_active = FALSE;

        /* Restore hooks */
        if (orig_WSASendTo)   jmp_restore(orig_WSASendTo, sv_wsa_send);
        if (orig_WSARecvFrom) jmp_restore(orig_WSARecvFrom, sv_wsa_recv);
        if (orig_sendto)      jmp_restore(orig_sendto, sv_send);
        if (orig_recvfrom)    jmp_restore(orig_recvfrom, sv_recv);
        if (orig_GQCS)        jmp_restore(orig_GQCS, sv_gqcs);

        FlushInstructionCache(GetCurrentProcess(), NULL, 0);

        /* Cleanup */
        unhook_boringssl();
        cleanup_shm();
        pcap_close();

        if (g_out != INVALID_HANDLE_VALUE) { CloseHandle(g_out); g_out = INVALID_HANDLE_VALUE; }
        if (g_cmdin != INVALID_HANDLE_VALUE) { CloseHandle(g_cmdin); g_cmdin = INVALID_HANDLE_VALUE; }
        if (g_mutex) CloseHandle(g_mutex);
        if (g_pcap_mutex) CloseHandle(g_pcap_mutex);

        if (g_io_th) { WaitForSingleObject(g_io_th, 500); CloseHandle(g_io_th); }
        if (g_cmd_th) { WaitForSingleObject(g_cmd_th, 500); CloseHandle(g_cmd_th); }
        if (g_watch_th) { WaitForSingleObject(g_watch_th, 500); CloseHandle(g_watch_th); }

        if (g_tls_idx != TLS_OUT_OF_INDEXES) { TlsFree(g_tls_idx); g_tls_idx = TLS_OUT_OF_INDEXES; }

        DeleteCriticalSection(&g_cs);
        DeleteCriticalSection(&g_replay_cs);
        DeleteCriticalSection(&g_kcs);
        DeleteCriticalSection(&g_ovl_cs);
    }

    return TRUE;
}