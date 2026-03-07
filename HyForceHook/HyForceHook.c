/*
 * HyForceHook.dll  v10  —  HyForce Security Research Engine
 *
 * Build x64 MSVC:
 *   cl /O2 /LD /D_WIN32_WINNT=0x0A00 HyForceHook.c /Fe:HyForceHook.dll ws2_32.lib psapi.lib iphlpapi.lib advapi32.lib
 *
 * v10 changes:
 *   + WSASend / send hooks (connected UDP — fixes C2S packet capture)
 *   + Server IP auto-learn from first S2C packet (port-agnostic C2S capture)
 *   + quiche_conn_stream_recv / quiche_conn_stream_send hooks (plaintext pre-encryption)
 *   + SSL_write / SSL_read hooks (BoringSSL plaintext bypass)
 *   + MSG_PLAINTEXT 0x15 — pipes decrypted/pre-encryption app data
 *   + Tighter memscan filter — fixes 250→64 oscillation / false positives
 *   + Socket peer cache for connected UDP dest tracking
 *   + QUICHEPROBE command — scan loaded modules for quiche functions
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
#define MSG_PLAINTEXT   0x15   /* pre-encryption / post-decryption app data */

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
    struct sockaddr_in* peer_ptr;   /* live pointer filled by OS after GQCS */
    LPINT                peer_len;   /* length pointer for recvfrom */
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
static volatile LONG g_fires_wsa_recv = 0, g_fires_wsa_recv2 = 0, g_fires_recv = 0;
static volatile LONG g_pkts_captured = 0;

static volatile uint64_t g_watch_addr = 0;
static volatile int      g_watch_ms = 0;
static HANDLE            g_watch_th = NULL;

/* ── Freeze toggles ───────────────────────────────────────── */
static volatile uint64_t g_freeze_hp_addr = 0;   /* 0 = off */
static volatile float    g_freeze_hp_val = 0.f;
static volatile float    g_freeze_maxhp_val = 0.f;
static HANDLE            g_freeze_hp_th = NULL;
static volatile uint64_t g_freeze_pos_addr = 0;   /* 0 = off */
static volatile double   g_freeze_x = 0, g_freeze_y = 0, g_freeze_z = 0;
static HANDLE            g_freeze_pos_th = NULL;

/* ── Generic value freeze (modular hotkey system) ─────────── */
#define FREEZE_GENERIC_MAX 32
typedef enum { FTYPE_F32 = 0, FTYPE_F64 = 1, FTYPE_I32 = 2, FTYPE_U8 = 3 } FreezeType;
typedef struct {
    volatile uint64_t  addr;
    volatile BOOL      active;
    FreezeType         type;
    union { float f32; double f64; int32_t i32; uint8_t u8; } val;
    int                interval_ms;
} FreezeSlot;
static FreezeSlot       g_freeze_slots[FREEZE_GENERIC_MAX];
static CRITICAL_SECTION g_freeze_cs;
static HANDLE           g_freeze_gen_th = NULL;
static DWORD WINAPI freeze_generic_th(LPVOID _) {
    (void)_;
    while (g_active) {
        int i;
        EnterCriticalSection(&g_freeze_cs);
        for (i = 0; i < FREEZE_GENERIC_MAX; i++) {
            FreezeSlot* s = &g_freeze_slots[i];
            if (!s->active || !s->addr) continue;
            __try {
                switch (s->type) {
                case FTYPE_F32: *(float*)(uintptr_t)s->addr = s->val.f32; break;
                case FTYPE_F64: *(double*)(uintptr_t)s->addr = s->val.f64; break;
                case FTYPE_I32: *(int32_t*)(uintptr_t)s->addr = s->val.i32; break;
                case FTYPE_U8:  *(uint8_t*)(uintptr_t)s->addr = s->val.u8;  break;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) { s->active = FALSE; }
        }
        LeaveCriticalSection(&g_freeze_cs);
        Sleep(50);
    }
    return 0;
}
/* Call once: FREEZE_GENERIC <slot> <addr_hex> <type:f32|f64|i32|u8> <value> <interval_ms>
   slot -1 = find first free slot */
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
/* ── SSL hook forward declarations (defined after probe_boringssl) ───────── */
/* hook_ssl_write / hook_ssl_read forward-declared below after SSL typedefs */

static void freeze_generic_set(int slot, uint64_t addr, const char* type, const char* valstr, int ms) {
    if (slot < 0) {
        int i; for (i = 0; i < FREEZE_GENERIC_MAX; i++) if (!g_freeze_slots[i].active) { slot = i; break; }
    }
    if (slot < 0 || slot >= FREEZE_GENERIC_MAX) return;
    FreezeSlot* s = &g_freeze_slots[slot];
    EnterCriticalSection(&g_freeze_cs);
    s->addr = addr; s->interval_ms = (ms > 0) ? ms : 50; s->active = TRUE;
    if (!strcmp(type, "f32")) { s->type = FTYPE_F32; s->val.f32 = (float)atof(valstr); }
    else if (!strcmp(type, "f64")) { s->type = FTYPE_F64; s->val.f64 = atof(valstr); }
    else if (!strcmp(type, "i32")) { s->type = FTYPE_I32; s->val.i32 = atoi(valstr); }
    else if (!strcmp(type, "u8")) { s->type = FTYPE_U8;  s->val.u8 = (uint8_t)atoi(valstr); }
    LeaveCriticalSection(&g_freeze_cs);
    pipe_log("[FREEZE_GENERIC] slot=%d addr=0x%llx type=%s val=%s interval=%dms",
        slot, (unsigned long long)addr, type, valstr, s->interval_ms);
}
static void freeze_generic_stop(int slot) {
    if (slot < 0) { /* stop all */
        int i; EnterCriticalSection(&g_freeze_cs);
        for (i = 0; i < FREEZE_GENERIC_MAX; i++) g_freeze_slots[i].active = FALSE;
        LeaveCriticalSection(&g_freeze_cs);
    }
    else if (slot < FREEZE_GENERIC_MAX) {
        EnterCriticalSection(&g_freeze_cs);
        g_freeze_slots[slot].active = FALSE;
        LeaveCriticalSection(&g_freeze_cs);
        pipe_log("[FREEZE_GENERIC] slot=%d OFF", slot);
    }
}

static DWORD g_injector_pid = 0;
static volatile BOOL g_pipe_connected = FALSE;

static OvlEntry         g_ovl[MAX_OVL];
static CRITICAL_SECTION g_ovl_cs;

/* Hook function-pointer types */
typedef int (WSAAPI* WSASendTo_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, const struct sockaddr*, int, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI* WSARecvFrom_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, struct sockaddr*, LPINT, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI* WSARecv_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI* sendto_t)(SOCKET, const char*, int, int, const struct sockaddr*, int);
typedef int (WSAAPI* recvfrom_t)(SOCKET, char*, int, int, struct sockaddr*, int*);
typedef BOOL(WINAPI* GQCS_t)(HANDLE, LPDWORD, PULONG_PTR, LPOVERLAPPED*, DWORD);

/* Forward declaration for hook_WSARecv */
int WSAAPI hook_WSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
/* New v10: connected-socket send (no destination address) */
typedef int (WSAAPI* WSASend_nb_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI* send_nb_t)(SOCKET, const char*, int, int);
/* New v10: BoringSSL plaintext bypass */
typedef int (*ssl_write_fn_t)(SSL*, const void*, int);
typedef int (*ssl_read_fn_t)(SSL*, void*, int);
static int hook_ssl_write(SSL* ssl, const void* buf, int num);
static int hook_ssl_read(SSL* ssl, void* buf, int num);
/* New v10: quiche stream hooks (plaintext pre-QUIC-encryption) */
typedef intptr_t(*quiche_stream_recv_t)(void*, uint64_t, uint8_t*, size_t, int*);
typedef intptr_t(*quiche_stream_send_t)(void*, uint64_t, const uint8_t*, size_t, int);

static WSASendTo_t   orig_WSASendTo = NULL;
static WSARecvFrom_t orig_WSARecvFrom = NULL;
static WSARecv_t     orig_WSARecv = NULL;
static sendto_t      orig_sendto = NULL;
static recvfrom_t    orig_recvfrom = NULL;
static GQCS_t        orig_GQCS = NULL;
/* New v10: connected-socket send hooks */
static WSASend_nb_t  orig_WSASend_nb = NULL;
static send_nb_t     orig_send_nb = NULL;
/* New v10: BoringSSL plaintext hooks */
static ssl_write_fn_t orig_ssl_write = NULL;
static ssl_read_fn_t  orig_ssl_read = NULL;
/* New v10: quiche stream hooks */
static quiche_stream_recv_t orig_quiche_recv = NULL;
static quiche_stream_send_t orig_quiche_send = NULL;

static BYTE sv_wsa_send[14], sv_wsa_recv[14], sv_wsa_recv2[14], sv_send[14], sv_recv[14], sv_gqcs[14];
/* New v10 saved bytes */
static BYTE sv_wsa_send_nb[14], sv_send_nb[14];
static BYTE sv_ssl_write[14], sv_ssl_read[14];
static BYTE sv_quiche_recv[14], sv_quiche_send[14];

/* New v10: known server IP (learned from first S2C packet) */
static volatile uint32_t g_server_ip = 0;

/* New v10: connected-socket peer cache */
#define MAX_SOCK_CACHE 32
typedef struct { SOCKET sock; uint32_t ip; uint16_t port; int used; } SockPeer;
static SockPeer         g_sock_cache[MAX_SOCK_CACHE];
static CRITICAL_SECTION g_sock_cs;

/* New v10: fire counters for connected-socket hooks */
static volatile LONG g_fires_wsa_send_nb = 0, g_fires_send_nb = 0;

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
/* New v10 */
static void     sock_cache_set(SOCKET s, uint32_t ip, uint16_t port);
static int      sock_cache_get(SOCKET s, uint32_t* ip, uint16_t* port);
static void     probe_quiche(void);


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
    jmp_write((void*)g_ssl_set, (void*)hook_SSL_CTX_set_kl);

    /* v10: Also hook SSL_write / SSL_read for direct plaintext capture.
     * Note: QUIC uses quiche streams, not SSL_write. These hooks help for
     * any TLS-over-TCP traffic and as a fallback. */
    void* ssl_w = GetProcAddress(mod, "SSL_write");
    if (ssl_w && !orig_ssl_write) {
        orig_ssl_write = (ssl_write_fn_t)ssl_w;
        memcpy(sv_ssl_write, ssl_w, 14);
        jmp_write(ssl_w, (void*)hook_ssl_write);
        pipe_log("[BORING] Hooked SSL_write");
    }
    void* ssl_r = GetProcAddress(mod, "SSL_read");
    if (ssl_r && !orig_ssl_read) {
        orig_ssl_read = (ssl_read_fn_t)ssl_r;
        memcpy(sv_ssl_read, ssl_r, 14);
        jmp_write(ssl_r, (void*)hook_ssl_read);
        pipe_log("[BORING] Hooked SSL_read");
    }
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
    /* v10: restore connected-socket and plaintext hooks */
    if (orig_WSASend_nb)  jmp_restore(orig_WSASend_nb, sv_wsa_send_nb);
    if (orig_send_nb)     jmp_restore(orig_send_nb, sv_send_nb);
    if (orig_ssl_write)   jmp_restore(orig_ssl_write, sv_ssl_write);
    if (orig_ssl_read)    jmp_restore(orig_ssl_read, sv_ssl_read);
    if (orig_quiche_recv) jmp_restore(orig_quiche_recv, sv_quiche_recv);
    if (orig_quiche_send) jmp_restore(orig_quiche_send, sv_quiche_send);
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
    if (dlen <= 0 || dlen > MAX_PKT) return;

    /* Learn server IP from ANY packet with known IP on Hytale port */
    if (ip != 0 && g_server_ip == 0 && is_hytale_port(port)) {
        InterlockedExchange((LONG*)&g_server_ip, (LONG)ip);
        EnterCriticalSection(&g_replay_cs);
        if (g_last_cs_ip == 0) g_last_cs_ip = ip;
        LeaveCriticalSection(&g_replay_cs);
        pipe_log("[HOOK] Server IP learned (dir=%u): %u.%u.%u.%u port %u", dir,
            ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF, ntohs(port));
    }
    /* Also store C2S server IP even after first S2C: update replay IP */
    if (dir == 1 && ip != 0 && g_server_ip == 0) {
        InterlockedExchange((LONG*)&g_server_ip, (LONG)ip);
        EnterCriticalSection(&g_replay_cs);
        if (g_last_cs_ip == 0) g_last_cs_ip = ip;
        LeaveCriticalSection(&g_replay_cs);
    }

    /* Pass if port is in Hytale range OR if IP matches known server */
    int pass = is_hytale_port(port);
    if (!pass && ip != 0) {
        uint32_t sip = g_server_ip;
        uint32_t rip;
        EnterCriticalSection(&g_replay_cs);
        rip = g_last_cs_ip;
        LeaveCriticalSection(&g_replay_cs);
        if ((sip && ip == sip) || (rip && ip == rip)) pass = 1;
    }
    /* QUIC fallback: packet with unknown IP — pass if QUIC fixed bit set (0x40 always set in QUIC).
       Applies to BOTH directions: C2S connected sockets lose IP, S2C IOCP recv fills peer AFTER
       GQCS completion so ovl_register captures zeros. Both cases arrive here with ip=0. */
    if (!pass && ip == 0 && dlen >= 21 && (data[0] & 0x40) != 0)
        pass = 1;
    if (!pass) return;

    InterlockedIncrement(&g_pkts_captured);
    pcap_write(data, (uint32_t)dlen);
    seq_check(data, dlen, dir);

    uint8_t tb[13]; uint64_t ts = now_us(); uint32_t u = (uint32_t)dlen;
    memcpy(tb, &ts, 8); memcpy(tb + 8, &u, 4); tb[12] = dir;
    pipe_send(MSG_TIMING, tb, 13);

    int tot = 7 + dlen;
    uint8_t* buf = (uint8_t*)malloc((size_t)tot);
    if (!buf) return;
    buf[0] = dir;
    memcpy(buf + 1, &ip, 4);
    memcpy(buf + 5, &port, 2);
    memcpy(buf + 7, data, dlen);
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
            g_ovl[i].peer_ptr = peer;  /* OS fills this buffer after GQCS fires */
            g_ovl[i].peer_len = NULL;
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
            struct sockaddr_in* peer_ptr = g_ovl[i].peer_ptr; /* live ptr filled by OS */
            g_ovl[i].used = 0;
            LeaveCriticalSection(&g_ovl_cs);
            if (buf && bytes > 0 && bytes <= (DWORD)bufsz) {
                uint32_t ip = peer.sin_addr.s_addr;
                uint16_t port = peer.sin_port;
                /* After GQCS completes the OS has filled peer_ptr — prefer it over stale copy */
                if (peer_ptr && peer_ptr->sin_family == AF_INET && peer_ptr->sin_addr.s_addr != 0) {
                    ip = peer_ptr->sin_addr.s_addr;
                    port = peer_ptr->sin_port;
                }
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

/* hook_WSARecv implementation - handles connected UDP socket receives */
static int WSAAPI hook_WSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    if (IsReentrant()) return orig_WSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);
    EnterHook(); InterlockedIncrement(&g_fires_wsa_recv2); DWORD se = GetLastError();
    EnterCriticalSection(&g_cs); jmp_restore(orig_WSARecv, sv_wsa_recv2); LeaveCriticalSection(&g_cs);

    int ret = orig_WSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);

    EnterCriticalSection(&g_cs); jmp_write(orig_WSARecv, (void*)hook_WSARecv); LeaveCriticalSection(&g_cs);
    if (ret != SOCKET_ERROR) SetLastError(se);

    /* Handle completed receives immediately (non-IOCP) */
    if (ret == 0 && lpNumberOfBytesRecvd && *lpNumberOfBytesRecvd > 0 && dwBufferCount > 0 && lpBuffers && lpBuffers[0].buf) {
        uint32_t ip = 0; uint16_t port = 0;
        /* Try to get peer info from socket cache or connected socket */
        if (!sock_cache_get(s, &ip, &port)) {
            struct sockaddr_in peer; int pl = sizeof(peer); memset(&peer, 0, sizeof(peer));
            if (getpeername(s, (struct sockaddr*)&peer, &pl) == 0 && peer.sin_family == AF_INET) {
                ip = peer.sin_addr.s_addr; port = peer.sin_port;
                sock_cache_set(s, ip, port);
            }
        }
        if (ip == 0) ip = g_server_ip;
        forward(1, (uint8_t*)lpBuffers[0].buf, (int)*lpNumberOfBytesRecvd, ip, port);
    }

    LeaveHook(); return ret;
}

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
    EnterCriticalSection(&g_cs); jmp_write(orig_WSASendTo, (void*)hook_WSASendTo); LeaveCriticalSection(&g_cs);
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
    EnterCriticalSection(&g_cs); jmp_write(orig_sendto, (void*)hook_sendto); LeaveCriticalSection(&g_cs);
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
        /* Patch: also store the live `from` pointer so ovl_fire can read it post-completion */
        {
            EnterCriticalSection(&g_ovl_cs);
            int oi;
            for (oi = 0; oi < MAX_OVL; oi++) {
                if (g_ovl[oi].used && g_ovl[oi].ov == ov) {
                    g_ovl[oi].peer_ptr = (struct sockaddr_in*)from;
                    break;
                }
            }
            LeaveCriticalSection(&g_ovl_cs);
        }
    }
    int ret = orig_WSARecvFrom(s, bufs, nb, recvd, flags, from, fromlen, ov, cb);
    EnterCriticalSection(&g_cs); jmp_write(orig_WSARecvFrom, (void*)hook_WSARecvFrom); LeaveCriticalSection(&g_cs);
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
    EnterCriticalSection(&g_cs); jmp_write(orig_recvfrom, (void*)hook_recvfrom); LeaveCriticalSection(&g_cs);
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
    EnterCriticalSection(&g_cs); jmp_write(orig_GQCS, (void*)hook_GQCS); LeaveCriticalSection(&g_cs);
    if (ret && ppOv && *ppOv && bytes && *bytes > 0) {
        ovl_fire(*ppOv, *bytes);
    }
    return ret;
}

/* ── Socket peer cache (connected UDP) ───────────────────── */
static void sock_cache_set(SOCKET s, uint32_t ip, uint16_t port) {
    EnterCriticalSection(&g_sock_cs);
    int i, oldest = 0;
    for (i = 0; i < MAX_SOCK_CACHE; i++) {
        if (!g_sock_cache[i].used || g_sock_cache[i].sock == s) { oldest = i; break; }
    }
    g_sock_cache[oldest].sock = s; g_sock_cache[oldest].ip = ip;
    g_sock_cache[oldest].port = port; g_sock_cache[oldest].used = 1;
    LeaveCriticalSection(&g_sock_cs);
}

static int sock_cache_get(SOCKET s, uint32_t* ip, uint16_t* port) {
    int found = 0;
    EnterCriticalSection(&g_sock_cs);
    int i;
    for (i = 0; i < MAX_SOCK_CACHE; i++) {
        if (g_sock_cache[i].used && g_sock_cache[i].sock == s) {
            *ip = g_sock_cache[i].ip; *port = g_sock_cache[i].port; found = 1; break;
        }
    }
    LeaveCriticalSection(&g_sock_cs);
    return found;
}

/* ── WSASend hook (connected UDP — C2S via IOCP) ─────────── */
static int WSAAPI hook_WSASend_nb(SOCKET s, LPWSABUF bufs, DWORD nb, LPDWORD sent, DWORD flags,
    LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cb)
{
    if (IsReentrant() || !orig_WSASend_nb) return orig_WSASend_nb(s, bufs, nb, sent, flags, ov, cb);
    EnterHook(); InterlockedIncrement(&g_fires_wsa_send_nb);
    EnterCriticalSection(&g_cs); jmp_restore(orig_WSASend_nb, sv_wsa_send_nb); LeaveCriticalSection(&g_cs);

    int ret = WSASend(s, bufs, nb, sent, flags, ov, cb);

    EnterCriticalSection(&g_cs); jmp_write(orig_WSASend_nb, (void*)hook_WSASend_nb); LeaveCriticalSection(&g_cs);

    DWORD le = GetLastError();
    int ok = (ret == 0) || (ret == SOCKET_ERROR && le == WSA_IO_PENDING);
    if (ok && nb > 0 && bufs && bufs[0].buf && bufs[0].len > 0) {
        uint32_t ip = 0; uint16_t port = 0;
        /* Try peer cache, then getpeername, then fall back to known server IP */
        if (!sock_cache_get(s, &ip, &port)) {
            struct sockaddr_in peer; int pl = sizeof(peer); memset(&peer, 0, sizeof(peer));
            if (getpeername(s, (struct sockaddr*)&peer, &pl) == 0 && peer.sin_family == AF_INET) {
                ip = peer.sin_addr.s_addr; port = peer.sin_port;
                sock_cache_set(s, ip, port);
            }
        }
        if (ip == 0) ip = g_server_ip; /* best guess */
        forward(0, (uint8_t*)bufs[0].buf, (int)bufs[0].len, ip, port); /* always try */
    }
    LeaveHook(); return ret;
}

/* ── send hook (connected UDP — blocking C2S) ────────────── */
static int WSAAPI hook_send_nb(SOCKET s, const char* buf, int len, int flags)
{
    if (IsReentrant() || !orig_send_nb) return orig_send_nb(s, buf, len, flags);
    EnterHook(); InterlockedIncrement(&g_fires_send_nb);
    EnterCriticalSection(&g_cs); jmp_restore(orig_send_nb, sv_send_nb); LeaveCriticalSection(&g_cs);

    int ret = send(s, buf, len, flags);

    EnterCriticalSection(&g_cs); jmp_write(orig_send_nb, (void*)hook_send_nb); LeaveCriticalSection(&g_cs);

    if (ret > 0 && buf && len > 0) {
        uint32_t ip = 0; uint16_t port = 0;
        if (!sock_cache_get(s, &ip, &port)) {
            struct sockaddr_in peer; int pl = sizeof(peer); memset(&peer, 0, sizeof(peer));
            if (getpeername(s, (struct sockaddr*)&peer, &pl) == 0 && peer.sin_family == AF_INET) {
                ip = peer.sin_addr.s_addr; port = peer.sin_port;
                sock_cache_set(s, ip, port);
            }
        }
        if (ip == 0) ip = g_server_ip;
        forward(0, (uint8_t*)buf, ret, ip, port); /* always try */
    }
    LeaveHook(); return ret;
}

/* ── BoringSSL SSL_write hook (pre-encryption plaintext) ─── */
static int hook_ssl_write(SSL* ssl, const void* buf, int num) {
    if (buf && num > 0 && num < MAX_PKT) {
        uint8_t* pay = (uint8_t*)malloc(1 + (size_t)num);
        if (pay) {
            pay[0] = 0; /* C2S direction */
            memcpy(pay + 1, buf, (size_t)num);
            pipe_send(MSG_PLAINTEXT, pay, 1 + (uint32_t)num);
            free(pay);
        }
    }
    EnterCriticalSection(&g_cs); jmp_restore(orig_ssl_write, sv_ssl_write); LeaveCriticalSection(&g_cs);
    int ret = orig_ssl_write(ssl, buf, num);
    EnterCriticalSection(&g_cs); jmp_write(orig_ssl_write, (void*)hook_ssl_write); LeaveCriticalSection(&g_cs);
    return ret;
}

/* ── BoringSSL SSL_read hook (post-decryption plaintext) ─── */
static int hook_ssl_read(SSL* ssl, void* buf, int num) {
    EnterCriticalSection(&g_cs); jmp_restore(orig_ssl_read, sv_ssl_read); LeaveCriticalSection(&g_cs);
    int ret = orig_ssl_read(ssl, buf, num);
    EnterCriticalSection(&g_cs); jmp_write(orig_ssl_read, (void*)hook_ssl_read); LeaveCriticalSection(&g_cs);
    if (ret > 0 && buf) {
        uint8_t* pay = (uint8_t*)malloc(1 + (size_t)ret);
        if (pay) {
            pay[0] = 1; /* S2C direction */
            memcpy(pay + 1, buf, (size_t)ret);
            pipe_send(MSG_PLAINTEXT, pay, 1 + (uint32_t)ret);
            free(pay);
        }
    }
    return ret;
}

/* ── quiche stream receive hook (plaintext S2C app data) ─── */
static intptr_t hook_quiche_recv(void* conn, uint64_t sid,
    uint8_t* buf, size_t buf_len, int* fin)
{
    EnterCriticalSection(&g_cs); jmp_restore(orig_quiche_recv, sv_quiche_recv); LeaveCriticalSection(&g_cs);
    intptr_t ret = orig_quiche_recv(conn, sid, buf, buf_len, fin);
    EnterCriticalSection(&g_cs); jmp_write(orig_quiche_recv, (void*)hook_quiche_recv); LeaveCriticalSection(&g_cs);
    if (ret > 0 && buf) {
        uint8_t* pay = (uint8_t*)malloc(9 + (size_t)ret);
        if (pay) {
            pay[0] = 1; /* S2C */
            memcpy(pay + 1, &sid, 8);
            memcpy(pay + 9, buf, (size_t)ret);
            pipe_send(MSG_PLAINTEXT, pay, 9 + (uint32_t)ret);
            free(pay);
        }
    }
    return ret;
}

/* ── quiche stream send hook (plaintext C2S app data) ──────── */
static intptr_t hook_quiche_send(void* conn, uint64_t sid,
    const uint8_t* buf, size_t buf_len, int fin)
{
    if (buf && buf_len > 0 && buf_len < (size_t)MAX_PKT) {
        uint8_t* pay = (uint8_t*)malloc(9 + buf_len);
        if (pay) {
            pay[0] = 0; /* C2S */
            memcpy(pay + 1, &sid, 8);
            memcpy(pay + 9, buf, buf_len);
            pipe_send(MSG_PLAINTEXT, pay, 9 + (uint32_t)buf_len);
            free(pay);
        }
    }
    EnterCriticalSection(&g_cs); jmp_restore(orig_quiche_send, sv_quiche_send); LeaveCriticalSection(&g_cs);
    intptr_t ret = orig_quiche_send(conn, sid, buf, buf_len, fin);
    EnterCriticalSection(&g_cs); jmp_write(orig_quiche_send, (void*)hook_quiche_send); LeaveCriticalSection(&g_cs);
    return ret;
}

/* ── probe_quiche: scan loaded modules for quiche functions ─ */
static void probe_quiche(void) {
    HMODULE mods[1024]; DWORD need; int i;
    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &need)) return;
    int n = (int)(need / sizeof(HMODULE));
    int found = 0;
    for (i = 0; i < n; i++) {
        void* fn_r = GetProcAddress(mods[i], "quiche_conn_stream_recv");
        void* fn_s = GetProcAddress(mods[i], "quiche_conn_stream_send");
        if (fn_r && !orig_quiche_recv) {
            orig_quiche_recv = (quiche_stream_recv_t)fn_r;
            memcpy(sv_quiche_recv, fn_r, 14);
            jmp_write(fn_r, (void*)hook_quiche_recv);
            pipe_log("[QUICHE] Hooked quiche_conn_stream_recv @ %p", fn_r);
            found++;
        }
        if (fn_s && !orig_quiche_send) {
            orig_quiche_send = (quiche_stream_send_t)fn_s;
            memcpy(sv_quiche_send, fn_s, 14);
            jmp_write(fn_s, (void*)hook_quiche_send);
            pipe_log("[QUICHE] Hooked quiche_conn_stream_send @ %p", fn_s);
            found++;
        }
        if (found == 2) break;
    }
    if (!found) pipe_log("[QUICHE] No quiche_conn_stream_* exports found (may be inlined in JNI)");
}
/* ── Scan helpers — deliberately relaxed for Hytale/JVM heap ── */
/* Hytale runs on HytaleClient.exe (native launcher wrapping JVM).
   JVM heap objects can be at any address. We scan ALL committed RW memory.
   Filters are wide so we catch even unusual layouts; the UI lets the user
   filter results further.  v11 changes:
     • Y no longer clamped 0-300  (underground areas exist)
     • Health min lowered to > 0.0  (dying entity = 0.1 HP is valid)
     • MaxHP raised to 1 000 000   (boss entities)
     • Coords extended to ±10 000 000  (large open worlds)
     • Velocity extended to ±500 m/s  (mounted/falling)
     • Broad scan mode: skips velocity check entirely             */
static int is_coord(double v) { return !isnan(v) && !isinf(v) && v > -10000000.0 && v < 10000000.0; }
static int is_health(float h) { return !isnan(h) && !isinf(h) && h >= 1.0f && h <= 500000.0f; }
static int is_vel(float v) { return !isnan(v) && !isinf(v) && v > -500.0f && v < 500.0f; }

/* Send a 76-byte memscan hit payload: [u64 addr][u32 dataSize][bytes] */
static void send_memscan_hit(uint8_t* p, SIZE_T avail) {
    uint8_t rep[76]; uint64_t a64 = (uint64_t)(uintptr_t)p; uint32_t sz = 56;
    memcpy(rep, &a64, 8); memcpy(rep + 8, &sz, 4);
    SIZE_T cp = (sz < (uint32_t)avail) ? sz : avail;
    if (cp > 56) cp = 56;
    memcpy(rep + 12, p, cp);
    pipe_send(MSG_MEMSCAN, rep, (uint32_t)(12 + cp));
}

/* strict scan: requires plausible velocity (standing still = 0 → passes) */
static void memscan_run(void) {
    int hits = 0;
    MEMORY_BASIC_INFORMATION mbi;
    uint8_t* addr = NULL;
    pipe_log("[MEMSCAN] Starting strict scan on HytaleClient.exe memory...");
    while (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        uint8_t* next = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;
        /* scan all committed RW regions — no size filter removed */
        if (mbi.State != MEM_COMMIT ||
            (mbi.Protect & PAGE_GUARD) || (mbi.Protect & PAGE_NOACCESS) ||
            !(mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
        {
            addr = next; continue;
        }
        uint8_t* base = (uint8_t*)mbi.BaseAddress; SIZE_T rsz = mbi.RegionSize;
        __try {
            SIZE_T off;
            for (off = 0; off + 44 <= rsz; off += 4) {
                uint8_t* p = base + off;
                float h = *(float*)(p + 0), mh = *(float*)(p + 4);
                if (!is_health(h) || !is_health(mh)) continue;
                if (mh < h * 0.001f) continue;          /* ratio guard only */
                double x = *(double*)(p + 8), y = *(double*)(p + 16), z = *(double*)(p + 24);
                if (!is_coord(x) || !is_coord(y) || !is_coord(z)) continue;
                if (x == 0.0 && y == 0.0 && z == 0.0) continue; /* uninitialized */
                float vx = *(float*)(p + 32), vy = *(float*)(p + 36), vz = *(float*)(p + 40);
                if (!is_vel(vx) || !is_vel(vy) || !is_vel(vz)) continue;
                send_memscan_hit(p, rsz - off);
                if (++hits >= 128) goto memscan_done;
                off += 40; /* skip past matched struct */
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        addr = next;
    }
memscan_done:
    pipe_log("[MEMSCAN] Done: %d hits", hits);
}

/* broad scan: no velocity requirement, any health+coord will match */
static void memscan_broad_impl(void);
static DWORD WINAPI memscan_broad_th(LPVOID _) { (void)_; memscan_broad_impl(); return 0; }
static void memscan_broad_impl(void) {
    int hits = 0;
    MEMORY_BASIC_INFORMATION mbi;
    uint8_t* addr = NULL;
    pipe_log("[MEMSCAN] Starting BROAD scan...");
    while (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        uint8_t* next = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;
        if (mbi.State != MEM_COMMIT ||
            (mbi.Protect & PAGE_GUARD) || (mbi.Protect & PAGE_NOACCESS) ||
            !(mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
        {
            addr = next; continue;
        }
        uint8_t* base = (uint8_t*)mbi.BaseAddress; SIZE_T rsz = mbi.RegionSize;
        __try {
            SIZE_T off;
            for (off = 0; off + 32 <= rsz; off += 4) {
                uint8_t* p = base + off;
                float h = *(float*)(p + 0), mh = *(float*)(p + 4);
                if (!is_health(h) || !is_health(mh)) continue;
                double x = *(double*)(p + 8), y = *(double*)(p + 16), z = *(double*)(p + 24);
                if (!is_coord(x) || !is_coord(y) || !is_coord(z)) continue;
                if (x == 0.0 && y == 0.0 && z == 0.0) continue;
                send_memscan_hit(p, rsz - off);
                if (++hits >= 256) goto broad_done;
                off += 28;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        addr = next;
    }
broad_done:
    pipe_log("[MEMSCAN] Broad done: %d hits", hits);
}

/* ── Direct memory read: MEMREAD <addr_hex> <size> → MSG_MEMREAD ── */
#define MSG_MEMREAD 0x1C
static void memread_addr(uint64_t addr, uint32_t sz) {
    if (sz > 4096) sz = 4096;
    uint8_t* buf = (uint8_t*)malloc(8 + sz);
    if (!buf) return;
    memcpy(buf, &addr, 8);
    __try { memcpy(buf + 8, (void*)(uintptr_t)addr, sz); }
    __except (EXCEPTION_EXECUTE_HANDLER) { memset(buf + 8, 0xCC, sz); }
    pipe_send(MSG_MEMREAD, buf, 8 + sz);
    free(buf);
}

/* ── Direct f64 write ── */
static void memwrite_f64(uint64_t addr, double val) {
    __try { *(double*)(uintptr_t)addr = val; pipe_log("[WRITE] f64 @ 0x%llx = %f", (unsigned long long)addr, val); }
    __except (EXCEPTION_EXECUTE_HANDLER) { pipe_log("[WRITE] f64 AV @ 0x%llx", (unsigned long long)addr); }
}

/* ── Direct i32 write ── */
static void memwrite_i32(uint64_t addr, int32_t val) {
    __try { *(int32_t*)(uintptr_t)addr = val; pipe_log("[WRITE] i32 @ 0x%llx = %d", (unsigned long long)addr, val); }
    __except (EXCEPTION_EXECUTE_HANDLER) { pipe_log("[WRITE] i32 AV @ 0x%llx", (unsigned long long)addr); }
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
            uint8_t pay[72]; uint64_t _wa = g_watch_addr; memcpy(pay, &_wa, 8); memcpy(pay + 8, cur, 64);
            pipe_send(MSG_MEMWATCH, pay, 72); memcpy(prev, cur, 64); first = 0;
        }
    }
    return 0;
}

/* ── Freeze HP thread — writes health+maxHP every 50ms ────── */
static DWORD WINAPI freeze_hp_th(LPVOID _) {
    (void)_;
    while (g_active && g_freeze_hp_addr) {
        __try {
            float* hp = (float*)(uintptr_t)g_freeze_hp_addr;
            float* mhp = hp + 1;          /* maxHealth is at offset +4 */
            *hp = g_freeze_hp_val;
            *mhp = g_freeze_maxhp_val;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { g_freeze_hp_addr = 0; break; }
        Sleep(50);
    }
    return 0;
}

/* ── Freeze Position thread — writes X/Y/Z every 50ms ────── */
static DWORD WINAPI freeze_pos_th(LPVOID _) {
    (void)_;
    while (g_active && g_freeze_pos_addr) {
        __try {
            /* layout: float hp(0), float maxhp(4), double X(8), double Y(16), double Z(24) */
            double* px = (double*)(uintptr_t)(g_freeze_pos_addr + 8);
            double* py = (double*)(uintptr_t)(g_freeze_pos_addr + 16);
            double* pz = (double*)(uintptr_t)(g_freeze_pos_addr + 24);
            *px = g_freeze_x; *py = g_freeze_y; *pz = g_freeze_z;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { g_freeze_pos_addr = 0; break; }
        Sleep(50);
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
        pipe_log("[STATS] WSASendTo:%ld sendto:%ld WSARecvFrom:%ld recvfrom:%ld "
            "WSASend_nb:%ld send_nb:%ld pkts:%ld srvIP:%u.%u.%u.%u",
            g_fires_wsa_send, g_fires_send, g_fires_wsa_recv, g_fires_recv,
            g_fires_wsa_send_nb, g_fires_send_nb, g_pkts_captured,
            g_server_ip & 0xFF, (g_server_ip >> 8) & 0xFF,
            (g_server_ip >> 16) & 0xFF, (g_server_ip >> 24) & 0xFF);
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
            else if (!strcmp(buf, "PING"))    pipe_send(MSG_STATUS, "PONG", 5);
            else if (!strcmp(buf, "STOP"))    g_active = FALSE;
            else if (!strcmp(buf, "EJECT"))   HyForceEject();
            else if (!strcmp(buf, "MEMSCAN")) CreateThread(NULL, 0, memscan_th, NULL, 0, NULL);
            else if (!strcmp(buf, "MEMSCAN_BROAD")) { CreateThread(NULL, 0, memscan_broad_th, NULL, 0, NULL); }
            else if (!strncmp(buf, "MEMREAD ", 8)) {
                uint64_t ra = 0; uint32_t rsz2 = 64;
                sscanf(buf + 8, "%llx %u", (unsigned long long*) & ra, &rsz2);
                memread_addr(ra, rsz2);
            }
            else if (!strncmp(buf, "MEMWRITE_F64 ", 13)) {
                uint64_t addr = 0; double val = 0.0;
                sscanf(buf + 13, "%llx %lf", (unsigned long long*) & addr, &val);
                memwrite_f64(addr, val);
            }
            else if (!strncmp(buf, "MEMWRITE_I32 ", 13)) {
                uint64_t addr = 0; int32_t val = 0;
                sscanf(buf + 13, "%llx %d", (unsigned long long*) & addr, &val);
                memwrite_i32(addr, val);
            }
            else if (!strncmp(buf, "MEMWRITE_U8 ", 12)) {
                uint64_t addr = 0; int val = 0;
                sscanf(buf + 12, "%llx %d", (unsigned long long*) & addr, &val);
                __try { *(uint8_t*)(uintptr_t)addr = (uint8_t)val; pipe_log("[WRITE] u8 @ 0x%llx = %d", (unsigned long long)addr, val); }
                __except (EXCEPTION_EXECUTE_HANDLER) { pipe_log("[WRITE] u8 AV @ 0x%llx", (unsigned long long)addr); }
            }
            else if (!strcmp(buf, "STRINGSCAN")) CreateThread(NULL, 0, stringscan_th, NULL, 0, NULL);
            else if (!strcmp(buf, "MODLIST")) CreateThread(NULL, 0, modlist_th, NULL, 0, NULL);
            else if (!strcmp(buf, "THREADLIST")) CreateThread(NULL, 0, threadlist_th, NULL, 0, NULL);
            else if (!strcmp(buf, "GADGETSCAN")) CreateThread(NULL, 0, gadgetscan_th, NULL, 0, NULL);
            else if (!strcmp(buf, "EXPLOITPROBE")) CreateThread(NULL, 0, exploitprobe_th, NULL, 0, NULL);
            else if (!strcmp(buf, "SOCKENUM")) sockenum_run();
            else if (!strcmp(buf, "REPLAY"))  do_replay();
            else if (!strcmp(buf, "PCAP_STOP")) pcap_close();
            else if (!strcmp(buf, "SEQRESET")) { g_seq_cs = g_seq_sc = UINT64_MAX; }
            else if (!strcmp(buf, "QUICHEPROBE")) probe_quiche(); /* v10 */
            else if (!strcmp(buf, "STATS"))
                pipe_log("[STATS] WSASendTo:%ld sendto:%ld WSARecvFrom:%ld WSARecv:%ld recvfrom:%ld pkts:%ld",
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
            /* ── Freeze / write commands ────────────────────────── */
            else if (!strncmp(buf, "FREEZE_HP ", 10)) {
                /* FREEZE_HP <addr_hex> <hp_float> <maxhp_float> */
                uint64_t addr = 0; float hp = 100.f, mhp = 100.f;
                sscanf(buf + 10, "%llx %f %f", (unsigned long long*) & addr, &hp, &mhp);
                g_freeze_hp_addr = addr; g_freeze_hp_val = hp; g_freeze_maxhp_val = mhp;
                if (g_freeze_hp_th) { WaitForSingleObject(g_freeze_hp_th, 300); CloseHandle(g_freeze_hp_th); }
                g_freeze_hp_th = CreateThread(NULL, 0, freeze_hp_th, NULL, 0, NULL);
                pipe_log("[FREEZE] HP freeze ON @ 0x%llx  hp=%.1f maxhp=%.1f", (unsigned long long)addr, hp, mhp);
            }
            else if (!strcmp(buf, "FREEZE_HP_STOP")) {
                g_freeze_hp_addr = 0;
                pipe_log("[FREEZE] HP freeze OFF");
            }
            else if (!strncmp(buf, "FREEZE_POS ", 11)) {
                /* FREEZE_POS <addr_hex> <x> <y> <z>  (doubles) */
                uint64_t addr = 0; double x = 0, y = 0, z = 0;
                sscanf(buf + 11, "%llx %lf %lf %lf", (unsigned long long*) & addr, &x, &y, &z);
                g_freeze_pos_addr = addr; g_freeze_x = x; g_freeze_y = y; g_freeze_z = z;
                if (g_freeze_pos_th) { WaitForSingleObject(g_freeze_pos_th, 300); CloseHandle(g_freeze_pos_th); }
                g_freeze_pos_th = CreateThread(NULL, 0, freeze_pos_th, NULL, 0, NULL);
                pipe_log("[FREEZE] Pos freeze ON @ 0x%llx  (%.2f, %.2f, %.2f)", (unsigned long long)addr, x, y, z);
            }
            else if (!strcmp(buf, "FREEZE_POS_STOP")) {
                g_freeze_pos_addr = 0;
                pipe_log("[FREEZE] Pos freeze OFF");
            }
            else if (!strncmp(buf, "MEMWRITE_F32 ", 13)) {
                /* MEMWRITE_F32 <addr_hex> <value_float>  — one-shot float write */
                uint64_t addr = 0; float val = 0.f;
                sscanf(buf + 13, "%llx %f", (unsigned long long*) & addr, &val);
                __try { *(float*)(uintptr_t)addr = val; pipe_log("[WRITE] f32 @ 0x%llx = %.6f", (unsigned long long)addr, val); }
                __except (EXCEPTION_EXECUTE_HANDLER) { pipe_log("[WRITE] f32 access violation @ 0x%llx", (unsigned long long)addr); }
            }
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
            else if (!strncmp(buf, "MEMWRITE_I32 ", 13)) {
                uint64_t addr = 0; int32_t val = 0;
                sscanf(buf + 13, "%llx %d", (unsigned long long*) & addr, &val);
                memwrite_i32(addr, val);
            }
            else if (!strncmp(buf, "FLYMODE ", 8)) {
                uint64_t addr = 0; char onoff[8] = { 0 };
                sscanf(buf + 8, "%llx %7s", (unsigned long long*) & addr, onoff);
                int enable = (onoff[0] == '1');
                float zero = 0.0f;
                if (enable) {
                    __try { *(float*)(uintptr_t)(addr + 36) = zero; }
                    __except (EXCEPTION_EXECUTE_HANDLER) {}
                }
                pipe_log("[FLY] %s @ 0x%llx", enable ? "ON" : "OFF", (unsigned long long)addr);
            }
            /* FREEZE_GENERIC <slot> <addr_hex> <type> <value> <interval_ms>
               slot=-1 for auto-slot. type: f32|f64|i32|u8 */
            else if (!strncmp(buf, "FREEZE_GENERIC ", 15)) {
                int slot = -1; uint64_t addr = 0;
                char type[8] = { 0 }, valstr[32] = { 0 }; int ms = 50;
                sscanf(buf + 15, "%d %llx %7s %31s %d",
                    &slot, (unsigned long long*) & addr, type, valstr, &ms);
                freeze_generic_set(slot, addr, type, valstr, ms);
            }
            else if (!strncmp(buf, "FREEZE_GENERIC_STOP ", 20)) {
                int slot = -1;
                sscanf(buf + 20, "%d", &slot);
                freeze_generic_stop(slot);
            }
            else if (!strcmp(buf, "FREEZE_ALL_STOP")) {
                freeze_generic_stop(-1);
                g_freeze_hp_addr = 0;
                g_freeze_pos_addr = 0;
                pipe_log("[FREEZE] All freezes stopped");
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
                    "HyForceHook/10-%s PID=%lu EXE=%s | "
                    "Hooks:6xWinSock+GQCS+BoringSSL+QuicheProbe | "
                    "IOCP+STRINGSCAN+MODLIST+GADGETSCAN+EXPLOIT+PLAINTEXT",
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
        InitializeCriticalSection(&g_sock_cs); /* v10 */
        InitializeCriticalSection(&g_freeze_cs); /* v11 generic freeze */
        memset(g_freeze_slots, 0, sizeof(g_freeze_slots));
        g_freeze_gen_th = CreateThread(NULL, 0, freeze_generic_th, NULL, 0, NULL);

        /* Create mutexes */
        g_mutex = CreateMutexW(NULL, FALSE, NULL);
        g_pcap_mutex = CreateMutexW(NULL, FALSE, NULL);
        if (!g_mutex || !g_pcap_mutex) return FALSE;

        /* TLS for reentrancy */
        g_tls_idx = TlsAlloc();

        /* Init structures */
        memset(g_ovl, 0, sizeof(g_ovl));
        memset(g_sock_cache, 0, sizeof(g_sock_cache)); /* v10 */
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
        orig_WSARecv = (WSARecv_t)GetProcAddress(ws2, "WSARecv");
        orig_sendto = (sendto_t)GetProcAddress(ws2, "sendto");
        orig_recvfrom = (recvfrom_t)GetProcAddress(ws2, "recvfrom");

        /* Install hooks */
        if (orig_WSASendTo) { memcpy(sv_wsa_send, orig_WSASendTo, 14); jmp_write(orig_WSASendTo, (void*)hook_WSASendTo); }
        if (orig_WSARecvFrom) { memcpy(sv_wsa_recv, orig_WSARecvFrom, 14); jmp_write(orig_WSARecvFrom, (void*)hook_WSARecvFrom); }
        if (orig_WSARecv) { memcpy(sv_wsa_recv2, orig_WSARecv, 14); jmp_write(orig_WSARecv, (void*)hook_WSARecv); }
        if (orig_sendto) { memcpy(sv_send, orig_sendto, 14); jmp_write(orig_sendto, (void*)hook_sendto); }
        if (orig_recvfrom) { memcpy(sv_recv, orig_recvfrom, 14); jmp_write(orig_recvfrom, (void*)hook_recvfrom); }

        /* v10: Hook WSASend and send for connected UDP sockets (C2S fix) */
        orig_WSASend_nb = (WSASend_nb_t)GetProcAddress(ws2, "WSASend");
        if (orig_WSASend_nb) { memcpy(sv_wsa_send_nb, orig_WSASend_nb, 14); jmp_write(orig_WSASend_nb, (void*)hook_WSASend_nb); }
        orig_send_nb = (send_nb_t)GetProcAddress(ws2, "send");
        if (orig_send_nb) { memcpy(sv_send_nb, orig_send_nb, 14); jmp_write(orig_send_nb, (void*)hook_send_nb); }

        /* Hook GQCS for IOCP */
        HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
        if (k32) {
            orig_GQCS = (GQCS_t)GetProcAddress(k32, "GetQueuedCompletionStatus");
            if (orig_GQCS) { memcpy(sv_gqcs, orig_GQCS, 14); jmp_write(orig_GQCS, (void*)hook_GQCS); }
        }

        /* Hook BoringSSL */
        hook_boringssl();

        /* v10: Probe for quiche functions immediately and again after delay */
        probe_quiche();

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
        if (orig_WSARecv)     jmp_restore(orig_WSARecv, sv_wsa_recv2);
        if (orig_sendto)      jmp_restore(orig_sendto, sv_send);
        if (orig_recvfrom)    jmp_restore(orig_recvfrom, sv_recv);
        if (orig_GQCS)        jmp_restore(orig_GQCS, sv_gqcs);
        /* v10 */
        if (orig_WSASend_nb)  jmp_restore(orig_WSASend_nb, sv_wsa_send_nb);
        if (orig_send_nb)     jmp_restore(orig_send_nb, sv_send_nb);
        if (orig_ssl_write)   jmp_restore(orig_ssl_write, sv_ssl_write);
        if (orig_ssl_read)    jmp_restore(orig_ssl_read, sv_ssl_read);
        if (orig_quiche_recv) jmp_restore(orig_quiche_recv, sv_quiche_recv);
        if (orig_quiche_send) jmp_restore(orig_quiche_send, sv_quiche_send);

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
        g_freeze_hp_addr = 0; g_freeze_pos_addr = 0;
        if (g_freeze_hp_th) { WaitForSingleObject(g_freeze_hp_th, 300); CloseHandle(g_freeze_hp_th); }
        if (g_freeze_pos_th) { WaitForSingleObject(g_freeze_pos_th, 300); CloseHandle(g_freeze_pos_th); }

        if (g_tls_idx != TLS_OUT_OF_INDEXES) { TlsFree(g_tls_idx); g_tls_idx = TLS_OUT_OF_INDEXES; }

        DeleteCriticalSection(&g_cs);
        DeleteCriticalSection(&g_replay_cs);
        DeleteCriticalSection(&g_kcs);
        DeleteCriticalSection(&g_ovl_cs);
        DeleteCriticalSection(&g_sock_cs); /* v10 */
    }

    return TRUE;
}