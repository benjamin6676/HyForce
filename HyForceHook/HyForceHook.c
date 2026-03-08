/*
 * HyForceHook.dll  v20  —  Production-Ready Hytale Security Research Engine
 *
 * Build x64 MSVC:
 *   cl /O2 /LD /D_WIN32_WINNT=0x0A00 /D_CRT_SECURE_NO_WARNINGS HyForceHook.c /Fe:HyForceHook.dll ws2_32.lib psapi.lib iphlpapi.lib advapi32.lib ntdll.lib shlwapi.lib
 *
 * v20 changes (over v14 enhanced base):
 *   + CRITICAL: hook_WSARecv registers overlapped BEFORE calling orig — GQCS/ovl_fire now sees WSARecv packets
 *   + CRITICAL: ovl_fire dereferences peer_ptr after GQCS (WSARecvFrom path); uses copy for WSARecv (connected) path
 *   + FIXED: pkts counter now increments on MSQUIC connected-socket S2C traffic
 *   + FIXED: STATS heartbeat includes WSARecv counter
 *   + FIXED: HP filter returns true (unknown) instead of false (exclude) when packet too short to sample
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

/* ═══════════════════════════════════════════════════════════════════
 * MSQUIC PLAINTEXT BYPASS  (v16)
 * ═══════════════════════════════════════════════════════════════════ */

#define MSG_QUIC_STREAM  0x16  /* plaintext stream data: [u8 dir][u64 stream_id][u32 len][data] */
#define MSG_QUIC_EVENT   0x17  /* stream lifecycle event: [u8 ev_type][u64 stream_id] */

/* ── Minimal msquic type definitions ─────────────────────────────── */
typedef void* HQUIC;
typedef uint32_t QUIC_STATUS;
#define QUIC_STATUS_SUCCESS    0u
#define QUIC_STREAM_EVENT_RECEIVE              1u
#define QUIC_STREAM_EVENT_SEND_COMPLETE        2u
#define QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE    7u
#define QUIC_STREAM_OPEN_FLAG_NONE             0u
#define QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL   1u
#define QUIC_STREAM_START_FLAG_IMMEDIATE       1u
#define QUIC_SEND_FLAG_FIN                     1u

typedef struct { uint32_t Length; uint8_t* Buffer; } QUIC_BUF;

typedef struct {
    /* RECEIVE fields at offset 8 in the union (Type field = 4B + 4B pad) */
    uint64_t AbsoluteOffset;
    uint64_t TotalBufferLength;
    QUIC_BUF* Buffers;
    uint32_t  BufferCount;
    uint32_t  Flags;
} QUIC_STREAM_RECEIVE_DATA;

typedef struct {
    uint32_t Type;
    uint32_t _pad;
    union {
        QUIC_STREAM_RECEIVE_DATA RECEIVE;
        uint8_t raw[128];
    };
} QUIC_STREAM_EVENT;

typedef QUIC_STATUS (WINAPI* QUIC_STREAM_CB)(HQUIC Stream, void* Ctx, QUIC_STREAM_EVENT* Ev);
typedef QUIC_STATUS (WINAPI* QUIC_STREAM_OPEN_FN)(HQUIC Conn, uint32_t Flags, QUIC_STREAM_CB Handler, void* Ctx, HQUIC* Stream);
typedef QUIC_STATUS (WINAPI* QUIC_STREAM_START_FN)(HQUIC Stream, uint32_t Flags);
typedef QUIC_STATUS (WINAPI* QUIC_STREAM_SEND_FN)(HQUIC Stream, const QUIC_BUF* Bufs, uint32_t Count, uint32_t Flags, void* SendCtx);
typedef void        (WINAPI* QUIC_STREAM_RECV_COMPLETE_FN)(HQUIC Stream, uint64_t Len);
typedef void        (WINAPI* QUIC_STREAM_CLOSE_FN)(HQUIC Stream);
typedef QUIC_STATUS (WINAPI* MsQuicOpenVersion_t)(uint32_t Version, const void** ApiTable);

/* QUIC_API_TABLE — partial layout, only entries we need */
typedef struct {
    void* fn[21];                              /* [0..20] SetContext..ConnectionSendResumptionTicket */
    QUIC_STREAM_OPEN_FN      StreamOpen;       /* [21] */
    QUIC_STREAM_CLOSE_FN     StreamClose;      /* [22] */
    QUIC_STREAM_START_FN     StreamStart;      /* [23] */
    void*                    StreamShutdown;   /* [24] */
    QUIC_STREAM_SEND_FN      StreamSend;       /* [25] */
    QUIC_STREAM_RECV_COMPLETE_FN StreamReceiveComplete; /* [26] */
    void* fn_rest[16];
} HF_QUIC_API;

/* ── Stream registry ─────────────────────────────────────────────── */
#define STREAM_REG_MAX 256
typedef struct {
    HQUIC          handle;
    QUIC_STREAM_CB real_cb;
    void*          real_ctx;
    HQUIC          conn;
    volatile BOOL  used;
} StreamReg;

/* ═══════════════════════════════════════════════════════════════════
 * GLOBAL VARIABLES
 * ═══════════════════════════════════════════════════════════════════ */

/* ── Core globals ─────────────────────────────────────────── */
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

static DWORD g_injector_pid = 0;
static volatile BOOL g_pipe_connected = FALSE;

static OvlEntry         g_ovl[MAX_OVL];
static CRITICAL_SECTION g_ovl_cs;

/* ── Hook function-pointer types ─────────────────────────── */
typedef int (WSAAPI* WSASendTo_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, const struct sockaddr*, int, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI* WSARecvFrom_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, struct sockaddr*, LPINT, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI* WSARecv_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI* sendto_t)(SOCKET, const char*, int, int, const struct sockaddr*, int);
typedef int (WSAAPI* recvfrom_t)(SOCKET, char*, int, int, struct sockaddr*, int*);
typedef BOOL(WINAPI* GQCS_t)(HANDLE, LPDWORD, PULONG_PTR, LPOVERLAPPED*, DWORD);

/* ── v10: connected-socket send (no destination address) ─── */
typedef int (WSAAPI* WSASend_nb_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI* send_nb_t)(SOCKET, const char*, int, int);

/* ── v10: BoringSSL plaintext bypass ─────────────────────── */
typedef int (*ssl_write_fn_t)(SSL*, const void*, int);
typedef int (*ssl_read_fn_t)(SSL*, void*, int);

/* ── v10: quiche stream hooks (plaintext pre-QUIC-encryption) */
typedef intptr_t(*quiche_stream_recv_t)(void*, uint64_t, uint8_t*, size_t, int*);
typedef intptr_t(*quiche_stream_send_t)(void*, uint64_t, const uint8_t*, size_t, int);

/* ── Hook function pointers ──────────────────────────────── */
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

/* Saved bytes for hook restoration */
static BYTE sv_wsa_send[14], sv_wsa_recv[14], sv_wsa_recv2[14], sv_send[14], sv_recv[14], sv_gqcs[14];
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

/* ═══════════════════════════════════════════════════════════════════
 * MSQUIC GLOBALS (v16+)
 * ═══════════════════════════════════════════════════════════════════ */

/* ── msquic globals ──────────────────────────────────────────────── */
static HF_QUIC_API*          g_msquic_real   = NULL;  /* pointer to real table */
static HF_QUIC_API           g_msquic_shadow;          /* our writable shadow copy */
static volatile BOOL         g_msquic_hooked = FALSE;
static MsQuicOpenVersion_t   orig_MsQuicOpen = NULL;
static BYTE                  sv_msquic_open[14];
static HQUIC                 g_msquic_conn   = NULL;   /* last seen connection (for inject) */
static CRITICAL_SECTION      g_stream_cs;              /* protects stream registry + conn */
static CRITICAL_SECTION      g_quic_cs;
static CRITICAL_SECTION      g_quic_ctx_cs;
static CRITICAL_SECTION      g_http3_cs;

/* ── Stream registry ─────────────────────────────────────────────── */
static StreamReg g_streams[STREAM_REG_MAX];

/* ── Stream testing controls ─────────────────────────────────────── */
static volatile int  g_stream_race_ms   = 0;
static volatile int  g_stream_fuzz_bits = 0;
static volatile int  g_stream_dup_count = 0;
static volatile BOOL g_stream_drop_next = FALSE;

/* ── C2S filter controls (client→server interception) ─────────────── */
static volatile uint32_t g_c2s_drop_opcode  = 0;
static volatile uint32_t g_c2s_dup_opcode   = 0;
static volatile int      g_c2s_dup_count    = 0;
static volatile BOOL     g_c2s_log_enabled  = FALSE;
static volatile LONG     g_c2s_drops_total  = 0;
static volatile LONG     g_c2s_dups_total   = 0;

/* ── S2C stream-level opcode drop filter ──────────────────────────── */
static volatile uint32_t g_s2c_drop_opcode  = 0;
static volatile LONG     g_s2c_drops_total  = 0;

/* ── v18 globals ─────────────────────────────────────────────────── */
static volatile BOOL g_auto_pong         = FALSE;
static volatile LONG g_pong_count        = 0;
static volatile BOOL g_trade_capture     = FALSE;

/* Packet recorder ring */
#define RECORD_MAX_FRAMES  2048
#define RECORD_MAX_BYTES   (4*1024*1024)
static uint8_t  g_record_buf[RECORD_MAX_BYTES];
static uint32_t g_record_offsets[RECORD_MAX_FRAMES];
static uint32_t g_record_sizes[RECORD_MAX_FRAMES];
static int      g_record_head   = 0;
static int      g_record_count  = 0;
static uint32_t g_record_bytes  = 0;
static volatile BOOL g_record_enabled = FALSE;
static CRITICAL_SECTION g_record_cs;

/* ── Position / speed override (ClientMovement 0x6C patcher) ──────── */
static volatile BOOL  g_pos_override   = FALSE;
static volatile float g_override_x     = 0.f;
static volatile float g_override_y     = 0.f;
static volatile float g_override_z     = 0.f;
static volatile float g_speed_mul      = 1.f;
static volatile BOOL  g_one_shot_tp    = FALSE;
static volatile LONG  g_tp_sent        = 0;

#define MOVEMENT_BUF_MAX 512
static uint8_t g_last_movement[MOVEMENT_BUF_MAX];
static int     g_last_movement_len = 0;
static CRITICAL_SECTION g_movement_cs;

/* ── Stream replay ring ──────────────────────────────────────────── */
#define STREAM_REPLAY_MAX 8192
static uint8_t g_stream_last[STREAM_REPLAY_MAX];
static int     g_stream_last_len   = 0;
static HQUIC   g_stream_last_handle = NULL;

/* ═══════════════════════════════════════════════════════════════════
 * v19 GLOBALS
 * ═══════════════════════════════════════════════════════════════════ */

static volatile BOOL     g_launch_armed    = FALSE;
static volatile float    g_launch_vx       = 0.f;
static volatile float    g_launch_vy       = 0.f;
static volatile float    g_launch_vz       = 0.f;
static volatile BOOL     g_spectate_mode   = FALSE;
static volatile BOOL     g_noclip          = FALSE;
static volatile BOOL     g_inf_reach       = FALSE;
static volatile BOOL     g_prop_scan_active= FALSE;
static volatile uint64_t g_prop_scan_eid   = 0;
static volatile int      g_prop_scan_idx   = 0;

/* ═══════════════════════════════════════════════════════════════════
 * v20 GLOBALS
 * ═══════════════════════════════════════════════════════════════════ */

/* Inventory lock */
static volatile BOOL     g_inv_lock        = FALSE;
static uint8_t*          g_inv_cache       = NULL;
static uint32_t          g_inv_cache_len   = 0;
static CRITICAL_SECTION  g_inv_cs;

/* PlayerSetup cache */
#define SETUP_MAX 4096
static uint8_t           g_last_player_setup[SETUP_MAX];
static uint32_t          g_last_player_setup_len = 0;
static CRITICAL_SECTION  g_setup_cs;

/* Item spam thread */
static volatile BOOL     g_item_spam_active = FALSE;
static volatile uint32_t g_item_spam_typeid = 0;
static volatile uint32_t g_item_spam_slot   = 0;
static volatile uint32_t g_item_spam_count  = 1;
static volatile uint32_t g_item_spam_delay  = 500;
static volatile LONG     g_item_spam_sent   = 0;
static HANDLE            g_item_spam_th     = NULL;

/* Opcode fuzzer */
static volatile BOOL     g_opfuzz_active   = FALSE;
static volatile uint16_t g_opfuzz_start    = 1;
static volatile uint16_t g_opfuzz_end      = 0x1FF;
static volatile uint16_t g_opfuzz_cur      = 1;
static volatile uint32_t g_opfuzz_delay    = 200;
static volatile LONG     g_opfuzz_sent     = 0;
static HANDLE            g_opfuzz_th       = NULL;
#define OPFUZZ_MSG       0x18

/* Waypoint system */
#define WAYPOINT_MAX  256
typedef struct { float x, y, z; } WaypointEntry;
static WaypointEntry     g_waypoints[WAYPOINT_MAX];
static volatile int      g_wp_count    = 0;
static volatile int      g_wp_cur      = 0;
static volatile BOOL     g_wp_active   = FALSE;
static volatile uint32_t g_wp_delay    = 1000;
static HANDLE            g_wp_th       = NULL;
static CRITICAL_SECTION  g_wp_cs;

/* Script runner */
static volatile BOOL     g_script_active = FALSE;
static char*             g_script_buf    = NULL;
static uint32_t          g_script_len    = 0;
static HANDLE            g_script_th     = NULL;
static CRITICAL_SECTION  g_script_cs;

/* ═══════════════════════════════════════════════════════════════════
 * FORWARD DECLARATIONS
 * ═══════════════════════════════════════════════════════════════════ */

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
static void     forward_pkt_to_shm(const uint8_t* data, uint32_t len, uint32_t ip, uint16_t port, uint8_t dir);
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
static void     memscan_broad_impl(void);
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
static void     sock_cache_set(SOCKET s, uint32_t ip, uint16_t port);
static int      sock_cache_get(SOCKET s, uint32_t* ip, uint16_t* port);
static void     probe_quiche(void);
static void     freeze_generic_set(int slot, uint64_t addr, const char* type, const char* valstr, int ms);
static void     freeze_generic_stop(int slot);
static void     memread_addr(uint64_t addr, uint32_t sz);
static void     memwrite_f64(uint64_t addr, double val);
static void     memwrite_i32(uint64_t addr, int32_t val);
static void     send_memscan_hit(uint8_t* p, SIZE_T avail);
static void     pipe_stream(uint8_t dir, HQUIC stream, const uint8_t* data, uint32_t len);
static uint8_t* flatten_quic_bufs(const QUIC_BUF* bufs, uint32_t count, uint32_t* out_len);
static void     msquic_inject(const uint8_t* data, uint32_t len);
static void     probe_msquic(void);
static void     msquic_list_streams(void);
static void     stream_reg_add(HQUIC h, QUIC_STREAM_CB cb, void* ctx, HQUIC conn);
static void     stream_reg_remove(HQUIC h);
static StreamReg* stream_reg_find(HQUIC h);
static void     inject_movement(float x, float y, float z);

/* Hook functions */
static int WSAAPI hook_WSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
static int WSAAPI hook_WSASendTo(SOCKET s, LPWSABUF bufs, DWORD nb, LPDWORD sent, DWORD flags, const struct sockaddr* to, int tolen, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cb);
static int WSAAPI hook_sendto(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen);
static int WSAAPI hook_WSARecvFrom(SOCKET s, LPWSABUF bufs, DWORD nb, LPDWORD recvd, LPDWORD flags, struct sockaddr* from, LPINT fromlen, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cb);
static int WSAAPI hook_recvfrom(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen);
static BOOL WINAPI hook_GQCS(HANDLE iocp, LPDWORD bytes, PULONG_PTR key, LPOVERLAPPED* ppOv, DWORD timeout);
static int WSAAPI hook_WSASend_nb(SOCKET s, LPWSABUF bufs, DWORD nb, LPDWORD sent, DWORD flags, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cb);
static int WSAAPI hook_send_nb(SOCKET s, const char* buf, int len, int flags);
static int hook_ssl_write(SSL* ssl, const void* buf, int num);
static int hook_ssl_read(SSL* ssl, void* buf, int num);
static intptr_t hook_quiche_recv(void* conn, uint64_t sid, uint8_t* buf, size_t buf_len, int* fin);
static intptr_t hook_quiche_send(void* conn, uint64_t sid, const uint8_t* buf, size_t buf_len, int fin);
static QUIC_STATUS WINAPI shim_stream_callback(HQUIC Stream, void* ShimCtx, QUIC_STREAM_EVENT* Ev);
static QUIC_STATUS WINAPI shim_StreamOpen(HQUIC Conn, uint32_t Flags, QUIC_STREAM_CB AppHandler, void* AppCtx, HQUIC* StreamOut);
static QUIC_STATUS WINAPI shim_StreamSend(HQUIC Stream, const QUIC_BUF* Bufs, uint32_t Count, uint32_t Flags, void* SendCtx);
static QUIC_STATUS WINAPI hook_MsQuicOpenVersion(uint32_t Version, const void** ApiOut);
static QUIC_STATUS WINAPI inject_stream_cb(HQUIC Stream, void* Ctx, QUIC_STREAM_EVENT* Ev);

/* Thread functions */
static DWORD WINAPI freeze_generic_th(LPVOID _);
static DWORD WINAPI memscan_th(LPVOID _);
static DWORD WINAPI memscan_broad_th(LPVOID _);
static DWORD WINAPI stringscan_th(LPVOID _);
static DWORD WINAPI modlist_th(LPVOID _);
static DWORD WINAPI threadlist_th(LPVOID _);
static DWORD WINAPI gadgetscan_th(LPVOID _);
static DWORD WINAPI exploitprobe_th(LPVOID _);
static DWORD WINAPI memwatch_th(LPVOID _);
static DWORD WINAPI freeze_hp_th(LPVOID _);
static DWORD WINAPI freeze_pos_th(LPVOID _);
static DWORD WINAPI rl_thread(LPVOID arg);
static DWORD WINAPI hb_thread(LPVOID _);
static DWORD WINAPI cmd_thread(LPVOID _);
static DWORD WINAPI io_thread(LPVOID _);
static DWORD WINAPI injector_monitor_th(LPVOID _);
static DWORD WINAPI item_spam_thread(LPVOID p);
static DWORD WINAPI opfuzz_thread(LPVOID p);
static DWORD WINAPI waypoint_thread(LPVOID p);
static DWORD WINAPI script_thread(LPVOID p);
static DWORD WINAPI portscan_th(LPVOID arg);

/* ═══════════════════════════════════════════════════════════════════
 * IMPLEMENTATION
 * ═══════════════════════════════════════════════════════════════════ */

/* ── Generic value freeze thread ─────────────────────────── */
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

    /* v10: Also hook SSL_write / SSL_read for direct plaintext capture */
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
    /* v16: restore msquic hook */
    if (orig_MsQuicOpen) jmp_restore(orig_MsQuicOpen, sv_msquic_open);
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
    /* QUIC fallback: packet with unknown IP — pass if QUIC fixed bit set */
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
            g_ovl[i].peer_ptr = peer;
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
            struct sockaddr_in* peer_ptr = g_ovl[i].peer_ptr;
            g_ovl[i].used = 0;
            LeaveCriticalSection(&g_ovl_cs);
            if (buf && bytes > 0 && bytes <= (DWORD)bufsz) {
                uint32_t ip = peer.sin_addr.s_addr;
                uint16_t port = peer.sin_port;
                /* After GQCS completes the OS has filled peer_ptr */
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

/* hook_WSARecv: connected UDP S2C receives */
static int WSAAPI hook_WSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    if (IsReentrant()) return orig_WSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);
    EnterHook(); InterlockedIncrement(&g_fires_wsa_recv2); DWORD se = GetLastError();
    EnterCriticalSection(&g_cs); jmp_restore(orig_WSARecv, sv_wsa_recv2); LeaveCriticalSection(&g_cs);

    /* IOCP path: register OVL BEFORE the call */
    if (lpOverlapped && dwBufferCount > 0 && lpBuffers && lpBuffers[0].buf) {
        struct sockaddr_in peer = { 0 };
        uint32_t cip = 0; uint16_t cport = 0;
        if (sock_cache_get(s, &cip, &cport)) {
            peer.sin_family = AF_INET;
            peer.sin_addr.s_addr = cip;
            peer.sin_port = cport;
        } else {
            int pl = sizeof(peer);
            if (getpeername(s, (struct sockaddr*)&peer, &pl) != 0)
                memset(&peer, 0, sizeof(peer));
            else if (peer.sin_family == AF_INET && peer.sin_addr.s_addr != 0)
                sock_cache_set(s, peer.sin_addr.s_addr, peer.sin_port);
        }
        ovl_register(lpOverlapped, lpBuffers[0].buf, (int)lpBuffers[0].len, &peer);
    }

    int ret = orig_WSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);

    EnterCriticalSection(&g_cs); jmp_write(orig_WSARecv, (void*)hook_WSARecv); LeaveCriticalSection(&g_cs);
    if (ret != SOCKET_ERROR) SetLastError(se);

    /* Sync completion */
    if (ret == 0 && lpNumberOfBytesRecvd && *lpNumberOfBytesRecvd > 0 && dwBufferCount > 0 && lpBuffers && lpBuffers[0].buf) {
        if (lpOverlapped) ovl_free(lpOverlapped);
        uint32_t ip = 0; uint16_t port = 0;
        if (!sock_cache_get(s, &ip, &port)) ip = g_server_ip;
        forward(1, (uint8_t*)lpBuffers[0].buf, (int)*lpNumberOfBytesRecvd, ip, port);
    } else if (ret == SOCKET_ERROR && GetLastError() != WSA_IO_PENDING && lpOverlapped) {
        ovl_free(lpOverlapped);
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
        /* Patch: also store the live `from` pointer */
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
        if (!sock_cache_get(s, &ip, &port)) {
            struct sockaddr_in peer; int pl = sizeof(peer); memset(&peer, 0, sizeof(peer));
            if (getpeername(s, (struct sockaddr*)&peer, &pl) == 0 && peer.sin_family == AF_INET) {
                ip = peer.sin_addr.s_addr; port = peer.sin_port;
                sock_cache_set(s, ip, port);
            }
        }
        if (ip == 0) ip = g_server_ip;
        forward(0, (uint8_t*)bufs[0].buf, (int)bufs[0].len, ip, port);
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
        forward(0, (uint8_t*)buf, ret, ip, port);
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

/* strict scan: requires plausible velocity */
static void memscan_run(void) {
    int hits = 0;
    MEMORY_BASIC_INFORMATION mbi;
    uint8_t* addr = NULL;
    pipe_log("[MEMSCAN] Starting strict scan on HytaleClient.exe memory...");
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
            for (off = 0; off + 44 <= rsz; off += 4) {
                uint8_t* p = base + off;
                float h = *(float*)(p + 0), mh = *(float*)(p + 4);
                if (!is_health(h) || !is_health(mh)) continue;
                if (mh < h * 0.001f) continue;
                double x = *(double*)(p + 8), y = *(double*)(p + 16), z = *(double*)(p + 24);
                if (!is_coord(x) || !is_coord(y) || !is_coord(z)) continue;
                if (x == 0.0 && y == 0.0 && z == 0.0) continue;
                float vx = *(float*)(p + 32), vy = *(float*)(p + 36), vz = *(float*)(p + 40);
                if (!is_vel(vx) || !is_vel(vy) || !is_vel(vz)) continue;
                send_memscan_hit(p, rsz - off);
                if (++hits >= 128) goto memscan_done;
                off += 40;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
        addr = next;
    }
memscan_done:
    pipe_log("[MEMSCAN] Done: %d hits", hits);
}

/* broad scan: no velocity requirement */
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
            float* mhp = hp + 1;
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
        pipe_log("[STATS] WSASendTo:%ld sendto:%ld WSARecvFrom:%ld WSARecv:%ld recvfrom:%ld "
            "WSASend_nb:%ld send_nb:%ld pkts:%ld srvIP:%u.%u.%u.%u",
            g_fires_wsa_send, g_fires_send, g_fires_wsa_recv, g_fires_wsa_recv2, g_fires_recv,
            g_fires_wsa_send_nb, g_fires_send_nb, g_pkts_captured,
            g_server_ip & 0xFF, (g_server_ip >> 8) & 0xFF,
            (g_server_ip >> 16) & 0xFF, (g_server_ip >> 24) & 0xFF);
    }
    return 0;
}

/* ── Item spam thread ───────────────────────────────────── */
static DWORD WINAPI item_spam_thread(LPVOID p) {
    (void)p;
    while (g_item_spam_active) {
        uint32_t tid=g_item_spam_typeid, slt=g_item_spam_slot, cnt=g_item_spam_count;
        uint8_t sf[20]={0}; uint32_t sflen=12; memcpy(sf,&sflen,4);
        sf[4]=0xAB; sf[5]=0x00; memcpy(sf+8,&slt,4); memcpy(sf+12,&tid,4); memcpy(sf+16,&cnt,4);
        uint32_t total=20; uint8_t frame[20];
        uint32_t flen2=16; memcpy(frame,&flen2,4);
        frame[4]=0xAB; frame[5]=0x00; frame[6]=0; frame[7]=0;
        memcpy(frame+8,&slt,4); memcpy(frame+12,&tid,4); memcpy(frame+16,&cnt,4);
        msquic_inject(frame,20);
        InterlockedIncrement(&g_item_spam_sent);
        Sleep(g_item_spam_delay);
    }
    return 0;
}

/* ── Opcode fuzzer thread ───────────────────────────────── */
static DWORD WINAPI opfuzz_thread(LPVOID p) {
    (void)p;
    uint16_t op;
    for(op=g_opfuzz_start; op<=g_opfuzz_end && g_opfuzz_active; op++) {
        g_opfuzz_cur=op;
        uint8_t frame[8]={0}; uint32_t flen=4; memcpy(frame,&flen,4);
        memcpy(frame+4,&op,2);
        msquic_inject(frame,8);
        InterlockedIncrement(&g_opfuzz_sent);
        if((op % 16)==0) pipe_log("[OPFUZZ] op=0x%04X sent=%ld",op,g_opfuzz_sent);
        Sleep(g_opfuzz_delay);
    }
    g_opfuzz_active=FALSE;
    pipe_log("[OPFUZZ] Done  sent=%ld",g_opfuzz_sent);
    return 0;
}

/* ── Waypoint thread ────────────────────────────────────── */
static DWORD WINAPI waypoint_thread(LPVOID p) {
    (void)p;
    while(g_wp_active && g_wp_cur < g_wp_count) {
        EnterCriticalSection(&g_wp_cs);
        float wx3=g_waypoints[g_wp_cur].x, wy3=g_waypoints[g_wp_cur].y, wz3=g_waypoints[g_wp_cur].z;
        g_wp_cur++;
        LeaveCriticalSection(&g_wp_cs);
        inject_movement(wx3,wy3,wz3);
        pipe_log("[WP] Arrived at point %d (%.1f,%.1f,%.1f)",g_wp_cur,wx3,wy3,wz3);
        Sleep(g_wp_delay);
    }
    if(g_wp_cur>=g_wp_count) { g_wp_active=FALSE; pipe_log("[WP] Route complete"); }
    return 0;
}

/* ── Script thread ───────────────────────────────────────── */
static DWORD WINAPI script_thread(LPVOID p) {
    (void)p;
    EnterCriticalSection(&g_script_cs);
    char* src = g_script_buf ? _strdup(g_script_buf) : NULL;
    LeaveCriticalSection(&g_script_cs);
    if(!src) return 0;

    char* line = src; char* end = src + strlen(src);
    int lineno = 0;
    while(line < end && g_script_active) {
        char* nl = strchr(line,'\n');
        if(!nl) nl = end;
        size_t llen = (size_t)(nl-line);
        if(llen > 0 && llen < 512) {
            char cmd[512]={0}; memcpy(cmd,line,(llen<511?llen:511));
            if(cmd[llen-1]=='\r') cmd[llen-1]='\0';
            if(strncmp(cmd,"SLEEP ",6)==0) {
                unsigned int ms=500; sscanf(cmd+6,"%u",&ms);
                if(ms>30000) ms=30000;
                Sleep(ms);
            } else if(strlen(cmd)>0 && cmd[0]!='#') {
                pipe_log("[SCRIPT L%d] %s",++lineno,cmd);
                if(strncmp(cmd,"TELEPORT ",9)==0) {
                    float sx=0,sy=0,sz=0; sscanf(cmd+9,"%f %f %f",&sx,&sy,&sz);
                    g_pos_override=TRUE; g_one_shot_tp=TRUE;
                    inject_movement(sx,sy,sz);
                } else if(strncmp(cmd,"SEND_CHAT ",10)==0) {
                    const char* shex=cmd+10; size_t shlen=strlen(shex); uint32_t sdlen=(uint32_t)(shlen/2);
                    if(sdlen>0&&sdlen<=512){
                        uint32_t sflen2=sdlen+4; uint32_t stotal=4+4+sdlen;
                        uint8_t* sframe=(uint8_t*)malloc(stotal);
                        if(sframe){memcpy(sframe,&sflen2,4);sframe[4]=0xD2;sframe[5]=0;sframe[6]=0;sframe[7]=0;
                            uint32_t sci; for(sci=0;sci<sdlen;sci++){unsigned int b=0;sscanf(shex+sci*2,"%02x",&b);sframe[8+sci]=(uint8_t)b;}
                            msquic_inject(sframe,stotal); free(sframe);}
                    }
                } else if(strncmp(cmd,"FORGE_STREAM ",13)==0) {
                    const char* fhex=cmd+13; size_t fhlen=strlen(fhex); uint32_t fdlen=(uint32_t)(fhlen/2);
                    if(fdlen>0&&fdlen<=8192){
                        uint8_t* fdata=(uint8_t*)malloc(fdlen); if(fdata){
                            uint32_t fci; for(fci=0;fci<fdlen;fci++){unsigned int b=0;sscanf(fhex+fci*2,"%02x",&b);fdata[fci]=(uint8_t)b;}
                            msquic_inject(fdata,fdlen); free(fdata);}
                    }
                }
            }
        }
        line = nl + 1;
    }
    free(src);
    g_script_active = FALSE;
    pipe_log("[SCRIPT] Done");
    return 0;
}

/* ── Inject movement packet ─────────────────────────────── */
static void inject_movement(float x, float y, float z) {
    uint8_t buf[MOVEMENT_BUF_MAX];
    int blen;
    EnterCriticalSection(&g_movement_cs);
    if (g_last_movement_len >= 20) {
        blen = g_last_movement_len;
        memcpy(buf, g_last_movement, blen);
    } else {
        blen = 20;
        memset(buf, 0, blen);
        uint32_t flen = 16; memcpy(buf, &flen, 4);
        buf[4] = 0x6C; buf[5] = 0x00;
    }
    LeaveCriticalSection(&g_movement_cs);
    if (blen >= 20) {
        memcpy(buf + 8,  &x, 4);
        memcpy(buf + 12, &y, 4);
        memcpy(buf + 16, &z, 4);
    }
    msquic_inject(buf, (uint32_t)blen);
    pipe_log("[TELEPORT] Injected movement X=%.2f Y=%.2f Z=%.2f  (%dB)", x, y, z, blen);
}

/* ── Stream registry helpers ────────────────────────────── */
static void stream_reg_add(HQUIC h, QUIC_STREAM_CB cb, void* ctx, HQUIC conn) {
    EnterCriticalSection(&g_stream_cs);
    int i;
    for (i = 0; i < STREAM_REG_MAX; i++) {
        if (!g_streams[i].used) {
            g_streams[i].handle = h;
            g_streams[i].real_cb = cb;
            g_streams[i].real_ctx = ctx;
            g_streams[i].conn = conn;
            g_streams[i].used = TRUE;
            break;
        }
    }
    LeaveCriticalSection(&g_stream_cs);
}

static void stream_reg_remove(HQUIC h) {
    EnterCriticalSection(&g_stream_cs);
    int i;
    for (i = 0; i < STREAM_REG_MAX; i++)
        if (g_streams[i].used && g_streams[i].handle == h) { g_streams[i].used = FALSE; break; }
    LeaveCriticalSection(&g_stream_cs);
}

static StreamReg* stream_reg_find(HQUIC h) {
    int i;
    for (i = 0; i < STREAM_REG_MAX; i++)
        if (g_streams[i].used && g_streams[i].handle == h) return &g_streams[i];
    return NULL;
}

/* ── MSQUIC shim_StreamSend ─────────────────────────────── */
static QUIC_STATUS WINAPI shim_StreamSend(HQUIC Stream, const QUIC_BUF* Bufs, uint32_t Count, uint32_t Flags, void* SendCtx)
{
    if (!g_msquic_real || !g_msquic_real->StreamSend)
        return QUIC_STATUS_SUCCESS;

    uint32_t opcode = 0;
    const uint8_t* firstbuf = (Count > 0 && Bufs && Bufs[0].Length >= 8 && Bufs[0].Buffer)
        ? (const uint8_t*)Bufs[0].Buffer : NULL;
    if (firstbuf) {
        memcpy(&opcode, firstbuf + 4, 4);
        opcode &= 0xFFFF;
    }

    /* ClientMovement (0x6C) interception */
    if (opcode == 0x6C && firstbuf && Count > 0) {
        uint32_t flat_len = 0; uint32_t bi2;
        for (bi2 = 0; bi2 < Count; bi2++) flat_len += Bufs[bi2].Length;

        if (flat_len >= 20 && flat_len < MOVEMENT_BUF_MAX) {
            uint8_t* flat_mv = (uint8_t*)malloc(flat_len);
            if (flat_mv) {
                uint32_t off2 = 0;
                for (bi2 = 0; bi2 < Count; bi2++) {
                    memcpy(flat_mv + off2, Bufs[bi2].Buffer, Bufs[bi2].Length);
                    off2 += Bufs[bi2].Length;
                }
                EnterCriticalSection(&g_movement_cs);
                memcpy(g_last_movement, flat_mv, flat_len);
                g_last_movement_len = (int)flat_len;
                LeaveCriticalSection(&g_movement_cs);

                if (g_pos_override) {
                    memcpy(flat_mv + 8,  (void*)&g_override_x, 4);
                    memcpy(flat_mv + 12, (void*)&g_override_y, 4);
                    memcpy(flat_mv + 16, (void*)&g_override_z, 4);
                    pipe_log("[POS-OVERRIDE] Patched XYZ=%.2f,%.2f,%.2f in 0x6C",
                        g_override_x, g_override_y, g_override_z);
                }

                float smul = g_speed_mul;
                if (smul != 1.f && flat_len >= 32) {
                    float vx, vy, vz;
                    memcpy(&vx, flat_mv + 20, 4); vx *= smul;
                    memcpy(&vy, flat_mv + 24, 4); vy *= smul;
                    memcpy(&vz, flat_mv + 28, 4); vz *= smul;
                    memcpy(flat_mv + 20, &vx, 4);
                    memcpy(flat_mv + 24, &vy, 4);
                    memcpy(flat_mv + 28, &vz, 4);
                }

                if (g_pos_override || smul != 1.f) {
                    QUIC_BUF pb = { flat_len, (char*)flat_mv };
                    QUIC_STATUS pst = g_msquic_real->StreamSend(Stream, &pb, 1, Flags, SendCtx);
                    free(flat_mv);
                    if (g_one_shot_tp && pst == QUIC_STATUS_SUCCESS) {
                        g_pos_override = FALSE; g_one_shot_tp = FALSE;
                        InterlockedIncrement(&g_tp_sent);
                        pipe_log("[TELEPORT] One-shot sent (total=%ld)", g_tp_sent);
                    }
                    return pst;
                }
                free(flat_mv);
            }
        }
    }

    /* Spectate mode — suppress 0x6C */
    if (g_spectate_mode && opcode == 0x6C) {
        return QUIC_STATUS_SUCCESS;
    }

    /* Noclip — drop 0x70 */
    if (g_noclip && opcode == 0x70) {
        return QUIC_STATUS_SUCCESS;
    }

    /* Infinite reach — drop 0x71 */
    if (g_inf_reach && opcode == 0x71) {
        return QUIC_STATUS_SUCCESS;
    }

    /* Velocity launch */
    if (g_launch_armed && opcode == 0x6C && firstbuf && Count > 0) {
        uint32_t flat_len = 0; uint32_t bi_l;
        for (bi_l = 0; bi_l < Count; bi_l++) flat_len += Bufs[bi_l].Length;
        if (flat_len >= 32) {
            uint8_t* lbuf = (uint8_t*)malloc(flat_len);
            if (lbuf) {
                uint32_t off_l = 0;
                for (bi_l = 0; bi_l < Count; bi_l++) {
                    memcpy(lbuf+off_l, Bufs[bi_l].Buffer, Bufs[bi_l].Length);
                    off_l += Bufs[bi_l].Length;
                }
                float lvx=g_launch_vx, lvy=g_launch_vy, lvz=g_launch_vz;
                memcpy(lbuf+20, &lvx, 4);
                memcpy(lbuf+24, &lvy, 4);
                memcpy(lbuf+28, &lvz, 4);
                QUIC_BUF lpb = { flat_len, (char*)lbuf };
                QUIC_STATUS lst = g_msquic_real->StreamSend(Stream, &lpb, 1, Flags, SendCtx);
                free(lbuf);
                g_launch_armed = FALSE;
                pipe_log("[LAUNCH] Fired vx=%.2f vy=%.2f vz=%.2f", lvx, lvy, lvz);
                return lst;
            }
        }
    }

    /* Trade capture */
    if (g_trade_capture && opcode == 0xCB && firstbuf && Count > 0) {
        uint32_t flat_len2 = 0; uint32_t bi0;
        for (bi0 = 0; bi0 < Count; bi0++) flat_len2 += Bufs[bi0].Length;
        uint8_t* flat2 = (uint8_t*)malloc(flat_len2);
        if (flat2) {
            uint32_t off0 = 0;
            for (bi0 = 0; bi0 < Count; bi0++) { memcpy(flat2+off0, Bufs[bi0].Buffer, Bufs[bi0].Length); off0 += Bufs[bi0].Length; }
            pipe_stream(0xC3, Stream, flat2, flat_len2);
            free(flat2);
        }
    }

    /* Log C2S if enabled */
    if (g_c2s_log_enabled && firstbuf && Count > 0) {
        uint32_t flat_len = 0; uint32_t bi;
        for (bi = 0; bi < Count; bi++) flat_len += Bufs[bi].Length;
        uint8_t* flat = (uint8_t*)malloc(flat_len);
        if (flat) {
            uint32_t off = 0;
            for (bi = 0; bi < Count; bi++) { memcpy(flat+off, Bufs[bi].Buffer, Bufs[bi].Length); off += Bufs[bi].Length; }
            pipe_stream(0xC2, Stream, flat, flat_len);
            free(flat);
        }
    }

    /* C2S drop */
    uint32_t drop_op = g_c2s_drop_opcode;
    if (drop_op && opcode == drop_op) {
        InterlockedIncrement(&g_c2s_drops_total);
        pipe_log("[C2S-DROP] opcode=0x%04X stream=%p  (total drops: %ld)",
            opcode, Stream, g_c2s_drops_total);
        return QUIC_STATUS_SUCCESS;
    }

    QUIC_STATUS st = g_msquic_real->StreamSend(Stream, Bufs, Count, Flags, SendCtx);

    /* C2S dup */
    uint32_t dup_op = g_c2s_dup_opcode;
    int dup_n = g_c2s_dup_count;
    if (dup_op && opcode == dup_op && dup_n > 0 && st == QUIC_STATUS_SUCCESS) {
        int d;
        for (d = 0; d < dup_n && d < 4; d++) {
            uint32_t flat_len = 0; uint32_t bi;
            for (bi = 0; bi < Count; bi++) flat_len += Bufs[bi].Length;
            uint8_t* copy = (uint8_t*)malloc(flat_len);
            if (copy) {
                uint32_t off = 0;
                for (bi = 0; bi < Count; bi++) { memcpy(copy+off, Bufs[bi].Buffer, Bufs[bi].Length); off += Bufs[bi].Length; }
                QUIC_BUF cb = { flat_len, copy };
                g_msquic_real->StreamSend(Stream, &cb, 1, Flags, copy);
                InterlockedIncrement(&g_c2s_dups_total);
            }
        }
        pipe_log("[C2S-DUP] opcode=0x%04X x%d  stream=%p  (total dups: %ld)",
            opcode, dup_n, Stream, g_c2s_dups_total);
    }

    return st;
}

/* ── Helper: pipe a stream payload ───────────────────────── */
static void pipe_stream(uint8_t dir, HQUIC stream, const uint8_t* data, uint32_t len) {
    if (len == 0) return;
    uint32_t hdr = 1 + 8 + 4;
    uint8_t* buf = (uint8_t*)malloc(hdr + len);
    if (!buf) return;
    buf[0] = dir;
    memcpy(buf + 1, &stream, 8);
    memcpy(buf + 9, &len, 4);
    memcpy(buf + 13, data, len);
    pipe_send(MSG_QUIC_STREAM, (char*)buf, hdr + len);
    free(buf);
}

/* ── Flatten QUIC_STREAM_EVENT buffers ───────────────────── */
static uint8_t* flatten_quic_bufs(const QUIC_BUF* bufs, uint32_t count, uint32_t* out_len) {
    uint32_t total = 0; uint32_t i;
    for (i = 0; i < count; i++) total += bufs[i].Length;
    if (!total) { *out_len = 0; return NULL; }
    uint8_t* p = (uint8_t*)malloc(total);
    if (!p) { *out_len = 0; return NULL; }
    uint32_t off = 0;
    for (i = 0; i < count; i++) { memcpy(p + off, bufs[i].Buffer, bufs[i].Length); off += bufs[i].Length; }
    *out_len = total;
    return p;
}

/* ── shim_stream_callback ───────────────────────────────── */
static QUIC_STATUS WINAPI shim_stream_callback(HQUIC Stream, void* ShimCtx, QUIC_STREAM_EVENT* Ev) {
    (void)ShimCtx;
    EnterCriticalSection(&g_stream_cs);
    StreamReg* reg = stream_reg_find(Stream);
    QUIC_STREAM_CB real_cb  = reg ? reg->real_cb  : NULL;
    void*          real_ctx = reg ? reg->real_ctx : NULL;
    LeaveCriticalSection(&g_stream_cs);

    if (Ev->Type == QUIC_STREAM_EVENT_RECEIVE) {
        QUIC_STREAM_RECEIVE_DATA* rx = &Ev->RECEIVE;
        uint32_t total = 0;
        uint8_t* flat = flatten_quic_bufs(rx->Buffers, rx->BufferCount, &total);

        if (flat && total > 0) {
            /* Apply stream-level fuzz */
            int fbits = g_stream_fuzz_bits;
            if (fbits > 0) fuzz_buf(flat, total, fbits);

            /* Store for replay */
            EnterCriticalSection(&g_replay_cs);
            int copy_len = (total < STREAM_REPLAY_MAX) ? total : STREAM_REPLAY_MAX;
            memcpy(g_stream_last, flat, copy_len);
            g_stream_last_len    = copy_len;
            g_stream_last_handle = Stream;
            LeaveCriticalSection(&g_replay_cs);

            /* Pipe plaintext to C# */
            pipe_stream(0x52, Stream, flat, total);

            /* v20: cache PlayerSetup for PERM_TEST_BIT */
            if (total >= 6) {
                uint16_t opcode2 = 0; memcpy(&opcode2, flat + 4, 2);
                if (opcode2 == 0x12 && total >= 16 && total < SETUP_MAX) {
                    EnterCriticalSection(&g_setup_cs);
                    memcpy(g_last_player_setup, flat + 8, total - 8);
                    g_last_player_setup_len = total - 8;
                    LeaveCriticalSection(&g_setup_cs);
                }

                /* v20: inventory lock */
                if (g_inv_lock && opcode2 == 0xAA) {
                    EnterCriticalSection(&g_inv_cs);
                    if (g_inv_cache && g_inv_cache_len > 0) {
                        QUIC_BUF ilbuf = { g_inv_cache_len, (char*)g_inv_cache };
                        QUIC_STREAM_EVENT ilev = {0};
                        ilev.Type = QUIC_STREAM_EVENT_RECEIVE;
                        ilev.RECEIVE.Buffers = &ilbuf;
                        ilev.RECEIVE.BufferCount = 1;
                        ilev.RECEIVE.TotalBufferLength = g_inv_cache_len;
                        EnterCriticalSection(&g_stream_cs);
                        StreamReg* ilsr=NULL; int ilsi;
                        for(ilsi=STREAM_REG_MAX-1;ilsi>=0;ilsi--)
                            if(g_streams[ilsi].used){ilsr=&g_streams[ilsi];break;}
                        QUIC_STREAM_CB ilcb=ilsr?ilsr->real_cb:NULL;
                        void* ilctx=ilsr?ilsr->real_ctx:NULL;
                        HQUIC ilsh=ilsr?ilsr->handle:NULL;
                        LeaveCriticalSection(&g_stream_cs);
                        if(ilcb && ilsh) {
                            ilcb(ilsh, ilctx, &ilev);
                        }
                    }
                    LeaveCriticalSection(&g_inv_cs);
                }
            }

            /* v18: packet recorder */
            if (g_record_enabled && total > 0) {
                EnterCriticalSection(&g_record_cs);
                if (g_record_bytes + total + 4 <= RECORD_MAX_BYTES) {
                    int slot = g_record_head % RECORD_MAX_FRAMES;
                    g_record_offsets[slot] = g_record_bytes;
                    g_record_sizes[slot]   = total;
                    memcpy(g_record_buf + g_record_bytes, flat, total);
                    g_record_bytes += total;
                    g_record_head++;
                    if (g_record_count < RECORD_MAX_FRAMES) g_record_count++;
                }
                LeaveCriticalSection(&g_record_cs);
            }

            /* v18: auto-pong */
            if (g_auto_pong && total >= 6) {
                uint16_t ping_op = 0; memcpy(&ping_op, flat + 4, 2);
                if (ping_op == 0x0001) {
                    uint8_t pong[8]={0};
                    uint32_t pflen=4; memcpy(pong,&pflen,4);
                    pong[4]=0x01; pong[5]=0x00;
                    msquic_inject(pong,8);
                    InterlockedIncrement(&g_pong_count);
                    pipe_log("[PONG] Auto-pong sent #%ld", g_pong_count);
                }
            }

            /* Race delay */
            int delay = g_stream_race_ms;
            if (delay > 0) Sleep((DWORD)delay);

            /* Drop */
            if (g_stream_drop_next) {
                InterlockedExchange((LONG*)&g_stream_drop_next, FALSE);
                if (g_msquic_real && g_msquic_real->StreamReceiveComplete)
                    g_msquic_real->StreamReceiveComplete(Stream, rx->TotalBufferLength);
                free(flat);
                return QUIC_STATUS_SUCCESS;
            }

            /* S2C opcode-specific drop */
            uint32_t s2c_drop_op = g_s2c_drop_opcode;
            if (s2c_drop_op && total >= 6) {
                uint16_t pkt_op = 0; memcpy(&pkt_op, flat + 4, 2);
                if ((uint32_t)pkt_op == s2c_drop_op) {
                    InterlockedIncrement(&g_s2c_drops_total);
                    if (g_msquic_real && g_msquic_real->StreamReceiveComplete)
                        g_msquic_real->StreamReceiveComplete(Stream, rx->TotalBufferLength);
                    pipe_log("[S2C-DROP] Dropped opcode=0x%04X  total=%ld", s2c_drop_op, g_s2c_drops_total);
                    free(flat);
                    return QUIC_STATUS_SUCCESS;
                }
            }

            QUIC_BUF single_buf = { total, flat };
            QUIC_STREAM_EVENT patched = *Ev;
            patched.RECEIVE.Buffers      = &single_buf;
            patched.RECEIVE.BufferCount  = 1;
            patched.RECEIVE.TotalBufferLength = total;

            /* Dup */
            int dup = g_stream_dup_count;
            if (dup > 0) {
                int d;
                InterlockedExchange((LONG*)&g_stream_dup_count, 0);
                for (d = 0; d < dup && d < 8; d++) {
                    if (real_cb) real_cb(Stream, real_ctx, &patched);
                    pipe_stream(0xD0 | (uint8_t)d, Stream, flat, total);
                }
            }

            QUIC_STATUS ret = real_cb ? real_cb(Stream, real_ctx, &patched) : QUIC_STATUS_SUCCESS;
            free(flat);
            return ret;
        }
        free(flat);
    }
    else if (Ev->Type == QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE) {
        uint8_t ev_buf[9]; ev_buf[0] = (uint8_t)Ev->Type; memcpy(ev_buf + 1, &Stream, 8);
        pipe_send(MSG_QUIC_EVENT, (char*)ev_buf, 9);
        QUIC_STATUS ret = real_cb ? real_cb(Stream, real_ctx, Ev) : QUIC_STATUS_SUCCESS;
        stream_reg_remove(Stream);
        return ret;
    }

    return real_cb ? real_cb(Stream, real_ctx, Ev) : QUIC_STATUS_SUCCESS;
}

/* ── shim_StreamOpen ────────────────────────────────────── */
static QUIC_STATUS WINAPI shim_StreamOpen(HQUIC Conn, uint32_t Flags,
    QUIC_STREAM_CB AppHandler, void* AppCtx, HQUIC* StreamOut)
{
    QUIC_STATUS st = g_msquic_real->StreamOpen(Conn, Flags, shim_stream_callback, NULL, StreamOut);
    if (st == QUIC_STATUS_SUCCESS && StreamOut && *StreamOut) {
        stream_reg_add(*StreamOut, AppHandler, AppCtx, Conn);
        EnterCriticalSection(&g_stream_cs);
        g_msquic_conn = Conn;
        LeaveCriticalSection(&g_stream_cs);
        pipe_log("[MSQUIC] StreamOpen conn=%p stream=%p flags=%u", Conn, *StreamOut, Flags);
    }
    return st;
}

/* ── hook_MsQuicOpenVersion ─────────────────────────────── */
static QUIC_STATUS WINAPI hook_MsQuicOpenVersion(uint32_t Version, const void** ApiOut) {
    EnterCriticalSection(&g_cs);
    jmp_restore(orig_MsQuicOpen, sv_msquic_open);
    LeaveCriticalSection(&g_cs);

    QUIC_STATUS st = orig_MsQuicOpen(Version, ApiOut);

    EnterCriticalSection(&g_cs);
    jmp_write(orig_MsQuicOpen, (void*)hook_MsQuicOpenVersion);
    LeaveCriticalSection(&g_cs);

    if (st != QUIC_STATUS_SUCCESS || !ApiOut || !*ApiOut) return st;

    HF_QUIC_API* real = (HF_QUIC_API*)*ApiOut;
    memcpy(&g_msquic_shadow, real, sizeof(g_msquic_shadow));
    g_msquic_real = real;

    g_msquic_shadow.StreamOpen = shim_StreamOpen;
    g_msquic_shadow.StreamSend = shim_StreamSend;

    *ApiOut = (const void*)&g_msquic_shadow;

    g_msquic_hooked = TRUE;
    pipe_log("[MSQUIC] API table intercepted (v%u). StreamOpen shimmed. Shadow @ %p", Version, &g_msquic_shadow);
    return st;
}

/* ── inject_stream_cb ───────────────────────────────────── */
static QUIC_STATUS WINAPI inject_stream_cb(HQUIC Stream, void* Ctx, QUIC_STREAM_EVENT* Ev) {
    (void)Ctx;
    if (Ev->Type == QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE) stream_reg_remove(Stream);
    return QUIC_STATUS_SUCCESS;
}

/* ── msquic_inject ──────────────────────────────────────── */
static void msquic_inject(const uint8_t* data, uint32_t len) {
    if (!g_msquic_hooked || !g_msquic_real) { pipe_log("[MSQUIC-INJ] Not hooked yet"); return; }
    EnterCriticalSection(&g_stream_cs);
    HQUIC conn = g_msquic_conn;
    LeaveCriticalSection(&g_stream_cs);
    if (!conn) { pipe_log("[MSQUIC-INJ] No connection handle captured yet"); return; }

    uint8_t* copy = (uint8_t*)malloc(len);
    if (!copy) return;
    memcpy(copy, data, len);

    HQUIC stream = NULL;
    QUIC_STATUS st = g_msquic_real->StreamOpen(conn, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL,
        inject_stream_cb, NULL, &stream);
    if (st != QUIC_STATUS_SUCCESS || !stream) {
        pipe_log("[MSQUIC-INJ] StreamOpen failed 0x%x", st); free(copy); return;
    }
    stream_reg_add(stream, inject_stream_cb, NULL, conn);

    st = g_msquic_real->StreamStart(stream, QUIC_STREAM_START_FLAG_IMMEDIATE);
    if (st != QUIC_STATUS_SUCCESS) {
        pipe_log("[MSQUIC-INJ] StreamStart failed 0x%x", st);
        g_msquic_real->StreamClose(stream);
        stream_reg_remove(stream);
        free(copy); return;
    }

    QUIC_BUF buf = { len, copy };
    st = g_msquic_real->StreamSend(stream, &buf, 1, QUIC_SEND_FLAG_FIN, copy);
    if (st != QUIC_STATUS_SUCCESS)
        pipe_log("[MSQUIC-INJ] StreamSend failed 0x%x", st);
    else
        pipe_log("[MSQUIC-INJ] Injected %u bytes on stream %p", len, stream);
}

/* ── probe_msquic ───────────────────────────────────────── */
static void probe_msquic(void) {
    if (g_msquic_hooked) { pipe_log("[MSQUIC] Already hooked"); return; }
    HMODULE mod = GetModuleHandleA("msquic.dll");
    if (!mod) { pipe_log("[MSQUIC] msquic.dll not loaded yet"); return; }
    void* fn = GetProcAddress(mod, "MsQuicOpenVersion");
    if (!fn) { pipe_log("[MSQUIC] MsQuicOpenVersion not found"); return; }
    orig_MsQuicOpen = (MsQuicOpenVersion_t)fn;
    memcpy(sv_msquic_open, fn, 14);
    EnterCriticalSection(&g_cs);
    jmp_write(fn, (void*)hook_MsQuicOpenVersion);
    LeaveCriticalSection(&g_cs);
    pipe_log("[MSQUIC] Hooked MsQuicOpenVersion @ %p (waiting for app to call it)", fn);
}

/* ── msquic_list_streams ────────────────────────────────── */
static void msquic_list_streams(void) {
    EnterCriticalSection(&g_stream_cs);
    int count = 0, i;
    for (i = 0; i < STREAM_REG_MAX; i++) {
        if (g_streams[i].used) {
            pipe_log("[STREAM #%d] handle=%p conn=%p cb=%p", count,
                g_streams[i].handle, g_streams[i].conn, g_streams[i].real_cb);
            count++;
        }
    }
    pipe_log("[MSQUIC] %d active streams  conn=%p  hooked=%d", count, g_msquic_conn, g_msquic_hooked);
    LeaveCriticalSection(&g_stream_cs);
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
            else if (!strcmp(buf, "QUICHEPROBE")) probe_quiche();
            /* v16 msquic bypass commands */
            else if (!strcmp(buf, "QUIC_PROBE")) probe_msquic();
            else if (!strcmp(buf, "QUIC_STREAMS")) msquic_list_streams();
            else if (!strncmp(buf, "QUIC_RACE ", 10)) {
                int ms = atoi(buf + 10);
                InterlockedExchange((LONG*)&g_stream_race_ms, ms);
                pipe_log("[MSQUIC] Race delay set to %d ms", ms);
            }
            else if (!strncmp(buf, "QUIC_FUZZ_STREAM ", 17)) {
                int bits = atoi(buf + 17);
                InterlockedExchange((LONG*)&g_stream_fuzz_bits, bits);
                pipe_log("[MSQUIC] Stream fuzz bits = %d", bits);
            }
            else if (!strncmp(buf, "QUIC_DUP ", 9)) {
                int n = atoi(buf + 9);
                InterlockedExchange((LONG*)&g_stream_dup_count, n);
                pipe_log("[MSQUIC] Will duplicate next RX event x%d", n);
            }
            else if (!strcmp(buf, "QUIC_DROP")) {
                InterlockedExchange((LONG*)&g_stream_drop_next, TRUE);
                pipe_log("[MSQUIC] Next S2C RX event will be dropped");
            }
            else if (!strcmp(buf, "QUIC_C2S_LOG_ON"))  { g_c2s_log_enabled = TRUE;  pipe_log("[C2S] Logging enabled");  }
            else if (!strcmp(buf, "QUIC_C2S_LOG_OFF")) { g_c2s_log_enabled = FALSE; pipe_log("[C2S] Logging disabled"); }
            else if (!strncmp(buf, "QUIC_DROP_C2S ", 14)) {
                unsigned int op = 0; sscanf(buf + 14, "%x", &op);
                InterlockedExchange((LONG*)&g_c2s_drop_opcode, (LONG)op);
                if (op) pipe_log("[C2S-DROP] Armed for opcode 0x%04X (e.g. 0x70=DamageInfo)", op);
                else    pipe_log("[C2S-DROP] Cleared");
            }
            else if (!strncmp(buf, "QUIC_DUP_C2S ", 13)) {
                unsigned int op = 0; int n = 1;
                sscanf(buf + 13, "%x %d", &op, &n);
                InterlockedExchange((LONG*)&g_c2s_dup_opcode, (LONG)op);
                InterlockedExchange((LONG*)&g_c2s_dup_count, n);
                if (op) pipe_log("[C2S-DUP] Armed for opcode 0x%04X x%d (e.g. 0xAF=MoveItemStack)", op, n);
                else    pipe_log("[C2S-DUP] Cleared");
            }
            else if (!strcmp(buf, "QUIC_C2S_STATS"))
                pipe_log("[C2S] drops=%ld  dups=%ld  drop_op=0x%04X  dup_op=0x%04X x%d",
                    g_c2s_drops_total, g_c2s_dups_total,
                    g_c2s_drop_opcode, g_c2s_dup_opcode, g_c2s_dup_count);
            /* v16 position / teleport / interaction forge */
            else if (!strncmp(buf, "TELEPORT ", 9)) {
                float tx = 0, ty = 0, tz = 0;
                sscanf(buf + 9, "%f %f %f", &tx, &ty, &tz);
                g_override_x = tx; g_override_y = ty; g_override_z = tz;
                g_pos_override = TRUE; g_one_shot_tp = TRUE;
                inject_movement(tx, ty, tz);
            }
            else if (!strncmp(buf, "POS_OVERRIDE ", 13)) {
                float tx = 0, ty = 0, tz = 0;
                sscanf(buf + 13, "%f %f %f", &tx, &ty, &tz);
                g_override_x = tx; g_override_y = ty; g_override_z = tz;
                g_pos_override = TRUE; g_one_shot_tp = FALSE;
                pipe_log("[POS] Sticky override ON  XYZ=%.2f,%.2f,%.2f", tx, ty, tz);
            }
            else if (!strcmp(buf, "POS_OVERRIDE_OFF")) {
                g_pos_override = FALSE; g_one_shot_tp = FALSE;
                pipe_log("[POS] Position override cleared");
            }
            else if (!strncmp(buf, "SPEED_MUL ", 10)) {
                float m = 1.f; sscanf(buf + 10, "%f", &m);
                g_speed_mul = m;
                pipe_log("[SPEED] Multiplier set to %.2fx", m);
            }
            else if (!strcmp(buf, "SPEED_MUL_OFF")) {
                g_speed_mul = 1.f;
                pipe_log("[SPEED] Speed multiplier cleared (1.0)");
            }
            else if (!strncmp(buf, "FORGE_STREAM ", 13)) {
                const char* hex = buf + 13;
                size_t hlen = strlen(hex); uint32_t dlen = (uint32_t)(hlen / 2);
                if (dlen > 0 && dlen <= 8192) {
                    uint8_t* data = (uint8_t*)malloc(dlen); uint32_t i2;
                    for (i2 = 0; i2 < dlen; i2++) {
                        unsigned int byte = 0; sscanf(hex + i2*2, "%02x", &byte);
                        data[i2] = (uint8_t)byte;
                    }
                    msquic_inject(data, dlen); free(data);
                } else pipe_log("[FORGE] Bad hex length %zu", hlen);
            }
            else if (!strcmp(buf, "QUIC_REPLAY_STREAM")) {
                EnterCriticalSection(&g_replay_cs);
                int rlen = g_stream_last_len;
                uint8_t* rcopy = rlen > 0 ? (uint8_t*)malloc(rlen) : NULL;
                if (rcopy) memcpy(rcopy, g_stream_last, rlen);
                LeaveCriticalSection(&g_replay_cs);
                if (rcopy && rlen > 0) { msquic_inject(rcopy, rlen); free(rcopy); }
                else pipe_log("[MSQUIC] No stream data captured yet for replay");
            }
            else if (!strncmp(buf, "QUIC_INJECT ", 12)) {
                const char* hex = buf + 12;
                size_t hlen = strlen(hex); uint32_t dlen = (uint32_t)(hlen / 2);
                if (dlen > 0 && dlen <= 8192) {
                    uint8_t* data = (uint8_t*)malloc(dlen); uint32_t i2;
                    for (i2 = 0; i2 < dlen; i2++) {
                        unsigned int byte = 0;
                        sscanf(hex + i2 * 2, "%02x", &byte);
                        data[i2] = (uint8_t)byte;
                    }
                    msquic_inject(data, dlen); free(data);
                } else pipe_log("[MSQUIC-INJ] Bad hex length %zu", hlen);
            }
            /* v17: chat / gamemode / permission / admin commands */
            else if (!strncmp(buf, "SEND_CHAT ", 10)) {
                const char* hex = buf + 10;
                size_t hlen = strlen(hex); uint32_t dlen = (uint32_t)(hlen / 2);
                if (dlen > 0 && dlen <= 4096) {
                    uint32_t frame_len = dlen + 4;
                    uint32_t total = 4 + 4 + dlen;
                    uint8_t* frame = (uint8_t*)malloc(total);
                    if (frame) {
                        memcpy(frame, &frame_len, 4);
                        frame[4] = 0xD2; frame[5] = 0x00; frame[6] = 0x00; frame[7] = 0x00;
                        uint32_t i3;
                        for (i3 = 0; i3 < dlen; i3++) {
                            unsigned int byte = 0; sscanf(hex + i3*2, "%02x", &byte);
                            frame[8 + i3] = (uint8_t)byte;
                        }
                        msquic_inject(frame, total); free(frame);
                        pipe_log("[CHAT] Injected 0xD2 ChatMessage %uB", dlen);
                    }
                } else pipe_log("[CHAT] Bad hex length %zu", hlen);
            }
            else if (!strncmp(buf, "SET_GAMEMODE ", 13)) {
                unsigned int mode = 0; sscanf(buf + 13, "%u", &mode);
                uint8_t frame[12] = {0};
                uint32_t flen = 8; memcpy(frame, &flen, 4);
                frame[4] = 0x65; frame[5] = 0x00;
                memcpy(frame + 8, &mode, 4);
                msquic_inject(frame, 12);
                pipe_log("[GAMEMODE] Forged 0x65 SetGameMode mode=%u", mode);
            }
            else if (!strncmp(buf, "REPLAY_SETUP ", 13)) {
                const char* hex = buf + 13;
                size_t hlen = strlen(hex); uint32_t dlen = (uint32_t)(hlen / 2);
                if (dlen > 0 && dlen <= 8192) {
                    uint32_t flen = dlen + 4;
                    uint32_t total = 4 + 4 + dlen;
                    uint8_t* frame = (uint8_t*)malloc(total);
                    if (frame) {
                        memcpy(frame, &flen, 4);
                        frame[4] = 0x12; frame[5] = 0x00; frame[6] = 0x00; frame[7] = 0x00;
                        uint32_t i4;
                        for (i4 = 0; i4 < dlen; i4++) {
                            unsigned int byte = 0; sscanf(hex + i4*2, "%02x", &byte);
                            frame[8 + i4] = (uint8_t)byte;
                        }
                        msquic_inject(frame, total); free(frame);
                        pipe_log("[PERM] Re-injected PlayerSetup (0x12) %uB", dlen);
                    }
                } else pipe_log("[PERM] Bad hex length %zu", hlen);
            }
            else if (!strncmp(buf, "KICK_ENTITY ", 12)) {
                uint64_t eid = 0; sscanf(buf + 12, "%llx", (unsigned long long*)&eid);
                uint8_t frame[20] = {0};
                uint32_t flen = 12; memcpy(frame, &flen, 4);
                frame[4] = 0x27; frame[5] = 0x01;
                memcpy(frame + 8, &eid, 8);
                msquic_inject(frame, 20);
                pipe_log("[KICK] Forged KickEntity eid=0x%llx", (unsigned long long)eid);
            }
            else if (!strncmp(buf, "ADMIN_CMD ", 10)) {
                unsigned int op = 0; int parsed_op = sscanf(buf + 10, "%x", &op);
                const char* sp = strchr(buf + 10, ' ');
                const char* hex = sp ? sp + 1 : "";
                size_t hlen = strlen(hex); uint32_t dlen = (uint32_t)(hlen / 2);
                if (parsed_op == 1 && dlen <= 8192) {
                    uint32_t flen = dlen + 4;
                    uint32_t total = 4 + 4 + dlen;
                    uint8_t* frame = (uint8_t*)malloc(total);
                    if (frame) {
                        memcpy(frame, &flen, 4);
                        uint16_t opw = (uint16_t)op; memcpy(frame + 4, &opw, 2);
                        frame[6] = 0x00; frame[7] = 0x00;
                        uint32_t i5;
                        for (i5 = 0; i5 < dlen; i5++) {
                            unsigned int byte = 0; sscanf(hex + i5*2, "%02x", &byte);
                            frame[8 + i5] = (uint8_t)byte;
                        }
                        msquic_inject(frame, total); free(frame);
                        pipe_log("[ADMIN] Forged opcode=0x%04X payload=%uB", op, dlen);
                    }
                } else pipe_log("[ADMIN] Bad args");
            }
            /* v17: S2C stream-level drop filter */
            else if (!strncmp(buf, "S2C_DROP_OPCODE ", 16)) {
                unsigned int op = 0; sscanf(buf + 16, "%x", &op);
                InterlockedExchange((LONG*)&g_s2c_drop_opcode, (LONG)(op & 0xFFFF));
                if (op) pipe_log("[S2C-DROP] Armed for opcode 0x%04X", op);
                else    pipe_log("[S2C-DROP] Cleared");
            }
            /* v18 commands */
            else if (!strcmp(buf, "AUTO_PONG_ON"))  { g_auto_pong = TRUE;  pipe_log("[PONG] Heartbeat enabled"); }
            else if (!strcmp(buf, "AUTO_PONG_OFF")) { g_auto_pong = FALSE; pipe_log("[PONG] Heartbeat disabled"); }
            else if (!strncmp(buf, "BLOCK_PLACE ", 12)) {
                int bx=0,by=0,bz=0; unsigned int btid=0,bface=0;
                sscanf(buf+12,"%d %d %d %x %u",&bx,&by,&bz,&btid,&bface);
                uint8_t bframe[25]={0};
                uint32_t bflen=17; memcpy(bframe,&bflen,4);
                bframe[4]=0x80; bframe[5]=0x00;
                memcpy(bframe+8,&bx,4); memcpy(bframe+12,&by,4); memcpy(bframe+16,&bz,4);
                memcpy(bframe+20,&btid,4); bframe[24]=(uint8_t)bface;
                msquic_inject(bframe,25);
                pipe_log("[BLOCK] PlaceBlock (%d,%d,%d) type=0x%X face=%u",bx,by,bz,btid,bface);
            }
            else if (!strncmp(buf, "BLOCK_BREAK ", 12)) {
                int bx=0,by=0,bz=0; sscanf(buf+12,"%d %d %d",&bx,&by,&bz);
                uint8_t bframe[20]={0};
                uint32_t bflen=12; memcpy(bframe,&bflen,4);
                bframe[4]=0x81; bframe[5]=0x00;
                memcpy(bframe+8,&bx,4); memcpy(bframe+12,&by,4); memcpy(bframe+16,&bz,4);
                msquic_inject(bframe,20);
                pipe_log("[BLOCK] BreakBlock (%d,%d,%d)",bx,by,bz);
            }
            else if (!strncmp(buf, "SET_ENTITY_PROP ", 16)) {
                uint64_t eid=0; unsigned int prop=0; char vhex[512]="";
                sscanf(buf+16,"%llx %u %511s",(unsigned long long*)&eid,&prop,vhex);
                size_t vhlen=strlen(vhex); uint32_t vdlen=(uint32_t)(vhlen/2);
                if(vdlen<=256){
                    uint32_t total=8+4+8+4+vdlen;
                    uint8_t* ef=(uint8_t*)malloc(total);
                    if(ef){
                        memset(ef,0,total);
                        uint32_t eflen=4+8+4+vdlen; memcpy(ef,&eflen,4);
                        ef[4]=0xA6; ef[5]=0x00;
                        memcpy(ef+8,&eid,8); memcpy(ef+16,&prop,4);
                        uint32_t vi;
                        for(vi=0;vi<vdlen;vi++){unsigned int b=0;sscanf(vhex+vi*2,"%02x",&b);ef[20+vi]=(uint8_t)b;}
                        msquic_inject(ef,total); free(ef);
                        pipe_log("[ENTPROP] eid=0x%llx prop=%u",(unsigned long long)eid,prop);
                    }
                }
            }
            else if (!strcmp(buf, "RECORD_ON"))  { g_record_enabled=TRUE;  pipe_log("[REC] Recording ON"); }
            else if (!strcmp(buf, "RECORD_OFF")) { g_record_enabled=FALSE; pipe_log("[REC] Recording OFF  frames=%d", g_record_count); }
            else if (!strcmp(buf, "RECORD_CLEAR")) {
                EnterCriticalSection(&g_record_cs); g_record_count=0; g_record_bytes=0; LeaveCriticalSection(&g_record_cs);
                pipe_log("[REC] Cleared");
            }
            else if (!strcmp(buf, "RECORD_STATS"))
                pipe_log("[REC] frames=%d bytes=%u enabled=%d", g_record_count, g_record_bytes, (int)g_record_enabled);
            else if (!strncmp(buf, "SPOOF_S2C ", 10)) {
                const char* hex=buf+10; size_t hlen=strlen(hex); uint32_t dlen=(uint32_t)(hlen/2);
                if(dlen>0&&dlen<=8192){
                    uint8_t* spf=(uint8_t*)malloc(dlen);
                    if(spf){
                        uint32_t si;
                        for(si=0;si<dlen;si++){unsigned int b=0;sscanf(hex+si*2,"%02x",&b);spf[si]=(uint8_t)b;}
                        EnterCriticalSection(&g_stream_cs);
                        StreamReg* sreg=NULL; int sri;
                        for(sri=STREAM_REG_MAX-1;sri>=0;sri--)
                            if(g_streams[sri].used){sreg=&g_streams[sri];break;}
                        QUIC_STREAM_CB cb=sreg?sreg->real_cb:NULL;
                        void* sctx=sreg?sreg->real_ctx:NULL;
                        HQUIC sh=sreg?sreg->handle:NULL;
                        LeaveCriticalSection(&g_stream_cs);
                        if(cb&&sh){
                            QUIC_BUF sbuf={dlen,(char*)spf};
                            QUIC_STREAM_EVENT sev={0};
                            sev.Type=QUIC_STREAM_EVENT_RECEIVE;
                            sev.RECEIVE.Buffers=&sbuf; sev.RECEIVE.BufferCount=1; sev.RECEIVE.TotalBufferLength=dlen;
                            cb(sh,sctx,&sev);
                            pipe_log("[SPOOF] %uB → stream cb sh=%p",dlen,sh);
                        } else pipe_log("[SPOOF] No stream registered");
                        free(spf);
                    }
                }
            }
            else if (!strcmp(buf,"TRADE_CAPTURE_ON"))  { g_trade_capture=TRUE;  pipe_log("[TRADE] Capture ON"); }
            else if (!strcmp(buf,"TRADE_CAPTURE_OFF")) { g_trade_capture=FALSE; pipe_log("[TRADE] Capture OFF"); }
            /* v20 commands */
            else if (!strcmp(buf,"INV_SNAPSHOT")) {
                pipe_log("[INV] Snapshot command received — C# will capture current tracker state");
            }
            else if (!strcmp(buf,"INV_LOCK_ON"))  { g_inv_lock=TRUE;  pipe_log("[INV] Lock ON — will re-inject cached 0xAA on each server update"); }
            else if (!strcmp(buf,"INV_LOCK_OFF")) { g_inv_lock=FALSE; pipe_log("[INV] Lock OFF"); }
            else if (!strncmp(buf,"INV_CACHE_SET ",14)) {
                const char* hex=buf+14; size_t hlen=strlen(hex); uint32_t dlen=(uint32_t)(hlen/2);
                if(dlen>0&&dlen<=8192){
                    EnterCriticalSection(&g_inv_cs);
                    if(g_inv_cache) free(g_inv_cache);
                    g_inv_cache=(uint8_t*)malloc(dlen); g_inv_cache_len=dlen;
                    uint32_t ci; for(ci=0;ci<dlen;ci++){unsigned int b=0;sscanf(hex+ci*2,"%02x",&b);g_inv_cache[ci]=(uint8_t)b;}
                    LeaveCriticalSection(&g_inv_cs);
                    pipe_log("[INV] Cached %uB inventory payload for lock",dlen);
                }
            }
            else if (!strncmp(buf,"DUPE_SLOT ",10)) {
                unsigned int ss=0,ds=1,cnt=1,rep=5;
                sscanf(buf+10,"%u %u %u %u",&ss,&ds,&cnt,&rep);
                if(rep>64) rep=64;
                uint32_t di;
                for(di=0;di<rep;di++){
                    uint8_t df[20]={0}; uint32_t dflen=16; memcpy(df,&dflen,4);
                    df[4]=0xAF; df[5]=0x00;
                    memcpy(df+8,&ss,4); memcpy(df+12,&ds,4); memcpy(df+16,&cnt,4);
                    msquic_inject(df,20);
                }
                pipe_log("[DUPE] Forged %u × 0xAF MoveItemStack src=%u dst=%u cnt=%u",rep,ss,ds,cnt);
            }
            else if (!strncmp(buf,"WINDOW_STEAL ",13)) {
                unsigned int wid=0,cslot=0,pslot=0;
                sscanf(buf+13,"%u %u %u",&wid,&cslot,&pslot);
                uint8_t wf[28]={0}; uint32_t wflen=20; memcpy(wf,&wflen,4);
                wf[4]=0xCB; wf[5]=0x00;
                memcpy(wf+8,&wid,4); uint32_t atype=0; memcpy(wf+12,&atype,4);
                memcpy(wf+16,&cslot,4); memcpy(wf+20,&pslot,4);
                msquic_inject(wf,28);
                pipe_log("[STEAL] WindowSteal wid=%u container[%u]→player[%u]",wid,cslot,pslot);
            }
            else if (!strncmp(buf,"ITEM_SPAM_START ",16)) {
                unsigned int stid=0,ss2=0,scnt=1,sdel=500;
                sscanf(buf+16,"%x %u %u %u",&stid,&ss2,&scnt,&sdel);
                g_item_spam_typeid=stid; g_item_spam_slot=ss2;
                g_item_spam_count=scnt; g_item_spam_delay=sdel;
                g_item_spam_active=TRUE;
                if(g_item_spam_th) { WaitForSingleObject(g_item_spam_th,200); CloseHandle(g_item_spam_th); }
                g_item_spam_th=CreateThread(NULL,0,item_spam_thread,NULL,0,NULL);
                pipe_log("[SPAM] ItemSpam ON typeId=0x%X slot=%u count=%u delay=%ums",stid,ss2,scnt,sdel);
            }
            else if (!strcmp(buf,"ITEM_SPAM_STOP")) {
                g_item_spam_active=FALSE;
                pipe_log("[SPAM] ItemSpam OFF  (sent %ld)",g_item_spam_sent);
            }
            else if (!strncmp(buf,"PERM_TEST_BIT ",14)) {
                unsigned int bit=0; sscanf(buf+14,"%u",&bit);
                if(bit<32 && g_last_player_setup_len>16){
                    EnterCriticalSection(&g_setup_cs);
                    uint8_t* copy=(uint8_t*)malloc(g_last_player_setup_len);
                    if(copy){
                        memcpy(copy,g_last_player_setup,g_last_player_setup_len);
                        uint32_t mask=(1u<<bit);
                        memcpy(copy+12,&mask,4);
                        uint32_t flen=g_last_player_setup_len+4;
                        uint32_t total=4+4+g_last_player_setup_len;
                        uint8_t* frame=(uint8_t*)malloc(total);
                        if(frame){
                            memcpy(frame,&flen,4); frame[4]=0x12; frame[5]=0x00; frame[6]=0x00; frame[7]=0x00;
                            memcpy(frame+8,copy,g_last_player_setup_len);
                            EnterCriticalSection(&g_stream_cs);
                            StreamReg* sreg4=NULL; int sri4;
                            for(sri4=STREAM_REG_MAX-1;sri4>=0;sri4--)
                                if(g_streams[sri4].used){sreg4=&g_streams[sri4];break;}
                            QUIC_STREAM_CB cb4=sreg4?sreg4->real_cb:NULL;
                            void* ctx4=sreg4?sreg4->real_ctx:NULL; HQUIC sh4=sreg4?sreg4->handle:NULL;
                            LeaveCriticalSection(&g_stream_cs);
                            if(cb4&&sh4){
                                QUIC_BUF pb4={total,(char*)frame};
                                QUIC_STREAM_EVENT ev4={0};
                                ev4.Type=QUIC_STREAM_EVENT_RECEIVE;
                                ev4.RECEIVE.Buffers=&pb4; ev4.RECEIVE.BufferCount=1; ev4.RECEIVE.TotalBufferLength=total;
                                cb4(sh4,ctx4,&ev4);
                                pipe_log("[PERM] Bit %u (0x%08X) injected into PlayerSetup",bit,mask);
                            }
                            free(frame);
                        }
                        free(copy);
                    }
                    LeaveCriticalSection(&g_setup_cs);
                } else pipe_log("[PERM] No captured PlayerSetup or bit out of range");
            }
            else if (!strncmp(buf,"PERM_INJECT_MASK ",17)) {
                unsigned int mask=0; sscanf(buf+17,"%x",&mask);
                if(g_last_player_setup_len>16){
                    EnterCriticalSection(&g_setup_cs);
                    uint8_t* copy=(uint8_t*)malloc(g_last_player_setup_len);
                    if(copy){
                        memcpy(copy,g_last_player_setup,g_last_player_setup_len);
                        memcpy(copy+12,&mask,4);
                        uint32_t flen=g_last_player_setup_len+4;
                        uint32_t total=4+4+g_last_player_setup_len;
                        uint8_t* frame=(uint8_t*)malloc(total);
                        if(frame){
                            memcpy(frame,&flen,4); frame[4]=0x12; frame[5]=0x00; frame[6]=0x00; frame[7]=0x00;
                            memcpy(frame+8,copy,g_last_player_setup_len);
                            EnterCriticalSection(&g_stream_cs);
                            StreamReg* sreg5=NULL; int sri5;
                            for(sri5=STREAM_REG_MAX-1;sri5>=0;sri5--)
                                if(g_streams[sri5].used){sreg5=&g_streams[sri5];break;}
                            QUIC_STREAM_CB cb5=sreg5?sreg5->real_cb:NULL;
                            void* ctx5=sreg5?sreg5->real_ctx:NULL; HQUIC sh5=sreg5?sreg5->handle:NULL;
                            LeaveCriticalSection(&g_stream_cs);
                            if(cb5&&sh5){
                                QUIC_BUF pb5={total,(char*)frame};
                                QUIC_STREAM_EVENT ev5={0};
                                ev5.Type=QUIC_STREAM_EVENT_RECEIVE;
                                ev5.RECEIVE.Buffers=&pb5; ev5.RECEIVE.BufferCount=1; ev5.RECEIVE.TotalBufferLength=total;
                                cb5(sh5,ctx5,&ev5);
                                pipe_log("[PERM] Mask 0x%08X injected into PlayerSetup",mask);
                            }
                            free(frame);
                        }
                        free(copy);
                    }
                    LeaveCriticalSection(&g_setup_cs);
                }
            }
            else if (!strncmp(buf,"OPCODE_FUZZ_START ",18)) {
                unsigned int ostart=1,oend=0x1FF,odel=200;
                sscanf(buf+18,"%x %x %u",&ostart,&oend,&odel);
                g_opfuzz_start=(uint16_t)ostart; g_opfuzz_end=(uint16_t)oend;
                g_opfuzz_delay=odel; g_opfuzz_active=TRUE; g_opfuzz_cur=ostart;
                if(g_opfuzz_th){WaitForSingleObject(g_opfuzz_th,200);CloseHandle(g_opfuzz_th);}
                g_opfuzz_th=CreateThread(NULL,0,opfuzz_thread,NULL,0,NULL);
                pipe_log("[OPFUZZ] Start 0x%04X..0x%04X delay=%ums",ostart,oend,odel);
            }
            else if (!strcmp(buf,"OPCODE_FUZZ_STOP")) {
                g_opfuzz_active=FALSE;
                pipe_log("[OPFUZZ] Stopped at 0x%04X",g_opfuzz_cur);
            }
            else if (!strcmp(buf,"OPCODE_FUZZ_STATUS"))
                pipe_log("[OPFUZZ] cur=0x%04X active=%d sent=%ld",g_opfuzz_cur,(int)g_opfuzz_active,g_opfuzz_sent);
            else if (!strncmp(buf,"WAYPOINT_ADD ",13)) {
                float wx2=0,wy2=0,wz2=0; sscanf(buf+13,"%f %f %f",&wx2,&wy2,&wz2);
                EnterCriticalSection(&g_wp_cs);
                if(g_wp_count<WAYPOINT_MAX){
                    g_waypoints[g_wp_count].x=wx2; g_waypoints[g_wp_count].y=wy2;
                    g_waypoints[g_wp_count].z=wz2; g_wp_count++;
                }
                LeaveCriticalSection(&g_wp_cs);
                pipe_log("[WP] Added (%.1f,%.1f,%.1f)  total=%d",wx2,wy2,wz2,g_wp_count);
            }
            else if (!strcmp(buf,"WAYPOINT_CLEAR")) {
                EnterCriticalSection(&g_wp_cs); g_wp_count=0; g_wp_cur=0; LeaveCriticalSection(&g_wp_cs);
                pipe_log("[WP] Cleared");
            }
            else if (!strncmp(buf,"WAYPOINT_RUN ",13)) {
                unsigned int wpdel=1000; sscanf(buf+13,"%u",&wpdel);
                g_wp_delay=wpdel; g_wp_active=TRUE; g_wp_cur=0;
                if(g_wp_th){WaitForSingleObject(g_wp_th,200);CloseHandle(g_wp_th);}
                g_wp_th=CreateThread(NULL,0,waypoint_thread,NULL,0,NULL);
                pipe_log("[WP] Running %d waypoints delay=%ums",g_wp_count,wpdel);
            }
            else if (!strcmp(buf,"WAYPOINT_STOP")) {
                g_wp_active=FALSE;
                pipe_log("[WP] Stopped at point %d",g_wp_cur);
            }
            else if (!strcmp(buf,"WAYPOINT_STATUS"))
                pipe_log("[WP] point=%d/%d active=%d",g_wp_cur,g_wp_count,(int)g_wp_active);
            else if (!strncmp(buf,"SCRIPT_EXEC ",12)) {
                const char* hex=buf+12; size_t hlen=strlen(hex); uint32_t dlen=(uint32_t)(hlen/2);
                if(dlen>0&&dlen<=65536){
                    char* script=(char*)malloc(dlen+1);
                    if(script){
                        uint32_t si2;
                        for(si2=0;si2<dlen;si2++){unsigned int b=0;sscanf(hex+si2*2,"%02x",&b);script[si2]=(char)b;}
                        script[dlen]='\0';
                        EnterCriticalSection(&g_script_cs);
                        if(g_script_buf) free(g_script_buf);
                        g_script_buf=script; g_script_len=dlen;
                        g_script_active=TRUE;
                        LeaveCriticalSection(&g_script_cs);
                        if(g_script_th){WaitForSingleObject(g_script_th,500);CloseHandle(g_script_th);}
                        g_script_th=CreateThread(NULL,0,script_thread,NULL,0,NULL);
                        pipe_log("[SCRIPT] Launching script %uB",dlen);
                    }
                }
            }
            else if (!strcmp(buf,"SCRIPT_STOP")) {
                g_script_active=FALSE;
                pipe_log("[SCRIPT] Stop requested");
            }
            /* v19 commands */
            else if (!strncmp(buf,"VELOCITY_LAUNCH ",16)) {
                float vx=0,vy=0,vz=0; sscanf(buf+16,"%f %f %f",&vx,&vy,&vz);
                g_launch_vx=vx; g_launch_vy=vy; g_launch_vz=vz;
                g_launch_armed=TRUE;
                pipe_log("[LAUNCH] Armed vx=%.2f vy=%.2f vz=%.2f",vx,vy,vz);
            }
            else if (!strcmp(buf,"VELOCITY_LAUNCH_OFF")) { g_launch_armed=FALSE; pipe_log("[LAUNCH] Cleared"); }
            else if (!strncmp(buf,"TIME_SET ",9)) {
                unsigned int ticks=0; sscanf(buf+9,"%u",&ticks);
                uint8_t tf[12]={0}; uint32_t tflen=8; memcpy(tf,&tflen,4);
                tf[4]=0x92; tf[5]=0x00; memcpy(tf+8,&ticks,4);
                EnterCriticalSection(&g_stream_cs);
                StreamReg* sreg2=NULL; int sri2;
                for(sri2=STREAM_REG_MAX-1;sri2>=0;sri2--)
                    if(g_streams[sri2].used){sreg2=&g_streams[sri2];break;}
                QUIC_STREAM_CB cb2=sreg2?sreg2->real_cb:NULL;
                void* ctx2=sreg2?sreg2->real_ctx:NULL; HQUIC sh2=sreg2?sreg2->handle:NULL;
                LeaveCriticalSection(&g_stream_cs);
                if(cb2&&sh2){
                    QUIC_BUF tb={12,(char*)tf}; QUIC_STREAM_EVENT tev={0};
                    tev.Type=QUIC_STREAM_EVENT_RECEIVE; tev.RECEIVE.Buffers=&tb;
                    tev.RECEIVE.BufferCount=1; tev.RECEIVE.TotalBufferLength=12;
                    cb2(sh2,ctx2,&tev);
                    pipe_log("[TIME] Spoofed UpdateTime ticks=%u",ticks);
                } else pipe_log("[TIME] No stream registered");
            }
            else if (!strncmp(buf,"WEATHER_SET ",12)) {
                unsigned int wt=0; sscanf(buf+12,"%u",&wt);
                uint8_t wf[12]={0}; uint32_t wflen=8; memcpy(wf,&wflen,4);
                wf[4]=0x95; wf[5]=0x00; memcpy(wf+8,&wt,4);
                EnterCriticalSection(&g_stream_cs);
                StreamReg* sreg3=NULL; int sri3;
                for(sri3=STREAM_REG_MAX-1;sri3>=0;sri3--)
                    if(g_streams[sri3].used){sreg3=&g_streams[sri3];break;}
                QUIC_STREAM_CB cb3=sreg3?sreg3->real_cb:NULL;
                void* ctx3=sreg3?sreg3->real_ctx:NULL; HQUIC sh3=sreg3?sreg3->handle:NULL;
                LeaveCriticalSection(&g_stream_cs);
                if(cb3&&sh3){
                    QUIC_BUF wb={12,(char*)wf}; QUIC_STREAM_EVENT wev={0};
                    wev.Type=QUIC_STREAM_EVENT_RECEIVE; wev.RECEIVE.Buffers=&wb;
                    wev.RECEIVE.BufferCount=1; wev.RECEIVE.TotalBufferLength=12;
                    cb3(sh3,ctx3,&wev);
                    pipe_log("[WEATHER] Spoofed UpdateWeather type=%u",wt);
                } else pipe_log("[WEATHER] No stream registered");
            }
            else if (!strcmp(buf,"RESPAWN_FORCE")) {
                uint8_t rf[8]={0}; uint32_t rfl=4; memcpy(rf,&rfl,4);
                rf[4]=0x6A; rf[5]=0x00;
                msquic_inject(rf,8);
                pipe_log("[RESPAWN] Forged 0x6A ClientRespawn");
            }
            else if (!strncmp(buf,"ENTITY_SCAN ",12)) {
                uint64_t scan_eid=0; sscanf(buf+12,"%llx",(unsigned long long*)&scan_eid);
                g_prop_scan_eid=scan_eid; g_prop_scan_active=TRUE; g_prop_scan_idx=0;
                pipe_log("[ESCAN] Starting prop scan eid=0x%llx",(unsigned long long)scan_eid);
            }
            else if (!strcmp(buf,"ENTITY_SCAN_STOP")) {
                g_prop_scan_active=FALSE;
                pipe_log("[ESCAN] Stopped at idx=%d",g_prop_scan_idx);
            }
            else if (!strcmp(buf,"SPECTATE_ON"))  { g_spectate_mode=TRUE;  pipe_log("[SPECTATE] Enabled — movement suppressed to server"); }
            else if (!strcmp(buf,"SPECTATE_OFF")) { g_spectate_mode=FALSE; pipe_log("[SPECTATE] Disabled"); }
            else if (!strcmp(buf,"NOCLIP_ON"))    { g_noclip=TRUE;  pipe_log("[NOCLIP] C2S 0x70 DamageInfo will be dropped"); }
            else if (!strcmp(buf,"NOCLIP_OFF"))   { g_noclip=FALSE; pipe_log("[NOCLIP] Disabled"); }
            else if (!strcmp(buf,"INF_REACH_ON")) { g_inf_reach=TRUE;  pipe_log("[REACH] 0x71 RangeCheck drop ON"); }
            else if (!strcmp(buf,"INF_REACH_OFF")){ g_inf_reach=FALSE; pipe_log("[REACH] 0x71 RangeCheck drop OFF"); }
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
            else if (!strncmp(buf, "FREEZE_HP ", 10)) {
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

    Sleep(1000);

    while (g_active) {
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
                    "HyForceHook/20-%s PID=%lu EXE=%s | "
                    "Hooks:WinSock+GQCS+BoringSSL+MSQUIC+QUICHE(Hytale)+QUIC_BYPASS | "
                    "Features:EmbeddedZstd+VarInt+HytalePackets+HTTP3+StreamReassembly+TLSKeyExtract | "
                    "IOCP+STRINGSCAN+MODLIST+GADGETSCAN+EXPLOIT+PLAINTEXT+QUIC_RAW | "
                    "FIX:WSARecv_IOCP_registered",
                    arch, (unsigned long)pid, exe[0] ? exe : "?");

                pipe_send(MSG_STATUS, hs, (uint32_t)strlen(hs) + 1);
            }
        }

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

        InitializeCriticalSection(&g_cs);
        InitializeCriticalSection(&g_replay_cs);
        InitializeCriticalSection(&g_kcs);
        InitializeCriticalSection(&g_ovl_cs);
        InitializeCriticalSection(&g_sock_cs);
        InitializeCriticalSection(&g_freeze_cs);
        InitializeCriticalSection(&g_stream_cs);
        InitializeCriticalSection(&g_quic_cs);
        InitializeCriticalSection(&g_quic_ctx_cs);
        InitializeCriticalSection(&g_http3_cs);
        InitializeCriticalSection(&g_movement_cs);
        InitializeCriticalSection(&g_record_cs);
        InitializeCriticalSection(&g_inv_cs);
        InitializeCriticalSection(&g_setup_cs);
        InitializeCriticalSection(&g_wp_cs);
        InitializeCriticalSection(&g_script_cs);
        memset(g_streams, 0, sizeof(g_streams));
        memset(g_freeze_slots, 0, sizeof(g_freeze_slots));
        g_freeze_gen_th = CreateThread(NULL, 0, freeze_generic_th, NULL, 0, NULL);

        g_mutex = CreateMutexW(NULL, FALSE, NULL);
        g_pcap_mutex = CreateMutexW(NULL, FALSE, NULL);
        if (!g_mutex || !g_pcap_mutex) return FALSE;

        g_tls_idx = TlsAlloc();

        memset(g_ovl, 0, sizeof(g_ovl));
        memset(g_sock_cache, 0, sizeof(g_sock_cache));
        init_shm();

        SetEnvironmentVariableA("SSLKEYLOGFILE", "C:\\temp\\ssl_keys.log");

        HMODULE ws2 = GetModuleHandleW(L"ws2_32.dll");
        if (!ws2) ws2 = LoadLibraryW(L"ws2_32.dll");
        if (!ws2) return FALSE;

        orig_WSASendTo = (WSASendTo_t)GetProcAddress(ws2, "WSASendTo");
        orig_WSARecvFrom = (WSARecvFrom_t)GetProcAddress(ws2, "WSARecvFrom");
        orig_WSARecv = (WSARecv_t)GetProcAddress(ws2, "WSARecv");
        orig_sendto = (sendto_t)GetProcAddress(ws2, "sendto");
        orig_recvfrom = (recvfrom_t)GetProcAddress(ws2, "recvfrom");

        if (orig_WSASendTo) { memcpy(sv_wsa_send, orig_WSASendTo, 14); jmp_write(orig_WSASendTo, (void*)hook_WSASendTo); }
        if (orig_WSARecvFrom) { memcpy(sv_wsa_recv, orig_WSARecvFrom, 14); jmp_write(orig_WSARecvFrom, (void*)hook_WSARecvFrom); }
        if (orig_WSARecv) { memcpy(sv_wsa_recv2, orig_WSARecv, 14); jmp_write(orig_WSARecv, (void*)hook_WSARecv); }
        if (orig_sendto) { memcpy(sv_send, orig_sendto, 14); jmp_write(orig_sendto, (void*)hook_sendto); }
        if (orig_recvfrom) { memcpy(sv_recv, orig_recvfrom, 14); jmp_write(orig_recvfrom, (void*)hook_recvfrom); }

        orig_WSASend_nb = (WSASend_nb_t)GetProcAddress(ws2, "WSASend");
        if (orig_WSASend_nb) { memcpy(sv_wsa_send_nb, orig_WSASend_nb, 14); jmp_write(orig_WSASend_nb, (void*)hook_WSASend_nb); }
        orig_send_nb = (send_nb_t)GetProcAddress(ws2, "send");
        if (orig_send_nb) { memcpy(sv_send_nb, orig_send_nb, 14); jmp_write(orig_send_nb, (void*)hook_send_nb); }

        HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
        if (k32) {
            orig_GQCS = (GQCS_t)GetProcAddress(k32, "GetQueuedCompletionStatus");
            if (orig_GQCS) { memcpy(sv_gqcs, orig_GQCS, 14); jmp_write(orig_GQCS, (void*)hook_GQCS); }
        }

        hook_boringssl();

        probe_quiche();

        probe_msquic();

        g_active = TRUE;
        g_io_th = CreateThread(NULL, 0, io_thread, NULL, 0, NULL);
        g_cmd_th = CreateThread(NULL, 0, cmd_thread, NULL, 0, NULL);
        CreateThread(NULL, 0, hb_thread, NULL, 0, NULL);
        CreateThread(NULL, 0, injector_monitor_th, NULL, 0, NULL);

    }
    else if (reason == DLL_PROCESS_DETACH) {
        g_active = FALSE;

        if (orig_WSASendTo)   jmp_restore(orig_WSASendTo, sv_wsa_send);
        if (orig_WSARecvFrom) jmp_restore(orig_WSARecvFrom, sv_wsa_recv);
        if (orig_WSARecv)     jmp_restore(orig_WSARecv, sv_wsa_recv2);
        if (orig_sendto)      jmp_restore(orig_sendto, sv_send);
        if (orig_recvfrom)    jmp_restore(orig_recvfrom, sv_recv);
        if (orig_GQCS)        jmp_restore(orig_GQCS, sv_gqcs);
        if (orig_WSASend_nb)  jmp_restore(orig_WSASend_nb, sv_wsa_send_nb);
        if (orig_send_nb)     jmp_restore(orig_send_nb, sv_send_nb);
        if (orig_ssl_write)   jmp_restore(orig_ssl_write, sv_ssl_write);
        if (orig_ssl_read)    jmp_restore(orig_ssl_read, sv_ssl_read);
        if (orig_quiche_recv) jmp_restore(orig_quiche_recv, sv_quiche_recv);
        if (orig_quiche_send) jmp_restore(orig_quiche_send, sv_quiche_send);
        if (orig_MsQuicOpen) jmp_restore(orig_MsQuicOpen, sv_msquic_open);

        FlushInstructionCache(GetCurrentProcess(), NULL, 0);

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
        DeleteCriticalSection(&g_sock_cs);
        DeleteCriticalSection(&g_freeze_cs);
        DeleteCriticalSection(&g_quic_cs);
        DeleteCriticalSection(&g_stream_cs);
        DeleteCriticalSection(&g_quic_ctx_cs);
        DeleteCriticalSection(&g_http3_cs);
        DeleteCriticalSection(&g_movement_cs);
        DeleteCriticalSection(&g_record_cs);
        DeleteCriticalSection(&g_inv_cs);
        DeleteCriticalSection(&g_setup_cs);
        DeleteCriticalSection(&g_wp_cs);
        DeleteCriticalSection(&g_script_cs);
    }

    return TRUE;
}