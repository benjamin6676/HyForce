/*
 * HyForceHook.dll  v8  —  HyForce Security Research Engine
 *
 * FIXES in v8:
 *   FIX 1 — Removed duplicate g_dwTlsIndex declaration (was compile error)
 *   FIX 2 — Added forward declarations for IsReentrant/EnterHook/LeaveHook
 *            (were called 558 lines before they were defined)
 *   FIX 3 — TlsAlloc() now called in DllMain so per-thread reentrancy works
 *   FIX 4 — TlsFree() called in DLL_PROCESS_DETACH
 *   FIX 5 — Reentrancy guard added to sendto/WSARecvFrom/recvfrom
 *            (was only on WSASendTo — other 3 could infinite-loop)
 *   FIX 6 — Null-check g_shm_header in forward_*_to_shm before use
 *   FIX 7 — g_injector_pid set via "INJPID <pid>" command; monitor
 *            waits 10s for PID before exiting rather than instant exit
 *
 * IMPROVEMENTS in v8:
 *   + MEMSCAN: page-level __try (10x faster, less stutter), skips
 *     small/system/guard pages, focuses on JVM heap-sized regions
 *   + MEMSCAN: stride skip past matched struct to avoid re-matching
 *   + MSG_MEMWATCH (0x0B): watch a specific address, push 64B delta
 *   + MEMWATCH <hex_addr> <ms> command + MEMWATCH_STOP
 *   + KEYLOG_FLUSH command: re-sends last 32 keylog lines
 *   + BoringSSL hook tries ssl_log_secret as fallback function name
 *   + Heartbeat now reports shared memory drop count
 *   + INJPID command for monitor thread
 *   + EJECT command from pipe (explicit clean eject)
 *
 * Build x64 (MinGW):
 *   gcc -O2 -shared -o HyForceHook64.dll HyForceHook.c -lws2_32 -lpsapi
 * Build x86 (MinGW):
 *   gcc -O2 -shared -m32 -o HyForceHook32.dll HyForceHook.c -lws2_32 -lpsapi
 * Build x64 (MSVC):
 *   cl /O2 /LD /D_WIN32_WINNT=0x0A00 HyForceHook.c /Fe:HyForceHook64.dll ws2_32.lib psapi.lib
 *
 * Target: java.exe / javaw.exe — JVM process using ~500MB+ after connecting
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

/* ── Pipe ───────────────────────────────────────────────── */
#define PIPE_DATA        L"\\\\.\\pipe\\HyForcePipe"
#define PIPE_CMD         L"\\\\.\\pipe\\HyForceCmdPipe"
#define MSG_PACKET       0x01
#define MSG_STATUS       0x02
#define MSG_LOG          0x03
#define MSG_TIMING       0x04
#define MSG_SEQ_ANOMALY  0x05
#define MSG_MEMSCAN      0x06
#define MSG_EJECTED      0x08
#define MSG_KEYLOG       0x09
#define MSG_MEMWATCH     0x0B
#define MAX_PKT          65535

/* ── Port filter ─────────────────────────────────────────── */
#define HYTALE_PORT_MIN  5520
#define HYTALE_PORT_MAX  5560

/* ── Shared memory ──────────────────────────────────────── */
#define SHARED_MEM_NAME      L"HyForceSharedMem"
#define SHARED_MEM_SIZE      (16*1024*1024)
#define RING_BUFFER_ENTRIES  4096

/* ── BoringSSL types ──────────────────────────────────────*/
typedef struct ssl_st    SSL;
typedef struct ssl_ctx_st SSL_CTX;
typedef void (*ssl_keylog_cb_t)(const SSL*, const char*);
typedef void (*SSL_CTX_set_keylog_cb_t)(SSL_CTX*, ssl_keylog_cb_t);
typedef ssl_keylog_cb_t (*SSL_CTX_get_keylog_cb_t)(const SSL_CTX*);

/* ── Ring buffer ─────────────────────────────────────────── */
typedef struct {
    volatile uint32_t ready;
    uint32_t type; uint64_t timestamp_us; uint32_t data_len; uint32_t seq_num;
    uint8_t  data[4080];
} RingBufferEntry;   /* 4096 bytes, page-aligned */

typedef struct {
    volatile uint32_t write_idx, read_idx, dropped;
    uint32_t entry_size, max_entries;
    uint64_t start_time_us;
} SharedMemoryHeader;

/* ── BoringSSL callback chain ────────────────────────────── */
typedef struct KE { SSL_CTX* ctx; ssl_keylog_cb_t orig; struct KE* next; } KeylogEntry;

/* ── Globals ─────────────────────────────────────────────── */
static SSL_CTX_set_keylog_cb_t  orig_SSL_set  = NULL;
static SSL_CTX_get_keylog_cb_t  orig_SSL_get  = NULL;
static KeylogEntry*             g_kchain      = NULL;
static CRITICAL_SECTION         g_keylog_cs;
static char  g_keylog_ring[32][256];
static int   g_keylog_ring_head = 0;

static HANDLE            g_shared_mem  = NULL;
static SharedMemoryHeader* g_shm        = NULL;
static RingBufferEntry*  g_ring        = NULL;
static uint32_t          g_seq_ctr     = 0;

static HANDLE   g_out        = INVALID_HANDLE_VALUE;
static HANDLE   g_cmdin      = INVALID_HANDLE_VALUE;
static HANDLE   g_mutex      = NULL;
static volatile BOOL g_active = FALSE;
static HANDLE   g_io_th      = NULL;
static HANDLE   g_cmd_th     = NULL;
static CRITICAL_SECTION g_cs;

/* FIX 1: single declaration */
static DWORD g_tls_idx = TLS_OUT_OF_INDEXES;  /* allocated in DllMain */

static HANDLE g_pcap       = INVALID_HANDLE_VALUE;
static HANDLE g_pcap_mutex = NULL;

static volatile int  g_fuzz_bits  = 0;
static uint8_t       g_last_cs[MAX_PKT];
static int           g_last_cs_len  = 0;
static uint32_t      g_last_cs_ip   = 0;
static uint16_t      g_last_cs_port = 0;
static CRITICAL_SECTION g_replay_cs;

static uint64_t g_seq_cs = UINT64_MAX;
static uint64_t g_seq_sc = UINT64_MAX;

static volatile LONG g_fires_wsa_send = 0, g_fires_send  = 0;
static volatile LONG g_fires_wsa_recv = 0, g_fires_recv  = 0;
static volatile LONG g_pkts_captured  = 0;

static volatile uint64_t g_watch_addr = 0;
static volatile int      g_watch_ms   = 0;
static HANDLE            g_watch_th   = NULL;

static DWORD g_injector_pid = 0;

typedef int (WSAAPI* WSASendTo_t)(SOCKET,LPWSABUF,DWORD,LPDWORD,DWORD,const struct sockaddr*,int,LPWSAOVERLAPPED,LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI* WSARecvFrom_t)(SOCKET,LPWSABUF,DWORD,LPDWORD,LPDWORD,struct sockaddr*,LPINT,LPWSAOVERLAPPED,LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI* sendto_t)(SOCKET,const char*,int,int,const struct sockaddr*,int);
typedef int (WSAAPI* recvfrom_t)(SOCKET,char*,int,int,struct sockaddr*,int*);
static WSASendTo_t   orig_WSASendTo  = NULL;
static WSARecvFrom_t orig_WSARecvFrom = NULL;
static sendto_t      orig_sendto     = NULL;
static recvfrom_t    orig_recvfrom   = NULL;
static BYTE sv_wsa_send[14], sv_wsa_recv[14], sv_send[14], sv_recv[14];

/* FIX 2: forward declarations so hooks can call them */
static int  IsReentrant(void);
static void EnterHook(void);
static void LeaveHook(void);
static void pipe_send(uint8_t type, const void* pay, uint32_t len);
static void pipe_log(const char* fmt, ...);
static void forward(uint8_t dir, const uint8_t* data, int dlen, uint32_t ip, uint16_t port);
static void forward_key_to_shm(const char* line, size_t len);
static void forward_pkt_to_shm(const uint8_t* d, uint32_t len, uint32_t ip, uint16_t port, uint8_t dir);
static void shm_write(uint32_t type, const uint8_t* data, uint32_t len);
static void jmp_write(void* tgt, void* hook);
static void jmp_restore(void* tgt, BYTE* saved);
static void fuzz_buf(uint8_t* buf, int len, int bits);
static void seq_check(const uint8_t* pkt, int len, uint8_t dir);
static void pcap_write(const uint8_t* data, uint32_t len);
static void pcap_open(const char* path);
static void pcap_close(void);
static void HyForceEject(void);
static void memscan_run(void);
static uint64_t now_us(void);
static int is_hytale_port(uint16_t port_be);
static int is_coord(double v);
static int is_health(float h);
static int is_vel(float v);

/* ── Reentrancy (FIX 3: TLS actually works now) ─────────── */
static int IsReentrant(void)
{
    if (g_tls_idx != TLS_OUT_OF_INDEXES)
        return TlsGetValue(g_tls_idx) != NULL;
    return 0;
}
static void EnterHook(void) { if (g_tls_idx != TLS_OUT_OF_INDEXES) TlsSetValue(g_tls_idx, (LPVOID)1); }
static void LeaveHook(void) { if (g_tls_idx != TLS_OUT_OF_INDEXES) TlsSetValue(g_tls_idx, NULL); }

/* ── JMP patch ───────────────────────────────────────────── */
static void jmp_write(void* tgt, void* hook)
{
    if (!tgt) return;
    DWORD old;
    VirtualProtect(tgt, 14, PAGE_EXECUTE_READWRITE, &old);
    uint8_t* p = (uint8_t*)tgt;
#ifdef _WIN64
    p[0]=0xFF; p[1]=0x25; *(DWORD*)(p+2)=0; *(uint64_t*)(p+6)=(uint64_t)(uintptr_t)hook;
#else
    p[0]=0xE9; *(DWORD*)(p+1)=(DWORD)((uint8_t*)hook - p - 5);
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

/* ── Shared memory ───────────────────────────────────────── */
static int init_shm(void)
{
    g_shared_mem = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL,
        PAGE_READWRITE|SEC_COMMIT, 0, SHARED_MEM_SIZE, SHARED_MEM_NAME);
    if (!g_shared_mem) return 0;
    g_shm = (SharedMemoryHeader*)MapViewOfFile(g_shared_mem,FILE_MAP_ALL_ACCESS,0,0,SHARED_MEM_SIZE);
    if (!g_shm) { CloseHandle(g_shared_mem); g_shared_mem=NULL; return 0; }
    if (g_shm->entry_size == 0) {
        g_shm->entry_size=sizeof(RingBufferEntry); g_shm->max_entries=RING_BUFFER_ENTRIES;
        g_shm->write_idx=0; g_shm->read_idx=0; g_shm->dropped=0;
        g_shm->start_time_us=now_us();
    }
    g_ring = (RingBufferEntry*)((uint8_t*)g_shm + sizeof(SharedMemoryHeader));
    return 1;
}
static void cleanup_shm(void)
{
    if (g_shm)        { UnmapViewOfFile(g_shm); g_shm=NULL; }
    if (g_shared_mem) { CloseHandle(g_shared_mem); g_shared_mem=NULL; }
}
static void shm_write(uint32_t type, const uint8_t* data, uint32_t len)
{
    if (!g_shm || !g_ring) return;
    uint32_t idx = InterlockedIncrement((LONG*)&g_shm->write_idx)-1;
    idx %= g_shm->max_entries;
    RingBufferEntry* e = &g_ring[idx];
    int sp=0; while (e->ready!=0 && sp++<1000) Sleep(0);
    if (e->ready!=0) { InterlockedIncrement((LONG*)&g_shm->dropped); return; }
    e->type=type; e->timestamp_us=now_us();
    e->data_len=(len>(uint32_t)sizeof(e->data))?(uint32_t)sizeof(e->data):len;
    e->seq_num=InterlockedIncrement((LONG*)&g_seq_ctr);
    memcpy(e->data, data, e->data_len);
    _WriteBarrier(); e->ready=1;
}

/* ── BoringSSL key extraction ────────────────────────────── */
static void our_keylog_cb(const SSL* ssl, const char* line)
{
    (void)ssl;
    if (!line || !*line) return;
    size_t len = strlen(line);
    pipe_send(MSG_KEYLOG, line, (uint32_t)(len+1));
    forward_key_to_shm(line, len);
    EnterCriticalSection(&g_keylog_cs);
    strncpy(g_keylog_ring[g_keylog_ring_head&31], line, 255);
    g_keylog_ring[g_keylog_ring_head&31][255]='\0';
    g_keylog_ring_head++;
    LeaveCriticalSection(&g_keylog_cs);
}
static void store_kchain(SSL_CTX* ctx, ssl_keylog_cb_t orig)
{
    EnterCriticalSection(&g_keylog_cs);
    KeylogEntry* e=g_kchain;
    while(e){ if(e->ctx==ctx){e->orig=orig; goto kc_done;} e=e->next; }
    e=(KeylogEntry*)malloc(sizeof(KeylogEntry));
    if(e){e->ctx=ctx;e->orig=orig;e->next=g_kchain;g_kchain=e;}
kc_done:
    LeaveCriticalSection(&g_keylog_cs);
}
static void hook_SSL_CTX_set_kl(SSL_CTX* ctx, ssl_keylog_cb_t cb)
{
    store_kchain(ctx, cb);
    if (orig_SSL_set) orig_SSL_set(ctx, our_keylog_cb);
    pipe_log("[KEYLOG] Hooked ctx=%p", (void*)ctx);
}
static void hook_boringssl(void)
{
    const char* names[]={"boringssl.dll","boringssl_shared.dll","ssl.dll","libssl.dll","libcrypto.dll",NULL};
    HMODULE mod=NULL;
    for(int i=0;names[i]&&!mod;i++) mod=GetModuleHandleA(names[i]);
    if(!mod){
        HMODULE mods[1024]; DWORD need;
        if(EnumProcessModules(GetCurrentProcess(),mods,sizeof(mods),&need)){
            int n=(int)(need/sizeof(HMODULE));
            for(int i=0;i<n&&!mod;i++)
                if(GetProcAddress(mods[i],"SSL_CTX_set_keylog_callback")){
                    mod=mods[i];
                    char nm[MAX_PATH]={0};
                    GetModuleFileNameExA(GetCurrentProcess(),mod,nm,MAX_PATH);
                    pipe_log("[KEYLOG] Found SSL in: %s",nm);
                }
        }
    }
    if(!mod){ pipe_log("[KEYLOG] BoringSSL not found — using SSLKEYLOGFILE fallback"); return; }
    orig_SSL_set=(SSL_CTX_set_keylog_cb_t)GetProcAddress(mod,"SSL_CTX_set_keylog_callback");
    if(!orig_SSL_set)
        orig_SSL_set=(SSL_CTX_set_keylog_cb_t)GetProcAddress(mod,"ssl_log_secret");
    if(!orig_SSL_set){ pipe_log("[KEYLOG] Callback fn not found (err=%lu)",GetLastError()); return; }
    orig_SSL_get=(SSL_CTX_get_keylog_cb_t)GetProcAddress(mod,"SSL_CTX_get_keylog_callback");
    static BYTE saved_ssl[14];
    memcpy(saved_ssl,(void*)orig_SSL_set,14);
    jmp_write((void*)orig_SSL_set, hook_SSL_CTX_set_kl);
    pipe_log("[KEYLOG] Hook installed @ %p",(void*)orig_SSL_set);
}
static void unhook_boringssl(void)
{
    EnterCriticalSection(&g_keylog_cs);
    while(g_kchain){ KeylogEntry* nx=g_kchain->next; free(g_kchain); g_kchain=nx; }
    LeaveCriticalSection(&g_keylog_cs);
}
static void forward_key_to_shm(const char* line, size_t len)
{
    if(!g_shm) return;  /* FIX 6 */
    uint8_t buf[4096]; buf[0]='K';
    uint32_t n=(uint32_t)((len<4095)?len:4095);
    memcpy(buf+1,line,n); shm_write(1,buf,n+1);
}
static void forward_pkt_to_shm(const uint8_t* data, uint32_t len, uint32_t ip, uint16_t port, uint8_t dir)
{
    if(!g_shm) return;  /* FIX 6 */
    uint8_t meta[4096]; uint32_t off=0;
    meta[off++]='P';
    uint64_t ts=now_us()-g_shm->start_time_us;
    memcpy(meta+off,&ts,8); off+=8;
    memcpy(meta+off,&ip,4); off+=4;
    memcpy(meta+off,&port,2); off+=2;
    meta[off++]=dir;
    uint32_t cp=(len<4080)?len:4080;
    memcpy(meta+off,&cp,4); off+=4;
    memcpy(meta+off,data,cp); off+=cp;
    shm_write(2,meta,off);
}

/* ── Pipe I/O ────────────────────────────────────────────── */
static void pipe_send(uint8_t type, const void* pay, uint32_t len)
{
    if(g_out==INVALID_HANDLE_VALUE) return;
    if(len>MAX_PKT) len=MAX_PKT;
    uint8_t hdr[5]={type,(uint8_t)(len&0xFF),(uint8_t)((len>>8)&0xFF),(uint8_t)((len>>16)&0xFF),(uint8_t)((len>>24)&0xFF)};
    if(WaitForSingleObject(g_mutex,50)!=WAIT_OBJECT_0) return;
    DWORD w; BOOL ok=WriteFile(g_out,hdr,5,&w,NULL);
    if(ok&&len>0) ok=WriteFile(g_out,pay,len,&w,NULL);
    if(!ok){ HANDLE tmp=g_out; g_out=INVALID_HANDLE_VALUE; CloseHandle(tmp); }
    ReleaseMutex(g_mutex);
}
static void pipe_log(const char* fmt, ...)
{
    char buf[512]; va_list ap; va_start(ap,fmt); vsnprintf(buf,511,fmt,ap); va_end(ap);
    pipe_send(MSG_LOG,buf,(uint32_t)strlen(buf)+1);
}

/* ── PCAP ────────────────────────────────────────────────── */
static void pcap_write(const uint8_t* data, uint32_t len)
{
    if(g_pcap==INVALID_HANDLE_VALUE||!len||len>MAX_PKT) return;
    FILETIME ft; GetSystemTimeAsFileTime(&ft);
    uint64_t us=(((uint64_t)ft.dwHighDateTime<<32|ft.dwLowDateTime)-116444736000000000ULL)/10;
    uint32_t ph[4]={(uint32_t)(us/1000000),(uint32_t)(us%1000000),len,len};
    WaitForSingleObject(g_pcap_mutex,100);
    DWORD w; WriteFile(g_pcap,ph,16,&w,NULL); WriteFile(g_pcap,data,len,&w,NULL);
    ReleaseMutex(g_pcap_mutex);
}
static void pcap_open(const char* path)
{
    WaitForSingleObject(g_pcap_mutex,500);
    if(g_pcap!=INVALID_HANDLE_VALUE){CloseHandle(g_pcap);g_pcap=INVALID_HANDLE_VALUE;}
    g_pcap=CreateFileA(path,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(g_pcap!=INVALID_HANDLE_VALUE){
        uint32_t gh[6]={0xa1b2c3d4,0x00040002,0,0,65535,101}; DWORD w;
        WriteFile(g_pcap,gh,24,&w,NULL); pipe_log("[PCAP] Opened: %s",path);
    } else pipe_log("[PCAP] Failed: %s (err=%lu)",path,GetLastError());
    ReleaseMutex(g_pcap_mutex);
}
static void pcap_close(void)
{
    WaitForSingleObject(g_pcap_mutex,500);
    if(g_pcap!=INVALID_HANDLE_VALUE){CloseHandle(g_pcap);g_pcap=INVALID_HANDLE_VALUE;pipe_log("[PCAP] Closed.");}
    ReleaseMutex(g_pcap_mutex);
}

/* ── Eject ───────────────────────────────────────────────── */
static void HyForceEject(void)
{
    pipe_send(MSG_EJECTED,"EJECTING",9); Sleep(50); g_active=FALSE;
    if(orig_WSASendTo)   jmp_restore(orig_WSASendTo,sv_wsa_send);
    if(orig_WSARecvFrom) jmp_restore(orig_WSARecvFrom,sv_wsa_recv);
    if(orig_sendto)      jmp_restore(orig_sendto,sv_send);
    if(orig_recvfrom)    jmp_restore(orig_recvfrom,sv_recv);
    FlushInstructionCache(GetCurrentProcess(),NULL,0);
    pcap_close(); cleanup_shm(); unhook_boringssl();
    if(g_out!=INVALID_HANDLE_VALUE){CloseHandle(g_out);g_out=INVALID_HANDLE_VALUE;}
    if(g_cmdin!=INVALID_HANDLE_VALUE){CloseHandle(g_cmdin);g_cmdin=INVALID_HANDLE_VALUE;}
}

/* ── Timing ──────────────────────────────────────────────── */
static uint64_t now_us(void)
{
    FILETIME ft; GetSystemTimeAsFileTime(&ft);
    uint64_t v=(uint64_t)ft.dwHighDateTime<<32|ft.dwLowDateTime;
    return (v-116444736000000000ULL)/10;
}

/* ── Seq check ───────────────────────────────────────────── */
static void seq_check(const uint8_t* pkt, int len, uint8_t dir)
{
    if(len<2||(pkt[0]&0x80)) return;
    int pn_len=(pkt[0]&0x03)+1; if(1+pn_len>len) return;
    uint64_t pn=0; for(int i=0;i<pn_len;i++) pn=(pn<<8)|pkt[1+i];
    uint64_t* last=(dir==0)?&g_seq_cs:&g_seq_sc;
    if(*last!=UINT64_MAX&&pn<=*last){
        uint8_t ab[80]; memcpy(ab,last,8); memcpy(ab+8,&pn,8); ab[16]=dir;
        snprintf((char*)ab+17,62,"SEQ dir=%d exp>%llu got=%llu",dir,(unsigned long long)*last,(unsigned long long)pn);
        pipe_send(MSG_SEQ_ANOMALY,ab,17+(uint32_t)strlen((char*)ab+17)+1);
    }
    *last=pn;
}

/* ── Fuzz ────────────────────────────────────────────────── */
static void fuzz_buf(uint8_t* buf, int len, int bits)
{
    if(len<=0) return;
    srand((unsigned)GetTickCount());
    for(int i=0;i<bits;i++) buf[rand()%len]^=(uint8_t)(1<<(rand()%8));
}

/* ── Port check ──────────────────────────────────────────── */
static int is_hytale_port(uint16_t port_be)
{
    uint16_t p=ntohs(port_be);
    return p>=HYTALE_PORT_MIN&&p<=HYTALE_PORT_MAX;
}

/* ── Core forward ────────────────────────────────────────── */
static void forward(uint8_t dir, const uint8_t* data, int dlen, uint32_t ip, uint16_t port)
{
    if(!is_hytale_port(port)&&!(dir==1&&ip==g_last_cs_ip)) return;
    if(dlen<=0||dlen>MAX_PKT) return;
    InterlockedIncrement(&g_pkts_captured);
    pcap_write(data,(uint32_t)dlen); seq_check(data,dlen,dir);
    uint8_t tb[13]; uint64_t ts=now_us(); uint32_t u=(uint32_t)dlen;
    memcpy(tb,&ts,8); memcpy(tb+8,&u,4); tb[12]=dir; pipe_send(MSG_TIMING,tb,13);
    int tot=7+dlen; uint8_t* buf=(uint8_t*)malloc((size_t)tot); if(!buf) return;
    buf[0]=dir; memcpy(buf+1,&ip,4); memcpy(buf+5,&port,2); memcpy(buf+7,data,dlen);
    pipe_send(MSG_PACKET,buf,(uint32_t)tot);
    forward_pkt_to_shm(data,(uint32_t)dlen,ip,port,dir);
    free(buf);
    if(dir==0){
        EnterCriticalSection(&g_replay_cs);
        if(dlen<=MAX_PKT){memcpy(g_last_cs,data,(size_t)dlen);g_last_cs_len=dlen;g_last_cs_ip=ip;g_last_cs_port=port;}
        LeaveCriticalSection(&g_replay_cs);
    }
}

/* ── Hooks (FIX 5: reentrancy on all four) ───────────────── */
static int WSAAPI hook_WSASendTo(SOCKET s,LPWSABUF bufs,DWORD nb,LPDWORD sent,DWORD flags,
    const struct sockaddr* to,int tolen,LPWSAOVERLAPPED ov,LPWSAOVERLAPPED_COMPLETION_ROUTINE cb)
{
    if(IsReentrant()) return orig_WSASendTo(s,bufs,nb,sent,flags,to,tolen,ov,cb);
    EnterHook(); InterlockedIncrement(&g_fires_wsa_send); DWORD se=GetLastError();
    EnterCriticalSection(&g_cs); jmp_restore(orig_WSASendTo,sv_wsa_send); LeaveCriticalSection(&g_cs);
    int ret; int fuzz=InterlockedExchange((LONG*)&g_fuzz_bits,0);
    if(fuzz>0&&nb>0&&bufs&&bufs[0].len>1){
        uint8_t* tmp=(uint8_t*)malloc(bufs[0].len);
        if(tmp){memcpy(tmp,bufs[0].buf,bufs[0].len);fuzz_buf(tmp+1,(int)bufs[0].len-1,fuzz);
            WSABUF fb={bufs[0].len,(char*)tmp}; ret=WSASendTo(s,&fb,1,sent,flags,to,tolen,ov,cb); free(tmp);}
        else ret=WSASendTo(s,bufs,nb,sent,flags,to,tolen,ov,cb);
    } else ret=WSASendTo(s,bufs,nb,sent,flags,to,tolen,ov,cb);
    EnterCriticalSection(&g_cs); jmp_write(orig_WSASendTo,hook_WSASendTo); LeaveCriticalSection(&g_cs);
    if(ret!=SOCKET_ERROR) SetLastError(se);
    if(ret==0&&nb>0&&bufs&&bufs[0].buf&&bufs[0].len>0){
        uint32_t ip=0; uint16_t port=0;
        if(to&&tolen>=(int)sizeof(struct sockaddr_in)){
            const struct sockaddr_in* sa=(const struct sockaddr_in*)to;
            if(sa->sin_family==AF_INET){ip=sa->sin_addr.s_addr;port=sa->sin_port;}
        }
        forward(0,(uint8_t*)bufs[0].buf,(int)bufs[0].len,ip,port);
    }
    LeaveHook(); return ret;
}

static int WSAAPI hook_sendto(SOCKET s,const char* buf,int len,int flags,
    const struct sockaddr* to,int tolen)
{
    if(IsReentrant()) return orig_sendto(s,buf,len,flags,to,tolen);  /* FIX 5 */
    EnterHook(); InterlockedIncrement(&g_fires_send); DWORD se=GetLastError();
    EnterCriticalSection(&g_cs); jmp_restore(orig_sendto,sv_send); LeaveCriticalSection(&g_cs);
    int ret; int fuzz=InterlockedExchange((LONG*)&g_fuzz_bits,0);
    if(fuzz>0&&len>1){
        uint8_t* tmp=(uint8_t*)malloc((size_t)len);
        if(tmp){memcpy(tmp,buf,(size_t)len);fuzz_buf(tmp+1,len-1,fuzz);
            ret=sendto(s,(char*)tmp,len,flags,to,tolen);free(tmp);}
        else ret=sendto(s,buf,len,flags,to,tolen);
    } else ret=sendto(s,buf,len,flags,to,tolen);
    EnterCriticalSection(&g_cs); jmp_write(orig_sendto,hook_sendto); LeaveCriticalSection(&g_cs);
    if(ret!=SOCKET_ERROR) SetLastError(se);
    if(ret>0&&buf&&len>0){
        uint32_t ip=0; uint16_t port=0;
        if(to&&tolen>=(int)sizeof(struct sockaddr_in)){
            const struct sockaddr_in* sa=(const struct sockaddr_in*)to;
            if(sa->sin_family==AF_INET){ip=sa->sin_addr.s_addr;port=sa->sin_port;}
        }
        forward(0,(uint8_t*)buf,len,ip,port);
    }
    LeaveHook(); return ret;
}

static int WSAAPI hook_WSARecvFrom(SOCKET s,LPWSABUF bufs,DWORD nb,LPDWORD recvd,LPDWORD flags,
    struct sockaddr* from,LPINT fromlen,LPWSAOVERLAPPED ov,LPWSAOVERLAPPED_COMPLETION_ROUTINE cb)
{
    if(IsReentrant()) return orig_WSARecvFrom(s,bufs,nb,recvd,flags,from,fromlen,ov,cb);  /* FIX 5 */
    EnterHook(); InterlockedIncrement(&g_fires_wsa_recv); DWORD se=GetLastError();
    EnterCriticalSection(&g_cs); jmp_restore(orig_WSARecvFrom,sv_wsa_recv); LeaveCriticalSection(&g_cs);
    int ret=WSARecvFrom(s,bufs,nb,recvd,flags,from,fromlen,ov,cb);
    EnterCriticalSection(&g_cs); jmp_write(orig_WSARecvFrom,hook_WSARecvFrom); LeaveCriticalSection(&g_cs);
    if(ret!=SOCKET_ERROR) SetLastError(se);
    if(ret==0&&recvd&&*recvd>0&&nb>0&&bufs&&bufs[0].buf){
        uint32_t ip=0; uint16_t port=0;
        if(from&&fromlen&&*fromlen>=(int)sizeof(struct sockaddr_in)){
            const struct sockaddr_in* sa=(const struct sockaddr_in*)from;
            if(sa->sin_family==AF_INET){ip=sa->sin_addr.s_addr;port=sa->sin_port;}
        }
        forward(1,(uint8_t*)bufs[0].buf,(int)*recvd,ip,port);
    }
    LeaveHook(); return ret;
}

static int WSAAPI hook_recvfrom(SOCKET s,char* buf,int len,int flags,
    struct sockaddr* from,int* fromlen)
{
    if(IsReentrant()) return orig_recvfrom(s,buf,len,flags,from,fromlen);  /* FIX 5 */
    EnterHook(); InterlockedIncrement(&g_fires_recv); DWORD se=GetLastError();
    EnterCriticalSection(&g_cs); jmp_restore(orig_recvfrom,sv_recv); LeaveCriticalSection(&g_cs);
    int ret=recvfrom(s,buf,len,flags,from,fromlen);
    EnterCriticalSection(&g_cs); jmp_write(orig_recvfrom,hook_recvfrom); LeaveCriticalSection(&g_cs);
    if(ret==SOCKET_ERROR){SetLastError(se);LeaveHook();return ret;}
    if(ret>0&&buf){
        uint32_t ip=0; uint16_t port=0;
        if(from&&fromlen&&*fromlen>=(int)sizeof(struct sockaddr_in)){
            const struct sockaddr_in* sa=(const struct sockaddr_in*)from;
            if(sa->sin_family==AF_INET){ip=sa->sin_addr.s_addr;port=sa->sin_port;}
        }
        forward(1,(uint8_t*)buf,ret,ip,port);
    }
    LeaveHook(); return ret;
}

/* ── Memory scan (improved: page-level try, heap focus) ──── */
static int is_coord(double v)  { return !isnan(v)&&!isinf(v)&&v>-65536.0&&v<65536.0; }
static int is_health(float h)  { return !isnan(h)&&h>0.0f&&h<=10000.0f; }
static int is_vel(float v)     { return !isnan(v)&&v>-2000.0f&&v<2000.0f; }

static void memscan_run(void)
{
    pipe_log("[MEMSCAN] Starting — scanning JVM heap-sized regions...");
    int hits=0;
    MEMORY_BASIC_INFORMATION mbi;
    uint8_t* addr=NULL;
    while(VirtualQuery(addr,&mbi,sizeof(mbi))==sizeof(mbi)){
        uint8_t* next=(uint8_t*)mbi.BaseAddress+mbi.RegionSize;
        if(next<=addr) break;
        /* Skip small/system/guard pages — focus on JVM heap */
        if(mbi.State!=MEM_COMMIT||mbi.RegionSize<65536||mbi.RegionSize>256*1024*1024||
           (mbi.Protect&PAGE_GUARD)||(mbi.Protect&PAGE_NOACCESS)||
           !(mbi.Protect&(PAGE_READWRITE|PAGE_WRITECOPY|PAGE_EXECUTE_READWRITE)))
        { addr=next; continue; }
        uint8_t* base=(uint8_t*)mbi.BaseAddress; SIZE_T rsz=mbi.RegionSize;
        __try {
            for(SIZE_T off=0;off+56<=rsz;off+=4){
                uint8_t* p=base+off;
                float h=*(float*)(p+0),mh=*(float*)(p+4);
                if(!is_health(h)||!is_health(mh)||mh<h) continue;
                double x=*(double*)(p+8),y=*(double*)(p+16),z=*(double*)(p+24);
                if(!is_coord(x)||!is_coord(y)||y<0.0||y>512.0||!is_coord(z)) continue;
                float vx=*(float*)(p+32),vy=*(float*)(p+36),vz=*(float*)(p+40);
                if(!is_vel(vx)||!is_vel(vy)||!is_vel(vz)) continue;
                uint8_t rep[76]; uint64_t a64=(uint64_t)(uintptr_t)p; uint32_t sz=56;
                memcpy(rep,&a64,8); memcpy(rep+8,&sz,4);
                SIZE_T cp=(sz<(uint32_t)(rsz-off))?sz:(SIZE_T)(rsz-off);
                memcpy(rep+12,p,cp);
                pipe_send(MSG_MEMSCAN,rep,(uint32_t)(12+cp));
                pipe_log("[MEMSCAN] @0x%llx hp=%.1f/%.1f xyz=(%.2f,%.2f,%.2f)",
                    (unsigned long long)a64,h,mh,x,y,z);
                if(++hits>=64) goto done;
                off+=52; /* skip past matched struct */
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER){}
        addr=next;
    }
done:
    pipe_log("[MEMSCAN] Done: %d hit(s) — rescan after ~30s if stale (JVM GC moves objects)",hits);
}
static DWORD WINAPI memscan_th(LPVOID _){(void)_;memscan_run();return 0;}

/* ── Memory watch thread ─────────────────────────────────── */
static DWORD WINAPI memwatch_th(LPVOID _)
{
    (void)_; uint8_t prev[64]={0}; int first=1;
    while(g_active&&g_watch_addr&&g_watch_ms>0){
        Sleep((DWORD)g_watch_ms);
        if(!g_watch_addr) break;
        uint8_t cur[64]={0};
        __try{ memcpy(cur,(void*)(uintptr_t)g_watch_addr,64); }
        __except(EXCEPTION_EXECUTE_HANDLER){
            pipe_log("[MEMWATCH] 0x%llx unreadable",g_watch_addr); break; }
        if(first||memcmp(cur,prev,64)!=0){
            uint8_t pay[72]; memcpy(pay,&g_watch_addr,8); memcpy(pay+8,cur,64);
            pipe_send(MSG_MEMWATCH,pay,72);
            memcpy(prev,cur,64); first=0;
        }
    }
    pipe_log("[MEMWATCH] Stopped"); return 0;
}

/* ── Rate limit thread ───────────────────────────────────── */
typedef struct{int count;int ms;}RLArgs;
static DWORD WINAPI rl_thread(LPVOID arg)
{
    RLArgs* a=(RLArgs*)arg; int count=a->count,ms=a->ms; free(a);
    EnterCriticalSection(&g_replay_cs);
    if(g_last_cs_len<=0){LeaveCriticalSection(&g_replay_cs);pipe_log("[RL] No packet.");return 0;}
    uint8_t pkt[MAX_PKT]; int len=g_last_cs_len; uint32_t ip=g_last_cs_ip; uint16_t port=g_last_cs_port;
    memcpy(pkt,g_last_cs,(size_t)len); LeaveCriticalSection(&g_replay_cs);
    SOCKET sock=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
    if(sock==INVALID_SOCKET){pipe_log("[RL] socket() failed");return 0;}
    struct sockaddr_in dst={0}; dst.sin_family=AF_INET; dst.sin_addr.s_addr=ip; dst.sin_port=port;
    int sp=(count>0&&ms>count)?ms/count:10; if(sp<1)sp=1;
    int ok=0,fail=0;
    for(int i=0;i<count&&g_active;i++){
        if(sendto(sock,(char*)pkt,len,0,(struct sockaddr*)&dst,sizeof(dst))>0) ok++; else fail++;
        Sleep((DWORD)sp);
    }
    closesocket(sock);
    uint8_t rb[8]; uint32_t cu=(uint32_t)ok,iv=(uint32_t)ms;
    memcpy(rb,&cu,4); memcpy(rb+4,&iv,4); pipe_send(0x07,rb,8);
    pipe_log("[RL] Done: %d OK, %d fail",ok,fail); return 0;
}

/* ── Replay ──────────────────────────────────────────────── */
static void do_replay(void)
{
    EnterCriticalSection(&g_replay_cs);
    if(g_last_cs_len<=0){LeaveCriticalSection(&g_replay_cs);pipe_log("[REPLAY] No packet.");return;}
    uint8_t pkt[MAX_PKT]; int len=g_last_cs_len; uint32_t ip=g_last_cs_ip; uint16_t port=g_last_cs_port;
    memcpy(pkt,g_last_cs,(size_t)len); LeaveCriticalSection(&g_replay_cs);
    SOCKET sock=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
    if(sock==INVALID_SOCKET){pipe_log("[REPLAY] socket() failed");return;}
    struct sockaddr_in dst={0}; dst.sin_family=AF_INET; dst.sin_addr.s_addr=ip; dst.sin_port=port;
    int r=sendto(sock,(char*)pkt,len,0,(struct sockaddr*)&dst,sizeof(dst));
    closesocket(sock);
    pipe_log("[REPLAY] %s %dB -> %s:%d",r>0?"OK":"FAIL",len,inet_ntoa(dst.sin_addr),ntohs(port));
}

/* ── Heartbeat ───────────────────────────────────────────── */
static DWORD WINAPI hb_thread(LPVOID _)
{
    (void)_;
    while(g_active){
        Sleep(5000); if(!g_active) break;
        pipe_log("[STATS] WSASendTo:%ld sendto:%ld WSARecvFrom:%ld recvfrom:%ld pkts:%ld shm_drop:%lu",
            g_fires_wsa_send,g_fires_send,g_fires_wsa_recv,g_fires_recv,g_pkts_captured,
            g_shm?g_shm->dropped:0UL);
    }
    return 0;
}

/* ── Command reader ──────────────────────────────────────── */
static DWORD WINAPI cmd_thread(LPVOID _)
{
    (void)_; char buf[1024]; int pos=0;
    while(g_active){
        if(g_cmdin==INVALID_HANDLE_VALUE){
            HANDLE h=CreateFileW(PIPE_CMD,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
            if(h!=INVALID_HANDLE_VALUE){g_cmdin=h;pos=0;} else{Sleep(500);continue;}
        }
        DWORD av=0;
        if(!PeekNamedPipe(g_cmdin,NULL,0,NULL,&av,NULL)){CloseHandle(g_cmdin);g_cmdin=INVALID_HANDLE_VALUE;continue;}
        if(!av){Sleep(20);continue;}
        char c; DWORD r;
        if(!ReadFile(g_cmdin,&c,1,&r,NULL)||r==0){CloseHandle(g_cmdin);g_cmdin=INVALID_HANDLE_VALUE;continue;}
        if(c=='\n'||c=='\r'){
            buf[pos]='\0'; pos=0; if(!buf[0]) continue;
            if     (!strcmp(buf,"PING"))    pipe_send(MSG_STATUS,"PONG",5);
            else if(!strcmp(buf,"STOP"))    g_active=FALSE;
            else if(!strcmp(buf,"EJECT"))   HyForceEject();
            else if(!strcmp(buf,"MEMSCAN")) CreateThread(NULL,0,memscan_th,NULL,0,NULL);
            else if(!strcmp(buf,"SEQRESET")){g_seq_cs=g_seq_sc=UINT64_MAX;pipe_log("[SEQ] reset");}
            else if(!strcmp(buf,"STATS"))
                pipe_log("[STATS] WSASendTo:%ld sendto:%ld WSARecvFrom:%ld recvfrom:%ld pkts:%ld",
                    g_fires_wsa_send,g_fires_send,g_fires_wsa_recv,g_fires_recv,g_pkts_captured);
            else if(!strcmp(buf,"REPLAY"))  do_replay();
            else if(!strcmp(buf,"PCAP_STOP")) pcap_close();
            else if(!strcmp(buf,"KEYLOG_FLUSH")){
                EnterCriticalSection(&g_keylog_cs);
                int n=(g_keylog_ring_head<32)?g_keylog_ring_head:32;
                for(int i=n-1;i>=0;i--){
                    int idx=(g_keylog_ring_head-1-i)&31;
                    if(g_keylog_ring[idx][0])
                        pipe_send(MSG_KEYLOG,g_keylog_ring[idx],(uint32_t)strlen(g_keylog_ring[idx])+1);
                }
                LeaveCriticalSection(&g_keylog_cs);
                pipe_log("[KEYLOG] Flushed %d cached lines",n);
            }
            else if(!strncmp(buf,"FUZZ ",5)){
                int bits=atoi(buf+5); InterlockedExchange((LONG*)&g_fuzz_bits,bits);
                pipe_log("[FUZZ] Armed %d bits",bits);
            }
            else if(!strncmp(buf,"PCAP_START ",11)) pcap_open(buf+11);
            else if(!strncmp(buf,"RATELIMIT ",10)){
                int cnt=0,ms=1000; sscanf(buf+10,"%d %d",&cnt,&ms);
                RLArgs* a=(RLArgs*)malloc(sizeof(RLArgs));
                if(a){a->count=cnt;a->ms=ms;CreateThread(NULL,0,rl_thread,a,0,NULL);}
            }
            else if(!strncmp(buf,"INJPID ",7)){  /* FIX 7 */
                g_injector_pid=(DWORD)atoi(buf+7);
                pipe_log("[MONITOR] Injector PID=%lu registered",(unsigned long)g_injector_pid);
            }
            else if(!strncmp(buf,"MEMWATCH ",9)){
                uint64_t waddr=0; int wms=250;
                sscanf(buf+9,"%llx %d",(unsigned long long*)&waddr,&wms);
                g_watch_addr=waddr; g_watch_ms=wms;
                if(g_watch_th){WaitForSingleObject(g_watch_th,500);CloseHandle(g_watch_th);}
                g_watch_th=CreateThread(NULL,0,memwatch_th,NULL,0,NULL);
                pipe_log("[MEMWATCH] 0x%llx every %dms",(unsigned long long)waddr,wms);
            }
            else if(!strcmp(buf,"MEMWATCH_STOP")){g_watch_addr=0;g_watch_ms=0;pipe_log("[MEMWATCH] Stopped");}
            else pipe_log("[CMD] Unknown: %s",buf);
        } else { if(pos<(int)sizeof(buf)-1) buf[pos++]=c; }
    }
    return 0;
}

/* ── IO reconnect thread ─────────────────────────────────── */
static DWORD WINAPI io_thread(LPVOID _)
{
    (void)_;
    while(g_active){
        if(g_out==INVALID_HANDLE_VALUE){
            HANDLE h=CreateFileW(PIPE_DATA,GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,
                NULL,OPEN_EXISTING,0,NULL);
            if(h!=INVALID_HANDLE_VALUE){
                DWORD mode=PIPE_READMODE_BYTE; SetNamedPipeHandleState(h,&mode,NULL,NULL);
                WaitForSingleObject(g_mutex,INFINITE); g_out=h; ReleaseMutex(g_mutex);
                char hs[320]; DWORD pid=GetCurrentProcessId();
                char exe[MAX_PATH]={0}; HANDLE hp=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);
                if(hp){DWORD sz=MAX_PATH;QueryFullProcessImageNameA(hp,0,exe,&sz);CloseHandle(hp);}
#ifdef _WIN64
                const char* arch="x64";
#else
                const char* arch="x86";
#endif
                snprintf(hs,sizeof(hs),
                    "HyForceHook/8-%s | PID=%lu | EXE=%s | Hooks:WSASendTo+sendto+WSARecvFrom+recvfrom | BoringSSL keylog",
                    arch,(unsigned long)pid,exe[0]?exe:"?");
                pipe_send(MSG_STATUS,hs,(uint32_t)strlen(hs)+1);
                pipe_log("[HOOK] 4 WinSock hooks + BoringSSL keylog active (port %d-%d) | SHM=%s",
                    HYTALE_PORT_MIN,HYTALE_PORT_MAX,g_shm?"ready":"unavailable");
            }
        }
        Sleep(500);
    }
    return 0;
}

/* ── Injector monitor (FIX 7) ────────────────────────────── */
static DWORD WINAPI injector_monitor_th(LPVOID _)
{
    (void)_;
    /* Wait up to 10s for INJPID command */
    for(int i=0;i<20&&g_injector_pid==0&&g_active;i++) Sleep(500);
    if(g_injector_pid==0) return 0;
    HANDLE hInj=OpenProcess(SYNCHRONIZE,FALSE,g_injector_pid);
    if(!hInj){pipe_log("[MONITOR] Cannot open injector PID=%lu",g_injector_pid);return 0;}
    while(g_active){
        if(WaitForSingleObject(hInj,1000)==WAIT_OBJECT_0){
            pipe_log("[MONITOR] Injector exited — auto-ejecting");
            CloseHandle(hInj); HyForceEject();
            FreeLibraryAndExitThread(GetModuleHandleW(L"HyForceHook.dll"),0);
            return 0;
        }
    }
    CloseHandle(hInj); return 0;
}

/* ── DllMain ─────────────────────────────────────────────── */
BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if(reason==DLL_PROCESS_ATTACH){
        DisableThreadLibraryCalls(hInst);
        InitializeCriticalSection(&g_cs);
        InitializeCriticalSection(&g_replay_cs);
        InitializeCriticalSection(&g_keylog_cs);
        g_mutex=CreateMutexW(NULL,FALSE,NULL);
        g_pcap_mutex=CreateMutexW(NULL,FALSE,NULL);
        if(!g_mutex||!g_pcap_mutex) return FALSE;

        /* FIX 3: allocate per-thread reentrancy slot */
        g_tls_idx=TlsAlloc();

        /* Shared memory (non-fatal) */
        init_shm();

        HMODULE ws2=GetModuleHandleW(L"ws2_32.dll");
        if(!ws2) ws2=LoadLibraryW(L"ws2_32.dll");
        if(!ws2) return FALSE;

        orig_WSASendTo =(WSASendTo_t) GetProcAddress(ws2,"WSASendTo");
        orig_WSARecvFrom=(WSARecvFrom_t)GetProcAddress(ws2,"WSARecvFrom");
        orig_sendto    =(sendto_t)    GetProcAddress(ws2,"sendto");
        orig_recvfrom  =(recvfrom_t)  GetProcAddress(ws2,"recvfrom");

        if(orig_WSASendTo) {memcpy(sv_wsa_send,orig_WSASendTo, 14);jmp_write(orig_WSASendTo, hook_WSASendTo);}
        if(orig_WSARecvFrom){memcpy(sv_wsa_recv,orig_WSARecvFrom,14);jmp_write(orig_WSARecvFrom,hook_WSARecvFrom);}
        if(orig_sendto)    {memcpy(sv_send,    orig_sendto,    14);jmp_write(orig_sendto,    hook_sendto);}
        if(orig_recvfrom)  {memcpy(sv_recv,    orig_recvfrom,  14);jmp_write(orig_recvfrom,  hook_recvfrom);}

        hook_boringssl();

        g_active=TRUE;
        g_io_th =CreateThread(NULL,0,io_thread,          NULL,0,NULL);
        g_cmd_th=CreateThread(NULL,0,cmd_thread,          NULL,0,NULL);
                 CreateThread(NULL,0,hb_thread,            NULL,0,NULL);
                 CreateThread(NULL,0,injector_monitor_th,  NULL,0,NULL);

    } else if(reason==DLL_PROCESS_DETACH){
        g_active=FALSE;

        /* FIX 4 */
        if(g_tls_idx!=TLS_OUT_OF_INDEXES){TlsFree(g_tls_idx);g_tls_idx=TLS_OUT_OF_INDEXES;}

        if(orig_WSASendTo)   jmp_restore(orig_WSASendTo,  sv_wsa_send);
        if(orig_WSARecvFrom) jmp_restore(orig_WSARecvFrom,sv_wsa_recv);
        if(orig_sendto)      jmp_restore(orig_sendto,     sv_send);
        if(orig_recvfrom)    jmp_restore(orig_recvfrom,   sv_recv);

        unhook_boringssl(); cleanup_shm(); pcap_close();
        if(g_out!=INVALID_HANDLE_VALUE){CloseHandle(g_out);g_out=INVALID_HANDLE_VALUE;}
        if(g_cmdin!=INVALID_HANDLE_VALUE){CloseHandle(g_cmdin);g_cmdin=INVALID_HANDLE_VALUE;}
        if(g_mutex) CloseHandle(g_mutex);
        if(g_pcap_mutex) CloseHandle(g_pcap_mutex);
        if(g_io_th) {WaitForSingleObject(g_io_th, 500);CloseHandle(g_io_th);}
        if(g_cmd_th){WaitForSingleObject(g_cmd_th,500);CloseHandle(g_cmd_th);}
        if(g_watch_th){WaitForSingleObject(g_watch_th,500);CloseHandle(g_watch_th);}
        DeleteCriticalSection(&g_cs);
        DeleteCriticalSection(&g_replay_cs);
        DeleteCriticalSection(&g_keylog_cs);
    }
    return TRUE;
}
