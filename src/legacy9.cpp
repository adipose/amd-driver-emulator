// legacy9: hosts a legacy D3D9 user-mode driver (the 2015 AMD atiumd64.dll) under a fake runtime, with the
// kernel side faked rather than forwarded, to answer questions the MPC-HC #4257 investigation left open:
//
//   1. Which heap does the driver allocate from, and does it put blocks in the 152-byte size class that the
//      damaged menu vectors live in?  (heap census, from hooks on the driver's own KERNEL32 imports)
//   2. Does anything the driver does write outside its own blocks?  (--redzone: every driver allocation on the
//      process heap is wrapped in wide guard zones that are checked at every checkpoint and on free)
//   3. Does anything land on blocks shaped like the victims?  (decoys: 152-byte blocks filled with a pointer
//      pattern, interleaved in the same process heap, compared at every checkpoint)
//
// Nothing here talks to the real kernel driver unless --qai-forward or --kmt-forward is given.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winternl.h>
#include <d3d10umddi.h> // pulls in d3dumddi.h and the D3DKMT thunk declarations

#include <intrin.h>
#include <share.h>    // _SH_DENYWR, so the log can be read while the host process is still running
#include <shellapi.h> // CommandLineToArgvW, for the DLL build's options

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <map>
#include <utility>
#include <vector>

// ---------------------------------------------------------------- logging

static FILE* g_logFile = nullptr;

static void Log(const char* fmt, ...)
{
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    printf("%s\n", buf);
    if (g_logFile) { fprintf(g_logFile, "%s\n", buf); fflush(g_logFile); }
}

static void HexDump(const char* label, const void* p, size_t n, size_t maxBytes = 96)
{
    const unsigned char* b = (const unsigned char*)p;
    size_t shown = n < maxBytes ? n : maxBytes;
    for (size_t i = 0; i < shown; i += 16) {
        char line[128];
        int o = snprintf(line, sizeof line, "    %s+%03zx:", label, i);
        for (size_t j = i; j < i + 16 && j < shown; j++) o += snprintf(line + o, sizeof line - o, " %02x", b[j]);
        Log("%s", line);
    }
    if (shown < n) Log("    ... (%zu bytes total)", n);
}

// Formats an address as module+offset.
static const char* Where(void* addr, char* out, size_t cap)
{
    HMODULE mod = nullptr;
    char path[MAX_PATH] = "?";
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCSTR)addr, &mod) && mod) {
        GetModuleFileNameA(mod, path, sizeof path);
        const char* base = strrchr(path, '\\');
        snprintf(out, cap, "%s+0x%zx", base ? base + 1 : path, (size_t)((char*)addr - (char*)mod));
    } else {
        snprintf(out, cap, "%p", addr);
    }
    return out;
}

static void LogStack(const char* what, int skip = 1, int frames = 6)
{
    void* st[16];
    USHORT n = RtlCaptureStackBackTrace(skip + 1, (ULONG)frames, st, nullptr);
    char line[1024];
    int o = snprintf(line, sizeof line, "    %s from:", what);
    for (USHORT i = 0; i < n; i++) {
        char w[300];
        o += snprintf(line + o, sizeof line - o, " %s", Where(st[i], w, sizeof w));
    }
    Log("%s", line);
}

static void Checkpoint(const char* name);
static void PrintSizeHistogram();

static LONG WINAPI CrashFilter(EXCEPTION_POINTERS* ep)
{
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    if (code < 0xC0000000 || code == 0xE06D7363) return EXCEPTION_CONTINUE_SEARCH;
    char w[300];
    Log("!! exception %08lx at %s", code, Where(ep->ExceptionRecord->ExceptionAddress, w, sizeof w));
    if (code == EXCEPTION_ACCESS_VIOLATION && ep->ExceptionRecord->NumberParameters >= 2)
        Log("!!   %s address %p", ep->ExceptionRecord->ExceptionInformation[0] ? "writing" : "reading",
            (void*)ep->ExceptionRecord->ExceptionInformation[1]);
    void* st[12];
    USHORT n = RtlCaptureStackBackTrace(0, 12, st, nullptr);
    for (USHORT i = 0; i < n; i++) Log("!!   frame %s", Where(st[i], w, sizeof w));
    static LONG once = 0;
    if (!InterlockedExchange(&once, 1)) { Checkpoint("at crash"); PrintSizeHistogram(); }
    return EXCEPTION_CONTINUE_SEARCH;
}

// ---------------------------------------------------------------- heap census, redzones

static HANDLE g_procHeap;
static CRITICAL_SECTION g_cs;
static bool g_redzone = false;
static bool g_traceAllocs = false; // --trace-allocs: log every driver allocation with its caller
static const SIZE_T RZ = 0x140; // wide enough to cover a write 0x114 past the end or 0x4c before the start
static const unsigned char RZ_FILL = 0xA5;

struct Live { HANDLE heap; SIZE_T size; bool zoned; void* caller; };
static std::map<void*, Live> g_live;

// Every process-heap block the driver has ever taken in the victim size class, kept after the free: adjacency to
// a menu vector is about where the bucket put the block, which a later free does not undo.
static std::vector<std::pair<void*, void*>> g_classHistory;

struct Census {
    size_t allocs = 0, frees = 0, bytes = 0;
    std::map<SIZE_T, size_t> bySize;     // every allocation ever made, by request size
};
static Census g_proc, g_priv;
static size_t g_virtualAllocs = 0;
static size_t g_zoneHits = 0;
static size_t g_zoneChecks = 0; // the denominator of the guard-zone result: how many checks were actually made

// Requests of 145..160 bytes share the bucket a 152-byte block falls in.
static bool InVictimClass(SIZE_T n) { return n >= 145 && n <= 160; }

// The distance between consecutive blocks of that bucket. Starts at the value the dump-side tooling assumes and
// is replaced by the measured one as soon as decoys are planted.
static SIZE_T g_stride = 0xB0;

static bool CheckZone(void* user, const Live& l, const char* when)
{
    const unsigned char* base = (const unsigned char*)user - RZ;
    const unsigned char* tail = (const unsigned char*)user + l.size;
    bool ok = true;
    for (SIZE_T i = 0; i < RZ; i++) {
        if (base[i] != RZ_FILL) {
            char w[300];
            Log("!! REDZONE HIT (%s): block %p size %zu (allocated by %s), byte at %+lld before start", when, user,
                l.size, Where(l.caller, w, sizeof w), (long long)i - (long long)RZ);
            HexDump("pre", base, RZ, RZ);
            ok = false;
            break;
        }
    }
    for (SIZE_T i = 0; i < RZ; i++) {
        if (tail[i] != RZ_FILL) {
            char w[300];
            Log("!! REDZONE HIT (%s): block %p size %zu (allocated by %s), byte at end+%zu", when, user, l.size,
                Where(l.caller, w, sizeof w), i);
            HexDump("post", tail, RZ, RZ);
            ok = false;
            break;
        }
    }
    g_zoneChecks++;
    if (!ok) g_zoneHits++;
    return ok;
}

static LPVOID WINAPI Hook_HeapAlloc(HANDLE heap, DWORD flags, SIZE_T size)
{
    bool zoned = g_redzone && heap == g_procHeap;
    void* p;
    if (zoned) {
        unsigned char* raw = (unsigned char*)HeapAlloc(heap, flags, size + 2 * RZ);
        if (!raw) return nullptr;
        memset(raw, RZ_FILL, RZ);
        memset(raw + RZ + size, RZ_FILL, RZ);
        p = raw + RZ;
    } else {
        p = HeapAlloc(heap, flags, size);
        if (!p) return nullptr;
    }
    EnterCriticalSection(&g_cs);
    Census& c = heap == g_procHeap ? g_proc : g_priv;
    c.allocs++;
    c.bytes += size;
    c.bySize[size]++;
    g_live[p] = Live{ heap, size, zoned, _ReturnAddress() };
    if (heap == g_procHeap && InVictimClass(size)) g_classHistory.push_back({ p, _ReturnAddress() });
    LeaveCriticalSection(&g_cs);
    if (heap == g_procHeap && InVictimClass(size)) {
        Log("  ** 152-byte-class block allocated on the process heap: %zu bytes = %p", size, p);
        LogStack("allocated", 0, 10);
    }
    if (g_traceAllocs) {
        char w[300];
        Log("  alloc %-7s %6zu bytes = %p  by %s", heap == g_procHeap ? "process" : "private", size, p,
            Where(_ReturnAddress(), w, sizeof w));
    }
    return p;
}

static BOOL WINAPI Hook_HeapFree(HANDLE heap, DWORD flags, LPVOID p)
{
    if (!p) return TRUE;
    Live l{};
    bool known = false;
    EnterCriticalSection(&g_cs);
    auto it = g_live.find(p);
    if (it != g_live.end()) {
        l = it->second;
        known = true;
        g_live.erase(it);
        (heap == g_procHeap ? g_proc : g_priv).frees++;
    }
    LeaveCriticalSection(&g_cs);
    if (known && l.heap == g_procHeap && InVictimClass(l.size)) {
        Log("  ** 152-byte-class block freed: %p (%zu bytes); contents at free:", p, l.size);
        HexDump("blk", p, l.size, l.size);
        LogStack("freed", 0, 10);
    }
    if (known && l.zoned) {
        CheckZone(p, l, "on free");
        return HeapFree(heap, flags, (unsigned char*)p - RZ);
    }
    return HeapFree(heap, flags, p);
}

static SIZE_T WINAPI Hook_HeapSize(HANDLE heap, DWORD flags, LPCVOID p)
{
    EnterCriticalSection(&g_cs);
    auto it = g_live.find((void*)p);
    bool zoned = it != g_live.end() && it->second.zoned;
    SIZE_T size = zoned ? it->second.size : 0;
    LeaveCriticalSection(&g_cs);
    return zoned ? size : HeapSize(heap, flags, p);
}

static LPVOID WINAPI Hook_HeapReAlloc(HANDLE heap, DWORD flags, LPVOID p, SIZE_T size)
{
    EnterCriticalSection(&g_cs);
    auto it = g_live.find(p);
    bool known = it != g_live.end();
    Live l = known ? it->second : Live{};
    LeaveCriticalSection(&g_cs);
    if (known && l.zoned) {
        if (flags & HEAP_REALLOC_IN_PLACE_ONLY) return nullptr;
        void* q = Hook_HeapAlloc(heap, flags, size);
        if (!q) return nullptr;
        memcpy(q, p, l.size < size ? l.size : size);
        Hook_HeapFree(heap, 0, p);
        return q;
    }
    void* q = HeapReAlloc(heap, flags, p, size);
    if (q) {
        EnterCriticalSection(&g_cs);
        if (known) g_live.erase(p);
        Census& c = heap == g_procHeap ? g_proc : g_priv;
        c.allocs++;
        c.bytes += size;
        c.bySize[size]++;
        g_live[q] = Live{ heap, size, false, _ReturnAddress() };
        LeaveCriticalSection(&g_cs);
    }
    return q;
}

static HANDLE WINAPI Hook_HeapCreate(DWORD opts, SIZE_T initial, SIZE_T maximum)
{
    HANDLE h = HeapCreate(opts, initial, maximum);
    Log("  heap: HeapCreate(opts=%lx, initial=%zu, max=%zu) = %p", opts, initial, maximum, h);
    LogStack("HeapCreate");
    return h;
}

static BOOL WINAPI Hook_HeapDestroy(HANDLE heap)
{
    size_t dropped = 0;
    EnterCriticalSection(&g_cs);
    for (auto it = g_live.begin(); it != g_live.end();) {
        if (it->second.heap == heap) { it = g_live.erase(it); dropped++; } else ++it;
    }
    LeaveCriticalSection(&g_cs);
    Log("  heap: HeapDestroy(%p), %zu blocks still live in it", heap, dropped);
    return HeapDestroy(heap);
}

static LPVOID WINAPI Hook_VirtualAlloc(LPVOID addr, SIZE_T size, DWORD type, DWORD prot)
{
    void* p = VirtualAlloc(addr, size, type, prot);
    InterlockedIncrement64((LONG64*)&g_virtualAllocs);
    Log("  heap: VirtualAlloc(%p, %zu, %lx, %lx) = %p", addr, size, type, prot, p);
    return p;
}

// ---------------------------------------------------------------- decoys

struct Decoy { ULONG_PTR* block; ULONG_PTR expect[19]; };
static std::vector<Decoy> g_decoys;
static size_t g_decoyHits = 0;

// Fills the 152-byte bucket of the process heap with victim-shaped blocks, then frees every other one so the
// driver's own allocations of that size class land between the survivors.
static void PlantDecoys(size_t n)
{
    std::vector<ULONG_PTR*> all;
    for (size_t i = 0; i < 2 * n; i++) all.push_back((ULONG_PTR*)HeapAlloc(g_procHeap, 0, 152));
    for (size_t i = 0; i < all.size(); i++) {
        if (i & 1) { HeapFree(g_procHeap, 0, all[i]); continue; }
        Decoy d;
        d.block = all[i];
        for (int s = 0; s < 19; s++) d.expect[s] = (ULONG_PTR)all[i] + 0x1000 + (ULONG_PTR)s * 0x50; // heap-pointer-like
        memcpy(d.block, d.expect, sizeof d.expect);
        g_decoys.push_back(d);
    }
    Log("decoys: %zu live 152-byte blocks, %zu holes left between them", g_decoys.size(), n);

    // The stride between same-size blocks, measured rather than assumed. The dump-side tooling assumes 0xB0
    // (152 + a 16-byte header, rounded to 16); what the heap actually does decides which addresses count as
    // neighbours of a damaged block.
    std::vector<ULONG_PTR> addrs;
    for (auto* p : all) addrs.push_back((ULONG_PTR)p);
    std::sort(addrs.begin(), addrs.end());
    std::map<ULONG_PTR, size_t> gaps;
    for (size_t i = 1; i < addrs.size(); i++) {
        ULONG_PTR d = addrs[i] - addrs[i - 1];
        if (d <= 0x400) gaps[d]++;
    }
    Log("measured spacing between consecutive 152-byte blocks (gaps up to 0x400):");
    for (auto& g : gaps) Log("    %6zu x 0x%llx (%llu bytes)", g.second, (unsigned long long)g.first,
                             (unsigned long long)g.first);
    ULONG_PTR best = 0;
    size_t bestN = 0;
    for (auto& g : gaps) if (g.second > bestN) { bestN = g.second; best = g.first; }
    if (best) {
        g_stride = (SIZE_T)best;
        Log("stride in use: 0x%llx (%llu bytes), seen %zu times%s", (unsigned long long)best,
            (unsigned long long)best, bestN, best == 0xB0 ? "" : "   <-- not the assumed 0xB0");
    }
}

// ------------------------------------------------- the #4257 signature, looked for live in the running heaps

static bool LooksLikeUserPtr(ULONG_PTR v) { return v >= 0x10000 && v <= 0x00007FFFFFFFFFFFull && !(v & 7); }

// The shape of a capacity-19 vector<T*> buffer: most slots are user-mode heap pointers sharing their high bits.
static bool VectorShape(const ULONG_PTR* q, size_t slots)
{
    ULONG_PTR high = 0;
    for (size_t i = 0; i < slots; i++)
        if (LooksLikeUserPtr(q[i])) { high = q[i] >> 24; break; }
    size_t ptrs = 0, shared = 0;
    for (size_t i = 0; i < slots; i++) {
        if (!LooksLikeUserPtr(q[i])) continue;
        ptrs++;
        if ((q[i] >> 24) == high) shared++;
    }
    return ptrs >= 12 && shared >= 10;
}

// The exact #4257 damage: bytes 0x64..0x6B zero, 0x60..0x63 and 0x6C..0x6F intact.
static bool DamageShape(const ULONG_PTR* q, size_t slots)
{
    if (slots < 14) return false;
    UINT32 lo12 = (UINT32)(q[12] & 0xFFFFFFFFu), hi12 = (UINT32)(q[12] >> 32);
    UINT32 lo13 = (UINT32)(q[13] & 0xFFFFFFFFu), hi13 = (UINT32)(q[13] >> 32);
    return hi12 == 0 && lo12 != 0 && lo13 == 0 && hi13 != 0;
}


static size_t g_signatureHits = 0;
static size_t g_victimsSeen = 0;
static size_t g_lastNearby = 0; // driver blocks within 4 strides of a vector-shaped block, at the last checkpoint

// Nothing in the walk allocates or logs: allocating from a heap being walked invalidates the walk.
static unsigned char g_sigCopy[32][192];
static void* g_sigAddr[32];
static DWORD g_sigSize[32];
static void* g_vicAddr[8192];

static void ScanHeapsForSignature(const char* when)
{
    HANDLE heaps[64];
    DWORD nheaps = GetProcessHeaps(64, heaps);
    if (nheaps > 64) nheaps = 64;
    size_t inClass = 0, victims = 0, sigs = 0;

    for (DWORD i = 0; i < nheaps; i++) {
        PROCESS_HEAP_ENTRY e = {};
        if (!HeapLock(heaps[i])) continue;
        while (HeapWalk(heaps[i], &e)) {
            if (!(e.wFlags & PROCESS_HEAP_ENTRY_BUSY)) continue;
            if (e.cbData < 144 || e.cbData > 176) continue;
            inClass++;
            const ULONG_PTR* q = (const ULONG_PTR*)e.lpData;
            size_t slots = e.cbData / 8;
            if (slots > 19) slots = 19;
            if (!VectorShape(q, slots)) continue;
            if (victims < 8192) g_vicAddr[victims] = e.lpData;
            victims++;
            if (!DamageShape(q, slots)) continue;
            if (sigs < 32) {
                memcpy(g_sigCopy[sigs], e.lpData, e.cbData);
                g_sigAddr[sigs] = e.lpData;
                g_sigSize[sigs] = e.cbData;
            }
            sigs++;
        }
        HeapUnlock(heaps[i]);
    }

    for (size_t i = 0; i < sigs && i < 32; i++) {
        Log("!! #4257 SIGNATURE at checkpoint '%s': block %p, %lu bytes, bytes 0x64..0x6B zero", when, g_sigAddr[i],
            g_sigSize[i]);
        HexDump("sig", g_sigCopy[i], g_sigSize[i], g_sigSize[i]);
    }
    g_signatureHits += sigs;
    g_victimsSeen = victims;

    // Adjacency: is any vector-shaped block within a few LFH strides of a block the driver took in this class?
    // The driver's blocks are taken from the history, not from the live set: most are freed again inside
    // OpenAdapter, and where the bucket put them is what matters.
    static std::map<void*, bool> reported; // each driver block is reported once, at its nearest neighbour
    size_t nearby = 0;
    size_t capped = victims < 8192 ? victims : 8192;
    EnterCriticalSection(&g_cs);
    std::vector<std::pair<void*, void*>> history = g_classHistory;
    LeaveCriticalSection(&g_cs);
    for (auto& b : history) {
        long long nearest = 0;
        void* at = nullptr;
        for (size_t v = 0; v < capped; v++) {
            if (g_vicAddr[v] == b.first) continue;
            long long d = (long long)((char*)g_vicAddr[v] - (char*)b.first);
            if (!at || (d < 0 ? -d : d) < (nearest < 0 ? -nearest : nearest)) { nearest = d; at = g_vicAddr[v]; }
        }
        if (!at || nearest <= -5 * (long long)g_stride || nearest >= 5 * (long long)g_stride) continue;
        nearby++;
        if (reported.count(b.first)) continue;
        reported[b.first] = true;
        char w[300];
        Log("    adjacency: driver block %p (from %s) is %+lld bytes (%+.2f strides) from vector-shaped block %p;"
            " a write %+lld from that block's start would land on the damaged bytes",
            b.first, Where(b.second, w, sizeof w), nearest, (double)nearest / (double)g_stride, at,
            0x64 - nearest);
    }

    g_lastNearby = nearby;
    Log("    heaps=%lu  blocks in the 152-byte class=%zu  vector-shaped=%zu  damaged=%zu  driver blocks ever in"
        " this class=%zu  of those within 4 strides of a vector-shaped block=%zu",
        nheaps, inClass, victims, sigs, history.size(), nearby);
}

static void Checkpoint(const char* name)
{
    // The heap is scanned first, before the decoys below are re-armed: re-arming repairs the very damage the
    // scan is looking for.
    Log("checkpoint %s", name);
    ScanHeapsForSignature(name);

    size_t bad = 0;
    for (auto& d : g_decoys) {
        if (!memcmp(d.block, d.expect, sizeof d.expect)) continue;
        bad++;
        const unsigned char* a = (const unsigned char*)d.block;
        const unsigned char* b = (const unsigned char*)d.expect;
        size_t first = 0, last = 0;
        bool seen = false;
        for (size_t i = 0; i < sizeof d.expect; i++)
            if (a[i] != b[i]) { if (!seen) first = i; last = i; seen = true; }
        Log("!! DECOY HIT at checkpoint '%s': block %p changed in bytes 0x%zx..0x%zx", name, d.block, first, last);
        HexDump("decoy", d.block, sizeof d.expect, sizeof d.expect);
        memcpy(d.block, d.expect, sizeof d.expect); // re-arm
    }
    g_decoyHits += bad;

    size_t zoned = 0, zoneBad = 0, liveProc = 0, livePriv = 0, liveClass = 0;
    EnterCriticalSection(&g_cs);
    for (auto& kv : g_live) {
        if (kv.second.heap == g_procHeap) { liveProc++; if (InVictimClass(kv.second.size)) liveClass++; } else livePriv++;
        if (kv.second.zoned) { zoned++; if (!CheckZone(kv.first, kv.second, name)) zoneBad++; }
    }
    size_t everClass = 0;
    for (auto& kv : g_proc.bySize) if (InVictimClass(kv.first)) everClass += kv.second;
    LeaveCriticalSection(&g_cs);

    Log("    decoys changed=%zu  redzones checked=%zu bad=%zu", bad, zoned, zoneBad);
    Log("    process heap: %zu allocs (%zu bytes), %zu live; in the 152-byte class: %zu ever, %zu live", g_proc.allocs,
        g_proc.bytes, liveProc, everClass, liveClass);
    Log("    private heaps: %zu allocs (%zu bytes), %zu live; VirtualAlloc calls: %zu", g_priv.allocs, g_priv.bytes,
        livePriv, g_virtualAllocs);
}

static void PrintSizeHistogram()
{
    EnterCriticalSection(&g_cs);
    std::vector<std::pair<size_t, SIZE_T>> top;
    for (auto& kv : g_proc.bySize) top.push_back({ kv.second, kv.first });
    LeaveCriticalSection(&g_cs);
    std::sort(top.begin(), top.end(), [](auto& a, auto& b) { return a.first > b.first; });
    Log("process-heap request sizes made by the driver (top 20 by count):");
    for (size_t i = 0; i < top.size() && i < 20; i++)
        Log("    %6zu x %zu bytes%s", top[i].first, top[i].second, InVictimClass(top[i].second) ? "   <-- 152-byte class" : "");
    Log("requests in the 152-byte class (145..160):");
    bool any = false;
    for (auto& t : top) if (InVictimClass(t.second)) { Log("    %6zu x %zu bytes", t.first, t.second); any = true; }
    if (!any) Log("    none");
}

// ---------------------------------------------------------------- loader and D3DKMT hooks

static wchar_t g_driverDir[MAX_PATH];
static bool g_kmtForward = false;
static void HookImports(HMODULE mod);

struct ThunkSlot { char name[64]; NTSTATUS(APIENTRY* real)(void*); };
static ThunkSlot g_thunks[48];
static int g_thunkCount = 0;

template <int N>
static NTSTATUS APIENTRY ThunkWrapper(void* arg)
{
    NTSTATUS s = g_kmtForward ? g_thunks[N].real(arg) : (NTSTATUS)0xC00000BB; // STATUS_NOT_SUPPORTED
    Log("  km %s(%p) = %08lx%s", g_thunks[N].name, arg, s, g_kmtForward ? "" : " [refused, not forwarded]");
    LogStack(g_thunks[N].name);
    return s;
}

template <size_t... I>
static void* ThunkWrapperAt(int n, std::index_sequence<I...>)
{
    static void* const table[] = { (void*)&ThunkWrapper<(int)I>... };
    return table[n];
}

static FARPROC WINAPI Hook_GetProcAddress(HMODULE mod, LPCSTR name)
{
    FARPROC real = GetProcAddress(mod, name);
    if ((UINT_PTR)name < 0x10000) return real;
    char w[300];
    Log("  GetProcAddress(%s, \"%s\") = %p", Where((void*)mod, w, sizeof w), name, (void*)real);
    if (real && !strncmp(name, "D3DKMT", 6)) {
        for (int i = 0; i < g_thunkCount; i++)
            if (!strcmp(g_thunks[i].name, name)) return (FARPROC)ThunkWrapperAt(i, std::make_index_sequence<48>{});
        if (g_thunkCount < 48) {
            int i = g_thunkCount++;
            strncpy_s(g_thunks[i].name, name, _TRUNCATE);
            g_thunks[i].real = (NTSTATUS(APIENTRY*)(void*))real;
            return (FARPROC)ThunkWrapperAt(i, std::make_index_sequence<48>{});
        }
    }
    return real;
}

// A sibling DLL the driver asks for by bare name is taken from the driver's own folder when it exists there.
static HMODULE LoadSibling(const wchar_t* name, DWORD flags)
{
    const wchar_t* base = wcsrchr(name, L'\\');
    base = base ? base + 1 : name;
    wchar_t local[MAX_PATH];
    swprintf_s(local, L"%s\\%s", g_driverDir, base);
    HMODULE h = nullptr;
    bool sibling = GetFileAttributesW(local) != INVALID_FILE_ATTRIBUTES;
    if (sibling) h = LoadLibraryExW(local, nullptr, 0);
    if (!h) h = LoadLibraryExW(name, nullptr, flags);
    Log("  LoadLibrary(\"%ls\") = %p%s", name, (void*)h, sibling && h ? " [from the driver folder]" : "");
    if (h && sibling) HookImports(h);
    return h;
}

static HMODULE WINAPI Hook_LoadLibraryW(LPCWSTR name) { return LoadSibling(name, 0); }
static HMODULE WINAPI Hook_LoadLibraryExW(LPCWSTR name, HANDLE, DWORD flags) { return LoadSibling(name, flags); }
static HMODULE WINAPI Hook_LoadLibraryA(LPCSTR name)
{
    wchar_t w[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, name, -1, w, MAX_PATH);
    return LoadSibling(w, 0);
}
static HMODULE WINAPI Hook_LoadLibraryExA(LPCSTR name, HANDLE, DWORD flags)
{
    wchar_t w[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, name, -1, w, MAX_PATH);
    return LoadSibling(w, flags);
}

static void WINAPI Hook_OutputDebugStringA(LPCSTR s) { Log("  driver says: %s", s ? s : "(null)"); }

struct ImportHook { const char* name; void* hook; };
static const ImportHook g_importHooks[] = {
    { "HeapAlloc", (void*)Hook_HeapAlloc },       { "HeapFree", (void*)Hook_HeapFree },
    { "HeapReAlloc", (void*)Hook_HeapReAlloc },   { "HeapSize", (void*)Hook_HeapSize },
    { "HeapCreate", (void*)Hook_HeapCreate },     { "HeapDestroy", (void*)Hook_HeapDestroy },
    { "VirtualAlloc", (void*)Hook_VirtualAlloc }, { "GetProcAddress", (void*)Hook_GetProcAddress },
    { "LoadLibraryA", (void*)Hook_LoadLibraryA }, { "LoadLibraryW", (void*)Hook_LoadLibraryW },
    { "LoadLibraryExA", (void*)Hook_LoadLibraryExA }, { "LoadLibraryExW", (void*)Hook_LoadLibraryExW },
    { "OutputDebugStringA", (void*)Hook_OutputDebugStringA },
};

static void HookImports(HMODULE mod)
{
    BYTE* base = (BYTE*)mod;
    auto* nt = (IMAGE_NT_HEADERS*)(base + ((IMAGE_DOS_HEADER*)base)->e_lfanew);
    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress) return;
    int patched = 0;
    for (auto* imp = (IMAGE_IMPORT_DESCRIPTOR*)(base + dir.VirtualAddress); imp->Name; imp++) {
        if (_stricmp((const char*)(base + imp->Name), "KERNEL32.dll")) continue;
        auto* names = (IMAGE_THUNK_DATA*)(base + (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
        auto* slots = (IMAGE_THUNK_DATA*)(base + imp->FirstThunk);
        for (; names->u1.AddressOfData; names++, slots++) {
            if (IMAGE_SNAP_BY_ORDINAL(names->u1.Ordinal)) continue;
            const char* fn = ((IMAGE_IMPORT_BY_NAME*)(base + names->u1.AddressOfData))->Name;
            for (auto& h : g_importHooks) {
                if (strcmp(fn, h.name)) continue;
                DWORD old;
                VirtualProtect(&slots->u1.Function, sizeof(void*), PAGE_READWRITE, &old);
                slots->u1.Function = (ULONG_PTR)h.hook;
                VirtualProtect(&slots->u1.Function, sizeof(void*), old, &old);
                patched++;
            }
        }
    }
    char w[300];
    Log("  hooked %d KERNEL32 imports of %s", patched, Where(mod, w, sizeof w));
}

// ---------------------------------------------------------------- the fake runtime (adapter level)

static bool g_qaiForward = false;
static D3DKMT_HANDLE g_realAdapter = 0;
static UINT g_qaiFill = 0;
static std::vector<std::pair<UINT, UINT>> g_qaiSet; // --qai-set off=value,...: dwords invented into the fake record

static D3DKMT_HANDLE FindRealAmdAdapter()
{
    D3DKMT_ADAPTERINFO infos[16] = {};
    D3DKMT_ENUMADAPTERS2 e = {};
    e.NumAdapters = 16;
    e.pAdapters = infos;
    if (D3DKMTEnumAdapters2(&e) < 0) return 0;
    for (ULONG i = 0; i < e.NumAdapters; i++) {
        D3DKMT_UMDFILENAMEINFO fn = {};
        fn.Version = KMTUMDVERSION_DX9;
        D3DKMT_QUERYADAPTERINFO q = {};
        q.hAdapter = infos[i].hAdapter;
        q.Type = KMTQAITYPE_UMDRIVERNAME;
        q.pPrivateDriverData = &fn;
        q.PrivateDriverDataSize = sizeof fn;
        if (D3DKMTQueryAdapterInfo(&q) < 0) continue;
        Log("real adapter %lu: DX9 UMD %ls", i, fn.UmdFileName);
        if (wcsstr(fn.UmdFileName, L"ati") || wcsstr(fn.UmdFileName, L"amd")) return infos[i].hAdapter;
    }
    return 0;
}

static HRESULT APIENTRY CALLBACK QueryAdapterInfoCb(HANDLE hAdapter, CONST D3DDDICB_QUERYADAPTERINFO* p)
{
    Log("cb QueryAdapterInfoCb(h=%p, size=%u)", hAdapter, p->PrivateDriverDataSize);
    LogStack("QueryAdapterInfoCb");
    if (g_qaiForward && g_realAdapter) {
        D3DKMT_QUERYADAPTERINFO q = {};
        q.hAdapter = g_realAdapter;
        q.Type = KMTQAITYPE_UMDRIVERPRIVATE;
        q.pPrivateDriverData = p->pPrivateDriverData;
        q.PrivateDriverDataSize = p->PrivateDriverDataSize;
        NTSTATUS s = D3DKMTQueryAdapterInfo(&q);
        Log("    forwarded to the real kernel driver: %08lx", s);
        if (s >= 0) HexDump("qai", p->pPrivateDriverData, p->PrivateDriverDataSize);
        return s >= 0 ? S_OK : E_FAIL;
    }
    memset(p->pPrivateDriverData, (int)g_qaiFill, p->PrivateDriverDataSize);
    for (auto& s : g_qaiSet)
        if (s.first + 4 <= p->PrivateDriverDataSize) memcpy((char*)p->pPrivateDriverData + s.first, &s.second, 4);
    Log("    answered with %u bytes of 0x%02x and %zu invented fields", p->PrivateDriverDataSize, g_qaiFill,
        g_qaiSet.size());
    return S_OK;
}

static HRESULT APIENTRY CALLBACK GetMultisampleMethodListCb(HANDLE hAdapter, D3DDDICB_GETMULTISAMPLEMETHODLIST* p)
{
    Log("cb GetMultisampleMethodListCb(h=%p, %ux%u fmt=%u)", hAdapter, p->Width, p->Height, (UINT)p->Format);
    p->MethodCount = 0;
    return S_OK;
}

typedef HRESULT(APIENTRY* PFN_OPENADAPTER)(D3DDDIARG_OPENADAPTER*);

static void TryCaps(const D3DDDI_ADAPTERFUNCS& f, HANDLE hDrv, const char* name, D3DDDICAPS_TYPE type, UINT size)
{
    std::vector<unsigned char> buf(size, 0);
    D3DDDIARG_GETCAPS a = {};
    a.Type = type;
    a.pData = buf.data();
    a.DataSize = size;
    HRESULT hr = f.pfnGetCaps(hDrv, &a);
    Log("GetCaps(%s, %u bytes) = %08lx", name, size, hr);
    if (SUCCEEDED(hr)) HexDump(name, buf.data(), size, 64);
}

int wmain(int argc, wchar_t** argv)
{
    const wchar_t* dll = nullptr;
    const wchar_t* logPath = L"legacy9.log";
    const wchar_t* jsonPath = nullptr;
    UINT iface = D3D_UMD_INTERFACE_VERSION_WIN7, version = 0x10;
    size_t decoys = 256, rounds = 1;
    DWORD delayMs = 0;
    bool closeOnly = false, selfTest = true, noDriver = false;
    for (int i = 1; i < argc; i++) {
        if (!wcscmp(argv[i], L"--dll") && i + 1 < argc) dll = argv[++i];
        else if (!wcscmp(argv[i], L"--log") && i + 1 < argc) logPath = argv[++i];
        else if (!wcscmp(argv[i], L"--rounds") && i + 1 < argc) rounds = wcstoul(argv[++i], nullptr, 0);
        else if (!wcscmp(argv[i], L"--delay") && i + 1 < argc) delayMs = wcstoul(argv[++i], nullptr, 0);
        else if (!wcscmp(argv[i], L"--iface") && i + 1 < argc) iface = wcstoul(argv[++i], nullptr, 0);
        else if (!wcscmp(argv[i], L"--version") && i + 1 < argc) version = wcstoul(argv[++i], nullptr, 0);
        else if (!wcscmp(argv[i], L"--decoys") && i + 1 < argc) decoys = wcstoul(argv[++i], nullptr, 0);
        else if (!wcscmp(argv[i], L"--redzone")) g_redzone = true;
        else if (!wcscmp(argv[i], L"--trace-allocs")) g_traceAllocs = true;
        else if (!wcscmp(argv[i], L"--qai-forward")) g_qaiForward = true;
        else if (!wcscmp(argv[i], L"--qai-fill") && i + 1 < argc) g_qaiFill = wcstoul(argv[++i], nullptr, 0) & 0xff;
        else if (!wcscmp(argv[i], L"--qai-set") && i + 1 < argc) {
            for (wchar_t* s = argv[++i]; s && *s;) {
                wchar_t* end;
                UINT off = wcstoul(s, &end, 0);
                if (*end != L'=') break;
                UINT val = wcstoul(end + 1, &end, 0);
                g_qaiSet.push_back({ off, val });
                s = *end == L',' ? end + 1 : nullptr;
            }
        }
        else if (!wcscmp(argv[i], L"--kmt-forward")) g_kmtForward = true;
        else if (!wcscmp(argv[i], L"--load-only")) closeOnly = true;
        else if (!wcscmp(argv[i], L"--no-self-test")) selfTest = false;
        else if (!wcscmp(argv[i], L"--no-driver")) noDriver = true;
        else if (!wcscmp(argv[i], L"--json") && i + 1 < argc) jsonPath = argv[++i];
        else { wprintf(L"unknown option %s\n", argv[i]); return 2; }
    }
    if (!dll && !noDriver) {
        wprintf(L"usage: legacy9 --dll <path to atiumd64.dll> [--redzone] [--decoys n] [--rounds n] [--delay ms]\n"
                L"               [--iface 0x..] [--version n] [--qai-set off=val,...] [--qai-fill 0x..]\n"
                L"               [--qai-forward] [--kmt-forward] [--trace-allocs] [--load-only] [--log path]\n"
                L"               [--json path] [--no-self-test]\n"
                L"       legacy9 --no-driver [--decoys n] [--json path]\n"
                L"               measures the heap and proves the damage detector fires, with no driver at all\n");
        return 2;
    }

    // Opened so it can be read while the probe is still running, which matters when the host is a long-lived
    // process such as the player.
    if (g_logFile) { fclose(g_logFile); g_logFile = nullptr; }
    g_logFile = _wfsopen(logPath, L"w", _SH_DENYWR);
    InitializeCriticalSection(&g_cs);
    g_procHeap = GetProcessHeap();
    AddVectoredExceptionHandler(1, CrashFilter);

    wchar_t full[MAX_PATH] = L"(none)";
    if (dll) {
        GetFullPathNameW(dll, MAX_PATH, full, nullptr);
        wcscpy_s(g_driverDir, full);
        if (wchar_t* s = wcsrchr(g_driverDir, L'\\')) *s = 0;
    }

    Log("legacy9: driver %ls", full);
    Log("host process: %ls (pid %lu)", GetCommandLineW(), GetCurrentProcessId());
    Log("options: iface=0x%x version=0x%x redzone=%d decoys=%zu rounds=%zu delay=%lu qai=%s kmt=%s", iface, version,
        g_redzone, decoys, rounds, delayMs, g_qaiForward ? "forward" : "fake", g_kmtForward ? "forward" : "refuse");
    if (g_qaiForward) {
        g_realAdapter = FindRealAmdAdapter();
        Log("real AMD adapter handle for --qai-forward: %08x", g_realAdapter);
    }

    if (g_redzone)
        Log("note: --redzone pads every driver allocation by 2 x 0x%zx bytes, which moves its 152-byte requests out"
            " of the victim size class. It tests whether the driver writes outside its own blocks; it cannot also"
            " test adjacency to a menu vector.",
            (size_t)RZ);

    if (delayMs) { Log("waiting %lu ms before the first round", delayMs); Sleep(delayMs); }

    PlantDecoys(decoys);

    // A detector that has never fired proves nothing, so damage one decoy in the exact #4257 pattern and require
    // the scan to report it before any conclusion is drawn from a quiet run.
    bool selfTestPassed = false;
    int rc = 0;
    if (selfTest && !g_decoys.empty()) {
        Log("self-test: zeroing bytes 0x64..0x6B of decoy block %p", g_decoys[0].block);
        memset((char*)g_decoys[0].block + 0x64, 0, 8);
        size_t before = g_signatureHits;
        Checkpoint("self-test");
        selfTestPassed = g_signatureHits > before;
        Log("SELF-TEST: %s (the scan %s the planted damage)", selfTestPassed ? "PASS" : "FAIL",
            selfTestPassed ? "found" : "did not find");
        g_signatureHits = 0;
        g_decoyHits = 0;
        // A detector that cannot see planted damage makes every later result meaningless, so the rounds are
        // skipped; the run still reports, so the failure is visible rather than silent.
        if (!selfTestPassed) { rc = 4; rounds = 0; }
    }

    if (rounds) Checkpoint("before load");

    HRESULT lastOpenHr = E_FAIL;
    size_t roundsDone = 0;
    if (noDriver) { Log("--no-driver: the heap was measured and the detector checked; no driver was loaded"); rounds = 0; }
    for (size_t round = 1; round <= rounds; round++) {
        char cp[64];
        auto at = [&](const char* what) { snprintf(cp, sizeof cp, "r%zu %s", round, what); return cp; };

        // DONT_RESOLVE_DLL_REFERENCES is not used: the driver's DllMain must run, as it does under the real
        // runtime. Its DllMain therefore runs before the import hooks are in place, so what it allocates there
        // is not counted.
        HMODULE mod = LoadLibraryExW(full, nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
        if (!mod) { Log("LoadLibrary failed: %lu", GetLastError()); return 1; }
        Log("round %zu: loaded at %p", round, (void*)mod);
        HookImports(mod);
        Checkpoint(at("after load"));

        if (!closeOnly) {
            auto open = (PFN_OPENADAPTER)GetProcAddress(mod, "OpenAdapter");
            if (!open) { Log("no OpenAdapter export"); return 1; }

            static int rtAdapter = 'tpdA';
            D3DDDI_ADAPTERCALLBACKS cb = {};
            cb.pfnQueryAdapterInfoCb = QueryAdapterInfoCb;
            cb.pfnGetMultisampleMethodListCb = GetMultisampleMethodListCb;
            D3DDDI_ADAPTERFUNCS funcs = {};
            D3DDDIARG_OPENADAPTER oa = {};
            oa.hAdapter = &rtAdapter;
            oa.Interface = iface;
            oa.Version = version;
            oa.pAdapterCallbacks = &cb;
            oa.pAdapterFuncs = &funcs;

            HRESULT hr = open(&oa);
            Log("OpenAdapter = %08lx  hAdapter(drv)=%p DriverVersion=0x%x  GetCaps=%p CreateDevice=%p CloseAdapter=%p",
                hr, oa.hAdapter, oa.DriverVersion, (void*)funcs.pfnGetCaps, (void*)funcs.pfnCreateDevice,
                (void*)funcs.pfnCloseAdapter);
            lastOpenHr = hr;
            Checkpoint(at("after OpenAdapter"));

            if (SUCCEEDED(hr) && funcs.pfnGetCaps) {
                TryCaps(funcs, oa.hAdapter, "GETD3D9CAPS", D3DDDICAPS_GETD3D9CAPS, 304);
                TryCaps(funcs, oa.hAdapter, "GETFORMATCOUNT", D3DDDICAPS_GETFORMATCOUNT, 4);
                TryCaps(funcs, oa.hAdapter, "GETDECODEGUIDCOUNT", D3DDDICAPS_GETDECODEGUIDCOUNT, 4);
                TryCaps(funcs, oa.hAdapter, "GETVIDEOPROCESSORDEVICEGUIDCOUNT",
                        D3DDDICAPS_GETVIDEOPROCESSORDEVICEGUIDCOUNT, 4);
                Checkpoint(at("after GetCaps"));
            }
            if (SUCCEEDED(hr) && funcs.pfnCloseAdapter) {
                HRESULT c = funcs.pfnCloseAdapter(oa.hAdapter);
                Log("CloseAdapter = %08lx", c);
            }
            if (FAILED(hr)) rc = 3;
        }

        BOOL freed = FreeLibrary(mod);
        Log("round %zu: FreeLibrary = %d", round, freed);
        Checkpoint(at("after unload"));
        roundsDone++;
    }

    PrintSizeHistogram();
    size_t everClass = 0;
    for (auto& kv : g_proc.bySize) if (InVictimClass(kv.first)) everClass += kv.second;
    Log("SUMMARY: rounds=%zu  driver allocations: %zu on the process heap (%zu of them in the 152-byte class),"
        " %zu on its own heaps",
        rounds, g_proc.allocs, everClass, g_priv.allocs);
    Log("SUMMARY: #4257 signature hits=%zu  decoy hits=%zu (%zu decoys)  guard-zone hits=%zu of %zu checks "
        " vector-shaped blocks last seen=%zu  measured stride=0x%zx",
        g_signatureHits, g_decoyHits, g_decoys.size(), g_zoneHits, g_zoneChecks, g_victimsSeen, (size_t)g_stride);
    // A result file, so a caller asserts on fields instead of parsing the log. Windows paths are full of
    // backslashes, which have to be escaped or the file is not JSON.
    auto jsonString = [](FILE* j, const wchar_t* s) {
        fputc('"', j);
        for (; s && *s; s++) {
            if (*s == L'\\' || *s == L'"') { fputc('\\', j); fputc((char)*s, j); }
            else if (*s >= 0x20 && *s < 0x7f) fputc((char)*s, j);
            else fprintf(j, "\\u%04x", (unsigned)*s);
        }
        fputc('"', j);
    };
    if (jsonPath) {
        FILE* j = _wfsopen(jsonPath, L"w", _SH_DENYWR);
        if (!j) {
            Log("could not write the result file %ls", jsonPath);
        } else {
            wchar_t host[MAX_PATH] = L"";
            GetModuleFileNameW(nullptr, host, MAX_PATH);
            fprintf(j, "{\n");
            fprintf(j, "  \"driver\": ");
            jsonString(j, dll ? full : L"");
            fprintf(j, ",\n  \"host\": ");
            jsonString(j, host);
            fprintf(j, ",\n");
            fprintf(j, "  \"hostPid\": %lu,\n", GetCurrentProcessId());
            fprintf(j, "  \"noDriver\": %s,\n", noDriver ? "true" : "false");
            fprintf(j, "  \"redzone\": %s,\n", g_redzone ? "true" : "false");
            fprintf(j, "  \"roundsRequested\": %zu,\n", rounds);
            fprintf(j, "  \"roundsDone\": %zu,\n", roundsDone);
            fprintf(j, "  \"lastOpenAdapterHr\": %ld,\n", (long)lastOpenHr);
            fprintf(j, "  \"selfTestRun\": %s,\n", selfTest ? "true" : "false");
            fprintf(j, "  \"selfTestPassed\": %s,\n", selfTestPassed ? "true" : "false");
            fprintf(j, "  \"stride\": %zu,\n", (size_t)g_stride);
            fprintf(j, "  \"decoys\": %zu,\n", g_decoys.size());
            fprintf(j, "  \"decoyHits\": %zu,\n", g_decoyHits);
            fprintf(j, "  \"signatureHits\": %zu,\n", g_signatureHits);
            fprintf(j, "  \"guardZoneChecks\": %zu,\n", g_zoneChecks);
            fprintf(j, "  \"guardZoneHits\": %zu,\n", g_zoneHits);
            fprintf(j, "  \"processHeapAllocs\": %zu,\n", g_proc.allocs);
            fprintf(j, "  \"privateHeapAllocs\": %zu,\n", g_priv.allocs);
            fprintf(j, "  \"victimClassAllocs\": %zu,\n", everClass);
            fprintf(j, "  \"vectorShapedBlocks\": %zu,\n", g_victimsSeen);
            fprintf(j, "  \"driverBlocksNearVector\": %zu\n", g_lastNearby);
            fprintf(j, "}\n");
            fclose(j);
            Log("result file: %ls", jsonPath);
        }
    }

    Log("PROBE DONE");
    if (g_logFile) { fclose(g_logFile); g_logFile = nullptr; }
    return rc;
}

#ifdef LEGACY9_DLL
// Built as a DLL as well, so the probe can run inside another process: there the driver's process heap really is
// the application's heap, which is the condition the #4257 investigation says a standalone harness cannot create.
// LEGACY9_ARGS carries the same options the exe takes.
static HINSTANCE g_self;

// Called by the injector on its own thread. Nothing happens in DllMain: the probe has to call LoadLibrary and
// open files, and doing that under the loader lock hangs the host.
extern "C" __declspec(dllexport) DWORD WINAPI Legacy9Run(LPVOID)
{
    wchar_t cmd[4096] = L"legacy9 ";
    size_t used = wcslen(cmd);
    if (!GetEnvironmentVariableW(L"LEGACY9_ARGS", cmd + used, (DWORD)(4096 - used))) {
        // Injection into a running process cannot set its environment, so the options come from a file written
        // beside this DLL instead.
        wchar_t path[MAX_PATH];
        GetModuleFileNameW(g_self, path, MAX_PATH);
        if (wchar_t* dot = wcsrchr(path, L'.')) wcscpy_s(dot, MAX_PATH - (dot - path), L".args");
        FILE* f = nullptr;
        if (!_wfopen_s(&f, path, L"rt, ccs=UTF-8") && f) {
            if (fgetws(cmd + used, (int)(4096 - used), f)) {
                for (wchar_t* p = cmd + used; *p; p++)
                    if (*p == L'\r' || *p == L'\n') { *p = 0; break; }
            }
            fclose(f);
        }
    }
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(cmd, &argc);
    if (!argv) return 1;
    // A log is opened before anything can fail, so a bad options line still leaves a trace in the host process.
    if (!g_logFile) {
        wchar_t path[MAX_PATH];
        GetModuleFileNameW(g_self, path, MAX_PATH);
        if (wchar_t* dot = wcsrchr(path, L'.')) wcscpy_s(dot, MAX_PATH - (dot - path), L"-startup.log");
        g_logFile = _wfsopen(path, L"w", _SH_DENYWR);
        Log("Legacy9Run in pid %lu with options: %ls", GetCurrentProcessId(), cmd);
    }
    return (DWORD)wmain(argc, argv);
}

BOOL WINAPI DllMain(HINSTANCE self, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        g_self = self;
        DisableThreadLibraryCalls(self);
    }
    return TRUE;
}
#endif
