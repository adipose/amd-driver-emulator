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

static HANDLE g_logHandle = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_logCs;
static INIT_ONCE g_logCsOnce = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK LogCsInit(PINIT_ONCE, PVOID, PVOID*) { InitializeCriticalSection(&g_logCs); return TRUE; }

static void Log(const char* fmt, ...)
{
    InitOnceExecuteOnce(&g_logCsOnce, LogCsInit, nullptr, nullptr);
    char buf[2050];
    int n = 0;
    va_list ap;
    va_start(ap, fmt);
    // Wrapped in __try: vsnprintf may crash on driver threads whose UCRT was never initialized.
    // WriteFile avoids all UCRT thread state and cannot trigger a secondary exception in our VEH.
    __try { n = vsnprintf(buf, (int)(sizeof(buf) - 2), fmt, ap); }
    __except(EXCEPTION_EXECUTE_HANDLER) { n = 0; }
    va_end(ap);
    if (n < 0 || n > (int)(sizeof(buf) - 2)) n = (int)(sizeof(buf) - 2);
    buf[n] = '\n'; buf[n+1] = '\0';
    EnterCriticalSection(&g_logCs);
    __try {
        if (g_logHandle != INVALID_HANDLE_VALUE) {
            DWORD written;
            WriteFile(g_logHandle, buf, (DWORD)(n + 1), &written, nullptr);
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
    LeaveCriticalSection(&g_logCs);
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

#include "../lib/decoy.h"

// Forward declarations used in the BP handler below (defined later in the file).
static size_t g_clearAHits = 0;   // clear.A BP hit count; used by --hw-test PASS/FAIL
static void* volatile g_mmobjForCrash = nullptr; // mmobj the crash injection targets (set at mmobj.init)
static bool g_plant710465 = false; // --plant-710465: plant the drdump 710465 misaligned store and let teardown fault
static uint8_t* s_fakeChannel;
static void* s_fakeStateVtbl[64];
static void* s_fakeResourceVtbl[64]; // vtable for s_fakeResource: slot 7 = StubRet1 (texture gate)
static void* s_patchedSbVtbl[64];
static bool  s_patchedSbVtblReady = false;
static bool  s_fakeVtblFlushPatched = false;
static void* s_realFlush = nullptr;    // resolved once from atiumd6a; vtable slot 4 when stages are bound
static ULONG_PTR __stdcall StubRet0();
static ULONG_PTR __stdcall StubRet1();
static uint8_t s_fakeSb[0x2000];     // forward-declared for stateApply use
static uint8_t s_fakeSb80[0x100];    // forward-declared for stateApply use; [s_fakeSb+0x80] sub-object
static void*   s_fakeSb80Vtbl[32];   // vtable for s_fakeSb80: slot 4 = StubRet1
static uint8_t s_fakeSb80Out[64];    // object s_fakeSb80's slot-23 stub fills into the caller's out-struct
static uint8_t s_fakeSb110[256];     // zero-filled; wired at [s_fakeSb+0x110] so the 0x128680 epilogue
                                     // destructor (0x257900 → 0x61BD0/0x64030) reads [+0x58]/[+0x60] as 0
static uint8_t s_fakeResource[0x200]; // forward-declared for stateApply use
static uint8_t* s_fakeInner152 = nullptr; // allocated from g_innerHeap on first use; freed after DR0 arm so the write lands on freed memory
static HANDLE   g_innerHeap = nullptr;    // private heap: freed pages stay mapped, so driver write completes without AV
static uint8_t s_fakeDecoyNull[256];   // safe write target when fix-unbind active: not a registered decoy
static uint8_t s_fakeChan10[128];      // forward-declared; two-level fake for [channel+0x10]
// When a real texture resource is about to be freed (IFakeD3DTexture9::Release) while still
// bound to a stage, the shim stores its inner pointer ([hRes+0x48]) here; the stateApply BP
// then arms a DR0 write watchpoint on inner+0x64 so the driver's own write-after-free is caught.
static void* g_wpInnerPtr = nullptr;
// Two-phase injection state: reset by defer.run each deferred flush; incremented by the
// stateApply SNAP INJECT. 0 = pre-BIND, 1 = BIND in flight (driver updates RSI[+0x88]),
// 2+ = post-BIND (UNBIND injection: new snapshot slot left null to trigger the CLEAR path).
static int s_phase = 0;
// Stop flag: set when clear.A fires so the UNBIND injection stops re-arming the
// stage record and the BIND/UNBIND loop terminates instead of cycling forever.
static bool s_clearFired = false;
// Version-driven (set by the shim's ShimArmBps from the BP table): builds without a
// defer.run RVA (16.2.1) run one synchronous stateApply per flush, so the
// BIND->UNBIND phase machine is restarted at gate.ret instead of defer.run.
static bool g_phaseResetAtGateRet = false;
static uint8_t s_nullRes[64] = {};   // non-null sentinel for UNBIND fn_1850 main path
static void*   s_vtblObj = nullptr;  // vtable caller obj saved at BIND for state injection
// Zeroed stand-in for the per-resource backing object the deep flush writes into.
// atiumd64:0x51D80 (called from atiumd6a:0x1D30 with rcx=[channel+0x188]) does
// mov rax,[rcx+0x10]; mov [rax+0x1A4],r13d; mov [rax+0x1A8],r13d -- when the ret244a
// BIND injection put hRes into the slot, [hRes+0x10] is null (the driver never
// allocated backing for the emulated resource) and the write AVs at address 0x1A4.
// [slot+0x10] is also chained by the stateApply gate (atiumd64:0x2FF90): rbp=slot's
// backing, rax=[backing+0x600], rcx=[rax+0x20] must both be non-null.  The real
// device_inner (captured at stateApply) satisfies both uses; s_resBacking with its
// +0x600 wired to the real holder is the fallback.
static uint8_t s_resBacking[0x1000];
static void*   s_realDevInner = nullptr;  // device_inner captured at stateApply (rcx, when [rcx+0x600] chain is live)
static void*   s_realHolder   = nullptr;  // [device_inner+0x600] captured with it

#include "../lib/veh_bp.h"

// Walks the interrupted thread's frames from an exception context, module+offset per frame.
static void LogFramesFrom(CONTEXT* c, int frames)
{
    CONTEXT ctx2 = *c;
    for (int i = 0; i < frames && ctx2.Rip; i++) {
        UINT64 imgBase = 0;
        PRUNTIME_FUNCTION fe = RtlLookupFunctionEntry(ctx2.Rip, &imgBase, nullptr);
        char w[300];
        Log("       frame %s", Where((void*)ctx2.Rip, w, sizeof w));
        if (!fe) break;
        UINT64 establisher = 0;
        PVOID handler = nullptr, nv = nullptr;
        KNONVOLATILE_CONTEXT_POINTERS nvp = {};
        RtlVirtualUnwind(UNW_FLAG_NHANDLER, imgBase, ctx2.Rip, fe, &ctx2, &nv, &establisher, &nvp);
    }
}

#ifdef D3D9SHIM_DLL
#include "legacy9_pool.cpp"
#else
// Standalone build: the pool/fence globals live in legacy9_pool.cpp (shim-only) and
// g_drawCommittedHRes lives in d3d9shim.cpp.  The BP handler bodies that reference
// them are dead code here (the shim arms those tags), so inert fallbacks suffice.
static void PoolLock() {}
static void PoolUnlock() {}
struct FencedBlock { void* page_base; void* obj_ptr; SIZE_T obj_size; bool triggered; };
static FencedBlock g_fenced[256] = {};
static int g_fencedCount = 0;
static HANDLE g_drawCommittedHRes[16] = {};
#endif

static void OnBp(EXCEPTION_POINTERS* ep)
{
    uintptr_t at = (uintptr_t)ep->ExceptionRecord->ExceptionAddress;
    for (size_t i = 0; i < g_bpsCount; i++) {
        Bp& b = g_bps[i];
        if (b.addr != at) continue;
        DWORD old;
        VirtualProtect((void*)at, 1, PAGE_EXECUTE_READWRITE, &old);
        *(unsigned char*)at = b.orig;
        VirtualProtect((void*)at, 1, old, &old);
        ep->ContextRecord->Rip = at;
        ep->ContextRecord->EFlags |= 0x100; // single-step over the restored byte
        g_rearm = at;
        char w[300];
        Log("  bp %-24s rcx=%p rdx=%p r8=%p r9=%p", b.tag, (void*)ep->ContextRecord->Rcx,
            (void*)ep->ContextRecord->Rdx, (void*)ep->ContextRecord->R8, (void*)ep->ContextRecord->R9);
        if (!strcmp(b.tag, "stateApply")) {
            // Observational only: the driver owns the channel, the draw-param structs and the
            // state snapshots; nothing here may substitute its own objects for them.  Log the
            // real objects and, when a texture was released while still bound (g_wpInnerPtr,
            // captured by the shim from the released resource's [hRes+0x48]), arm a DR0 write
            // watchpoint on inner+0x64 through the exception context so the driver's own
            // write-after-free is caught by the hardware.
            static int s_stateApplyCount = 0;
            s_stateApplyCount++;
            void* s = (void*)ep->ContextRecord->Rdx;
            __try {
                void* rbp = *(void**)((char*)s + 0x58);
                void* r14 = *(void**)((char*)s + 0x60);
                // The atiumd64 gate at 0x2FF90 calls atiumd6a:0x2180 only when both rax=[atiumd64+0x7F45C0]
                // and rcx=[[device_inner+0x600]+0x20] are non-null; dump that chain (rcx=device_inner here).
                void* inner = (void*)ep->ContextRecord->Rcx;
                void* p600 = *(void**)((char*)inner + 0x600);
                void* chan  = p600 ? *(void**)((char*)p600 + 0x20) : nullptr;
                Log("       stateApply(#%d): drawparams %p %p  [inner+0x600]=%p channel=%p",
                    s_stateApplyCount, rbp, r14, p600, chan);
#ifdef D3D9SHIM_DLL
                // Capture the real device_inner/holder pair the first time the gate runs
                // with a live chain; st.call20 installs it as [hRes+0x10] so the same gate
                // keeps working after the BIND injection puts our resource in the slot.
                if (p600 && chan && inner != (void*)s_resBacking &&
                    inner != s_realDevInner && (uintptr_t)inner > 0x10000) {
                    s_realDevInner = inner;
                    s_realHolder = p600;
                    if (!*(void**)(s_resBacking + 0x600))
                        *(void**)(s_resBacking + 0x600) = p600;
                    Log("       stateApply: captured device_inner=%p holder=%p (for [hRes+0x10] install)",
                        inner, p600);
                    // The old-resource clear (fn_1850 -> atiumd64:0x53180 -> 0x596D0) runs
                    // rcx=device_inner and calls [device_inner+0xD8] when [hRes+0x10]!=0,
                    // gated on [[device_inner]+4] >= 0x3002.  Dump that chain once.
                    __try {
                        void* vt = *(void**)inner;
                        unsigned ver = vt ? *(unsigned*)((char*)vt + 4) : 0;
                        void* p8 = *(void**)((char*)inner + 8);
                        void* pd8 = *(void**)((char*)inner + 0xD8);
                        char w1[300], w2[300];
                        Log("       stateApply: device_inner vtbl=%p [vtbl+4]=%08x [+8]=%p [+0xD8]=%s",
                            vt, ver, p8, pd8 ? Where(pd8, w1, sizeof w1) : "(null)");
                        (void)w2;
                        // One-shot version-gate bypass: the clear path at atiumd64:0x53180
                        // requires [[device_inner]+4] >= 0x3002, but the adapter settings
                        // block carries 0xC00 here.  Patch it once so clear.A can fire.
                        static bool s_vtblVerPatched = false;
                        if (vt && ver < 0x3002 && !s_vtblVerPatched) {
                            *(unsigned*)((char*)vt + 4) = 0x3002;
                            s_vtblVerPatched = true;
                            Log("       stateApply: PATCHED [vtbl+4] 0x%08x -> 0x3002 (version gate bypass)", ver);
                        }
                    } __except (EXCEPTION_EXECUTE_HANDLER) { Log("       stateApply: devinner dump fault"); }
                }
#endif
                if (rbp) {
                    void* snap = *(void**)((char*)rbp + 0x1B8);
                    Log("       stateApply: rbp snapshot=%p slots [+0x88]=%p [+0x98]=%p [+0x1A0]=%x", snap,
                        snap ? *(void**)((char*)snap + 0x88) : nullptr,
                        snap ? *(void**)((char*)snap + 0x98) : nullptr,
                        snap ? *(unsigned*)((char*)snap + 0x1A0) : 0);
                    static int s_snapDumped = 0;
                    if (snap && s_snapDumped < 4) {
                        s_snapDumped++;
                        HexDump("snap", snap, 0x60, 0x60);
                        HexDump("snap+0x1a00", (char*)snap + 0x1A00, 0x80, 0x80);
                    }
                }
                if (chan) {
                    void* sb = *(void**)((char*)chan + 0x28);
                    Log("       stateApply: [chan+0x28]=%p vtbl=%p", sb, sb ? *(void**)sb : nullptr);
                }
#ifdef D3D9SHIM_DLL
                // Use the draw-committed snapshot (captured at DrawPrimitive time, before MPCVR
                // unbinds textures before Present). g_shimBoundCount is 0 by the time the deferred
                // flush fires stateApply; g_drawCommittedCount preserves the state from draw time.
                Log("       stateApply: D3D9SHIM block liveCount=%d committedCount=%d r14=%p",
                    g_shimBoundCount, g_drawCommittedCount, r14);
                // Inject texture binding into the r14 (new-state) snapshot so
                // atiumd6a:0x2180 passes the CMP [snapshot+0x1A0],0 check at RVA 0x241A
                // and reaches the flush path instead of branching to the skip at 0x24EF.
                // snapshot = *(r14+0x1B8); r14 is the second draw-params from s+0x60.
                void* r14_snap = nullptr;
                __try { r14_snap = r14 ? *(void**)((char*)r14 + 0x1B8) : nullptr; }
                __except (EXCEPTION_EXECUTE_HANDLER) {}
                // Steady-state gate fix: during playback the recorder never rebuilds the
                // snapshots -- the stateApply gate at 0x30334 checks [rbp+0x1B8]!=0 and the
                // gate fn 0x2FF90 then checks [r14+0x1B8]!=0, and after one forced flush the
                // driver epilogue clears the r14 link so the gate never fires again
                // (2155/2158 stateApplies skipped in a 25s MPCVR run).  Cross-link both
                // draw-params to whichever snapshot is live so the flush runs every cycle.
                if (rbp && r14 && g_drawCommittedCount > 0 && !s_clearFired) {
                    void* rbp_snap = nullptr;
                    __try { rbp_snap = *(void**)((char*)rbp + 0x1B8); }
                    __except (EXCEPTION_EXECUTE_HANDLER) {}
                    static int s_linkLog = 0;
                    if (!rbp_snap && r14_snap) {
                        __try {
                            *(void**)((char*)rbp + 0x1B8) = r14_snap;
                            if (s_linkLog < 8) { s_linkLog++;
                                Log("       stateApply: linked [rbp+0x1B8]=%p (was null) -- forcing flush gate",
                                    r14_snap); }
                        } __except (EXCEPTION_EXECUTE_HANDLER) {}
                    } else if (rbp_snap && !r14_snap) {
                        __try {
                            *(void**)((char*)r14 + 0x1B8) = rbp_snap;
                            r14_snap = rbp_snap;
                            if (s_linkLog < 8) { s_linkLog++;
                                Log("       stateApply: linked [r14+0x1B8]=%p (was null) -- forcing flush gate",
                                    rbp_snap); }
                        } __except (EXCEPTION_EXECUTE_HANDLER) {}
                    }
                }
                if (r14_snap && s_clearFired) {
                    Log("       stateApply: clear already fired - skipping SNAP INJECT (loop stop)");
                } else if (r14_snap) {
                    __try {
                        // The flush's stage-0 resource has two sources:
                        //   BIND phase: the shim-committed binding g_shimStageHRes[0].
                        //     g_drvBoundHRes[0] cannot be used here -- it is only recorded
                        //     after pfnSetTexture returns, but the first flush (and this
                        //     handler) runs INSIDE that call, so keying BIND on it meant
                        //     bindPhase was always false, the BIND inject never fired, and
                        //     the driver never allocated the inner object.
                        //   UNBIND phase: the driver-side applied binding g_drvBoundHRes[0]
                        //     (a texture the driver still references even after the shim
                        //     released it -- exactly the #4257 condition).
                        HANDLE shimH0 = g_shimStageHRes[0];
                        HANDLE drvH0  = g_drvBoundHRes[0];
                        bool bindPhase = (s_phase == 0 && shimH0 != nullptr);
                        HANDLE injectH0 = bindPhase ? shimH0 : drvH0;
                        // Always inject the &g_stageRec POINTER (not a count!) so the
                        // CMP [snap+0x1A0],0 at 0x241A passes.  res0/res1 are what the
                        // driver reads at st.baa5 ([RBX+0x08]) as the NEW resource: hRes
                        // only in the BIND phase, null in UNBIND so the 0x244A vtable
                        // call takes the CLEAR path instead of re-BINDing.
                        g_stageRec.pad0 = nullptr;
                        g_stageRec.res0 = bindPhase ? injectH0 : (HANDLE)s_nullRes;
                        g_stageRec.res1 = injectH0 ? injectH0 : (HANDLE)s_nullRes;  // applied binding - OLD resource for CLEAR path
                        *(void**)((char*)r14_snap + 0x1A0) = (void*)&g_stageRec;
                        if (s_phase == 0 && injectH0) {
                            // Phase 1 BIND: inject hRes so the driver binds stage 0
                            *(void**)((char*)r14_snap + 0x88) = (void*)injectH0;
                            Log("       stateApply: BIND INJECT (phase 1) r14_snap=%p [+0x88]=%p [+0x1A0]=&stageRec",
                                r14_snap, injectH0);
                            // Inject [hRes+8]=hRes (self-ref, non-null) and [hRes+16]=1 so fn_1850 takes the main path.
                            void* hResPtr = (void*)injectH0;
                            // If hRes is already fenced (released-while-bound, pump path),
                            // do NOT touch it at all: the driver's own deref of the fenced
                            // page is the FENCE UAF detection, and a shim-side touch would
                            // either fault here or (worse) get the page disarmed first.
                            bool hResFenced = false;
                            if (hResPtr) {
                                uintptr_t _pg = (uintptr_t)hResPtr & ~(uintptr_t)0xFFF;
                                PoolLock();
                                for (int _i = 0; _i < g_fencedCount; _i++)
                                    if (!g_fenced[_i].triggered &&
                                        (uintptr_t)g_fenced[_i].page_base == _pg) { hResFenced = true; break; }
                                PoolUnlock();
                            }
                            if (hResPtr && hResFenced) {
                                Log("       stateApply: BIND - hRes=%p page FENCED, skipping self-ref patch (UAF trigger live)", hResPtr);
                            } else if (hResPtr) {
                                __try {
                                    // Do not clobber a FENCE-UAF bait pointer planted by the
                                    // shim's Release at [hRes+8]: fn_1850 passes [hRes+8] to the
                                    // clear dispatch, and clr.inner dereferences it -- the bait
                                    // is a PAGE_NOACCESS page whose touch is the detection.
                                    void* cur8 = *(void**)((char*)hResPtr + 8);
                                    bool isBait = false;
                                    PoolLock();
                                    for (int _i = 0; _i < g_fencedCount; _i++)
                                        if (g_fenced[_i].page_base == cur8) { isBait = true; break; }
                                    PoolUnlock();
                                    if (!isBait) {
                                        *(ULONG_PTR*)((char*)hResPtr + 8)  = (ULONG_PTR)hResPtr;
                                        Log("       stateApply: BIND - patched hRes[+8]=self hRes[+16]=1 at %p", hResPtr);
                                    } else {
                                        static int s_baitKept = 0;
                                        if (s_baitKept < 6) { s_baitKept++;
                                            Log("       stateApply: BIND - hRes[+8]=%p is bait, NOT patching to self at %p", cur8, hResPtr); }
                                    }
                                    *(DWORD*)((char*)hResPtr + 16) = 1;
                                } __except(EXCEPTION_EXECUTE_HANDLER) { Log("       stateApply: hRes patch fault"); }
                            }
                            // The driver has now applied this binding: record it so later
                            // UNBIND phases inject what the *driver* still references, even
                            // if the shim has since released it (the #4257 window).
                            g_drvBoundHRes[0] = injectH0;
                            Log("       stateApply: BIND applied - g_drvBoundHRes[0]=%p", injectH0);
                        } else {
                            // Phase 2+ UNBIND: explicitly null [+0x88] (the BIND phase set it to hRes; must clear it
                            // so the driver sees new=null and triggers the CLEAR path, not another BIND).
                            *(void**)((char*)r14_snap + 0x88) = nullptr;
                            Log("       stateApply: UNBIND INJECT (phase %d) r14_snap=%p [+0x88]=null(cleared) [+0x1A0]=&stageRec",
                                s_phase, r14_snap);
                            // Unbind applied: the driver no longer references the stage-0
                            // resource after this flush.
                            g_drvBoundHRes[0] = nullptr;
                        }
                        s_phase++;
                    } __except (EXCEPTION_EXECUTE_HANDLER) { Log("       stateApply: SNAP INJECT fault"); }
                }
                // Arm DR0 on the released texture's real inner object, when one has been captured
                // and not armed yet.  Writing Dr0/Dr7 into the exception context is what arms it:
                // the OS restores the context when OnBp returns.  (RtlCaptureContext /
                // SetThreadContext deadlock from this path.)
                static void* s_wpArmedFor[4] = {};
                static int s_wpSlots = 0;
                if (g_wpInnerPtr && s_wpSlots < 4) {
                    bool seen = false;
                    for (int i = 0; i < s_wpSlots; i++) if (s_wpArmedFor[i] == g_wpInnerPtr) seen = true;
                    if (!seen) {
                        uintptr_t wpAddr = (uintptr_t)g_wpInnerPtr + 0x64;
                        SetDrSlot(ep->ContextRecord, s_wpSlots, wpAddr);
                        InitOnceExecuteOnce(&g_hwWpCsOnce, HwWpCsInit, nullptr, nullptr);
                        g_hwWp[s_wpSlots] = HwWp{ wpAddr, g_wpInnerPtr, true };
                        Log("       stateApply: armed DR%d write WP on REAL freed inner %p+0x64 "
                            "(from m_hRes+0x48 of a texture released while bound)",
                            s_wpSlots, g_wpInnerPtr);
                        s_wpArmedFor[s_wpSlots++] = g_wpInnerPtr;
                    }
                }
#endif
            } __except (EXCEPTION_EXECUTE_HANDLER) { Log("       (read fault)"); }
        } else if (!strcmp(b.tag, "flush")) {
            // Count the real flush: entry of atiumd6a's state-flush function with the driver's own
            // state.  rcx = the [channel+0x28] object, rdx = channel, r8/r9 = old/new snapshots.
            static size_t s_flushCount = 0;
            s_flushCount++;
            __try {
                void* chan = (void*)ep->ContextRecord->Rdx;
                void* newsnap = (void*)ep->ContextRecord->R9;
                void* slot0 = newsnap ? *(void**)((char*)newsnap + 0x88) : nullptr;
                void* res48 = slot0 ? *(void**)((char*)slot0 + 0x48) : nullptr;
                Log("       flush(#%zu): this=%p chan=%p old=%p new=%p  new[+0x88]=%p [res+0x48]=%p",
                    s_flushCount, (void*)ep->ContextRecord->Rcx, chan,
                    (void*)ep->ContextRecord->R8, newsnap, slot0, res48);
                if (slot0 && !res48) {
                    // hRes[+0x48] still null -- scan hRes for the first live pointer to find real offset.
                    for (int _off = 0x40; _off <= 0x100; _off += 8) {
                        void* v = nullptr;
                        __try { v = *(void**)((char*)slot0 + _off); } __except(EXCEPTION_EXECUTE_HANDLER) {}
                        if (v && (uintptr_t)v > 0x10000)
                            Log("       flush hRes scan: hRes[+0x%x]=%p (non-null)", _off, v);
                    }
                }
                if (res48 && (uintptr_t)res48 > 0x10000) {
                    Log("       flush: hRes[+0x48]=%p IS non-null -- capturing as g_wpInnerPtr", res48);
                    g_wpInnerPtr = res48;
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) { Log("       flush: (read fault)"); }
        } else if (!strcmp(b.tag, "clrzero")) {
            // Skip the CALL instruction entirely (race-free alternative to capping r8).
            // The clrzero BP is at a 5-byte CALL rel32 (original byte 0xe8); skipping it
            // prevents both this thread and any other thread from running the uncapped
            // memset(inner_obj, 0, 0x1000) that would overflow the 152-byte block.
            // Re-arm the BP immediately (we un-armed it above at line 158) so other threads
            // that reach this call site also skip it, closing the race window.
            {
                DWORD ra_old;
                VirtualProtect((void*)at, 1, PAGE_EXECUTE_READWRITE, &ra_old);
                *(unsigned char*)at = 0xCC;    // re-arm immediately
                VirtualProtect((void*)at, 1, ra_old, &ra_old);
            }
            ep->ContextRecord->Rip = at + 5;   // advance past the 5-byte call instruction
            ep->ContextRecord->EFlags &= ~0x100u;  // cancel single-step (no re-arm needed)
            g_rearm = 0;
            Log("       clrzero: skipped call (race-free), inner_obj=%p", (void*)ep->ContextRecord->Rcx);
        } else if (!strcmp(b.tag, "acquire")) {
            void* ctx = (void*)ep->ContextRecord->Rcx;
            __try {
                Log("       acquire: n=%lu ctx->[0]=%p ctx->[8]=%x ctx->[0x10]=%p",
                    (unsigned long)ep->ContextRecord->Rdx, *(void**)ctx, *(unsigned*)((char*)ctx + 8),
                    *(void**)((char*)ctx + 0x10));
            } __except (EXCEPTION_EXECUTE_HANDLER) { Log("       (read fault)"); }
        } else if (!strcmp(b.tag, "mmdev.done")) {
            // At atiumd64+0x1E9C8: rax = result of atiumd6a:0x9430 call, stored to [rbx+0x5028].
            Log("       mmdev.done: [settings+0x5028] <- rax=%p (settings=%p)",
                (void*)ep->ContextRecord->Rax, (void*)ep->ContextRecord->Rbx);
        } else if (!strcmp(b.tag, "mmobj.make")) {
            // atiumd6a:0x9430(rcx?, rdx=settings+0x20, r8=settings+0x5030)
            Log("       mmobj.make: rdx=%p r8=%p", (void*)ep->ContextRecord->Rdx,
                (void*)ep->ContextRecord->R8);
        } else if (!strcmp(b.tag, "chan.make")) {
            // atiumd6a:0x3710(rcx=holder, rdx=[settings+0x5028])
            Log("       chan.make: holder=%p [settings+0x5028]=%p",
                (void*)ep->ContextRecord->Rcx, (void*)ep->ContextRecord->Rdx);
        } else if (!strcmp(b.tag, "mmdev.make")) {
            Log("       mmdev.make: settings=%p", (void*)ep->ContextRecord->Rcx);
        } else if (!strcmp(b.tag, "holder.make")) {
            Log("       holder.make: dev_inner=%p", (void*)ep->ContextRecord->Rcx);
        } else if (!strcmp(b.tag, "mmdev.free")) {
            Log("       mmdev.free: settings=%p [+0x5028]=%p", (void*)ep->ContextRecord->Rcx,
                (void*)ep->ContextRecord->Rcx);
        } else if (!strcmp(b.tag, "mmobj.init")) {
            // At atiumd6a+0x9482: eax = init() result; 1 means the object is kept. rbx is the new
            // object; [rbx] is its vtable, which identifies the variant (the #4257 crash object has
            // its vtable at atiumd6a RVA 0x2CEB90; the OpenAdapter variant at 0x4A2B68).
            void* vt = nullptr;
            __try { vt = *(void**)ep->ContextRecord->Rbx; } __except (EXCEPTION_EXECUTE_HANDLER) {}
            char wv[128];
            Log("       mmobj.init: init returned %d (rbx=%p vtable=%p %s)",
                (int)ep->ContextRecord->Rax, (void*)ep->ContextRecord->Rbx, vt,
                vt ? Where(vt, wv, sizeof wv) : "(unreadable)");
            // init == 1 keeps the object, which is the branch whose destructor later runs
            // vtable+0x40 (crash.fn). Remember it so the workload can plant the bad pointer.
            if ((int)ep->ContextRecord->Rax == 1)
                g_mmobjForCrash = (void*)ep->ContextRecord->Rbx;
        } else if (!strcmp(b.tag, "crash.fn")) {
            // atiumd6a:0x37510 — the crash vtable's slot+0x40. The field crash is the read of
            // [obj+0x68] at +0x7A (0x3758A); log the object and that field before it happens.
            void* obj = (void*)ep->ContextRecord->Rcx;
            void* f68 = nullptr;
            __try { f68 = *(void**)((char*)obj + 0x68); } __except (EXCEPTION_EXECUTE_HANDLER) {}
            char wv[128];
            Log("       crash.fn: obj=%p [obj+0x68]=%p %s", obj, f68,
                f68 ? Where(f68, wv, sizeof wv) : "(null)");
        } else if (!strcmp(b.tag, "init.ok") || !strcmp(b.tag, "init.fail")) {
            Log("       %s: rbp+0x20=%x rbp+0x30=%x", b.tag,
                *(unsigned*)(ep->ContextRecord->Rbp + 0x20),
                *(unsigned*)(ep->ContextRecord->Rbp + 0x30));
        } else if (!strncmp(b.tag, "init.", 5)) {
            Log("       %s: eax=%llx rbx=%p rdi=%p rsi=%p", b.tag,
                (unsigned long long)ep->ContextRecord->Rax, (void*)ep->ContextRecord->Rbx,
                (void*)ep->ContextRecord->Rdi, (void*)ep->ContextRecord->Rsi);
        } else if (!strncmp(b.tag, "q370.", 5)) {
            Log("       %s: eax=%llx rbx=%p rdi=%p", b.tag,
                (unsigned long long)ep->ContextRecord->Rax, (void*)ep->ContextRecord->Rbx,
                (void*)ep->ContextRecord->Rdi);
        } else if (!strncmp(b.tag, "s80.", 4)) {
            Log("       %s: eax=%llx rbx=%p rdi=%p rsi=%p", b.tag,
                (unsigned long long)ep->ContextRecord->Rax, (void*)ep->ContextRecord->Rbx,
                (void*)ep->ContextRecord->Rdi, (void*)ep->ContextRecord->Rsi);
        } else if (!strncmp(b.tag, "q7b.", 4)) {
            Log("       %s: eax=%llx rbx=%p ebp=%p rsi=%p rdi=%p", b.tag,
                (unsigned long long)ep->ContextRecord->Rax, (void*)ep->ContextRecord->Rbx,
                (void*)ep->ContextRecord->Rbp, (void*)ep->ContextRecord->Rsi,
                (void*)ep->ContextRecord->Rdi);
        } else if (!strcmp(b.tag, "cap.read")) {
            // 0x85370(rcx=obj80, rdx=&count, r8d=engine id, r9=&out1): logs the engine id the
            // driver wants from atiumd6a.cap.
            Log("       cap.read: engine id=%x rdx=%p r9=%p", (unsigned)ep->ContextRecord->R8,
                (void*)ep->ContextRecord->Rdx, (void*)ep->ContextRecord->R9);
        } else if (!strcmp(b.tag, "draw.pipe")) {
            // 0x35470: the immediate draw path.  It early-outs unless [hDev+0xE10] and
            // [hDev+0x1C90] are non-null; log them plus the deferred-batch count and the
            // 0x100000 gate bit the deferred flush (0x2DE40) requires.
            __try {
                void* d = (void*)ep->ContextRecord->Rcx;
                void* hRes1c90 = *(void**)((char*)d + 0x1C90);
                int dcnt = *(int*)((char*)d + 0x47B0);
                unsigned gate = *(unsigned*)((char*)d + 0x18);
                Log("       draw.pipe: hDev=%p [+0xE10]=%p [+0x1C90]=%p [+0x47B0]=%d [+0x18]=%08x type=%lu count=%lu",
                    d, *(void**)((char*)d + 0xE10), hRes1c90,
                    dcnt, gate,
                    (unsigned long)ep->ContextRecord->Rdx,
                    (unsigned long)ep->ContextRecord->R8);
                // Stale-reference probe: if the texture handle the device still holds at
                // [+0x1C90] was released, its inner page ([hRes+0x48]) is PAGE_NOACCESS.
                if (hRes1c90) {
                    void* inner = *(void**)((char*)hRes1c90 + 0x48);
                    if (inner) {
                        MEMORY_BASIC_INFORMATION mbi;
                        if (VirtualQuery(inner, &mbi, sizeof mbi) &&
                            (mbi.State == MEM_FREE || mbi.Protect == PAGE_NOACCESS)) {
                            Log("       STALE REF detected hRes=%p inner=%p (%s)",
                                hRes1c90, inner,
                                mbi.State == MEM_FREE ? "MEM_FREE" : "PAGE_NOACCESS");
                        }
                    }
                }
                // Force the deferred flush: nonzero deferred-batch count + the 0x100000
                // gate bit, so deferFlush (0x2DE40) runs on this draw.
                *(int*)((char*)d + 0x47B0) = 1;
                *(unsigned*)((char*)d + 0x18) = gate | 0x100000;
            } __except (EXCEPTION_EXECUTE_HANDLER) { Log("       draw.pipe: (read fault)"); }
        } else if (!strcmp(b.tag, "defer.run")) {
            Log("       defer.run: 0x2DE9A reached (deferred flush running)");
            s_phase = 0;  // new deferred flush: restart the BIND→UNBIND injection sequence
            s_clearFired = false;
        } else if (!strcmp(b.tag, "draw.rec")) {
            Log("       draw.rec: recorder 0x2CCE0 reached");
        } else if (!strcmp(b.tag, "st.flush")) {
            // atiumd6a:0x2180 entry. r9 = new draw-params; *(r9+0x1B8) = new snapshot.
            __try {
                void* r9   = (void*)ep->ContextRecord->R9;
                void* snap = r9 ? *(void**)((char*)r9 + 0x1B8) : nullptr;
                void* h88  = snap ? *(void**)((char*)snap + 0x88) : nullptr;
                unsigned s1a0 = snap ? *(unsigned*)((char*)snap + 0x1A0) : 0u;
                Log("       st.flush: chan=%p r9=%p snap=%p [+0x88]=%p [+0x1A0]=%u",
                    (void*)ep->ContextRecord->Rcx, r9, snap, h88, s1a0);
            } __except (EXCEPTION_EXECUTE_HANDLER) { Log("       st.flush: (read fault)"); }
        } else if (!strcmp(b.tag, "st.br241a")) {
            // CMP [RSI+0x1A0], R15 at RVA 0x241A. RSI = viewport-state object = [rdx+0x18].
            // The handler previously read RCX (which the BP log shows), but the CMP uses RSI.
            // Log both and inject into [RSI+0x1A0] and [RSI+0x88] to pass the check.
            void* rsi = (void*)ep->ContextRecord->Rsi;
            void* rcx_snap = (void*)ep->ContextRecord->Rcx;
            void* rdi_val = (void*)ep->ContextRecord->Rdi;
            unsigned s1a0_rsi = 0, s1a0_rcx = 0;
            void* h88_rsi = nullptr;
            {
                __try {
                    h88_rsi  = rsi ? *(void**)((char*)rsi + 0x88) : nullptr;
                    s1a0_rsi = rsi ? *(unsigned*)((char*)rsi + 0x1A0) : 0u;
                    s1a0_rcx = rcx_snap ? *(unsigned*)((char*)rcx_snap + 0x1A0) : 0u;
                    void* hres48 = h88_rsi ? *(void**)((char*)h88_rsi + 0x48) : nullptr;
                    unsigned char rdiByte = 0;
                    if (rdi_val) __try { rdiByte = *(unsigned char*)rdi_val; } __except(EXCEPTION_EXECUTE_HANDLER) { rdiByte = 0xEE; }
                    Log("       st.br241a: RSI=%p [+0x88]=%p [+0x1A0]=%u hRes[+0x48]=%p RDI=%p [RDI]=%02x (%s)",
                        rsi, h88_rsi, s1a0_rsi, hres48, rdi_val, rdiByte,
                        s1a0_rsi ? "WILL FLUSH" : "WILL SKIP");
                    Log("       st.br241a: RCX=%p [+0x1A0]=%u (inject source)", rcx_snap, s1a0_rcx);
                    if (h88_rsi && !hres48) {
                        for (int _off = 0x40; _off <= 0x100; _off += 8) {
                            void* v = nullptr;
                            __try { v = *(void**)((char*)h88_rsi + _off); } __except (EXCEPTION_EXECUTE_HANDLER) {}
                            if (v && (uintptr_t)v > 0x10000)
                                Log("       st.br241a: hRes[+0x%x]=%p (non-null)", _off, v);
                        }
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) { Log("       st.br241a: (read fault)"); }
            }
            Log("       st.br241a: post-__try RSI=%p s1a0_rsi=%u RCX=%p s1a0_rcx=%u",
                rsi, s1a0_rsi, rcx_snap, s1a0_rcx);
#ifdef D3D9SHIM_DLL
            // Inject the driver-side applied binding so the CMP passes; which half depends
            // on the phase.  g_drvBoundHRes[0] is what the driver currently references --
            // a released texture appears here only when it was destroyed without a prior
            // unbind (the #4257 condition); the draw-committed snapshot must NOT be used
            // here because it would re-present textures the driver already let go.
            if (g_drawCommittedCount > 0 && rsi && !s_clearFired) {
                HANDLE injectH0 = g_drvBoundHRes[0];
                __try {
                    // Populate the stage-entry record with the applied texture handle.
                    // res0/res1 must be hRes only for BIND (s_phase==1); in UNBIND they are
                    // s_nullRes so the driver takes the CLEAR path instead of re-BINDing.
                    bool bindPhase = (s_phase == 1) && injectH0;
                    g_stageRec.pad0 = nullptr;
                    g_stageRec.res0 = bindPhase ? injectH0 : (HANDLE)s_nullRes;
                    g_stageRec.res1 = bindPhase ? injectH0 : (HANDLE)s_nullRes;
                    *(void**)((char*)rsi + 0x1A0) = (void*)&g_stageRec;
                    if (s_phase == 1 && injectH0) {
                        // Phase 1 BIND: set RSI[+0x88]=null so the driver sees no old binding.
                        // Clear RDI so the dirty-flag check at 0x242C (CMP [RDI],R15B) passes;
                        // RDI was loaded from [RSI+0x148] at 0x2260, and setting the register
                        // directly avoids having to know whether [RSI+0x148] is safe to overwrite.
                        *(void**)((char*)rsi + 0x88) = nullptr;
                        ep->ContextRecord->Rdi = 0;
                        Log("       st.br241a: BIND phase - RSI[+0x88]=null [+0x1A0]=&stageRec RDI->0");
                    } else {
                        // Initialize s_nullRes sentinel: [+8]=hRes (non-null), [+16]=1 so fn_1850 main path runs.
                        // With no applied binding, self-reference s_nullRes: the sentinel is
                        // static storage that is never released, so clr.inner reads stay mapped.
                        *(ULONG_PTR*)(s_nullRes + 8)  = (ULONG_PTR)(injectH0 ? injectH0 : (HANDLE)s_nullRes);
                        *(DWORD*)(s_nullRes + 16) = 1;
                        Log("       st.br241a: UNBIND ph%d - s_nullRes[+8]=%p [+16]=1", s_phase,
                            (void*)*(ULONG_PTR*)(s_nullRes + 8));
                        // Phase 2+ UNBIND: inject RSI[+0x88]=hRes (the driver's BIND processing did NOT
                        // update RSI[+0x88] in this emulated context, so we inject it manually).
                        // Also zero RDI: the dirty-flag check at 0x242C (CMP [RDI],R15B) with [RDI]=1
                        // causes st.skip; zeroing RDI matches the BIND path's pre-condition (RDI was
                        // already 0 when BIND succeeded).
                        *(void**)((char*)rsi + 0x88) = (void*)injectH0;
                        ep->ContextRecord->Rdi = 0;
                        Log("       st.br241a: UNBIND phase %d - RSI[+0x88]=hRes=%p [+0x1A0]=&stageRec RDI->0",
                            s_phase, (void*)injectH0);
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) { Log("       st.br241a: inject fault"); }
            } else if (s_clearFired) {
                Log("       st.br241a: clear already fired - skipping re-injection (loop stop)");
            }
#endif
        } else if (!strcmp(b.tag, "st.br22f8")) {
            Log("       st.br22f8: STATES DIFFER branch reached (will continue to full flush)");
        } else if (!strcmp(b.tag, "st.skip")) {
            Log("       st.skip: flush SKIPPED (stage count was 0, no-op return)");
        } else if (!strcmp(b.tag, "st.r14p90")) {
            // 0x2435: MOV RAX, [R14+0x90]; if null, driver AVs into its own SEH → 0x24EF.
            __try {
                void* r14 = (void*)ep->ContextRecord->R14;
                void* rbx = (void*)ep->ContextRecord->Rbx;
                void* p90 = r14 ? *(void**)((char*)r14 + 0x90) : nullptr;
                void* p90p20 = p90 ? *(void**)((char*)p90 + 0x20) : nullptr;
                Log("       st.r14p90: R14=%p [+0x90]=%p [+0x90+0x20]=%p RBX=%p", r14, p90, p90p20, rbx);
            } __except (EXCEPTION_EXECUTE_HANDLER) { Log("       st.r14p90: (read fault)"); }
        } else if (!strcmp(b.tag, "st.baa5")) {
            // 0xBAA5: TEST RBX,RBX before the crash-prone RBX!=0 path (faults at 0xBAB7
            // on [RBX+8] when RBX is the sentinel 1).
            __try {
                void* rbx = (void*)ep->ContextRecord->Rbx;
                void* rdx = (void*)ep->ContextRecord->Rdx;
                void* rbxp8 = nullptr, *rbxp10 = nullptr;
                __try {
                    if (rbx) { rbxp8  = *(void**)((char*)rbx + 0x08); }
                } __except(EXCEPTION_EXECUTE_HANDLER) { rbxp8 = (void*)0xDEAD0008; }
                __try {
                    if (rbx) { rbxp10 = *(void**)((char*)rbx + 0x10); }
                } __except(EXCEPTION_EXECUTE_HANDLER) { rbxp10 = (void*)0xDEAD0010; }
                Log("       st.baa5: RBX=%p [+0x08]=%p [+0x10]=%p  RDX(RSI)=%p",
                    rbx, rbxp8, rbxp10, rdx);
            } __except (EXCEPTION_EXECUTE_HANDLER) { Log("       st.baa5: (fault)"); }
        } else if (!strcmp(b.tag, "st.b1850")) {
            __try {
                void* rcx = (void*)ep->ContextRecord->Rcx;
                void* rdx = (void*)ep->ContextRecord->Rdx;
                void* r8  = (void*)ep->ContextRecord->R8;
                Log("       st.b1850: resource call: RCX=%p RDX=%p R8=%p", rcx, rdx, r8);
                Log("       st.b1850: RDX(old)=%p vs committed hRes=%p  s_nullRes[+8]=%p",
                    rdx, (void*)g_drawCommittedHRes[0], *(void**)(s_nullRes + 8));
                // One-shot hex dump of the stage binding (RDX) -- the object the clear
                // dispatch at atiumd64+0x53180 actually receives as RCX and reads [+0x10]
                // from.  RCX here is hRes; the binding is what matters downstream.
                static bool s_b1850_dumped = false;
                if (!s_b1850_dumped && rdx && rcx == (void*)g_drawCommittedHRes[0]) {
                    s_b1850_dumped = true;
                    Log("       st.b1850: HEX DUMP stage_binding=%p (rcx=hRes):", rdx);
                    __try {
                        for (int o = 0; o < 0x70; o += 8) {
                            Log("         [+0x%02x] = %p", o, *(void**)((char*)rdx + o));
                        }
                    } __except (EXCEPTION_EXECUTE_HANDLER) { Log("       st.b1850: (dump fault at some offset)"); }
                }
                // fn_1850(new=RCX, old=RDX, r8): when [new+8] and [new+0x10] pass it calls
                // the old-resource clear through the indirect fn ptr at atiumd6a+0x82EA10
                // (rcx=old, rdx=r8, r8d=1).  Resolve that slot so we can see which routine
                // the clear dispatches to and why it never reaches st.uaf (0x12E90F).
                static HMODULE s_a6a = nullptr;
                if (!s_a6a) s_a6a = GetModuleHandleA("atiumd6a.dll");
                if (s_a6a) {
                    void* tgt = *(void**)((char*)s_a6a + 0x82EA10);
                    char w[300];
                    Log("       st.b1850: clear dispatch [a6a+0x82EA10]=%s",
                        tgt ? Where(tgt, w, sizeof w) : "(null)");
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) { Log("       st.b1850: (fault)"); }
        } else if (!strcmp(b.tag, "st.ret244a")) {
            Log("       st.ret244a: vtable CALL at 0x244A returned OK");
            // With the deep-flush recursion broken, the flush epilogue past 0x2499 now
            // runs: at 0x24CF it calls 0x3E240 -> 0xB020, which feeds [p58+0x188] to the
            // handle mapper at [atiumd6a+0x82EA38].  Injecting our hRes there made the
            // mapper return garbage (AV at 0xB051 reading 0x100000011).  Leave the
            // driver's own value in place and just observe, so the epilogue can run.
            if (s_phase == 1 && s_vtblObj && !s_clearFired) {
                __try {
                    void* p58 = *(void**)((char*)s_vtblObj + 0x58);
                    if (p58) {
                        void* old188 = *(void**)((char*)p58 + 0x188);
                        static HMODULE s_a6a3 = nullptr;
                        if (!s_a6a3) s_a6a3 = GetModuleHandleA("atiumd6a.dll");
                        void* mapper = s_a6a3 ? *(void**)((char*)s_a6a3 + 0x82EA38) : nullptr;
                        char w[300];
                        Log("       st.ret244a: BIND observe [vtblObj+0x58+0x188]=%p (NOT injecting hRes=%p); mapper=%s",
                            old188, (void*)g_drawCommittedHRes[0],
                            mapper ? Where(mapper, w, sizeof w) : "(null)");
                    }
                } __except(EXCEPTION_EXECUTE_HANDLER) { Log("       st.ret244a: inject fault"); }
            }
        } else if (!strcmp(b.tag, "clr.dispatch")) {
            Log("       clr.dispatch: RCX=%p RDX=%p R8=%p R9=%p",
                (void*)ep->ContextRecord->Rcx, (void*)ep->ContextRecord->Rdx,
                (void*)ep->ContextRecord->R8, (void*)ep->ContextRecord->R9);
        } else if (!strcmp(b.tag, "clr.inner")) {
            void* r9 = (void*)ep->ContextRecord->R9;
            unsigned r9p10 = 0;
            bool r9IsBait = false;
            // Never touch a fenced bait page from our own instrumentation: the driver's
            // next instruction (cmp dword [r9+0x10],0 at 0x596E7) must be the one that
            // faults, so the FENCE UAF is attributed to the driver, not to this read.
            // Compare page-aligned: R9 is typically the hRes itself (self-patched
            // [hRes+8]), which sits at page_base+8 on its fenced VA page.
            uintptr_t r9page = (uintptr_t)r9 & ~(uintptr_t)0xFFF;
            PoolLock();
            for (int _i = 0; _i < g_fencedCount; _i++)
                if ((uintptr_t)g_fenced[_i].page_base == r9page && !g_fenced[_i].triggered) { r9IsBait = true; break; }
            PoolUnlock();
            if (r9IsBait) {
                Log("       clr.inner: R9=%p IS BAIT (fenced) -- leaving the [R9+0x10] read to the driver", r9);
            } else {
                __try { if (r9) r9p10 = *(unsigned*)((char*)r9 + 0x10); } __except(EXCEPTION_EXECUTE_HANDLER) {}
                Log("       clr.inner: RCX=%p RDX=%p R8=%p R9=%p [R9+0x10]=%u",
                    (void*)ep->ContextRecord->Rcx, (void*)ep->ContextRecord->Rdx,
                    (void*)ep->ContextRecord->R8, r9, r9p10);
            }
        } else if (!strcmp(b.tag, "clr.path2")) {
            Log("       clr.path2: about to call [device_inner+0xD8]: R8=%p",
                (void*)ep->ContextRecord->R8);
        } else if (!strcmp(b.tag, "st.callc0")) {
            __try {
                void* obj = (void*)ep->ContextRecord->Rcx;
                void* vtbl = obj ? *(void**)obj : nullptr;
                void* fn = vtbl ? *(void**)((char*)vtbl + 0xc0) : nullptr;
                char w[300];
                Log("       st.callc0: obj=%p vtbl=%p fn[+0xc0]=%s",
                    obj, vtbl, fn ? Where(fn, w, sizeof w) : "(null)");
                if (s_phase == 1 && !s_clearFired) {
                    s_vtblObj = obj;
                    Log("       st.callc0: BIND - saved s_vtblObj=%p", obj);
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        } else if (!strcmp(b.tag, "st.baef")) {
            Log("       st.baef: RBX=0 path at 0xBAEF taken");
        } else if (!strcmp(b.tag, "st.call38")) {
            __try {
                void* obj = (void*)ep->ContextRecord->Rcx;
                Log("       st.call38: obj=%p vtbl=%p", obj, obj ? *(void**)obj : nullptr);
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        } else if (!strcmp(b.tag, "st.call20")) {
            __try {
                void* obj = (void*)ep->ContextRecord->Rcx;
                void* vtbl = obj ? *(void**)obj : nullptr;
                void* fn = vtbl ? *(void**)((char*)vtbl + 0x20) : nullptr;
                char w[300];
                Log("       st.call20: obj=%p vtbl=%p fn[+0x20]=%s (entering deep flush path)",
                    obj, vtbl, fn ? Where(fn, w, sizeof w) : "(null)");
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
#ifdef D3D9SHIM_DLL
            // The deep flush (atiumd6a:0x1D30, rbp=rdx=channel) calls atiumd64:0x51D80 with
            // rcx=[channel+0x188]; that function dereferences [rcx+0x10] as the resource's
            // backing object and writes [backing+0x1A4]/[+0x1A8].  When the ret244a BIND
            // injection put hRes into the slot, [hRes+0x10] is null (or the sentinel 1 the
            // SNAP INJECT planted) because the driver never allocated backing for the
            // emulated resource, so the write AVs at address 0x1A4.  Install a zeroed,
            // committed stand-in so the driver's own flag-clearing completes.
            __try {
                void* chan2 = (void*)ep->ContextRecord->Rdx;
                void* slot = chan2 ? *(void**)((char*)chan2 + 0x188) : nullptr;
                if (slot && (uintptr_t)slot > 0x10000) {
                    void* backing = *(void**)((char*)slot + 0x10);
                    Log("       st.call20: [chan+0x188]=%p [slot+0x10](backing)=%p", slot, backing);
                    // Only patch slots that hold one of the shim's committed resource
                    // handles -- never a driver-owned object that happens to be there.
                    bool ours = false;
                    for (int _i = 0; _i < 16; _i++)
                        if (slot == (void*)g_drawCommittedHRes[_i] && g_drawCommittedHRes[_i]) { ours = true; break; }
                    if (ours && (uintptr_t)backing < 0x10000) {
                        // Prefer the real device_inner: atiumd64:0x51D80 then clears
                        // [device_inner+0x1A4]/[+0x1A8] exactly as in the unmodified flow
                        // (slot=holder, [holder+0x10]=device_inner) and the stateApply gate
                        // finds its [+0x600] -> [+0x20] chain already live.  Fall back to
                        // the zeroed stand-in (its +0x600 wired to the real holder).
                        void* install = s_realDevInner ? s_realDevInner : (void*)s_resBacking;
                        *(void**)((char*)slot + 0x10) = install;
                        Log("       st.call20: installed backing %p (%s) at [slot %p+0x10]",
                            install, s_realDevInner ? "real device_inner" : "zeroed stand-in", slot);
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) { Log("       st.call20: backing install fault"); }
            // The deep flush at atiumd6a:0x1D30 (called here) never returns to 0x2499
            // (st.ret2496 armed, 0 hits in 931 calls).  It reads [r8+0x1B8]/[r8+0x1C0]
            // and [r9+0x1B8]/[r9+0x1C0] -- the two snapshots' chain links -- before the
            // indirect submit call; a null link AVs at 0x1EC4/0x1EDA into driver SEH.
            // Log the links once per unique pair so the next run can see the culprit.
            static int s_dfDumped = 0;
            if (s_dfDumped < 3) {
                s_dfDumped++;
                __try {
                    void* s1 = (void*)ep->ContextRecord->R8;
                    void* s2 = (void*)ep->ContextRecord->R9;
                    void* l1 = s1 ? *(void**)((char*)s1 + 0x1B8) : nullptr;
                    void* l2 = s2 ? *(void**)((char*)s2 + 0x1B8) : nullptr;
                    Log("       st.call20: deepflush args snap1=%p [+0x1B8]=%p  snap2=%p [+0x1B8]=%p",
                        s1, l1, s2, l2);
                } __except (EXCEPTION_EXECUTE_HANDLER) { Log("       st.call20: (link dump fault)"); }
            }
#endif
        } else if (!strcmp(b.tag, "st.uaf")) {
            __try {
                void* rcx = (void*)ep->ContextRecord->Rcx;
                Log("       st.uaf: ENTERED! RCX=%p (texture-clear fn begins)", rcx);
                Log("ST.UAF FIRED = CLEAR PATH REACHED (old=hRes, new=null transition)");
            } __except(EXCEPTION_EXECUTE_HANDLER) {}
        } else if (!strcmp(b.tag, "st.sub24e0")) {
            Log("       st.sub24e0: command-submit vtable call at 0x24E0");
        } else if (!strcmp(b.tag, "st.ret2496")) {
            Log("       st.ret2496: call at 0x2496 RETURNED eax=%08x", (unsigned)ep->ContextRecord->Rax);
        } else if (!strcmp(b.tag, "st.dfcall")) {
            // atiumd6a:0x1D30+0x1B7: the deep flush's last act is an indirect call
            // through the global fn ptr at atiumd6a+0x82EA28, with rcx=[channel+0x188]
            // and rdx=&record on the stack.  0x2499 never sees a return, so the truth
            // about whether 0x1D30 completes lives here and at st.dfret.
            __try {
                static HMODULE s_a6a2 = nullptr;
                if (!s_a6a2) s_a6a2 = GetModuleHandleA("atiumd6a.dll");
                void* tgt = s_a6a2 ? *(void**)((char*)s_a6a2 + 0x82EA28) : nullptr;
                char w[300];
                Log("       st.dfcall: rcx=%p rdx=%p rsp=%p target=%s",
                    (void*)ep->ContextRecord->Rcx, (void*)ep->ContextRecord->Rdx,
                    (void*)ep->ContextRecord->Rsp,
                    tgt ? Where(tgt, w, sizeof w) : "(null)");
            } __except (EXCEPTION_EXECUTE_HANDLER) { Log("       st.dfcall: (fault)"); }
            // Chain walk (first few calls only): 0x51D80 resolves record+0x48/+0x58 into
            // two objects and re-enters stateApply with them; stateApply's gate reads
            // [obj+0x1B8] again.  If the chain is stale/cyclic the flush recurses
            // forever, which is exactly what "0x2499 never fires" looks like.
            static int s_dfWalk = 0;
            if (s_dfWalk < 3) {
                s_dfWalk++;
                __try {
                    char* rec = (char*)ep->ContextRecord->Rdx;
                    for (int k = 0; k < 2; k++) {
                        char* o = *(char**)(rec + 0x48 + k * 0x10);
                        if (!o) { Log("       st.dfcall: rec[+0x%02x]=null", 0x48 + k * 0x10); continue; }
                        unsigned type = *(unsigned*)(o + 4);
                        void* link = *(void**)(o + 0x1B8);
                        unsigned f1c0 = *(unsigned*)(o + 0x1C0);
                        void* link2 = nullptr;
                        if (link && (uintptr_t)link > 0x10000)
                            __try { link2 = *(void**)((char*)link + 0x1B8); } __except (EXCEPTION_EXECUTE_HANDLER) { link2 = (void*)-1; }
                        Log("       st.dfcall: rec[+0x%02x]=%p type=%u [+0x1B8]=%p [+0x1C0]=%x link[+0x1B8]=%p",
                            0x48 + k * 0x10, o, type, link, f1c0, link2);
                    }
                    static HMODULE s_a64 = nullptr;
                    if (!s_a64) s_a64 = GetModuleHandleA("atiumd64.dll");
                    void* gate = s_a64 ? *(void**)((char*)s_a64 + 0x7F45C0) : nullptr;
                    char w2[300];
                    Log("       st.dfcall: gate target [a64+0x7F45C0]=%s",
                        gate ? Where(gate, w2, sizeof w2) : "(null)");
                } __except (EXCEPTION_EXECUTE_HANDLER) { Log("       st.dfcall: (walk fault)"); }
            }
        } else if (!strcmp(b.tag, "st.dfret")) {
            Log("       st.dfret: deep-flush inner call RETURNED eax=%08x", (unsigned)ep->ContextRecord->Rax);
        } else if (!strcmp(b.tag, "sa.gatechk")) {
            // stateApply+0x24: rbp = [params+0x58] (resolved object A).  The gate call
            // at 0x3034D is skipped when [rbp+0x1B8]==0 -- the recursion base case.
            static int s_gc = 0;
            if (s_gc < 6) {
                s_gc++;
                __try {
                    void* rbp = (void*)ep->ContextRecord->Rbp;
                    void* link = rbp ? *(void**)((char*)rbp + 0x1B8) : nullptr;
                    Log("       sa.gatechk: rbp=%p [rbp+0x1B8]=%p (%s)", rbp, link,
                        link ? "GATE TAKEN -> recursion" : "gate skipped");
                } __except (EXCEPTION_EXECUTE_HANDLER) { Log("       sa.gatechk: (fault)"); }
            }
#ifdef D3D9SHIM_DLL
            // Break the flush recursion.  stateApply is entered two ways: from the
            // recorder's deferred-flush path (legitimate: the gate must fire so the
            // flush runs) and from 0x51D80+0x3AD (atiumd64+0x520E2 return address), the
            // deep flush re-entering stateApply with stale resolved objects whose
            // [+0x1B8] links are only ever cleared by the flush epilogue past
            // atiumd6a:0x2499 -- which never runs because the gate recurses first.
            // Chicken-and-egg.  On the nested entry, hide the stale link so the gate
            // is skipped and the whole chain unwinds for the first time.
            __try {
                static HMODULE s_a64b = nullptr;
                if (!s_a64b) s_a64b = GetModuleHandleA("atiumd64.dll");
                // 5 pushes + sub rsp,0x40 in stateApply's prologue: caller's return
                // address lives at [rsp+0x68] here.
                void* retaddr = *(void**)((char*)ep->ContextRecord->Rsp + 0x68);
                if (s_a64b && g_gcRetSA && retaddr == (void*)((char*)s_a64b + g_gcRetSA)) {
                    void* rbp = (void*)ep->ContextRecord->Rbp;
                    void* old = rbp ? *(void**)((char*)rbp + 0x1B8) : nullptr;
                    if (rbp && old) {
                        *(void**)((char*)rbp + 0x1B8) = nullptr;
                        static int s_unlink = 0;
                        if (s_unlink < 8) {
                            s_unlink++;
                            Log("       sa.gatechk: NESTED stateApply -- unlinked [rbp %p+0x1B8] (was %p) to stop recursion",
                                rbp, old);
                        }
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) { Log("       sa.gatechk: (unlink fault)"); }
#endif
        } else if (!strcmp(b.tag, "gate.call")) {
            __try {
                char w[300];
                void* rax = (void*)ep->ContextRecord->Rax;
                Log("       gate.call: rcx=%p rax=%s rsp=%p", (void*)ep->ContextRecord->Rcx,
                    rax ? Where(rax, w, sizeof w) : "(null)", (void*)ep->ContextRecord->Rsp);
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        } else if (!strcmp(b.tag, "gate.ret")) {
            Log("       gate.ret: flush returned eax=%08x", (unsigned)ep->ContextRecord->Rax);
            // Builds without defer.run (16.2.1: one synchronous stateApply per flush)
            // restart the BIND->UNBIND injection sequence here, once per flush cycle.
            if (g_phaseResetAtGateRet) { s_phase = 0; s_clearFired = false; }
        } else if (!strcmp(b.tag, "sub.resolved")) {
            // 0x51D80+0x7D: rsi/rdi = the two objects resolved from record+0x48/+0x58.
            // stateApply is about to be re-entered with these; their +0x1B8 links decide
            // whether the gate recurses.
            static int s_sr = 0;
            if (s_sr < 6) {
                s_sr++;
                __try {
                    void* rsi = (void*)ep->ContextRecord->Rsi;
                    void* rdi = (void*)ep->ContextRecord->Rdi;
                    void* ls = rsi ? *(void**)((char*)rsi + 0x1B8) : nullptr;
                    void* ld = rdi ? *(void**)((char*)rdi + 0x1B8) : nullptr;
                    Log("       sub.resolved: rsi=%p [+0x1B8]=%p  rdi=%p [+0x1B8]=%p", rsi, ls, rdi, ld);
                } __except (EXCEPTION_EXECUTE_HANDLER) { Log("       sub.resolved: (fault)"); }
            }
        } else if (!strcmp(b.tag, "sub.callSA")) {
            Log("       sub.callSA: 0x51D80 re-enters stateApply (rcx=%p rdx=%p)",
                (void*)ep->ContextRecord->Rcx, (void*)ep->ContextRecord->Rdx);
        } else if (!strcmp(b.tag, "sub.retSA")) {
            Log("       sub.retSA: stateApply returned eax=%08x", (unsigned)ep->ContextRecord->Rax);
        } else if (!strcmp(b.tag, "st.crash64")) {
            Log("       st.crash64: at atiumd64+0x59827 before crash");
        } else if (!strcmp(b.tag, "clear.call")) {
            // atiumd64:0x596D0+0x88: about to call r8=[device_inner+0xD8] with
            // rcx=[device_inner+8], rdx=&record ([rsp+0x20]).  This is the inner
            // clear the fn_1850 dispatch reaches when [hRes+0x10] is non-null.
            __try {
                void* r8fn = (void*)ep->ContextRecord->R8;
                char w[300];
                Log("       clear.call: rcx=%p rdx=%p r8=%s",
                    (void*)ep->ContextRecord->Rcx, (void*)ep->ContextRecord->Rdx,
                    r8fn ? Where(r8fn, w, sizeof w) : "(null)");
            } __except (EXCEPTION_EXECUTE_HANDLER) { Log("       clear.call: (fault)"); }
        } else if (!strcmp(b.tag, "newbuf.chk")) {
            void* rdi = (void*)ep->ContextRecord->Rdi;
            __try { Log("       newbuf: [chunk+0x4E60]=%p [0]=%p", rdi, *(void**)rdi); }
            __except (EXCEPTION_EXECUTE_HANDLER) { Log("       (read fault)"); }
        } else if (!strcmp(b.tag, "chunkinit")) {
            // 0x556D0(device, chunk, ringdesc): the ring descriptor carries the CPU base at +0x30 and byte size
            // at +0x38; +0x28 selects the model (bit 0x100 of chunk+0x30 skips the CPU-pointer fill).
            void* desc = (void*)ep->ContextRecord->R8;
            void* device = (void*)ep->ContextRecord->Rcx;
            __try {
                Log("       chunkinit: chunk=%p desc=%p +0x28=%x +0x2C=%x +0x30(cpu)=%p +0x38(size)=%llx",
                    (void*)ep->ContextRecord->Rdx, desc, *(unsigned*)((char*)desc + 0x28),
                    *(unsigned*)((char*)desc + 0x2C), *(void**)((char*)desc + 0x30),
                    *(unsigned long long*)((char*)desc + 0x38));
                void* settings = *(void**)device;
                Log("       settings=%p +0x214=%08x +0x5434=%08x +0x4CA8=%p dev+0xECC=%08x", settings,
                    *(unsigned*)((char*)settings + 0x214), *(unsigned*)((char*)settings + 0x5434),
                    *(void**)((char*)settings + 0x4CA8), *(unsigned*)((char*)device + 0xECC));
                // The ring size/alignment table the divider reads.
                HexDump("settings+0x2C80", (char*)settings + 0x2C80, 0x260, 0x260);
                HexDump("device+0x2C80", (char*)device + 0x2C80, 0x260, 0x260);
                char w3[300];
                Log("       device+0x128 = %s", Where(*(void**)((char*)device + 0x128), w3, sizeof w3));
            } __except (EXCEPTION_EXECUTE_HANDLER) { Log("       (read fault)"); }
        } else if (!strcmp(b.tag, "chunkinit.fill")) {
            Log("       chunkinit at fill decision: [chunk+0x30]=%08x", (unsigned)ep->ContextRecord->Rbx);
            void* chunk = (void*)ep->ContextRecord->Rbx;
            __try { Log("       chunk+0x30 = %08x", *(unsigned*)((char*)chunk + 0x30)); }
            __except (EXCEPTION_EXECUTE_HANDLER) { Log("       (read fault)"); }
        } else if (!strcmp(b.tag, "pipesel")) {
            Log("       pipesel: pipe=%lu flags=%x", (unsigned long)ep->ContextRecord->Rdx,
                (unsigned)ep->ContextRecord->R8);
            LogFramesFrom(ep->ContextRecord, 4);
        } else if (!strcmp(b.tag, "fill.setup")) {
            // 0x58D94: r8=[rbp-8] (ring CPU base), edx=[rbp] (size) about to go into the record fill.
            uintptr_t rbp = ep->ContextRecord->Rbp;
            __try {
                Log("       fill.setup: [rbp-8](cpu)=%p [rbp](size)=%llx chunk=%p chunk+0x30=%08x",
                    *(void**)(rbp - 8), *(unsigned long long*)rbp, (void*)ep->ContextRecord->Rdi,
                    *(unsigned*)(ep->ContextRecord->Rdi + 0x30));
            } __except (EXCEPTION_EXECUTE_HANDLER) { Log("       (read fault)"); }
        } else if (!strcmp(b.tag, "fill.rec")) {
            // 0x58E27: the inline record fill; skipped when chunk+0x30 bit 0x100 is set.
            __try {
                Log("       fill.rec: rec=%p r8(cpu)=%p edx(size)=%x [chunk+0x30]=%08x",
                    (void*)ep->ContextRecord->Rsi, (void*)ep->ContextRecord->R8, (unsigned)ep->ContextRecord->Rdx,
                    *(unsigned*)(ep->ContextRecord->Rdi + 0x30));
            } __except (EXCEPTION_EXECUTE_HANDLER) { Log("       (read fault)"); }
        } else if (!strcmp(b.tag, "init.gate")) {
            // 0x58DEE: cmp [rsp+24h],0 decides between the full init (0x5556D0) and the inline fill.
            __try {
                Log("       init.gate: [rsp+0x24]=%x esi-path rcx=%p", *(unsigned*)(ep->ContextRecord->Rsp + 0x24),
                    (void*)ep->ContextRecord->Rcx);
            } __except (EXCEPTION_EXECUTE_HANDLER) { Log("       (read fault)"); }
        } else if (!strcmp(b.tag, "init.pre")) {
            // 0x58D1C: rcx = [rsp+0x28] (=esi, the model selector) gates the desc build at 0x58D94.
            Log("       init.pre: [rsp+0x28]=%p", (void*)*(uintptr_t*)(ep->ContextRecord->Rsp + 0x28));
        } else if (!strcmp(b.tag, "init.skip")) {
            Log("       init.skip reached (r14d path)");
        } else if (!strcmp(b.tag, "ringmap")) {
            // 0x58740(device, chunk): allocates and CPU-maps the ring. Its gates read the settings block.
            void* device = (void*)ep->ContextRecord->Rcx;
            __try {
                void* settings = *(void**)device;
                Log("       ringmap: settings+0x5434=%08x settings+0x214=%08x",
                    *(unsigned*)((char*)settings + 0x5434), *(unsigned*)((char*)settings + 0x214));
            } __except (EXCEPTION_EXECUTE_HANDLER) { Log("       (read fault)"); }
            LogFramesFrom(ep->ContextRecord, 3);
        } else if (!strcmp(b.tag, "ringmap.fail")) {
            Log("       ringmap: returning 0x80004005 (no ring allocated)");
        } else if (!strcmp(b.tag, "ringmap.reuse")) {
            // 0x58776, inside 0x58740: rsi is the device; 0x59FB0(chunk) will query device+0xD0.
            void* dev = (void*)ep->ContextRecord->Rsi;
            __try {
                char w[300];
                void* cb = *(void**)((char*)dev + 0xD0);
                Log("       ringmap.reuse: device=%p querycb=%s ctx=%p", dev,
                    cb ? Where(cb, w, sizeof w) : "(null)", *(void**)((char*)dev + 8));
            } __except (EXCEPTION_EXECUTE_HANDLER) { Log("       (read fault)"); }
        } else if (!strcmp(b.tag, "ringdiv")) {
            // 0x6D420(device, desc): computes (caps2+0x2BC << 20) / desc+0x24 -- the divisor is 0 in our runs.
            void* desc = (void*)ep->ContextRecord->Rdx;
            void* device = (void*)ep->ContextRecord->Rcx;
            __try {
                void* settings = *(void**)device;
                void* caps2 = *(void**)((char*)settings + 0x3C90);
                Log("       ringdiv: desc=%p desc+0x24=%08x caps2+0x2BC=%08x", desc,
                    *(unsigned*)((char*)desc + 0x24), *(unsigned*)((char*)caps2 + 0x2BC));
                unsigned* d = (unsigned*)desc;
                Log("       ringdiv desc: %08x %08x %08x %08x %08x %08x %08x %08x", d[0], d[1], d[2], d[3],
                    d[4], d[5], d[6], d[7]);
            } __except (EXCEPTION_EXECUTE_HANDLER) { Log("       (read fault)"); }
            LogFramesFrom(ep->ContextRecord, 4);
        } else if (!strncmp(b.tag, "clear.", 6)) {
            // clear.A uses [rbx+64h]; clear.B/1/2/3 all use [rcx+64h]  (confirmed from au6a-full.asm)
            uintptr_t tgt = !strcmp(b.tag, "clear.A")
                ? ep->ContextRecord->Rbx
                : ep->ContextRecord->Rcx;
            bool hit = false;
            for (auto& d : g_decoys)
                if (tgt >= (uintptr_t)d.block && tgt < (uintptr_t)d.block + 152)
                    { hit = true; break; }
            if (!strcmp(b.tag, "clear.A")) g_clearAHits++;
            // Also read the current value at the write target (the UAF write overwrites it).
            void* curVal = nullptr;
            __try { curVal = *(void**)(tgt + 0x64); } __except(EXCEPTION_EXECUTE_HANDLER) { curVal = (void*)0xDEAD0064; }
            Log("       clear write: target=%p [+0x64]@%p=%p r15=%p %s",
                (void*)tgt, (void*)(tgt + 0x64), curVal, (void*)ep->ContextRecord->R15,
                hit ? "*** DECOY HIT ***" : "not a decoy");
            if (!strcmp(b.tag, "clear.A")) {
                s_clearFired = true;  // stop the UNBIND re-injection loop after the first CLEAR
                Log("       clear.A: MOV [RBX+0x64], R15 about to execute: RBX=%p R15=%p TARGET=%p",
                    (void*)ep->ContextRecord->Rbx, (void*)ep->ContextRecord->R15,
                    (void*)(ep->ContextRecord->Rbx + 0x64));
                Log("CLEAR.A WRITE SITE REACHED - UAF WRITE IMMINENT");
            }
        } else if (!strcmp(b.tag, "relobj")) {
            // 0x13E260: virtual call target that crashes at +0x31 because [rcx+8] = FFFFFFFFFFFFFFFF.
            // rcx = the object (rdi in the function body); dump vtable and key fields to identify it.
            void* obj = (void*)ep->ContextRecord->Rcx;
            void* vtbl = nullptr, *f8 = nullptr, *f10 = nullptr, *f18 = nullptr;
            __try { vtbl = *(void**)obj; } __except(1) {}
            __try { f8   = *(void**)((char*)obj + 0x08); } __except(1) {}
            __try { f10  = *(void**)((char*)obj + 0x10); } __except(1) {}
            __try { f18  = *(void**)((char*)obj + 0x18); } __except(1) {}
            Log("       relobj: rcx=%p vtbl=%p [+8]=%p [+0x10]=%p [+0x18]=%p", obj, vtbl, f8, f10, f18);
            char ww[300];
            if (vtbl) {
                void* s5 = nullptr;
                __try { s5 = *((void**)vtbl + 5); } __except(1) {}
                Log("       relobj: vtbl[5]=%s", Where(s5, ww, sizeof ww));
            }
            Log("       relobj: rdx=%p r8=%p r9=%p rsi=%p rdi=%p",
                (void*)ep->ContextRecord->Rdx, (void*)ep->ContextRecord->R8,
                (void*)ep->ContextRecord->R9,  (void*)ep->ContextRecord->Rsi,
                (void*)ep->ContextRecord->Rdi);
            LogFramesFrom(ep->ContextRecord, 5);
        } else if (!strcmp(b.tag, "allocfactory")) {
            LogFramesFrom(ep->ContextRecord, 5);
        } else if (!strcmp(b.tag, "getwriteptr")) {
            LogFramesFrom(ep->ContextRecord, 5);
        }
        (void)w;
        return;
    }
}

#ifdef D3D9SHIM_DLL
static bool HandleHwWpException(EXCEPTION_POINTERS* ep);
static void ArmWriteWatchpoint(uintptr_t addr, void* freed_obj);
#endif

static LONG WINAPI CrashFilter(EXCEPTION_POINTERS* ep)
{
    DWORD code = ep->ExceptionRecord->ExceptionCode;
#ifdef D3D9SHIM_DLL
    if (code == EXCEPTION_ACCESS_VIOLATION && ep->ExceptionRecord->NumberParameters >= 2) {
        uintptr_t faultAddr = (uintptr_t)ep->ExceptionRecord->ExceptionInformation[1];
        PoolLock();
        FencedBlock* fb = nullptr;
        bool fenceNoise = false;
        void* noisePage = nullptr;
        for (int i = 0; i < g_fencedCount; i++) {
            if (g_fenced[i].triggered) continue;
            if (faultAddr >= (uintptr_t)g_fenced[i].page_base &&
                faultAddr <  (uintptr_t)g_fenced[i].page_base + 4096) {
                // Heap pages are shared: a fault OUTSIDE the freed block's extent is
                // another (still-live) allocation on the same page -- heap noise, not a
                // UAF.  Only a fault inside [obj_ptr, obj_ptr+obj_size) counts.
                uintptr_t o = (uintptr_t)g_fenced[i].obj_ptr;
                if (faultAddr >= o && faultAddr < o + g_fenced[i].obj_size) {
                    fb = &g_fenced[i];
                    fb->triggered = true;
                    break;
                }
                fenceNoise = true;
                noisePage = g_fenced[i].page_base;
            }
        }
        PoolUnlock();
        if (fenceNoise && !fb) {
            // Restore access so the process can continue, but do not report this as a
            // FENCE UAF: it is not the freed object being touched.
            Log("fence-noise: fault_addr=%p on fenced page %p (outside freed extent; access restored)",
                (void*)faultAddr, noisePage);
            DWORD old;
            VirtualProtect(noisePage, 4096, PAGE_READWRITE, &old);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        if (fb) {
            uintptr_t rip = ep->ContextRecord->Rip;
            HMODULE hmod = nullptr;
            GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                               GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               (LPCSTR)rip, &hmod);
            char modName[MAX_PATH] = "?";
            if (hmod) GetModuleFileNameA(hmod, modName, sizeof(modName));
            uintptr_t rva = rip - (uintptr_t)hmod;
            // Heap recycling: a fenced block went back to the heap at DestroyResource, and
            // the heap hands its memory out again.  ntdll heap code (carving the new
            // block) or our own shim (heap hooks / BP handlers) touching the page means
            // the block has been REUSED -- the new owner's accesses are legitimate, so
            // disarm the entry rather than reporting a UAF.  Only a fault from another
            // module (the driver) inside the freed extent is a stale-reference candidate.
            if (strstr(modName, "ntdll.dll")) {
                Log("fence-recycle: fault_addr=%p freed_obj=%p from %s+0x%llx -- block reused, disarmed",
                    (void*)faultAddr, fb->obj_ptr, modName, (unsigned long long)rva);
                DWORD old;
                VirtualProtect(fb->page_base, 4096, PAGE_READWRITE, &old);
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            if (strstr(modName, "d3d9.dll")) {
                // Our own instrumentation touched the fenced block (a diagnostic read
                // or the stateApply self-ref patch).  Disarming here would un-fence the
                // page BEFORE the driver's stale access, and the real UAF would never
                // be seen -- exactly what happened to the STILL BOUND pump runs.  All
                // shim touches of resource memory are __try-protected, so pass the
                // fault to the shim's own SEH and keep the page fenced.
                Log("fence-shim: fault_addr=%p freed_obj=%p from %s+0x%llx -- page KEPT fenced",
                    (void*)faultAddr, fb->obj_ptr, modName, (unsigned long long)rva);
                return EXCEPTION_CONTINUE_SEARCH;
            }
            Log("*** FENCE UAF: fault_addr=%p freed_obj=%p from %s+0x%llx (rip=%p)",
                (void*)faultAddr, fb->obj_ptr,
                modName, (unsigned long long)rva, (void*)rip);
            DWORD old;
            VirtualProtect(fb->page_base, 4096, PAGE_READWRITE, &old);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        // The fakeInner VirtualAlloc page (fenced to PAGE_NOACCESS on Release) is not in
        // g_fenced; catch its UAF fault the same way so it logs instead of crashing.
        if (!fb && g_wpInnerPtr) {
            uintptr_t page = (uintptr_t)g_wpInnerPtr & ~(uintptr_t)0xFFF;
            if (faultAddr >= page && faultAddr < page + 4096) {
                uintptr_t rip = ep->ContextRecord->Rip;
                HMODULE hmod = nullptr;
                GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                   GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                   (LPCSTR)rip, &hmod);
                char modName[MAX_PATH] = "?";
                if (hmod) GetModuleFileNameA(hmod, modName, sizeof(modName));
                uintptr_t rva = rip - (uintptr_t)hmod;
                Log("*** FENCE UAF: fault_addr=%p freed_obj=%p from %s+0x%llx (rip=%p)",
                    (void*)faultAddr, g_wpInnerPtr,
                    modName, (unsigned long long)rva, (void*)rip);
                DWORD old;
                VirtualProtect((void*)page, 4096, PAGE_READWRITE, &old);
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }
#endif
    if (code == STATUS_BREAKPOINT) {
        uintptr_t at = (uintptr_t)ep->ExceptionRecord->ExceptionAddress;
        BpsLock();
        for (size_t i = 0; i < g_bpsCount; i++)
            if (g_bps[i].addr == at) { OnBp(ep); BpsUnlock(); return EXCEPTION_CONTINUE_EXECUTION; }
        // An int3 at an armed address that matches no entry means the table was corrupted
        // (previously: the heap vector's buffer sat in the 152-byte class and the driver's
        // stray write zeroed it) — say so rather than passing silently.
        char wb[300];
        Log("!! unmatched int3 at %s (g_bps entries: %zu)", Where((void*)at, wb, sizeof wb),
            g_bpsCount);
        for (size_t i = 0; i < g_bpsCount; i++)
            Log("!!   g_bps: %s at %p (orig %02x)", g_bps[i].tag, (void*)g_bps[i].addr,
                g_bps[i].orig);
        BpsUnlock();
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if (code == EXCEPTION_SINGLE_STEP) {
#ifdef D3D9SHIM_DLL
        // A hardware watchpoint from the pool hook (legacy9_pool.cpp) also arrives as a
        // single-step; let it claim the exception first when no bp re-arm is pending.
        if (HandleHwWpException(ep) && !g_rearm)
            return EXCEPTION_CONTINUE_EXECUTION;
#endif
        if (g_rearm) {
            uintptr_t at = g_rearm;
            g_rearm = 0;
            BpsLock();
            for (size_t i = 0; i < g_bpsCount; i++)
                if (g_bps[i].addr == at) {
                    DWORD old;
                    VirtualProtect((void*)at, 1, PAGE_EXECUTE_READWRITE, &old);
                    *(unsigned char*)at = 0xCC;
                    VirtualProtect((void*)at, 1, old, &old);
                }
            BpsUnlock();
            ep->ContextRecord->EFlags &= ~0x100u;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    char w[300];
    if ((code >> 16) == 0x4001 &&
        !(ep->ExceptionRecord->ExceptionFlags & EXCEPTION_NONCONTINUABLE)) {
        // D3D/debugger notification: swallow silently so the process doesn't terminate.
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (code < 0xC0000000 || code == 0xE06D7363) {
        Log("!! non-error exception %08lx at %s", code, Where(ep->ExceptionRecord->ExceptionAddress, w, sizeof w));
        return EXCEPTION_CONTINUE_SEARCH;
    }
    Log("!! exception %08lx at %s", code, Where(ep->ExceptionRecord->ExceptionAddress, w, sizeof w));
    if (code == EXCEPTION_ACCESS_VIOLATION && ep->ExceptionRecord->NumberParameters >= 2)
        Log("!!   %s address %p", ep->ExceptionRecord->ExceptionInformation[0] ? "writing" : "reading",
            (void*)ep->ExceptionRecord->ExceptionInformation[1]);
    void* st[12] = {};
    USHORT n = 0;
    __try { n = RtlCaptureStackBackTrace(0, 12, st, nullptr); } __except(EXCEPTION_EXECUTE_HANDLER) {}
    for (USHORT i = 0; i < n; i++) Log("!!   frame %s", Where(st[i], w, sizeof w));

    // At the reserve fault (emit helper, atiumd64+0x5447bf) rcx still holds the command-buffer manager (the
    // reserve `this`) and rdx the emit context's buffer-state field, because the reserve NULL-return path leaves
    // both registers alone. Dumping the manager's fields here says which NULL condition fired.
    HMODULE drv = nullptr;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCSTR)ep->ExceptionRecord->ExceptionAddress, &drv) && drv) {
        uintptr_t rva = (uintptr_t)ep->ExceptionRecord->ExceptionAddress - (uintptr_t)drv;
        if (rva == 0x36c95 && ep->ContextRecord) {
            // Crash at add [rbx], rax inside function 0x46C30.
            // rbx = rcx_arg+8, so rcx = rbx-8. Log to find what returned 0 from vtable[7].
            CONTEXT& cx = *ep->ContextRecord;
            Log("!!   0x36c95: rcx=%p rdx=%p rbx=%p r14=%p r15=%p r8=%p rax=%p rsi=%p",
                (void*)cx.Rcx, (void*)cx.Rdx, (void*)cx.Rbx, (void*)cx.R14,
                (void*)cx.R15, (void*)cx.R8, (void*)cx.Rax, (void*)cx.Rsi);
            // rbx == rcx_to_0x46C30 + 8 (from lea rbx,[rcx+8] inside 0x46C30), so rcx_to_0x46C30 = rbx-8
            Log("!!   0x36c95: rcx_arg_to_0x46C30=%p (= rbx-8)", (void*)(cx.Rbx - 8));
            // Log r14's vtable to identify the type (slot 7 returned 0 → rcx=0 → crash)
            if (cx.R14) {
                void* r14_vtbl = nullptr;
                __try { r14_vtbl = *(void**)cx.R14; } __except(1) {}
                void* r14_vtbl7 = nullptr;
                if (r14_vtbl) { __try { r14_vtbl7 = *((void**)r14_vtbl + 7); } __except(1) {} }
                // Also dump the first 10 slots of r14's vtable so we can find which driver type this is
                Log("!!   0x36c95: r14=%p vtbl=%p vtbl[7]=%p", (void*)cx.R14, r14_vtbl, r14_vtbl7);
                for (int _si = 0; _si < 10; _si++) {
                    void* slot = nullptr;
                    if (r14_vtbl) { __try { slot = *((void**)r14_vtbl + _si); } __except(1) {} }
                    Log("!!   0x36c95:   r14->vtbl[%d]=%p", _si, slot);
                }
                // Also dump [r14+0x40] and [r14+0x1B8] to compare with stateApply log
                void* r14_40 = nullptr, *r14_1b8 = nullptr;
                __try { r14_40  = *(void**)((char*)cx.R14 + 0x40);  } __except(1) {}
                __try { r14_1b8 = *(void**)((char*)cx.R14 + 0x1B8); } __except(1) {}
                Log("!!   0x36c95: r14[+0x40]=%p r14[+0x1B8]=%p", r14_40, r14_1b8);
            }
            // Unwind one frame to get caller's r14 (the object on which vtable[7] was called)
            CONTEXT ctx2 = cx;
            UINT64 imgBase2 = 0;
            PRUNTIME_FUNCTION fe2 = RtlLookupFunctionEntry(ctx2.Rip, &imgBase2, nullptr);
            if (fe2) {
                UINT64 est2 = 0; PVOID h2 = nullptr, nv2 = nullptr;
                KNONVOLATILE_CONTEXT_POINTERS nvp2 = {};
                RtlVirtualUnwind(UNW_FLAG_NHANDLER, imgBase2, ctx2.Rip, fe2, &ctx2, &nv2, &est2, &nvp2);
                char fw2[300];
                Log("!!   0x36c95: caller=%s r14=%p rcx=%p rdx=%p",
                    Where((void*)ctx2.Rip, fw2, sizeof fw2), (void*)ctx2.R14, (void*)ctx2.Rcx, (void*)ctx2.Rdx);
            }
        }
        // The cleanup-path and [channel+0x10] crash fixups that used to live here were removed
        // with the fake channel/state block: a crash in the driver now always means the harness
        // failed to supply something real, and must be reported rather than steered around.
        if ((rva == 0x12cb06 || rva == 0x12cb23) && ep->ContextRecord) {
            // Crash inside flush — dump all GP regs to find null source.
            CONTEXT& cx = *ep->ContextRecord;
            Log("!!   flush+0x%x: rax=%p rbx=%p rcx=%p rdx=%p", rva - 0x12C950,
                (void*)cx.Rax,(void*)cx.Rbx,(void*)cx.Rcx,(void*)cx.Rdx);
            Log("!!   flush+0x%x: rsi=%p rdi=%p r8=%p r9=%p r10=%p r11=%p r12=%p r13=%p r14=%p r15=%p",
                rva - 0x12C950,
                (void*)cx.Rsi,(void*)cx.Rdi,(void*)cx.R8,(void*)cx.R9,
                (void*)cx.R10,(void*)cx.R11,(void*)cx.R12,(void*)cx.R13,(void*)cx.R14,(void*)cx.R15);
        }
        if (rva == 0x3bfaa && ep->ContextRecord) {
            // Crash at selector 0x4BFA0+0xA — reading [rcx+0xB0] where rcx is the texture resource.
            // rcx = 0 means the caller passed a null texture slot from the state block.
            // Dump rcx and the caller's return address to identify which state-block slot is null.
            CONTEXT& cx = *ep->ContextRecord;
            Log("!!   0x3bfaa: rcx=%p (texture resource arg — null means empty slot)",
                (void*)cx.Rcx);
            // Unwind one frame to get the flush caller's context (the call instruction address
            // tells us which slot offset it passed).
            CONTEXT ctx2 = cx;
            UINT64 ib2 = 0;
            PRUNTIME_FUNCTION fe2 = RtlLookupFunctionEntry(ctx2.Rip, &ib2, nullptr);
            if (fe2) {
                UINT64 est2 = 0; PVOID h2 = nullptr; KNONVOLATILE_CONTEXT_POINTERS nv2 = {};
                RtlVirtualUnwind(UNW_FLAG_NHANDLER, ib2, ctx2.Rip, fe2, &ctx2, &h2, &est2, &nv2);
                char fw[300];
                Log("!!   0x3bfaa: caller=%s rcx=%p rdx=%p r8=%p rbx=%p r12=%p r13=%p r14=%p r15=%p",
                    Where((void*)ctx2.Rip, fw, sizeof fw), (void*)ctx2.Rcx, (void*)ctx2.Rdx, (void*)ctx2.R8,
                    (void*)ctx2.Rbx, (void*)ctx2.R12, (void*)ctx2.R13, (void*)ctx2.R14, (void*)ctx2.R15);
                // Check non-volatile registers — the state block this pointer is typically in r14 or rbx.
                void* sb_candidate = nullptr;
                if ((ULONG_PTR)ctx2.R14 >= 0x1000 && (ULONG_PTR)ctx2.R14 <= 0x7FF000000000ULL)
                    sb_candidate = (void*)ctx2.R14;
                else if ((ULONG_PTR)ctx2.Rbx >= 0x1000 && (ULONG_PTR)ctx2.Rbx <= 0x7FF000000000ULL)
                    sb_candidate = (void*)ctx2.Rbx;
                if (sb_candidate) {
                    Log("!!   0x3bfaa: sb_candidate=%p [+0x20]=%08x [+0x28]=%p [+0x40]=%p [+0x50]=%p",
                        sb_candidate,
                        *(unsigned*)((char*)sb_candidate + 0x20),
                        *(void**)((char*)sb_candidate + 0x28),
                        *(void**)((char*)sb_candidate + 0x40),
                        *(void**)((char*)sb_candidate + 0x50));
                    Log("!!   0x3bfaa: [+0x60]=%p [+0x68]=%p [+0x88]=%p [+0x98]=%p [+0xA8]=%p [+0xB8]=%p",
                        *(void**)((char*)sb_candidate + 0x60),
                        *(void**)((char*)sb_candidate + 0x68),
                        *(void**)((char*)sb_candidate + 0x88),
                        *(void**)((char*)sb_candidate + 0x98),
                        *(void**)((char*)sb_candidate + 0xA8),
                        *(void**)((char*)sb_candidate + 0xB8));
                }
            }
        }
        if (rva == 0x12ca04 && ep->ContextRecord) {
            // Crash at flush+0xB4 (atiumd6a:0x13CA04). Dump all GP regs to identify the stale pointer.
            CONTEXT& cx = *ep->ContextRecord;
            Log("!!   0x12ca04: rax=%p rbx=%p rcx=%p rdx=%p",
                (void*)cx.Rax,(void*)cx.Rbx,(void*)cx.Rcx,(void*)cx.Rdx);
            Log("!!   0x12ca04: rsi=%p rdi=%p r8=%p r9=%p r10=%p r11=%p r12=%p r13=%p r14=%p r15=%p",
                (void*)cx.Rsi,(void*)cx.Rdi,(void*)cx.R8,(void*)cx.R9,
                (void*)cx.R10,(void*)cx.R11,(void*)cx.R12,(void*)cx.R13,(void*)cx.R14,(void*)cx.R15);
            // Identify the bad pointer by checking which register ~equals the read target.
            // Also dump rcx as a likely 'this' and what fields it has.
            if (cx.Rcx) {
                void* f0=nullptr,*f8=nullptr,*f10=nullptr,*f18=nullptr,*f20=nullptr,*f28=nullptr;
                __try { f0  = *(void**)cx.Rcx; } __except(1) {}
                __try { f8  = *(void**)((char*)cx.Rcx+0x08); } __except(1) {}
                __try { f10 = *(void**)((char*)cx.Rcx+0x10); } __except(1) {}
                __try { f18 = *(void**)((char*)cx.Rcx+0x18); } __except(1) {}
                __try { f20 = *(void**)((char*)cx.Rcx+0x20); } __except(1) {}
                __try { f28 = *(void**)((char*)cx.Rcx+0x28); } __except(1) {}
                Log("!!   0x12ca04: rcx=%p [+0]=%p [+8]=%p [+0x10]=%p [+0x18]=%p [+0x20]=%p [+0x28]=%p",
                    (void*)cx.Rcx,f0,f8,f10,f18,f20,f28);
            }
            if (cx.Rdi) {
                void* f0=nullptr,*f8=nullptr,*f10=nullptr,*f18=nullptr;
                __try { f0  = *(void**)cx.Rdi; } __except(1) {}
                __try { f8  = *(void**)((char*)cx.Rdi+0x08); } __except(1) {}
                __try { f10 = *(void**)((char*)cx.Rdi+0x10); } __except(1) {}
                __try { f18 = *(void**)((char*)cx.Rdi+0x18); } __except(1) {}
                Log("!!   0x12ca04: rdi=%p [+0]=%p [+8]=%p [+0x10]=%p [+0x18]=%p",
                    (void*)cx.Rdi,f0,f8,f10,f18);
            }
        }
        if (rva == 0x12e291 && ep->ContextRecord) {
            // Crash at mov rax,[rcx] inside function 0x13E260 — rcx=[rdi+8] = -1.
            CONTEXT& cx = *ep->ContextRecord;
            Log("!!   0x12e291: rcx=%p rdi=%p rsi=%p r8=%p r9=%p", (void*)cx.Rcx, (void*)cx.Rdi,
                (void*)cx.Rsi, (void*)cx.R8, (void*)cx.R9);
            void* rdi = (void*)cx.Rdi;
            if (rdi) {
                void* dv = nullptr, *d8 = nullptr, *d10 = nullptr, *d18 = nullptr, *d20 = nullptr;
                __try { dv  = *(void**)rdi; } __except(1) {}
                __try { d8  = *(void**)((char*)rdi + 0x08); } __except(1) {}
                __try { d10 = *(void**)((char*)rdi + 0x10); } __except(1) {}
                __try { d18 = *(void**)((char*)rdi + 0x18); } __except(1) {}
                __try { d20 = *(void**)((char*)rdi + 0x20); } __except(1) {}
                Log("!!   rdi=%p vtbl=%p [+8]=%p [+0x10]=%p [+0x18]=%p [+0x20]=%p", rdi, dv, d8, d10, d18, d20);
                char w2[300]; if (dv) {
                    for (int si = 0; si < 8; si++) {
                        void* slot = nullptr; __try { slot = *((void**)dv + si); } __except(1) {}
                        Log("!!   rdi->vtbl[%d]=%s", si, Where(slot, w2, sizeof w2));
                    }
                }
            }
        }
        if (rva == 0x5447bf && ep->ContextRecord) {
            // reserve tail-jumps to the engine's acquire callback (engine+0x88), so the fault-time rcx/rdx are
            // the callback's, not reserve's. The emit context M is r14 in the caller's frame (atiumd64+0x531016);
            // unwind from the fault into that frame to recover it.
            CONTEXT ctx2 = *ep->ContextRecord;
            UINT64 imgBase = 0;
            if (RtlLookupFunctionEntry(ctx2.Rip, &imgBase, nullptr)) {
                UINT64 establisher = 0;
                PVOID handler = nullptr;
                PVOID nv = nullptr;
                KNONVOLATILE_CONTEXT_POINTERS nvp = {};
                while (ctx2.Rip) {
                    PRUNTIME_FUNCTION fe = RtlLookupFunctionEntry(ctx2.Rip, &imgBase, nullptr);
                    if (!fe) break;
                    RtlVirtualUnwind(UNW_FLAG_NHANDLER, imgBase, ctx2.Rip, fe, &ctx2, &nv, &establisher, &nvp);
                    char fw[300];
                    Log("!!   unwind: rip=%s r14=%p", Where((void*)ctx2.Rip, fw, sizeof fw), (void*)ctx2.R14);
                    uintptr_t frva = ctx2.Rip - (uintptr_t)drv;
                    if (frva >= 0x530000 && frva <= 0x532000 && ctx2.R14) {
                        uintptr_t m = ctx2.R14;
                        __try {
                            void* eng = *(void**)(m + 0x40C0);
                            void* st0 = *(void**)(m + 0x40D0);
                            void* st1 = *(void**)(m + 0x40E0);
                            Log("!!   M=%p manager(engine)=%p M+0x40D0=%p M+0x40E0=%p", (void*)m, eng, st0, st1);
                            char w2[300];
                            Log("!!   engine: +0x30=%p +0x48=%p +0x58=%p +0x68=%p +0x88=%s",
                                *(void**)((char*)eng + 0x30), *(void**)((char*)eng + 0x48),
                                *(void**)((char*)eng + 0x58), *(void**)((char*)eng + 0x68),
                                Where(*(void**)((char*)eng + 0x88), w2, sizeof w2));
                            Log("!!   engine: +0x340(cur)=%p +0x348(remaining)=%08x +0x588=%p +0x590=%p",
                                *(void**)((char*)eng + 0x340), *(unsigned*)((char*)eng + 0x348),
                                *(void**)((char*)eng + 0x588), *(void**)((char*)eng + 0x590));
                            if (st0)
                                Log("!!   *bufstate: [0]=%p [1]=%p [2]=%p", *(void**)st0,
                                    *(void**)((char*)st0 + 8), *(void**)((char*)st0 + 0x10));
                            // The acquire callback's chunk object: ctx->[0x10], with the CPU write pointer at
                            // +0x0 and the remaining-dword count at +0x18.
                            void* chunk = *(void**)((char*)st0 + 0x10);
                            if (chunk) {
                                Log("!!   chunk=%p [0](cur)=%p [1]=%p [0x10]=%p +0x18(rem)=%08x", chunk,
                                    *(void**)chunk, *(void**)((char*)chunk + 8),
                                    *(void**)((char*)chunk + 0x10), *(unsigned*)((char*)chunk + 0x18));
                                Log("!!   chunk: +0x20=%p +0x28=%p +0x30=%08x +0x70=%08x +0x74=%08x",
                                    *(void**)((char*)chunk + 0x20), *(void**)((char*)chunk + 0x28),
                                    *(unsigned*)((char*)chunk + 0x30), *(unsigned*)((char*)chunk + 0x70),
                                    *(unsigned*)((char*)chunk + 0x74));
                                void* c28 = *(void**)((char*)chunk + 0x28);
                                void* c4e60 = *(void**)((char*)chunk + 0x4E60);
                                Log("!!   chunk: +0x24=%08x +0x5C=%08x +0x4BB0=%08x +0x5394=%08x +0x28->%p +0x4E60->%p",
                                    *(unsigned*)((char*)chunk + 0x24), *(unsigned*)((char*)chunk + 0x5C),
                                    *(unsigned*)((char*)chunk + 0x4BB0), *(unsigned*)((char*)chunk + 0x5394),
                                    c4e60 ? *(void**)c4e60 : nullptr, c4e60);
                            }
                        } __except (EXCEPTION_EXECUTE_HANDLER) {
                            Log("!!   (a field read faulted)");
                        }
                        break;
                    }
                }
            }
        }
    }
    static LONG once = 0;
    if (!InterlockedExchange(&once, 1)) {
        Checkpoint("at crash");
        PrintSizeHistogram();
        if (g_workloadDone) {
            // Teardown crash: main thread will never reach the normal SUMMARY path.
            Log("SUMMARY (early-exit): decoy hits=%zu (%zu decoys)",
                g_decoyHits, g_decoys.size());
            Log("PROBE DONE (early-exit: unhandled crash during teardown)");
            // (WriteFile is unbuffered; no fflush needed)
        }
    }
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
#ifdef D3D9SHIM_DLL
    if (g_inCreateResource) {
        // Driver alloc during pfnCreateResource: give it a private VA region instead
        // of an LFH heap block, so the Release-time fence faults only stale references
        // to THIS allocation.  Recorded in g_createResourceAllocs as before (original
        // size); census tracking is skipped -- the block never enters the heap.
        SIZE_T vaSize = ((size ? size : 1) + 4095) & ~(SIZE_T)4095;
        void* p = VirtualAlloc(nullptr, vaSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!p) return nullptr;
        if (g_vmAllocsCount < 256)
            g_vmAllocs[g_vmAllocsCount++] = VmAlloc{ p, size, false };
        if (g_createResourceAllocsCount < 32)
            g_createResourceAllocs[g_createResourceAllocsCount++] = DriverAlloc{ p, size };
        return p;
    }
#endif
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
#ifdef D3D9SHIM_DLL
    if (g_inCreateResource && g_createResourceAllocsCount < 32)
        g_createResourceAllocs[g_createResourceAllocsCount++] = DriverAlloc{ p, size };
#endif
    return p;
}

static BOOL WINAPI Hook_HeapFree(HANDLE heap, DWORD flags, LPVOID p)
{
    if (!p) return TRUE;
#ifdef D3D9SHIM_DLL
    // VA-backed driver alloc (private page from the CreateResource redirect): never
    // hand it to HeapFree, and do NOT VirtualFree it either -- Release fences the
    // still-committed page after pfnDestroyResource.  Leaked by design (harness).
    for (int _va = 0; _va < g_vmAllocsCount; _va++)
        if (g_vmAllocs[_va].ptr == p) return TRUE;
#endif
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
#ifdef D3D9SHIM_DLL
        void* inner48 = nullptr;
        __try { inner48 = *(void**)((char*)p + 0x48); } __except(EXCEPTION_EXECUTE_HANDLER) {}
        if (inner48 && (uintptr_t)inner48 > 0x10000) {
            Log("  heap-free 152b: inner=%p -> arming watchpoint on inner+0x64", inner48);
            ArmWriteWatchpoint((uintptr_t)inner48 + 0x64, p);
        }
#endif
    }
    if (known && l.zoned) {
        CheckZone(p, l, "on free");
        return HeapFree(heap, flags, (unsigned char*)p - RZ);
    }
    return HeapFree(heap, flags, p);
}

static SIZE_T WINAPI Hook_HeapSize(HANDLE heap, DWORD flags, LPCVOID p)
{
#ifdef D3D9SHIM_DLL
    for (int _va = 0; _va < g_vmAllocsCount; _va++)
        if (g_vmAllocs[_va].ptr == p) return g_vmAllocs[_va].size;
#endif
    EnterCriticalSection(&g_cs);
    auto it = g_live.find((void*)p);
    bool zoned = it != g_live.end() && it->second.zoned;
    SIZE_T size = zoned ? it->second.size : 0;
    LeaveCriticalSection(&g_cs);
    return zoned ? size : HeapSize(heap, flags, p);
}

static LPVOID WINAPI Hook_HeapReAlloc(HANDLE heap, DWORD flags, LPVOID p, SIZE_T size)
{
#ifdef D3D9SHIM_DLL
    for (int _va = 0; _va < g_vmAllocsCount; _va++)
        if (g_vmAllocs[_va].ptr == p) {
            // VA-backed driver alloc: real HeapReAlloc would fail on the non-heap
            // pointer.  Reallocate as a fresh private page and keep both tracking
            // tables pointing at the new address.
            if (flags & HEAP_REALLOC_IN_PLACE_ONLY) return nullptr;
            SIZE_T vaSize = ((size ? size : 1) + 4095) & ~(SIZE_T)4095;
            void* q = VirtualAlloc(nullptr, vaSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!q) return nullptr;
            SIZE_T oldSz = g_vmAllocs[_va].size;
            memcpy(q, p, oldSz < size ? oldSz : size);
            g_vmAllocs[_va] = VmAlloc{ q, size, false };
            for (int _ca = 0; _ca < g_createResourceAllocsCount; _ca++)
                if (g_createResourceAllocs[_ca].ptr == p) {
                    g_createResourceAllocs[_ca] = DriverAlloc{ q, size };
                    break;
                }
            return q;
        }
#endif
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

#include "../lib/heap_scan.h"

static size_t g_signatureHits = 0;
static size_t g_victimsSeen = 0;
static size_t g_lastNearby = 0; // driver blocks within 4 strides of a vector-shaped block, at the last checkpoint

static void ScanHeapsForSignature(const char* when)
{
    HANDLE heaps[64];
    DWORD nheaps = GetProcessHeaps(64, heaps);
    if (nheaps > 64) nheaps = 64;
    size_t inClass = 0, victims = 0, sigs = 0;

    for (DWORD i = 0; i < nheaps; i++) {
        if (!HeapLock(heaps[i])) continue;
        bool ok = WalkOneHeap(heaps[i], &inClass, &victims, &sigs);
        if (ok) HeapUnlock(heaps[i]); // skip unlock if heap walk crashed; heap metadata is suspect
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
        // The displacement is from the vector-shaped block's start to the damaged bytes at its +0x64, measured
        // in the driver block's frame: 0x64 - (victim - driver). Printed in hex, which is how the offsets in
        // this investigation are written.
        long long disp = 0x64 - nearest;
        Log("    adjacency: driver block %p (from %s) is %+lld bytes (%+.2f strides) from vector-shaped block %p;"
            " a write at %s0x%llx from the driver block's start would land on that block's damaged bytes",
            b.first, Where(b.second, w, sizeof w), nearest, (double)nearest / (double)g_stride, at,
            disp < 0 ? "-" : "+", (unsigned long long)(disp < 0 ? -disp : disp));
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
static bool g_kmtFake    = false;  // --kmt-fake: return STATUS_SUCCESS with plausible fake output (no real GPU needed)
static bool g_bpClear = false;    // --bp-clear: arm int3 at every atiumd6a +0x64 write site; logs rcx at each hit
static bool g_forceFlush = false; // --force-flush: set [device+0x47B0]=1 before each draw to prod the deferred flush path
static ULONG_PTR __stdcall StubRet0() { return 0; }
static ULONG_PTR __stdcall StubRet1() { return 1; }

// State vtable[10] (offset +0x50): return a pointer to a struct where [+0x0]==1.
// atiumd6a:0x2180 calls [state_vtable+0x50], then checks [result+0]==1 at +0x1229F.
// Without this, StubRet0 returns null and [0] dereferences immediately.
static ULONG_PTR s_fakeStateObj[4] = { 1, 0, 0, 0 };
static ULONG_PTR __stdcall StubRetFakeStateObj() { return (ULONG_PTR)s_fakeStateObj; }
static ULONG_PTR __stdcall StubRetFakeResource()  { return (ULONG_PTR)s_fakeResource; }

// vtable slot 23 (offset +0xB8) on s_fakeSb80: 0x128680 calls it with rdx = an out-struct
// on its own stack, then reads object pointers from [out+0x20] and [out+0x28] and calls
// vtable slots on them.  A plain StubRet0 leaves those stack slots uninitialised (crash at
// 0x1287a8, "mov r8,[rbx]").  Fill both with s_fakeSb80Out, whose vtable is s_stubVtbl
// (all StubRet0), so the follow-on calls return 0 without crashing.
static ULONG_PTR __stdcall StubFillSb80Out(ULONG_PTR, ULONG_PTR out, ULONG_PTR, ULONG_PTR) {
    *(void**)(out + 0x20) = s_fakeSb80Out;
    *(void**)(out + 0x28) = s_fakeSb80Out;
    return 0;
}

// s_fakeChanAccumBuf: destination buffer for the per-frame accumulate call
// (atiumd6a:0x4A400 calls fake_channel->vtable[7] to get this pointer, then passes
// it as rcx to 0x46C30 which writes 11 qwords of accumulated deltas into [rcx+8..+88]).
static uint8_t s_fakeChanAccumBuf[128];

// s_fakeSb80: sub-object wired at [s_fakeSb+0x80] and [s_fakeChannel+0x80].
// Three sites read a null [arg+0x80] and dereference it as a C++ object:
//   atiumd6a:0x128680+0xD3  (rva 0x118753): mov rax,[r14]  r14=[rsi+0x80]
//   atiumd6a:0x12A420+0xD3  (rva 0x11a4f3): mov rax,[r14]  r14=[rsi+0x80]
//   atiumd6a:0x12CAD0+0xCF  (rva 0x11cb9f): mov rax,[r15]  r15=[r14+0x80]
// With the sub-object provided, 0x128680 calls vtable slot 4 and early-exits (return 0)
// unless it returns 1.  The VEH forced-return these replace handed back rax=1, so
// slot 4 = StubRet1 to preserve that behaviour.
// (s_fakeSb80 and s_fakeSb80Vtbl are forward-declared near the top of the file.)
// The flush also passes [stateblock+0x80] to the selector 0x4BFA0, which reads
// [s_fakeSb80+0xB0] and returns s_fakeSb80+0x00/+0x30/+0x60 as a C++ object; the
// object must therefore be 0x100 bytes with the vtable at all three offsets and a
// valid selector dword at +0xB0 (2, same trial value as s_fakeResource).

// s_fakeResource: minimal fake texture-resource struct placed at s_fakeSb[+0x88] (and +0x98,
// +0x28 etc.) so the bound-resource selector 0x4BFA0 doesn't crash reading [null+0xB0].
// Layout: [+0xB0]=2 → selector returns sub-object (tentative; adjust as we learn more).
// Inner-object pointer at +0x48, +0x78, +0xA8 to cover all three return-value offsets.
// s_fakeResource and s_fakeInner152 are forward-declared near the top of the file.
static ULONG_PTR __stdcall StubRetChanAccumBuf() { return (ULONG_PTR)s_fakeChanAccumBuf; }

// s_fakeStateVtbl[64] declared as forward at the top of the file (before OnBp).
static bool s_fakeVtblsInited = false;

// 32-entry vtable for fake channel object: all StubRet0, index 18 = StubRet1
static void* s_fakeChanVtbl[32];

// Generic all-StubRet0 vtable reused by all inner fake objects below.
// 128 entries to cover high vtable offsets: atiumd6a:0x16122 calls slot 78 (offset 0x270),
// which must be a readable entry that returns 0 → triggers early-exit branch at 0x1612A.
static void* s_stubVtbl[128];

// Two-level fake for [channel+0x10]:
//   [channel+0x10]            → s_fakeChan10 (vtable at [+0])
//   [s_fakeChan10+0x70]       → s_fakeChan10Sub (vtable at [+0])
//   [s_fakeChan10+0x30]       → s_fakeChan10Sub2 (vtable at [+0])
// atiumd6a:0x13C950 reads [channel+0x10], then dereferences [+0x70] for a vtable
// and calls vtable[+0xD0] on that sub-object.
// s_fakeChan10 is forward-declared near the top of the file
static uint8_t s_fakeChan10Sub[32];   // [+0x00]=vtbl ptr (used at [chan10+0x70])
static uint8_t s_fakeChan10Sub2[32];  // [+0x00]=vtbl ptr (used at [chan10+0x30])

// Two-level fake for [channel+0x90]:
//   [channel+0x90]            → s_fakeChan90 (vtable at [+0])
//   [s_fakeChan90+0x20]       → s_fakeChan90Sub (vtable at [+0])
// atiumd6a:0x2180 at +0x12435 reads [channel+0x90]+0x20 and calls vtable[+0xC0] and [+0xA8].
static uint8_t s_fakeChan90[64];     // [+0x00]=vtbl ptr; [+0x20]=sub ptr
static uint8_t s_fakeChan90Sub[32];  // [+0x00]=vtbl ptr

// Render-state lookup table: [[s_fakeChan10+0x28]+index*4+0xB48] — zero-filled so every
// lookup returns 0 (≠ 2), causing func_646C0 to return false cleanly via the jnz path
// without crashing.  Must be large enough for the max index (0x18D)*4 + 0xB48 = 0x1030.
static uint8_t s_fakeTable[0x1800];

// Fully fake state block wired at [s_fakeChannel+0x28].  Vtable = s_fakeStateVtbl (with the
// real flush at slot 4) so the flush BP fires; all data fields are zero so crashes inside the
// flush hit small NULL+offset addresses rather than stale far pointers.
// (s_fakeSb is forward-declared near the top of the file; this comment marks the definition.)

// s_patchedSbVtbl / s_patchedSbVtblReady: forward-declared near the top of the file.
// A copy of sb_vtbl_A with slot 5 → StubRet0 to skip the 0x13E260 crash.

// 0x200-byte fake channel object: vtable ptr at [+0] points to s_fakeChanVtbl
// Heap-allocated to avoid issues with static lifetime (declaration near top of file)

static void InitFakeVtbls() {
    if (s_fakeVtblsInited) return;

    // Generic stub vtable: all StubRet0 (128 entries — covers high offsets like 0x270 = slot 78)
    for (int i = 0; i < 128; i++) s_stubVtbl[i] = (void*)StubRet0;

    // State vtable: all StubRet0, then override specific slots:
    for (int i = 0; i < 64; i++) s_fakeStateVtbl[i] = (void*)StubRet0;
    // vtable[10] = offset +0x50: return struct with [+0x0]=1 (checked at atiumd6a+0x1229F)
    s_fakeStateVtbl[10] = (void*)StubRetFakeStateObj;
    // vtable[7]  = offset +0x38: return non-zero to pass the gate at 0x13C9BD
    s_fakeStateVtbl[7]  = (void*)StubRet1;
    // vtable[12] = offset +0x60: return 1 so the cmp at 0x13C9E5 falls through to the clear path
    s_fakeStateVtbl[12] = (void*)StubRet1;

    // Channel vtable: all StubRet0, then override specific slots:
    for (int i = 0; i < 32; i++) s_fakeChanVtbl[i] = (void*)StubRet0;
    s_fakeChanVtbl[18] = (void*)StubRet1;
    // Slot 7 (offset +0x38): atiumd6a:0x4A400 calls this to get the per-frame accumulator
    // buffer, then passes it to 0x46C30 which writes 11 accumulated qwords to [rcx+8..+88].
    // Returns s_fakeChanAccumBuf (a 128-byte zero-filled static buffer).
    memset(s_fakeChanAccumBuf, 0, sizeof s_fakeChanAccumBuf);
    s_fakeChanVtbl[7]  = (void*)StubRetChanAccumBuf;

    // Initialise the two-level fake for [channel+0x10]
    memset(s_fakeChan10,     0, sizeof s_fakeChan10);
    memset(s_fakeChan10Sub,  0, sizeof s_fakeChan10Sub);
    memset(s_fakeChan10Sub2, 0, sizeof s_fakeChan10Sub2);
    *(void**)s_fakeChan10     = s_stubVtbl;
    *(void**)s_fakeChan10Sub  = s_stubVtbl;
    *(void**)s_fakeChan10Sub2 = s_stubVtbl;
    *(void**)(s_fakeChan10 + 0x70) = s_fakeChan10Sub;
    // [+0x28]: render-state lookup table — func_646C0 reads [[channel+0x10]+0x28] as the base
    // of a DWORD array; crash at atiumd6a:0x4D59C (AV at 0x1020) when this is null.
    *(void**)(s_fakeChan10 + 0x28) = s_fakeTable;
    // [+0x30]: atiumd6a:0x16116 reads [[channel+0x10]+0x30], then calls vtable[78] on it.
    // StubRet0 returns 0 → branch at 0x1612A taken → function 0x16100 returns 1 cleanly.
    *(void**)(s_fakeChan10 + 0x30) = s_fakeChan10Sub2;
    // [+0x38]: flush/sub_13E8D0 do "mov rcx,[channel+0x10]; mov rcx,[rcx+0x38]" then dereference.
    // Self-ref avoids the null-deref: [[+0x38]]=s_stubVtbl, call vtable[7]=StubRet0 → al=0.
    *(void**)(s_fakeChan10 + 0x38) = s_fakeChan10;

    // Fake state block vtable
    *(void**)s_fakeSb = s_fakeStateVtbl;

    // s_fakeSb80: all-StubRet0 vtable except slot 4 = StubRet1 (see declaration comment).
    memset(s_fakeSb80, 0, sizeof s_fakeSb80);
    for (int i = 0; i < 32; i++) s_fakeSb80Vtbl[i] = (void*)StubRet0;
    s_fakeSb80Vtbl[4] = (void*)StubRet1;
    s_fakeSb80Vtbl[23] = (void*)StubFillSb80Out;
    *(void**)s_fakeSb80 = s_fakeSb80Vtbl;
    // Selector 0x4BFA0 returns s_fakeSb80+0x00/+0x30/+0x60 depending on [+0xB0];
    // each returned sub-object is called through its vtable, so set all three.
    *(void**)(s_fakeSb80 + 0x30) = s_fakeSb80Vtbl;
    *(void**)(s_fakeSb80 + 0x60) = s_fakeSb80Vtbl;
    *(DWORD*)(s_fakeSb80 + 0xB0) = 2;
    *(void**)s_fakeSb80Out = s_stubVtbl;
    *(void**)(s_fakeSb + 0x80) = s_fakeSb80;
    *(void**)(s_fakeSb + 0x110) = s_fakeSb110;

    // Fake texture resource: wired at s_fakeSb[+0x88] etc so the bound-resource selector
    // 0x4BFA0 doesn't crash reading [null+0xB0].  [+0xB0]=2 is a trial value; inner-object
    // pointer placed at all three possible selected+0x48 offsets (+0x48, +0x78, +0xA8) so
    // regardless of which of the three non-null return cases fires, [selected+0x48] is valid.
    memset(s_fakeResource,  0, sizeof s_fakeResource);
    // s_fakeInner152 is heap-allocated here (private heap so freed memory can't be reallocated by
    // any other code).  stateApply(2) frees it and immediately reallocates to simulate reset freeing
    // the texture inner object and another allocation reusing the freed slot.
    if (!g_innerHeap)
        g_innerHeap = HeapCreate(HEAP_NO_SERIALIZE, 0x40000, 0);
    if (!s_fakeInner152)
        s_fakeInner152 = (uint8_t*)HeapAlloc(g_innerHeap, HEAP_ZERO_MEMORY, 0x1200);
    // Fill every pointer-sized slot (0x08 to end) with s_fakeResource itself so any chain of
    // dereferences through the object stays non-null.  Specific overrides follow.
    for (int _r = 0x08; _r + 8 <= (int)sizeof s_fakeResource; _r += 8)
        *(void**)(s_fakeResource + _r) = s_fakeResource;
    for (int _r = 0x08; _r + 8 <= 0x1200; _r += 8)
        *(void**)(s_fakeInner152 + _r) = s_fakeInner152;
    // s_fakeResourceVtbl: texture-resource vtable.  Slot 7 = StubRet1 so the initial gate
    // at flush+0x6D ("call [rbx_vtable+0x38]; test al,al; jz skip") passes (non-zero = valid).
    // All other slots = StubRet0 so any virtual call returns 0 without crashing.
    for (auto& p : s_fakeResourceVtbl) p = (void*)StubRet0;
    s_fakeResourceVtbl[7]  = (void*)StubRet1;
    // sub_13E8D0 entry gate: "call [vtable+0xA0]" (slot 20) must return 1 to proceed to clear path.
    s_fakeResourceVtbl[20] = (void*)StubRet1;
    // sub_13E8D0 selector result vtable[12]: "call [rdx+0x60]" on selector(res) result, then
    // "mov rbx,[rax+0x48]".  Return s_fakeResource so [rax+0x48] = s_fakeInner152.
    s_fakeResourceVtbl[12] = (void*)StubRetFakeResource;
    // The selector 0x4BFA0 returns resource+0x00, +0x30, or +0x60 depending on [resource+0xB0].
    // Each returned sub-object is treated as a C++ object — give each a vtable so virtual calls work.
    *(void**)s_fakeResource = s_fakeResourceVtbl;                   // sub-obj vtable at +0x00
    *(void**)(s_fakeResource + 0x30) = s_fakeResourceVtbl;          // sub-obj vtable at +0x30
    *(void**)(s_fakeResource + 0x60) = s_fakeResourceVtbl;          // sub-obj vtable at +0x60
    s_fakeResource[0xB0] = 2; // type selector byte — try "2" first; adjust if selector returns NULL
    *(void**)(s_fakeResource + 0x00 + 0x48) = s_fakeInner152; // inner GPU resource for base
    *(void**)(s_fakeResource + 0x30 + 0x48) = s_fakeInner152; // inner GPU resource for +0x30
    *(void**)(s_fakeResource + 0x60 + 0x48) = s_fakeInner152; // inner GPU resource for +0x60
    // s_fakeInner152: also needs a vtable so the clear routine can call virtual methods on it.
    *(void**)s_fakeInner152 = s_stubVtbl;

    // Initialise the two-level fake for [channel+0x90]
    memset(s_fakeChan90,    0, sizeof s_fakeChan90);
    memset(s_fakeChan90Sub, 0, sizeof s_fakeChan90Sub);
    *(void**)s_fakeChan90    = s_stubVtbl;
    *(void**)s_fakeChan90Sub = s_stubVtbl;
    *(void**)(s_fakeChan90 + 0x20) = s_fakeChan90Sub;

    // Fake channel: 0x200 bytes, vtable ptr at [+0].  Must cover +0x110: the 0x128680
    // epilogue destructor reads [channel+0x110] and dereferences it (0x61BD0/0x64030).
    s_fakeChannel = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x200);
    if (s_fakeChannel) *(void**)s_fakeChannel = s_fakeChanVtbl;
    s_fakeVtblsInited = true;
}

// Unblock atiumd64:0x2FF90: set [[device_inner+0x600]+0x20] to the fake channel object.
// device_inner = [hDevice+0x10]; channel_holder = [device_inner+0x600].
// In its own function because wmain has C++ objects to unwind, which forbids __try there (C2712).
static void InstallFakeChannel(HANDLE hDevice) {
    if (!s_fakeChannel) return;
    __try {
        void* device_inner = *(void**)((char*)hDevice + 0x10);
        if (device_inner) {
            void* chan_holder = *(void**)((char*)device_inner + 0x600);
            if (chan_holder) {
                void** chan_slot = (void**)((char*)chan_holder + 0x20);
                if (*chan_slot == nullptr) {
                    *chan_slot = s_fakeChannel;
                    Log("fake-channel: dev_inner=%p chan_holder=%p chan=%p vtbl=%p",
                        device_inner, chan_holder, (void*)s_fakeChannel, s_fakeChanVtbl);
                } else {
                    Log("fake-channel: slot already set to %p, not overwriting", *chan_slot);
                }
            } else {
                Log("fake-channel: chan_holder=[dev_inner+0x600] is null");
            }
        } else {
            Log("fake-channel: device_inner=[hDevice+0x10] is null");
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Log("fake-channel: exception while setting channel");
    }
    // Wire up [channel+0x10]: atiumd6a:0x13C950 reads [[channel+0x10]+0x70] for a vtable
    // object and calls vtable[+0xD0] on it.  s_fakeChan10 and s_fakeChan10Sub satisfy that.
    *(void**)(s_fakeChannel + 0x10) = s_fakeChan10;
    // Wire [channel+0x80]: the flush helpers 0x128680 / 0x12A420 / 0x12CAD0 read
    // [channel+0x80] (or [stateblock+0x80]) and dereference it as a C++ object.
    *(void**)(s_fakeChannel + 0x80) = s_fakeSb80;
    // Wire [channel+0x110]: 0x128680's epilogue destructor (0x257900) passes
    // [channel+0x110] as rcx to 0x61BD0/0x64030, which read [rcx+0x58]/[+0x60].
    // A zero-filled buffer makes both take their skip paths.
    *(void**)(s_fakeChannel + 0x110) = s_fakeSb110;
    // Wire up [channel+0x28]: real state block with its vtable patched to s_fakeStateVtbl.
    // Using the real state block keeps real driver fields intact (texture slots at [+0x88]/[+0x98],
    // the texture-stage index at [+0x20], etc.) while letting us control all virtual calls on it.
    __try {
        HMODULE a6a = GetModuleHandleA("atiumd6a.dll");
        void* dev_vtable    = a6a ? (char*)a6a + (0x4BC970 - 0x10000) : nullptr;
        void* sb_vtable_A   = a6a ? (char*)a6a + (0x4B7180 - 0x10000) : nullptr;
        void* sb_vtable_B   = a6a ? (char*)a6a + (0x4B6F00 - 0x10000) : nullptr;
        Log("fake-channel: a6a=%p dev_vtbl=%p sb_vtbl_A=%p sb_vtbl_B=%p",
            (void*)a6a, dev_vtable, sb_vtable_A, sb_vtable_B);
        void* found_dev = nullptr;
        void* found_sb  = nullptr;
        MEMORY_BASIC_INFORMATION mbi;
        char* addr = nullptr;
        while (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.State == MEM_COMMIT &&
                (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED) &&
                (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) &&
                !(mbi.Protect & PAGE_GUARD) &&
                mbi.RegionSize >= 8) {
                for (char* p = (char*)mbi.BaseAddress;
                     p + 8 <= (char*)mbi.BaseAddress + mbi.RegionSize;
                     p += 8) {
                    void* v;
                    __try { v = *(void**)p; } __except(1) { v = nullptr; }
                    if (!v) continue;
                    if (v == dev_vtable && !found_dev) {
                        found_dev = p;
                        void* sb_from_dev = nullptr;
                        __try { sb_from_dev = *(void**)((char*)p + 0x190); } __except(1) {}
                        Log("fake-channel: found device=%p → [+0x190]=%p", p, sb_from_dev);
                        if (sb_from_dev) {
                            MEMORY_BASIC_INFORMATION sb_mbi;
                            bool sb_readable = VirtualQuery(sb_from_dev, &sb_mbi, sizeof sb_mbi) == sizeof sb_mbi
                                            && sb_mbi.State == MEM_COMMIT
                                            && (sb_mbi.Protect & (PAGE_READONLY|PAGE_READWRITE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE));
                            if (sb_readable) {
                                void* sb_v = nullptr;
                                __try { sb_v = *(void**)sb_from_dev; } __except(1) {}
                                if (sb_v == sb_vtable_A || sb_v == sb_vtable_B) {
                                    found_sb = sb_from_dev;
                                    Log("fake-channel: state_block from dev+0x190: %p vtbl=%p", found_sb, sb_v);
                                }
                            }
                        }
                    }
                    if ((v == sb_vtable_A || v == sb_vtable_B) && !found_dev && !found_sb) {
                        // Fall back to direct vtable match only if device was not found yet.
                        // This may pick the wrong object; prefer the [device+0x190] path above.
                        found_sb = p;
                        Log("fake-channel: found state_block (vtbl-scan fallback)=%p vtbl=%p", p, v);
                    }
                    if (found_sb) break;
                }
            }
            addr += mbi.RegionSize;
            if (!addr) break;
            if (found_sb) break;
        }
        if (found_sb) {
            void* sb_vtbl = nullptr;
            __try { sb_vtbl = *(void**)found_sb; } __except(1) {}
            void* sb_8 = nullptr;
            __try { sb_8 = *(void**)((char*)found_sb + 0x08); } __except(1) {}
            Log("fake-channel: state_block=%p vtbl=%p [+8]=%p tex0=%p tex1=%p idx=%d",
                found_sb, sb_vtbl, sb_8,
                *(void**)((char*)found_sb + 0x88),
                *(void**)((char*)found_sb + 0x98),
                *(int*)((char*)found_sb + 0x20));
        } else {
            Log("fake-channel: state_block not found — using s_fakeSb");
        }
        // Always wire s_fakeSb, never found_sb: on a second call (post-Reset device recreate)
        // the scan can find a stale or garbage address and the driver dereferences it before
        // stateApply fires to re-wire s_fakeSb, crashing on the driver thread.
        // Pre-initialise s_fakeSb so the driver survives the window before stateApply does
        // the full re-setup: vtable + flush patch + texture slots (same shape stateApply makes).
        *(void**)s_fakeSb = s_fakeStateVtbl;
        if (!s_fakeVtblFlushPatched) {
            HMODULE a6a = GetModuleHandleA("atiumd6a.dll");
            if (a6a) {
                s_realFlush = (char*)a6a + (0x13C950 - 0x10000);
                s_fakeStateVtbl[4] = s_realFlush;
                s_fakeStateVtbl[5] = (void*)StubRet0; // 0x13E260 → skip base-vtable crash
                s_fakeVtblFlushPatched = true;
                Log("fake-channel: s_fakeStateVtbl[4]=real flush %p, [5]=StubRet0", s_fakeStateVtbl[4]);
            }
        }
        if (!*(void**)(s_fakeSb + 0x88)) {
            for (int _off = 0x28; _off <= 0xBF; _off += 8)
                *(void**)(s_fakeSb + _off) = s_fakeResource;
            *(void**)(s_fakeSb + 0xA0) = nullptr;  // gate: [+0xA2] must stay 0
        }
        // Wired after the 0x28..0xBF fill above so the loop doesn't overwrite it.
        *(void**)(s_fakeSb + 0x80) = s_fakeSb80;
        *(void**)(s_fakeSb + 0x110) = s_fakeSb110;
        *(void**)(s_fakeChannel + 0x28) = s_fakeSb;
        Log("fake-channel: s_fakeSb pre-initialised and wired → [chan+0x28]");
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Log("fake-channel: exception during state_block vmem scan; using s_fakeSb");
        *(void**)(s_fakeChannel + 0x28) = s_fakeSb;
    }
    // Wire up [channel+0x90]: two-level fake for the 0x12435 path in atiumd6a:0x2180.
    *(void**)(s_fakeChannel + 0x90) = s_fakeChan90;
}

static bool g_fakeDrawParams = false; // --fake-draw-params: allocate fake draw-param buffers at [hDevice+0x4958/0x4960]
static void HookImports(HMODULE mod);

struct ThunkSlot { char name[64]; NTSTATUS(APIENTRY* real)(void*); };
static ThunkSlot g_thunks[48];
static int g_thunkCount = 0;

// --kmt-fake: answer the driver's D3DKMT calls with STATUS_SUCCESS and just enough output for the
// CPU-side draw path to run to the flush, without real hardware. Handles are a throwaway counter;
// nothing needs tracking yet.
static UINT32 s_nextFakeHandle = 1;
static BYTE   s_fakeLockBuf[4096];

static NTSTATUS FakeKmt(const char* name, void* arg)
{
    if (!strcmp(name, "D3DKMTCreateAllocation")) {
        auto* p = (D3DKMT_CREATEALLOCATION*)arg;
        if (p->pAllocationInfo) {
            for (UINT i = 0; i < p->NumAllocations; i++)
                p->pAllocationInfo[i].hAllocation = s_nextFakeHandle++;
        }
        p->hResource = s_nextFakeHandle++;
        return (NTSTATUS)0;
    }
    if (!strcmp(name, "D3DKMTCreateSynchronizationObject")) {
        auto* p = (D3DKMT_CREATESYNCHRONIZATIONOBJECT*)arg;
        p->hSyncObject = s_nextFakeHandle++;
        return (NTSTATUS)0;
    }
    if (!strcmp(name, "D3DKMTRender")) {
        // Refuse the actual GPU submission: the driver bails out before spinning on a fence
        // that the fake GPU would never signal. The deferred flush (and the clear write) has
        // already run before this call, so refusing here is safe and avoids an infinite wait.
        return (NTSTATUS)0xC00000BB; // STATUS_NOT_SUPPORTED
    }
    if (!strcmp(name, "D3DKMTLock")) {
        auto* p = (D3DKMT_LOCK*)arg;
        p->pData = s_fakeLockBuf;
        return (NTSTATUS)0;
    }
    // DestroyAllocation, DestroySynchronizationObject, SignalSynchronizationObject,
    // WaitForSynchronizationObject, Escape, Unlock, and everything else: succeed and leave it at that.
    return (NTSTATUS)0;
}

template <int N>
static NTSTATUS APIENTRY ThunkWrapper(void* arg)
{
    NTSTATUS s;
    const char* tag;
    if (g_kmtForward) {
        s   = g_thunks[N].real(arg);
        tag = "";
    } else if (g_kmtFake) {
        s   = FakeKmt(g_thunks[N].name, arg);
        tag = " [fake]";
    } else {
        s   = (NTSTATUS)0xC00000BB; // STATUS_NOT_SUPPORTED
        tag = " [refused, not forwarded]";
    }
    Log("  km %s(%p) = %08lx%s", g_thunks[N].name, arg, s, tag);
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
    // Null guard before any dereference
    if (!name) {
        Log("  LoadSibling: null name, skipping");
        return nullptr;
    }
    __try {
    const wchar_t* base = wcsrchr(name, L'\\');
        base = base ? base + 1 : name;
        // Use WideCharToMultiByte for safe logging: avoids %ls crash on bad pointer
        char safen[MAX_PATH * 2 + 4] = "(bad)";
        char safeb[MAX_PATH * 2 + 4] = "(bad)";
        WideCharToMultiByte(CP_ACP, 0, name, -1, safen, (int)sizeof safen, nullptr, nullptr);
        WideCharToMultiByte(CP_ACP, 0, base, -1, safeb, (int)sizeof safeb, nullptr, nullptr);
        char safedir[MAX_PATH * 2 + 4] = "(bad)";
        WideCharToMultiByte(CP_ACP, 0, g_driverDir, -1, safedir, (int)sizeof safedir, nullptr, nullptr);
        Log("  LoadSibling: name='%s' base='%s' driverDir='%s'", safen, safeb, g_driverDir[0] ? safedir : "(empty)");
        wchar_t local[MAX_PATH];
        HMODULE h = nullptr;
        bool sibling = false;
        if (g_driverDir[0] && base && base[0]) {
        swprintf_s(local, L"%s\\%s", g_driverDir, base);
            sibling = GetFileAttributesW(local) != INVALID_FILE_ATTRIBUTES;
            if (sibling) h = LoadLibraryExW(local, nullptr, 0);
        }
        if (!h) h = LoadLibraryExW(name, nullptr, flags);
    Log("  LoadLibrary(\"%s\") = %p%s", safen, (void*)h, sibling && h ? " [from the driver folder]" : "");
        if (h && sibling) {
            HookImports(h);
            if (_wcsicmp(base, L"atiumd6a.dll") == 0) {
                // Object-factory BPs in both builds: which mmobj variant gets created is the
                // question in the standalone probe too (crash object: vtable atiumd6a RVA 0x2CEB90).
                ArmBp(h, 0x009430, "mmobj.make");   // creates [settings+0x5028]
                ArmBp(h, 0x009482, "mmobj.init");     // post-init call: eax = init result
                if (g_plant710465) {
                    ArmBp(h, 0x037510, "crash.fn");   // crash vtable's slot+0x40: reads [obj+0x68]
                    ArmBp(h, 0x0094D0, "dtor.a6a");   // field crash path through the factory's dtor
                }
            }
#ifdef D3D9SHIM_DLL
            if (_wcsicmp(base, L"atiumd6a.dll") == 0) {
                // Diagnostic: arm the object-factory BPs as soon as atiumd6a is in memory,
                // before the driver can call them during OpenAdapter/CreateDevice.
                // These RVAs are the 15.7.1 (a6a build 513) addresses.  On any other build
                // they can land mid-instruction, and a BP restore+single-step there would
                // execute corrupted code, so skip the whole list.
                DWORD a6aMinor = GetModuleMinorBuild(h);
                if (a6aMinor != 513) {
                    Log("  LoadSibling: atiumd6a minor build = %lu -- skipping 15.7.1 diagnostic arms",
                        (unsigned long)a6aMinor);
                    // The version-driven early BPs are still valid for this build.
                    ShimArmEarlyA6a(h);
                } else {
                ArmBp(h, 0x009430, "mmobj.make");   // creates [settings+0x5028]
                ArmBp(h, 0x003710, "chan.make");    // creates [holder+0x20] (channel)
                ArmBp(h, 0x002180, "st.flush");     // atiumd6a state-flush entry
                ArmBp(h, 0x085370, "cap.read");       // engine-caps file reader: r8d = engine id
                ArmBp(h, 0x0022F8, "st.br22f8");      // 0x2180: states-differ branch (real flush)
                ArmBp(h, 0x00241A, "st.br241a");      // 0x2180: same-state branch
                ArmBp(h, 0x0024EF, "st.skip");        // 0x2180: skip (no flush)
                ArmBp(h, 0x002435, "st.r14p90");      // 0x2180: MOV RAX,[R14+0x90] (null check)
                ArmBp(h, 0x00BAA5, "st.baa5");        // vtable fn: TEST RBX,RBX before [RBX+8] deref
                ArmBp(h, 0x001850, "st.b1850");       // inner resource binder called with [entry+0x08]
                ArmBp(h, 0x002450, "st.ret244a");     // 0x2180: return point after vtable CALL at 0x244A
                ArmBp(h, 0x00BAEF, "st.baef");        // vtable fn: RBX=0 path
                ArmBp(h, 0x002405, "st.call38");      // 0x2180: [[chan+0x28]+0x18] vt+0x38 call
                ArmBp(h, 0x002496, "st.call20");      // 0x2180: [chan+0x28] vt+0x20 call
                ArmBp(h, 0x002499, "st.ret2496");     // 0x2180: return point after st.call20
                ArmBp(h, 0x001EE7, "st.dfcall");      // 0x1D30: indirect submit call via [a6a+0x82EA28]
                ArmBp(h, 0x001EED, "st.dfret");       // 0x1D30: return point of that call
                ArmBp(h, 0x00244A, "st.callc0");      // 0x2180: vtable call [rax+0xc0]
                }
            }
#endif
            if (g_bpClear && _wcsicmp(base, L"atiumd6a.dll") == 0) {
                Log("bp-clear: atiumd6a.dll at %p; arming clear write sites + caller gates", (void*)h);
                // Clear write sites (the actual +0x64 writes): RVA = VA_preferred - 0x10000
                ArmBp(h, 0x12EA32, "clear.A"); // path A write:  0x13EA32
                ArmBp(h, 0x12E946, "clrzero"); // call site for memset(inner_obj,0,0x1000); cap r8=0 before the call
                ArmBp(h, 0x0F44EC, "clear.B"); // path B write:  0x1044EC
                ArmBp(h, 0x0F7305, "clear.1"); // new write:     0x107305
                ArmBp(h, 0x1EBD09, "clear.2"); // new write:     0x1FBD09
                ArmBp(h, 0x1FED70, "clear.3"); // new write:     0x20ED70
                // Caller-level gates: do these functions even get called?
                ArmBp(h, 0x12C950, "flush");   // state-flush function 0x13C950 (contains clear calls)
                ArmBp(h, 0x12E260, "relobj");  // virtual call target that crashes at +0x31 ([rdi+8]=-1)
                ArmBp(h, 0x0F4520, "tss.disp");// TSS dispatcher 0x104520 (path B caller)
                ArmBp(h, 0x11A420, "gate");    // sub_12A420 (the gate condition for the clear)
            }
        }
        return h;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Log("  LoadSibling: exception in body, loading original without sibling check");
        return LoadLibraryExW(name, nullptr, flags);
    }
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

// ---------------------------------------------------------------- atiumd6a.cap emulation
//
// The driver's engine discovery (atiumd6a:0x85370 counting, 0x85730 parsing) reads a
// capabilities file "atiumd6a.cap" from the system directory. The 2015 package shipped
// it next to the driver; it is data, not code, and it is absent here, so the file APIs
// are answered for that one path with an in-memory file. The format, recovered from
// 0x85370: a 0x20-byte plaintext header (magic 0x02010F01 at +4, index entry size at +8,
// engine record size at +0xC, index count at +0x10, default index at +0x14), then an
// index of 0x10-byte records {id, start, ?, end}, then engine records. Everything past
// the header is XOR-obfuscated: key 0x86ACD572, advancing by 0x5742AF69 per dword.
// Engine records are counted into two arrays by 0x85370: a record whose [0x88] equals
// the header's first dword (or -1) is counted, into out1 when its [4] is nonzero.

static const HANDLE kFakeCapHandle = (HANDLE)(ULONG_PTR)0xCA990001;
static uint64_t g_fakeCapPos = 0;
static bool g_fakeCapBuilt = false;
static uint8_t g_fakeCap[0x100];
static size_t g_fakeCapSize = 0;

static void BuildFakeCap()
{
    if (g_fakeCapBuilt) return;
    g_fakeCapBuilt = true;
    memset(g_fakeCap, 0, sizeof g_fakeCap);
    auto put32 = [&](size_t off, uint32_t v) { memcpy(g_fakeCap + off, &v, 4); };
    put32(0x00, 1);           // version dword; engine record [0x88] must equal it to be counted
    put32(0x04, 0x02010F01);  // magic
    put32(0x08, 0x10);        // index entry size
    put32(0x0C, 0x90);        // engine record size
    put32(0x10, 1);           // index entry count
    put32(0x14, 0);           // default index
    uint32_t key = 0x86ACD572;
    auto putX = [&](size_t off, uint32_t v) { put32(off, v ^ key); key += 0x5742AF69; };
    putX(0x20, 0);            // index[0].id = 0
    putX(0x24, 0);            // index[0].start = 0
    putX(0x28, 0);            // index[0].?
    putX(0x2C, 0);            // index[0].end = 0  (one engine record)
    for (size_t i = 0; i < 0x90 / 4; i++) putX(0x30 + i * 4, (i == 1 || i == 0x88 / 4) ? 1 : 0);
    g_fakeCapSize = 0x30 + 0x90;
}

static HANDLE WINAPI Hook_CreateFileA(LPCSTR name, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES sa,
                                      DWORD disp, DWORD flags, HANDLE tmpl)
{
    if (name) {
        const char* base = strrchr(name, '\\');
        base = base ? base + 1 : name;
        if (_stricmp(base, "atiumd6a.cap") == 0) {
            BuildFakeCap();
            g_fakeCapPos = 0;
            Log("  cap: CreateFileA(\"%s\") answered with the in-memory capabilities file", name);
            return kFakeCapHandle;
        }
    }
    return CreateFileA(name, access, share, sa, disp, flags, tmpl);
}

static BOOL WINAPI Hook_ReadFile(HANDLE h, LPVOID buf, DWORD n, LPDWORD nread, LPOVERLAPPED ov)
{
    if (h == kFakeCapHandle) {
        size_t left = g_fakeCapSize > g_fakeCapPos ? g_fakeCapSize - (size_t)g_fakeCapPos : 0;
        DWORD got = (DWORD)(n < left ? n : left);
        if (got) memcpy(buf, g_fakeCap + g_fakeCapPos, got);
        g_fakeCapPos += got;
        if (nread) *nread = got;
        return TRUE;
    }
    return ReadFile(h, buf, n, nread, ov);
}

static DWORD WINAPI Hook_SetFilePointer(HANDLE h, LONG dist, PLONG high, DWORD method)
{
    if (h == kFakeCapHandle) {
        int64_t base = method == FILE_BEGIN ? 0
                     : method == FILE_CURRENT ? (int64_t)g_fakeCapPos
                     : (int64_t)g_fakeCapSize;
        int64_t np = base + dist;
        if (np < 0) np = 0;
        g_fakeCapPos = (uint64_t)np;
        if (high) *high = (LONG)(g_fakeCapPos >> 32);
        return (DWORD)g_fakeCapPos;
    }
    return SetFilePointer(h, dist, high, method);
}

static BOOL WINAPI Hook_CloseHandle(HANDLE h)
{
    if (h == kFakeCapHandle) return TRUE;
    return CloseHandle(h);
}

struct ImportHook { const char* name; void* hook; };
static const ImportHook g_importHooks[] = {
    { "HeapAlloc", (void*)Hook_HeapAlloc },       { "HeapFree", (void*)Hook_HeapFree },
    { "HeapReAlloc", (void*)Hook_HeapReAlloc },   { "HeapSize", (void*)Hook_HeapSize },
    { "HeapCreate", (void*)Hook_HeapCreate },     { "HeapDestroy", (void*)Hook_HeapDestroy },
    { "VirtualAlloc", (void*)Hook_VirtualAlloc }, { "GetProcAddress", (void*)Hook_GetProcAddress },
    { "LoadLibraryA", (void*)Hook_LoadLibraryA }, { "LoadLibraryW", (void*)Hook_LoadLibraryW },
    { "LoadLibraryExA", (void*)Hook_LoadLibraryExA }, { "LoadLibraryExW", (void*)Hook_LoadLibraryExW },
    { "OutputDebugStringA", (void*)Hook_OutputDebugStringA },
    { "CreateFileA", (void*)Hook_CreateFileA },       { "ReadFile", (void*)Hook_ReadFile },
    { "SetFilePointer", (void*)Hook_SetFilePointer }, { "CloseHandle", (void*)Hook_CloseHandle },
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
static std::vector<std::pair<UINT, UINT>> g_qaiSet2; // --qai-set2: dwords invented into the second, larger record
struct QaiFillRange { UINT off, len, byte; }; // --qai-fill-range off:len:byte: memset a range inside the record
static std::vector<QaiFillRange> g_qaiFillRange;  // ranges for the first record, applied in command-line order
static std::vector<QaiFillRange> g_qaiFillRange2; // ranges for the second record
static UINT g_qaiFill2 = 0; // --qai-fill2: fill byte for the second record; the driver reads some of its fields
static bool g_qaiIndex2 = false; // --qai-index2: fill the second record with dword indices (mapping probe)
static bool g_breakpoints = false; // --bp: arm the int3 breakpoints that trace the driver's ring setup
                            // as small scalars and treats 0 differently from a filler, so it is configurable

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
    if (p->PrivateDriverDataSize == 0x3A00) {
        // The second record is a different structure: it carries 8-byte memory-sizing fields, so a 4-byte
        // write at offset N sets the low dword and the high dword must stay zero. It is filled with its own
        // fill byte (zero unless --qai-fill2 says otherwise) and takes its invented fields from --qai-set2,
        // not the fill byte and --qai-set of the first record.
        if (g_qaiIndex2) {
            // Debug mode: dword N of the record holds N, so a dump of wherever the driver copies the record
            // reads as a map from target offset to source offset.
            for (UINT i = 0; i * 4 + 4 <= p->PrivateDriverDataSize; i++)
                ((UINT*)p->pPrivateDriverData)[i] = i;
        } else {
            memset(p->pPrivateDriverData, (int)g_qaiFill2, p->PrivateDriverDataSize);
        }
        for (auto& r : g_qaiFillRange2)
            if (r.off < p->PrivateDriverDataSize) {
                UINT n = p->PrivateDriverDataSize - r.off;
                if (n > r.len) n = r.len;
                memset((char*)p->pPrivateDriverData + r.off, (int)r.byte, n);
            }
        // The driver copies the record verbatim starting at offset 0x2A00 into its adapter block, where a
        // per-engine table describes the command-buffer rings. In the WDDM 2 device path the driver sizes its
        // ring segments from that table: engine 0's alignment is read at 0x2C2C (a power-of-two mask base) and
        // its segment size at 0x2C30, and the table is considered present only when +0x2A00 is nonzero with a
        // count of at least 1 at +0x2A04. All four read as zero in a blank record, which makes the driver skip
        // its ring setup and fault on the first command packet. Supply a small plausible geometry; explicit
        // --qai-set2 fields below still win over these defaults.
        if (!g_qaiIndex2) {
            static const std::pair<UINT, UINT> ringDefaults[] = {
                { 0x2A00, 1 },       // engine table present
                { 0x2A04, 1 },       // one engine
                { 0x2C2C, 0x1000 },  // engine 0 ring alignment: one page
                { 0x2C30, 0x10000 }, // engine 0 ring segment size: 64 KB
            };
            for (auto& d : ringDefaults)
                memcpy((char*)p->pPrivateDriverData + d.first, &d.second, 4);
        }
        for (auto& s : g_qaiSet2)
            if (s.first + 4 <= p->PrivateDriverDataSize) memcpy((char*)p->pPrivateDriverData + s.first, &s.second, 4);
        Log("    answered the %u-byte record with 0x%02x, %zu fill ranges and %zu invented fields (--qai-set2)",
            p->PrivateDriverDataSize, g_qaiFill2, g_qaiFillRange2.size(), g_qaiSet2.size());
        return S_OK;
    }
    memset(p->pPrivateDriverData, (int)g_qaiFill, p->PrivateDriverDataSize);
    for (auto& r : g_qaiFillRange)
        if (r.off < p->PrivateDriverDataSize) {
            UINT n = p->PrivateDriverDataSize - r.off;
            if (n > r.len) n = r.len;
            memset((char*)p->pPrivateDriverData + r.off, (int)r.byte, n);
        }
    // The record carries the adapter's registry path as a NUL-terminated string at +0xE8 (the driver
    // compares it against "SYSTEM" at atiumd64+0x199F, and atiumd6a's device init searches it for
    // "SYSTEM"/"SOFTWARE" before it will build its device objects; an empty string makes the init
    // return failure and the whole channel/state path stays dark). The kernel would supply this on
    // real hardware, so invent it the same way as the other record fields.
    {
        static const char kRegPath[] =
            "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Class"
            "\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000";
        if (0xE8 + sizeof kRegPath <= p->PrivateDriverDataSize)
            memcpy((char*)p->pPrivateDriverData + 0xE8, kRegPath, sizeof kRegPath);
    }
    for (auto& s : g_qaiSet)
        if (s.first + 4 <= p->PrivateDriverDataSize) memcpy((char*)p->pPrivateDriverData + s.first, &s.second, 4);
    Log("    answered the %u-byte record with 0x%02x, %zu fill ranges and %zu invented fields (--qai-set)",
        p->PrivateDriverDataSize, g_qaiFill, g_qaiFillRange.size(), g_qaiSet.size());
    return S_OK;
}

static HRESULT APIENTRY CALLBACK GetMultisampleMethodListCb(HANDLE hAdapter, D3DDDICB_GETMULTISAMPLEMETHODLIST* p)
{
    Log("cb GetMultisampleMethodListCb(h=%p, %ux%u fmt=%u)", hAdapter, p->Width, p->Height, (UINT)p->Format);
    p->MethodCount = 0;
    return S_OK;
}

// ---------------------------------------------------- the fake kernel, device level
//
// Past OpenAdapter the driver stops asking questions and starts allocating memory, creating contexts and
// submitting command buffers. None of that can be forwarded: the kernel driver on this machine is bound to
// different hardware. So it is answered instead -- handles are invented, allocations are backed by ordinary
// virtual memory, and submissions are accepted and reported complete.
//
// Every buffer handed to the driver is followed by an inaccessible page, so a write past the end of a locked
// allocation or a command buffer faults at the instruction that made it rather than corrupting the harness.

struct FakeAlloc {
    D3DKMT_HANDLE handle;
    SIZE_T size;        // what was handed out, excluding the guard page
    void* mem;
    ULONGLONG gpuVa;
};
static std::map<D3DKMT_HANDLE, FakeAlloc> g_fakeAllocs;
static D3DKMT_HANDLE g_nextKmHandle = 0x00300000;

// Where the invented GPU virtual addresses start, and the granularity they are handed out at. A driver for
// hardware of this age may believe its address space is small, and an address beyond what it thinks it has is
// a plausible reason for it to refuse. --gpu-va-base moves it; 64 KB is the usual GPU page granularity.
static ULONGLONG g_gpuVaBase = 0x0000000000100000ull;
static ULONGLONG g_gpuVaNext = 0;
static ULONGLONG g_gpuVaGrain = 0x10000;

static ULONGLONG NextGpuVa(ULONGLONG size)
{
    if (!g_gpuVaNext) g_gpuVaNext = g_gpuVaBase;
    ULONGLONG va = (g_gpuVaNext + g_gpuVaGrain - 1) & ~(g_gpuVaGrain - 1);
    if (!size) size = g_gpuVaGrain;
    g_gpuVaNext = va + ((size + g_gpuVaGrain - 1) & ~(g_gpuVaGrain - 1));
    return va;
}
static SIZE_T g_lockSize = 32u << 20; // what an allocation is backed with when the driver locks it
static bool g_escapeZero = false;     // --escape-zero: answer an escape with zeros instead of leaving it alone
static bool g_sysmem = false;         // --sysmem: back every allocation at AllocateCb and return it as pSystemMem
static size_t g_guardFaults = 0;

// Virtual memory with an inaccessible page after it, so an overrun faults instead of spreading.
static void* GuardedAlloc(SIZE_T size, SIZE_T* outTotal = nullptr)
{
    SIZE_T page = 0x1000;
    SIZE_T usable = (size + page - 1) & ~(page - 1);
    BYTE* base = (BYTE*)VirtualAlloc(nullptr, usable + page, MEM_RESERVE, PAGE_NOACCESS);
    if (!base) return nullptr;
    if (!VirtualAlloc(base, usable, MEM_COMMIT, PAGE_READWRITE)) { VirtualFree(base, 0, MEM_RELEASE); return nullptr; }
    if (outTotal) *outTotal = usable;
    return base;
}

struct FakeContext {
    HANDLE handle;
    void* cmd;
    UINT cmdSize;
    D3DDDI_ALLOCATIONLIST* allocList;
    UINT allocListSize;
    D3DDDI_PATCHLOCATIONLIST* patchList;
    UINT patchListSize;
    ULONGLONG cmdGpuVa;
};
static std::map<HANDLE, FakeContext> g_fakeContexts;
static UINT_PTR g_nextContext = 0xC0000;
static size_t g_submits = 0;

static bool SizeContext(FakeContext* c, UINT cmdSize, UINT allocCount, UINT patchCount)
{
    if (cmdSize < 0x10000) cmdSize = 0x100000;
    if (allocCount < 256) allocCount = 4096;
    if (patchCount < 256) patchCount = 4096;
    c->cmd = GuardedAlloc(cmdSize);
    c->allocList = (D3DDDI_ALLOCATIONLIST*)GuardedAlloc(allocCount * sizeof(D3DDDI_ALLOCATIONLIST));
    c->patchList = (D3DDDI_PATCHLOCATIONLIST*)GuardedAlloc(patchCount * sizeof(D3DDDI_PATCHLOCATIONLIST));
    if (!c->cmd || !c->allocList || !c->patchList) return false;
    c->cmdSize = cmdSize;
    c->allocListSize = allocCount;
    c->patchListSize = patchCount;
    c->cmdGpuVa = NextGpuVa(cmdSize);
    return true;
}

// Each table slot gets its own stub, so a callback the driver needs and the harness has not implemented is
// named by slot and offset instead of crashing on a null pointer.
static const size_t DEV_CB_SLOTS = sizeof(D3DDDI_DEVICECALLBACKS) / sizeof(void*);
static size_t g_devStubHits = 0;

template <int N>
static HRESULT APIENTRY DevStub(void* a, void* b, void* c, void* d)
{
    (void)a; (void)b; (void)c; (void)d;
    g_devStubHits++;
    Log("  cb device slot %d (offset 0x%zx) [stub] = E_NOTIMPL", N, (size_t)N * sizeof(void*));
    LogStack("stub");
    return E_NOTIMPL;
}

template <size_t... I>
static void FillDevStubs(void** table, std::index_sequence<I...>)
{
    ((table[I] = (void*)&DevStub<(int)I>), ...);
}

static HRESULT APIENTRY CALLBACK DevAllocateCb(HANDLE hDevice, D3DDDICB_ALLOCATE* p)
{
    (void)hDevice;
    p->hKMResource = ++g_nextKmHandle;
    for (UINT i = 0; i < p->NumAllocations; i++) {
        D3DDDI_ALLOCATIONINFO* a = &p->pAllocationInfo[i];
        FakeAlloc f{};
        f.handle = ++g_nextKmHandle;
        f.size = 0;
        f.mem = nullptr;
        f.gpuVa = NextGpuVa(g_lockSize);
        if (g_sysmem) {
            // The runtime backs a CPU-visible allocation with system memory up front and hands the pointer back
            // in pSystemMem; the driver then never needs to lock it. Its own private data says which allocations
            // are CPU-visible, but only the driver can read that, so every allocation is backed.
            f.mem = GuardedAlloc(g_lockSize, &f.size);
            if (!f.mem) return E_OUTOFMEMORY;
            a->pSystemMem = f.mem;
        }
        g_fakeAllocs[f.handle] = f;
        a->hAllocation = f.handle;
    }
    Log("  cb AllocateCb(hResource=%p, %u allocations, %u bytes private) = S_OK, hKMResource=%x", p->hResource,
        p->NumAllocations, p->PrivateDriverDataSize, p->hKMResource);
    if (p->pPrivateDriverData && p->PrivateDriverDataSize)
        HexDump("    res", p->pPrivateDriverData, p->PrivateDriverDataSize, 48);
    for (UINT i = 0; i < p->NumAllocations; i++) {
        D3DDDI_ALLOCATIONINFO* a = &p->pAllocationInfo[i];
        Log("    allocation %u: handle=%x pSystemMem=%p flags=%08x, %u bytes of private data", i, a->hAllocation,
            a->pSystemMem, a->Flags.Value, a->PrivateDriverDataSize);
        if (a->pPrivateDriverData && a->PrivateDriverDataSize)
            HexDump("    alloc", a->pPrivateDriverData, a->PrivateDriverDataSize, 64);
    }
    return S_OK;
}

static HRESULT APIENTRY CALLBACK DevDeallocateCb(HANDLE hDevice, CONST D3DDDICB_DEALLOCATE* p)
{
    (void)hDevice;
    for (UINT i = 0; i < p->NumAllocations && p->HandleList; i++) {
        auto it = g_fakeAllocs.find(p->HandleList[i]);
        if (it == g_fakeAllocs.end()) continue;
        if (it->second.mem) VirtualFree(it->second.mem, 0, MEM_RELEASE);
        g_fakeAllocs.erase(it);
    }
    Log("  cb DeallocateCb(hResource=%p, %u allocations) = S_OK", p->hResource, p->NumAllocations);
    return S_OK;
}

static HRESULT APIENTRY CALLBACK DevLockCb(HANDLE hDevice, D3DDDICB_LOCK* p)
{
    (void)hDevice;
    auto it = g_fakeAllocs.find(p->hAllocation);
    if (it == g_fakeAllocs.end()) {
        Log("  cb LockCb(hAllocation=%x) = E_INVALIDARG, no such allocation", p->hAllocation);
        return E_INVALIDARG;
    }
    FakeAlloc& f = it->second;
    if (!f.mem) {
        // The size the driver meant is in its own private data, which only it understands, so the allocation is
        // backed generously and the guard page catches a driver that wants more than this.
        SIZE_T want = p->NumPages ? (SIZE_T)p->NumPages * 0x1000 : g_lockSize;
        if (want < g_lockSize) want = g_lockSize;
        f.mem = GuardedAlloc(want, &f.size);
        if (!f.mem) { Log("  cb LockCb: out of memory backing %zu bytes", want); return E_OUTOFMEMORY; }
    }
    p->pData = f.mem;
    p->GpuVirtualAddress = f.gpuVa;
    Log("  cb LockCb(hAllocation=%x, pages=%u, flags=%08x) = S_OK, %zu bytes at %p, gpuVa %llx", p->hAllocation,
        p->NumPages, p->Flags.Value, f.size, f.mem, f.gpuVa);
    return S_OK;
}

static HRESULT APIENTRY CALLBACK DevUnlockCb(HANDLE hDevice, CONST D3DDDICB_UNLOCK* p)
{
    (void)hDevice;
    Log("  cb UnlockCb(%u allocations) = S_OK", p->NumAllocations);
    return S_OK;
}

static HRESULT APIENTRY CALLBACK DevEscapeCb(HANDLE hAdapterOrDevice, CONST D3DDDICB_ESCAPE* p)
{
    (void)hAdapterOrDevice;
    // The payload is an AMD-private request with its own 0x80-byte header (size, version, opcode) and is
    // answered in place. Zeroing it destroys the header the driver is about to re-read, so the buffer is left
    // exactly as the driver filled it: anything the driver validates about its own request still holds, and the
    // reply body reads as whatever it initialised. --escape-zero asks for the old behaviour instead.
    Log("  cb EscapeCb(hDevice=%p, hContext=%p, %u bytes, flags=%08x, opcode=%08x) = S_OK%s", p->hDevice,
        p->hContext, p->PrivateDriverDataSize, p->Flags.Value,
        p->PrivateDriverDataSize >= 12 ? ((const UINT*)p->pPrivateDriverData)[2] : 0,
        g_escapeZero ? ", answered with zeros" : ", left as the driver filled it");
    if (p->pPrivateDriverData && p->PrivateDriverDataSize) {
        HexDump("esc", p->pPrivateDriverData, p->PrivateDriverDataSize, 32);
        if (g_escapeZero) memset(p->pPrivateDriverData, 0, p->PrivateDriverDataSize);
        if (g_qaiIndex2) {
            // Debug: answer the escape with a dword index map past the 0x10-byte header, so wherever the
            // driver copies the reply the dump names the source offset.
            for (UINT i = 4; i * 4 + 4 <= p->PrivateDriverDataSize; i++)
                ((UINT*)p->pPrivateDriverData)[i] = i;
        }
    }
    return S_OK;
}

static HRESULT APIENTRY CALLBACK DevCreateContextCb(HANDLE hDevice, D3DDDICB_CREATECONTEXT* p)
{
    (void)hDevice;
    FakeContext c{};
    c.handle = (HANDLE)++g_nextContext;
    if (!SizeContext(&c, 0, 0, 0)) return E_OUTOFMEMORY;
    g_fakeContexts[c.handle] = c;
    p->hContext = c.handle;
    p->pCommandBuffer = c.cmd;
    p->CommandBufferSize = c.cmdSize;
    p->pAllocationList = c.allocList;
    p->AllocationListSize = c.allocListSize;
    p->pPatchLocationList = c.patchList;
    p->PatchLocationListSize = c.patchListSize;
    p->CommandBuffer = c.cmdGpuVa;
    Log("  cb CreateContextCb(node=%u, affinity=%u, %u bytes private) = S_OK, hContext=%p, command buffer %u bytes"
        " at %p",
        p->NodeOrdinal, p->EngineAffinity, p->PrivateDriverDataSize, c.handle, c.cmdSize, c.cmd);
    LogStack("CreateContextCb", 1, 8);
    if (p->pPrivateDriverData && p->PrivateDriverDataSize) HexDump("ctx", p->pPrivateDriverData, p->PrivateDriverDataSize, 64);
    return S_OK;
}

static HRESULT APIENTRY CALLBACK DevDestroyContextCb(HANDLE hDevice, CONST D3DDDICB_DESTROYCONTEXT* p)
{
    (void)hDevice;
    auto it = g_fakeContexts.find(p->hContext);
    if (it != g_fakeContexts.end()) {
        if (it->second.cmd) VirtualFree(it->second.cmd, 0, MEM_RELEASE);
        if (it->second.allocList) VirtualFree(it->second.allocList, 0, MEM_RELEASE);
        if (it->second.patchList) VirtualFree(it->second.patchList, 0, MEM_RELEASE);
        g_fakeContexts.erase(it);
    }
    Log("  cb DestroyContextCb(hContext=%p) = S_OK", p->hContext);
    return S_OK;
}

// The submission itself: the command buffer is accepted, nothing executes it, and the driver is given a buffer
// to carry on writing into.
static HRESULT APIENTRY CALLBACK DevRenderCb(HANDLE hDevice, D3DDDICB_RENDER* p)
{
    (void)hDevice;
    g_submits++;
    auto it = g_fakeContexts.find(p->hContext);
    if (it == g_fakeContexts.end()) {
        Log("  cb RenderCb(hContext=%p) = E_INVALIDARG, no such context", p->hContext);
        return E_INVALIDARG;
    }
    FakeContext& c = it->second;
    if (p->Flags.ResizeCommandBuffer || p->Flags.ResizeAllocationList || p->Flags.ResizePatchLocationList) {
        FakeContext n{};
        n.handle = c.handle;
        if (!SizeContext(&n, p->NewCommandBufferSize, p->NewAllocationListSize, p->NewPatchLocationListSize))
            return E_OUTOFMEMORY;
        if (c.cmd) VirtualFree(c.cmd, 0, MEM_RELEASE);
        if (c.allocList) VirtualFree(c.allocList, 0, MEM_RELEASE);
        if (c.patchList) VirtualFree(c.patchList, 0, MEM_RELEASE);
        c = n;
        Log("  cb RenderCb: resized to command buffer %u, allocation list %u, patch list %u", c.cmdSize,
            c.allocListSize, c.patchListSize);
    }
    p->pNewCommandBuffer = c.cmd;
    p->NewCommandBufferSize = c.cmdSize;
    p->pNewAllocationList = c.allocList;
    p->NewAllocationListSize = c.allocListSize;
    p->pNewPatchLocationList = c.patchList;
    p->NewPatchLocationListSize = c.patchListSize;
    p->NewCommandBuffer = c.cmdGpuVa;
    p->QueuedBufferCount = 0; // nothing is queued: the submission is reported already complete
    Log("  cb RenderCb(hContext=%p, %u bytes at offset %u, %u allocations, %u patches) = S_OK", p->hContext,
        p->CommandLength, p->CommandOffset, p->NumAllocations, p->NumPatchLocations);
    return S_OK;
}

static HRESULT APIENTRY CALLBACK DevPresentCb(HANDLE hDevice, D3DDDICB_PRESENT* p)
{
    (void)hDevice;
    Log("  cb PresentCb(src=%x, dst=%x, hContext=%p) = S_OK", p->hSrcAllocation, p->hDstAllocation, p->hContext);
    return S_OK;
}

static HRESULT APIENTRY CALLBACK DevCreateSyncCb(HANDLE hDevice, D3DDDICB_CREATESYNCHRONIZATIONOBJECT* p)
{
    (void)hDevice;
    p->hSyncObject = ++g_nextKmHandle;
    Log("  cb CreateSynchronizationObjectCb(type=%u) = S_OK, handle=%x", (UINT)p->Info.Type, p->hSyncObject);
    return S_OK;
}

static HRESULT APIENTRY CALLBACK DevDestroySyncCb(HANDLE hDevice, CONST D3DDDICB_DESTROYSYNCHRONIZATIONOBJECT* p)
{
    (void)hDevice;
    Log("  cb DestroySynchronizationObjectCb(%x) = S_OK", p->hSyncObject);
    return S_OK;
}

// Waits return at once and signals are accepted: with nothing executing, every fence is already past.
static HRESULT APIENTRY CALLBACK DevWaitSyncCb(HANDLE hDevice, CONST D3DDDICB_WAITFORSYNCHRONIZATIONOBJECT* p)
{
    (void)hDevice;
    Log("  cb WaitForSynchronizationObjectCb(%u objects) = S_OK, returned at once", p->ObjectCount);
    return S_OK;
}

static HRESULT APIENTRY CALLBACK DevSignalSyncCb(HANDLE hDevice, CONST D3DDDICB_SIGNALSYNCHRONIZATIONOBJECT* p)
{
    (void)hDevice;
    Log("  cb SignalSynchronizationObjectCb(%u objects) = S_OK", p->ObjectCount);
    return S_OK;
}

// The 2-variants take the fence value explicitly; the fence words handed out by DevCreateSync2Cb are
// already past every value the driver can wait for, so these complete at once like the non-2 versions.
static HRESULT APIENTRY CALLBACK DevWaitSync2Cb(HANDLE hDevice, CONST D3DDDICB_WAITFORSYNCHRONIZATIONOBJECT2* p)
{
    (void)hDevice;
    if (g_wpInnerPtr) {
        char* probe = (char*)g_wpInnerPtr + 0x64;
        // If the probe target sits on a fenced bait page, the probe itself would fault and
        // be logged as a FENCE UAF from our own module -- that is instrumentation noise,
        // not a driver UAF.  Skip it; the driver's own deref of the bait is the detection.
        uintptr_t probePage = (uintptr_t)g_wpInnerPtr & ~(uintptr_t)0xFFF;
        bool fenced = false;
        PoolLock();
        for (int _i = 0; _i < g_fencedCount; _i++)
            if ((uintptr_t)g_fenced[_i].page_base == probePage) { fenced = true; break; }
        PoolUnlock();
        if (fenced) {
            Log("shim: DevWaitSync2Cb: probe skipped, %p is on a fenced bait page", (void*)probePage);
        } else {
            Log("shim: DevWaitSync2Cb: UAF probe write at %p (g_wpInnerPtr=%p)", probe, g_wpInnerPtr);
            __try {
                *(volatile ULONG_PTR*)probe = 0;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                Log("shim: DevWaitSync2Cb: probe except %08lx (VEH logged FENCE UAF)", GetExceptionCode());
            }
        }
        g_wpInnerPtr = nullptr;
    }
    Log("  cb WaitForSynchronizationObject2Cb(%u objects, fence=%llu) = S_OK",
        p ? p->ObjectCount : 0u, p ? (unsigned long long)p->FenceValue : 0ull);
    return S_OK;
}

static HRESULT APIENTRY CALLBACK DevSignalSync2Cb(HANDLE hDevice, CONST D3DDDICB_SIGNALSYNCHRONIZATIONOBJECT2* p)
{
    (void)hDevice;
    Log("  cb SignalSynchronizationObject2Cb(%u objects) = S_OK", p->ObjectCount);
    return S_OK;
}

static HRESULT APIENTRY CALLBACK DevQueryResidencyCb(HANDLE hDevice, CONST D3DDDICB_QUERYRESIDENCY* p)
{
    (void)hDevice;
    for (UINT i = 0; i < p->NumAllocations && p->pResidencyStatus; i++)
        p->pResidencyStatus[i] = D3DDDI_RESIDENCYSTATUS_RESIDENTINGPUMEMORY;
    Log("  cb QueryResidencyCb(%u allocations) = S_OK, all resident", p->NumAllocations);
    return S_OK;
}

static HRESULT APIENTRY CALLBACK DevSetPriorityCb(HANDLE hDevice, D3DDDICB_SETPRIORITY* p)
{
    (void)hDevice;
    Log("  cb SetPriorityCb(%u allocations) = S_OK", p->NumAllocations);
    return S_OK;
}

static HRESULT APIENTRY CALLBACK DevSetAsyncCallbacksCb(HANDLE hDevice, BOOL enable)
{
    (void)hDevice;
    Log("  cb SetAsyncCallbacksCb(%s) = S_OK", enable ? "enable" : "disable");
    return S_OK;
}

static HRESULT APIENTRY CALLBACK DevSetDisplayModeCb(HANDLE hDevice, D3DDDICB_SETDISPLAYMODE* p)
{
    (void)hDevice;
    Log("  cb SetDisplayModeCb(primary=%x) = S_OK", p->hPrimaryAllocation);
    return S_OK;
}

// ---- the WDDM 2 memory model ------------------------------------------------------------------------------
//
// Bit 7 of the adapter record's flags at +0x1F4 switches the driver onto this path: paging queues, GPU virtual
// addresses, residency and SubmitCommand instead of RenderCb. Nothing executes, so every fence is reported
// already past: the fence words the driver polls are held at a value no wait can exceed, and every paging
// operation returns a fence value of 0, meaning there is nothing to wait for.

static UINT64* g_fenceWords = nullptr; // a page of fence values handed out to paging queues and sync objects
static size_t g_fenceNext = 0;
static size_t g_pagingQueues = 0;

static UINT64* NextFenceWord()
{
    if (!g_fenceWords) {
        g_fenceWords = (UINT64*)GuardedAlloc(0x1000);
        if (!g_fenceWords) return nullptr;
    }
    if (g_fenceNext >= 0x1000 / sizeof(UINT64)) g_fenceNext = 0;
    UINT64* w = &g_fenceWords[g_fenceNext++];
    *w = 0x7FFFFFFFFFFFFFFFull; // already past anything the driver can wait for
    return w;
}

static HRESULT APIENTRY CALLBACK DevCreatePagingQueueCb(HANDLE hDevice, D3DDDICB_CREATEPAGINGQUEUE* p)
{
    (void)hDevice;
    UINT64* fence = NextFenceWord();
    if (!fence) return E_OUTOFMEMORY;
    p->hPagingQueue = ++g_nextKmHandle;
    p->hSyncObject = ++g_nextKmHandle;
    p->FenceValueCPUVirtualAddress = fence;
    g_pagingQueues++;
    Log("  cb CreatePagingQueueCb(priority=%d, adapter=%u) = S_OK, queue=%x, fence word at %p", (int)p->Priority,
        p->PhysicalAdapterIndex, p->hPagingQueue, fence);
    return S_OK;
}

static HRESULT APIENTRY CALLBACK DevDestroyPagingQueueCb(HANDLE hDevice, CONST D3DDDI_DESTROYPAGINGQUEUE* p)
{
    (void)hDevice;
    Log("  cb DestroyPagingQueueCb(%x) = S_OK", p->hPagingQueue);
    return S_OK;
}

static HRESULT APIENTRY CALLBACK DevMakeResidentCb(HANDLE hDevice, D3DDDI_MAKERESIDENT* p)
{
    (void)hDevice;
    p->PagingFenceValue = 0;
    p->NumBytesToTrim = 0;
    Log("  cb MakeResidentCb(queue=%x, %u allocations) = S_OK, nothing to wait for", p->hPagingQueue,
        p->NumAllocations);
    return S_OK;
}

static HRESULT APIENTRY CALLBACK DevEvictCb(HANDLE hDevice, D3DDDICB_EVICT* p)
{
    (void)hDevice;
    p->NumBytesToTrim = 0;
    Log("  cb EvictCb(%u allocations) = S_OK", p->NumAllocations);
    return S_OK;
}

static HRESULT APIENTRY CALLBACK DevReserveGpuVaCb(HANDLE hDevice, D3DDDI_RESERVEGPUVIRTUALADDRESS* p)
{
    (void)hDevice;
    ULONGLONG size = p->Size ? p->Size : 0x1000;
    p->VirtualAddress = NextGpuVa(size);
    p->PagingFenceValue = 0;
    Log("  cb ReserveGpuVirtualAddressCb(size=%llx) = S_OK, va=%llx", size, p->VirtualAddress);
    return S_OK;
}

static HRESULT APIENTRY CALLBACK DevMapGpuVaCb(HANDLE hDevice, D3DDDI_MAPGPUVIRTUALADDRESS* p)
{
    (void)hDevice;
    ULONGLONG va = p->BaseAddress;
    if (!va) {
        auto it = g_fakeAllocs.find(p->hAllocation);
        va = it != g_fakeAllocs.end() ? it->second.gpuVa : NextGpuVa(p->SizeInPages * 0x1000);
    }
    // The driver may constrain where the mapping may land. A virtual address outside what it asked for is a
    // plausible reason for it to give up, so the request is honoured when it names a range.
    if (!p->BaseAddress && (p->MinimumAddress || p->MaximumAddress)) {
        ULONGLONG lo = p->MinimumAddress ? p->MinimumAddress : va;
        ULONGLONG hi = p->MaximumAddress ? p->MaximumAddress : (ULONGLONG)-1;
        ULONGLONG want = (lo + 0xFFFFF) & ~0xFFFFFull;
        ULONGLONG size = p->SizeInPages * 0x1000;
        if (want + size <= hi) va = want;
    }
    p->VirtualAddress = va;
    p->PagingFenceValue = 0;
    Log("  cb MapGpuVirtualAddressCb(allocation=%x, base=%llx, min=%llx, max=%llx, offset=%llx, pages=%llx,"
        " protection=%llx) = S_OK, va=%llx",
        p->hAllocation, (unsigned long long)p->BaseAddress, (unsigned long long)p->MinimumAddress,
        (unsigned long long)p->MaximumAddress, (unsigned long long)p->OffsetInPages,
        (unsigned long long)p->SizeInPages, (unsigned long long)p->DriverProtection, va);
    return S_OK;
}

static HRESULT APIENTRY CALLBACK DevFreeGpuVaCb(HANDLE hDevice, CONST D3DDDICB_FREEGPUVIRTUALADDRESS* p)
{
    (void)hDevice;
    Log("  cb FreeGpuVirtualAddressCb(base=%llx, size=%llx) = S_OK", (unsigned long long)p->BaseAddress,
        (unsigned long long)p->Size);
    return S_OK;
}

static HRESULT APIENTRY CALLBACK DevUpdateGpuVaCb(HANDLE hDevice, CONST D3DDDICB_UPDATEGPUVIRTUALADDRESS* p)
{
    (void)hDevice;
    Log("  cb UpdateGpuVirtualAddressCb(%u operations) = S_OK", p->NumOperations);
    return S_OK;
}

static HRESULT APIENTRY CALLBACK DevLock2Cb(HANDLE hDevice, D3DDDICB_LOCK2* p)
{
    (void)hDevice;
    auto it = g_fakeAllocs.find(p->hAllocation);
    if (it == g_fakeAllocs.end()) {
        Log("  cb Lock2Cb(%x) = E_INVALIDARG, no such allocation", p->hAllocation);
        return E_INVALIDARG;
    }
    FakeAlloc& f = it->second;
    if (!f.mem) {
        f.mem = GuardedAlloc(g_lockSize, &f.size);
        if (!f.mem) return E_OUTOFMEMORY;
    }
    p->pData = f.mem;
    Log("  cb Lock2Cb(%x, flags=%08x) = S_OK, %zu bytes at %p", p->hAllocation, p->Flags.Value, f.size, f.mem);
    return S_OK;
}

static HRESULT APIENTRY CALLBACK DevUnlock2Cb(HANDLE hDevice, CONST D3DDDICB_UNLOCK2* p)
{
    (void)hDevice;
    Log("  cb Unlock2Cb(%x) = S_OK", p->hAllocation);
    return S_OK;
}

static HRESULT APIENTRY CALLBACK DevInvalidateCacheCb(HANDLE hDevice, CONST D3DDDICB_INVALIDATECACHE* p)
{
    (void)hDevice;
    Log("  cb InvalidateCacheCb(%x) = S_OK", p->hAllocation);
    return S_OK;
}

static HRESULT APIENTRY CALLBACK DevCreateContextVirtualCb(HANDLE hDevice, D3DDDICB_CREATECONTEXTVIRTUAL* p)
{
    (void)hDevice;
    // In this model the driver writes its own command buffers into allocations it owns, so no buffers are
    // handed back here; only the handle.
    FakeContext c{};
    c.handle = (HANDLE)++g_nextContext;
    g_fakeContexts[c.handle] = c;
    p->hContext = c.handle;
    if (g_qaiIndex2 && p->pPrivateDriverData && p->PrivateDriverDataSize >= 8) {
        // Debug: overwrite the driver's request with a dword index map (keep its 8-byte header), so wherever
        // the driver copies the KMD's answer the dump names the source offset.
        for (UINT i = 2; i * 4 + 4 <= p->PrivateDriverDataSize; i++)
            ((UINT*)p->pPrivateDriverData)[i] = i;
    }
    Log("  cb CreateContextVirtualCb(node=%u, affinity=%u, %u bytes private) = S_OK, hContext=%p", p->NodeOrdinal,
        p->EngineAffinity, p->PrivateDriverDataSize, c.handle);
    if (p->pPrivateDriverData && p->PrivateDriverDataSize) HexDump("ctx", p->pPrivateDriverData, p->PrivateDriverDataSize, 48);
    return S_OK;
}

static HRESULT APIENTRY CALLBACK DevSubmitCommandCb(HANDLE hDevice, CONST D3DDDICB_SUBMITCOMMAND* p)
{
    (void)hDevice;
    g_submits++;
    Log("  cb SubmitCommandCb(commands at %llx, %u bytes, %u broadcast contexts) = S_OK, reported complete",
        (unsigned long long)p->Commands, p->CommandLength, p->BroadcastContextCount);
    return S_OK;
}

static HRESULT APIENTRY CALLBACK DevCreateSync2Cb(HANDLE hDevice, D3DDDICB_CREATESYNCHRONIZATIONOBJECT2* p)
{
    (void)hDevice;
    p->hSyncObject = ++g_nextKmHandle;
    if (p->Info.Type == D3DDDI_MONITORED_FENCE) {
        UINT64* fence = NextFenceWord();
        if (!fence) return E_OUTOFMEMORY;
        // NextFenceWord() already holds the word past every value the driver can wait for; honouring
        // InitialFenceValue here would leave the fence stuck at its start value, since the Signal* callbacks
        // never advance it, and any later wait on this object would spin forever.
        p->Info.MonitoredFence.FenceValueCPUVirtualAddress = fence;
        p->Info.MonitoredFence.FenceValueGPUVirtualAddress = NextGpuVa(0x1000);
    }
    Log("  cb CreateSynchronizationObject2Cb(type=%d) = S_OK, handle=%x", (int)p->Info.Type, p->hSyncObject);
    return S_OK;
}

static HRESULT APIENTRY CALLBACK DevWaitSyncFromCpuCb(HANDLE hDevice,
                                                      CONST D3DDDICB_WAITFORSYNCHRONIZATIONOBJECTFROMCPU* p)
{
    (void)hDevice;
    Log("  cb WaitForSynchronizationObjectFromCpuCb(%u objects) = S_OK, returned at once", p->ObjectCount);
    return S_OK;
}

static HRESULT APIENTRY CALLBACK DevSignalSyncFromCpuCb(HANDLE hDevice,
                                                        CONST D3DDDICB_SIGNALSYNCHRONIZATIONOBJECTFROMCPU* p)
{
    (void)hDevice;
    // The fence the driver is signalling is held past every value it can ask about, so nothing has to move.
    Log("  cb SignalSynchronizationObjectFromCpuCb(%u objects) = S_OK", p->ObjectCount);
    return S_OK;
}

static HRESULT APIENTRY CALLBACK DevWaitSyncFromGpuCb(HANDLE hDevice,
                                                      CONST D3DDDICB_WAITFORSYNCHRONIZATIONOBJECTFROMGPU* p)
{
    (void)hDevice;
    Log("  cb WaitForSynchronizationObjectFromGpuCb(%u objects) = S_OK", p->ObjectCount);
    return S_OK;
}

static HRESULT APIENTRY CALLBACK DevSignalSyncFromGpuCb(HANDLE hDevice,
                                                        CONST D3DDDICB_SIGNALSYNCHRONIZATIONOBJECTFROMGPU* p)
{
    (void)hDevice;
    Log("  cb SignalSynchronizationObjectFromGpuCb(%u objects) = S_OK", p->ObjectCount);
    return S_OK;
}

static HRESULT APIENTRY CALLBACK DevSignalSyncFromGpu2Cb(HANDLE hDevice,
                                                         CONST D3DDDICB_SIGNALSYNCHRONIZATIONOBJECTFROMGPU2* p)
{
    (void)hDevice;
    Log("  cb SignalSynchronizationObjectFromGpu2Cb(%u objects) = S_OK", p->ObjectCount);
    return S_OK;
}

static HRESULT APIENTRY CALLBACK DevDeallocate2Cb(HANDLE hDevice, CONST D3DDDICB_DEALLOCATE2* p)
{
    (void)hDevice;
    for (UINT i = 0; i < p->NumAllocations && p->HandleList; i++) {
        auto it = g_fakeAllocs.find(p->HandleList[i]);
        if (it == g_fakeAllocs.end()) continue;
        if (it->second.mem) VirtualFree(it->second.mem, 0, MEM_RELEASE);
        g_fakeAllocs.erase(it);
    }
    Log("  cb Deallocate2Cb(%u allocations) = S_OK", p->NumAllocations);
    return S_OK;
}

static HRESULT APIENTRY CALLBACK DevOfferAllocationsCb(HANDLE hDevice, CONST D3DDDICB_OFFERALLOCATIONS* p)
{
    (void)hDevice;
    Log("  cb OfferAllocationsCb(%u allocations) = S_OK", p->NumAllocations);
    return S_OK;
}

static HRESULT APIENTRY CALLBACK DevReclaimAllocationsCb(HANDLE hDevice, CONST D3DDDICB_RECLAIMALLOCATIONS* p)
{
    (void)hDevice;
    for (UINT i = 0; i < p->NumAllocations && p->pDiscarded; i++) p->pDiscarded[i] = FALSE;
    Log("  cb ReclaimAllocationsCb(%u allocations) = S_OK, none discarded", p->NumAllocations);
    return S_OK;
}

static HRESULT APIENTRY CALLBACK DevLogUMDMarkerCb(HANDLE hDevice, CONST D3DDDICB_LOGUMDMARKER* p)
{
    (void)hDevice; (void)p;
    return S_OK;
}

static void FillDeviceCallbacks(D3DDDI_DEVICECALLBACKS* cb)
{
    FillDevStubs<>((void**)cb, std::make_index_sequence<DEV_CB_SLOTS>{});
    cb->pfnAllocateCb = DevAllocateCb;
    cb->pfnDeallocateCb = DevDeallocateCb;
    cb->pfnLockCb = DevLockCb;
    cb->pfnUnlockCb = DevUnlockCb;
    cb->pfnEscapeCb = DevEscapeCb;
    cb->pfnCreateContextCb = DevCreateContextCb;
    cb->pfnDestroyContextCb = DevDestroyContextCb;
    cb->pfnRenderCb = DevRenderCb;
    cb->pfnPresentCb = DevPresentCb;
    cb->pfnCreateSynchronizationObjectCb = DevCreateSyncCb;
    cb->pfnDestroySynchronizationObjectCb = DevDestroySyncCb;
    cb->pfnWaitForSynchronizationObjectCb = DevWaitSyncCb;
    cb->pfnSignalSynchronizationObjectCb = DevSignalSyncCb;
    cb->pfnQueryResidencyCb = DevQueryResidencyCb;
    cb->pfnSetPriorityCb = DevSetPriorityCb;
    cb->pfnSetAsyncCallbacksCb = DevSetAsyncCallbacksCb;
    cb->pfnSetDisplayModeCb = DevSetDisplayModeCb;

    // The WDDM 2 half, which the driver uses when the adapter record asks for it.
    cb->pfnCreatePagingQueueCb = DevCreatePagingQueueCb;
    cb->pfnDestroyPagingQueueCb = DevDestroyPagingQueueCb;
    cb->pfnMakeResidentCb = DevMakeResidentCb;
    cb->pfnEvictCb = DevEvictCb;
    cb->pfnReserveGpuVirtualAddressCb = DevReserveGpuVaCb;
    cb->pfnMapGpuVirtualAddressCb = DevMapGpuVaCb;
    cb->pfnFreeGpuVirtualAddressCb = DevFreeGpuVaCb;
    cb->pfnUpdateGpuVirtualAddressCb = DevUpdateGpuVaCb;
    cb->pfnLock2Cb = DevLock2Cb;
    cb->pfnUnlock2Cb = DevUnlock2Cb;
    cb->pfnInvalidateCacheCb = DevInvalidateCacheCb;
    cb->pfnCreateContextVirtualCb = DevCreateContextVirtualCb;
    cb->pfnSubmitCommandCb = DevSubmitCommandCb;
    cb->pfnCreateSynchronizationObject2Cb = DevCreateSync2Cb;
    cb->pfnWaitForSynchronizationObject2Cb = DevWaitSync2Cb;
    cb->pfnSignalSynchronizationObject2Cb = DevSignalSync2Cb;
    cb->pfnWaitForSynchronizationObjectFromCpuCb = DevWaitSyncFromCpuCb;
    cb->pfnSignalSynchronizationObjectFromCpuCb = DevSignalSyncFromCpuCb;
    cb->pfnWaitForSynchronizationObjectFromGpuCb = DevWaitSyncFromGpuCb;
    cb->pfnSignalSynchronizationObjectFromGpuCb = DevSignalSyncFromGpuCb;
    cb->pfnSignalSynchronizationObjectFromGpu2Cb = DevSignalSyncFromGpu2Cb;
    cb->pfnDeallocate2Cb = DevDeallocate2Cb;
    cb->pfnOfferAllocationsCb = DevOfferAllocationsCb;
    cb->pfnReclaimAllocationsCb = DevReclaimAllocationsCb;
    cb->pfnLogUMDMarkerCb = DevLogUMDMarkerCb;
}

typedef HRESULT(APIENTRY* PFN_OPENADAPTER)(D3DDDIARG_OPENADAPTER*);

// ---------------------------------------------------------------- the workload
//
// --workload: between CreateDevice and DestroyDevice, drive the device with a small D3D9 workload so the
// driver's draw-time and resource-management code actually runs. Each round creates a 64x64 A8R8G8B8 texture,
// binds it to stage 0 with MODULATE blending and linear filtering, draws one triangle from a user-memory
// stream and destroys the texture. A NULL entry point or a failing HRESULT is logged and counted, never
// fatal: the point is to see what the driver accepts.
//
// The D3D9 user-mode DDI has no pfnSetSamplerState: sampler filtering arrives as texture-stage state
// (D3DDDITSS_MAGFILTER / D3DDDITSS_MINFILTER), so that is what is set here.
//
// --workload-reset runs the runtime's device-lost/Reset sequence between iterations (see RunWorkloadReset):
// a bulk invalidation and re-creation of the tracked DEFAULT-pool resources, with no state-block scrub.

static size_t g_wlOk = 0, g_wlFailed = 0, g_wlMissing = 0;
static bool g_wlDangle = false; // --workload-dangle: destroy a bound texture without unbinding it first
static bool g_wlStaleDraw = false; // --workload-stale-draw: after destroy, issue another draw before the next bind
static bool g_wlReset = false; // --workload-reset: between iterations, run the device-lost/Reset DDI sequence
static int  g_passiveWatchSec = 0; // --passive-watch N: arm BPs on the already-loaded atiumd6a.dll, wait N seconds
static bool g_hwTest = false;      // --hw-test: real-hardware fix verification (implies --kmt-forward --qai-forward
                                   // --bp-clear --device --workload --workload-dangle --workload-stale-draw).
                                   // PASS/FAIL is based on g_clearAHits rather than decoy writes.
                                   // Bug proof: expect hits > 0.  Fix proof (+ --workload-fix-unbind): expect 0.
static bool g_wlFixUnbind = false; // --workload-fix-unbind: unbind all stages immediately before each DestroyResource,
                                   // modelling the fix applied to MPCVR and the built-in renderer.

static void WlResult(const char* what, HRESULT hr)
{
    if (SUCCEEDED(hr)) g_wlOk++;
    else g_wlFailed++;
    Log("  workload: %-28s = %08lx", what, hr);
}

static void WlMissing(const char* what)
{
    g_wlMissing++;
    Log("  workload: %-28s skipped, the driver filled no entry point", what);
}

// The pieces of a workload round, shared by the serial and batch modes so the DDI argument structs exist
// in exactly one place.

// One 64x64 A8R8G8B8 texture in the DEFAULT pool. rtHandle is the handle value the fake runtime assigns;
// the driver may replace it. Returns the live handle, or nullptr when creation failed or is unsupported.
static HANDLE WlCreateTexture(HANDLE hDevice, D3DDDI_DEVICEFUNCS* df, UINT_PTR rtHandle)
{
    if (!df->pfnCreateResource) { WlMissing("CreateResource"); return nullptr; }
    D3DDDI_SURFACEINFO surf = {};
    surf.Width = 64;
    surf.Height = 64;
    surf.Depth = 1;
    D3DDDIARG_CREATERESOURCE cr = {};
    cr.Format = D3DDDIFMT_A8R8G8B8;
    cr.Pool = D3DDDIPOOL_VIDEOMEMORY;
    cr.MultisampleType = D3DDDIMULTISAMPLE_NONE;
    cr.pSurfList = &surf;
    cr.SurfCount = 1;
    cr.MipLevels = 1;
    cr.Flags.Texture = 1;
    cr.Rotation = D3DDDI_ROTATION_IDENTITY;
    cr.hResource = (HANDLE)rtHandle;
    HRESULT hr = df->pfnCreateResource(hDevice, &cr);
    WlResult("CreateResource(texture)", hr);
    return SUCCEEDED(hr) ? cr.hResource : nullptr;
}

// All 8 texture stages: MODULATE colour, linear magnification and minification.
static void WlTextureStageState(HANDLE hDevice, D3DDDI_DEVICEFUNCS* df)
{
    if (df->pfnSetTextureStageState) {
        D3DDDIARG_TEXTURESTAGESTATE tss = {};
        for (UINT s = 0; s < 8; s++) {
            tss.Stage = s;
            tss.State = D3DDDITSS_COLOROP;
            tss.Value = D3DTOP_MODULATE;
            WlResult("SetTSS(COLOROP=MODULATE)", df->pfnSetTextureStageState(hDevice, &tss));
            tss.State = D3DDDITSS_MAGFILTER;
            tss.Value = D3DDDITEXF_LINEAR;
            WlResult("SetTSS(MAGFILTER=LINEAR)", df->pfnSetTextureStageState(hDevice, &tss));
            tss.State = D3DDDITSS_MINFILTER;
            WlResult("SetTSS(MINFILTER=LINEAR)", df->pfnSetTextureStageState(hDevice, &tss));
        }
    } else WlMissing("SetTextureStageState");
}

// Point stream 0 at the user-memory triangle and draw it.
static void WlDrawTriangle(HANDLE hDevice, D3DDDI_DEVICEFUNCS* df, const float* verts)
{
    if (df->pfnSetStreamSourceUm) {
        D3DDDIARG_SETSTREAMSOURCEUM ss = {};
        ss.Stream = 0;
        ss.Stride = 3 * sizeof(float);
        WlResult("SetStreamSourceUm(0)", df->pfnSetStreamSourceUm(hDevice, &ss, verts));
    } else WlMissing("SetStreamSourceUm");

    if (df->pfnDrawPrimitive) {
        if (g_forceFlush || g_fakeDrawParams) {
            *(DWORD*)((uintptr_t)hDevice + 0x47B0) = 1;
            Log("  force-flush: set [hDevice+0x47B0]=1 (was %d)", *(DWORD*)((uintptr_t)hDevice + 0x47B0));
        }
        D3DDDIARG_DRAWPRIMITIVE dp = {};
        dp.PrimitiveType = D3DPT_TRIANGLELIST;
        dp.VStart = 0;
        dp.PrimitiveCount = 1;
        WlResult("DrawPrimitive(tri)", df->pfnDrawPrimitive(hDevice, &dp, nullptr));
    } else if (df->pfnDrawPrimitive2) {
        D3DDDIARG_DRAWPRIMITIVE2 dp = {};
        dp.PrimitiveType = D3DPT_TRIANGLELIST;
        dp.FirstVertexOffset = 0;
        dp.PrimitiveCount = 1;
        WlResult("DrawPrimitive2(tri)", df->pfnDrawPrimitive2(hDevice, &dp));
    } else WlMissing("DrawPrimitive");
}

// A draw issued against a state block whose bound texture was just destroyed (--workload-stale-draw).
static void WlStaleDraw(HANDLE hDevice, D3DDDI_DEVICEFUNCS* df, const char* what)
{
    if (!df->pfnDrawPrimitive) return;
    if (g_fakeDrawParams) *(DWORD*)((uintptr_t)hDevice + 0x47B0) = 1;
    D3DDDIARG_DRAWPRIMITIVE dp = {};
    dp.PrimitiveType = D3DPT_TRIANGLELIST;
    dp.VStart = 0;
    dp.PrimitiveCount = 1;
    WlResult(what, df->pfnDrawPrimitive(hDevice, &dp, nullptr));
    if (df->pfnFlush) WlResult("Flush", df->pfnFlush(hDevice));
}

// --workload-reset: the device-lost/Reset step, run between workload iterations. There is no pfnReset in the
// WDDM UMD DDI (the D3DDDI_DEVICEFUNCS table at d3dumddi.h:3240-3397 has nothing of the kind): when the runtime
// services IDirect3DDevice9::Reset it does the invalidation itself. The sequence here follows that:
//
//   1. pfnPresent            - how the runtime learns the device is lost: Present returns
//                              D3DDDIERR_DEVICELOST / D3DDDIERR_DEVICEREMOVED (d3dumddi.h:3018-3019 for the
//                              prototype, :4723 for DEVICEREMOVED; the D3DDDIARG_PRESENT layout is at :48-56).
//   2. pfnFlush              - the pipe is drained before anything is torn down.
//   3. pfnDestroyResource    - en masse, on every D3DPOOL_DEFAULT resource the runtime tracks. Nothing unbinds
//                              them from the state block first: Reset releases the runtime's references, and
//                              the UMD never receives a SetTexture(0) for a handle it still counts as bound.
//   4. pfnCreateResource     - the implicit DEFAULT set (backbuffer, depth stencil) is re-created; app-owned
//                              DEFAULT resources are simply released. (Shared resources come back through
//                              pfnOpenResource instead; this workload's textures are not shared.)
//   5. pfnSetDisplayMode     - a fullscreen Reset ends by re-establishing the primary (prototype at
//                              d3dumddi.h:3016-3017, D3DDDIARG_SETDISPLAYMODE at :25-29).
//
// With --workload-stale-draw a state-apply is inserted after step 3: the draw walks the state block while its
// bound-texture slot still holds a handle the driver just destroyed, which is the crash shape the field dumps
// show after Alt-Tab out of a fullscreen-exclusive app.
static void RunWorkloadReset(HANDLE hDevice, D3DDDI_DEVICEFUNCS* df, std::vector<HANDLE>& tracked)
{
    Log("  workload: --- device-lost/Reset step, %zu tracked DEFAULT-pool resources ---", tracked.size());

    if (df->pfnPresent) {
        D3DDDIARG_PRESENT p = {};
        p.hSrcResource = tracked.empty() ? nullptr : tracked.back();
        p.Flags.Blt = 1;
        WlResult("Present(lost-device poll)", df->pfnPresent(hDevice, &p));
    } else WlMissing("Present");

    if (df->pfnFlush) WlResult("Flush(pre-Reset)", df->pfnFlush(hDevice));
    else WlMissing("Flush");

    // The bulk invalidation. No unbind first: that is the point of the mode.
    for (HANDLE h : tracked) {
        if (df->pfnDestroyResource) WlResult("DestroyResource(Reset)", df->pfnDestroyResource(hDevice, h));
        else WlMissing("DestroyResource");
    }

    if (g_wlStaleDraw && df->pfnDrawPrimitive) {
        D3DDDIARG_DRAWPRIMITIVE dp = {};
        dp.PrimitiveType = D3DPT_TRIANGLELIST;
        dp.VStart = 0;
        dp.PrimitiveCount = 1;
        WlResult("DrawPrimitive(post-Reset stale)", df->pfnDrawPrimitive(hDevice, &dp, nullptr));
        if (df->pfnFlush) WlResult("Flush(post-Reset)", df->pfnFlush(hDevice));
    }

    // Re-create what was destroyed. The recreated handles stay tracked, so the next iteration's Reset
    // invalidates a growing set, the way a long-running app's implicit resources accumulate.
    std::vector<HANDLE> recreated;
    for (size_t k = 0; k < tracked.size(); k++) {
        if (df->pfnCreateResource) {
            D3DDDI_SURFACEINFO surf = {};
            surf.Width = 64;
            surf.Height = 64;
            surf.Depth = 1;
            D3DDDIARG_CREATERESOURCE cr = {};
            cr.Format = D3DDDIFMT_A8R8G8B8;
            cr.Pool = D3DDDIPOOL_VIDEOMEMORY;
            cr.MultisampleType = D3DDDIMULTISAMPLE_NONE;
            cr.pSurfList = &surf;
            cr.SurfCount = 1;
            cr.MipLevels = 1;
            cr.Flags.Texture = 1;
            cr.Rotation = D3DDDI_ROTATION_IDENTITY;
            cr.hResource = (HANDLE)(UINT_PTR)(0x60000 + k); // the runtime's handle; the driver replaces it
            HRESULT hr = df->pfnCreateResource(hDevice, &cr);
            WlResult("CreateResource(Reset re-create)", hr);
            if (SUCCEEDED(hr)) recreated.push_back(cr.hResource);
        } else WlMissing("CreateResource");
    }
    tracked.swap(recreated);

    if (df->pfnSetDisplayMode) {
        D3DDDIARG_SETDISPLAYMODE sdm = {};
        sdm.hResource = tracked.empty() ? nullptr : tracked.front();
        sdm.SubResourceIndex = 0;
        WlResult("SetDisplayMode(Reset)", df->pfnSetDisplayMode(hDevice, &sdm));
    } else WlMissing("SetDisplayMode");

    // Deliberately no SetTexture here: the state block keeps the pre-Reset binding, and only the next
    // iteration's bind overwrites it.
}

static void RunWorkload(HANDLE hDevice, D3DDDI_DEVICEFUNCS* df, size_t rounds)
{
    size_t ok0 = g_wlOk, failed0 = g_wlFailed, missing0 = g_wlMissing;
    // One triangle in user memory, bound through SetStreamSourceUm the way the runtime handles
    // DrawPrimitiveUP: three vertices of three floats each.
    static const float verts[9] = {
        -0.5f, -0.5f, 0.5f,
         0.5f, -0.5f, 0.5f,
         0.0f,  0.5f, 0.5f,
    };
    // Everything the fake runtime is tracking in the DEFAULT pool. The Reset step invalidates this set in
    // bulk; without --workload-reset it never holds more than the current round's texture.
    std::vector<HANDLE> tracked;
    for (size_t i = 0; i < rounds; i++) {
        HANDLE hTex = WlCreateTexture(hDevice, df, 0x50000 + i);
        if (hTex) tracked.push_back(hTex);

        if (hTex) {
            if (df->pfnSetTexture)
                for (UINT s = 0; s < 8; s++) WlResult("SetTexture(stage N)", df->pfnSetTexture(hDevice, s, hTex));
            else WlMissing("SetTexture");
        }

        WlTextureStageState(hDevice, df);
        WlDrawTriangle(hDevice, df, verts);

        // --workload-reset: between iterations the runtime's Reset path replaces the round's own teardown.
        // The Reset step does the destroying (with no unbind, Reset semantics), so --workload-dangle is
        // implied for this round, and --workload-stale-draw's post-destroy draw happens inside the step,
        // against the state block the invalidation left stale.
        if (g_wlReset && i + 1 < rounds) {
            RunWorkloadReset(hDevice, df, tracked);
            continue;
        }

        if (hTex) {
            // A real runtime unbinds before destroying the texture; a sloppy app destroys a bound one, and the
            // state block keeps the raw pointer, which the next draw walks. --workload-dangle leaves the slot
            // bound so the next round's bind-and-draw sequence runs through the dangling pointer.
            if (!g_wlDangle && df->pfnSetTexture)
                for (UINT s = 0; s < 8; s++) WlResult("SetTexture(N, unbind)", df->pfnSetTexture(hDevice, s, nullptr));
            if (g_wlFixUnbind && df->pfnSetTexture) {
                for (UINT s = 0; s < 8; s++) WlResult("SetTexture(N, fix-unbind)", df->pfnSetTexture(hDevice, s, nullptr));
            }
            if (df->pfnDestroyResource) {
                WlResult("DestroyResource", df->pfnDestroyResource(hDevice, hTex));
                tracked.erase(std::find(tracked.begin(), tracked.end(), hTex));
            }
            else WlMissing("DestroyResource");
        }
        if (g_wlStaleDraw) WlStaleDraw(hDevice, df, "DrawPrimitive(stale)");
    }
    // Resources the last Reset re-created are never bound and never destroyed by a round's own teardown;
    // destroy them here so DestroyDevice does not meet live resources the runtime would have cleaned up.
    for (HANDLE h : tracked) {
        if (df->pfnDestroyResource) WlResult("DestroyResource(leftover)", df->pfnDestroyResource(hDevice, h));
        else WlMissing("DestroyResource");
    }
    Log("workload: %zu rounds, %zu calls succeeded, %zu failed, %zu skipped (no entry point)", rounds,
        g_wlOk - ok0, g_wlFailed - failed0, g_wlMissing - missing0);
}

// --workload-batch N: each round creates N textures and holds them ALL live at once, drawing through each
// in turn, before any is destroyed. The serial mode destroys each texture before creating the next, so the
// heap allocator hands back the same freed 152-byte resource-tracking block every time and a whole session
// sees one unique driver allocation in that class. Holding N live scatters N distinct driver allocations
// through the size class's free list, among the planted decoys, and the checkpoint while they are live is
// where the adjacency the #4257 investigation is after would show.
//
// --workload-rounds repeats the whole create-N / draw / destroy-N cycle. --workload-dangle keeps its
// meaning: the mass destroy runs with the last texture still bound to stage 0. --workload-stale-draw draws
// once more after the mass destroy, against the state block that still points at the last bound texture.
static void RunWorkloadBatch(HANDLE hDevice, D3DDDI_DEVICEFUNCS* df, size_t batchSize, size_t rounds)
{
    size_t ok0 = g_wlOk, failed0 = g_wlFailed, missing0 = g_wlMissing;
    static const float verts[9] = {
        -0.5f, -0.5f, 0.5f,
         0.5f, -0.5f, 0.5f,
         0.0f,  0.5f, 0.5f,
    };
    size_t created = 0, destroyed = 0;
    std::vector<HANDLE> tracked; // for the Reset step, as in the serial mode
    for (size_t r = 0; r < rounds; r++) {
        Log("  workload(batch): --- round %zu of %zu, holding %zu textures live ---", r + 1, rounds, batchSize);
        std::vector<HANDLE> live;
        for (size_t i = 0; i < batchSize; i++) {
            HANDLE h = WlCreateTexture(hDevice, df, 0x50000 + r * batchSize + i);
            if (h) { live.push_back(h); tracked.push_back(h); created++; }
        }
        // Draw through every texture while the whole batch stays live.
        for (HANDLE h : live) {
            if (df->pfnSetTexture)
                for (UINT s = 0; s < 8; s++) WlResult("SetTexture(stage N)", df->pfnSetTexture(hDevice, s, h));
            else WlMissing("SetTexture");
            WlTextureStageState(hDevice, df);
            WlDrawTriangle(hDevice, df, verts);
        }
        // Scan the heap while the N driver-side resource blocks are all live and scattered.
        char cp[64];
        snprintf(cp, sizeof cp, "batch round %zu: %zu textures live", r + 1, live.size());
        Checkpoint(cp);

        // As in the serial mode: with --workload-reset the Reset step replaces the round's own teardown,
        // destroying the tracked set with no unbind.
        if (g_wlReset && r + 1 < rounds) {
            RunWorkloadReset(hDevice, df, tracked);
            live.clear();
            continue;
        }

        if (!g_wlDangle && df->pfnSetTexture)
            for (UINT s = 0; s < 8; s++) WlResult("SetTexture(N, unbind)", df->pfnSetTexture(hDevice, s, nullptr));
        if (g_wlFixUnbind && df->pfnSetTexture) {
            for (UINT s = 0; s < 8; s++) WlResult("SetTexture(N, fix-unbind)", df->pfnSetTexture(hDevice, s, nullptr));
        }
        for (HANDLE h : live) {
            if (df->pfnDestroyResource) {
                WlResult("DestroyResource", df->pfnDestroyResource(hDevice, h));
                tracked.erase(std::find(tracked.begin(), tracked.end(), h));
                destroyed++;
            }
            else WlMissing("DestroyResource");
        }
        if (g_wlStaleDraw) WlStaleDraw(hDevice, df, "DrawPrimitive(stale)");
    }
    for (HANDLE h : tracked) {
        if (df->pfnDestroyResource) WlResult("DestroyResource(leftover)", df->pfnDestroyResource(hDevice, h));
        else WlMissing("DestroyResource");
    }
    Log("workload(batch): %zu rounds x %zu textures: %zu created, %zu destroyed; %zu calls succeeded,"
        " %zu failed, %zu skipped (no entry point)", rounds, batchSize, created, destroyed,
        g_wlOk - ok0, g_wlFailed - failed0, g_wlMissing - missing0);
}

// --patch rva=hexbytes, applied to the driver's image after import hooks: forces an experiment on driver code.
static std::vector<std::pair<UINT, std::vector<unsigned char>>> g_patches;

static void ApplyPatches(HMODULE mod)
{
    for (auto& p : g_patches) {
        BYTE* at = (BYTE*)mod + p.first;
        DWORD old;
        if (!VirtualProtect(at, p.second.size(), PAGE_EXECUTE_READWRITE, &old)) { Log("patch at +%x: VirtualProtect failed", p.first); continue; }
        memcpy(at, p.second.data(), p.second.size());
        VirtualProtect(at, p.second.size(), old, &old);
        Log("patched driver at +%x with %zu bytes", p.first, p.second.size());
    }
}

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

// The d3d9 shim build brings its own entry point; wmain stays for the exe and the injectable probe,
// whose Legacy9Run calls it.
#if !defined(D3D9SHIM_DLL)
int wmain(int argc, wchar_t** argv)
{
    const wchar_t* dll = nullptr;
    const wchar_t* logPath = L"legacy9.log";
    const wchar_t* jsonPath = nullptr;
    UINT iface = D3D_UMD_INTERFACE_VERSION_WIN7, version = 0x10;
    size_t decoys = 256, rounds = 1;
    DWORD delayMs = 0;
    bool closeOnly = false, selfTest = true, noDriver = false, withDevice = false;
    bool withWorkload = false;
    size_t workloadRounds = 4;
    size_t workloadBatch = 0; // --workload-batch: textures held live at once; 0 = serial mode
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
        else if (!wcscmp(argv[i], L"--qai-fill2") && i + 1 < argc) g_qaiFill2 = wcstoul(argv[++i], nullptr, 0) & 0xff;
        else if (!wcscmp(argv[i], L"--qai-index2")) g_qaiIndex2 = true;
        else if (!wcscmp(argv[i], L"--bp")) g_breakpoints = true;
        else if (!wcscmp(argv[i], L"--bp-clear")) g_bpClear = true;
        else if (!wcscmp(argv[i], L"--plant-710465")) g_plant710465 = true;
        else if (!wcscmp(argv[i], L"--force-flush")) g_forceFlush = true;
        else if (!wcscmp(argv[i], L"--fake-draw-params")) g_fakeDrawParams = true;
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
        else if (!wcscmp(argv[i], L"--qai-set2") && i + 1 < argc) {
            for (wchar_t* s = argv[++i]; s && *s;) {
                wchar_t* end;
                UINT off = wcstoul(s, &end, 0);
                if (*end != L'=') break;
                UINT val = wcstoul(end + 1, &end, 0);
                g_qaiSet2.push_back({ off, val });
                s = *end == L',' ? end + 1 : nullptr;
            }
        }
        else if (!wcscmp(argv[i], L"--qai-fill-range") && i + 1 < argc) {
            wchar_t* s = argv[++i];
            wchar_t* end;
            QaiFillRange r = {};
            r.off = wcstoul(s, &end, 0);
            if (*end == L':') {
                r.len = wcstoul(end + 1, &end, 0);
                if (*end == L':') {
                    r.byte = wcstoul(end + 1, &end, 0) & 0xff;
                    g_qaiFillRange.push_back(r);
                }
            }
        }
        else if (!wcscmp(argv[i], L"--qai-fill-range2") && i + 1 < argc) {
            wchar_t* s = argv[++i];
            wchar_t* end;
            QaiFillRange r = {};
            r.off = wcstoul(s, &end, 0);
            if (*end == L':') {
                r.len = wcstoul(end + 1, &end, 0);
                if (*end == L':') {
                    r.byte = wcstoul(end + 1, &end, 0) & 0xff;
                    g_qaiFillRange2.push_back(r);
                }
            }
        }
        else if (!wcscmp(argv[i], L"--kmt-forward")) g_kmtForward = true;
        else if (!wcscmp(argv[i], L"--kmt-fake")) g_kmtFake = true;
        else if (!wcscmp(argv[i], L"--passive-watch") && i + 1 < argc) {
            // Arm clear BPs on the already-loaded atiumd6a.dll (injected into a live player), wait N
            // seconds, then print the clear.A hit count. No fake device is created; MPCVR's own draws
            // trigger the BPs. Useful for confirming the bug fires naturally from a Reset / format change.
            g_passiveWatchSec = _wtoi(argv[++i]);
            g_bpClear = true;
        }
        else if (!wcscmp(argv[i], L"--hw-test")) {
            // Real-hardware fix verification. Implies everything needed to reach atiumd6a's clear path
            // via the native GPU draw pipeline. Use --workload-fix-unbind alongside to test the fix.
            g_hwTest = true;
            g_kmtForward = true;
            g_qaiForward = true;
            g_bpClear = true;
            withDevice = true;
            withWorkload = true;
            g_wlDangle = true;
            g_wlStaleDraw = true;
        }
        else if (!wcscmp(argv[i], L"--load-only")) closeOnly = true;
        else if (!wcscmp(argv[i], L"--no-self-test")) selfTest = false;
        else if (!wcscmp(argv[i], L"--no-driver")) noDriver = true;
        else if (!wcscmp(argv[i], L"--device")) withDevice = true;
        else if (!wcscmp(argv[i], L"--workload")) withWorkload = true;
        else if (!wcscmp(argv[i], L"--workload-rounds") && i + 1 < argc) workloadRounds = wcstoul(argv[++i], nullptr, 0);
        else if (!wcscmp(argv[i], L"--workload-batch")) {
            // The value is optional so the flag reads like the other workload switches; --workload-batch
            // alone means 32.
            workloadBatch = 32;
            if (i + 1 < argc && argv[i + 1][0] >= L'0' && argv[i + 1][0] <= L'9')
                workloadBatch = wcstoul(argv[++i], nullptr, 0);
            withWorkload = true;
        }
        else if (!wcscmp(argv[i], L"--workload-dangle")) g_wlDangle = true;
        else if (!wcscmp(argv[i], L"--workload-stale-draw")) g_wlStaleDraw = true;
        else if (!wcscmp(argv[i], L"--workload-reset")) g_wlReset = true;
        else if (!wcscmp(argv[i], L"--workload-fix-unbind")) g_wlFixUnbind = true;
        else if (!wcscmp(argv[i], L"--escape-zero")) g_escapeZero = true;
        else if (!wcscmp(argv[i], L"--sysmem")) g_sysmem = true;
        else if (!wcscmp(argv[i], L"--gpu-va-base") && i + 1 < argc) g_gpuVaBase = wcstoull(argv[++i], nullptr, 0);
        else if (!wcscmp(argv[i], L"--patch") && i + 1 < argc) {
            wchar_t* end;
            UINT rva = wcstoul(argv[++i], &end, 0);
            std::vector<unsigned char> bytes;
            if (end && *end == L'=')
                for (const wchar_t* s = end + 1; s[0] && s[1]; s += 2) {
                    wchar_t pair[3] = { s[0], s[1], 0 };
                    bytes.push_back((unsigned char)wcstoul(pair, nullptr, 16));
                }
            g_patches.push_back({ rva, bytes });
        }
        else if (!wcscmp(argv[i], L"--lock-size") && i + 1 < argc) g_lockSize = (SIZE_T)wcstoull(argv[++i], nullptr, 0);
        else if (!wcscmp(argv[i], L"--json") && i + 1 < argc) jsonPath = argv[++i];
        else { wprintf(L"unknown option %s\n", argv[i]); return 2; }
    }
    if (!dll && !noDriver) {
        wprintf(L"usage: legacy9 --dll <path to atiumd64.dll> [--redzone] [--decoys n] [--rounds n] [--delay ms]\n"
                L"               [--iface 0x..] [--version n] [--qai-set off=val,...] [--qai-set2 off=val,...] [--qai-fill 0x..] [--qai-fill2 0x..]\n"
                L"               [--qai-fill-range off:len:byte ...] [--qai-fill-range2 off:len:byte ...]\n"
                L"               [--qai-forward] [--kmt-forward] [--trace-allocs] [--load-only] [--log path]\n"
                L"               [--json path] [--no-self-test] [--device] [--workload [--workload-rounds n] [--workload-dangle]\n"
                L"               [--workload-stale-draw] [--workload-reset] [--workload-batch [n]]]\n"
                L"       legacy9 --no-driver [--decoys n] [--json path]\n"
                L"               measures the heap and proves the damage detector fires, with no driver at all\n");
        return 2;
    }

    // Opened so it can be read while the probe is still running, which matters when the host is a long-lived
    // process such as the player.
    if (g_logHandle != INVALID_HANDLE_VALUE) { CloseHandle(g_logHandle); g_logHandle = INVALID_HANDLE_VALUE; }
    g_logHandle = CreateFileW(logPath, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
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

    if (g_passiveWatchSec > 0) {
        // Passive-watch mode: arm BPs on atiumd6a.dll already in this process (MPCVR loaded it),
        // wait for the player to trigger a Reset or format change, then report clear.A hits.
        // No fake device is created; this is purely observational.
        HMODULE aMod = LoadLibraryExW(full, nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
        if (aMod) HookImports(aMod);
        HMODULE a6a = GetModuleHandleW(L"atiumd6a.dll");
        if (a6a) {
            Log("passive-watch: atiumd6a.dll at %p; arming clear write sites + caller gates", (void*)a6a);
            ArmBp(a6a, 0x12EA32, "clear.A");
            ArmBp(a6a, 0x12E946, "clrzero");
            ArmBp(a6a, 0x0F44EC, "clear.B");
            ArmBp(a6a, 0x0F7305, "clear.1");
            ArmBp(a6a, 0x1EBD09, "clear.2");
            ArmBp(a6a, 0x1FED70, "clear.3");
            ArmBp(a6a, 0x12C950, "flush");
            ArmBp(a6a, 0x12E260, "relobj");
            ArmBp(a6a, 0x0F4520, "tss.disp");
            ArmBp(a6a, 0x11A420, "gate");
        } else {
            Log("passive-watch: atiumd6a.dll not found in process; BPs not armed (player may not use this driver)");
        }
        Log("passive-watch: watching for %d seconds -- trigger a format change or seek in the player now",
            g_passiveWatchSec);
        Sleep((DWORD)(g_passiveWatchSec * 1000));
        Log("SUMMARY: clear.A hits=%zu", g_clearAHits);
        if (g_clearAHits > 0) Log("PROBE DONE (passive-watch: clear.A fired %zu times -- bug confirmed)", g_clearAHits);
        else                  Log("PROBE DONE (passive-watch: clean -- no clear.A hits in %ds)", g_passiveWatchSec);
        // (WriteFile is unbuffered; no fflush needed)
        return rc;
    }

    if (rounds) Checkpoint("before load");

    HRESULT lastOpenHr = E_FAIL, lastCreateDeviceHr = E_FAIL;
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
        ApplyPatches(mod);
        Checkpoint(at("after load"));

        // Arm the teardown-path BPs before OpenAdapter: the mmobj factory runs during OpenAdapter,
        // so arming in the device phase (the g_breakpoints block below) misses the creation store.
        if (g_breakpoints) {
            ArmBp(mod, 0x1E9C8, "mmdev.done");  // store of the mmobj factory result to [settings+0x5028]
            ArmBp(mod, 0x94E3,  "dtor.field");  // the field crash's destroy caller (atiumd64+0x94E3)
        }

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
            // The device phase. The field dumps all have the driver unloaded by the time they were written, so
            // the driver had been through CreateDevice and teardown; that is the window, and the adapter phase
            // before it barely touches the heap.
            if (SUCCEEDED(hr) && withDevice && funcs.pfnCreateDevice) {
                static D3DDDI_DEVICECALLBACKS devCb;
                FillDeviceCallbacks(&devCb);

                static int rtDevice = 'cveD';
                void* devFuncs[512] = {};
                FakeContext deviceBuffers{};
                if (!SizeContext(&deviceBuffers, 0, 0, 0)) { Log("out of memory for the device buffers"); return 1; }

                D3DDDIARG_CREATEDEVICE cd = {};
                cd.hDevice = &rtDevice;
                cd.Interface = iface;
                cd.Version = version;
                cd.pCallbacks = &devCb;
                cd.pCommandBuffer = deviceBuffers.cmd;
                cd.CommandBufferSize = deviceBuffers.cmdSize;
                cd.pAllocationList = deviceBuffers.allocList;
                cd.AllocationListSize = deviceBuffers.allocListSize;
                cd.pPatchLocationList = deviceBuffers.patchList;
                cd.PatchLocationListSize = deviceBuffers.patchListSize;
                cd.pDeviceFuncs = (D3DDDI_DEVICEFUNCS*)devFuncs;
                cd.CommandBuffer = deviceBuffers.cmdGpuVa;

                size_t stubsBefore = g_devStubHits;
                // --bp watches the command-buffer machinery with int3 breakpoints handled by the VEH: the
                // acquire callback, the flush/new-buffer pair, the allocation factory, the ring setup. The
                // offsets are into this specific 2015 atiumd64.dll.
                if (g_breakpoints) {
                    ArmBp(mod, 0x7F9C0, "acquire");
                    ArmBp(mod, 0x574D0, "flush");
                    ArmBp(mod, 0x565B0, "newbuf");
                    ArmBp(mod, 0x565E4, "newbuf.chk");
                    ArmBp(mod, 0x70460, "allocfactory");
                    ArmBp(mod, 0x71280, "cpuptr");
                    ArmBp(mod, 0x5330B0, "eng.acquire");
                    ArmBp(mod, 0x51A550, "getwriteptr");
                    ArmBp(mod, 0x556D0, "chunkinit");
                    ArmBp(mod, 0x55989, "chunkinit.fill");
                    ArmBp(mod, 0x58A90, "pipesel");
                    ArmBp(mod, 0x58600, "pipeswitch");
                    ArmBp(mod, 0x58D94, "fill.setup");
                    ArmBp(mod, 0x58E27, "fill.rec");
                    ArmBp(mod, 0x58DEE, "init.gate");
                    ArmBp(mod, 0x58D1C, "init.pre");
                    ArmBp(mod, 0x58EA3, "init.skip");
                    ArmBp(mod, 0x58740, "ringmap");
                    ArmBp(mod, 0x587DD, "ringmap.fail");
                    ArmBp(mod, 0x58776, "ringmap.reuse");
                    ArmBp(mod, 0x6D420, "ringdiv");
                }
                HRESULT dhr = funcs.pfnCreateDevice(oa.hAdapter, &cd);
                lastCreateDeviceHr = dhr;
                size_t filled = 0;
                for (size_t i = 0; i < 512; i++) if (devFuncs[i]) filled++;
                Log("CreateDevice = %08lx  device funcs filled: %zu slots  callback stubs hit: %zu", dhr, filled,
                    g_devStubHits - stubsBefore);
                { char w1[128], w2[128], w3[128];
                  Log("  pfnSetTextureStageState=%s  pfnSetTexture=%s  pfnDrawPrimitive=%s",
                      Where((void*)devFuncs[3], w1, sizeof w1),
                      Where((void*)devFuncs[4], w2, sizeof w2),
                      Where((void*)devFuncs[10], w3, sizeof w3));
                  if (g_bpClear && devFuncs[3] && devFuncs[10]) {
                      ArmBp(mod, (uintptr_t)devFuncs[3]  - (uintptr_t)mod, "pfnTSS.entry");
                      ArmBp(mod, (uintptr_t)devFuncs[10] - (uintptr_t)mod, "pfnDraw.entry");
                      ArmBp(mod, 0x30310, "stateApply");   // called from deferred-flush when [dev+0x47B0]>0
                      ArmBp(mod, 0x2DE40, "deferFlush");   // the deferred-flush gate itself
                  } }
                Log("    fake kernel so far: %zu allocations, %zu contexts, %zu submissions", g_fakeAllocs.size(),
                    g_fakeContexts.size(), g_submits);
                Checkpoint(at("after CreateDevice"));

                if (SUCCEEDED(dhr)) {
                    auto* df = (D3DDDI_DEVICEFUNCS*)devFuncs;
                    // Log the gate flag and dirty count before the workload
                    if (cd.hDevice) {
                        DWORD flags18 = *(DWORD*)((uintptr_t)cd.hDevice + 0x18);
                        DWORD dc47B0  = *(DWORD*)((uintptr_t)cd.hDevice + 0x47B0);
                        DWORD dc47C0  = *(DWORD*)((uintptr_t)cd.hDevice + 0x47C0);
                        DWORD dc4740  = *(DWORD*)((uintptr_t)cd.hDevice + 0x4740);
                        { char wgfp[128];
                          void* gfp = *(void**)((uintptr_t)mod + 0x7F45C0);
                          Log("  atiumd64+0x7F45C0 (cross-DLL fn ptr) = %p %s",
                              gfp, Where(gfp, wgfp, sizeof wgfp)); }
                        Log("  [hDevice+0x18]=0x%08lx gate=%-3s  [+0x47B0]=%d [+0x47C0]=%d [+0x4740]=%d (dirty counts pre-workload)",
                            flags18, (flags18 & 0x100000) ? "SET" : "clr", dc47B0, dc47C0, dc4740);
                    }
                    if (g_fakeDrawParams && cd.hDevice) {
                        uint8_t* buf = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x1000);
                        if (buf) {
                            uint8_t* fake_rbp = buf;
                            uint8_t* fake_r14 = buf + 0x400;
                            uint8_t* state1   = buf + 0x800;
                            uint8_t* state2   = buf + 0xC00;
                            *(void**)(fake_rbp + 0x1B8) = state1;
                            *(void**)(fake_r14 + 0x1B8) = state2;
                            // atiumd64:0x80B88/0x80D97 (surface-format resolver under the flush): reads
                            // [params+0x40] and then dereferences it for a flags dword; null crashes at
                            // atiumd64+0x80D9B. The resolver runs on both draw-param structs (the crash was
                            // on fake_r14's), so point both at zeroed memory: all bt tests fall through.
                            *(void**)(fake_rbp + 0x40) = state1;
                            *(void**)(fake_r14 + 0x40) = state2;
                            *(void**)((uintptr_t)cd.hDevice + 0x4958) = fake_rbp;
                            *(void**)((uintptr_t)cd.hDevice + 0x4960) = fake_r14;
                            *(DWORD*)((uintptr_t)cd.hDevice + 0x47B0) = 1;
                            Log("fake-draw-params: buf=%p  [+0x4958]=buf  [+0x4960]=buf+0x400  [+0x47B0]=1",
                                (void*)buf);

                            // Fake state vtables: atiumd6a:0x2180 reads state->vtable at [+0x0].
                            // vtable[10](+0x50) must return a struct where [+0x0]==1 (atiumd6a+0x1229F);
                            // vtable[7](+0x38) must return != 0 for the gate inside 0x13C950.
                            // [state1+0x1A0] must be non-zero so the 0x1241A branch at atiumd6a:0x2180
                            // proceeds to the state-flush call rather than the early exit at 0x124EF.
                            InitFakeVtbls();
                            *(void**)state1 = s_fakeStateVtbl;
                            *(void**)state2 = s_fakeStateVtbl;
                            // 0x13C9BD: call [rax+0x38] where rax=[fake_rbp]; needs vtable[7]=StubRet1
                            *(void**)fake_rbp = s_fakeStateVtbl;
                            *(void**)fake_r14 = s_fakeStateVtbl;
                            *(ULONG_PTR*)(state1 + 0x1A0) = 1;
                            Log("fake-state-vtables: state1=%p state2=%p fake_rbp=%p vtbl=%p [state1+0x1A0]=1",
                                (void*)state1, (void*)state2, (void*)fake_rbp, (void*)s_fakeStateVtbl);

                            // Fake channel object: the flush gate at atiumd64:0x2FF90 reads
                            // [[device_inner+0x600]+0x20] and skips atiumd6a:0x2180 when null. Supply a fake
                            // channel whose vtable satisfies:
                            //   [+0x78] (index 15) must return 0  -> continue past the gate at 0x121C1
                            //   [+0x90] (index 18) must return !=0 -> checker 0x12640 skips the null-ptr paths
                            // device_inner = [hDevice+0x10]; channel_holder = [device_inner+0x600].
                            InstallFakeChannel(cd.hDevice);
                        } else Log("fake-draw-params: HeapAlloc failed");
                    }
                    if (withWorkload) {
                        Checkpoint(at("before workload"));
                        if (workloadBatch) RunWorkloadBatch(cd.hDevice, df, workloadBatch, workloadRounds);
                        else RunWorkload(cd.hDevice, df, workloadRounds);
                        Checkpoint(at("after workload"));
                        g_workloadDone = true;
                        Log("SUMMARY: decoy hits=%zu (%zu decoys)  clear.A hits=%zu",
                            g_decoyHits, g_decoys.size(), g_clearAHits);
                        if (g_hwTest) {
                            // On real TeraScale hardware the clear path runs via the native GPU pipeline;
                            // g_clearAHits is the authoritative signal (no fake channel needed).
                            if (g_wlFixUnbind) {
                                if (g_clearAHits == 0) Log("PROBE DONE (hw-test fix: PASS — SetTexture(null) suppressed clear write)");
                                else                   Log("PROBE DONE (hw-test fix: FAIL — %zu clear.A hits despite unbind before destroy)", g_clearAHits);
                            } else {
                                if (g_clearAHits > 0)  Log("PROBE DONE (hw-test bug: PASS — clear write confirmed, %zu clear.A hits)", g_clearAHits);
                                else                   Log("PROBE DONE (hw-test bug: FAIL — clear.A never fired; wrong hardware or driver?)");
                            }
                        } else if (g_wlFixUnbind) {
                            if (g_decoyHits == 0) Log("PROBE DONE (fix-unbind: PASS — clear write suppressed)");
                            else                  Log("PROBE DONE (fix-unbind: FAIL — %zu hits despite unbind before destroy)", g_decoyHits);
                        } else {
                            Log("PROBE DONE");
                        }
                        // (WriteFile is unbuffered; no fflush needed)
                    }
                    // Try to trigger the crashing mmobj creation by issuing a CreateResource.
                    // The field crash object (vtable atiumd6a RVA 0x2CEB90) is made by the same
                    // factory that runs during CreateDevice, but only once real rendering work
                    // reaches the driver. One 1x1 A8R8G8B8 texture is the smallest such call.
                    if (df->pfnCreateResource) {
                        D3DDDI_SURFACEINFO surf = {};
                        surf.Width  = 1;
                        surf.Height = 1;
                        surf.Depth  = 1;
                        D3DDDIARG_CREATERESOURCE cr = {};
                        cr.hResource = (HANDLE)0x40000;  // fake runtime handle; the driver may replace it
                        cr.Format = D3DDDIFMT_A8R8G8B8;
                        cr.Pool = D3DDDIPOOL_VIDEOMEMORY;
                        cr.MultisampleType = D3DDDIMULTISAMPLE_NONE;
                        cr.pSurfList = &surf;
                        cr.SurfCount = 1;
                        cr.MipLevels = 1;
                        cr.Flags.Texture = 1;
                        cr.Rotation = D3DDDI_ROTATION_IDENTITY;
                        HRESULT crhr = df->pfnCreateResource(cd.hDevice, &cr);
                        Log("  pfnCreateResource = %08lx  hResource=%p", crhr, (void*)cr.hResource);
                        if (SUCCEEDED(crhr) && g_plant710465 && g_mmobjForCrash) {
                            // Inject the bad pointer: write an 8-byte value at obj+0x64 so the
                            // destructor at vtable+0x40 (crash.fn) reads obj+0x68 as a bad address.
                            // The real crash has a 64-bit pointer stored at +0x64 (not +0x60 or
                            // +0x68), so obj+0x68 reads the HIGH 4 bytes of that value = a
                            // non-canonical address.
                            uint8_t* obj = (uint8_t*)g_mmobjForCrash;
                            *(uint64_t*)(obj + 0x64) = 0x00000001DEADBEEFULL;
                            Log("  injected bad pointer at obj+0x64: obj=%p [obj+0x68] now 0x00000001DEADBEEF as qword",
                                g_mmobjForCrash);
                            g_mmobjForCrash = nullptr;
                        }
                        // If it succeeded, also destroy it: the field crash is on the teardown path
                        // (atiumd64+0x94E3 -> atiumd6a:0x94D0 -> vtable+0x40).
                        if (SUCCEEDED(crhr) && df->pfnDestroyResource) {
                            HRESULT dres = df->pfnDestroyResource(cd.hDevice, cr.hResource);
                            Log("  pfnDestroyResource = %08lx", dres);
                        }
                    } else {
                        Log("  the driver filled no pfnCreateResource");
                    }
                    if (df->pfnDestroyDevice) {
                        HRESULT ddhr = df->pfnDestroyDevice(cd.hDevice);
                        Log("DestroyDevice = %08lx", ddhr);
                    } else {
                        Log("the driver filled no pfnDestroyDevice, so the device is left as it is");
                    }
                    Checkpoint(at("after DestroyDevice"));
                }
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
            fprintf(j, "  \"devicePhase\": %s,\n", withDevice ? "true" : "false");
            fprintf(j, "  \"lastCreateDeviceHr\": %ld,\n", (long)lastCreateDeviceHr);
            fprintf(j, "  \"fakeKernelSubmissions\": %zu,\n", g_submits);
            fprintf(j, "  \"deviceCallbackStubsHit\": %zu,\n", g_devStubHits);
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
    if (g_logHandle != INVALID_HANDLE_VALUE) { CloseHandle(g_logHandle); g_logHandle = INVALID_HANDLE_VALUE; }
    return rc;
}
#endif // !D3D9SHIM_DLL

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
    if (g_logHandle == INVALID_HANDLE_VALUE) {
        wchar_t path[MAX_PATH];
        GetModuleFileNameW(g_self, path, MAX_PATH);
        if (wchar_t* dot = wcsrchr(path, L'.')) wcscpy_s(dot, MAX_PATH - (dot - path), L"-startup.log");
        g_logHandle = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
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
