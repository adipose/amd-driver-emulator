// d3d9shim: a proxy d3d9.dll that answers Direct3DCreate9/Direct3DCreate9Ex with fake COM objects whose
// texture and draw calls go straight into the 2015 AMD atiumd64.dll user-mode driver through the fake
// runtime in legacy9.cpp -- no real d3d9 runtime, no real kernel driver. Dropped beside an exe that links
// d3d9.dll, it runs that exe's D3D9 traffic through the legacy driver in-process, with the legacy9
// instrumentation (heap census, decoys, breakpoints) attached.
//
// Built by build.ps1 -Target d3d9shim into build\d3d9.dll and copied next to the quarantine player.
// The driver path defaults to this repo's drivers\atiumd64.dll; LEGACY9_DRIVER overrides it.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define INITGUID
#include <initguid.h>
#include <d3d9.h>   // COM interfaces; must precede legacy9.cpp
static HINSTANCE g_shimSelf = nullptr; // forward for DllMain
struct IFakeD3D9Ex;
struct IFakeD3DDevice9Ex;
struct IFakeD3DTexture9;
struct IFakeD3DSurface9;
struct IFakeD3DPixelShader9;
#ifndef D3D9SHIM_DLL
#define D3D9SHIM_DLL
#endif
// Resource handle per D3D9 stage and total bound count -- updated by SetTexture.
// Declared before legacy9.cpp so its stateApply BP handler can inject them into
// the driver new-state snapshot before atiumd6a:0x2180 reads snapshot[+0x1A0].
static HANDLE g_shimStageHRes[16] = {};
static int    g_shimBoundCount    = 0;
// Snapshot of bound textures taken at DrawPrimitive time, before MPCVR unbinds them.
// stateApply fires from the deferred flush AFTER unbind, so it reads from here.
static HANDLE g_drawCommittedHRes[16] = {};
static int    g_drawCommittedCount    = 0;
// Driver-side APPLIED binding per stage.  The driver's deferred state flush runs
// synchronously inside pfnSetTexture/pfnDestroyResource; what its clear path
// (fn_1850) fence-waits is the binding being torn down -- i.e. this table's value,
// not the app-live one.  Updated in SetTexture AFTER the DDI call returns (the
// flush inside it consumed the old binding) and by the stateApply BIND/UNBIND
// injects.  Deliberately NOT cleared in Release after DestroyResource: with the
// swallow-one-unbind trigger the driver never saw the unbind, so the applied
// binding must survive into the next stateApply for the FENCE UAF to fire.
// This is what makes OLD vs NEW MPCVR distinguishable: NEW's ReleaseVP unbinds
// first, so by DestroyResource the driver holds no reference.
static HANDLE g_drvBoundHRes[16] = {};
// Swallow-one-unbind race trigger: after the first draw, the NEXT stage-0
// SetTexture(0, null) is reported to the app as done but NOT forwarded to the
// driver, leaving the driver's applied binding in place.  Old MPCVR then
// releases the texture without re-unbinding (the #4257 UAF window); new
// MPCVR's ReleaseVP unbinds explicitly, spending the trigger harmlessly while
// the texture is still alive.
static bool g_swallowNextUnbind = false;
static bool s_swallowArmed      = false;
// Synthetic per-stage binding record for the texture flush gate at atiumd6a:0x241A.
// [RSI+0x1A0] is a POINTER to this record (not a count).  The flush function reads
// [record+0x08] as the stage-0 resource handle passed to its inner binder (0x1850).
static struct { HANDLE pad0; HANDLE res0; HANDLE res1; } g_stageRec = {};
struct DriverAlloc { void* ptr; SIZE_T size; };
static bool        g_inCreateResource         = false;
static DriverAlloc g_createResourceAllocs[32] = {};
static int         g_createResourceAllocsCount = 0;
// VA-backed private pages for driver allocs made while g_inCreateResource is set.
// Driver heap allocs land on SHARED LFH pages, so fencing one at Release faults
// every still-live neighbour on the page (fence-noise/fence-recycle in BOTH MPCVR
// builds -- indistinguishable).  Redirecting those allocs to VirtualAlloc gives
// each its own page(s) and makes the Release-time fence exact.  Hook_HeapAlloc
// fills this table; Hook_HeapFree leaves the pages in place (deferred free) so
// Release can fence them.
struct VmAlloc { void* ptr; SIZE_T size; bool fenced; };
static VmAlloc g_vmAllocs[256] = {};
static int     g_vmAllocsCount = 0;
// sa.gatechk recursion-break: sub.retSA offset in atiumd64 (version-driven; the
// default is the 15.7.1 value).  Declared before the legacy9.cpp include because
// the included code references it.
static DWORD g_gcRetSA = 0x520E2;
// Defined after the include; the LoadSibling hook in legacy9.cpp uses it to gate
// its build-specific atiumd6a diagnostic arms.
static DWORD GetModuleMinorBuild(HMODULE mod);
// Defined after the include; arms the version-driven early atiumd6a BPs.
static void ShimArmEarlyA6a(HMODULE a6a);
#include "legacy9.cpp"  // infrastructure; wmain suppressed

// ---------------------------------------------------------------- driver bring-up

static HMODULE g_shimMod = nullptr;
static HANDLE g_shimDevice = nullptr;
static HANDLE ShimCreateSurfaceResource(UINT w, UINT h, D3DFORMAT fmt, bool isRT, bool isZ);
static IFakeD3DTexture9* s_stageBound[16] = {};  // which IFakeD3DTexture9 is bound per D3D9 stage
static D3DDDI_ADAPTERFUNCS g_shimAdapterFuncs = {};
static HANDLE g_shimAdapter = nullptr;
static void* g_shimDevFuncs[512] = {};
static FakeContext g_shimContext;
static HWND g_shimFocusWnd = nullptr;

// Version-driven BP table.  The RVAs below were pre-computed per driver build
// (14.4 / 15.7.1 / 16.2.1); an RVA of 0 means "not armed for this build".
struct BpSet {
    DWORD a64minor;
    // atiumd64 BPs
    DWORD stateApply, saGatechk, gateCall, gateRet;
    DWORD deferRun, deferFlush, drawPipe, drawRec;
    DWORD subResolved, subCallSA, subRetSA;
    DWORD recWrap0, recWrap1, recWrap2, recWrap3;
    DWORD snapCall, snapBuild, snapStages;
    DWORD stCrash64, clrInner, clrPath2, clrDispatch;
    // atiumd6a BPs
    DWORD clearA, stUaf, stSub24e0, clrZero, flushRva;
    DWORD tssDisp, gateA6a, bcCase, bcClearfn;
    // early-arm RVAs for ShimCreateDevice
    DWORD stFlushEarly;   // atiumd6a stateApply-a6a
    DWORD clrZeroEarly;   // atiumd6a clrzero early
    // sa.gatechk recursion-break: sub.retSA address in atiumd64
    DWORD gcRetSA;
};

static DWORD GetModuleMinorBuild(HMODULE mod) {
    wchar_t path[MAX_PATH];
    if (!GetModuleFileNameW(mod, path, MAX_PATH)) return 0;
    DWORD dummy;
    DWORD sz = GetFileVersionInfoSizeW(path, &dummy);
    if (!sz || sz > 65536) return 0;
    static BYTE buf[65536];
    if (!GetFileVersionInfoW(path, 0, sz, buf)) return 0;
    VS_FIXEDFILEINFO* ffi = nullptr;
    UINT ffiSz = 0;
    if (!VerQueryValueW(buf, L"\\", (LPVOID*)&ffi, &ffiSz) || !ffi) return 0;
    // File versions are 9.14.10.NNNN: the distinguishing build (1029/1128/1171)
    // is the fourth component, LOWORD(dwFileVersionLS).
    return LOWORD(ffi->dwFileVersionLS);
}

static const BpSet g_bpSets[] = {
    // 14.4: atiumd64 build 1029
    { 1029,
      0x31220, 0x31244, 0x30F43, 0x30F45,
      0x2EC9A, 0x2EC40, 0x363C0, 0,
      0,       0,       0,
      0, 0, 0, 0,
      0, 0, 0,
      0, 0, 0, 0,
      0x0F4A6D, 0, 0, 0, 0,
      0, 0, 0, 0,
      0x1BA0, 0,
      0
    },
    // 15.7.1: atiumd64 build 1128
    { 1128,
      0x30310, 0x30334, 0x30053, 0x30055,
      0x2DE9A, 0x2DE40, 0x35470, 0x2CCE0,
      0x51DFD, 0x520DD, 0x520E2,
      0x0A0E2, 0x0B140, 0x511E2, 0x13090,
      0x2D8C70, 0x1712A0, 0x176CBB,
      0x59827, 0x596D0, 0x597DC, 0x53180,
      0x12EA32, 0x12E90F, 0x0024E0, 0x12E946, 0x12C950,
      0x0F4520, 0x11A420, 0x124777, 0x12E8D0,
      0x2180, 0x12E946,
      0x520E2
    },
    // 16.2.1: atiumd64 build 1171
    { 1171,
      0x311F0, 0x31214, 0x30F53, 0x30F55,
      0,       0,       0x36170, 0,
      0,       0x0538BD,0x0538C2,
      0, 0, 0, 0,
      0, 0, 0,
      0, 0, 0, 0,
      0x1453D2,0x1452AF,0, 0, 0,
      0, 0, 0, 0x145270,
      0x2180, 0,
      0x0538C2
    },
};
static const int g_bpSetsCount = 3;

static const BpSet* GetBpSet() {
    if (!g_shimMod) return nullptr;
    DWORD minor = GetModuleMinorBuild(g_shimMod);
    Log("shim: atiumd64 minor build = %lu", (unsigned long)minor);
    for (int i = 0; i < g_bpSetsCount; i++)
        if (g_bpSets[i].a64minor == minor) return &g_bpSets[i];
    Log("shim: WARNING -- no BP table for build %lu, falling back to 15.7.1", (unsigned long)minor);
    for (int i = 0; i < g_bpSetsCount; i++)
        if (g_bpSets[i].a64minor == 1128) return &g_bpSets[i];
    return nullptr;
}

// Arms the version-driven early atiumd6a BPs (st.flush/clrzero).  Called from the
// LoadSibling hook the moment atiumd6a.dll is mapped -- the driver's own LoadLibrary
// happens during OpenAdapter, after ShimCreateDevice's early-arm block has already
// run, so this is the only point that is actually early.
static void ShimArmEarlyA6a(HMODULE a6a)
{
    const BpSet* bps = GetBpSet();
    DWORD czRva = bps ? bps->clrZeroEarly : 0x12E946;
    DWORD sfRva = bps ? bps->stFlushEarly  : 0x2180;
    if (czRva) ArmBp(a6a, czRva, "clrzero");
    if (sfRva) ArmBp(a6a, sfRva, "st.flush");
}

// Arms the breakpoints that trace the clear-write path. Called once after device creation and again on
// ResetEx: the module image survives a device reset, so a re-arm only matters if a BP was left restored.
static void ShimArmBps()
{
    const BpSet* bps = GetBpSet();
    if (!bps) { ShimHookPool(); return; }
#define ABP(mod, rva, tag) do { if (rva) ArmBp((mod), (rva), (tag)); } while(0)
    ABP(g_shimMod, bps->stateApply,  "stateApply");
    ABP(g_shimMod, bps->saGatechk,   "sa.gatechk");
    ABP(g_shimMod, bps->gateCall,    "gate.call");
    ABP(g_shimMod, bps->gateRet,     "gate.ret");
    ABP(g_shimMod, bps->subResolved, "sub.resolved");
    ABP(g_shimMod, bps->subCallSA,   "sub.callSA");
    ABP(g_shimMod, bps->subRetSA,    "sub.retSA");
    ABP(g_shimMod, bps->deferRun,    "defer.run");
    ABP(g_shimMod, bps->deferFlush,  "deferFlush");
    ABP(g_shimMod, bps->drawPipe,    "draw.pipe");
    ABP(g_shimMod, bps->drawRec,     "draw.rec");
    ABP(g_shimMod, bps->recWrap0,    "rec.wrap0");
    ABP(g_shimMod, bps->recWrap1,    "rec.wrap1");
    ABP(g_shimMod, bps->recWrap2,    "rec.wrap2");
    ABP(g_shimMod, bps->recWrap3,    "rec.wrap3");
    ABP(g_shimMod, bps->snapCall,    "snap.call");
    ABP(g_shimMod, bps->snapBuild,   "snap.build");
    ABP(g_shimMod, bps->snapStages,  "snap.stages");
    ABP(g_shimMod, bps->stCrash64,   "st.crash64");
    ABP(g_shimMod, bps->clrInner,    "clr.inner");
    ABP(g_shimMod, bps->clrPath2,    "clr.path2");
    ABP(g_shimMod, bps->clrDispatch, "clr.dispatch");
    HMODULE a6a = GetModuleHandleA("atiumd6a.dll");
    if (a6a) {
        ABP(a6a, bps->clearA,    "clear.A");
        ABP(a6a, bps->stUaf,     "st.uaf");
        ABP(a6a, bps->stSub24e0, "st.sub24e0");
        ABP(a6a, bps->clrZero,   "clrzero");
        ABP(a6a, bps->flushRva,  "flush");
        ABP(a6a, bps->tssDisp,   "tss.disp");
        ABP(a6a, bps->gateA6a,   "gate");
        ABP(a6a, bps->bcCase,    "bc.case");
        ABP(a6a, bps->bcClearfn, "bc.clearfn");
    }
#undef ABP
    g_gcRetSA = bps->gcRetSA;
    Log("shim: g_gcRetSA = 0x%x (sub.retSA for sa.gatechk recursion break)", g_gcRetSA);
    g_phaseResetAtGateRet = (bps->deferRun == 0);
    if (g_phaseResetAtGateRet)
        Log("shim: no defer.run for this build -- BIND/UNBIND phase resets at gate.ret");
    ShimHookPool();
}

// The pfnCreateDevice half of device bring-up, shared by ShimCreateDevice and the ResetEx re-create.
// Follows the wmain device phase (legacy9.cpp): FillDeviceCallbacks + SizeContext, then the
// --fake-draw-params block so draws reach the deferred-flush path.
static HRESULT ShimCreateDriverDevice()
{
    static D3DDDI_DEVICECALLBACKS devCb;
    FillDeviceCallbacks(&devCb);

    static int rtDevice = 'cveD';
    if (!g_shimContext.cmd && !SizeContext(&g_shimContext, 0, 0, 0)) {
        Log("shim: out of memory for the device buffers");
        return E_OUTOFMEMORY;
    }

    D3DDDIARG_CREATEDEVICE cd = {};
    cd.hDevice = &rtDevice;
    cd.Interface = 9;
    cd.Version = 0xC00;
    cd.pCallbacks = &devCb;
    cd.pCommandBuffer = g_shimContext.cmd;
    cd.CommandBufferSize = g_shimContext.cmdSize;
    cd.pAllocationList = g_shimContext.allocList;
    cd.AllocationListSize = g_shimContext.allocListSize;
    cd.pPatchLocationList = g_shimContext.patchList;
    cd.PatchLocationListSize = g_shimContext.patchListSize;
    cd.pDeviceFuncs = (D3DDDI_DEVICEFUNCS*)g_shimDevFuncs;
    cd.CommandBuffer = g_shimContext.cmdGpuVa;

    HRESULT dhr = g_shimAdapterFuncs.pfnCreateDevice(g_shimAdapter, &cd);
    size_t filled = 0;
    for (size_t i = 0; i < 512; i++) if (g_shimDevFuncs[i]) filled++;
    Log("shim: CreateDevice = %08lx  device funcs filled: %zu slots", dhr, filled);
    { char w1[128], w2[128], w3[128], w4[128];
      Log("shim: pfnSetTexture=%s pfnDrawPrimitive=%s pfnSetRenderTarget=%s pfnFlush=%s",
          Where(g_shimDevFuncs[4], w1, sizeof w1), Where(g_shimDevFuncs[10], w2, sizeof w2),
          Where(g_shimDevFuncs[62], w3, sizeof w3), Where(g_shimDevFuncs[41], w4, sizeof w4)); }
    // Full table dump (once): identify the recorder-path DDIs.
    static bool s_dumpedFuncs = false;
    if (!s_dumpedFuncs) {
        s_dumpedFuncs = true;
        for (int i = 0; i < 512 && i * 8 < (int)sizeof(D3DDDI_DEVICEFUNCS); i++) {
            if (!g_shimDevFuncs[i]) continue;
            char w[300];
            Log("shim: devfunc[%d] = %s", i, Where(g_shimDevFuncs[i], w, sizeof w));
        }
    }
    if (FAILED(dhr)) return dhr;
    g_shimDevice = cd.hDevice;

    // Diagnostic: which link in the driver's own channel-creation chain is broken?
    // atiumd64:0x1CF0 creates [device_inner+0x600] (holder) and then sets [holder+0x20]
    // (the channel) from factory table+0x50 (atiumd64+0x7F4590) gated on [settings+0x5028],
    // which is itself created by table+0x08 (atiumd64+0x7F4548) in atiumd64:0x1E959.
    __try {
        void* device_inner = *(void**)((char*)g_shimDevice + 0x10);
        void* settings = device_inner ? *(void**)device_inner : nullptr;
        void* s5028 = settings ? *(void**)((char*)settings + 0x5028) : nullptr;
        void* holder = device_inner ? *(void**)((char*)device_inner + 0x600) : nullptr;
        void* channel = holder ? *(void**)((char*)holder + 0x20) : nullptr;
        char* mod = (char*)g_shimMod;
        void* tbl08 = *(void**)(mod + 0x7F4548);
        void* tbl50 = *(void**)(mod + 0x7F4590);
        void* tbl80 = *(void**)(mod + 0x7F45C0);
        Log("shim: diag: dev_inner=%p settings=%p [settings+0x5028]=%p holder=%p [holder+0x20]=%p",
            device_inner, settings, s5028, holder, channel);
        Log("shim: diag: out-table: [+0x08]=%p [+0x50]=%p [+0x80]=%p", tbl08, tbl50, tbl80);
        Log("shim: diag: [hDev+0x4958]=%p [+0x4960]=%p [+0x47B0]=%x (driver-owned draw params)",
            *(void**)((char*)g_shimDevice + 0x4958), *(void**)((char*)g_shimDevice + 0x4960),
            *(unsigned*)((char*)g_shimDevice + 0x47B0));
        if (holder) {
            Log("shim: diag: holder: [+4]=%x [+8]=%p [+0x10]=%p [+0x668]=%p",
                *(unsigned*)((char*)holder + 4), *(void**)((char*)holder + 8),
                *(void**)((char*)holder + 0x10), *(void**)((char*)holder + 0x668));
        }
        // Which device-implementation vtable did the chip selector install?  The slots at
        // +0x220/+0x2D8/+0x2F8/+0x300 decide whether draws go through the batch recorder.
        if (device_inner) {
            void* impl = *(void**)((char*)device_inner + 0x2268);
            if (impl) {
                char w1[128], w2[128], w3[128], w4[128], w5[128], w6[128];
                Log("shim: diag: impl=%p [+0x220]=%s [+0x2D8]=%s [+0x2F8]=%s [+0x300]=%s",
                    impl,
                    Where(*(void**)((char*)impl + 0x220), w1, sizeof w1),
                    Where(*(void**)((char*)impl + 0x2D8), w2, sizeof w2),
                    Where(*(void**)((char*)impl + 0x2F8), w3, sizeof w3),
                    Where(*(void**)((char*)impl + 0x300), w4, sizeof w4));
                Log("shim: diag: impl [+0x2F0]=%s [+0x138]=%s",
                    Where(*(void**)((char*)impl + 0x2F0), w5, sizeof w5),
                    Where(*(void**)((char*)impl + 0x138), w6, sizeof w6));
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { Log("shim: diag: read fault"); }

    // No fake draw-param buffers, no fake channel: the driver builds both itself from the
    // real DDI calls (SetRenderTarget/SetDepthStencil, SetTexture, DrawPrimitive).
    // The runtime's windowed-mode setup: tell the driver the primary it presents from.
    // (devfunc[39], not [33]: the table order differs from the header's.  The driver
    // refuses it with 0x8876087A in this configuration either way; windowed mode
    // does not depend on it.)
    if (g_shimDevFuncs) {
        D3DDDI_DEVICEFUNCS* df = (D3DDDI_DEVICEFUNCS*)g_shimDevFuncs;
        if (df->pfnSetDisplayMode) {
            HANDLE hPrim = ShimCreateSurfaceResource(1920, 1080, D3DFMT_X8R8G8B8, true, false);
            D3DDDIARG_SETDISPLAYMODE sdm = {};
            sdm.hResource = hPrim;
            sdm.SubResourceIndex = 0;
            HRESULT hr = df->pfnSetDisplayMode(g_shimDevice, &sdm);
            Log("shim: SetDisplayMode(hResource=%p) = %08lx", hPrim, hr);
        }
    }
    return S_OK;
}

static HRESULT ShimCreateDevice(HWND hFocusWnd)
{
    if (g_shimDevice) return S_OK;
    g_shimFocusWnd = hFocusWnd;
    {
        wchar_t v[4] = L"";
        g_plant710465 = GetEnvironmentVariableW(L"MPC_PLANT_710465", v, 4) && v[0] == L'1';
        if (g_plant710465) Log("shim: MPC_PLANT_710465=1, the drdump 710465 store will be planted after the first texture");
    }

    wchar_t dll[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"LEGACY9_DRIVER", dll, MAX_PATH);
    if (!n || n >= MAX_PATH)
        wcscpy_s(dll, L"C:\\dev\\amd-driver-emulator\\drivers\\atiumd64.dll");

    wchar_t full[MAX_PATH];
    GetFullPathNameW(dll, MAX_PATH, full, nullptr);
    wcscpy_s(g_driverDir, full);
    if (wchar_t* s = wcsrchr(g_driverDir, L'\\')) *s = 0;

    g_shimMod = LoadLibraryExW(full, nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!g_shimMod) { Log("shim: LoadLibrary(%ls) failed: %lu", full, GetLastError()); return E_FAIL; }
    Log("shim: driver %ls loaded at %p", full, (void*)g_shimMod);
    HookImports(g_shimMod);

    // Diagnostic: atiumd64-side creators/destructor for the atiumd6a device objects,
    // armed before OpenAdapter/CreateDevice so we see them if they run there.
    // These RVAs are the 15.7.1 (build 1128) addresses; on any other build they can
    // land mid-instruction, where the 0xCC silently corrupts an operand instead of
    // trapping, so arm them only there.
    if (GetModuleMinorBuild(g_shimMod) == 1128) {
    ArmBp(g_shimMod, 0x1E959, "mmdev.make");  // creates [settings+0x5028] (lazy)
    ArmBp(g_shimMod, 0x1CF0,  "holder.make"); // creates [dev_inner+0x600] holder
    ArmBp(g_shimMod, 0x1E9F0, "mmdev.free");
    ArmBp(g_shimMod, 0x1E9C8, "mmdev.done");  // 0x1E959's store of [settings+0x5028]
    }

    // Arm clrzero before CreateDevice: the driver's initialization runs the
    // memset(inner_obj,0,0x1000) path that overflows the 152-byte inner block into
    // adjacent heap metadata.  atiumd6a.dll is a static dep of atiumd64.dll and is
    // already in memory here.  ArmBp is idempotent so ShimArmBps below is safe.
    {
        HMODULE a6a_early = GetModuleHandleA("atiumd6a.dll");
        if (a6a_early) {
            const BpSet* early_bps = GetBpSet();
            DWORD czRva  = early_bps ? early_bps->clrZeroEarly : 0x12E946;
            DWORD sfRva  = early_bps ? early_bps->stFlushEarly  : 0x2180;
            if (czRva) ArmBp(a6a_early, czRva,    "clrzero");
            ArmBp(a6a_early, 0x009430, "mmobj.make");   // creates [settings+0x5028]
            ArmBp(a6a_early, 0x003710, "chan.make");    // creates [holder+0x20] (channel)
            if (sfRva) ArmBp(a6a_early, sfRva,    "st.flush");     // atiumd6a state-flush entry
            ArmBp(a6a_early, 0x009482, "mmobj.init");   // logs the variant's vtable, records it for the plant
            if (g_plant710465) {
                ArmBp(a6a_early, 0x037510, "crash.fn");
                ArmBp(a6a_early, 0x0094D0, "dtor.a6a");
            }
        }
    }

    // The exe takes the adapter-record fields from --qai-set/--gpu-va-base; the shim has no command line,
    // so the known-good WDDM2 set (the default in tools/inject.ps1) is supplied directly. Record 2's ring
    // table defaults are already hardcoded in QueryAdapterInfoCb.
    g_gpuVaBase = 0x20000;
    g_qaiSet = { { 0x000, 0x260 }, { 0x30, 0x5b }, { 0x3c, 8 }, { 0x1f4, 0x480 }, { 0xd4, 2 } };
    g_qaiSet2 = { { 0x2a00, 1 }, { 0x2a04, 1 }, { 0x2c2c, 1 }, { 0x2c30, 1 } };

    auto open = (PFN_OPENADAPTER)GetProcAddress(g_shimMod, "OpenAdapter");
    if (!open) { Log("shim: no OpenAdapter export"); return E_FAIL; }

    static int rtAdapter = 'tpdA';
    D3DDDI_ADAPTERCALLBACKS cb = {};
    cb.pfnQueryAdapterInfoCb = QueryAdapterInfoCb;
    cb.pfnGetMultisampleMethodListCb = GetMultisampleMethodListCb;
    D3DDDIARG_OPENADAPTER oa = {};
    oa.hAdapter = &rtAdapter;
    oa.Interface = 9;
    oa.Version = 0xC00;
    oa.pAdapterCallbacks = &cb;
    oa.pAdapterFuncs = &g_shimAdapterFuncs;

    HRESULT hr = open(&oa);
    g_shimAdapter = oa.hAdapter;
    Log("shim: OpenAdapter = %08lx  hAdapter(drv)=%p DriverVersion=0x%x", hr, oa.hAdapter, oa.DriverVersion);
    if (FAILED(hr)) return hr;

    hr = ShimCreateDriverDevice();
    if (FAILED(hr)) return hr;

    ShimArmBps();
    PlantDecoys(32);
    return S_OK;
}

// ---------------------------------------------------------------- fake COM objects

// Creates a real driver resource for a surface (render target / depth stencil), the way the
// D3D runtime would for app-created surfaces.  Returns the driver's resource handle.
static HANDLE ShimCreateSurfaceResource(UINT w, UINT h, D3DFORMAT fmt, bool isRT, bool isZ)
{
    D3DDDI_DEVICEFUNCS* df = (D3DDDI_DEVICEFUNCS*)g_shimDevFuncs;
    if (!df->pfnCreateResource || !g_shimDevice) return nullptr;
    D3DDDI_SURFACEINFO surf = {};
    surf.Width = w;
    surf.Height = h;
    surf.Depth = 1;
    D3DDDIARG_CREATERESOURCE cr = {};
    cr.Format = (D3DDDIFORMAT)fmt;
    cr.Pool = D3DDDIPOOL_VIDEOMEMORY;
    cr.MultisampleType = D3DDDIMULTISAMPLE_NONE;
    cr.pSurfList = &surf;
    cr.SurfCount = 1;
    cr.MipLevels = 1;
    cr.Flags.RenderTarget = isRT ? 1 : 0;
    cr.Flags.ZBuffer = isZ ? 1 : 0;
    cr.Rotation = D3DDDI_ROTATION_IDENTITY;
    static UINT_PTR s_nextSurfHandle = 0x70000;
    cr.hResource = (HANDLE)s_nextSurfHandle++;
    HRESULT hr = df->pfnCreateResource(g_shimDevice, &cr);
    static int s_logged = 0;
    if (s_logged < 8) { s_logged++; Log("shim: CreateSurfaceResource(%ux%u fmt=%u rt=%d z=%d) = %08lx hRes=%p",
        w, h, (UINT)fmt, (int)isRT, (int)isZ, hr, cr.hResource); }
    return SUCCEEDED(hr) ? cr.hResource : nullptr;
}

struct IFakeD3DSurface9 : IDirect3DSurface9
{
    ULONG m_ref = 1;
    HANDLE m_hRes = nullptr;
    UINT m_w = 0, m_h = 0;
    D3DFORMAT m_fmt = D3DFMT_X8R8G8B8;
    IDirect3DDevice9* m_dev = nullptr;

    IFakeD3DSurface9(HANDLE hRes, UINT w, UINT h, D3DFORMAT fmt, IDirect3DDevice9* dev)
        : m_hRes(hRes), m_w(w), m_h(h), m_fmt(fmt), m_dev(dev) {}

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObj) override
    {
        if (!ppvObj) return E_INVALIDARG;
        if (riid == IID_IDirect3DSurface9 || riid == IID_IDirect3DResource9 || riid == IID_IUnknown) {
            *ppvObj = static_cast<IDirect3DSurface9*>(this);
            AddRef();
            return S_OK;
        }
        *ppvObj = nullptr;
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++m_ref; }
    ULONG STDMETHODCALLTYPE Release() override
    {
        ULONG r = --m_ref;
        if (!r) delete this;
        return r;
    }

    // IDirect3DResource9
    HRESULT STDMETHODCALLTYPE GetDevice(IDirect3DDevice9** ppDevice) override
    {
        if (!ppDevice || !m_dev) return E_NOTIMPL;
        m_dev->AddRef();
        *ppDevice = m_dev;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE SetPrivateData(REFGUID, CONST void*, DWORD, DWORD) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetPrivateData(REFGUID, void*, DWORD*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE FreePrivateData(REFGUID) override { return E_NOTIMPL; }
    DWORD STDMETHODCALLTYPE SetPriority(DWORD) override { return 0; }
    DWORD STDMETHODCALLTYPE GetPriority() override { return 0; }
    void STDMETHODCALLTYPE PreLoad() override {}
    D3DRESOURCETYPE STDMETHODCALLTYPE GetType() override { return D3DRTYPE_SURFACE; }

    // IDirect3DSurface9
    HRESULT STDMETHODCALLTYPE GetContainer(REFIID, void** ppContainer) override
    {
        if (ppContainer) *ppContainer = nullptr;
        return E_NOINTERFACE;
    }
    HRESULT STDMETHODCALLTYPE GetDesc(D3DSURFACE_DESC* pDesc) override
    {
        if (!pDesc) return E_INVALIDARG;
        pDesc->Format = m_fmt;
        pDesc->Type = D3DRTYPE_SURFACE;
        pDesc->Usage = 0;
        pDesc->Pool = D3DPOOL_DEFAULT;
        pDesc->MultiSampleType = D3DMULTISAMPLE_NONE;
        pDesc->MultiSampleQuality = 0;
        pDesc->Width = m_w;
        pDesc->Height = m_h;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE LockRect(D3DLOCKED_RECT* pLockedRect, CONST RECT*, DWORD) override
    {
        if (!pLockedRect) return E_INVALIDARG;
        static unsigned char s_buf[4096];
        pLockedRect->Pitch = (INT)(m_w * 4);
        pLockedRect->pBits = s_buf;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE UnlockRect() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE GetDC(HDC*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE ReleaseDC(HDC) override { return E_NOTIMPL; }
};

// Force the driver's deferred state flush outside the Present path.  MPC-HC's
// teardown releases the bound textures AFTER the last Present, so without a pump
// no flush ever observes the stale binding to the just-released resource (and the
// FENCE-UAF bait planted at [hRes+0x10] is never read).  One CaptureToSysMem per
// call, the same recorder entry the Present path uses.
static void ShimPumpFlush()
{
    D3DDDI_DEVICEFUNCS* df = (D3DDDI_DEVICEFUNCS*)g_shimDevFuncs;
    if (!g_shimDevice || !df) return;
    if (df->pfnFlush) {
        __try { df->pfnFlush(g_shimDevice); }
        __except(EXCEPTION_EXECUTE_HANDLER) { Log("shim: pump pfnFlush faulted (suppressed)"); }
    }
    if (!df->pfnCaptureToSysMem || !df->pfnCreateResource) return;
    static HANDLE s_pumpSrc = nullptr;
    static HANDLE s_pumpDst = nullptr;
    __try {
        if (!s_pumpSrc) s_pumpSrc = ShimCreateSurfaceResource(1920, 1080, D3DFMT_X8R8G8B8, true, false);
        if (!s_pumpDst) {
            D3DDDI_SURFACEINFO surf = {};
            surf.Width = 1920; surf.Height = 1080; surf.Depth = 1;
            D3DDDIARG_CREATERESOURCE cr = {};
            cr.Format = (D3DDDIFORMAT)D3DFMT_X8R8G8B8;
            cr.Pool = D3DDDIPOOL_VIDEOMEMORY;
            cr.MultisampleType = D3DDDIMULTISAMPLE_NONE;
            cr.pSurfList = &surf;
            cr.SurfCount = 1;
            cr.MipLevels = 1;
            cr.Rotation = D3DDDI_ROTATION_IDENTITY;
            static UINT_PTR s_pumpHandle = 0xA0000;
            cr.hResource = (HANDLE)s_pumpHandle++;
            HRESULT shr = df->pfnCreateResource(g_shimDevice, &cr);
            s_pumpDst = SUCCEEDED(shr) ? cr.hResource : nullptr;
            Log("shim: pump sysmem target CreateResource = %08lx hRes=%p", shr, cr.hResource);
        }
        if (s_pumpSrc && s_pumpDst) {
            D3DDDIARG_CAPTURETOSYSMEM cap = {};
            cap.hSrcResource = s_pumpSrc;
            cap.hDstResource = s_pumpDst;
            RECT r = { 0, 0, 1920, 1080 };
            cap.SrcRect = r;
            cap.DstRect = r;
            HRESULT chr = df->pfnCaptureToSysMem(g_shimDevice, &cap);
            static int s_pumpLog = 0;
            if (s_pumpLog < 6) { s_pumpLog++; Log("shim: pump CaptureToSysMem = %08lx", chr); }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) { Log("shim: pump faulted (suppressed)"); }
}

struct IFakeD3DTexture9 : IDirect3DTexture9
{
    ULONG m_ref = 1;
    HANDLE m_hRes = nullptr;
    UINT m_w = 0, m_h = 0;
    D3DFORMAT m_fmt = D3DFMT_A8R8G8B8;
    IDirect3DDevice9* m_dev = nullptr;
    DriverAlloc m_driverAllocs[32] = {};
    int         m_driverAllocsCount = 0;

    IFakeD3DTexture9(HANDLE hRes, UINT w, UINT h, D3DFORMAT fmt, IDirect3DDevice9* dev)
        : m_hRes(hRes), m_w(w), m_h(h), m_fmt(fmt), m_dev(dev) {}

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObj) override
    {
        if (!ppvObj) return E_INVALIDARG;
        if (riid == IID_IDirect3DTexture9 || riid == IID_IDirect3DBaseTexture9 ||
            riid == IID_IDirect3DResource9 || riid == IID_IUnknown) {
            *ppvObj = static_cast<IDirect3DTexture9*>(this);
            AddRef();
            return S_OK;
        }
        *ppvObj = nullptr;
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++m_ref; }
    ULONG STDMETHODCALLTYPE Release() override
    {
        Log("shim: tex Release entry: hRes=%p ref=%lu", (void*)m_hRes, m_ref);
        ULONG r = --m_ref;
        if (!r) {
            D3DDDI_DEVICEFUNCS* df = (D3DDDI_DEVICEFUNCS*)g_shimDevFuncs;
            if (m_hRes && g_shimDevice && df->pfnDestroyResource) {
                // Find whether this texture is still bound to any stage.  If it is, the
                // caller (MPCVR's ReleaseVP/ReleaseDevice) is committing the AMD UAF bug:
                // it destroys a texture that the driver's stage still references.
                // Capture m_hRes[+0x48] DIRECTLY — the driver inner-object for THIS resource —
                // so the next stateApply arms DR0 on the REAL freed pool object, not on the
                // synthetic s_fakeInner152 buffer.
                int boundStage = -1;
                for (int s = 0; s < 16; s++) {
                    if (s_stageBound[s] == this) { boundStage = s; break; }
                }
                // Diagnostic: dump the live stage table at every final release so the
                // OLD-vs-NEW difference (unbind-before-release) is visible in the log.
                {
                    int nb = 0;
                    for (int s = 0; s < 16; s++) if (g_shimStageHRes[s]) nb++;
                    Log("shim: tex Release: stages live=%d [0]=%p [1]=%p [2]=%p [3]=%p (releasing hRes=%p)",
                        nb, (void*)g_shimStageHRes[0], (void*)g_shimStageHRes[1],
                        (void*)g_shimStageHRes[2], (void*)g_shimStageHRes[3], (void*)m_hRes);
                }
                // Diagnostic: where does the driver's own current binding point at release
                // time?  s_realHolder = [device_inner+0x600]; channel = [holder+0x20];
                // the flush reads its stage-0 record through [chan+0x188].
                __try {
                    void* holder = s_realHolder;
                    void* chan = holder ? *(void**)((char*)holder + 0x20) : nullptr;
                    void* rec = chan ? *(void**)((char*)chan + 0x188) : nullptr;
                    void* rec8 = rec ? *(void**)((char*)rec + 8) : nullptr;
                    void* rec10 = rec ? *(void**)((char*)rec + 0x10) : nullptr;
                    Log("shim: tex Release: drvbind holder=%p chan=%p [chan+0x188]=%p rec[+8]=%p rec[+0x10]=%p (releasing hRes=%p)",
                        holder, chan, rec, rec8, rec10, (void*)m_hRes);
                } __except(EXCEPTION_EXECUTE_HANDLER) {
                    Log("shim: tex Release: drvbind read faulted");
                }
                void* inner = nullptr;
                __try { inner = *(void**)((char*)m_hRes + 0x48); } __except(EXCEPTION_EXECUTE_HANDLER) {}
                if (boundStage >= 0) {
                    // Texture released while still bound: this IS the AMD UAF condition.
                    Log("shim: tex Release: hRes=%p STILL BOUND stage %d m_hRes[+0x48]=%p",
                        m_hRes, boundStage, inner);
                    if (inner && (uintptr_t)inner > 0x10000) {
                        g_wpInnerPtr = inner;
                        Log("shim: tex Release: g_wpInnerPtr <- REAL inner %p (from m_hRes)",
                            inner);
                    } else {
                        // m_hRes[+0x48] not yet allocated by the driver (SetTexture alone doesn't
                        // trigger the inner-object allocator; stateApply does).  The true trap cannot
                        // fire for this texture release.  Log and fall through without setting
                        // g_wpInnerPtr: stateApply will NOT arm DR0 on the synthetic fallback.
                        Log("shim: tex Release: m_hRes[+0x48]=null — inner not allocated, "
                            "true trap unavailable for this release");
                    }
                    s_stageBound[boundStage] = nullptr;
                } else {
                    Log("shim: tex Release: hRes=%p not bound (stage already cleared) "
                        "m_hRes[+0x48]=%p", m_hRes, inner);
                }
                // Fence all driver heap allocations recorded during CreateResource.
                // Fencing must happen AFTER pfnDestroyResource: Destroy (and the heap
                // bookkeeping it triggers in ntdll, plus our own BP handlers) still
                // touches those pages during teardown, so fencing beforehand faults the
                // destructor path from non-driver call sites (false hit in both builds).
                // The post-reset flush will fault here if the stage is still live.
                df->pfnDestroyResource(g_shimDevice, m_hRes);
                for (int _da = 0; _da < m_driverAllocsCount; _da++) {
                    void* ptr = m_driverAllocs[_da].ptr;
                    SIZE_T sz = m_driverAllocs[_da].size;
                    if (!ptr || (uintptr_t)ptr <= 0x10000 || !sz) continue;
                    MEMORY_BASIC_INFORMATION mbi = {};
                    if (!VirtualQuery(ptr, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT) {
                        Log("shim: tex Release: driverAlloc[%d] ptr=%p not committed (skipped)", _da, ptr);
                        continue;
                    }
                    // Fence ONLY the pages the freed block spans, not the whole heap region:
                    // the region holds many still-live allocations, and fencing it faults
                    // ntdll heap code and unrelated driver objects (false FENCE UAF hits).
                    uintptr_t first = (uintptr_t)ptr & ~(uintptr_t)0xFFF;
                    uintptr_t last  = ((uintptr_t)ptr + sz - 1) & ~(uintptr_t)0xFFF;
                    for (uintptr_t page = first; page <= last; page += 0x1000) {
                        DWORD oldProt = 0;
                        if (!VirtualProtect((void*)page, 4096, PAGE_NOACCESS, &oldProt)) {
                            Log("shim: tex Release: VirtualProtect(%p) failed %lu", (void*)page, GetLastError());
                            continue;
                        }
                        PoolLock();
                        if (g_fencedCount < 256) {
                            // VA-backed allocs own their page(s): any access within the
                            // page is a stale reference, so the fenced extent spans the
                            // whole page.  (A heap-recorded fallback, if one ever slips
                            // through, keeps the exact [ptr, ptr+sz) extent.)
                            void* fObj = ptr; SIZE_T fSz = sz;
                            for (int _va = 0; _va < g_vmAllocsCount; _va++)
                                if (g_vmAllocs[_va].ptr == ptr) {
                                    g_vmAllocs[_va].fenced = true;
                                    fObj = (void*)page; fSz = 4096;
                                    break;
                                }
                            g_fenced[g_fencedCount++] = FencedBlock{ (void*)page, fObj, fSz, false };
                            Log("shim: tex Release: fenced driverAlloc[%d] page=%p ptr=%p size=%zu",
                                _da, (void*)page, ptr, (size_t)sz);
                        }
                        PoolUnlock();
                    }
                }
                Log("shim: tex Release: fenced %d driverAllocs after Destroy (hRes=%p)", m_driverAllocsCount, (void*)m_hRes);
                // Do NOT clear g_drvBoundHRes[s] here: the whole point of the
                // swallow-one-unbind trigger is that the driver never got the
                // unbind for this resource, so the driver-side applied binding
                // must SURVIVE DestroyResource.  The next stateApply UNBIND
                // inject then passes the freed hRes to fn_1850 as the OLD
                // resource and the clear path dereferences the fenced pages
                // (FENCE UAF).  g_drvBoundHRes[0] is cleared by the stateApply
                // UNBIND branch once the driver has actually processed an
                // unbind -- which, for NEW MPCVR, already happened inside its
                // explicit ReleaseVP SetTexture(0, null), so the table is null
                // by DestroyResource there and nothing is injected.
                if (boundStage >= 0) {
                    // The driver still holds its applied binding to this now-freed
                    // resource (swallowed unbind).  Force a deferred flush NOW so the
                    // driver's clear path runs against the fenced pages: teardown
                    // releases happen after the last Present, so without a pump no
                    // later flush would ever observe the stale binding.
                    Log("shim: tex Release: STILL BOUND - pumping flush against fenced hRes=%p", (void*)m_hRes);
                    ShimPumpFlush();
                }
            }
            delete this;
        }
        return r;
    }

    // IDirect3DResource9
    HRESULT STDMETHODCALLTYPE GetDevice(IDirect3DDevice9** ppDevice) override
    {
        if (!ppDevice || !m_dev) return E_NOTIMPL;
        m_dev->AddRef();
        *ppDevice = m_dev;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE SetPrivateData(REFGUID, CONST void*, DWORD, DWORD) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetPrivateData(REFGUID, void*, DWORD*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE FreePrivateData(REFGUID) override { return E_NOTIMPL; }
    DWORD STDMETHODCALLTYPE SetPriority(DWORD) override { return 0; }
    DWORD STDMETHODCALLTYPE GetPriority() override { return 0; }
    void STDMETHODCALLTYPE PreLoad() override {}
    D3DRESOURCETYPE STDMETHODCALLTYPE GetType() override { return D3DRTYPE_TEXTURE; }

    // IDirect3DBaseTexture9
    DWORD STDMETHODCALLTYPE SetLOD(DWORD) override { return 0; }
    DWORD STDMETHODCALLTYPE GetLOD() override { return 0; }
    DWORD STDMETHODCALLTYPE GetLevelCount() override { return 1; }
    HRESULT STDMETHODCALLTYPE SetAutoGenFilterType(D3DTEXTUREFILTERTYPE) override { return S_OK; }
    D3DTEXTUREFILTERTYPE STDMETHODCALLTYPE GetAutoGenFilterType() override { return D3DTEXF_LINEAR; }
    void STDMETHODCALLTYPE GenerateMipSubLevels() override {}

    // IDirect3DTexture9
    HRESULT STDMETHODCALLTYPE GetLevelDesc(UINT Level, D3DSURFACE_DESC* pDesc) override
    {
        if (!pDesc) return E_INVALIDARG;
        pDesc->Format = m_fmt;
        pDesc->Type = D3DRTYPE_SURFACE;
        pDesc->Usage = 0;
        pDesc->Pool = D3DPOOL_DEFAULT;
        pDesc->MultiSampleType = D3DMULTISAMPLE_NONE;
        pDesc->MultiSampleQuality = 0;
        pDesc->Width = m_w;
        pDesc->Height = m_h;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetSurfaceLevel(UINT Level, IDirect3DSurface9** ppSurfaceLevel) override
    {
        if (!ppSurfaceLevel) return E_INVALIDARG;
        *ppSurfaceLevel = new IFakeD3DSurface9(m_hRes, m_w, m_h, m_fmt, m_dev);
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE LockRect(UINT Level, D3DLOCKED_RECT* pLockedRect, CONST RECT*, DWORD) override
    {
        if (!pLockedRect) return E_INVALIDARG;
        static unsigned char s_buf[1920 * 1080 * 4];
        pLockedRect->Pitch = (INT)(m_w * 4);
        pLockedRect->pBits = s_buf;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE UnlockRect(UINT Level) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE AddDirtyRect(CONST RECT*) override { return S_OK; }
};

struct IFakeD3DPixelShader9 : IDirect3DPixelShader9
{
    ULONG m_ref = 1;

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObj) override
    {
        if (!ppvObj) return E_INVALIDARG;
        if (riid == IID_IDirect3DPixelShader9 || riid == IID_IUnknown) {
            *ppvObj = static_cast<IDirect3DPixelShader9*>(this);
            AddRef();
            return S_OK;
        }
        *ppvObj = nullptr;
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++m_ref; }
    ULONG STDMETHODCALLTYPE Release() override
    {
        ULONG r = --m_ref;
        if (!r) delete this;
        return r;
    }
    HRESULT STDMETHODCALLTYPE GetDevice(IDirect3DDevice9**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetFunction(void*, UINT* pSizeOfData) override
    {
        if (pSizeOfData) *pSizeOfData = 0;
        return S_OK;
    }
};

// Set after the class definitions below; the device hands it out from GetDirect3D.
static IDirect3D9* ShimGetD3D9();

struct IFakeD3DVertexBuffer9 : IDirect3DVertexBuffer9
{
    ULONG m_ref = 1;
    static constexpr size_t kBufSize = 4096;
    unsigned char m_buf[kBufSize] = {};

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override
    {
        if (!ppv) return E_INVALIDARG;
        if (riid == IID_IDirect3DVertexBuffer9 || riid == IID_IDirect3DResource9 || riid == IID_IUnknown) {
            *ppv = static_cast<IDirect3DVertexBuffer9*>(this); AddRef(); return S_OK;
        }
        *ppv = nullptr; return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++m_ref; }
    ULONG STDMETHODCALLTYPE Release() override { ULONG r = --m_ref; if (!r) delete this; return r; }

    HRESULT STDMETHODCALLTYPE GetDevice(IDirect3DDevice9**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetPrivateData(REFGUID, CONST void*, DWORD, DWORD) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetPrivateData(REFGUID, void*, DWORD*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE FreePrivateData(REFGUID) override { return E_NOTIMPL; }
    DWORD STDMETHODCALLTYPE SetPriority(DWORD) override { return 0; }
    DWORD STDMETHODCALLTYPE GetPriority() override { return 0; }
    void STDMETHODCALLTYPE PreLoad() override {}
    D3DRESOURCETYPE STDMETHODCALLTYPE GetType() override { return D3DRTYPE_VERTEXBUFFER; }

    HRESULT STDMETHODCALLTYPE Lock(UINT OffsetToLock, UINT, void** ppbData, DWORD) override
    {
        if (!ppbData) return E_INVALIDARG;
        *ppbData = m_buf + (OffsetToLock < kBufSize ? OffsetToLock : 0);
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Unlock() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE GetDesc(D3DVERTEXBUFFER_DESC* pDesc) override
    {
        if (!pDesc) return E_INVALIDARG;
        pDesc->Format = D3DFMT_VERTEXDATA;
        pDesc->Type = D3DRTYPE_VERTEXBUFFER;
        pDesc->Usage = 0;
        pDesc->Pool = D3DPOOL_DEFAULT;
        pDesc->Size = kBufSize;
        pDesc->FVF = 0;
        return S_OK;
    }
};

struct IFakeD3DVertexDeclaration9 : IDirect3DVertexDeclaration9
{
    ULONG m_ref = 1;
    HANDLE m_hDecl = nullptr;

    IFakeD3DVertexDeclaration9(HANDLE h) : m_hDecl(h) {}

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override
    {
        if (!ppv) return E_INVALIDARG;
        if (riid == IID_IDirect3DVertexDeclaration9 || riid == IID_IUnknown) {
            *ppv = static_cast<IDirect3DVertexDeclaration9*>(this); AddRef(); return S_OK;
        }
        *ppv = nullptr; return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++m_ref; }
    ULONG STDMETHODCALLTYPE Release() override { ULONG r = --m_ref; if (!r) delete this; return r; }
    HRESULT STDMETHODCALLTYPE GetDevice(IDirect3DDevice9** ppDevice) override
    {
        if (!ppDevice) return E_INVALIDARG;
        *ppDevice = nullptr;
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE GetDeclaration(D3DVERTEXELEMENT9* pElements, UINT* pNumElements) override
    {
        if (pNumElements) *pNumElements = 0;
        (void)pElements;
        return S_OK;
    }
};

// Translates the app's vertex elements to the DDI form and asks the driver for a declaration
// handle.  This is what the D3D runtime does; without it the driver has no input layout and
// every draw is a no-op.
static HANDLE ShimCreateVertexDecl(const D3DVERTEXELEMENT9* elems)
{
    D3DDDI_DEVICEFUNCS* df = (D3DDDI_DEVICEFUNCS*)g_shimDevFuncs;
    if (!df->pfnCreateVertexShaderDecl || !g_shimDevice || !elems) return nullptr;
    D3DDDIVERTEXELEMENT conv[24] = {};
    UINT n = 0;
    for (; n < 24 && elems[n].Stream != 0xFF; n++) {
        conv[n].Stream = (USHORT)elems[n].Stream;
        conv[n].Offset = (USHORT)elems[n].Offset;
        conv[n].Type = (UCHAR)elems[n].Type;
        conv[n].Method = (UCHAR)elems[n].Method;
        conv[n].Usage = (UCHAR)elems[n].Usage;
        conv[n].UsageIndex = (UCHAR)elems[n].UsageIndex;
    }
    D3DDDIARG_CREATEVERTEXSHADERDECL arg = {};
    arg.NumVertexElements = n;
    HRESULT hr = df->pfnCreateVertexShaderDecl(g_shimDevice, &arg, conv);
    static int s_logged = 0;
    if (s_logged < 6) { s_logged++; Log("shim: CreateVertexShaderDecl(%u elems) = %08lx hDecl=%p", n, hr, arg.ShaderHandle); }
    return SUCCEEDED(hr) ? arg.ShaderHandle : nullptr;
}

struct IFakeD3DDevice9Ex;

struct IFakeD3DSwapChain9 : IDirect3DSwapChain9
{
    ULONG m_ref = 1;
    IFakeD3DDevice9Ex* m_dev;

    IFakeD3DSwapChain9(IFakeD3DDevice9Ex* dev) : m_dev(dev) {}

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override
    {
        if (!ppv) return E_INVALIDARG;
        if (riid == IID_IDirect3DSwapChain9 || riid == IID_IUnknown) {
            *ppv = static_cast<IDirect3DSwapChain9*>(this); AddRef(); return S_OK;
        }
        *ppv = nullptr; return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++m_ref; }
    ULONG STDMETHODCALLTYPE Release() override { ULONG r = --m_ref; if (!r) delete this; return r; }

    HRESULT STDMETHODCALLTYPE Present(CONST RECT* pSourceRect, CONST RECT* pDestRect,
                                      HWND hDestWindowOverride, CONST RGNDATA* pDirtyRegion,
                                      DWORD dwFlags) override;
    HRESULT STDMETHODCALLTYPE GetFrontBufferData(IDirect3DSurface9*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE GetBackBuffer(UINT iBackBuffer, D3DBACKBUFFER_TYPE Type,
                                            IDirect3DSurface9** ppBackBuffer) override;
    HRESULT STDMETHODCALLTYPE GetRasterStatus(D3DRASTER_STATUS*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetDisplayMode(D3DDISPLAYMODE* pMode) override
    {
        if (!pMode) return E_INVALIDARG;
        pMode->Width = 1920; pMode->Height = 1080; pMode->RefreshRate = 60; pMode->Format = D3DFMT_X8R8G8B8;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetDevice(IDirect3DDevice9** ppDevice) override;
    HRESULT STDMETHODCALLTYPE GetPresentParameters(D3DPRESENT_PARAMETERS* pPresentationParameters) override
    {
        if (!pPresentationParameters) return E_INVALIDARG;
        memset(pPresentationParameters, 0, sizeof *pPresentationParameters);
        pPresentationParameters->BackBufferWidth = 1920;
        pPresentationParameters->BackBufferHeight = 1080;
        pPresentationParameters->BackBufferFormat = D3DFMT_X8R8G8B8;
        pPresentationParameters->BackBufferCount = 1;
        pPresentationParameters->SwapEffect = D3DSWAPEFFECT_DISCARD;
        pPresentationParameters->Windowed = TRUE;
        return S_OK;
    }
};

struct IFakeD3DDevice9Ex : IDirect3DDevice9Ex
{
    ULONG m_ref = 1;
    D3DDDI_DEVICEFUNCS* m_df;

    IFakeD3DDevice9Ex() : m_df((D3DDDI_DEVICEFUNCS*)g_shimDevFuncs) {}

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObj) override
    {
        if (!ppvObj) return E_INVALIDARG;
        if (riid == IID_IDirect3DDevice9Ex || riid == IID_IDirect3DDevice9 || riid == IID_IUnknown) {
            *ppvObj = static_cast<IDirect3DDevice9Ex*>(this);
            AddRef();
            return S_OK;
        }
        // Log the first few unknown QI requests so we know what MPCVR asks for
        static int s_qiLog = 0;
        if (s_qiLog < 8) {
            s_qiLog++;
            void* caller = _ReturnAddress();
            char callerMod[64] = "?"; DWORD callerOff = 0;
            HMODULE hm = nullptr;
            if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                   (LPCSTR)caller, &hm) && hm) {
                GetModuleFileNameA(hm, callerMod, sizeof(callerMod));
                char* base = strrchr(callerMod, '\\');
                if (base) memmove(callerMod, base + 1, strlen(base));
                callerOff = (DWORD)((ULONG_PTR)caller - (ULONG_PTR)hm);
            }
            wchar_t envVal[8] = L""; DWORD envLen = GetEnvironmentVariableW(L"MPC_D3D9_SHIM", envVal, 8);
            Log("shim: dev QI unknown {%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x} -> E_NOINTERFACE  [caller=%s+0x%lx MPC_D3D9_SHIM=%ls(%lu)]",
                riid.Data1, riid.Data2, riid.Data3,
                riid.Data4[0], riid.Data4[1], riid.Data4[2], riid.Data4[3],
                riid.Data4[4], riid.Data4[5], riid.Data4[6], riid.Data4[7],
                callerMod, callerOff, envVal, envLen);
        }
        *ppvObj = nullptr;
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++m_ref; }
    ULONG STDMETHODCALLTYPE Release() override
    {
        ULONG r = --m_ref;
        if (!r) delete this;
        return r;
    }

    // ---- real DDI calls ----------------------------------------------------------------------------

    HRESULT STDMETHODCALLTYPE SetTexture(DWORD Stage, IDirect3DBaseTexture9* pTexture) override
    {
        HANDLE hRes = nullptr;
        if (pTexture) {
            IDirect3DTexture9* t = nullptr;
            if (SUCCEEDED(pTexture->QueryInterface(IID_IDirect3DTexture9, (void**)&t)) && t) {
                hRes = ((IFakeD3DTexture9*)t)->m_hRes;
                // Track which IFakeD3DTexture9 is bound per stage so Release can detect
                // "freed while bound" and capture the real driver inner-object pointer.
                if (Stage < 16) s_stageBound[Stage] = (IFakeD3DTexture9*)t;
                t->Release();
                if (Stage < 16) g_shimStageHRes[Stage] = hRes;
                g_shimBoundCount = 0; for (int _i = 0; _i < 16; _i++) if (g_shimStageHRes[_i]) g_shimBoundCount++;
            }
        } else {
            // Swallow-one-unbind trigger: hide the first stage-0 unbind after the
            // first draw from the driver.  The shim reports success and keeps its
            // own stage tracking intact (s_stageBound/g_shimStageHRes stay set), so
            // a later Release sees the texture STILL BOUND while the driver's
            // applied binding (g_drvBoundHRes[0]) also still references it.
            if (Stage == 0 && g_swallowNextUnbind && g_shimStageHRes[0]) {
                g_swallowNextUnbind = false;
                Log("shim: SetTexture(0, null) SWALLOWED - driver left bound (hRes=%p)",
                    (void*)g_shimStageHRes[0]);
                return S_OK;
            }
            // Unbind: clear the stage tracking entry so Release can distinguish
            // "unbound before release" (fix present) from "still bound".
            if (Stage < 16) s_stageBound[Stage] = nullptr;
            if (Stage < 16) g_shimStageHRes[Stage] = nullptr;
            g_shimBoundCount = 0; for (int _i = 0; _i < 16; _i++) if (g_shimStageHRes[_i]) g_shimBoundCount++;
            Log("shim: SetTexture(%u, null) UNBIND boundCount=%d", Stage, g_shimBoundCount);
        }
        HRESULT hr = S_OK;
        if (m_df->pfnSetTexture && g_shimDevice)
            hr = m_df->pfnSetTexture(g_shimDevice, Stage, hRes);
        // The DDI call runs the driver's deferred flush synchronously; the flush
        // consumed the previous applied binding, so the new binding is now applied.
        if (Stage < 16) g_drvBoundHRes[Stage] = hRes;
        // Diagnostic: does the driver populate hRes[+0x48] at SetTexture time?
        if (hRes) {
            void* inner = nullptr;
            __try { inner = *(void**)((char*)hRes + 0x48); } __except(EXCEPTION_EXECUTE_HANDLER) {}
            Log("shim: SetTexture(%u, hRes=%p) inner[+0x48]=%p hr=%08lx boundCount=%d", Stage, hRes, inner, hr, g_shimBoundCount);
        }
        return hr;
    }

    HRESULT STDMETHODCALLTYPE SetTextureStageState(DWORD Stage, D3DTEXTURESTAGESTATETYPE Type,
                                                   DWORD Value) override
    {
        if (m_df->pfnSetTextureStageState && g_shimDevice) {
            D3DDDIARG_TEXTURESTAGESTATE tss = {};
            tss.Stage = Stage;
            tss.State = (D3DDDITEXTURESTAGESTATETYPE)Type;
            tss.Value = Value;
            return m_df->pfnSetTextureStageState(g_shimDevice, &tss);
        }
        return S_OK;
    }

    // Fullscreen-triangle fallback used when the caller hands over no vertex data; matches the workload's
    // single-triangle draw in legacy9.cpp.
    static const float kVerts[9]; // = { -1,-1,0,  3,-1,0,  -1,3,0 }

    HRESULT STDMETHODCALLTYPE DrawPrimitiveUP(D3DPRIMITIVETYPE PrimitiveType, UINT PrimitiveCount,
                                              CONST void* pVertexStreamZeroData,
                                              UINT VertexStreamZeroStride) override
    {
        if (!g_shimDevice) return S_OK;
        const void* verts = pVertexStreamZeroData ? pVertexStreamZeroData : (const void*)kVerts;
        if (m_df->pfnSetStreamSourceUm) {
            D3DDDIARG_SETSTREAMSOURCEUM ss = {};
            ss.Stream = 0;
            ss.Stride = VertexStreamZeroStride ? VertexStreamZeroStride : 3 * sizeof(float);
            m_df->pfnSetStreamSourceUm(g_shimDevice, &ss, verts);
        }
        if (m_df->pfnDrawPrimitive) {
            D3DDDIARG_DRAWPRIMITIVE dp = {};
            dp.PrimitiveType = PrimitiveType;
            dp.VStart = 0;
            dp.PrimitiveCount = PrimitiveCount ? PrimitiveCount : 1;
            // Snapshot the currently-bound texture handles at draw time. MPCVR unbinds
            // textures before Present, so by the time the deferred flush fires stateApply
            // the live g_shimBoundCount is already 0. We preserve state here instead.
            g_drawCommittedCount = 0;
            for (int _i = 0; _i < 16; _i++) {
                g_drawCommittedHRes[_i] = g_shimStageHRes[_i];
                if (g_shimStageHRes[_i]) g_drawCommittedCount++;
            }
            static int s_logged = 0;
            if (s_logged < 3) { s_logged++; Log("shim: DrawPrimitiveUP -> pfnDrawPrimitive  committedCount=%d hRes[0]=%p", g_drawCommittedCount, (void*)g_drawCommittedHRes[0]); }
            HRESULT hrDraw = m_df->pfnDrawPrimitive(g_shimDevice, &dp, nullptr);
            // Re-arm the swallow-one-unbind trigger after EVERY draw: MPCVR's
            // per-frame TextureBlt cleanup unbinds stage 0 after each draw, so a
            // one-shot swallow is spent on frame 1 and the window closes long
            // before the format-change ReleaseVP.  Re-arming keeps the driver's
            // applied stage-0 binding in place until the release.  NEW MPCVR's
            // explicit ReleaseVP unbind is the first unbind NOT swallowed (the
            // flag was spent by the frame cleanup), so it still reaches the
            // driver while the texture is alive -- preserving the A/B split.
            g_swallowNextUnbind = true;
            if (!s_swallowArmed) {
                s_swallowArmed = true;
                Log("shim: DrawPrimitiveUP: swallow-one-unbind ARMED (re-armed every draw)");
            }
            return hrDraw;
        }
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE CreateTexture(UINT Width, UINT Height, UINT Levels, DWORD Usage,
                                            D3DFORMAT Format, D3DPOOL Pool, IDirect3DTexture9** ppTexture,
                                            HANDLE* pSharedHandle) override
    {
        if (!ppTexture) return E_INVALIDARG;
        *ppTexture = nullptr;
        if (!m_df->pfnCreateResource || !g_shimDevice) {
            Log("shim: CreateTexture(%ux%u fmt=%u) -> E_NOTIMPL (no pfnCreateResource or no device)", Width, Height, (UINT)Format);
            return E_NOTIMPL;
        }
        // One texture with the caller's own geometry and usage flags; the render-target
        // usage must reach the driver or it refuses to build a render-target view for it.
        D3DDDI_SURFACEINFO surf = {};
        surf.Width = Width;
        surf.Height = Height;
        surf.Depth = 1;
        D3DDDIARG_CREATERESOURCE cr = {};
        cr.Format = (D3DDDIFORMAT)Format;
        cr.Pool = D3DDDIPOOL_VIDEOMEMORY;
        cr.MultisampleType = D3DDDIMULTISAMPLE_NONE;
        cr.pSurfList = &surf;
        cr.SurfCount = 1;
        cr.MipLevels = 1;
        cr.Flags.Texture = 1;
        if (Usage & D3DUSAGE_RENDERTARGET) cr.Flags.RenderTarget = 1;
        if (Usage & D3DUSAGE_DEPTHSTENCIL) cr.Flags.ZBuffer = 1;
        cr.Rotation = D3DDDI_ROTATION_IDENTITY;
        static UINT_PTR s_nextRtHandle = 0x50000;
        cr.hResource = (HANDLE)s_nextRtHandle++; // the runtime's handle; the driver replaces it
        g_inCreateResource = true;
        g_createResourceAllocsCount = 0;
        HRESULT hr = m_df->pfnCreateResource(g_shimDevice, &cr);
        g_inCreateResource = false;
        int nDriverAllocs = g_createResourceAllocsCount;
        Log("shim: CreateTexture: pfnCreateResource recorded %d driver allocs", nDriverAllocs);
        for (int _da = 0; _da < nDriverAllocs; _da++)
            Log("shim:   driverAlloc[%d] = %p  size=%zu", _da, g_createResourceAllocs[_da].ptr, (size_t)g_createResourceAllocs[_da].size);
        // Diagnostic: read hRes[+0x48] immediately after CreateResource to check whether
        // the driver populates the inner-object pointer at resource-creation time.
        // (No __try needed: the resource handle is valid because pfnCreateResource succeeded.)
        void* innerAtCreate = SUCCEEDED(hr) ? *(void**)((char*)cr.hResource + 0x48) : nullptr;
        Log("shim: CreateTexture(%ux%u fmt=%u) -> CreateResource = %08lx hRes=%p inner[+0x48]=%p",
            Width, Height, (UINT)Format, hr, cr.hResource, innerAtCreate);
        if (SUCCEEDED(hr) && g_plant710465 && g_mmobjForCrash) {
            *(uint64_t*)((uint8_t*)g_mmobjForCrash + 0x64) = 0x00000001DEADBEEFULL;
            Log("shim: injected bad pointer at obj+0x64: obj=%p", g_mmobjForCrash);
            g_mmobjForCrash = nullptr;
        }
        // Diagnostic (first few resources only): dump every non-null qword in the first
        // 0x100 bytes of the driver's resource object, so the offsets the deep flush
        // follows ([hRes+0x10] backing, [hRes+0x48] inner) are visible at creation time.
        if (SUCCEEDED(hr)) {
            static int s_hresDumped = 0;
            if (s_hresDumped < 6) {
                s_hresDumped++;
                for (int off = 0; off < 0x100; off += 8) {
                    void* v = *(void**)((char*)cr.hResource + off);
                    if (v && (uintptr_t)v > 0x10000)
                        Log("shim: hRes[+0x%02x]=%p (non-null at create)", off, v);
                }
            }
        }
        if (FAILED(hr)) return hr;
        auto* tex = new IFakeD3DTexture9(cr.hResource, Width, Height, Format, this);
        for (int _da = 0; _da < nDriverAllocs; _da++)
            tex->m_driverAllocs[_da] = g_createResourceAllocs[_da];
        tex->m_driverAllocsCount = nDriverAllocs;
        *ppTexture = tex;
        return S_OK;
    }

    // The runtime's Reset: drain, destroy, re-create, and put the fake channel and breakpoints back.
    HRESULT STDMETHODCALLTYPE ResetEx(D3DPRESENT_PARAMETERS*, D3DDISPLAYMODEEX*) override
    {
        Log("shim: ResetEx");
        // pfnFlush and pfnDestroyDevice can crash in atiumd6a when our fake state does not satisfy
        // the driver destructor (reading from sentinel -1 fields). Catch and suppress: a new device
        // will be created below, so a partial destroy is better than aborting the reset sequence.
        __try {
            if (g_shimDevice && m_df->pfnFlush) m_df->pfnFlush(g_shimDevice);
        } __except(Log("shim: ResetEx pfnFlush exception %08lx at %p (suppressed)",
                       GetExceptionCode(),
                       GetExceptionInformation() ? GetExceptionInformation()->ExceptionRecord->ExceptionAddress : nullptr),
                   EXCEPTION_EXECUTE_HANDLER) {
        }
        __try {
            if (g_shimDevice && m_df->pfnDestroyDevice) {
                HRESULT hr = m_df->pfnDestroyDevice(g_shimDevice);
                Log("shim: ResetEx DestroyDevice = %08lx", hr);
            }
        } __except(Log("shim: ResetEx pfnDestroyDevice exception %08lx at %p (suppressed)",
                       GetExceptionCode(),
                       GetExceptionInformation() ? GetExceptionInformation()->ExceptionRecord->ExceptionAddress : nullptr),
                   EXCEPTION_EXECUTE_HANDLER) {
        }
        g_shimDevice = nullptr;
        HRESULT hr = ShimCreateDriverDevice();
        if (FAILED(hr)) return hr;
        ShimArmBps();
        Log("shim: ResetEx returning S_OK");
        return S_OK;
    }

    // ---- special returns ---------------------------------------------------------------------------

    HRESULT STDMETHODCALLTYPE GetDirect3D(IDirect3D9** ppD3D9) override
    {
        if (!ppD3D9) return E_INVALIDARG;
        IDirect3D9* d3d = ShimGetD3D9();
        if (d3d) d3d->AddRef();
        *ppD3D9 = d3d;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetDeviceCaps(D3DCAPS9* pCaps) override
    {
        if (!pCaps) return E_INVALIDARG;
        memset(pCaps, 0, sizeof *pCaps);
        pCaps->PixelShaderVersion = D3DPS_VERSION(3, 0);
        pCaps->MaxSimultaneousTextures = 8;
        pCaps->MaxTextureWidth = 4096;
        pCaps->MaxTextureHeight = 4096;
        static int s_logged = 0;
        if (!s_logged++) Log("shim: GetDeviceCaps called");
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetDisplayMode(UINT iSwapChain, D3DDISPLAYMODE* pMode) override
    {
        if (!pMode) return E_INVALIDARG;
        pMode->Width = 1920;
        pMode->Height = 1080;
        pMode->RefreshRate = 60;
        pMode->Format = D3DFMT_X8R8G8B8;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetDisplayModeEx(UINT iSwapChain, D3DDISPLAYMODEEX* pMode,
                                               D3DDISPLAYROTATION* pRotation) override
    {
        if (!pMode) return E_INVALIDARG;
        pMode->Size = sizeof(D3DDISPLAYMODEEX);
        pMode->Width = 1920;
        pMode->Height = 1080;
        pMode->RefreshRate = 60;
        pMode->Format = D3DFMT_X8R8G8B8;
        pMode->ScanLineOrdering = D3DSCANLINEORDERING_PROGRESSIVE;
        if (pRotation) *pRotation = D3DDISPLAYROTATION_IDENTITY;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetCreationParameters(D3DDEVICE_CREATION_PARAMETERS* pParameters) override
    {
        if (!pParameters) return E_INVALIDARG;
        pParameters->AdapterOrdinal = 0;
        pParameters->DeviceType = D3DDEVTYPE_HAL;
        pParameters->hFocusWindow = g_shimFocusWnd;
        pParameters->BehaviorFlags = D3DCREATE_HARDWARE_VERTEXPROCESSING;
        return S_OK;
    }
    UINT STDMETHODCALLTYPE GetAvailableTextureMem() override { return 512u << 20; }
    UINT STDMETHODCALLTYPE GetNumberOfSwapChains() override { return 1; }
    BOOL STDMETHODCALLTYPE GetSoftwareVertexProcessing() override { return FALSE; }
    HRESULT STDMETHODCALLTYPE GetMaximumFrameLatency(UINT* pMaxLatency) override
    {
        if (pMaxLatency) *pMaxLatency = 3;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetBackBuffer(UINT iSwapChain, UINT iBackBuffer, D3DBACKBUFFER_TYPE Type,
                                            IDirect3DSurface9** ppBackBuffer) override
    {
        if (!ppBackBuffer) return E_INVALIDARG;
        // A real render-target resource for the backbuffer, created once, so a
        // SetRenderTarget(backbuffer) binds a driver surface rather than null.
        static HANDLE s_bbRes = ShimCreateSurfaceResource(1920, 1080, D3DFMT_X8R8G8B8, true, false);
        *ppBackBuffer = new IFakeD3DSurface9(s_bbRes, 1920, 1080, D3DFMT_X8R8G8B8, this);
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetRenderTarget(DWORD RenderTargetIndex,
                                              IDirect3DSurface9** ppRenderTarget) override
    {
        if (!ppRenderTarget) return E_INVALIDARG;
        *ppRenderTarget = new IFakeD3DSurface9(nullptr, 1920, 1080, D3DFMT_X8R8G8B8, this);
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetDepthStencilSurface(IDirect3DSurface9** ppZStencilSurface) override
    {
        if (!ppZStencilSurface) return E_INVALIDARG;
        *ppZStencilSurface = new IFakeD3DSurface9(nullptr, 1920, 1080, D3DFMT_D24S8, this);
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE CreateRenderTarget(UINT Width, UINT Height, D3DFORMAT Format,
                                                 D3DMULTISAMPLE_TYPE MultiSample, DWORD MultisampleQuality,
                                                 BOOL Lockable, IDirect3DSurface9** ppSurface,
                                                 HANDLE* pSharedHandle) override
    {
        if (!ppSurface) return E_INVALIDARG;
        HANDLE hRes = ShimCreateSurfaceResource(Width, Height, Format, true, false);
        *ppSurface = new IFakeD3DSurface9(hRes, Width, Height, Format, this);
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE CreateDepthStencilSurface(UINT Width, UINT Height, D3DFORMAT Format,
                                                        D3DMULTISAMPLE_TYPE MultiSample,
                                                        DWORD MultisampleQuality, BOOL Discard,
                                                        IDirect3DSurface9** ppSurface,
                                                        HANDLE* pSharedHandle) override
    {
        if (!ppSurface) return E_INVALIDARG;
        HANDLE hRes = ShimCreateSurfaceResource(Width, Height, Format, false, true);
        *ppSurface = new IFakeD3DSurface9(hRes, Width, Height, Format, this);
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE CreateOffscreenPlainSurface(UINT Width, UINT Height, D3DFORMAT Format,
                                                          D3DPOOL Pool, IDirect3DSurface9** ppSurface,
                                                          HANDLE* pSharedHandle) override
    {
        if (!ppSurface) return E_INVALIDARG;
        *ppSurface = new IFakeD3DSurface9(nullptr, Width, Height, Format, this);
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE CreateRenderTargetEx(UINT Width, UINT Height, D3DFORMAT Format,
                                                   D3DMULTISAMPLE_TYPE MultiSample, DWORD MultisampleQuality,
                                                   BOOL Lockable, IDirect3DSurface9** ppSurface,
                                                   HANDLE* pSharedHandle, DWORD dwUsage) override
    {
        return CreateRenderTarget(Width, Height, Format, MultiSample, MultisampleQuality, Lockable,
                                  ppSurface, pSharedHandle);
    }
    HRESULT STDMETHODCALLTYPE CreateOffscreenPlainSurfaceEx(UINT Width, UINT Height, D3DFORMAT Format,
                                                            D3DPOOL Pool, IDirect3DSurface9** ppSurface,
                                                            HANDLE* pSharedHandle, DWORD dwUsage) override
    {
        return CreateOffscreenPlainSurface(Width, Height, Format, Pool, ppSurface, pSharedHandle);
    }
    HRESULT STDMETHODCALLTYPE CreateDepthStencilSurfaceEx(UINT Width, UINT Height, D3DFORMAT Format,
                                                          D3DMULTISAMPLE_TYPE MultiSample,
                                                          DWORD MultisampleQuality, BOOL Discard,
                                                          IDirect3DSurface9** ppSurface,
                                                          HANDLE* pSharedHandle, DWORD dwUsage) override
    {
        return CreateDepthStencilSurface(Width, Height, Format, MultiSample, MultisampleQuality, Discard,
                                         ppSurface, pSharedHandle);
    }
    HRESULT STDMETHODCALLTYPE CreatePixelShader(CONST DWORD* pFunction,
                                                IDirect3DPixelShader9** ppShader) override
    {
        if (!ppShader) return E_INVALIDARG;
        *ppShader = new IFakeD3DPixelShader9();
        static int s_logged = 0;
        if (!s_logged++) Log("shim: CreatePixelShader called");
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE CreateQuery(D3DQUERYTYPE Type, IDirect3DQuery9** ppQuery) override
    {
        if (ppQuery) *ppQuery = nullptr;
        return E_NOTIMPL;
    }
    BOOL STDMETHODCALLTYPE ShowCursor(BOOL bShow) override { return FALSE; }
    float STDMETHODCALLTYPE GetNPatchMode() override { return 0.0f; }

    // ---- S_OK stubs ----------------------------------------------------------------------------------

    HRESULT STDMETHODCALLTYPE TestCooperativeLevel() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE EvictManagedResources() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SetCursorProperties(UINT, UINT, IDirect3DSurface9*) override { return S_OK; }
    void STDMETHODCALLTYPE SetCursorPosition(int, int, DWORD) override {}
    HRESULT STDMETHODCALLTYPE SetDialogBoxMode(BOOL) override { return S_OK; }
    void STDMETHODCALLTYPE SetGammaRamp(UINT, DWORD, CONST D3DGAMMARAMP*) override {}
    void STDMETHODCALLTYPE GetGammaRamp(UINT, D3DGAMMARAMP*) override {}
    HRESULT STDMETHODCALLTYPE Reset(D3DPRESENT_PARAMETERS* p) override { return ResetEx(p, nullptr); }
    // The runtime's Present: a blt of the current render target to the screen through the
    // driver's own present path (which is also where its draw batching flushes).
    static HANDLE g_lastRt0;
    static HRESULT ShimPresentDdi(IFakeD3DDevice9Ex* dev)
    {
        D3DDDI_DEVICEFUNCS* df = (D3DDDI_DEVICEFUNCS*)g_shimDevFuncs;
        if (!df->pfnPresent || !g_shimDevice) return S_OK;
        static HANDLE s_fallbackSrc = ShimCreateSurfaceResource(1920, 1080, D3DFMT_X8R8G8B8, true, false);
        HANDLE hSrc = g_lastRt0 ? g_lastRt0 : s_fallbackSrc;
        D3DDDIARG_PRESENT p = {};
        p.hSrcResource = hSrc;
        p.SrcSubResourceIndex = 0;
        p.Flags.Blt = 1;
        HRESULT hr = df->pfnPresent(g_shimDevice, &p);
        static int s_logged = 0;
        if (s_logged < 6) { s_logged++; Log("shim: Present(hSrc=%p) = %08lx", hSrc, hr); }
        // The runtime's readback: GetRenderTargetData maps to pfnCaptureToSysMem, which is
        // the entry into the driver's batch recorder (0x2CCE0) -- the only driver of the
        // deferred state flush (stateApply -> atiumd6a flush).  One readback per present,
        // like the runtime does for thumbnail/stat capture paths, drives the batch forward.
        if (df->pfnCaptureToSysMem && hSrc) {
            static HANDLE s_sysmem = nullptr;
            if (!s_sysmem) {
                D3DDDI_SURFACEINFO surf = {};
                surf.Width = 1920;
                surf.Height = 1080;
                surf.Depth = 1;
                D3DDDIARG_CREATERESOURCE cr = {};
                cr.Format = (D3DDDIFORMAT)D3DFMT_X8R8G8B8;
                cr.Pool = D3DDDIPOOL_VIDEOMEMORY;
                cr.MultisampleType = D3DDDIMULTISAMPLE_NONE;
                cr.pSurfList = &surf;
                cr.SurfCount = 1;
                cr.MipLevels = 1;
                cr.Rotation = D3DDDI_ROTATION_IDENTITY;
                static UINT_PTR s_sysHandle = 0x90000;
                cr.hResource = (HANDLE)s_sysHandle++;
                HRESULT shr = df->pfnCreateResource(g_shimDevice, &cr);
                s_sysmem = SUCCEEDED(shr) ? cr.hResource : nullptr;
                Log("shim: sysmem capture target CreateResource = %08lx hRes=%p", shr, cr.hResource);
            }
            if (s_sysmem) {
                D3DDDIARG_CAPTURETOSYSMEM cap = {};
                cap.hSrcResource = hSrc;
                cap.hDstResource = s_sysmem;
                RECT r = { 0, 0, 1920, 1080 };
                cap.SrcRect = r;
                cap.DstRect = r;
                HRESULT chr = df->pfnCaptureToSysMem(g_shimDevice, &cap);
                if (s_logged < 12) { s_logged++; Log("shim: CaptureToSysMem(src=%p) = %08lx", hSrc, chr); }
            }
        }
        return hr;
    }
    HRESULT STDMETHODCALLTYPE Present(CONST RECT*, CONST RECT*, HWND, CONST RGNDATA*) override
    {
        return ShimPresentDdi(this);
    }
    HRESULT STDMETHODCALLTYPE PresentEx(CONST RECT*, CONST RECT*, HWND, CONST RGNDATA*, DWORD) override
    {
        return ShimPresentDdi(this);
    }
    HRESULT STDMETHODCALLTYPE BeginScene() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE EndScene() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE Clear(DWORD, CONST D3DRECT*, DWORD, D3DCOLOR, float, DWORD) override
    {
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE UpdateSurface(IDirect3DSurface9*, CONST RECT*, IDirect3DSurface9*,
                                            CONST POINT*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE UpdateTexture(IDirect3DBaseTexture9*, IDirect3DBaseTexture9*) override
    {
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetRenderTargetData(IDirect3DSurface9*, IDirect3DSurface9*) override
    {
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetFrontBufferData(UINT, IDirect3DSurface9*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE StretchRect(IDirect3DSurface9*, CONST RECT*, IDirect3DSurface9*, CONST RECT*,
                                          D3DTEXTUREFILTERTYPE) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ColorFill(IDirect3DSurface9*, CONST RECT*, D3DCOLOR) override {
        static int s_logged = 0;
        if (!s_logged++) Log("shim: ColorFill called");
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE SetRenderTarget(DWORD RenderTargetIndex, IDirect3DSurface9* pRenderTarget) override
    {
        HANDLE hRes = pRenderTarget ? ((IFakeD3DSurface9*)pRenderTarget)->m_hRes : nullptr;
        if (RenderTargetIndex == 0) g_lastRt0 = hRes;
        if (m_df->pfnSetRenderTarget && g_shimDevice) {
            D3DDDIARG_SETRENDERTARGET rt = {};
            rt.RenderTargetIndex = RenderTargetIndex;
            rt.hRenderTarget = hRes;
            rt.SubResourceIndex = 0;
            HRESULT hr = m_df->pfnSetRenderTarget(g_shimDevice, &rt);
            static int s_logged = 0;
            if (s_logged < 8) { s_logged++; Log("shim: SetRenderTarget(%u, hRes=%p) = %08lx", RenderTargetIndex, hRes, hr); }
            return hr;
        }
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE SetDepthStencilSurface(IDirect3DSurface9* pNewZStencil) override
    {
        HANDLE hRes = pNewZStencil ? ((IFakeD3DSurface9*)pNewZStencil)->m_hRes : nullptr;
        if (m_df->pfnSetDepthStencil && g_shimDevice) {
            D3DDDIARG_SETDEPTHSTENCIL ds = {};
            ds.hZBuffer = hRes;
            HRESULT hr = m_df->pfnSetDepthStencil(g_shimDevice, &ds);
            static int s_logged = 0;
            if (s_logged < 4) { s_logged++; Log("shim: SetDepthStencilSurface(hRes=%p) = %08lx", hRes, hr); }
            return hr;
        }
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE SetTransform(D3DTRANSFORMSTATETYPE, CONST D3DMATRIX*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE GetTransform(D3DTRANSFORMSTATETYPE State, D3DMATRIX* pMatrix) override
    {
        if (!pMatrix) return E_INVALIDARG;
        memset(pMatrix, 0, sizeof *pMatrix);
        pMatrix->m[0][0] = pMatrix->m[1][1] = pMatrix->m[2][2] = pMatrix->m[3][3] = 1.0f;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE MultiplyTransform(D3DTRANSFORMSTATETYPE, CONST D3DMATRIX*) override
    {
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE SetViewport(CONST D3DVIEWPORT9*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SetMaterial(CONST D3DMATERIAL9*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SetLight(DWORD, CONST D3DLIGHT9*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE LightEnable(DWORD, BOOL) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SetClipPlane(DWORD, CONST float*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SetRenderState(D3DRENDERSTATETYPE, DWORD) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE GetRenderState(D3DRENDERSTATETYPE, DWORD* pValue) override
    {
        if (pValue) *pValue = 0;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE SetClipStatus(CONST D3DCLIPSTATUS9*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SetSamplerState(DWORD, D3DSAMPLERSTATETYPE, DWORD) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ValidateDevice(DWORD* pNumPasses) override
    {
        if (pNumPasses) *pNumPasses = 0;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE SetPaletteEntries(UINT, CONST PALETTEENTRY*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SetCurrentTexturePalette(UINT) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SetScissorRect(CONST RECT*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SetSoftwareVertexProcessing(BOOL) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SetNPatchMode(float) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE DrawPrimitive(D3DPRIMITIVETYPE, UINT, UINT) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE DrawIndexedPrimitive(D3DPRIMITIVETYPE, INT, UINT, UINT, UINT,
                                                   UINT) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE DrawIndexedPrimitiveUP(D3DPRIMITIVETYPE, UINT, UINT, UINT, CONST void*,
                                                     D3DFORMAT, CONST void*, UINT) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SetVertexDeclaration(IDirect3DVertexDeclaration9* pDecl) override
    {
        HANDLE hDecl = pDecl ? ((IFakeD3DVertexDeclaration9*)pDecl)->m_hDecl : nullptr;
        D3DDDI_DEVICEFUNCS* df = (D3DDDI_DEVICEFUNCS*)g_shimDevFuncs;
        if (df->pfnSetVertexShaderDecl && g_shimDevice) {
            HRESULT hr = df->pfnSetVertexShaderDecl(g_shimDevice, hDecl);
            static int s_logged = 0;
            if (s_logged < 6) { s_logged++; Log("shim: SetVertexShaderDecl(%p) = %08lx", hDecl, hr); }
            return hr;
        }
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE SetFVF(DWORD FVF) override
    {
        // The runtime translates FVF into a vertex declaration; do the same for the
        // common MPCVR layout (transformed position + one texcoord set) and bind it.
        D3DVERTEXELEMENT9 elems[8];
        UINT n = 0;
        memset(elems, 0, sizeof elems);
        USHORT off = 0;
        if (FVF & D3DFVF_XYZRHW) {
            elems[n++] = { 0, off, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITIONT, 0 };
            off += 16;
        } else if (FVF & D3DFVF_XYZ) {
            elems[n++] = { 0, off, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0 };
            off += 12;
        }
        if (FVF & D3DFVF_NORMAL) { elems[n++] = { 0, off, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_NORMAL, 0 }; off += 12; }
        if (FVF & D3DFVF_DIFFUSE) { elems[n++] = { 0, off, D3DDECLTYPE_D3DCOLOR, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_COLOR, 0 }; off += 4; }
        static const float k_texSize[5] = { 0, 2, 3, 4, 1 };
        DWORD texCount = (FVF & D3DFVF_TEXCOUNT_MASK) >> D3DFVF_TEXCOUNT_SHIFT;
        for (DWORD t = 0; t < texCount && t < 4; t++) {
            DWORD dim = (FVF >> (16 + 2 * t)) & 3;
            D3DDECLTYPE ty = dim == 3 ? D3DDECLTYPE_FLOAT4 : dim == 2 ? D3DDECLTYPE_FLOAT3 : dim == 1 ? D3DDECLTYPE_FLOAT1 : D3DDECLTYPE_FLOAT2;
            USHORT sz = (USHORT)(dim == 3 ? 16 : dim == 2 ? 12 : dim == 1 ? 4 : 8);
            elems[n] = { 0, off, (BYTE)ty, (BYTE)D3DDECLMETHOD_DEFAULT, (BYTE)D3DDECLUSAGE_TEXCOORD, (BYTE)t };
            n++;
            off += sz;
        }
        elems[n] = { 0xFF, 0, D3DDECLTYPE_UNUSED, 0, 0, 0 };
        static DWORD s_lastFvf = 0;
        static HANDLE s_fvfDecl = nullptr;
        if (FVF != s_lastFvf || !s_fvfDecl) { s_fvfDecl = ShimCreateVertexDecl(elems); s_lastFvf = FVF; }
        D3DDDI_DEVICEFUNCS* df = (D3DDDI_DEVICEFUNCS*)g_shimDevFuncs;
        if (df->pfnSetVertexShaderDecl && g_shimDevice) {
            HRESULT hr = df->pfnSetVertexShaderDecl(g_shimDevice, s_fvfDecl);
            Log("shim: SetFVF(%08x) -> SetVertexShaderDecl(%p) = %08lx", FVF, s_fvfDecl, hr);
            return hr;
        }
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE SetVertexShader(IDirect3DVertexShader9*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SetVertexShaderConstantF(UINT, CONST float*, UINT) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SetVertexShaderConstantI(UINT, CONST int*, UINT) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SetVertexShaderConstantB(UINT, CONST BOOL*, UINT) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SetStreamSource(UINT, IDirect3DVertexBuffer9*, UINT, UINT) override
    {
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE SetIndices(IDirect3DIndexBuffer9*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SetStreamSourceFreq(UINT, UINT) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SetPixelShader(IDirect3DPixelShader9*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SetPixelShaderConstantF(UINT, CONST float*, UINT) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SetPixelShaderConstantI(UINT, CONST int*, UINT) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SetPixelShaderConstantB(UINT, CONST BOOL*, UINT) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE BeginStateBlock() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SetGPUThreadPriority(INT) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE WaitForVBlank(UINT) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE CheckResourceResidency(IDirect3DResource9**, UINT32) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SetMaximumFrameLatency(UINT) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE CheckDeviceState(HWND) override { return S_OK; }

    // ---- swapchains --------------------------------------------------------------------------------

    HRESULT STDMETHODCALLTYPE CreateAdditionalSwapChain(D3DPRESENT_PARAMETERS*,
                                                        IDirect3DSwapChain9** ppSwapChain) override
    {
        if (!ppSwapChain) return E_INVALIDARG;
        *ppSwapChain = new IFakeD3DSwapChain9(this);
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetSwapChain(UINT iSwapChain, IDirect3DSwapChain9** ppSwapChain) override
    {
        if (!ppSwapChain || iSwapChain != 0) return E_INVALIDARG;
        *ppSwapChain = new IFakeD3DSwapChain9(this);
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetRasterStatus(UINT, D3DRASTER_STATUS*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE CreateVolumeTexture(UINT, UINT, UINT, UINT, DWORD, D3DFORMAT, D3DPOOL,
                                                  IDirect3DVolumeTexture9**, HANDLE*) override
    {
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE CreateCubeTexture(UINT, UINT, DWORD, D3DFORMAT, D3DPOOL,
                                                IDirect3DCubeTexture9**, HANDLE*) override
    {
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE CreateVertexBuffer(UINT Length, DWORD Usage, DWORD FVF, D3DPOOL Pool,
                                                 IDirect3DVertexBuffer9** ppVB, HANDLE*) override
    {
        if (!ppVB) return E_INVALIDARG;
        *ppVB = new IFakeD3DVertexBuffer9();
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE CreateIndexBuffer(UINT, DWORD, D3DFORMAT, D3DPOOL, IDirect3DIndexBuffer9**,
                                                HANDLE*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetViewport(D3DVIEWPORT9*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetMaterial(D3DMATERIAL9*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetLight(DWORD, D3DLIGHT9*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetLightEnable(DWORD, BOOL*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetClipPlane(DWORD, float*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE CreateStateBlock(D3DSTATEBLOCKTYPE, IDirect3DStateBlock9**) override
    {
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE EndStateBlock(IDirect3DStateBlock9**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetClipStatus(D3DCLIPSTATUS9*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetTexture(DWORD, IDirect3DBaseTexture9**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetTextureStageState(DWORD, D3DTEXTURESTAGESTATETYPE, DWORD*) override
    {
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE GetSamplerState(DWORD, D3DSAMPLERSTATETYPE, DWORD*) override
    {
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE GetPaletteEntries(UINT, PALETTEENTRY*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetCurrentTexturePalette(UINT*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetScissorRect(RECT*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE ProcessVertices(UINT, UINT, UINT, IDirect3DVertexBuffer9*,
                                              IDirect3DVertexDeclaration9*, DWORD) override
    {
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE CreateVertexDeclaration(CONST D3DVERTEXELEMENT9* pVertexElements,
                                                      IDirect3DVertexDeclaration9** ppDecl) override
    {
        if (!ppDecl) return E_INVALIDARG;
        HANDLE h = ShimCreateVertexDecl(pVertexElements);
        *ppDecl = new IFakeD3DVertexDeclaration9(h);
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetVertexDeclaration(IDirect3DVertexDeclaration9**) override
    {
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE GetFVF(DWORD*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE CreateVertexShader(CONST DWORD*, IDirect3DVertexShader9**) override
    {
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE GetVertexShader(IDirect3DVertexShader9**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetVertexShaderConstantF(UINT, float*, UINT) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetVertexShaderConstantI(UINT, int*, UINT) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetVertexShaderConstantB(UINT, BOOL*, UINT) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetStreamSource(UINT, IDirect3DVertexBuffer9**, UINT*, UINT*) override
    {
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE GetStreamSourceFreq(UINT, UINT*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetIndices(IDirect3DIndexBuffer9**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetPixelShader(IDirect3DPixelShader9**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetPixelShaderConstantF(UINT, float*, UINT) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetPixelShaderConstantI(UINT, int*, UINT) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetPixelShaderConstantB(UINT, BOOL*, UINT) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE DrawRectPatch(UINT, CONST float*, CONST D3DRECTPATCH_INFO*) override
    {
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE DrawTriPatch(UINT, CONST float*, CONST D3DTRIPATCH_INFO*) override
    {
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE DeletePatch(UINT) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetConvolutionMonoKernel(UINT, UINT, float*, float*) override
    {
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE ComposeRects(IDirect3DSurface9*, IDirect3DSurface9*,
                                           IDirect3DVertexBuffer9*, UINT, IDirect3DVertexBuffer9*,
                                           D3DCOMPOSERECTSOP, int, int) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetGPUThreadPriority(INT*) override { return E_NOTIMPL; }
};

const float IFakeD3DDevice9Ex::kVerts[9] = { -1, -1, 0, 3, -1, 0, -1, 3, 0 };
HANDLE IFakeD3DDevice9Ex::g_lastRt0 = nullptr;

// ---- swapchain method bodies (need the full device type) ---------------------------------------------

HRESULT STDMETHODCALLTYPE IFakeD3DSwapChain9::Present(CONST RECT*, CONST RECT*, HWND,
                                                      CONST RGNDATA*, DWORD)
{
    return IFakeD3DDevice9Ex::ShimPresentDdi(m_dev);
}

HRESULT STDMETHODCALLTYPE IFakeD3DSwapChain9::GetBackBuffer(UINT iBackBuffer, D3DBACKBUFFER_TYPE Type,
                                                            IDirect3DSurface9** ppBackBuffer)
{
    return m_dev->GetBackBuffer(0, iBackBuffer, Type, ppBackBuffer);
}

HRESULT STDMETHODCALLTYPE IFakeD3DSwapChain9::GetDevice(IDirect3DDevice9** ppDevice)
{
    if (!ppDevice) return E_INVALIDARG;
    *ppDevice = m_dev;
    m_dev->AddRef();
    return S_OK;
}

struct IFakeD3D9Ex : IDirect3D9Ex
{
    ULONG m_ref = 1;

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObj) override
    {
        if (!ppvObj) return E_INVALIDARG;
        if (riid == IID_IDirect3D9Ex || riid == IID_IDirect3D9 || riid == IID_IUnknown) {
            *ppvObj = static_cast<IDirect3D9Ex*>(this);
            AddRef();
            return S_OK;
        }
        *ppvObj = nullptr;
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++m_ref; }
    ULONG STDMETHODCALLTYPE Release() override
    {
        // A singleton: hand the count down but never delete, the exports can hand it out again.
        return m_ref ? --m_ref : 0;
    }

    HRESULT STDMETHODCALLTYPE RegisterSoftwareDevice(void*) override { return E_NOTIMPL; }
    UINT STDMETHODCALLTYPE GetAdapterCount() override { return 1; }
    HRESULT STDMETHODCALLTYPE GetAdapterIdentifier(UINT Adapter, DWORD Flags,
                                                   D3DADAPTER_IDENTIFIER9* pIdentifier) override
    {
        if (!pIdentifier) return E_INVALIDARG;
        memset(pIdentifier, 0, sizeof *pIdentifier);
        strcpy_s(pIdentifier->Driver, "atiumd64.dll");
        strcpy_s(pIdentifier->Description, "AMD Radeon HD 6970");
        pIdentifier->VendorId = 0x1002;
        pIdentifier->DeviceId = 0x6718;
        return S_OK;
    }
    UINT STDMETHODCALLTYPE GetAdapterModeCount(UINT Adapter, D3DFORMAT Format) override { return 1; }
    HRESULT STDMETHODCALLTYPE EnumAdapterModes(UINT Adapter, D3DFORMAT Format, UINT Mode,
                                               D3DDISPLAYMODE* pMode) override
    {
        if (!pMode) return E_INVALIDARG;
        pMode->Width = 1920;
        pMode->Height = 1080;
        pMode->RefreshRate = 60;
        pMode->Format = D3DFMT_X8R8G8B8;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetAdapterDisplayMode(UINT Adapter, D3DDISPLAYMODE* pMode) override
    {
        return EnumAdapterModes(Adapter, D3DFMT_X8R8G8B8, 0, pMode);
    }
    HRESULT STDMETHODCALLTYPE CheckDeviceType(UINT, D3DDEVTYPE, D3DFORMAT, D3DFORMAT, BOOL) override
    {
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE CheckDeviceFormat(UINT, D3DDEVTYPE, D3DFORMAT, DWORD, D3DRESOURCETYPE,
                                                D3DFORMAT) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE CheckDeviceMultiSampleType(UINT, D3DDEVTYPE, D3DFORMAT, BOOL,
                                                         D3DMULTISAMPLE_TYPE, DWORD*) override
    {
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE CheckDepthStencilMatch(UINT, D3DDEVTYPE, D3DFORMAT, D3DFORMAT,
                                                     D3DFORMAT) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE CheckDeviceFormatConversion(UINT, D3DDEVTYPE, D3DFORMAT, D3DFORMAT) override
    {
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetDeviceCaps(UINT Adapter, D3DDEVTYPE DeviceType, D3DCAPS9* pCaps) override
    {
        if (!pCaps) return E_INVALIDARG;
        memset(pCaps, 0, sizeof *pCaps);
        pCaps->PixelShaderVersion = D3DPS_VERSION(3, 0);
        pCaps->VertexShaderVersion = D3DVS_VERSION(3, 0);
        pCaps->MaxSimultaneousTextures = 8;
        return S_OK;
    }
    HMONITOR STDMETHODCALLTYPE GetAdapterMonitor(UINT Adapter) override
    {
        return MonitorFromWindow(nullptr, MONITOR_DEFAULTTOPRIMARY);
    }
    HRESULT STDMETHODCALLTYPE CreateDevice(UINT Adapter, D3DDEVTYPE DeviceType, HWND hFocusWindow,
                                           DWORD BehaviorFlags,
                                           D3DPRESENT_PARAMETERS* pPresentationParameters,
                                           IDirect3DDevice9** ppReturnedDeviceInterface) override
    {
        if (!ppReturnedDeviceInterface) return E_INVALIDARG;
        IDirect3DDevice9Ex* ex = nullptr;
        HRESULT hr = CreateDeviceEx(Adapter, DeviceType, hFocusWindow, BehaviorFlags,
                                    pPresentationParameters, nullptr, &ex);
        if (SUCCEEDED(hr)) *ppReturnedDeviceInterface = ex;
        return hr;
    }
    UINT STDMETHODCALLTYPE GetAdapterModeCountEx(UINT Adapter,
                                                 CONST D3DDISPLAYMODEFILTER* pFilter) override
    {
        return 1;
    }
    HRESULT STDMETHODCALLTYPE EnumAdapterModesEx(UINT Adapter, CONST D3DDISPLAYMODEFILTER* pFilter,
                                                 UINT Mode, D3DDISPLAYMODEEX* pMode) override
    {
        if (!pMode) return E_INVALIDARG;
        pMode->Size = sizeof(D3DDISPLAYMODEEX);
        pMode->Width = 1920;
        pMode->Height = 1080;
        pMode->RefreshRate = 60;
        pMode->Format = D3DFMT_X8R8G8B8;
        pMode->ScanLineOrdering = D3DSCANLINEORDERING_PROGRESSIVE;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetAdapterDisplayModeEx(UINT Adapter, D3DDISPLAYMODEEX* pMode,
                                                      D3DDISPLAYROTATION* pRotation) override
    {
        HRESULT hr = EnumAdapterModesEx(Adapter, nullptr, 0, pMode);
        if (SUCCEEDED(hr) && pRotation) *pRotation = D3DDISPLAYROTATION_IDENTITY;
        return hr;
    }
    HRESULT STDMETHODCALLTYPE CreateDeviceEx(UINT Adapter, D3DDEVTYPE DeviceType, HWND hFocusWindow,
                                             DWORD BehaviorFlags,
                                             D3DPRESENT_PARAMETERS* pPresentationParameters,
                                             D3DDISPLAYMODEEX* pFullscreenDisplayMode,
                                             IDirect3DDevice9Ex** ppReturnedDeviceInterface) override
    {
        if (!ppReturnedDeviceInterface) return E_INVALIDARG;
        *ppReturnedDeviceInterface = nullptr;
        Log("shim: CreateDeviceEx(adapter=%u, type=%d, wnd=%p)", Adapter, (int)DeviceType,
            (void*)hFocusWindow);
        HRESULT hr = ShimCreateDevice(hFocusWindow);
        if (FAILED(hr)) return hr;
        *ppReturnedDeviceInterface = new IFakeD3DDevice9Ex();
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetAdapterLUID(UINT Adapter, LUID* pLUID) override
    {
        if (!pLUID) return E_INVALIDARG;
        *pLUID = LUID{};
        return S_OK;
    }
};

static IFakeD3D9Ex* g_pFakeD3D9 = nullptr;
static IDirect3D9* ShimGetD3D9() { return g_pFakeD3D9; }

// ---------------------------------------------------------------- entry points

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        g_shimSelf = hInst;
        // DisableThreadLibraryCalls(hInst); // removed: CRT per-thread init must run on driver threads
        InitializeCriticalSection(&g_cs);
        g_procHeap = GetProcessHeap();
        // signal to DX9VideoProcessor.cpp IsHarnessMode() check
        SetEnvironmentVariableW(L"MPC_D3D9_SHIM", L"1");
        AddVectoredExceptionHandler(1, CrashFilter);
        g_pFakeD3D9 = new IFakeD3D9Ex();
        // The log sits beside the DLL and is opened shareable, so it can be followed while the host runs.
        wchar_t path[MAX_PATH];
        GetModuleFileNameW(hInst, path, MAX_PATH);
        if (wchar_t* dot = wcsrchr(path, L'.')) wcscpy_s(dot, MAX_PATH - (dot - path), L"-pid0.log");
        g_logHandle = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        Log("d3d9shim loaded in pid %lu", GetCurrentProcessId());
    }
    return TRUE;
}

extern "C" HRESULT WINAPI Direct3DCreate9Ex(UINT sdkVer, IDirect3D9Ex** ppD3D)
{
    if (!ppD3D) return E_INVALIDARG;
    g_pFakeD3D9->AddRef();
    *ppD3D = g_pFakeD3D9;
    return S_OK;
}

extern "C" IDirect3D9* WINAPI Direct3DCreate9(UINT sdkVer)
{
    g_pFakeD3D9->AddRef();
    return g_pFakeD3D9;
}

extern "C" __declspec(dllexport) int WINAPI HarnessShimLoaded() { return 1; }
