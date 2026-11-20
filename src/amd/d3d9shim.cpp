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
#include "legacy9.cpp"  // infrastructure; wmain suppressed

// ---------------------------------------------------------------- driver bring-up

static bool HarnessUnbindFixEnabled() {
    char buf[4] = {};
    GetEnvironmentVariableA("MPC_HARNESS_UNBIND_FIX", buf, sizeof buf);
    return buf[0] == '1';
}

static HMODULE g_shimMod = nullptr;
static HANDLE g_shimDevice = nullptr;
static D3DDDI_ADAPTERFUNCS g_shimAdapterFuncs = {};
static HANDLE g_shimAdapter = nullptr;
static void* g_shimDevFuncs[512] = {};
static FakeContext g_shimContext;
static HWND g_shimFocusWnd = nullptr;

// Arms the breakpoints that trace the clear-write path. Called once after device creation and again on
// ResetEx: the module image survives a device reset, so a re-arm only matters if a BP was left restored.
static void ShimArmBps()
{
    ArmBp(g_shimMod, 0x30310, "stateApply");
    HMODULE a6a = GetModuleHandleA("atiumd6a.dll");
    if (a6a) {
        ArmBp(a6a, 0x12EA32, "clear.A");
        ArmBp(a6a, 0x12E946, "clrzero");
        ArmBp(a6a, 0x12C950, "flush");
        ArmBp(a6a, 0x0F4520, "tss.disp");
        ArmBp(a6a, 0x11A420, "gate");
    }
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
    if (FAILED(dhr)) return dhr;
    g_shimDevice = cd.hDevice;

    // Fake draw-param buffers (legacy9.cpp's --fake-draw-params block): the deferred-flush resolver
    // dereferences [hDevice+0x4958]/[+0x4960] through their +0x40 and +0x1B8 fields, and a draw only
    // reaches the flush when [hDevice+0x47B0] is nonzero.
    uint8_t* buf = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x1000);
    if (!buf) { Log("shim: fake-draw-params HeapAlloc failed"); return E_OUTOFMEMORY; }
    uint8_t* fake_rbp = buf;
    uint8_t* fake_r14 = buf + 0x400;
    uint8_t* state1   = buf + 0x800;
    uint8_t* state2   = buf + 0xC00;
    *(void**)(fake_rbp + 0x1B8) = state1;
    *(void**)(fake_r14 + 0x1B8) = state2;
    *(void**)(fake_rbp + 0x40) = state1;
    *(void**)(fake_r14 + 0x40) = state2;
    *(void**)((uintptr_t)g_shimDevice + 0x4958) = fake_rbp;
    *(void**)((uintptr_t)g_shimDevice + 0x4960) = fake_r14;
    *(DWORD*)((uintptr_t)g_shimDevice + 0x47B0) = 1;
    Log("shim: fake-draw-params: buf=%p  [+0x4958]=buf  [+0x4960]=buf+0x400  [+0x47B0]=1", (void*)buf);

    InitFakeVtbls();
    *(void**)state1 = s_fakeStateVtbl;
    *(void**)state2 = s_fakeStateVtbl;
    *(void**)fake_rbp = s_fakeStateVtbl;
    *(void**)fake_r14 = s_fakeStateVtbl;
    *(ULONG_PTR*)(state1 + 0x1A0) = 1;

    InstallFakeChannel(g_shimDevice);
    g_fakeDrawParams = true;
    return S_OK;
}

static HRESULT ShimCreateDevice(HWND hFocusWnd)
{
    if (g_shimDevice) return S_OK;
    g_shimFocusWnd = hFocusWnd;

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

    // Arm clrzero before CreateDevice: the driver's initialization runs the
    // memset(inner_obj,0,0x1000) path that overflows the 152-byte inner block into
    // adjacent heap metadata.  atiumd6a.dll is a static dep of atiumd64.dll and is
    // already in memory here.  ArmBp is idempotent so ShimArmBps below is safe.
    {
        HMODULE a6a_early = GetModuleHandleA("atiumd6a.dll");
        if (a6a_early) ArmBp(a6a_early, 0x12E946, "clrzero");
    }

    // The exe takes the adapter-record fields from --qai-set/--gpu-va-base; the shim has no command line,
    // so the known-good WDDM2 set (the default in tools/inject.ps1) is supplied directly. Record 2's ring
    // table defaults are already hardcoded in QueryAdapterInfoCb.
    g_gpuVaBase = 0x20000;
    g_qaiSet = { { 0x000, 0x260 }, { 0x30, 0x5a }, { 0x3c, 8 }, { 0x1f4, 0x480 }, { 0xd4, 2 } };
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

struct IFakeD3DTexture9 : IDirect3DTexture9
{
    ULONG m_ref = 1;
    HANDLE m_hRes = nullptr;
    UINT m_w = 0, m_h = 0;
    D3DFORMAT m_fmt = D3DFMT_A8R8G8B8;
    IDirect3DDevice9* m_dev = nullptr;

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
        ULONG r = --m_ref;
        if (!r) {
            D3DDDI_DEVICEFUNCS* df = (D3DDDI_DEVICEFUNCS*)g_shimDevFuncs;
            if (m_hRes && g_shimDevice && df->pfnDestroyResource) {
                // Before freeing the driver resource, capture its inner pointer so the next
                // stateApply wires clear.A's write target to real_inner+0x64 and the hardware
                // watchpoint (also armed here) fires on the actual UAF write.
                // The driver's selector(res) == *(res+0x48).  stateApply fills s_fakeResource[+0x48]
                // with s_fakeInner152 (or a real pool inner if the pool hook supplies one later).
                // Read from s_fakeResource, not from m_hRes: m_hRes[+0x48] is always 0 because the
                // real texture handle never reaches the driver's state-flush inner-object allocator
                // (stateApply intercepts and diverts to s_fakeSb/s_fakeResource before that point).
                void* inner = nullptr;
                __try { inner = *(void**)((char*)s_fakeResource + 0x48); } __except(EXCEPTION_EXECUTE_HANDLER) {}
                Log("shim: tex Release: hRes=%p s_fakeResource[+0x48]=%p (%s)", m_hRes, inner,
                    inner && (uintptr_t)inner > 0x10000 ? "arming WP" : "skipped");
                if (inner && (uintptr_t)inner > 0x10000) {
                    // Don't call ArmWriteWatchpoint here: RtlCaptureContext/SetThreadContext hang
                    // when called from within a draw-path callback.  Store the pointer; the next
                    // stateApply VEH hit will arm the watchpoint via ep->ContextRecord directly.
                    g_wpInnerPtr = inner;
                }
                df->pfnDestroyResource(g_shimDevice, m_hRes);
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
                t->Release();
            }
        } else if (HarnessUnbindFixEnabled()) {
            g_fakeSbSlotsEmpty = true;
            Log("shim: SetTexture(%u, null) fix-unbind -> slots empty", Stage);
        }
        if (m_df->pfnSetTexture && g_shimDevice)
            return m_df->pfnSetTexture(g_shimDevice, Stage, hRes);
        return S_OK;
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
            *(DWORD*)((uintptr_t)g_shimDevice + 0x47B0) = 1; // prod the deferred-flush path
            D3DDDIARG_DRAWPRIMITIVE dp = {};
            dp.PrimitiveType = PrimitiveType;
            dp.VStart = 0;
            dp.PrimitiveCount = PrimitiveCount ? PrimitiveCount : 1;
            static int s_logged = 0;
            if (s_logged < 3) { s_logged++; Log("shim: DrawPrimitiveUP -> pfnDrawPrimitive"); }
            return m_df->pfnDrawPrimitive(g_shimDevice, &dp, nullptr);
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
        // One 64x64 A8R8G8B8 texture in the DEFAULT pool, as WlCreateTexture does it.
        D3DDDI_SURFACEINFO surf = {};
        surf.Width = 64;
        surf.Height = 64;
        surf.Depth = 1;
        D3DDDIARG_CREATERESOURCE cr = {};
        cr.Format = D3DDDIFMT_A8R8G8B8; // == (D3DDDIFORMAT)D3DFMT_A8R8G8B8, value 21
        cr.Pool = D3DDDIPOOL_VIDEOMEMORY;
        cr.MultisampleType = D3DDDIMULTISAMPLE_NONE;
        cr.pSurfList = &surf;
        cr.SurfCount = 1;
        cr.MipLevels = 1;
        cr.Flags.Texture = 1;
        cr.Rotation = D3DDDI_ROTATION_IDENTITY;
        static UINT_PTR s_nextRtHandle = 0x50000;
        cr.hResource = (HANDLE)s_nextRtHandle++; // the runtime's handle; the driver replaces it
        HRESULT hr = m_df->pfnCreateResource(g_shimDevice, &cr);
        Log("shim: CreateTexture(%ux%u fmt=%u) -> CreateResource = %08lx hRes=%p", Width, Height,
            (UINT)Format, hr, cr.hResource);
        if (FAILED(hr)) return hr;
        *ppTexture = new IFakeD3DTexture9(cr.hResource, Width, Height, Format, this);
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
        *ppBackBuffer = new IFakeD3DSurface9(nullptr, 1920, 1080, D3DFMT_X8R8G8B8, this);
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
        *ppSurface = new IFakeD3DSurface9(nullptr, Width, Height, Format, this);
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE CreateDepthStencilSurface(UINT Width, UINT Height, D3DFORMAT Format,
                                                        D3DMULTISAMPLE_TYPE MultiSample,
                                                        DWORD MultisampleQuality, BOOL Discard,
                                                        IDirect3DSurface9** ppSurface,
                                                        HANDLE* pSharedHandle) override
    {
        if (!ppSurface) return E_INVALIDARG;
        *ppSurface = new IFakeD3DSurface9(nullptr, Width, Height, Format, this);
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
    HRESULT STDMETHODCALLTYPE Present(CONST RECT*, CONST RECT*, HWND, CONST RGNDATA*) override
    {
        return S_OK;
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
    HRESULT STDMETHODCALLTYPE SetRenderTarget(DWORD, IDirect3DSurface9*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SetDepthStencilSurface(IDirect3DSurface9*) override { return S_OK; }
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
    HRESULT STDMETHODCALLTYPE SetVertexDeclaration(IDirect3DVertexDeclaration9*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE SetFVF(DWORD) override { return S_OK; }
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
    HRESULT STDMETHODCALLTYPE PresentEx(CONST RECT*, CONST RECT*, HWND, CONST RGNDATA*, DWORD) override
    {
        return S_OK;
    }

    // ---- E_NOTIMPL for the rest -----------------------------------------------------------------------

    HRESULT STDMETHODCALLTYPE CreateAdditionalSwapChain(D3DPRESENT_PARAMETERS*,
                                                        IDirect3DSwapChain9**) override
    {
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE GetSwapChain(UINT, IDirect3DSwapChain9**) override { return E_NOTIMPL; }
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
    HRESULT STDMETHODCALLTYPE CreateVertexBuffer(UINT, DWORD, DWORD, D3DPOOL, IDirect3DVertexBuffer9**,
                                                 HANDLE*) override { return E_NOTIMPL; }
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
    HRESULT STDMETHODCALLTYPE CreateVertexDeclaration(CONST D3DVERTEXELEMENT9*,
                                                      IDirect3DVertexDeclaration9**) override
    {
        return E_NOTIMPL;
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
