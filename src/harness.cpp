// Fake D3D11 runtime around the AMD user-mode driver (amdxx64.dll).
//
// Plays the role d3d11.dll normally plays: loads the UMD, calls OpenAdapter10_2
// with its own adapter callbacks, then CalcPrivateDeviceSize / CreateDevice with
// its own kernel-thunk and core-layer callback tables. Every callback the driver
// makes is logged. Callbacks that need the real kernel driver are forwarded to
// the D3DKMT* thunks in gdi32; anything not yet implemented logs and fails.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winternl.h> // NTSTATUS, which the DDI headers expect from the kernel side
#include <d3d10umddi.h>

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <map>
#include <utility>
#include <vector>

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

// ---------------------------------------------------------------- logging

static FILE* g_logFile = nullptr;
static int g_depth = 0;
static bool g_stacks = false; // --stacks: log the driver call stack for every kernel-thunk callback
static HRESULT g_pendingHr = E_PENDING; // what a callback returns for STATUS_PENDING (--pending-hr to override)

static void Log(const char* fmt, ...)
{
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    for (FILE* f : { stdout, g_logFile }) {
        if (!f) continue;
        fprintf(f, "%*s%s\n", g_depth * 2, "", buf);
        fflush(f);
    }
}

static void HexDump(const char* label, const void* p, size_t n, size_t maxBytes = 64)
{
    if (!p || !n) { Log("%s: <empty>", label); return; }
    const BYTE* b = (const BYTE*)p;
    size_t shown = n < maxBytes ? n : maxBytes;
    char line[4 * 64 + 64];
    for (size_t off = 0; off < shown; off += 16) {
        int len = snprintf(line, sizeof(line), "%s +%04zx:", label, off);
        for (size_t i = off; i < off + 16 && i < shown; ++i)
            len += snprintf(line + len, sizeof(line) - len, " %02x", b[i]);
        Log("%s", line);
    }
    if (shown < n) Log("%s ... (%zu bytes total)", label, n);
}

struct Scope {
    Scope() { ++g_depth; }
    ~Scope() { --g_depth; }
};

static HRESULT FromNt(NTSTATUS s)
{
    // STATUS_PENDING from the paging thunks (MakeResident, MapGpuVirtualAddress)
    // means the driver must wait on the paging fence before using the result.
    if (s == 0x103) return g_pendingHr;
    if (NT_SUCCESS(s)) return S_OK;
    // What the real runtime does for thunk failures is HRESULT_FROM_NT.
    return (HRESULT)(s | 0x10000000);
}

// ---------------------------------------------------------------- runtime state

// Runtime handles handed to the driver start with a tag, because the driver is
// free to pass either the adapter or the device handle to some callbacks.
enum RtKind : UINT32 { RT_ADAPTER = 'tpdA', RT_DEVICE = 'cveD', RT_RESOURCE = 'crsR' };

struct RtAdapter {
    RtKind kind = RT_ADAPTER;
    D3DKMT_HANDLE hKm = 0;
    LUID luid{};
    D3D10DDI_HADAPTER hDrv{};
    D3D10_2DDI_ADAPTERFUNCS funcs{};
};

struct RtDevice {
    RtKind kind = RT_DEVICE;
    RtAdapter* adapter = nullptr;
    D3DKMT_HANDLE hKm = 0;
    void* drvStorage = nullptr;
    D3D10DDI_HDEVICE hDrv{};
    std::map<HANDLE, D3DKMT_HANDLE> resources; // runtime resource handle -> kernel resource handle
};

static RtAdapter g_adapter;
static RtDevice g_device;

static RtDevice* AsDevice(HANDLE h)
{
    return h && *(RtKind*)h == RT_DEVICE ? (RtDevice*)h : nullptr;
}

static RtAdapter* AdapterOf(HANDLE h)
{
    if (!h) return nullptr;
    if (*(RtKind*)h == RT_ADAPTER) return (RtAdapter*)h;
    if (*(RtKind*)h == RT_DEVICE) return ((RtDevice*)h)->adapter;
    return nullptr;
}

// ---------------------------------------------------------------- crash reporting

static LONG WINAPI CrashFilter(EXCEPTION_POINTERS* ep)
{
    const EXCEPTION_RECORD* er = ep->ExceptionRecord;
    // Ignore C++ exceptions and debug prints the driver may raise and handle itself.
    if (er->ExceptionCode == 0xE06D7363 || er->ExceptionCode == 0x406D1388 ||
        er->ExceptionCode == DBG_PRINTEXCEPTION_C || er->ExceptionCode == 0x4001000A)
        return EXCEPTION_CONTINUE_SEARCH;
    HMODULE mod = nullptr;
    wchar_t name[MAX_PATH] = L"?";
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCWSTR)er->ExceptionAddress, &mod) && mod)
        GetModuleFileNameW(mod, name, MAX_PATH);
    const wchar_t* base = wcsrchr(name, L'\\');
    Log("!! exception %08lx at %p (%ls+0x%llx)", er->ExceptionCode, er->ExceptionAddress,
        base ? base + 1 : name, (unsigned long long)((BYTE*)er->ExceptionAddress - (BYTE*)mod));
    if (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && er->NumberParameters >= 2)
        Log("!!   %s address %p", er->ExceptionInformation[0] ? "writing" : "reading",
            (void*)er->ExceptionInformation[1]);
    return EXCEPTION_CONTINUE_SEARCH;
}

// ---------------------------------------------------------------- import hooks
//
// The driver also talks to the OS directly. Patching its import table lets the
// log show which modules and exports it goes looking for behind our back.

static void LogCaller(const char* what)
{
    void* frames[12];
    USHORT n = RtlCaptureStackBackTrace(2, 12, frames, nullptr);
    char line[512];
    int len = snprintf(line, sizeof(line), "   %s stack:", what);
    for (USHORT i = 0; i < n && len < (int)sizeof(line) - 40; ++i) {
        HMODULE mod = nullptr;
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCWSTR)frames[i], &mod);
        wchar_t name[MAX_PATH] = L"?";
        if (mod) GetModuleFileNameW(mod, name, MAX_PATH);
        const wchar_t* base = wcsrchr(name, L'\\');
        len += snprintf(line + len, sizeof(line) - len, " %ls+%llx", base ? base + 1 : name,
                        (unsigned long long)((BYTE*)frames[i] - (BYTE*)mod));
    }
    Log("%s", line);
}

// The driver resolves some D3DKMT thunks itself instead of using the callback
// table. Each one it asks for is handed a wrapper that logs the call and then
// forwards to the real thunk. Every D3DKMT thunk takes a single pointer.
struct ThunkSlot { char name[64]; NTSTATUS (APIENTRY* real)(void*); };
static ThunkSlot g_thunks[64];
static int g_thunkCount = 0;

template <int N>
static NTSTATUS APIENTRY ThunkWrapper(void* arg)
{
    NTSTATUS st = g_thunks[N].real(arg);
    Log("km %s(%p) = %08lx  [direct]", g_thunks[N].name, arg, st);
    if (!NT_SUCCESS(st)) { Scope s; LogCaller("failed thunk"); }
    return st;
}

template <size_t... I>
static void* ThunkWrapperAt(int n, std::index_sequence<I...>)
{
    static void* const table[] = { (void*)&ThunkWrapper<(int)I>... };
    return table[n];
}

static FARPROC WrapThunk(const char* name, FARPROC real)
{
    for (int i = 0; i < g_thunkCount; ++i)
        if (!strcmp(g_thunks[i].name, name))
            return (FARPROC)ThunkWrapperAt(i, std::make_index_sequence<_countof(g_thunks)>());
    if (g_thunkCount == _countof(g_thunks)) return real;
    int i = g_thunkCount++;
    strcpy_s(g_thunks[i].name, name);
    g_thunks[i].real = (NTSTATUS (APIENTRY*)(void*))real;
    return (FARPROC)ThunkWrapperAt(i, std::make_index_sequence<_countof(g_thunks)>());
}

static FARPROC WINAPI Hook_GetProcAddress(HMODULE mod, LPCSTR name)
{
    FARPROC r = GetProcAddress(mod, name);
    if (r && (UINT_PTR)name > 0xffff && !strncmp(name, "D3DKMT", 6)) r = WrapThunk(name, r);
    wchar_t modName[MAX_PATH] = L"?";
    GetModuleFileNameW(mod, modName, MAX_PATH);
    const wchar_t* base = wcsrchr(modName, L'\\');
    if ((UINT_PTR)name > 0xffff) Log("os GetProcAddress(%ls, %s) = %p", base ? base + 1 : modName, name, r);
    else Log("os GetProcAddress(%ls, #%u) = %p", base ? base + 1 : modName, (UINT)(UINT_PTR)name, r);
    return r;
}

static HMODULE WINAPI Hook_LoadLibraryA(LPCSTR name)
{
    HMODULE r = LoadLibraryA(name);
    Log("os LoadLibraryA(%s) = %p", name, r);
    return r;
}

static HMODULE WINAPI Hook_LoadLibraryExA(LPCSTR name, HANDLE file, DWORD flags)
{
    HMODULE r = LoadLibraryExA(name, file, flags);
    Log("os LoadLibraryExA(%s, %08lx) = %p", name, flags, r);
    return r;
}

static HMODULE WINAPI Hook_LoadLibraryExW(LPCWSTR name, HANDLE file, DWORD flags)
{
    HMODULE r = LoadLibraryExW(name, file, flags);
    Log("os LoadLibraryExW(%ls, %08lx) = %p", name, flags, r);
    return r;
}

static HMODULE WINAPI Hook_GetModuleHandleA(LPCSTR name)
{
    HMODULE r = GetModuleHandleA(name);
    Log("os GetModuleHandleA(%s) = %p", name ? name : "<exe>", r);
    return r;
}

static HMODULE WINAPI Hook_GetModuleHandleW(LPCWSTR name)
{
    HMODULE r = GetModuleHandleW(name);
    Log("os GetModuleHandleW(%ls) = %p", name ? name : L"<exe>", r);
    return r;
}

static void WINAPI Hook_OutputDebugStringA(LPCSTR s)
{
    Log("os OutputDebugStringA: %s", s ? s : "");
    OutputDebugStringA(s);
}

static HANDLE WINAPI Hook_CreateThread(LPSECURITY_ATTRIBUTES sa, SIZE_T stack, LPTHREAD_START_ROUTINE fn, LPVOID arg,
                                       DWORD flags, LPDWORD tid)
{
    DWORD id = 0;
    HANDLE r = CreateThread(sa, stack, fn, arg, flags, &id);
    if (tid) *tid = id;
    Log("os CreateThread(start=%p) = %p tid=%lu", fn, r, id);
    return r;
}

struct ImportHook { const char* dll; const char* name; void* hook; };

static const ImportHook g_importHooks[] = {
    { "KERNEL32.dll", "GetProcAddress", Hook_GetProcAddress },
    { "KERNEL32.dll", "LoadLibraryA", Hook_LoadLibraryA },
    { "KERNEL32.dll", "LoadLibraryExA", Hook_LoadLibraryExA },
    { "KERNEL32.dll", "LoadLibraryExW", Hook_LoadLibraryExW },
    { "KERNEL32.dll", "GetModuleHandleA", Hook_GetModuleHandleA },
    { "KERNEL32.dll", "GetModuleHandleW", Hook_GetModuleHandleW },
    { "KERNEL32.dll", "OutputDebugStringA", Hook_OutputDebugStringA },
    { "KERNEL32.dll", "CreateThread", Hook_CreateThread },
};

static void HookImports(HMODULE mod)
{
    BYTE* base = (BYTE*)mod;
    auto* nt = (IMAGE_NT_HEADERS*)(base + ((IMAGE_DOS_HEADER*)base)->e_lfanew);
    const IMAGE_DATA_DIRECTORY& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress) return;
    int patched = 0;
    for (auto* desc = (IMAGE_IMPORT_DESCRIPTOR*)(base + dir.VirtualAddress); desc->Name; ++desc) {
        const char* dll = (const char*)(base + desc->Name);
        auto* names = (IMAGE_THUNK_DATA*)(base + (desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk));
        auto* slots = (IMAGE_THUNK_DATA*)(base + desc->FirstThunk);
        for (; names->u1.AddressOfData; ++names, ++slots) {
            if (IMAGE_SNAP_BY_ORDINAL(names->u1.Ordinal)) continue;
            const char* fn = ((IMAGE_IMPORT_BY_NAME*)(base + names->u1.AddressOfData))->Name;
            for (const ImportHook& h : g_importHooks) {
                if (_stricmp(dll, h.dll) || strcmp(fn, h.name)) continue;
                DWORD old;
                VirtualProtect(&slots->u1.Function, sizeof(void*), PAGE_READWRITE, &old);
                slots->u1.Function = (ULONG_PTR)h.hook;
                VirtualProtect(&slots->u1.Function, sizeof(void*), old, &old);
                ++patched;
            }
        }
    }
    Log("hooked %d imports", patched);
}

// ---------------------------------------------------------------- adapter callbacks

static HRESULT APIENTRY CALLBACK QueryAdapterInfoCb(HANDLE hAdapter, CONST D3DDDICB_QUERYADAPTERINFO* p)
{
    RtAdapter* a = (RtAdapter*)hAdapter;
    Log("cb QueryAdapterInfoCb size=%u", p->PrivateDriverDataSize);
    Scope s;
    D3DKMT_QUERYADAPTERINFO q{};
    q.hAdapter = a->hKm;
    q.Type = KMTQAITYPE_UMDRIVERPRIVATE;
    q.pPrivateDriverData = p->pPrivateDriverData;
    q.PrivateDriverDataSize = p->PrivateDriverDataSize;
    NTSTATUS st = D3DKMTQueryAdapterInfo(&q);
    Log("-> D3DKMTQueryAdapterInfo(UMDRIVERPRIVATE) = %08lx", st);
    if (NT_SUCCESS(st)) HexDump("   data", p->pPrivateDriverData, p->PrivateDriverDataSize);
    return FromNt(st);
}

static HRESULT APIENTRY CALLBACK QueryAdapterInfoCb2(HANDLE hAdapter, CONST D3DDDICB_QUERYADAPTERINFO2* p)
{
    RtAdapter* a = (RtAdapter*)hAdapter;
    Log("cb QueryAdapterInfoCb2 type=%d size=%u", (int)p->QueryType, p->PrivateDriverDataSize);
    Scope s;
    D3DKMT_QUERYADAPTERINFO q{};
    q.hAdapter = a->hKm;
    switch (p->QueryType) {
    case D3DDDI_QUERYADAPTERTYPE_DRIVERPRIVATE: q.Type = KMTQAITYPE_UMDRIVERPRIVATE; break;
    case D3DDDI_QUERYADAPTERTYPE_QUERYREGISTRY: q.Type = KMTQAITYPE_QUERYREGISTRY; break;
    default:
        Log("-> unsupported query type, E_NOTIMPL");
        return E_NOTIMPL;
    }
    q.pPrivateDriverData = p->pPrivateDriverData;
    q.PrivateDriverDataSize = p->PrivateDriverDataSize;
    NTSTATUS st = D3DKMTQueryAdapterInfo(&q);
    Log("-> D3DKMTQueryAdapterInfo(%d) = %08lx", (int)q.Type, st);
    return FromNt(st);
}

static HRESULT APIENTRY CALLBACK GetMultisampleMethodListCb(HANDLE hAdapter, D3DDDICB_GETMULTISAMPLEMETHODLIST* p)
{
    RtAdapter* a = (RtAdapter*)hAdapter;
    Log("cb GetMultisampleMethodListCb src=%u %ux%u fmt=%d count=%u", p->VidPnSourceId, p->Width, p->Height,
        (int)p->Format, p->MethodCount);
    Scope s;
    D3DKMT_GETMULTISAMPLEMETHODLIST q{};
    q.hAdapter = a->hKm;
    q.VidPnSourceId = p->VidPnSourceId;
    q.Width = p->Width;
    q.Height = p->Height;
    q.Format = p->Format;
    q.pMethodList = (D3DKMT_MULTISAMPLEMETHOD*)p->pMethodList;
    q.MethodCount = p->MethodCount;
    NTSTATUS st = D3DKMTGetMultisampleMethodList(&q);
    p->MethodCount = q.MethodCount;
    Log("-> %08lx count=%u", st, q.MethodCount);
    return FromNt(st);
}

// ---------------------------------------------------------------- generic stub tables
//
// Every slot in a callback table gets its own stub so an unimplemented call is
// reported by name instead of crashing on a null pointer. On x64 all of these
// callbacks share one calling convention, so one stub shape fits them all.

#define KT_CALLBACKS(X) \
    X(pfnAllocateCb) X(pfnDeallocateCb) X(pfnSetPriorityCb) X(pfnQueryResidencyCb) X(pfnSetDisplayModeCb) \
    X(pfnPresentCb) X(pfnRenderCb) X(pfnLockCb) X(pfnUnlockCb) X(pfnEscapeCb) X(pfnCreateOverlayCb) \
    X(pfnUpdateOverlayCb) X(pfnFlipOverlayCb) X(pfnDestroyOverlayCb) X(pfnCreateContextCb) X(pfnDestroyContextCb) \
    X(pfnCreateSynchronizationObjectCb) X(pfnDestroySynchronizationObjectCb) X(pfnWaitForSynchronizationObjectCb) \
    X(pfnSignalSynchronizationObjectCb) X(pfnSetAsyncCallbacksCb) X(pfnSetDisplayPrivateDriverFormatCb) \
    X(pfnOfferAllocationsCb) X(pfnReclaimAllocationsCb) X(pfnCreateSynchronizationObject2Cb) \
    X(pfnWaitForSynchronizationObject2Cb) X(pfnSignalSynchronizationObject2Cb) X(pfnPresentMultiPlaneOverlayCb) \
    X(pfnLogUMDMarkerCb) X(pfnMakeResidentCb) X(pfnEvictCb) X(pfnWaitForSynchronizationObjectFromCpuCb) \
    X(pfnSignalSynchronizationObjectFromCpuCb) X(pfnWaitForSynchronizationObjectFromGpuCb) \
    X(pfnSignalSynchronizationObjectFromGpuCb) X(pfnCreatePagingQueueCb) X(pfnDestroyPagingQueueCb) X(pfnLock2Cb) \
    X(pfnUnlock2Cb) X(pfnInvalidateCacheCb) X(pfnReserveGpuVirtualAddressCb) X(pfnMapGpuVirtualAddressCb) \
    X(pfnFreeGpuVirtualAddressCb) X(pfnUpdateGpuVirtualAddressCb) X(pfnCreateContextVirtualCb) X(pfnSubmitCommandCb) \
    X(pfnDeallocate2Cb) X(pfnSignalSynchronizationObjectFromGpu2Cb) X(pfnReclaimAllocations2Cb) \
    X(pfnGetResourcePresentPrivateDriverDataCb) X(pfnUpdateAllocationPropertyCb) X(pfnOfferAllocations2Cb) \
    X(pfnReclaimAllocations3Cb) X(pfnAcquireResourceCb) X(pfnReleaseResourceCb) X(pfnCreateHwContextCb) \
    X(pfnDestroyHwContextCb) X(pfnCreateHwQueueCb) X(pfnDestroyHwQueueCb) X(pfnSubmitCommandToHwQueueCb) \
    X(pfnSubmitWaitForSyncObjectsToHwQueueCb) X(pfnSubmitSignalSyncObjectsToHwQueueCb) \
    X(pfnSubmitPresentBltToHwQueueCb) X(pfnSubmitPresentToHwQueueCb) X(pfnSubmitHistorySequenceCb)

#define UM_CALLBACKS(X) \
    X(pfnSetErrorCb) X(pfnStateVsConstBufCb) X(pfnStatePsSrvCb) X(pfnStatePsShaderCb) X(pfnStatePsSamplerCb) \
    X(pfnStateVsShaderCb) X(pfnStatePsConstBufCb) X(pfnStateIaInputLayoutCb) X(pfnStateIaVertexBufCb) \
    X(pfnStateIaIndexBufCb) X(pfnStateGsConstBufCb) X(pfnStateGsShaderCb) X(pfnStateIaPrimitiveTopologyCb) \
    X(pfnStateVsSrvCb) X(pfnStateVsSamplerCb) X(pfnStateGsSrvCb) X(pfnStateGsSamplerCb) X(pfnStateOmRenderTargetsCb) \
    X(pfnStateOmBlendStateCb) X(pfnStateOmDepthStateCb) X(pfnStateRsRastStateCb) X(pfnStateSoTargetsCb) \
    X(pfnStateRsViewportsCb) X(pfnStateRsScissorCb) X(pfnDisableDeferredStagingResourceDestruction) \
    X(pfnStateTextFilterSizeCb) X(pfnStateHsSrvCb) X(pfnStateHsShaderCb) X(pfnStateHsSamplerCb) \
    X(pfnStateHsConstBufCb) X(pfnStateDsSrvCb) X(pfnStateDsShaderCb) X(pfnStateDsSamplerCb) X(pfnStateDsConstBufCb) \
    X(pfnPerformAmortizedProcessingCb) X(pfnStateCsSrvCb) X(pfnStateCsUavCb) X(pfnStateCsShaderCb) \
    X(pfnStateCsSamplerCb) X(pfnStateCsConstBufCb) X(pfnCreateContextCb) X(pfnCreateContextVirtualCb) \
    X(pfnShaderCacheGetValueCb) X(pfnShaderCacheStoreValueCb) X(pfnShaderCacheAddRefCb) X(pfnShaderCacheReleaseCb) \
    X(pfnQueryScanoutCapsCb)

#define DXGI_CALLBACKS(X) \
    X(pfnPresentCb) X(pfnPresentMultiplaneOverlayCb) X(pfnPresentMultiplaneOverlay1Cb) \
    X(pfnSubmitPresentBltToHwQueueCb) X(pfnSubmitPresentToHwQueueCb)

#define NAME_ENTRY(n) #n,
static const char* const g_ktNames[] = { KT_CALLBACKS(NAME_ENTRY) };
static const char* const g_umNames[] = { UM_CALLBACKS(NAME_ENTRY) };
static const char* const g_dxgiNames[] = { DXGI_CALLBACKS(NAME_ENTRY) };

static_assert(sizeof(g_ktNames) == sizeof(D3DDDI_DEVICECALLBACKS), "KT callback list out of sync with header");
static_assert(sizeof(g_umNames) == sizeof(D3DWDDM2_6DDI_CORELAYER_DEVICECALLBACKS), "UM callback list out of sync");
static_assert(sizeof(g_dxgiNames) == sizeof(DXGI_DDI_BASE_CALLBACKS), "DXGI callback list out of sync");

enum TableKind { TK_KT, TK_UM, TK_DXGI };

template <int Kind, int N>
static HRESULT APIENTRY Stub(void* h, UINT_PTR a, UINT_PTR b, UINT_PTR c)
{
    const char* name = Kind == TK_KT ? g_ktNames[N] : Kind == TK_UM ? g_umNames[N] : g_dxgiNames[N];
    const char* table = Kind == TK_KT ? "KT" : Kind == TK_UM ? "UM" : "DXGI";
    Log("cb %s.%s(h=%p, %p, %p, %p)  [stub]", table, name, h, (void*)a, (void*)b, (void*)c);
    return E_NOTIMPL;
}

template <int Kind, size_t... I>
static void FillStubs(void** table, std::index_sequence<I...>)
{
    void* stubs[] = { (void*)&Stub<Kind, (int)I>... };
    memcpy(table, stubs, sizeof(stubs));
}

// ---------------------------------------------------------------- kernel-thunk callbacks

static HRESULT APIENTRY CALLBACK EscapeCb(HANDLE hDevice, CONST D3DDDICB_ESCAPE* p)
{
    RtAdapter* a = AdapterOf(hDevice);
    RtDevice* d = AsDevice(p->hDevice);
    if (!a) { Log("cb KT.pfnEscapeCb(h=%p): unrecognised handle", hDevice); return E_INVALIDARG; }
    Log("cb KT.pfnEscapeCb(h=%p) hDevice=%p hContext=%p flags=%08x data=%p size=%u", hDevice, p->hDevice, p->hContext,
        p->Flags.Value, p->pPrivateDriverData, p->PrivateDriverDataSize);
    Scope s;
    LogCaller("escape");
    HexDump("   in ", p->pPrivateDriverData, p->PrivateDriverDataSize);
    D3DKMT_ESCAPE e{};
    e.hAdapter = a->hKm;
    e.hDevice = d ? d->hKm : 0;
    e.Type = D3DKMT_ESCAPE_DRIVERPRIVATE;
    e.Flags = p->Flags;
    e.pPrivateDriverData = p->pPrivateDriverData;
    e.PrivateDriverDataSize = p->PrivateDriverDataSize;
    e.hContext = (D3DKMT_HANDLE)(UINT_PTR)p->hContext;
    NTSTATUS st = D3DKMTEscape(&e);
    Log("-> D3DKMTEscape = %08lx", st);
    if (NT_SUCCESS(st)) HexDump("   out", p->pPrivateDriverData, p->PrivateDriverDataSize);
    return FromNt(st);
}

// Resolves the device for a KT callback, or fails the call if the handle is not ours.
#define KT_DEVICE(name)                                                                 \
    RtDevice* d = AsDevice(hDevice);                                                    \
    if (!d) { Log("cb KT." name "(h=%p): not a device handle", hDevice); return E_INVALIDARG; } \
    if (g_stacks) LogCaller(name);

static HANDLE KmToHandle(D3DKMT_HANDLE h) { return (HANDLE)(UINT_PTR)h; }
static D3DKMT_HANDLE HandleToKm(HANDLE h) { return (D3DKMT_HANDLE)(UINT_PTR)h; }

static HRESULT APIENTRY CALLBACK CreatePagingQueueCb(HANDLE hDevice, D3DDDICB_CREATEPAGINGQUEUE* p)
{
    KT_DEVICE("pfnCreatePagingQueueCb");
    Log("cb KT.pfnCreatePagingQueueCb priority=%d physAdapter=%u", (int)p->Priority, p->PhysicalAdapterIndex);
    Scope s;
    D3DKMT_CREATEPAGINGQUEUE q{};
    q.hDevice = d->hKm;
    q.Priority = p->Priority;
    q.PhysicalAdapterIndex = p->PhysicalAdapterIndex;
    NTSTATUS st = D3DKMTCreatePagingQueue(&q);
    p->hPagingQueue = q.hPagingQueue;
    p->hSyncObject = q.hSyncObject;
    p->FenceValueCPUVirtualAddress = q.FenceValueCPUVirtualAddress;
    Log("-> %08lx hPagingQueue=%08x hSyncObject=%08x fenceVA=%p", st, q.hPagingQueue, q.hSyncObject,
        q.FenceValueCPUVirtualAddress);
    return FromNt(st);
}

static HRESULT APIENTRY CALLBACK DestroyPagingQueueCb(HANDLE hDevice, const D3DDDI_DESTROYPAGINGQUEUE* p)
{
    KT_DEVICE("pfnDestroyPagingQueueCb");
    D3DDDI_DESTROYPAGINGQUEUE q = *p;
    NTSTATUS st = D3DKMTDestroyPagingQueue(&q);
    Log("cb KT.pfnDestroyPagingQueueCb hPagingQueue=%08x -> %08lx", p->hPagingQueue, st);
    return FromNt(st);
}

static HRESULT CreateContextVirtualCommon(RtDevice* d, const char* who, UINT node, UINT engine,
                                          D3DDDI_CREATECONTEXTFLAGS flags, void* priv, UINT privSize, HANDLE* out)
{
    Log("cb %s node=%u engine=%u flags=%08x privSize=%u", who, node, engine, flags.Value, privSize);
    Scope s;
    HexDump("   priv", priv, privSize);
    D3DKMT_CREATECONTEXTVIRTUAL c{};
    c.hDevice = d->hKm;
    c.NodeOrdinal = node;
    c.EngineAffinity = engine;
    c.Flags = flags;
    c.pPrivateDriverData = priv;
    c.PrivateDriverDataSize = privSize;
    c.ClientHint = D3DKMT_CLIENTHINT_DX10;
    NTSTATUS st = D3DKMTCreateContextVirtual(&c);
    *out = KmToHandle(c.hContext);
    Log("-> D3DKMTCreateContextVirtual = %08lx hContext=%08x", st, c.hContext);
    return FromNt(st);
}

static HRESULT APIENTRY CALLBACK CreateContextVirtualCb(HANDLE hDevice, D3DDDICB_CREATECONTEXTVIRTUAL* p)
{
    KT_DEVICE("pfnCreateContextVirtualCb");
    return CreateContextVirtualCommon(d, "KT.pfnCreateContextVirtualCb", p->NodeOrdinal, p->EngineAffinity, p->Flags,
                                      p->pPrivateDriverData, p->PrivateDriverDataSize, &p->hContext);
}

static HRESULT APIENTRY CALLBACK UmCreateContextVirtualCb(D3D10DDI_HRTCORELAYER h, D3DWDDM2_0DDICB_CREATECONTEXTVIRTUAL* p)
{
    RtDevice* d = AsDevice(h.handle);
    if (!d) return E_INVALIDARG;
    Log("   (ContextTypeFlags=%08x)", p->ContextTypeFlags);
    return CreateContextVirtualCommon(d, "UM.pfnCreateContextVirtualCb", p->NodeOrdinal, p->EngineAffinity, p->Flags,
                                      p->pPrivateDriverData, p->PrivateDriverDataSize, &p->hContext);
}

template <class CB>
static HRESULT CreateContextCommon(RtDevice* d, const char* who, CB* p)
{
    Log("cb %s node=%u engine=%u flags=%08x privSize=%u", who, p->NodeOrdinal, p->EngineAffinity, p->Flags.Value,
        p->PrivateDriverDataSize);
    Scope s;
    HexDump("   priv", p->pPrivateDriverData, p->PrivateDriverDataSize);
    D3DKMT_CREATECONTEXT c{};
    c.hDevice = d->hKm;
    c.NodeOrdinal = p->NodeOrdinal;
    c.EngineAffinity = p->EngineAffinity;
    c.Flags = p->Flags;
    c.pPrivateDriverData = p->pPrivateDriverData;
    c.PrivateDriverDataSize = p->PrivateDriverDataSize;
    c.ClientHint = D3DKMT_CLIENTHINT_DX10;
    NTSTATUS st = D3DKMTCreateContext(&c);
    p->hContext = KmToHandle(c.hContext);
    p->pCommandBuffer = c.pCommandBuffer;
    p->CommandBufferSize = c.CommandBufferSize;
    p->pAllocationList = c.pAllocationList;
    p->AllocationListSize = c.AllocationListSize;
    p->pPatchLocationList = c.pPatchLocationList;
    p->PatchLocationListSize = c.PatchLocationListSize;
    p->CommandBuffer = c.CommandBuffer;
    Log("-> D3DKMTCreateContext = %08lx hContext=%08x cmdbuf=%p/%u alloclist=%p/%u patchlist=%p/%u", st, c.hContext,
        c.pCommandBuffer, c.CommandBufferSize, c.pAllocationList, c.AllocationListSize, c.pPatchLocationList,
        c.PatchLocationListSize);
    return FromNt(st);
}

static HRESULT APIENTRY CALLBACK CreateContextCb(HANDLE hDevice, D3DDDICB_CREATECONTEXT* p)
{
    KT_DEVICE("pfnCreateContextCb");
    return CreateContextCommon(d, "KT.pfnCreateContextCb", p);
}

static HRESULT APIENTRY CALLBACK UmCreateContextCb(D3D10DDI_HRTCORELAYER h, D3DWDDM2_0DDICB_CREATECONTEXT* p)
{
    RtDevice* d = AsDevice(h.handle);
    if (!d) return E_INVALIDARG;
    Log("   (ContextTypeFlags=%08x)", p->ContextTypeFlags);
    return CreateContextCommon(d, "UM.pfnCreateContextCb", p);
}

static HRESULT APIENTRY CALLBACK DestroyContextCb(HANDLE hDevice, CONST D3DDDICB_DESTROYCONTEXT* p)
{
    KT_DEVICE("pfnDestroyContextCb");
    D3DKMT_DESTROYCONTEXT c{ HandleToKm(p->hContext) };
    NTSTATUS st = D3DKMTDestroyContext(&c);
    Log("cb KT.pfnDestroyContextCb hContext=%08x -> %08lx", c.hContext, st);
    return FromNt(st);
}

static HRESULT APIENTRY CALLBACK AllocateCb(HANDLE hDevice, D3DDDICB_ALLOCATE* p)
{
    KT_DEVICE("pfnAllocateCb");
    Log("cb KT.pfnAllocateCb hResource=%p n=%u privSize=%u", p->hResource, p->NumAllocations, p->PrivateDriverDataSize);
    Scope s;
    D3DKMT_CREATEALLOCATION c{};
    c.hDevice = d->hKm;
    c.pPrivateDriverData = p->pPrivateDriverData;
    c.PrivateDriverDataSize = p->PrivateDriverDataSize;
    c.NumAllocations = p->NumAllocations;
    c.pAllocationInfo2 = p->pAllocationInfo2;
    if (p->hResource) {
        c.Flags.CreateResource = 1;
        c.hPrivateRuntimeResourceHandle = p->hResource;
    }
    NTSTATUS st = D3DKMTCreateAllocation2(&c);
    p->hKMResource = c.hResource;
    if (NT_SUCCESS(st) && p->hResource) d->resources[p->hResource] = c.hResource;
    Log("-> D3DKMTCreateAllocation2 = %08lx hKMResource=%08x", st, c.hResource);
    for (UINT i = 0; i < p->NumAllocations; ++i) {
        const D3DDDI_ALLOCATIONINFO2& ai = p->pAllocationInfo2[i];
        Log("   [%u] hAllocation=%08x sysmem=%p privSize=%u flags=%08x gpuVA=%llx", i, ai.hAllocation, ai.pSystemMem,
            ai.PrivateDriverDataSize, ai.Flags.Value, (unsigned long long)ai.GpuVirtualAddress);
    }
    return FromNt(st);
}

static HRESULT DeallocateCommon(RtDevice* d, const char* who, HANDLE hResource, UINT n, const D3DKMT_HANDLE* list,
                                D3DDDICB_DESTROYALLOCATION2FLAGS flags)
{
    D3DKMT_DESTROYALLOCATION2 c{};
    c.hDevice = d->hKm;
    if (hResource) {
        auto it = d->resources.find(hResource);
        if (it == d->resources.end()) { Log("cb %s: unknown hResource %p", who, hResource); return E_INVALIDARG; }
        c.hResource = it->second;
        d->resources.erase(it);
    } else {
        c.phAllocationList = list;
        c.AllocationCount = n;
    }
    c.Flags = flags;
    NTSTATUS st = D3DKMTDestroyAllocation2(&c);
    Log("cb %s hResource=%p(km %08x) n=%u first=%08x flags=%08x -> %08lx", who, hResource, c.hResource, n,
        (!hResource && n) ? list[0] : 0, flags.Value, st);
    return FromNt(st);
}

static HRESULT APIENTRY CALLBACK DeallocateCb(HANDLE hDevice, CONST D3DDDICB_DEALLOCATE* p)
{
    KT_DEVICE("pfnDeallocateCb");
    return DeallocateCommon(d, "KT.pfnDeallocateCb", p->hResource, p->NumAllocations, p->HandleList, {});
}

static HRESULT APIENTRY CALLBACK Deallocate2Cb(HANDLE hDevice, CONST D3DDDICB_DEALLOCATE2* p)
{
    KT_DEVICE("pfnDeallocate2Cb");
    return DeallocateCommon(d, "KT.pfnDeallocate2Cb", p->hResource, p->NumAllocations, p->HandleList, p->Flags);
}

static HRESULT APIENTRY CALLBACK Lock2Cb(HANDLE hDevice, D3DDDICB_LOCK2* p)
{
    KT_DEVICE("pfnLock2Cb");
    D3DKMT_LOCK2 l{};
    l.hDevice = d->hKm;
    l.hAllocation = p->hAllocation;
    l.Flags = p->Flags;
    NTSTATUS st = D3DKMTLock2(&l);
    p->pData = l.pData;
    Log("cb KT.pfnLock2Cb hAllocation=%08x flags=%08x -> %08lx pData=%p", p->hAllocation, p->Flags.Value, st, l.pData);
    return FromNt(st);
}

static HRESULT APIENTRY CALLBACK Unlock2Cb(HANDLE hDevice, CONST D3DDDICB_UNLOCK2* p)
{
    KT_DEVICE("pfnUnlock2Cb");
    D3DKMT_UNLOCK2 u{ d->hKm, p->hAllocation };
    NTSTATUS st = D3DKMTUnlock2(&u);
    Log("cb KT.pfnUnlock2Cb hAllocation=%08x -> %08lx", p->hAllocation, st);
    return FromNt(st);
}

static HRESULT APIENTRY CALLBACK MakeResidentCb(HANDLE hDevice, D3DDDI_MAKERESIDENT* p)
{
    KT_DEVICE("pfnMakeResidentCb");
    UINT n = p->NumAllocations;
    NTSTATUS st = D3DKMTMakeResident(p);
    Log("cb KT.pfnMakeResidentCb queue=%08x n=%u first=%08x flags=%08x -> %08lx fence=%llu trim=%llu",
        p->hPagingQueue, n, n ? p->AllocationList[0] : 0, p->Flags.Value, st,
        (unsigned long long)p->PagingFenceValue, (unsigned long long)p->NumBytesToTrim);
    // STATUS_PENDING is a success code here: the driver must wait on the paging fence.
    return FromNt(st);
}

static HRESULT APIENTRY CALLBACK EvictCb(HANDLE hDevice, D3DDDICB_EVICT* p)
{
    KT_DEVICE("pfnEvictCb");
    D3DKMT_EVICT e{};
    e.hDevice = d->hKm;
    e.NumAllocations = p->NumAllocations;
    e.AllocationList = p->AllocationList;
    e.Flags = p->Flags;
    NTSTATUS st = D3DKMTEvict(&e);
    p->NumBytesToTrim = e.NumBytesToTrim;
    Log("cb KT.pfnEvictCb n=%u -> %08lx trim=%llu", p->NumAllocations, st, (unsigned long long)e.NumBytesToTrim);
    return FromNt(st);
}

static HRESULT APIENTRY CALLBACK ReserveGpuVirtualAddressCb(HANDLE hDevice, D3DDDI_RESERVEGPUVIRTUALADDRESS* p)
{
    KT_DEVICE("pfnReserveGpuVirtualAddressCb");
    NTSTATUS st = D3DKMTReserveGpuVirtualAddress(p);
    Log("cb KT.pfnReserveGpuVirtualAddressCb queue=%08x base=%llx size=%llx -> %08lx va=%llx", p->hPagingQueue,
        (unsigned long long)p->BaseAddress, (unsigned long long)p->Size, st, (unsigned long long)p->VirtualAddress);
    return FromNt(st);
}

static HRESULT APIENTRY CALLBACK MapGpuVirtualAddressCb(HANDLE hDevice, D3DDDI_MAPGPUVIRTUALADDRESS* p)
{
    KT_DEVICE("pfnMapGpuVirtualAddressCb");
    NTSTATUS st = D3DKMTMapGpuVirtualAddress(p);
    Log("cb KT.pfnMapGpuVirtualAddressCb queue=%08x hAllocation=%08x base=%llx pages=%llx -> %08lx va=%llx fence=%llu",
        p->hPagingQueue, p->hAllocation, (unsigned long long)p->BaseAddress, (unsigned long long)p->SizeInPages, st,
        (unsigned long long)p->VirtualAddress, (unsigned long long)p->PagingFenceValue);
    return FromNt(st);
}

static HRESULT APIENTRY CALLBACK FreeGpuVirtualAddressCb(HANDLE hDevice, CONST D3DDDICB_FREEGPUVIRTUALADDRESS* p)
{
    KT_DEVICE("pfnFreeGpuVirtualAddressCb");
    D3DKMT_FREEGPUVIRTUALADDRESS f{};
    f.hAdapter = d->adapter->hKm;
    f.BaseAddress = p->BaseAddress;
    f.Size = p->Size;
    NTSTATUS st = D3DKMTFreeGpuVirtualAddress(&f);
    Log("cb KT.pfnFreeGpuVirtualAddressCb base=%llx size=%llx -> %08lx", (unsigned long long)p->BaseAddress,
        (unsigned long long)p->Size, st);
    return FromNt(st);
}

static HRESULT APIENTRY CALLBACK CreateSynchronizationObject2Cb(HANDLE hDevice, D3DDDICB_CREATESYNCHRONIZATIONOBJECT2* p)
{
    KT_DEVICE("pfnCreateSynchronizationObject2Cb");
    D3DKMT_CREATESYNCHRONIZATIONOBJECT2 c{};
    c.hDevice = d->hKm;
    c.Info = p->Info;
    NTSTATUS st = D3DKMTCreateSynchronizationObject2(&c);
    p->Info = c.Info;
    p->hSyncObject = c.hSyncObject;
    Log("cb KT.pfnCreateSynchronizationObject2Cb type=%d flags=%08x -> %08lx hSyncObject=%08x", (int)p->Info.Type,
        p->Info.Flags.Value, st, c.hSyncObject);
    return FromNt(st);
}

static HRESULT APIENTRY CALLBACK DestroySynchronizationObjectCb(HANDLE hDevice, CONST D3DDDICB_DESTROYSYNCHRONIZATIONOBJECT* p)
{
    KT_DEVICE("pfnDestroySynchronizationObjectCb");
    D3DKMT_DESTROYSYNCHRONIZATIONOBJECT c{ p->hSyncObject };
    NTSTATUS st = D3DKMTDestroySynchronizationObject(&c);
    Log("cb KT.pfnDestroySynchronizationObjectCb hSyncObject=%08x -> %08lx", p->hSyncObject, st);
    return FromNt(st);
}

static HRESULT APIENTRY CALLBACK WaitForSynchronizationObjectFromCpuCb(HANDLE hDevice, CONST D3DDDICB_WAITFORSYNCHRONIZATIONOBJECTFROMCPU* p)
{
    KT_DEVICE("pfnWaitForSynchronizationObjectFromCpuCb");
    D3DKMT_WAITFORSYNCHRONIZATIONOBJECTFROMCPU w{};
    w.hDevice = d->hKm;
    w.ObjectCount = p->ObjectCount;
    w.ObjectHandleArray = p->ObjectHandleArray;
    w.FenceValueArray = p->FenceValueArray;
    w.hAsyncEvent = p->hAsyncEvent;
    w.Flags = p->Flags;
    NTSTATUS st = D3DKMTWaitForSynchronizationObjectFromCpu(&w);
    Log("cb KT.pfnWaitForSynchronizationObjectFromCpuCb n=%u obj0=%08x fence0=%llu event=%p -> %08lx", p->ObjectCount,
        p->ObjectCount ? p->ObjectHandleArray[0] : 0,
        p->ObjectCount ? (unsigned long long)p->FenceValueArray[0] : 0ull, p->hAsyncEvent, st);
    return FromNt(st);
}

static HRESULT APIENTRY CALLBACK SignalSynchronizationObjectFromCpuCb(HANDLE hDevice, CONST D3DDDICB_SIGNALSYNCHRONIZATIONOBJECTFROMCPU* p)
{
    KT_DEVICE("pfnSignalSynchronizationObjectFromCpuCb");
    D3DKMT_SIGNALSYNCHRONIZATIONOBJECTFROMCPU sg{};
    sg.hDevice = d->hKm;
    sg.ObjectCount = p->ObjectCount;
    sg.ObjectHandleArray = p->ObjectHandleArray;
    sg.FenceValueArray = p->FenceValueArray;
    NTSTATUS st = D3DKMTSignalSynchronizationObjectFromCpu(&sg);
    Log("cb KT.pfnSignalSynchronizationObjectFromCpuCb n=%u -> %08lx", p->ObjectCount, st);
    return FromNt(st);
}

static HRESULT APIENTRY CALLBACK SubmitCommandCb(HANDLE hDevice, CONST D3DDDICB_SUBMITCOMMAND* p)
{
    KT_DEVICE("pfnSubmitCommandCb");
    Log("cb KT.pfnSubmitCommandCb commands=%llx len=%u flags=%08x contexts=%u ctx0=%p privSize=%u primaries=%u history=%u",
        (unsigned long long)p->Commands, p->CommandLength, p->Flags.Value, p->BroadcastContextCount,
        p->BroadcastContextCount ? p->BroadcastContext[0] : nullptr, p->PrivateDriverDataSize, p->NumPrimaries,
        p->NumHistoryBuffers);
    Scope s;
    HexDump("   priv", p->pPrivateDriverData, p->PrivateDriverDataSize);
    D3DKMT_SUBMITCOMMAND c{};
    c.Commands = p->Commands;
    c.CommandLength = p->CommandLength;
    c.Flags.NullRendering = p->Flags.NullRendering;
    c.BroadcastContextCount = p->BroadcastContextCount;
    for (UINT i = 0; i < p->BroadcastContextCount && i < D3DDDI_MAX_BROADCAST_CONTEXT; ++i)
        c.BroadcastContext[i] = HandleToKm(p->BroadcastContext[i]);
    c.pPrivateDriverData = p->pPrivateDriverData;
    c.PrivateDriverDataSize = p->PrivateDriverDataSize;
    c.NumPrimaries = p->NumPrimaries;
    memcpy(c.WrittenPrimaries, p->WrittenPrimaries, sizeof(c.WrittenPrimaries));
    c.NumHistoryBuffers = p->NumHistoryBuffers;
    c.HistoryBufferArray = p->HistoryBufferArray;
    NTSTATUS st = D3DKMTSubmitCommand(&c);
    Log("-> D3DKMTSubmitCommand = %08lx", st);
    return FromNt(st);
}

static HRESULT APIENTRY CALLBACK WaitForSynchronizationObjectFromGpuCb(HANDLE hDevice, CONST D3DDDICB_WAITFORSYNCHRONIZATIONOBJECTFROMGPU* p)
{
    KT_DEVICE("pfnWaitForSynchronizationObjectFromGpuCb");
    D3DKMT_WAITFORSYNCHRONIZATIONOBJECTFROMGPU w{};
    w.hContext = HandleToKm(p->hContext);
    w.ObjectCount = p->ObjectCount;
    w.ObjectHandleArray = p->ObjectHandleArray;
    memcpy(w.Reserved, p->Reserved, sizeof(w.Reserved));
    NTSTATUS st = D3DKMTWaitForSynchronizationObjectFromGpu(&w);
    Log("cb KT.pfnWaitForSynchronizationObjectFromGpuCb ctx=%08x n=%u obj0=%08x -> %08lx", w.hContext, p->ObjectCount,
        p->ObjectCount ? p->ObjectHandleArray[0] : 0, st);
    return FromNt(st);
}

static HRESULT APIENTRY CALLBACK SignalSynchronizationObjectFromGpuCb(HANDLE hDevice, CONST D3DDDICB_SIGNALSYNCHRONIZATIONOBJECTFROMGPU* p)
{
    KT_DEVICE("pfnSignalSynchronizationObjectFromGpuCb");
    D3DKMT_SIGNALSYNCHRONIZATIONOBJECTFROMGPU sg{};
    sg.hContext = HandleToKm(p->hContext);
    sg.ObjectCount = p->ObjectCount;
    sg.ObjectHandleArray = p->ObjectHandleArray;
    memcpy(sg.Reserved, p->Reserved, sizeof(sg.Reserved));
    NTSTATUS st = D3DKMTSignalSynchronizationObjectFromGpu(&sg);
    Log("cb KT.pfnSignalSynchronizationObjectFromGpuCb ctx=%08x n=%u obj0=%08x -> %08lx", sg.hContext, p->ObjectCount,
        p->ObjectCount ? p->ObjectHandleArray[0] : 0, st);
    return FromNt(st);
}

static HRESULT APIENTRY CALLBACK SignalSynchronizationObjectFromGpu2Cb(HANDLE hDevice, CONST D3DDDICB_SIGNALSYNCHRONIZATIONOBJECTFROMGPU2* p)
{
    KT_DEVICE("pfnSignalSynchronizationObjectFromGpu2Cb");
    std::vector<D3DKMT_HANDLE> contexts(p->BroadcastContextCount);
    for (ULONG i = 0; i < p->BroadcastContextCount; ++i) contexts[i] = HandleToKm(p->BroadcastContextArray[i]);
    D3DKMT_SIGNALSYNCHRONIZATIONOBJECTFROMGPU2 sg{};
    sg.ObjectCount = p->ObjectCount;
    sg.ObjectHandleArray = p->ObjectHandleArray;
    sg.Flags = p->Flags;
    sg.BroadcastContextCount = p->BroadcastContextCount;
    sg.BroadcastContextArray = contexts.data();
    memcpy(sg.Reserved, p->Reserved, sizeof(sg.Reserved));
    NTSTATUS st = D3DKMTSignalSynchronizationObjectFromGpu2(&sg);
    Log("cb KT.pfnSignalSynchronizationObjectFromGpu2Cb n=%u obj0=%08x flags=%08x contexts=%lu fence=%llu -> %08lx",
        p->ObjectCount, p->ObjectCount ? p->ObjectHandleArray[0] : 0, p->Flags.Value, p->BroadcastContextCount,
        (unsigned long long)p->FenceValue, st);
    return FromNt(st);
}

static HRESULT APIENTRY CALLBACK LogUMDMarkerCb(HANDLE, CONST D3DDDICB_LOGUMDMARKER*)
{
    return S_OK; // ETW marker only; nothing for a harness to do
}

static void APIENTRY CALLBACK PerformAmortizedProcessingCb(D3D10DDI_HRTCORELAYER)
{
    // The runtime uses this to trim deferred-destruction queues; the harness keeps none.
}

static HRESULT g_lastError = S_OK; // most DDI entry points return void and report failure through SetErrorCb

static void APIENTRY CALLBACK SetErrorCb(D3D10DDI_HRTCORELAYER, HRESULT hr)
{
    g_lastError = hr;
    Log("cb UM.pfnSetErrorCb hr=%08lx", hr);
    Scope s;
    LogCaller("SetError");
}

// ---------------------------------------------------------------- adapter discovery

static bool FindAdapter(const wchar_t* match, RtAdapter* out, wchar_t* umdPath)
{
    D3DKMT_ADAPTERINFO infos[16]{};
    D3DKMT_ENUMADAPTERS2 e{};
    e.NumAdapters = 16;
    e.pAdapters = infos;
    NTSTATUS st = D3DKMTEnumAdapters2(&e);
    if (!NT_SUCCESS(st)) { Log("D3DKMTEnumAdapters2 failed %08lx", st); return false; }
    bool found = false;
    for (ULONG i = 0; i < e.NumAdapters; ++i) {
        D3DKMT_UMDFILENAMEINFO fn{};
        fn.Version = KMTUMDVERSION_DX11;
        D3DKMT_QUERYADAPTERINFO q{};
        q.hAdapter = infos[i].hAdapter;
        q.Type = KMTQAITYPE_UMDRIVERNAME;
        q.pPrivateDriverData = &fn;
        q.PrivateDriverDataSize = sizeof(fn);
        st = D3DKMTQueryAdapterInfo(&q);
        Log("adapter %lu: hAdapter=%08x luid=%08lx:%08lx sources=%lu umd(dx11)=%ls", i, infos[i].hAdapter,
            infos[i].AdapterLuid.HighPart, infos[i].AdapterLuid.LowPart, infos[i].NumOfSources,
            NT_SUCCESS(st) ? fn.UmdFileName : L"<none>");
        if (!found && NT_SUCCESS(st) && wcsstr(fn.UmdFileName, match)) {
            found = true;
            out->hKm = infos[i].hAdapter;
            out->luid = infos[i].AdapterLuid;
            wcscpy_s(umdPath, MAX_PATH, fn.UmdFileName);
        } else {
            D3DKMT_CLOSEADAPTER c{ infos[i].hAdapter };
            D3DKMTCloseAdapter(&c);
        }
    }
    return found;
}

static const char* IfaceName(UINT iface)
{
    switch (iface) {
    case D3D10_0_DDI_INTERFACE_VERSION: return "D3D10_0";
    case D3D10_1_DDI_INTERFACE_VERSION: return "D3D10_1";
    case D3D11_0_DDI_INTERFACE_VERSION: return "D3D11_0";
    case D3D11_1_DDI_INTERFACE_VERSION: return "D3D11_1";
    case D3DWDDM1_3_DDI_INTERFACE_VERSION: return "WDDM1_3";
    case D3DWDDM2_0_DDI_INTERFACE_VERSION: return "WDDM2_0";
    case D3DWDDM2_1_DDI_INTERFACE_VERSION: return "WDDM2_1";
    case D3DWDDM2_2_DDI_INTERFACE_VERSION: return "WDDM2_2";
    case D3DWDDM2_3_DDI_INTERFACE_VERSION: return "WDDM2_3";
    case D3DWDDM2_4_DDI_INTERFACE_VERSION: return "WDDM2_4";
    case D3DWDDM2_5_DDI_INTERFACE_VERSION: return "WDDM2_5";
    case D3DWDDM2_6_DDI_INTERFACE_VERSION: return "WDDM2_6";
    case D3DWDDM2_7_DDI_INTERFACE_VERSION: return "WDDM2_7";
    case D3DWDDM2_8_DDI_INTERFACE_VERSION: return "WDDM2_8";
    case D3DWDDM2_9_DDI_INTERFACE_VERSION: return "WDDM2_9";
    case D3DWDDM3_0_DDI_INTERFACE_VERSION: return "WDDM3_0";
    case D3DWDDM3_1_DDI_INTERFACE_VERSION: return "WDDM3_1";
    case D3DWDDM3_2_DDI_INTERFACE_VERSION: return "WDDM3_2";
    }
    return "?";
}

// ---------------------------------------------------------------- first workload
//
// The smallest sequence that proves the driver is really rendering under the
// fake runtime: clear a render target, copy it to a staging texture, map that
// and compare the pixels with the clear colour.

struct RtResource {
    RtKind kind = RT_RESOURCE;
    const char* name = "";
    void* drv = nullptr;
};

static D3D10DDI_HRESOURCE CreateTexture(D3DWDDM2_6DDI_DEVICEFUNCS* f, RtResource* rt, UINT w, UINT h, UINT usage,
                                        UINT bind, UINT mapFlags)
{
    D3D10DDI_MIPINFO mip{ w, h, 1, w, h, 1 };
    D3D11DDIARG_CREATERESOURCE cr{};
    cr.pMipInfoList = &mip;
    cr.ResourceDimension = D3D10DDIRESOURCE_TEXTURE2D;
    cr.Usage = usage;
    cr.BindFlags = bind;
    cr.MapFlags = mapFlags;
    cr.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    cr.SampleDesc.Count = 1;
    cr.MipLevels = 1;
    cr.ArraySize = 1;

    SIZE_T size = f->pfnCalcPrivateResourceSize(g_device.hDrv, &cr);
    rt->drv = _aligned_malloc(size ? size : 16, 64);
    memset(rt->drv, 0, size);
    D3D10DDI_HRESOURCE hRes{ rt->drv };
    D3D10DDI_HRTRESOURCE hRt{ rt };
    Log("call CreateResource '%s' %ux%u usage=%u bind=%08x (private size %zu)", rt->name, w, h, usage, bind, size);
    {
        Scope s;
        f->pfnCreateResource(g_device.hDrv, &cr, hRes, hRt);
    }
    return hRes;
}

static bool ClearReadbackTest(D3DWDDM2_6DDI_DEVICEFUNCS* f)
{
    const UINT W = 64, H = 64;
    g_lastError = S_OK;

    RtResource rtTex, rtStaging;
    rtTex.name = "render target";
    rtStaging.name = "staging";
    D3D10DDI_HRESOURCE hTex = CreateTexture(f, &rtTex, W, H, D3D10_DDI_USAGE_DEFAULT, D3D10_DDI_BIND_RENDER_TARGET, 0);
    D3D10DDI_HRESOURCE hStaging = CreateTexture(f, &rtStaging, W, H, D3D10_DDI_USAGE_STAGING, 0, D3D10_DDI_CPU_ACCESS_READ);
    if (FAILED(g_lastError)) { Log("resource creation failed: %08lx", g_lastError); return false; }

    D3DWDDM2_0DDIARG_CREATERENDERTARGETVIEW cv{};
    cv.hDrvResource = hTex;
    cv.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    cv.ResourceDimension = D3D10DDIRESOURCE_TEXTURE2D;
    cv.Tex2D.ArraySize = 1;
    SIZE_T rtvSize = f->pfnCalcPrivateRenderTargetViewSize(g_device.hDrv, &cv);
    void* rtvMem = _aligned_malloc(rtvSize ? rtvSize : 16, 64);
    memset(rtvMem, 0, rtvSize);
    D3D10DDI_HRENDERTARGETVIEW hRtv{ rtvMem };
    static RtResource rtRtv;
    rtRtv.name = "rtv";
    Log("call CreateRenderTargetView (private size %zu)", rtvSize);
    {
        Scope s;
        f->pfnCreateRenderTargetView(g_device.hDrv, &cv, hRtv, D3D10DDI_HRTRENDERTARGETVIEW{ &rtRtv });
    }

    FLOAT color[4] = { 0.25f, 0.5f, 0.75f, 1.0f };
    Log("call ClearRenderTargetView (0.25, 0.5, 0.75, 1.0)");
    {
        Scope s;
        f->pfnClearRenderTargetView(g_device.hDrv, hRtv, color);
    }
    Log("call ResourceCopy staging <- render target");
    {
        Scope s;
        f->pfnResourceCopy(g_device.hDrv, hStaging, hTex);
    }
    Log("call Flush");
    {
        Scope s;
        f->pfnFlush(g_device.hDrv, D3DWDDM2_0DDI_CONTEXTTYPE_ALL, 0);
    }

    D3D10DDI_MAPPED_SUBRESOURCE mapped{};
    Log("call StagingResourceMap(READ)");
    {
        Scope s;
        f->pfnStagingResourceMap(g_device.hDrv, hStaging, 0, D3D10_DDI_MAP_READ, 0, &mapped);
    }
    Log("mapped pData=%p RowPitch=%u DepthPitch=%u lastError=%08lx", mapped.pData, mapped.RowPitch, mapped.DepthPitch,
        g_lastError);

    bool ok = false;
    if (mapped.pData && SUCCEEDED(g_lastError)) {
        const BYTE expect[4] = { 0x40, 0x80, 0xBF, 0xFF };
        UINT bad = 0;
        for (UINT y = 0; y < H; ++y) {
            const BYTE* row = (const BYTE*)mapped.pData + (size_t)y * mapped.RowPitch;
            for (UINT x = 0; x < W; ++x)
                for (int c = 0; c < 4; ++c)
                    if (abs((int)row[x * 4 + c] - (int)expect[c]) > 1) { ++bad; break; }
        }
        const BYTE* p0 = (const BYTE*)mapped.pData;
        Log("pixel(0,0) = %02x %02x %02x %02x, expected 40 80 bf ff; mismatching pixels: %u of %u", p0[0], p0[1], p0[2],
            p0[3], bad, W * H);
        ok = bad == 0;
        Scope s;
        f->pfnStagingResourceUnmap(g_device.hDrv, hStaging, 0);
    }
    Log("CLEAR TEST: %s", ok ? "PASS" : "FAIL");

    Log("call destroy view and resources");
    {
        Scope s;
        f->pfnDestroyRenderTargetView(g_device.hDrv, hRtv);
        f->pfnDestroyResource(g_device.hDrv, hStaging);
        f->pfnDestroyResource(g_device.hDrv, hTex);
    }
    _aligned_free(rtvMem);
    _aligned_free(rtStaging.drv);
    _aligned_free(rtTex.drv);
    return ok;
}

// ---------------------------------------------------------------- main

int wmain(int argc, wchar_t** argv)
{
    const wchar_t* match = L"amdxx64";
    const wchar_t* dllOverride = nullptr;
    UINT maxIface = D3DWDDM2_6_DDI_INTERFACE_VERSION;
    UINT level = D3D11DDI_3DPIPELINELEVEL_11_0;
    bool stopAfterOpen = false;
    bool runClearTest = true;
    for (int i = 1; i < argc; ++i) {
        if (!wcscmp(argv[i], L"--match") && i + 1 < argc) match = argv[++i];
        else if (!wcscmp(argv[i], L"--dll") && i + 1 < argc) dllOverride = argv[++i];
        else if (!wcscmp(argv[i], L"--max-iface") && i + 1 < argc) maxIface = wcstoul(argv[++i], nullptr, 0);
        else if (!wcscmp(argv[i], L"--level") && i + 1 < argc) level = wcstoul(argv[++i], nullptr, 0);
        else if (!wcscmp(argv[i], L"--adapter-only")) stopAfterOpen = true;
        else if (!wcscmp(argv[i], L"--stacks")) g_stacks = true;
        else if (!wcscmp(argv[i], L"--no-test")) runClearTest = false;
        else if (!wcscmp(argv[i], L"--pending-hr") && i + 1 < argc) g_pendingHr = (HRESULT)wcstoul(argv[++i], nullptr, 0);
        else {
            wprintf(L"usage: harness [--match substr] [--dll path] [--max-iface 0xMMMMmmmm] [--level n]\n"
                    L"               [--adapter-only] [--no-test] [--stacks] [--pending-hr 0xHRESULT]\n");
            return 2;
        }
    }

    _wfopen_s(&g_logFile, L"harness.log", L"w");
    AddVectoredExceptionHandler(1, CrashFilter);

    wchar_t umdPath[MAX_PATH] = L"";
    if (!FindAdapter(match, &g_adapter, umdPath)) {
        Log("no adapter whose DX11 UMD name contains '%ls'", match);
        return 1;
    }
    if (dllOverride) wcscpy_s(umdPath, dllOverride);
    // The registry value can hold several comma-separated names; DX11 uses the first.
    if (wchar_t* comma = wcschr(umdPath, L',')) *comma = 0;

    Log("loading %ls", umdPath);
    HMODULE umd = LoadLibraryExW(umdPath, nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!umd) { Log("LoadLibrary failed, error %lu", GetLastError()); return 1; }
    Log("loaded at %p", umd);
    HookImports(umd);

    auto openAdapter = (PFND3D10DDI_OPENADAPTER)GetProcAddress(umd, "OpenAdapter10_2");
    if (!openAdapter) { Log("no OpenAdapter10_2 export"); return 1; }

    // --- OpenAdapter10_2
    D3DDDI_ADAPTERCALLBACKS adapterCb{};
    adapterCb.pfnQueryAdapterInfoCb = QueryAdapterInfoCb;
    adapterCb.pfnGetMultisampleMethodListCb = GetMultisampleMethodListCb;
    adapterCb.pfnQueryAdapterInfoCb2 = QueryAdapterInfoCb2;

    D3D10DDIARG_OPENADAPTER oa{};
    oa.hRTAdapter.handle = &g_adapter;
    oa.Interface = D3D11_0_DDI_INTERFACE_VERSION;
    oa.Version = (UINT)(D3D11_0_DDI_SUPPORTED & 0xffffffff);
    oa.pAdapterCallbacks = &adapterCb;
    oa.pAdapterFuncs_2 = &g_adapter.funcs;

    Log("call OpenAdapter10_2 Interface=%08x Version=%08x", oa.Interface, oa.Version);
    HRESULT hr;
    {
        Scope s;
        hr = openAdapter(&oa);
    }
    Log("OpenAdapter10_2 = %08lx hAdapter=%p", hr, oa.hAdapter.pDrvPrivate);
    if (FAILED(hr)) return 1;
    g_adapter.hDrv = oa.hAdapter;
    Log("adapter funcs: CalcPrivateDeviceSize=%p CreateDevice=%p CloseAdapter=%p GetSupportedVersions=%p GetCaps=%p",
        g_adapter.funcs.pfnCalcPrivateDeviceSize, g_adapter.funcs.pfnCreateDevice, g_adapter.funcs.pfnCloseAdapter,
        g_adapter.funcs.pfnGetSupportedVersions, g_adapter.funcs.pfnGetCaps);

    // --- GetSupportedVersions
    UINT32 nVersions = 0;
    {
        Scope s;
        hr = g_adapter.funcs.pfnGetSupportedVersions(g_adapter.hDrv, &nVersions, nullptr);
    }
    Log("GetSupportedVersions(count) = %08lx n=%u", hr, nVersions);
    std::vector<UINT64> versions(nVersions);
    if (nVersions) {
        Scope s;
        hr = g_adapter.funcs.pfnGetSupportedVersions(g_adapter.hDrv, &nVersions, versions.data());
    }
    UINT64 chosen = 0;
    for (UINT64 v : versions) {
        UINT iface = (UINT)(v >> 32);
        Log("  supported %08x:%08x  %s build %u rev %u", iface, (UINT)v, IfaceName(iface), (UINT)(v >> 16) & 0xffff,
            (UINT)v & 0xffff);
        if (iface <= maxIface && v > chosen) chosen = v;
    }
    if (!chosen) { Log("no supported version at or below %08x", maxIface); return 1; }
    UINT iface = (UINT)(chosen >> 32), version = (UINT)chosen;
    Log("using %s (%08x:%08x)", IfaceName(iface), iface, version);

    // --- GetCaps
    {
        D3D11DDI_THREADING_CAPS tc{};
        D3D10_2DDIARG_GETCAPS gc{ D3D11DDICAPS_THREADING, nullptr, &tc, sizeof(tc) };
        hr = g_adapter.funcs.pfnGetCaps(g_adapter.hDrv, &gc);
        Log("GetCaps(THREADING) = %08lx caps=%08x", hr, tc.Caps);

        D3D11DDI_3DPIPELINESUPPORT_CAPS pc{};
        gc = { D3D11DDICAPS_3DPIPELINESUPPORT, nullptr, &pc, sizeof(pc) };
        hr = g_adapter.funcs.pfnGetCaps(g_adapter.hDrv, &gc);
        Log("GetCaps(3DPIPELINESUPPORT) = %08lx caps=%08x", hr, pc.Caps);
    }
    if (stopAfterOpen) return 0;

    // --- kernel device, as the runtime creates before calling the driver
    g_device.adapter = &g_adapter;
    D3DKMT_CREATEDEVICE kcd{};
    kcd.hAdapter = g_adapter.hKm;
    NTSTATUS st = D3DKMTCreateDevice(&kcd);
    Log("D3DKMTCreateDevice = %08lx hDevice=%08x", st, kcd.hDevice);
    if (!NT_SUCCESS(st)) return 1;
    g_device.hKm = kcd.hDevice;

    // --- callback tables
    static D3DDDI_DEVICECALLBACKS kt;
    FillStubs<TK_KT>((void**)&kt, std::make_index_sequence<sizeof(kt) / sizeof(void*)>());
    kt.pfnEscapeCb = EscapeCb;
    kt.pfnCreatePagingQueueCb = CreatePagingQueueCb;
    kt.pfnDestroyPagingQueueCb = DestroyPagingQueueCb;
    kt.pfnCreateContextCb = CreateContextCb;
    kt.pfnCreateContextVirtualCb = CreateContextVirtualCb;
    kt.pfnDestroyContextCb = DestroyContextCb;
    kt.pfnAllocateCb = AllocateCb;
    kt.pfnDeallocateCb = DeallocateCb;
    kt.pfnDeallocate2Cb = Deallocate2Cb;
    kt.pfnLock2Cb = Lock2Cb;
    kt.pfnUnlock2Cb = Unlock2Cb;
    kt.pfnMakeResidentCb = MakeResidentCb;
    kt.pfnEvictCb = EvictCb;
    kt.pfnReserveGpuVirtualAddressCb = ReserveGpuVirtualAddressCb;
    kt.pfnMapGpuVirtualAddressCb = MapGpuVirtualAddressCb;
    kt.pfnFreeGpuVirtualAddressCb = FreeGpuVirtualAddressCb;
    kt.pfnCreateSynchronizationObject2Cb = CreateSynchronizationObject2Cb;
    kt.pfnDestroySynchronizationObjectCb = DestroySynchronizationObjectCb;
    kt.pfnWaitForSynchronizationObjectFromCpuCb = WaitForSynchronizationObjectFromCpuCb;
    kt.pfnSignalSynchronizationObjectFromCpuCb = SignalSynchronizationObjectFromCpuCb;
    kt.pfnSubmitCommandCb = SubmitCommandCb;
    kt.pfnWaitForSynchronizationObjectFromGpuCb = WaitForSynchronizationObjectFromGpuCb;
    kt.pfnSignalSynchronizationObjectFromGpuCb = SignalSynchronizationObjectFromGpuCb;
    kt.pfnSignalSynchronizationObjectFromGpu2Cb = SignalSynchronizationObjectFromGpu2Cb;
    kt.pfnLogUMDMarkerCb = LogUMDMarkerCb;

    static D3DWDDM2_6DDI_CORELAYER_DEVICECALLBACKS um;
    FillStubs<TK_UM>((void**)&um, std::make_index_sequence<sizeof(um) / sizeof(void*)>());
    um.pfnSetErrorCb = SetErrorCb;
    um.pfnPerformAmortizedProcessingCb = PerformAmortizedProcessingCb;
    um.pfnCreateContextCb = UmCreateContextCb;
    um.pfnCreateContextVirtualCb = UmCreateContextVirtualCb;

    static DXGI_DDI_BASE_CALLBACKS dxgiCb;
    FillStubs<TK_DXGI>((void**)&dxgiCb, std::make_index_sequence<sizeof(dxgiCb) / sizeof(void*)>());

    // Function tables the driver fills in. Sized generously and zeroed so we can
    // see exactly how many slots a given interface version populates.
    static void* deviceFuncs[1024];
    static void* dxgiFuncs[128];
    static PFND3D10DDI_RETRIEVESUBOBJECT retrieveSubObject = nullptr;

    UINT flags = ((level & 0x7) << D3D11DDI_CREATEDEVICE_FLAG_3DPIPELINESUPPORT_SHIFT) |
                 ((level & 0x18) << D3D11DDI_CREATEDEVICE_FLAG_3DPIPELINESUPPORT_SHIFT2);

    D3D10DDIARG_CALCPRIVATEDEVICESIZE cs{ iface, version, flags };
    SIZE_T devSize;
    {
        Scope s;
        devSize = g_adapter.funcs.pfnCalcPrivateDeviceSize(g_adapter.hDrv, &cs);
    }
    Log("CalcPrivateDeviceSize(flags=%08x) = %zu", flags, devSize);
    g_device.drvStorage = _aligned_malloc(devSize ? devSize : 16, 64);
    memset(g_device.drvStorage, 0, devSize);

    D3D10DDIARG_CREATEDEVICE cd{};
    cd.hRTDevice.handle = &g_device;
    cd.Interface = iface;
    cd.Version = version;
    cd.pKTCallbacks = &kt;
    cd.pDeviceFuncs = (D3D10DDI_DEVICEFUNCS*)deviceFuncs;
    cd.hDrvDevice.pDrvPrivate = g_device.drvStorage;
    cd.DXGIBaseDDI.pDXGIBaseCallbacks = &dxgiCb;
    cd.DXGIBaseDDI.pDXGIDDIBaseFunctions = (DXGI_DDI_BASE_FUNCTIONS*)dxgiFuncs;
    cd.hRTCoreLayer.handle = &g_device;
    cd.pWDDM2_6UMCallbacks = &um;
    cd.Flags = flags;
    cd.ppfnRetrieveSubObject = &retrieveSubObject;

    Log("call CreateDevice");
    {
        Scope s;
        hr = g_adapter.funcs.pfnCreateDevice(g_adapter.hDrv, &cd);
    }
    Log("CreateDevice = %08lx", hr);

    size_t nDev = 0, nDxgi = 0;
    for (size_t i = 0; i < _countof(deviceFuncs); ++i) if (deviceFuncs[i]) nDev = i + 1;
    for (size_t i = 0; i < _countof(dxgiFuncs); ++i) if (dxgiFuncs[i]) nDxgi = i + 1;
    Log("device funcs filled: %zu slots, dxgi funcs: %zu slots, retrieveSubObject=%p", nDev, nDxgi, retrieveSubObject);

    if (FAILED(hr)) return 1;
    g_device.hDrv = cd.hDrvDevice;

    int rc = 0;
    if (runClearTest) {
        if (iface != D3DWDDM2_6_DDI_INTERFACE_VERSION) {
            Log("clear test needs the WDDM2_6 function table layout; skipped for %s", IfaceName(iface));
        } else {
            rc = ClearReadbackTest((D3DWDDM2_6DDI_DEVICEFUNCS*)deviceFuncs) ? 0 : 1;
        }
    }

    // --- teardown, in the order the runtime uses
    Log("call DestroyDevice");
    {
        Scope s;
        ((D3DWDDM2_6DDI_DEVICEFUNCS*)deviceFuncs)->pfnDestroyDevice(g_device.hDrv);
    }
    D3DKMT_DESTROYDEVICE kdd{ g_device.hKm };
    st = D3DKMTDestroyDevice(&kdd);
    Log("D3DKMTDestroyDevice = %08lx", st);
    {
        Scope s;
        hr = g_adapter.funcs.pfnCloseAdapter(g_adapter.hDrv);
    }
    Log("CloseAdapter = %08lx", hr);
    return rc;
}
