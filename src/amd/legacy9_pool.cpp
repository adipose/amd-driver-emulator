// Pool allocator hooking for atiumd6a.dll (shim build only).
//
// The driver's 152-byte-class objects come from a private pool allocator, not the process heap, so
// the heap-census/decoy machinery never sees them.  This file finds that allocator by signature
// (the mov edx/r8d, 0x98 size argument), detours alloc and free with 5-byte E9 hooks plus a
// jmp-[rip] trampoline, tracks live 0x98 allocations, and on free arms a hardware write
// watchpoint (DR0-DR3) on [inner+0x64] of the just-freed object: the clear-via-selector routine
// writes [boundTex+0x48]+0x64 after the free, and the watchpoint turns that UAF write into a
// single-step the CrashFilter can attribute exactly.
//
// Included from legacy9.cpp under D3D9SHIM_DLL; Log() and the VEH are already defined there.

#ifdef D3D9SHIM_DLL

// ---- live-allocation table -------------------------------------------------------------------------------
// Fixed static storage for the same reason as g_bps: this table describes the size class whose
// stray writes we are hunting, so it must not itself live in a heap block of that class.
static CRITICAL_SECTION g_poolCs;
static INIT_ONCE g_poolCsOnce = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK PoolCsInit(PINIT_ONCE, PVOID, PVOID*) { InitializeCriticalSection(&g_poolCs); return TRUE; }
static void PoolLock() { InitOnceExecuteOnce(&g_poolCsOnce, PoolCsInit, nullptr, nullptr); EnterCriticalSection(&g_poolCs); }
static void PoolUnlock() { LeaveCriticalSection(&g_poolCs); }

struct PoolEntry { void* ptr; };
static PoolEntry g_poolLive[256];
static int g_poolLiveHead = 0;

// ---- trampolines and originals ----------------------------------------------------------------------------
static uint8_t* g_trampolinePage = nullptr;
static uint8_t* g_poolAllocTramp = nullptr;
static uint8_t* g_poolFreeTramp = nullptr;

typedef void* (*PoolAllocFn)(void* a0, size_t size, ULONG_PTR a2, ULONG_PTR a3);
typedef void  (*PoolFreeFn)(void* p, ULONG_PTR a1, ULONG_PTR a2, ULONG_PTR a3);
static PoolAllocFn g_poolAllocOrig = nullptr;
static PoolFreeFn  g_poolFreeOrig = nullptr;

// ---- hardware watchpoints ---------------------------------------------------------------------------------
struct HwWp { uintptr_t addr; void* freed_obj; bool active; };
static HwWp g_hwWp[4];
static CRITICAL_SECTION g_hwWpCs;
static INIT_ONCE g_hwWpCsOnce = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK HwWpCsInit(PINIT_ONCE, PVOID, PVOID*) { InitializeCriticalSection(&g_hwWpCs); return TRUE; }
static void HwWpLock() { InitOnceExecuteOnce(&g_hwWpCsOnce, HwWpCsInit, nullptr, nullptr); EnterCriticalSection(&g_hwWpCs); }
static void HwWpUnlock() { LeaveCriticalSection(&g_hwWpCs); }

// Program DR<slot> with addr and set DR7 for an 8-byte write watchpoint: local enable at bit
// 2*slot, RW=01 (write) at bits 16+4*slot, LEN=11 (8 bytes) at bits 18+4*slot.
static void SetDrSlot(CONTEXT* ctx, int slot, uintptr_t addr)
{
    switch (slot) {
    case 0: ctx->Dr0 = addr; break;
    case 1: ctx->Dr1 = addr; break;
    case 2: ctx->Dr2 = addr; break;
    case 3: ctx->Dr3 = addr; break;
    default: return;
    }
    DWORD64 mask = (1ULL << (2 * slot)) | (0xFULL << (16 + 4 * slot));
    ctx->Dr7 &= ~mask;
    ctx->Dr7 |= (1ULL << (2 * slot))        // local enable
              | (1ULL << (16 + 4 * slot))   // RW = 01: break on data write
              | (2ULL << (18 + 4 * slot));  // LEN = 10: 8 bytes (x64)
}

// Arm a write watchpoint on addr in the current thread.
// Note: SuspendThread on driver worker threads deadlocks when called from the state-flush path
// (those threads hold driver-internal locks that the current thread also needs).  Since the
// UAF write happens on the current thread's own state flush, the current-thread-only approach
// is sufficient.
static void ArmWriteWatchpoint(uintptr_t addr, void* freed_obj)
{
    int slot = -1;
    HwWpLock();
    for (int i = 0; i < 4; i++) {
        if (!g_hwWp[i].active) { g_hwWp[i] = HwWp{ addr, freed_obj, true }; slot = i; break; }
    }
    HwWpUnlock();
    if (slot < 0) {
        Log("pool: no free DR slot for watchpoint on %p (freed_obj=%p)", (void*)addr, freed_obj);
        return;
    }
    // GetThreadContext cannot read a running thread's own context, so capture and push back.
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    RtlCaptureContext(&ctx);
    SetDrSlot(&ctx, slot, addr);
    SetThreadContext(GetCurrentThread(), &ctx);
    Log("pool: armed DR%d write watchpoint on %p (freed_obj=%p)", slot, (void*)addr, freed_obj);
}

// Called from CrashFilter on EXCEPTION_SINGLE_STEP.  Returns true when the exception was one of
// our hardware watchpoints firing, i.e. a real UAF write to a freed 152-byte-class object.
static bool HandleHwWpException(EXCEPTION_POINTERS* ep)
{
    InitOnceExecuteOnce(&g_hwWpCsOnce, HwWpCsInit, nullptr, nullptr);
    EnterCriticalSection(&g_hwWpCs);
    bool handled = false;
    DWORD64 dr6 = ep->ContextRecord->Dr6;
    if (dr6 & 0xF) {
        for (int i = 0; i < 4; i++) {
            if (!g_hwWp[i].active || !(dr6 & (1ULL << i))) continue;
            Log("*** REAL UAF WRITE: target=%p freed_obj=%p", (void*)g_hwWp[i].addr, g_hwWp[i].freed_obj);
            g_hwWp[i].active = false;
            // Disarm this slot in the faulting thread: clear the enable and condition bits.
            DWORD64 mask = (1ULL << (2 * i)) | (0xFULL << (16 + 4 * i));
            ep->ContextRecord->Dr7 &= ~mask;
            ep->ContextRecord->Dr6 &= ~(1ULL << i);
            handled = true;
        }
    }
    LeaveCriticalSection(&g_hwWpCs);
    if (handled)
        ep->ContextRecord->EFlags &= ~0x100u; // clear TF so execution continues past the write
    return handled;
}

// ---- 5-byte detour ----------------------------------------------------------------------------------------
// Overwrites the first 5 bytes of target with a rel32 jump to replacement.  trampoline_out gets
// the original 5 bytes plus a jmp [rip+0] back to target+5, so the original stays callable.
static bool InstallHook(void* target, void* replacement, uint8_t* trampoline_out)
{
    ptrdiff_t disp = (char*)replacement - ((char*)target + 5);
    if (disp < (ptrdiff_t)(int32_t)0x80000000 || disp > (ptrdiff_t)0x7fffffff) {
        Log("pool: InstallHook: displacement too large (%p -> %p)", target, replacement);
        return false;
    }
    DWORD old;
    if (!VirtualProtect(target, 5, PAGE_EXECUTE_READWRITE, &old)) {
        Log("pool: InstallHook: VirtualProtect(%p) failed (%lu)", target, GetLastError());
        return false;
    }
    memcpy(trampoline_out, target, 5);
    // FF 25 00 00 00 00 <8-byte absolute target> == jmp qword ptr [rip+0]
    trampoline_out[5] = 0xFF;
    trampoline_out[6] = 0x25;
    *(uint32_t*)(trampoline_out + 7) = 0;
    *(uintptr_t*)(trampoline_out + 11) = (uintptr_t)target + 5;

    uint8_t* t = (uint8_t*)target;
    t[0] = 0xE9;
    *(int32_t*)(t + 1) = (int32_t)disp;
    VirtualProtect(target, 5, old, &old);
    FlushInstructionCache(GetCurrentProcess(), target, 5);
    return true;
}

// ---- the hooks ----------------------------------------------------------------------------------------------
static void* HookPoolAlloc(void* a0, size_t size, ULONG_PTR a2, ULONG_PTR a3)
{
    void* result = g_poolAllocOrig(a0, size, a2, a3);
    if (result && size == 0x98) {
        PoolLock();
        g_poolLive[g_poolLiveHead % 256].ptr = result;
        g_poolLiveHead++;
        PoolUnlock();
        Log("pool: alloc 0x98 -> %p", result);
    }
    return result;
}

static void HookPoolFree(void* p, ULONG_PTR a1, ULONG_PTR a2, ULONG_PTR a3)
{
    if (p) {
        bool found = false;
        void* inner48 = nullptr;
        PoolLock();
        for (int i = 0; i < 256; i++) {
            if (g_poolLive[i].ptr == p) {
                g_poolLive[i].ptr = nullptr;
                found = true;
                break;
            }
        }
        if (found) {
            __try { inner48 = *(void**)((char*)p + 0x48); } __except(EXCEPTION_EXECUTE_HANDLER) {}
        }
        PoolUnlock();
        if (found && inner48) {
            Log("pool: free %p (inner=%p) -> watchpoint on inner+0x64", p, inner48);
            ArmWriteWatchpoint((uintptr_t)inner48 + 0x64, p);
        }
    }
    g_poolFreeOrig(p, a1, a2, a3);
}

// ---- signature scan and install -----------------------------------------------------------------------------
// Finds the pool allocator by its characteristic size argument: mov edx, 0x98 (ba 98 00 00 00)
// or mov r8d, 0x98 (41 b8 98 00 00 00) immediately ahead of a call, then locates the paired
// free by the mov rcx, rax (48 8b c8) + call pattern that follows the allocation call site.
static void ShimHookPool()
{
    static bool installed = false;
    if (installed) return;

    HMODULE a6a = GetModuleHandleA("atiumd6a.dll");
    if (!a6a) { Log("pool: atiumd6a.dll not loaded, hook skipped"); return; }

    uint8_t* base = (uint8_t*)a6a;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { Log("pool: bad DOS header"); return; }
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { Log("pool: bad NT header"); return; }
    size_t imageSize = nt->OptionalHeader.SizeOfImage;

    uint8_t* scan = base + 0x1000;
    uint8_t* end = base + imageSize - 32;
    uint8_t* poolAllocFn = nullptr;
    uint8_t* allocCallSite = nullptr;
    for (uint8_t* p = scan; p < end && !allocCallSite; p++) {
        bool sizeArg = (p[0] == 0xba && p[1] == 0x98 && p[2] == 0x00 && p[3] == 0x00 && p[4] == 0x00) ||
                       (p[0] == 0x41 && p[1] == 0xb8 && p[2] == 0x98 && p[3] == 0x00 && p[4] == 0x00 && p[5] == 0x00);
        if (!sizeArg) continue;
        size_t prefix = (p[0] == 0x41) ? 6 : 5;
        for (size_t j = prefix; j < prefix + 32; j++) {
            if (p[j] == 0xE8) {
                int32_t rel = *(int32_t*)(p + j + 1);
                poolAllocFn = p + j + 5 + rel;
                allocCallSite = p + j;
                break;
            }
        }
    }
    if (!allocCallSite) {
        Log("pool: warning: pool-alloc signature (size 0x98 + call) not found in atiumd6a.dll");
        return;
    }

    // Log the alloc function's RVA so we can match against the known pool-function pair
    // 0x83E100 / 0x2D5280 (from prior analysis of atiumd6a).
    uintptr_t allocRva = (uintptr_t)poolAllocFn - (uintptr_t)base;
    Log("pool: alloc function at %p (RVA=0x%llx, call site %p)",
        (void*)poolAllocFn, (unsigned long long)allocRva, (void*)allocCallSite);

    // The two known pool-function RVAs: one is alloc, the other is free.
    // Whichever the scan found as alloc, use the partner as free.
    static const uintptr_t kPoolRvaA = 0x83E100;
    static const uintptr_t kPoolRvaB = 0x2D5280;
    uint8_t* poolFreeFn = nullptr;
    if (allocRva == kPoolRvaA)
        poolFreeFn = base + kPoolRvaB;
    else if (allocRva == kPoolRvaB)
        poolFreeFn = base + kPoolRvaA;
    else {
        // Known RVAs don't match this build — fall back to narrow pattern scan.
        Log("pool: alloc RVA 0x%llx doesn't match known pair (0x%llx/0x%llx), trying pattern scan",
            (unsigned long long)allocRva,
            (unsigned long long)kPoolRvaA, (unsigned long long)kPoolRvaB);
        for (uint8_t* p = allocCallSite + 5; p < allocCallSite + 5 + 256 && !poolFreeFn; p++) {
            if (p[0] == 0x48 && p[1] == 0x8b && p[2] == 0xc8) { // mov rcx, rax
                for (size_t j = 3; j < 3 + 16; j++) {
                    if (p[j] == 0xE8) {
                        int32_t rel = *(int32_t*)(p + j + 1);
                        poolFreeFn = p + j + 5 + rel;
                        break;
                    }
                }
            }
        }
    }
    if (!poolFreeFn) {
        Log("pool: warning: could not locate pool-free function (alloc RVA=0x%llx)",
            (unsigned long long)allocRva);
        return;
    }
    Log("pool: free function at %p (RVA=0x%llx)", (void*)poolFreeFn,
        (unsigned long long)((uintptr_t)poolFreeFn - (uintptr_t)base));
    Log("pool: pairing confirmed: alloc=%p free=%p", (void*)poolAllocFn, (void*)poolFreeFn);

    g_trampolinePage = (uint8_t*)VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE,
                                              PAGE_EXECUTE_READWRITE);
    if (!g_trampolinePage) {
        Log("pool: VirtualAlloc for trampolines failed (%lu)", GetLastError());
        return;
    }
    memset(g_trampolinePage, 0x90, 4096);
    g_poolAllocTramp = g_trampolinePage;
    g_poolFreeTramp = g_trampolinePage + 32;

    if (!InstallHook(poolAllocFn, (void*)&HookPoolAlloc, g_poolAllocTramp)) return;
    if (!InstallHook(poolFreeFn, (void*)&HookPoolFree, g_poolFreeTramp)) return;
    g_poolAllocOrig = (PoolAllocFn)g_poolAllocTramp;
    g_poolFreeOrig = (PoolFreeFn)g_poolFreeTramp;
    installed = true;
    Log("pool: allocator hooks installed (trampolines at %p)", (void*)g_trampolinePage);
}

#endif // D3D9SHIM_DLL
