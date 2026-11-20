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

// ---- IAT-style function-pointer replacement ---------------------------------------------------------------
// The pool alloc/free are dispatched through QWORD pointers in atiumd6a's data section (a pool-manager
// vtable), and the actual functions live in a different AMD module outside atiumd6a's image range.
// A 5-byte rel32 patch can't bridge that gap, so we replace the pointer in the vtable instead.
// The original pointer is stored separately; each hook calls it directly with no trampoline.

// True alloc: pool_alloc(pool_mgr, template_obj, ...) — size is NOT an argument; the pool
// is a fixed 0x98 size-class, so every return from this function is a 0x98-byte block.
// True free:  pool_free(pool_mgr, obj, ...) — first arg is the pool manager, second is the
// block to return.  Both are dispatched through the pool manager's vtable (ff 15).
typedef void* (*PoolAllocFn)(void* a0, void* a1, ULONG_PTR a2, ULONG_PTR a3);
typedef void  (*PoolFreeFn )(void* a0, void* p,  ULONG_PTR a2, ULONG_PTR a3);
static PoolAllocFn g_poolAllocOrig = nullptr;
static PoolFreeFn  g_poolFreeOrig = nullptr;
static void** g_poolAllocSlot = nullptr;  // vtable slot we patched for alloc
static void** g_poolFreeSlot  = nullptr;  // vtable slot we patched for free

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
static void* HookPoolAlloc(void* a0, void* a1, ULONG_PTR a2, ULONG_PTR a3)
{
    void* result = g_poolAllocOrig(a0, a1, a2, a3);
    if (result) {
        PoolLock();
        g_poolLive[g_poolLiveHead % 256].ptr = result;
        g_poolLiveHead++;
        PoolUnlock();
        Log("pool: alloc 0x98 -> %p", result);
    }
    return result;
}

static void HookPoolFree(void* a0, void* p, ULONG_PTR a2, ULONG_PTR a3)
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
    g_poolFreeOrig(a0, p, a2, a3);
}

// ---- scan-based install ----------------------------------------------------------------------------------
// Two-phase scan:
//
//   Phase 1 — find the zero-fill call site.
//     Scan for "mov r8d, 0x98" (41 B8 98 00 00 00) followed within 32 bytes by a rel32 call.
//     That call is a rep-stosb / memset variant that zeroes the freshly-allocated block.
//     It is NOT the true pool alloc; it is an anchor for phase 2.
//
//   Phase 2 — find the TRUE alloc by scanning backwards from the zero-fill call site.
//     The calling sequence is:
//       call TRUE_ALLOC     ; returns new block pointer in rax
//       ...
//       mov rcx, rax        ; 48 8B C8 — move pointer to rcx for the zero-fill call
//       [xor edx, edx]      ; fill = 0
//       mov r8d, 0x98       ; size = 0x98
//       call ZERO_FILL      ; ← zero-fill call site
//     Scan backwards from the zero-fill site for "48 8B C8", then backwards from there for E8.
//
//   Phase 3 — emit a hex dump of ±160 bytes around the zero-fill call site so we can
//     identify the pool-free function in the same function body.
//
// The pool-free function is found in the hex dump; it will be hardcoded in a follow-up.
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

    // ---- Phase 1: find the zero-fill call site ---------------------------------------------------------
    uint8_t* zeroFillCallSite = nullptr;
    uint8_t* zeroFillFn       = nullptr;

    // Limit scan to first 2 MB: the call site is at RVA ~0x5FC4, well within that range.
    uint8_t* scanEnd = base + (imageSize < 0x200000 ? imageSize : 0x200000) - 32;
    for (uint8_t* p = base + 0x1000; p < scanEnd && !zeroFillCallSite; p++) {
        // mov r8d, 0x98: 41 B8 98 00 00 00
        if (p[0] == 0x41 && p[1] == 0xB8 && p[2] == 0x98 &&
            p[3] == 0x00 && p[4] == 0x00 && p[5] == 0x00) {
            for (int j = 6; j < 38 && !zeroFillCallSite; j++) {
                if (p[j] == 0xE8) {
                    int32_t rel = *(int32_t*)(p + j + 1);
                    uint8_t* target = p + j + 5 + rel;
                    uintptr_t rva = (uintptr_t)target - (uintptr_t)base;
                    if (rva >= 0x1000 && rva < imageSize) {
                        zeroFillCallSite = p + j;
                        zeroFillFn       = target;
                    }
                }
            }
        }
    }

    if (!zeroFillCallSite) {
        Log("pool: warning: could not find zero-fill call site");
        return;
    }
    Log("pool: zero-fill call site %p (RVA=0x%llx), zero-fill fn %p (RVA=0x%llx)",
        (void*)zeroFillCallSite,
        (unsigned long long)((uintptr_t)zeroFillCallSite - (uintptr_t)base),
        (void*)zeroFillFn,
        (unsigned long long)((uintptr_t)zeroFillFn       - (uintptr_t)base));

    // ---- Phase 2: forward scan for the indirect pool-alloc dispatch (ff 15) -------------------------
    // The allocation call uses an indirect dispatch (ff 15) through the pool manager's vtable.
    // It follows the zero-fill call after a few arg-setup instructions:
    //   call ZERO_FILL          ← zeroFillCallSite (+0)
    //   mov rsi, [rbp+0x77]
    //   ...                     (arg setup: pool_mgr in rcx, template ptr in rdx)
    //   call [rip+disp]  (ff 15)  ← the true pool alloc, ~+60 bytes from zeroFillCallSite
    //
    // The vtable slot immediately after (+8 bytes) is the companion pool-free function.
    uint8_t* trueAllocFn = nullptr;
    uint8_t* trueFreeFn  = nullptr;

    for (int fwd = 5; fwd <= 128 && !trueAllocFn; fwd++) {
        uint8_t* p = zeroFillCallSite + fwd;
        if (p[0] != 0xFF || p[1] != 0x15) continue;
        int32_t disp = *(int32_t*)(p + 2);
        uint8_t** fnPtrAddr = (uint8_t**)(p + 6 + (ptrdiff_t)disp);
        uint8_t* candidate = nullptr;
        __try { candidate = *fnPtrAddr; } __except(EXCEPTION_EXECUTE_HANDLER) { continue; }
        // Don't require the alloc function to be inside atiumd6a — it may live in a
        // different AMD module.  Just check the pointer is in an executable page.
        MEMORY_BASIC_INFORMATION mbi = {};
        if (!VirtualQuery(candidate, &mbi, sizeof(mbi))) continue;
        if (!(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                             PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) continue;
        trueAllocFn = candidate;
        g_poolAllocSlot = (void**)fnPtrAddr;

        // Try the adjacent vtable slot (+8 bytes) for the pool-free companion.
        uint8_t* freeCand = nullptr;
        __try { freeCand = *(fnPtrAddr + 1); } __except(EXCEPTION_EXECUTE_HANDLER) {}
        MEMORY_BASIC_INFORMATION mbif = {};
        if (freeCand && VirtualQuery(freeCand, &mbif, sizeof(mbif)) &&
            (mbif.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                             PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) &&
            freeCand != trueAllocFn) {
            trueFreeFn = freeCand;
            g_poolFreeSlot = (void**)(fnPtrAddr + 1);
        }
        Log("pool: vtable at %p -> alloc=%p free=%p", (void*)fnPtrAddr,
            (void*)trueAllocFn, (void*)trueFreeFn);
    }

    if (!trueAllocFn) {
        Log("pool: warning: forward ff-15 scan could not find pool alloc");
        return;
    }

    // ---- Install hooks via vtable-slot replacement (IAT style) ---------------------------------------
    // The driver dispatches through these pointers; replace them with our hook functions.
    // The original function addresses are stored in g_poolAllocOrig/g_poolFreeOrig for the
    // hooks to call directly — no trampoline or rel32 patch needed.
    auto PatchSlot = [](void** slot, void* hook, void** origOut, const char* name) -> bool {
        DWORD old;
        if (!VirtualProtect(slot, 8, PAGE_READWRITE, &old)) {
            Log("pool: VirtualProtect(%s slot %p) failed (%lu)", name, (void*)slot, GetLastError());
            return false;
        }
        *origOut = *slot;
        *slot = hook;
        VirtualProtect(slot, 8, old, &old);
        FlushInstructionCache(GetCurrentProcess(), slot, 8);
        Log("pool: patched %s slot %p: %p -> %p", name, (void*)slot, *origOut, hook);
        return true;
    };

    void* allocOrig = nullptr;
    if (!PatchSlot(g_poolAllocSlot, (void*)&HookPoolAlloc, &allocOrig, "alloc")) return;
    g_poolAllocOrig = (PoolAllocFn)allocOrig;
    installed = true;

    if (g_poolFreeSlot) {
        void* freeOrig = nullptr;
        if (PatchSlot(g_poolFreeSlot, (void*)&HookPoolFree, &freeOrig, "free"))
            g_poolFreeOrig = (PoolFreeFn)freeOrig;
    }
    Log("pool: hooks installed (alloc%s)", g_poolFreeOrig ? " + free" : " only");
}

#endif // D3D9SHIM_DLL
