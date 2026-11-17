#pragma once
// Heap walker and signature scanner: LooksLikeUserPtr, VectorShape, DamageShape,
// sig/victim global buffers, and WalkOneHeap.
//
// Included from src/amd/legacy9.cpp.  WalkOneHeap references Log() which must be defined before
// this header is included.
//
// ScanHeapsForSignature is NOT extracted here: it references g_stride, g_cs, g_procHeap, and
// g_classHistory which are all defined in legacy9.cpp and are too entangled to separate cleanly.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <cstdint>
#include <cstring>

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

// Nothing in the walk allocates or logs: allocating from a heap being walked invalidates the walk.
static unsigned char g_sigCopy[32][192];
static void* g_sigAddr[32];
static DWORD g_sigSize[32];
static void* g_vicAddr[8192];

// Separate function so __try can be used without hitting C2712 (no C++ objects in scope here).
static bool WalkOneHeap(HANDLE heap, size_t* pInClass, size_t* pVictims, size_t* pSigs)
{
    PROCESS_HEAP_ENTRY e = {};
    __try {
        while (HeapWalk(heap, &e)) {
            if (!(e.wFlags & PROCESS_HEAP_ENTRY_BUSY)) continue;
            if (e.cbData < 144 || e.cbData > 176) continue;
            (*pInClass)++;
            const ULONG_PTR* q = (const ULONG_PTR*)e.lpData;
            size_t slots = e.cbData / 8;
            if (slots > 19) slots = 19;
            if (!VectorShape(q, slots)) continue;
            if (*pVictims < 8192) g_vicAddr[*pVictims] = e.lpData;
            (*pVictims)++;
            if (!DamageShape(q, slots)) continue;
            size_t s = *pSigs;
            if (s < 32) {
                memcpy(g_sigCopy[s], e.lpData, e.cbData);
                g_sigAddr[s] = e.lpData;
                g_sigSize[s] = e.cbData;
            }
            (*pSigs)++;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Log("!! ScanHeapsForSignature: HeapWalk AV on heap %p, skipping", heap);
        return false;
    }
    return true;
}
