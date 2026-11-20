#pragma once
// VEH breakpoint mechanism: Bp record, global breakpoint table, re-arm address, and ArmBp helper.
//
// Included from src/amd/legacy9.cpp.  ArmBp references Log(), which must be defined (not merely
// declared) before this header is included at its call site.
//
// SyntaxNote: functions are static so they become file-statics of the including translation unit.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <cstdint>
#include <vector>

// ---- int3 breakpoints inside the driver, handled by the VEH ---------------------------------------------
// Lets the run log say which driver-internal paths execute and with what arguments, without a debugger.
struct Bp { uintptr_t addr; unsigned char orig; const char* tag; };
// Fixed static table, not a heap vector: this harness deliberately provokes the driver's
// wild 152-byte-class writes, and a heap-allocated bp table lands in that size class — a
// stray zeroing wiped the vector's buffer mid-flush (every entry read back as zero, so the
// gate bp surfaced as an unhandled int3 inside pfnFlush).  Static storage can't be a victim.
static Bp g_bps[32];
static size_t g_bpsCount = 0;
static uintptr_t g_rearm = 0; // address to re-arm when the single-step after a breakpoint lands

// g_bps is read by CrashFilter on any thread that takes an int3 and written by ArmBp on the
// arming thread; keep the accesses serialized.  CRITICAL_SECTIONs are recursive, so a nested
// exception on the arming thread cannot deadlock against itself.
static CRITICAL_SECTION g_bpsCs;
static INIT_ONCE g_bpsCsOnce = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK BpsCsInit(PINIT_ONCE, PVOID, PVOID*) { InitializeCriticalSection(&g_bpsCs); return TRUE; }
static void BpsLock() { InitOnceExecuteOnce(&g_bpsCsOnce, BpsCsInit, nullptr, nullptr); EnterCriticalSection(&g_bpsCs); }
static void BpsUnlock() { LeaveCriticalSection(&g_bpsCs); }

static void ArmBp(HMODULE mod, uintptr_t rva, const char* tag)
{
    uintptr_t at = (uintptr_t)mod + rva;
    BpsLock();
    for (size_t i = 0; i < g_bpsCount; i++) {
        if (g_bps[i].addr == at) {
            Log("  ArmBp(%s) at %p: already armed, skipping", tag, (void*)at);
            BpsUnlock();
            return;
        }
    }
    DWORD old;
    if (!VirtualProtect((void*)at, 1, PAGE_EXECUTE_READWRITE, &old)) {
        Log("  ArmBp(%s) at %p: VirtualProtect failed (%lu)", tag, (void*)at, GetLastError());
        BpsUnlock();
        return;
    }
    if (g_bpsCount >= sizeof g_bps / sizeof g_bps[0]) {
        Log("  ArmBp(%s) at %p: bp table full", tag, (void*)at);
        BpsUnlock();
        return;
    }
    unsigned char orig = *(unsigned char*)at;
    *(unsigned char*)at = 0xCC;
    VirtualProtect((void*)at, 1, old, &old);
    Log("  ArmBp(%s) at %p: orig byte 0x%02x -> 0xCC", tag, (void*)at, orig);
    g_bps[g_bpsCount++] = Bp{ at, orig, tag };
    BpsUnlock();
}
