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
static std::vector<Bp> g_bps;
static uintptr_t g_rearm = 0; // address to re-arm when the single-step after a breakpoint lands

static void ArmBp(HMODULE mod, uintptr_t rva, const char* tag)
{
    uintptr_t at = (uintptr_t)mod + rva;
    DWORD old;
    if (!VirtualProtect((void*)at, 1, PAGE_EXECUTE_READWRITE, &old)) {
        Log("  ArmBp(%s) at %p: VirtualProtect failed (%lu)", tag, (void*)at, GetLastError());
        return;
    }
    unsigned char orig = *(unsigned char*)at;
    *(unsigned char*)at = 0xCC;
    VirtualProtect((void*)at, 1, old, &old);
    Log("  ArmBp(%s) at %p: orig byte 0x%02x -> 0xCC", tag, (void*)at, orig);
    g_bps.push_back({ at, orig, tag });
}
