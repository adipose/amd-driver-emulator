#pragma once
// Checkpoint and decoy probe system: Decoy record, global decoy table, hit counter, workload flag.
//
// Included from src/amd/legacy9.cpp.
//
// Checkpoint() is NOT extracted here: it references g_live, g_procHeap, g_cs, g_proc, g_priv,
// g_virtualAllocs, InVictimClass, CheckZone, and ScanHeapsForSignature -- all defined in
// legacy9.cpp and too entangled to separate cleanly.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <vector>

struct Decoy { ULONG_PTR* block; ULONG_PTR expect[19]; };
static std::vector<Decoy> g_decoys;
static size_t g_decoyHits = 0;
static bool g_workloadDone = false; // set after Checkpoint("after workload"); gates early-exit PROBE DONE
