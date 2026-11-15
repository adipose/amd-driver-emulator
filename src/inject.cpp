// inject: loads legacy9hook.dll into another process and calls its Legacy9Run export, so the probe runs inside
// that process's heap. Written as a native tool because the scripted version could not load a DLL at all.
//
//   inject --check <dll>                 load the DLL here and report why, if it fails
//   inject --pid <n> --dll <hook dll>    load it into that process and start the probe
//
// Nothing is installed and no driver code runs in this process; the probe's own options come from the .args file
// beside the hook DLL.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <cwchar>

static void Err(const wchar_t* what)
{
    DWORD e = GetLastError();
    wchar_t* msg = nullptr;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr,
                   e, 0, (LPWSTR)&msg, 0, nullptr);
    wprintf(L"%ls failed: %lu %ls\n", what, e, msg ? msg : L"");
    if (msg) LocalFree(msg);
}

int wmain(int argc, wchar_t** argv)
{
    const wchar_t* dll = nullptr;
    const wchar_t* check = nullptr;
    DWORD pid = 0;
    for (int i = 1; i < argc; i++) {
        if (!wcscmp(argv[i], L"--pid") && i + 1 < argc) pid = wcstoul(argv[++i], nullptr, 0);
        else if (!wcscmp(argv[i], L"--dll") && i + 1 < argc) dll = argv[++i];
        else if (!wcscmp(argv[i], L"--check") && i + 1 < argc) check = argv[++i];
        else { wprintf(L"unknown option %ls\n", argv[i]); return 2; }
    }

    if (check) {
        HMODULE m = LoadLibraryExW(check, nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
        if (!m) { Err(L"LoadLibraryEx"); return 1; }
        void* p = (void*)GetProcAddress(m, "Legacy9Run");
        wprintf(L"loaded %ls at %p, Legacy9Run at %p\n", check, (void*)m, p);
        return p ? 0 : 1;
    }

    if (!pid || !dll) { wprintf(L"usage: inject --pid <n> --dll <legacy9hook.dll>   |   inject --check <dll>\n"); return 2; }

    wchar_t full[MAX_PATH];
    if (!GetFullPathNameW(dll, MAX_PATH, full, nullptr)) { Err(L"GetFullPathName"); return 1; }

    // The export's offset inside the image is read from a local copy, then applied to the module's base in the
    // target: the two images have the same layout.
    HMODULE local = LoadLibraryExW(full, nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (!local) { Err(L"LoadLibraryEx (local copy)"); return 1; }
    void* localProc = (void*)GetProcAddress(local, "Legacy9Run");
    if (!localProc) { wprintf(L"Legacy9Run is not exported\n"); return 1; }
    SIZE_T rva = (SIZE_T)((char*)localProc - (char*)local);

    HANDLE proc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
                                  PROCESS_VM_WRITE | PROCESS_VM_READ,
                              FALSE, pid);
    if (!proc) { Err(L"OpenProcess"); return 1; }

    SIZE_T bytes = (wcslen(full) + 1) * sizeof(wchar_t);
    void* remote = VirtualAllocEx(proc, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) { Err(L"VirtualAllocEx"); return 1; }
    if (!WriteProcessMemory(proc, remote, full, bytes, nullptr)) { Err(L"WriteProcessMemory"); return 1; }

    void* loadLibrary = (void*)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    HANDLE t = CreateRemoteThread(proc, nullptr, 0, (LPTHREAD_START_ROUTINE)loadLibrary, remote, 0, nullptr);
    if (!t) { Err(L"CreateRemoteThread (LoadLibraryW)"); return 1; }
    DWORD w = WaitForSingleObject(t, 30000);
    DWORD code = 0;
    GetExitCodeThread(t, &code);
    CloseHandle(t);
    wprintf(L"LoadLibraryW in pid %lu: wait=%lu exit=0x%lx\n", pid, w, code);
    if (w != WAIT_OBJECT_0) { wprintf(L"the remote LoadLibraryW did not finish\n"); return 1; }
    if (!code) { wprintf(L"the target could not load the DLL\n"); return 1; }

    // The exit code holds only the low 32 bits of the module handle, so the base is read back from the target.
    HMODULE mods[1024];
    DWORD needed = 0;
    void* base = nullptr;
    typedef BOOL(WINAPI * PFN_ENUM)(HANDLE, HMODULE*, DWORD, LPDWORD);
    typedef DWORD(WINAPI * PFN_NAME)(HANDLE, HMODULE, LPWSTR, DWORD);
    HMODULE psapi = LoadLibraryW(L"kernel32.dll");
    auto enumMods = (PFN_ENUM)GetProcAddress(psapi, "K32EnumProcessModules");
    auto modName = (PFN_NAME)GetProcAddress(psapi, "K32GetModuleFileNameExW");
    if (enumMods && modName && enumMods(proc, mods, sizeof mods, &needed)) {
        for (DWORD i = 0; i < needed / sizeof(HMODULE); i++) {
            wchar_t name[MAX_PATH] = L"";
            modName(proc, mods[i], name, MAX_PATH);
            if (_wcsicmp(name, full) == 0) { base = mods[i]; break; }
        }
    }
    if (!base) { wprintf(L"the DLL loaded but its base could not be found in the target\n"); return 1; }

    void* entry = (char*)base + rva;
    wprintf(L"legacy9hook.dll at %p in pid %lu, Legacy9Run at %p\n", base, pid, entry);
    HANDLE t2 = CreateRemoteThread(proc, nullptr, 0, (LPTHREAD_START_ROUTINE)entry, nullptr, 0, nullptr);
    if (!t2) { Err(L"CreateRemoteThread (Legacy9Run)"); return 1; }
    wprintf(L"probe thread started in pid %lu\n", pid);
    CloseHandle(t2);
    CloseHandle(proc);
    return 0;
}
