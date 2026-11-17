# amd-driver-emulator

Plays the role of the Direct3D runtime so a real graphics user-mode driver can
be driven, measured and bounds-checked inside a process of the test's
choosing, including the player's own.

The D3D runtime talks to a user-mode display driver through a documented
interface: it calls `OpenAdapter` / `OpenAdapter10_2` / `OpenAdapter12` and
hands over a table of callbacks. This repository implements that side. The
driver is a real DLL doing real work; everything beneath it belongs to the
harness.

It is the driver-side sibling of the virtual devices in the MPC-HC test
framework. Those stand in for hardware the player talks *to*; this one stands
in for the runtime a real driver is loaded *by*, which makes a driver testable
on a machine that does not have its hardware.

Two harnesses, built from the same conventions:

- **`legacy9`** hosts a legacy D3D9 user-mode driver, with the kernel side
  faked rather than forwarded, and measures what the driver does to the heap
  it was given. This is the one the test suite drives.
- **`harness`** hosts the current D3D11 user-mode driver of the installed AMD
  driver, with the kernel side forwarded to the real kernel driver, far enough
  to create a device and render.

## What is proven

On Windows 10 22H2 (19045) with an AMD Radeon 780M, 2026-11-15:

| | |
|---|---|
| Host the 2015 legacy D3D9 UMD (`atiumd64.dll`) with no card of its family present | yes |
| `OpenAdapter` succeeds, `GetCaps` answers D3D9 caps and a format count | yes |
| Run it inside a running MPC-HC process, in that process's own heap | yes |
| Measure the heap stride of a size class instead of assuming it | yes, 160 bytes |
| Guard zones on every driver allocation, checked at each free | yes, 1470 checks |
| Detect a planted heap-damage pattern in a live heap walk | yes |
| Host the current D3D11 UMD (`amdxx64.dll`) through `CreateDevice` and render | yes, clear and read back |
| Drive the legacy driver into `CreateDevice` with a faked kernel | yes, 35 kernel callbacks deep |
| Get the legacy driver's `CreateDevice` to succeed | yes, with an invented adapter record |

## The legacy device phase

`--device` runs `CreateDevice` with the kernel side faked: allocations backed
by guarded virtual memory, invented GPU virtual addresses, paging queues, and
submissions accepted and reported complete. The driver reads a description of
its hardware from a private adapter record, and with a minimal invented record
it completes device creation.

The record is read by the DDI entry at `atiumd64+0x18E0`, in two queries
through the same `pfnQueryAdapterInfoCb` callback. The first is `0x260` (608)
bytes: the returned record's first dword must equal `0x260` (checked at
`+0x1914`), the checksum at `+0xC` is verified only when non-zero, and `+0x1F4`
is a flags dword whose bit 7 selects the WDDM 2 memory model (paging queues,
GPU virtual addresses, `SubmitCommand`) over WDDM 1.x and whose bit 10
(`0x400`) gates the second query. The second, issued at `+0x1C19` only when
bit 10 is set, is `0x3A00` (14848) bytes into adapter context `+0x280`, and is
where the hardware and memory description lives.

The minimal set of fields that gets `CreateDevice` to return `S_OK`, every
other byte of both records left zero:

    --qai-set  0=0x260,0x30=0x5a,0x3c=8,0x1f4=0x480,0xd4=2
    --qai-set2 0x2a00=1,0x2a04=1,0x2c2c=1,0x2c30=1
    --gpu-va-base 0x20000

In the first record: `+0x0` the size; `+0x30` a chip/family selector (`0x5a`
or `0x5b`); `+0x3C` a count that must be exactly 8; `+0x1F4` the flags
(`0x80|0x400`); and `+0xD4` a count of at least two, which caps at four and
gates a per-entry copy loop at `+0x1A39`, so it reads like an engine or ring
count. In the second record, four gates are read back through the device
object: a memory-size field at `+0x2A00`/`+0x2A04` (checked at `+0x7BAD7` and
`+0x7BAE4`) and two flags at `+0x2C2C`/`+0x2C30` (`+0x7BAFE`, `+0x7BAF1`).

When any of those second-record gates reads zero, the driver takes a branch to
`+0x7BD80` that returns `S_OK` without initialising its command-buffer manager;
a later command emit then dereferences the null manager and faults writing a
packet header to address 0 (`+0x5447BF`). A driver that reports success while
leaving a subsystem uninitialised is a defect in its own right, independent of
the invented record.

One field looks like a magic number and is not. A blanket byte-fill of both
records reaches `CreateDevice` only for the fill bytes `0x01` and `0x08`, not
`0x02`, `0x04` or `0x0C`. The sensitive byte is at second-record `+0xC06`, read
at `+0x132941`, and the measured rule is `(byte & 7) <= 1`: `0x01` and `0x08`
satisfy it and the others do not. It is a byte read, not a dword.

Past `CreateDevice` the next wall is synchronisation: the driver makes its
allocations resident and then waits on a monitored fence the faked kernel never
advances, spinning in `WaitForSynchronizationObjectFromGpuCb` until the stack
overflows. Reporting that fence already complete is the next step.

Two things worth keeping in mind. A clean run under an invented record proves
very little, because the driver takes the paths that record selects, which are
not necessarily the ones a real card of that family would select. But a write
outside its own allocation, which the guard zones catch, is wrong on any
hardware and would be worth having whatever the record said. The evidence this
harness can produce is asymmetric, and only one side of it is worth chasing.

## What it needs

A Visual Studio 2022 with the C++ toolset. No WDK installation: the DDI
headers come from Microsoft's `Microsoft.Windows.WDK.x64` NuGet package, and
neither they nor the driver binaries under test are redistributed here (see
`NOTICE` and `drivers\README.md`).

    .\build.ps1   # fetches the DDI headers from nuget.org on a fresh checkout, then builds

builds four binaries into `build\`: `legacy9.exe`, `legacy9hook.dll` (the same
probe, to run inside another process), `inject.exe` (loads the hook into a
running process) and `harness.exe` (the D3D11 path).

## Running the legacy probe

    .\tools\legacy9.ps1 -NoDriver                     measure the heap, check the detector, load nothing
    .\tools\legacy9.ps1 -Rounds 6 -Decoys 128         open and close the adapter six times
    .\tools\legacy9.ps1 -Redzone                      guard zones on every driver allocation
    .\tools\inject.ps1 -Player <mpc-hc64.exe>         the same, inside a player it starts
    .\tools\inject.ps1 -ProcessId <pid>               the same, inside a process already running

`-Json <path>` writes the result as JSON so a caller can assert on fields
instead of parsing the log. `build\legacy9.exe` with no arguments lists every
option.

What the probe does, in order: plant decoy blocks shaped like the object under
investigation, measure the heap stride from their addresses, prove the damage
detector fires by planting damage in one decoy and requiring the scan to find
it, then load the driver and call it, checkpointing after each step. A
checkpoint walks every heap in the process looking for the damage pattern,
compares every decoy against what it was, and checks every guard zone.

## What it measures

- **The heap the driver allocates from.** The driver's own `KERNEL32` heap
  imports are hooked, so every allocation is attributed and counted by size.
  The legacy D3D9 driver takes the great majority of its blocks from
  `GetProcessHeap()`, which is the application's heap.
- **The stride of a size class**, from the addresses of blocks the probe
  allocated itself, rather than from arithmetic over a header size.
- **Adjacency.** For each driver block in a size class of interest, the
  distance to the nearest block shaped like the object under investigation,
  and the displacement a write from there would need to reach it.
- **Whether anything writes out of bounds**, with `-Redzone`: each driver
  allocation is padded with wide guard zones, checked at every checkpoint and
  at every free.

`-Redzone` pads every driver allocation, which moves its requests out of the
size class being studied. It answers whether the driver writes outside its own
blocks; it cannot also answer whether its blocks land next to something else.
Those are separate runs.

## Faking the hardware

A driver branches on what the kernel tells it about the adapter. The legacy
D3D9 driver reads a 608-byte private record through `pfnQueryAdapterInfoCb`
and validates it before it will open: a size field, a family, and a chip id
and revision. `--qai-set off=value,...` invents those fields; the scripts pass
the set that gets the 2015 driver open.

This is the harness's real limit, and it bounds every conclusion drawn from
it. The driver takes the code paths the invented record selects, which are not
necessarily the ones a real card of that family would select. A crash under
the harness may be the harness; a clean run proves less than it looks.
`--qai-forward` instead forwards the query to the installed kernel driver,
which is only meaningful when the hardware actually matches.

## Traps

- The kernel side is refused, not forwarded, unless `--kmt-forward` is passed.
  The legacy driver resolves some `D3DKMT*` entry points itself through
  `GetProcAddress`, so those are wrapped and logged too.
- A DLL cannot be loaded from the agent shell on this machine (`LoadLibrary`
  fails with error 126 for any DLL), which is why `inject.exe` exists as a
  native tool rather than as PowerShell.
- The probe's log is opened for shared reading and closed when the run ends,
  so it can be followed while a long-lived host process is still running.
- Nothing here installs a driver. The legacy package is for hardware the test
  machines do not have and must not be installed on them.
