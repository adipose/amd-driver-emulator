# drivers

The user-mode driver under test goes here. Nothing in this directory is
committed: these are AMD's binaries, and this repository does not
redistribute them.

The probe needs only the user-mode DLLs, and loads them as a library. It does
not install anything, and the kernel-mode files are here only so the set
matches a dump's module list.

| file | what it is | needed |
|---|---|---|
| `atiumd64.dll` | the D3D9 user-mode driver, the one `OpenAdapter` is called on | yes |
| `atiumd6a.dll` | loaded by it as a sibling; the 152-byte object lives in this one | yes |
| `aticfx64.dll` | the D3D10/11 user-mode driver of the same package | no |
| `atiu9p64.dll` | the D3D9 pass-through loader | no |
| `atikmdag.sys`, `atikmpag.sys` | kernel mode, for reference only; never loaded | no |

## Getting them

For the MPC-HC #4257 investigation these came from the last Catalyst/Crimson
package for TeraScale cards (Radeon HD 5000, HD 6000, and the HD 7000 parts
below the HD 7700), built 2015-08-04. Download the legacy package from AMD and
extract it; the files are under the packed driver directory. Do not install
it. It is a legacy package for hardware the test machines do not have.

The build in the field dumps is not this one. The dumps carry four `atiumd64`
timestamps between 2015-08-07 and 2015-11-05, and the extractable package is
three days older than the earliest. Treat results as applying to the branch,
not to an exact build.

## Where the probe looks

In order: `--dll` on the command line, `$env:MPC_TEST_AMDUMD`, then
`drivers\atiumd64.dll` beside this file. `tools\Find-LegacyDriver.ps1`
implements that search and is what the scripts and the test suite call.
