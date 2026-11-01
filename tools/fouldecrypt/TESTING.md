# FoulDecrypt aligned-only Taurine test

Build: arm64 / iOS 14.0+, USE_LIBKERNRW=1, USE_LIBKRW and USE_TFP0 undefined.
Links /usr/lib/libkernrw.0.dylib. The kernel provider is not initialized by the aligned decryption path.
The unaligned branch is compiled out and replaced with a hard failure.
No installation package, foulwrapper, app registration, app launch or fairplayd restart is used.
FairPlay authorization on XS / iOS 14.8 remains unverified.

## 1. PC: prepare a separate copy

Keep the original encrypted IPA untouched. Extract a COPY to a new folder, retaining
Payload/Pacemaker.app, the executable's original name, and complete SC_Info directory.
Do not re-sign or strip the input executable's signature.
Use the actual .app/executable names if they differ from these examples.
This tool processes a Mach-O executable, not the IPA archive.

Extract this build artifact to a new folder. Open PowerShell inside it:

    $phoneIP = Read-Host "iPhone Wi-Fi IP"
    $phoneTarget = "root@$phoneIP"
    $scratch = "/var/tmp/pm-foul-" + (Get-Date -Format "yyyyMMdd-HHmmss")
    ssh $phoneTarget "umask 077; mkdir '$scratch'"
    if ($LASTEXITCODE -ne 0) { throw "Scratch folder creation failed." }
    scp -O .\fouldecrypt-taurine-aligned "${phoneTarget}:$scratch/"
    if ($LASTEXITCODE -ne 0) { throw "Helper transfer failed." }
    $appCopy = Read-Host "Full PC path to the separately extracted Pacemaker.app"
    scp -O -r "$appCopy" "${phoneTarget}:$scratch/"
    if ($LASTEXITCODE -ne 0) { throw "App COPY transfer failed." }
    Write-Host "Scratch folder: $scratch"
    ssh $phoneTarget

Enter SSH credentials privately at the normal prompt.

## 2. iPhone SSH shell: test only the scratch copy

Substitute the printed scratch folder below. Both paths must resolve under /var/tmp.
Never use /var/containers or the existing offloaded app's location.

    cd /var/tmp/pm-foul-YOUR-TIMESTAMP
    chmod 700 ./fouldecrypt-taurine-aligned
    ./fouldecrypt-taurine-aligned -v ./Pacemaker.app/Pacemaker ./Pacemaker.decrypted
    result=$?
    printf 'decrypt exit=%s\n' "$result"

The destination must not exist. Existing files/symlinks are rejected with O_EXCL.
Input is opened read-only; encrypted slices are checked before output creation.
Unaligned regions, mmap errors or decryption errors stop processing without kernel fallback.
A failed attempt may leave a NEW incomplete output. Do not treat it as decrypted.
If another attempt is justified, choose a new filename rather than overwriting anything.

If mmap/mremap_encrypted returns EPERM, STOP. Do not install/register Pacemaker,
execute its binary, restart fairplayd or change jailbreaks to work around it.
Retain SC_Info; a bare executable does not establish FairPlay authorization.

The helper checks cryptid=0 and changed encrypted bytes after successful remap/copy.
Exit=0 alone is insufficient. Verify independently below.

## 3. PC: pull and independently inspect output

In the iPhone shell:

    exit

In the original PC PowerShell window, still inside the artifact folder:

    $originalCopy = Join-Path $appCopy "Pacemaker"
    $verifiedCopy = Join-Path $PWD "Pacemaker.decrypted"
    if (Test-Path -LiteralPath $verifiedCopy) { throw "Local output exists; choose a new filename." }
    scp -O "${phoneTarget}:$scratch/Pacemaker.decrypted" "$verifiedCopy"
    if ($LASTEXITCODE -ne 0) { throw "Output transfer failed." }
    py -3 .\verify_macho.py "$originalCopy" "$verifiedCopy"

Use the actual executable name if different. Do not sign/repackage before comparison.
The verifier reads both saved files and requires equal sizes and matching encryption metadata,
output cryptid=0, changed encrypted bytes, and no other changes apart from cryptid fields.

For your reported slice expect:
    cryptoff=0x4000 cryptsize=0xc28000 cryptid=1 -> 0

If these values differ, reconcile the exact file/slice before proceeding.
Hashes for both files are printed. A PASS verifies structure and changed-byte integrity,
not complete plaintext correctness or app launchability.
Do not install the result on the XS containing offloaded Pacemaker data.
Share diagnostic text only; keep SC_Info, IPA contents and account data private.

## Provenance

upstream/ contains the unmodified pinned FoulDecrypt source tar.
BUILD-SPEC.txt identifies FoulDecrypt and KernInfra; the upstream gitmodules pin dependencies.
SAFETY-CHANGES.patch records local modifications separately.
DEPENDENCIES.txt, LOAD-COMMANDS.txt and EMBEDDED-ENTITLEMENTS.plist record inspection.
The original upstream entitlements are preserved.
CI builds/signs/inspects the helper, but never executes device code or kernel operations.
