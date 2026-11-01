#!/bin/bash
set -euo pipefail
ROOT="$PWD"
mkdir -p work
git clone https://github.com/NyaMisty/fouldecrypt.git work/fouldecrypt-upstream
cd work/fouldecrypt-upstream
git checkout --detach c480edd2a648fbe5e200a2b05b7f3d739c91fbf1
git submodule update --init --recursive
test "$(git -C kerninfra rev-parse HEAD)" = 8dff02e5c8ba26184031b34cc808fcc45416a651
git archive --format=tar HEAD > "$ROOT/work/fouldecrypt-upstream.tar"
cd "$ROOT"
cp -R work/fouldecrypt-upstream work/fouldecrypt-build
cd work/fouldecrypt-build
cp "$ROOT/tools/fouldecrypt/main.safe.cpp" main.cpp
python3 - <<'PY'
from pathlib import Path
p = Path("Makefile")
s = p.read_text().replace("export USE_LIBKRW = 1", "# USE_LIBKRW disabled")
s = s.replace("# export USE_LIBKERNRW = 1", "export USE_LIBKERNRW = 1")
s = s.replace("TOOL_NAME = fouldecrypt flexdecrypt2 foulwrapper", "TOOL_NAME = fouldecrypt")
p.write_text(s)
PY
git diff -- main.cpp Makefile > "$ROOT/work/SAFETY-CHANGES.patch"
mkdir obj
SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
CFLAGS=(-arch arm64 -isysroot "$SDK" -miphoneos-version-min=14.0 -O2 -DUSE_LIBKERNRW=1 -UUSE_LIBKRW -UUSE_TFP0 -DFOULDECRYPT_ALIGNED_ONLY=1 -Ikerninfra/includes -DFMT_HEADER_ONLY=1)
xcrun --sdk iphoneos clang "${CFLAGS[@]}" -c kerninfra/patchfinder/libdimentio.c -o obj/patchfinder.o
xcrun --sdk iphoneos clang "${CFLAGS[@]}" -c kerninfra/rw_prov/rw_prov_libkernrw/rw_prov_libkernrw.c -o obj/provider.o
for source in main.cpp foulmain.cpp kerninfra/kern_func.cpp kerninfra/rw_wrap/rw_wrap.cpp kerninfra/kerninfra.mm; do
  name="$(basename "$source")"
  xcrun --sdk iphoneos clang++ "${CFLAGS[@]}" -std=c++20 -c "$source" -o "obj/$name.o"
done
xcrun --sdk iphoneos clang++ "${CFLAGS[@]}" obj/*.o -framework Foundation -framework IOKit -lcompression -Lkerninfra/libs -lkernrw -Wl,-no_fixup_chains -o fouldecrypt-taurine-aligned
ldid -Sentitlements.plist fouldecrypt-taurine-aligned
test "$(lipo -archs fouldecrypt-taurine-aligned)" = arm64
xcrun otool -L fouldecrypt-taurine-aligned > "$ROOT/work/DEPENDENCIES.txt"
grep -q /usr/lib/libkernrw.0.dylib "$ROOT/work/DEPENDENCIES.txt"
if grep -q 'libkrw' "$ROOT/work/DEPENDENCIES.txt"; then echo "Wrong KRW provider"; exit 1; fi
xcrun otool -l fouldecrypt-taurine-aligned > "$ROOT/work/LOAD-COMMANDS.txt"
grep -q LC_DYLD_INFO "$ROOT/work/LOAD-COMMANDS.txt"
if grep -q LC_DYLD_CHAINED_FIXUPS "$ROOT/work/LOAD-COMMANDS.txt"; then exit 1; fi
ldid -e fouldecrypt-taurine-aligned > "$ROOT/work/EMBEDDED-ENTITLEMENTS.plist"
plutil -lint "$ROOT/work/EMBEDDED-ENTITLEMENTS.plist"
cmp entitlements.plist "$ROOT/work/fouldecrypt-upstream/entitlements.plist"
xcrun --sdk iphoneos clang++ "${CFLAGS[@]}" -std=c++20 -E main.cpp > "$ROOT/work/main.preprocessed.cpp"
python3 - "$ROOT/work/main.preprocessed.cpp" <<'PY'
import sys
s = open(sys.argv[1]).read()
region = s[s.index("unprotect(int f,"):s.index("decrypt_macho_slide(int f,")]
assert "prepare_kernel(" not in region
assert "crypto_backing_offset().store" not in region
assert "crypto_start().store" not in region
assert "kernel patching is disabled" in region
print("Verified: decryption path has no kernel fallback")
PY
cd "$ROOT"
mkdir -p artifact/upstream
cp work/fouldecrypt-build/fouldecrypt-taurine-aligned artifact/
cp work/fouldecrypt-upstream/entitlements.plist artifact/
cp tools/fouldecrypt/verify_macho.py tools/fouldecrypt/TESTING.md artifact/
cp work/DEPENDENCIES.txt work/LOAD-COMMANDS.txt work/EMBEDDED-ENTITLEMENTS.plist work/SAFETY-CHANGES.patch artifact/
cp work/fouldecrypt-upstream.tar artifact/upstream/
git rev-parse HEAD > artifact/BUILD-COMMIT.txt
printf '%s\n' 'FoulDecrypt c480edd2a648fbe5e200a2b05b7f3d739c91fbf1' 'KernInfra 8dff02e5c8ba26184031b34cc808fcc45416a651' 'USE_LIBKERNRW=1 USE_LIBKRW=undefined ALIGNED_ONLY=1 arm64 iOS-min=14.0' > artifact/BUILD-SPEC.txt
xcodebuild -version > artifact/TOOLCHAIN.txt
(cd artifact && shasum -a 256 fouldecrypt-taurine-aligned verify_macho.py > SHA256SUMS.txt)
