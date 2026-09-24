#!/bin/sh
set -eu

die() { printf 'build-release: %s\n' "$*" >&2; exit 1; }
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
# shellcheck disable=SC1091
. "$SCRIPT_DIR/asset-pins.sh"

[ "$(uname -s)/$(uname -m)" = Linux/x86_64 ] || die 'release must be built on Linux x86_64'
command -v curl >/dev/null 2>&1 || die 'curl is required'
command -v tar >/dev/null 2>&1 || die 'tar is required'
command -v sha256sum >/dev/null 2>&1 || die 'sha256sum is required'
command -v openssl >/dev/null 2>&1 || die 'OpenSSL is required to check the OpenCode npm package'
command -v readelf >/dev/null 2>&1 || die 'readelf is required for the GLIBC compatibility check'
command -v ldd >/dev/null 2>&1 || die 'ldd is required to collect llama shared libraries'
command -v grep >/dev/null 2>&1 || die 'grep is required for release validation'
command -v python3 >/dev/null 2>&1 || die 'python3 is required to append the executable footer'

SCRIPT_OUT=${1:-"$REPO_ROOT/dist/disk-cleanup-agent-linux-x86_64"}
mkdir -p "$(dirname -- "$SCRIPT_OUT")"
SCRIPT_OUT=$(CDPATH= cd -- "$(dirname -- "$SCRIPT_OUT")" && pwd)/$(basename -- "$SCRIPT_OUT")
WORK=$(mktemp -d "${TMPDIR:-/tmp}/disk-cleanup-release.XXXXXX") || die 'cannot create a release staging directory'
SMOKE_ROOT=
cleanup() { rm -rf "$WORK"; [ -z "$SMOKE_ROOT" ] || rm -rf "$SMOKE_ROOT"; }
trap cleanup EXIT HUP INT TERM
CACHE="$WORK/cache"
BUNDLE="$WORK/bundle"
mkdir -p "$CACHE" "$BUNDLE/bin" "$BUNDLE/lib/cleanup_agent" "$BUNDLE/llama" "$BUNDLE/model" "$BUNDLE/python" "$BUNDLE/licenses"

fetch() {
  name=$1 url=$2 expected=$3 file="$CACHE/$1"
  if [ -n "${DISKCLEANUP_DOWNLOAD_CACHE:-}" ] && [ -f "$DISKCLEANUP_DOWNLOAD_CACHE/$name" ]; then
    cp "$DISKCLEANUP_DOWNLOAD_CACHE/$name" "$file"
  else
    curl --fail --location --silent --show-error --retry 3 --connect-timeout 20 --max-time 1800 "$url" -o "$file" \
      || die "download failed: $url"
  fi
  printf '%s  %s\n' "$expected" "$file" | sha256sum -c - >/dev/null || die "SHA-256 mismatch for $name"
}
fetch_sha512() {
  name=$1 url=$2 expected=$3 file="$CACHE/$1"
  if [ -n "${DISKCLEANUP_DOWNLOAD_CACHE:-}" ] && [ -f "$DISKCLEANUP_DOWNLOAD_CACHE/$name" ]; then
    cp "$DISKCLEANUP_DOWNLOAD_CACHE/$name" "$file"
  else
    curl --fail --location --silent --show-error --retry 3 --connect-timeout 20 --max-time 1800 "$url" -o "$file" \
      || die "download failed: $url"
  fi
  actual=$(openssl dgst -sha512 -binary "$file" | openssl base64 -A) || die "could not hash $name"
  [ "$actual" = "$expected" ] || die "SHA-512 mismatch for $name"
}

fetch_sha512 opencode.tgz "$OPENCODE_URL" "$OPENCODE_SHA512"
fetch llama.tar.gz "$LLAMA_URL" "$LLAMA_SHA256"
fetch model.gguf "$MODEL_URL" "$MODEL_SHA256"
[ "$(wc -c <"$CACHE/model.gguf" | tr -d ' ')" = "$MODEL_BYTES" ] || die 'GGUF size mismatch'
fetch opencode.LICENSE "$OPENCODE_LICENSE_URL" "$OPENCODE_LICENSE_SHA256"
fetch model.LICENSE "$MODEL_LICENSE_URL" "$MODEL_LICENSE_SHA256"
fetch python.tar.gz "$PYTHON_URL" "$PYTHON_SHA256"

# Fetch and verify the exact Go toolchain used by the static launcher build.
GO_ROOT="$WORK/go"
if command -v go >/dev/null 2>&1 && [ "$(go version | awk '{print $3}')" = "go$GO_VERSION" ]; then
  GO_BIN=$(command -v go)
else
  fetch go.tar.gz "$GO_URL" "$GO_SHA256"
  mkdir -p "$GO_ROOT"
  tar -xzf "$CACHE/go.tar.gz" -C "$GO_ROOT"
  GO_BIN="$GO_ROOT/go/bin/go"
fi

mkdir -p "$WORK/opencode" "$WORK/llama"
tar -xzf "$CACHE/opencode.tgz" -C "$WORK/opencode"
cp "$WORK/opencode/package/bin/opencode" "$BUNDLE/bin/opencode"
chmod 755 "$BUNDLE/bin/opencode"

tar -xzf "$CACHE/llama.tar.gz" -C "$WORK/llama"
LLAMA_ROOT="$WORK/llama/llama-$LLAMA_VERSION"
[ -x "$LLAMA_ROOT/llama-server" ] || die 'llama archive has no llama-server binary'
cp -a "$LLAMA_ROOT"/llama-server "$LLAMA_ROOT"/lib*.so* "$BUNDLE/llama/"
cp "$LLAMA_ROOT/LICENSE" "$BUNDLE/licenses/llama-LICENSE"

# Include non-glibc runtime libraries required by llama.cpp so they do not
# depend on apt-installed openssl or libgomp on the target machine. glibc is
# the one host runtime dependency and is checked by the launcher preflight.
ldd "$BUNDLE/llama/llama-server" >"$WORK/llama.ldd"
if grep -q 'not found' "$WORK/llama.ldd"; then cat "$WORK/llama.ldd" >&2; die 'llama shared-library dependency is missing on the build runner'; fi
while IFS= read -r library; do
  [ -f "$library" ] || continue
  base=$(basename -- "$library")
  case "$base" in
    libc.so.*|libm.so.*|libpthread.so.*|libdl.so.*|librt.so.*|libutil.so.*|ld-linux*.so.*|libgcc_s.so.*|linux-vdso.so.*) continue ;;
  esac
  [ -e "$BUNDLE/llama/$base" ] || cp -L "$library" "$BUNDLE/llama/$base"
done <<EOF
$(awk '/=> \/|^[[:space:]]*\// { for (i=1; i<=NF; i++) if ($i ~ /^\//) { print $i; break } }' "$WORK/llama.ldd")
EOF
if ! LD_LIBRARY_PATH="$BUNDLE/llama" ldd "$BUNDLE/llama/llama-server" | grep -q 'not found'; then :; else die 'llama dependencies remain unresolved after bundling'; fi

tar -xzf "$CACHE/python.tar.gz" -C "$BUNDLE"
[ -x "$BUNDLE/python/bin/python3" ] || [ -x "$BUNDLE/python/bin/python3.12" ] || die 'portable Python archive has an unexpected layout'
python_license=$(find "$BUNDLE/python" -type f \( -iname 'license.txt' -o -iname 'license' \) -print -quit)
[ -n "$python_license" ] || die 'portable Python archive does not contain its license'
cp "$python_license" "$BUNDLE/licenses/python-LICENSE"
go_root_actual=$("$GO_BIN" env GOROOT)
[ -f "$go_root_actual/LICENSE" ] || die 'pinned Go toolchain does not contain its license'
cp "$go_root_actual/LICENSE" "$BUNDLE/licenses/go-LICENSE"

ln "$CACHE/model.gguf" "$BUNDLE/model/$MODEL_FILENAME" 2>/dev/null || cp "$CACHE/model.gguf" "$BUNDLE/model/$MODEL_FILENAME"
cp "$CACHE/opencode.LICENSE" "$BUNDLE/licenses/opencode-LICENSE"
cp "$CACHE/model.LICENSE" "$BUNDLE/licenses/qwen-Apache-2.0-LICENSE"
[ -f "$REPO_ROOT/LICENSE" ] || die 'repository MIT license is missing'
cp "$REPO_ROOT/LICENSE" "$BUNDLE/licenses/disk-cleanup-agent-MIT-LICENSE"
cp "$REPO_ROOT"/cleanup_agent/*.py "$BUNDLE/lib/cleanup_agent/"
cat >"$BUNDLE/ASSET-VERSIONS.txt" <<EOF
Release: guarded cleanup preview; model assessment is advisory; deletion requires explicit config and fresh checks.
Disk Cleanup Agent code license: MIT (disk-cleanup-agent-MIT-LICENSE included).
Architecture: Linux x86_64; glibc >= 2.34; CPU only.
Launcher: Go $GO_VERSION, statically linked (BSD-3-Clause license included).
OpenCode: $OPENCODE_VERSION (opencode-linux-x64, pinned npm integrity SHA-512).
llama.cpp: $LLAMA_VERSION ($LLAMA_COMMIT), upstream Ubuntu x64 CPU asset.
Python: CPython $PYTHON_VERSION+$PYTHON_BUILD, python-build-standalone.
Model: $MODEL_REPOSITORY@$MODEL_REVISION/$MODEL_FILENAME ($MODEL_BYTES bytes).
Model SHA-256: $MODEL_SHA256
Model license: Apache-2.0 (Qwen/Qwen3.5-0.8B).
Offline runtime flags disable OpenCode auto-update, model fetch, and default plugins.
EOF

version=$("$BUNDLE/python/bin/python3" --version 2>&1 || "$BUNDLE/python/bin/python3.12" --version 2>&1)
case "$version" in "Python $PYTHON_VERSION"*) ;; *) die "unexpected bundled Python: $version" ;; esac
"$BUNDLE/bin/opencode" --version | grep -q "^$OPENCODE_VERSION$" || die 'bundled OpenCode version mismatch'
"$BUNDLE/llama/llama-server" --version 2>&1 | grep -q "build 11160, commit 70c4e1582" || die 'bundled llama.cpp revision mismatch'
max_glibc=$(
  for file in "$BUNDLE/bin/opencode" "$BUNDLE/llama/llama-server" "$BUNDLE/llama"/*.so* \
    "$BUNDLE/python/bin/python3" "$BUNDLE/python/bin/python3.12" "$BUNDLE/python/lib"/libpython*.so*; do
    [ -f "$file" ] || continue
    readelf --version-info "$file" 2>/dev/null | grep -o 'GLIBC_[0-9.]*' || true
  done | sort -Vu | tail -n1
)
[ -n "$max_glibc" ] || die 'could not determine the bundled GLIBC symbol floor'
max_number=${max_glibc#GLIBC_}
if [ "$(printf '%s\n' "$max_number" 2.34 | sort -V | tail -n1)" != 2.34 ]; then
  die "bundled runtime requires $max_glibc, newer than the declared GLIBC_2.34 floor"
fi

if [ -d "$REPO_ROOT/tests" ]; then
  PATH="$(dirname -- "$GO_BIN"):$PATH" "$BUNDLE/python/bin/python3" -m unittest discover -s "$REPO_ROOT/tests" -v
fi

# Reuse the just-verified downloads to exercise the documented source install
# without another network fetch. Checksums are still verified by install.sh.
SOURCE_PREFIX="$WORK/source install prefix"
DISKCLEANUP_DOWNLOAD_CACHE="$CACHE" sh "$SCRIPT_DIR/install.sh" --prefix "$SOURCE_PREFIX"
"$SOURCE_PREFIX/bin/disk-cleanup-agent" --help >/dev/null
source_runtime=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}
source_expect_noexec=false
if [ -d /dev/shm ] && [ -w /dev/shm ] && command -v findmnt >/dev/null 2>&1 && \
  findmnt -no OPTIONS -T /dev/shm | tr ',' '\n' | grep -qx noexec; then
  source_runtime=/dev/shm
  source_expect_noexec=true
fi
[ -d "$source_runtime" ] && [ -w "$source_runtime" ] || source_runtime="$WORK/source runtime"
if [ "$source_expect_noexec" != true ] && command -v findmnt >/dev/null 2>&1 && \
  findmnt -no OPTIONS -T "$source_runtime" | tr ',' '\n' | grep -qx noexec; then
  source_expect_noexec=true
fi
mkdir -p "$source_runtime"
source_doctor=$(env -u DISKCLEANUP_BUNDLE_DIR -u DISKCLEANUP_RUNTIME_DIR \
  XDG_RUNTIME_DIR="$source_runtime" "$SOURCE_PREFIX/bin/disk-cleanup-agent" doctor --json) \
  || die 'source-installed doctor smoke test failed'
if [ "$source_expect_noexec" = true ]; then
  python3 -c 'import json,sys; d=json.loads(sys.argv[1]); assert d["model"]["present"]; assert all(x["found"] for x in d["executables"].values()); assert not d["bundled_mode"]; assert d["service_manager_required"] is False; assert d["runtime_dir"]["executable"] is False' "$source_doctor" \
    || die 'source-installed doctor failed on the noexec XDG runtime directory'
else
  python3 -c 'import json,sys; d=json.loads(sys.argv[1]); assert d["model"]["present"]; assert all(x["found"] for x in d["executables"].values()); assert not d["bundled_mode"]; assert d["service_manager_required"] is False' "$source_doctor" \
    || die 'source-installed doctor returned an invalid environment report'
fi

# The cache model and bundle model share a hard link on this filesystem.
# Removing temporary downloads/source install before compression lowers peak
# space while preserving the prepared bundle and pinned Go toolchain.
rm -rf "$CACHE" "$WORK/opencode" "$WORK/llama" "$SOURCE_PREFIX"
PATH="$(dirname -- "$GO_BIN"):$PATH" "$SCRIPT_DIR/make-onefile.sh" --bundle "$BUNDLE" --output "$SCRIPT_OUT"
asset_size=$(wc -c <"$SCRIPT_OUT" | tr -d ' ')
[ "$asset_size" -lt 2147483648 ] || die "final release asset is $asset_size bytes; GitHub's single-asset ceiling is 2 GiB"

# Drop the extracted payload and toolchain before exercising the actual
# self-extracting asset, which needs another temporary extraction.
rm -rf "$BUNDLE" "$GO_ROOT"

# Exercise the actual self-extracting ELF, including its model checksum and CLI
# paths. On a root invocation, drop to nobody; GitHub hosted runners are already
# unprivileged and run this directly. A hard link makes the asset reachable
# outside /root without another copy of the multi-gigabyte archive.
SMOKE_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/dca-rootless-smoke.XXXXXX") || die 'cannot create a rootless smoke directory'
mkdir -p "$SMOKE_ROOT/home" "$SMOKE_ROOT/runtime"
SMOKE_ASSET="$SCRIPT_OUT"
if [ "$(id -u)" -eq 0 ]; then
  command -v runuser >/dev/null 2>&1 || die 'runuser is required for rootless release smoke testing'
  chown -R nobody:nogroup "$SMOKE_ROOT"
  chmod 700 "$SMOKE_ROOT/home" "$SMOKE_ROOT/runtime"
  SMOKE_ASSET="$SMOKE_ROOT/disk-cleanup-agent"
  ln "$SCRIPT_OUT" "$SMOKE_ASSET" || die 'cannot expose the release asset to the unprivileged smoke user'
  onefile_help=$(runuser -u nobody -- env "HOME=$SMOKE_ROOT/home" "TMPDIR=$SMOKE_ROOT/runtime" "DISKCLEANUP_RUNTIME_DIR=$SMOKE_ROOT/runtime" "$SMOKE_ASSET" --help) \
    || die 'rootless one-file --help smoke test failed'
  onefile_doctor=$(runuser -u nobody -- env "HOME=$SMOKE_ROOT/home" "TMPDIR=$SMOKE_ROOT/runtime" "DISKCLEANUP_RUNTIME_DIR=$SMOKE_ROOT/runtime" "$SMOKE_ASSET" doctor --json) \
    || die 'rootless one-file doctor smoke test failed'
else
  onefile_help=$(env "HOME=$SMOKE_ROOT/home" "TMPDIR=$SMOKE_ROOT/runtime" "DISKCLEANUP_RUNTIME_DIR=$SMOKE_ROOT/runtime" "$SMOKE_ASSET" --help) \
    || die 'one-file --help smoke test failed'
  onefile_doctor=$(env "HOME=$SMOKE_ROOT/home" "TMPDIR=$SMOKE_ROOT/runtime" "DISKCLEANUP_RUNTIME_DIR=$SMOKE_ROOT/runtime" "$SMOKE_ASSET" doctor --json) \
    || die 'one-file doctor smoke test failed'
fi
case "$onefile_help" in *"read-only-first disk investigation CLI"*) ;; *) die 'one-file --help output is unexpected' ;; esac
python3 -c 'import json,sys; d=json.loads(sys.argv[1]); assert d["model"]["present"]; assert all(x["found"] for x in d["executables"].values()); assert d["bundled_mode"]; assert d["service_manager_required"] is False; assert d["runtime_dir"]["writable"]' "$onefile_doctor" \
  || die 'one-file doctor returned an invalid bundled environment report'

printf '%s  %s\n' "$(sha256sum "$SCRIPT_OUT" | awk '{print $1}')" "$(basename -- "$SCRIPT_OUT")" >"$SCRIPT_OUT.sha256"
printf 'Release artifact ready: %s (%s bytes)\n' "$SCRIPT_OUT" "$asset_size"
