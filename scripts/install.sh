#!/bin/sh
set -eu

die() { printf 'disk-cleanup-agent installer: %s\n' "$*" >&2; exit 1; }

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
# shellcheck disable=SC1091
. "$SCRIPT_DIR/asset-pins.sh"

if [ -n "${DISKCLEANUP_PREFIX:-}" ]; then
  PREFIX=$DISKCLEANUP_PREFIX
elif [ -n "${HOME:-}" ]; then
  PREFIX=$HOME/.local/share/disk-cleanup-agent
else
  PREFIX=
fi
while [ "$#" -gt 0 ]; do
  case "$1" in
    --prefix)
      [ "$#" -ge 2 ] || die '--prefix needs a directory'
      PREFIX=$2
      shift 2
      ;;
    --help|-h)
      cat <<'EOF'
Usage: sh scripts/install.sh [--prefix DIR]

Installs this source checkout, OpenCode, llama.cpp and the pinned local model
under a user-writable prefix. It uses system python3 and does not use pip, root,
PM2, or systemd. Set DISKCLEANUP_PREFIX instead of passing --prefix.
EOF
      exit 0
      ;;
    *) die "unknown option: $1" ;;
  esac
done
[ -n "$PREFIX" ] || die 'set HOME or DISKCLEANUP_PREFIX'
case "$PREFIX" in
  /*) ;;
  *) PREFIX=$(pwd)/$PREFIX ;;
esac

command -v curl >/dev/null 2>&1 || die 'curl is required for installation'
command -v tar >/dev/null 2>&1 || die 'tar is required for installation'
command -v sha256sum >/dev/null 2>&1 || die 'sha256sum is required for installation'
command -v openssl >/dev/null 2>&1 || die 'openssl is required to verify the pinned OpenCode package'
command -v ldd >/dev/null 2>&1 || die 'ldd is required to inspect the pinned llama runtime dependencies'
command -v awk >/dev/null 2>&1 || die 'awk is required to inspect llama runtime dependencies'
command -v python3 >/dev/null 2>&1 || die 'python3 is required for source installation'
python3 -c 'import sys; assert sys.version_info >= (3,10)' 2>/dev/null || die 'Python 3.10 or newer is required'

mkdir -p "$PREFIX/versions" "$PREFIX/bin"
chmod 700 "$PREFIX" "$PREFIX/versions"

SOURCE_HASH=$(
  cd "$REPO_ROOT"
  find cleanup_agent -type f -name '*.py' -print | LC_ALL=C sort | while IFS= read -r f; do sha256sum "$f"; done
  sha256sum "$SCRIPT_DIR/asset-pins.sh" "$SCRIPT_DIR/install.sh"
) || die 'could not fingerprint the source tree'
INSTALL_ID=$(printf '%s\n' "$SOURCE_HASH" | sha256sum | cut -c1-16)
VERSION_ID="source-$INSTALL_ID"
FINAL="$PREFIX/versions/$VERSION_ID"

install_wrapper() {
  wrapper_tmp="$PREFIX/bin/.disk-cleanup-agent.$$"
  cat >"$wrapper_tmp" <<'EOF'
#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ASSETS="$ROOT/current"
export OPENCODE_BIN="$ASSETS/opencode/bin/opencode"
export LLAMA_SERVER_BIN="$ASSETS/llama/llama-server"
export CLEANUP_AGENT_MODEL_PATH="$ASSETS/model/Qwen3.5-0.8B-Q4_K_M.gguf"
export LD_LIBRARY_PATH="$ASSETS/llama${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export PYTHONPATH="$ASSETS/app${PYTHONPATH:+:$PYTHONPATH}"
exec python3 -m cleanup_agent.cli "$@"
EOF
  chmod 755 "$wrapper_tmp"
  mv -f "$wrapper_tmp" "$PREFIX/bin/disk-cleanup-agent"
}

if [ -f "$FINAL/.install-complete" ]; then
  ln -sfn "versions/$VERSION_ID" "$PREFIX/.current.$$"
  mv -Tf "$PREFIX/.current.$$" "$PREFIX/current"
  install_wrapper
  printf 'Installed disk-cleanup-agent at %s\n' "$PREFIX/bin/disk-cleanup-agent"
  exit 0
fi
[ ! -e "$FINAL" ] || die "incomplete install exists at $FINAL; preserve it and choose a new prefix or remove it manually"

STAGE=$(mktemp -d "$PREFIX/versions/.stage.XXXXXX") || die 'cannot create staging directory'
cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT HUP INT TERM
mkdir -p "$STAGE/app/cleanup_agent" "$STAGE/opencode/bin" "$STAGE/llama" "$STAGE/model" "$STAGE/licenses"
cp "$REPO_ROOT"/cleanup_agent/*.py "$STAGE/app/cleanup_agent/"

check_space() {
  # The model is downloaded directly into the staging tree; leave room for
  # metadata and the other small pinned assets.
  available=$(df -Pk "$PREFIX" | awk 'NR==2 { print $4 * 1024 }')
  [ -n "$available" ] || die 'could not determine free space on the install filesystem'
  required=$((MODEL_BYTES + 536870912))
  [ "$available" -ge "$required" ] || die "need at least $((required / 1048576)) MiB free; found $((available / 1048576)) MiB"
}
check_space

DOWNLOAD="$STAGE/.downloads"
mkdir -p "$DOWNLOAD"
fetch() {
  cache_name=$1 url=$2 output=$3
  if [ -n "${DISKCLEANUP_DOWNLOAD_CACHE:-}" ] && [ -f "$DISKCLEANUP_DOWNLOAD_CACHE/$cache_name" ]; then
    cp "$DISKCLEANUP_DOWNLOAD_CACHE/$cache_name" "$output"
  else
    curl --fail --location --silent --show-error --retry 2 --connect-timeout 20 --max-time 1800 "$url" -o "$output" \
      || die "download failed: $url"
  fi
}
verify_sha256() {
  expected=$1 file=$2 actual=$(sha256sum "$file" | awk '{ print $1 }')
  [ "$actual" = "$expected" ] || die "SHA-256 mismatch for $(basename "$file")"
}
verify_sha512() {
  expected=$1 file=$2
  actual=$(openssl dgst -sha512 -binary "$file" | openssl base64 -A) || die 'OpenSSL is required to verify OpenCode'
  [ "$actual" = "$expected" ] || die "SHA-512 mismatch for $(basename "$file")"
}

fetch opencode.tgz "$OPENCODE_URL" "$DOWNLOAD/opencode.tgz"
verify_sha512 "$OPENCODE_SHA512" "$DOWNLOAD/opencode.tgz"
mkdir -p "$DOWNLOAD/opencode"
tar -xzf "$DOWNLOAD/opencode.tgz" -C "$DOWNLOAD/opencode"
cp "$DOWNLOAD/opencode/package/bin/opencode" "$STAGE/opencode/bin/opencode"
chmod 755 "$STAGE/opencode/bin/opencode"

fetch llama.tar.gz "$LLAMA_URL" "$DOWNLOAD/llama.tar.gz"
verify_sha256 "$LLAMA_SHA256" "$DOWNLOAD/llama.tar.gz"
mkdir -p "$DOWNLOAD/llama"
tar -xzf "$DOWNLOAD/llama.tar.gz" -C "$DOWNLOAD/llama"
LLAMA_ROOT="$DOWNLOAD/llama/llama-$LLAMA_VERSION"
[ -x "$LLAMA_ROOT/llama-server" ] || die 'pinned llama archive has no llama-server'
cp -a "$LLAMA_ROOT"/llama-server "$LLAMA_ROOT"/lib*.so* "$STAGE/llama/"
cp "$LLAMA_ROOT/LICENSE" "$STAGE/licenses/llama-LICENSE"
ldd "$STAGE/llama/llama-server" >"$DOWNLOAD/llama.ldd" 2>&1 || die 'llama.cpp cannot start on this host; it requires glibc 2.34 and OpenSSL 3'
if grep -q 'not found' "$DOWNLOAD/llama.ldd"; then cat "$DOWNLOAD/llama.ldd" >&2; die 'llama.cpp is missing a host shared library'; fi
while IFS= read -r library; do
  [ -f "$library" ] || continue
  base=$(basename -- "$library")
  case "$base" in
    libc.so.*|libm.so.*|libpthread.so.*|libdl.so.*|librt.so.*|libutil.so.*|ld-linux*.so.*|libgcc_s.so.*|linux-vdso.so.*) continue ;;
  esac
  [ -e "$STAGE/llama/$base" ] || cp -L "$library" "$STAGE/llama/$base"
done <<EOF
$(awk '/=> \/|^[[:space:]]*\// { for (i=1; i<=NF; i++) if ($i ~ /^\//) { print $i; break } }' "$DOWNLOAD/llama.ldd")
EOF

fetch model.gguf "$MODEL_URL" "$STAGE/model/$MODEL_FILENAME"
verify_sha256 "$MODEL_SHA256" "$STAGE/model/$MODEL_FILENAME"
[ "$(wc -c <"$STAGE/model/$MODEL_FILENAME" | tr -d ' ')" = "$MODEL_BYTES" ] || die 'GGUF model has an unexpected file size'

fetch opencode.LICENSE "$OPENCODE_LICENSE_URL" "$STAGE/licenses/opencode-LICENSE"
verify_sha256 "$OPENCODE_LICENSE_SHA256" "$STAGE/licenses/opencode-LICENSE"
fetch model.LICENSE "$MODEL_LICENSE_URL" "$STAGE/licenses/qwen-Apache-2.0-LICENSE"
verify_sha256 "$MODEL_LICENSE_SHA256" "$STAGE/licenses/qwen-Apache-2.0-LICENSE"

rm -rf "$DOWNLOAD"
cat >"$STAGE/ASSET-VERSIONS.txt" <<EOF
OpenCode: $OPENCODE_VERSION (npm opencode-linux-x64)
llama.cpp: $LLAMA_VERSION ($LLAMA_COMMIT), CPU x86_64
Python host requirement: 3.10+
Model: $MODEL_REPOSITORY@$MODEL_REVISION/$MODEL_FILENAME
Model SHA-256: $MODEL_SHA256
Model license: Apache-2.0 (Qwen/Qwen3.5-0.8B)
EOF
printf '%s\n' "$INSTALL_ID" >"$STAGE/.install-complete"
chmod -R go-rwx "$STAGE"
mv "$STAGE" "$FINAL"
trap - EXIT HUP INT TERM

ln -sfn "versions/$VERSION_ID" "$PREFIX/.current.$$"
mv -Tf "$PREFIX/.current.$$" "$PREFIX/current"
install_wrapper
printf 'Installed disk-cleanup-agent at %s\n' "$PREFIX/bin/disk-cleanup-agent"
printf 'Add %s/bin to PATH to run it.\n' "$PREFIX"
