#!/bin/sh
set -eu

die() { printf 'make-onefile: %s\n' "$*" >&2; exit 1; }
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
BUNDLE=
OUTPUT=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --bundle) [ "$#" -ge 2 ] || die '--bundle needs a directory'; BUNDLE=$2; shift 2 ;;
    --output) [ "$#" -ge 2 ] || die '--output needs a file'; OUTPUT=$2; shift 2 ;;
    --help|-h) printf 'Usage: scripts/make-onefile.sh --bundle DIR --output FILE\n'; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done
[ -n "$BUNDLE" ] && [ -d "$BUNDLE" ] || die '--bundle must name an existing directory'
[ -n "$OUTPUT" ] || die '--output is required'
command -v go >/dev/null 2>&1 || die 'Go is required to build the static ELF launcher'
command -v tar >/dev/null 2>&1 || die 'tar is required to assemble the release bundle'
command -v gzip >/dev/null 2>&1 || die 'gzip is required to assemble the release bundle'
command -v python3 >/dev/null 2>&1 || die 'python3 is required to append the bundle footer'

case "$(go env GOOS)/$(go env GOARCH)" in
  linux/amd64) ;;
  *) die 'release launcher must be built on Linux amd64' ;;
esac
[ -x "$BUNDLE/python/bin/python3" ] || [ -x "$BUNDLE/python/bin/python3.12" ] || die 'bundle must include a Python runtime under python/bin/'
[ -x "$BUNDLE/bin/opencode" ] || die 'bundle must include bin/opencode'
[ -x "$BUNDLE/llama/llama-server" ] || die 'bundle must include llama/llama-server'
[ -f "$BUNDLE/model/Qwen3.5-0.8B-Q4_K_M.gguf" ] || die 'bundle must include the pinned Qwen GGUF under model/'

OUTPUT_DIR=$(dirname -- "$OUTPUT")
mkdir -p "$OUTPUT_DIR"
OUTPUT=$(CDPATH= cd -- "$OUTPUT_DIR" && pwd)/$(basename -- "$OUTPUT")
WORK=$(mktemp -d "${TMPDIR:-/tmp}/disk-cleanup-package.XXXXXX") || die 'cannot create temporary build directory'
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT HUP INT TERM

model_hash=$(sha256sum "$BUNDLE/model/Qwen3.5-0.8B-Q4_K_M.gguf" | awk '{print $1}')
opencode_hash=$(sha256sum "$BUNDLE/bin/opencode" | awk '{print $1}')
llama_hash=$(sha256sum "$BUNDLE/llama/llama-server" | awk '{print $1}')
python_bin="$BUNDLE/python/bin/python3"
[ -x "$python_bin" ] || python_bin="$BUNDLE/python/bin/python3.12"
python_hash=$(sha256sum "$python_bin" | awk '{print $1}')
linker_flags="-s -w -X main.embeddedModelSHA256=$model_hash -X main.embeddedOpenCodeSHA256=$opencode_hash -X main.embeddedLlamaSHA256=$llama_hash -X main.embeddedPythonSHA256=$python_hash"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags="$linker_flags" -o "$WORK/launcher" "$REPO_ROOT/packaging/launcher/main.go"
# Stream the deterministic archive directly into the temporary executable.
# This avoids a second multi-gigabyte copy of the compressed model on disk.
python3 - "$WORK/launcher" "$BUNDLE" "$OUTPUT" <<'PY'
import hashlib
import os
import pathlib
import shutil
import struct
import subprocess
import sys

launcher = pathlib.Path(sys.argv[1])
bundle = pathlib.Path(sys.argv[2])
output = pathlib.Path(sys.argv[3])
limit = 2 * 1024 * 1024 * 1024
temporary = output.with_name(output.name + f".tmp.{os.getpid()}")
digest = hashlib.sha256()
archive_size = 0
process = None
command = [
    "tar", "--sort=name", "--mtime=UTC 2020-01-01", "--owner=0", "--group=0",
    "--numeric-owner", "-czf", "-", "-C", str(bundle),
    "bin", "lib", "llama", "model", "python", "licenses", "ASSET-VERSIONS.txt",
]
try:
    with temporary.open("wb") as dst, launcher.open("rb") as src:
        shutil.copyfileobj(src, dst, 1024 * 1024)
        process = subprocess.Popen(command, stdout=subprocess.PIPE)
        assert process.stdout is not None
        while block := process.stdout.read(1024 * 1024):
            archive_size += len(block)
            if archive_size >= limit:
                process.kill()
                raise SystemExit(f"compressed bundle exceeds the 2 GiB limit ({archive_size} bytes)")
            digest.update(block)
            dst.write(block)
        status = process.wait()
        if status != 0:
            raise SystemExit(f"tar failed while creating the release bundle (exit {status})")
        dst.write(b"DCAEND01")
        dst.write(struct.pack(">Q", archive_size))
        dst.write(digest.digest())
        dst.flush()
        os.fsync(dst.fileno())
    temporary.chmod(0o755)
    asset_size = temporary.stat().st_size
    if asset_size >= limit:
        raise SystemExit(f"final release asset is {asset_size} bytes; limit is 2 GiB")
    temporary.replace(output)
    print(f"bundle archive: {archive_size} bytes")
    print(f"one-file asset: {asset_size} bytes")
except BaseException:
    if process is not None:
        if process.poll() is None:
            process.kill()
        process.wait()
    temporary.unlink(missing_ok=True)
    raise
PY
sha256sum "$OUTPUT" >"$OUTPUT.sha256"
printf 'Created %s\n' "$OUTPUT"
