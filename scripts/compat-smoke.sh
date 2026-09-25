#!/usr/bin/env bash
set -Eeuo pipefail

die() { printf 'compat-smoke: %s\n' "$*" >&2; exit 1; }
usage() {
  die 'usage: scripts/compat-smoke.sh (--context TEST_CONTEXT | --host TEST_UNIX_ENDPOINT) --confirm-daemon-id ID [--dry-run] PATH_TO_RELEASE_ASSET'
}
TARGET_CONTEXT=
TARGET_HOST=
CONFIRM_DAEMON_ID=
DRY_RUN=false
ASSET_ARG=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --context)
      [ "$#" -ge 2 ] || usage
      [ -z "$TARGET_CONTEXT" ] && [ -z "$TARGET_HOST" ] || usage
      TARGET_CONTEXT=$2; shift 2 ;;
    --host)
      [ "$#" -ge 2 ] || usage
      [ -z "$TARGET_CONTEXT" ] && [ -z "$TARGET_HOST" ] || usage
      TARGET_HOST=$2; shift 2 ;;
    --confirm-daemon-id)
      [ "$#" -ge 2 ] || usage
      CONFIRM_DAEMON_ID=$2; shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    --*) usage ;;
    *)
      [ -z "$ASSET_ARG" ] || usage
      ASSET_ARG=$1; shift ;;
  esac
done
[ -n "$ASSET_ARG" ] && [ -n "$CONFIRM_DAEMON_ID" ] || usage
[ -n "$TARGET_CONTEXT" ] || [ -n "$TARGET_HOST" ] || usage
[ -z "$TARGET_CONTEXT" ] || [ -z "$TARGET_HOST" ] || usage
if [ -n "$TARGET_CONTEXT" ]; then
  [ "$TARGET_CONTEXT" != default ] || die 'refusing Docker default context; configure a separate test daemon context'
fi
ASSET=$(cd -- "$(dirname -- "$ASSET_ARG")" && pwd)/$(basename -- "$ASSET_ARG")
[ -x "$ASSET" ] || die "release asset is missing or not executable: $ASSET"
DOCKER_BIN=$(command -v docker) || die 'Docker CLI is required'
command -v timeout >/dev/null || die 'timeout is required'
command -v python3 >/dev/null || die 'python3 is required for evidence validation'
command -v sha256sum >/dev/null || die 'sha256sum is required'
command -v realpath >/dev/null || die 'realpath is required to compare Docker socket aliases safely'

# Bound every Docker CLI call, including metadata reads and trap cleanup.
docker_call() {
  local seconds=$1; shift
  timeout --signal=TERM --kill-after=5s "${seconds}s" "$DOCKER_BIN" "$@"
}
docker_target() {
  local seconds=$1; shift
  if [ -n "$TARGET_CONTEXT" ]; then
    docker_call "$seconds" --context "$TARGET_CONTEXT" "$@"
  else
    docker_call "$seconds" --host "$TARGET_HOST" "$@"
  fi
}
docker() { docker_target 30 "$@"; }
docker_long() {
  local seconds=$1; shift
  docker_target "$seconds" "$@"
}

normalize_endpoint() {
  case "$1" in
    unix://*)
      local path=${1#unix://}
      printf 'unix://%s' "$(realpath -m -- "$path")" ;;
    *) printf '%s' "${1%/}" ;;
  esac
}

# Context metadata and `info` are read-only. Refuse if the requested target is
# the current/default daemon, a configured local socket, or an alias of either.
CURRENT_CONTEXT=$(docker_call 30 context show) || die 'cannot determine current Docker context'
CURRENT_CONTEXT=${CURRENT_CONTEXT//$'\n'/}
[ -n "$CURRENT_CONTEXT" ] || die 'current Docker context is empty'
CURRENT_ENDPOINT=$(docker_call 30 context inspect "$CURRENT_CONTEXT" --format '{{ (index .Endpoints "docker").Host }}') || die 'cannot inspect current Docker endpoint'
DEFAULT_ENDPOINT=$(docker_call 30 context inspect default --format '{{ (index .Endpoints "docker").Host }}') || die 'cannot inspect default Docker endpoint'
if [ -n "$TARGET_CONTEXT" ]; then
  [ "$TARGET_CONTEXT" != "$CURRENT_CONTEXT" ] || die 'refusing the current Docker context; select a separate test context'
  TARGET_ENDPOINT=$(docker_call 30 context inspect "$TARGET_CONTEXT" --format '{{ (index .Endpoints "docker").Host }}') || die "cannot inspect requested Docker context $TARGET_CONTEXT"
else
  TARGET_ENDPOINT=$TARGET_HOST
fi
[ -n "$TARGET_ENDPOINT" ] || die 'requested Docker endpoint is empty'
target_normalized=$(normalize_endpoint "$TARGET_ENDPOINT")
case "$target_normalized" in
  unix://*)
    target_socket=${target_normalized#unix://}
    [ -S "$target_socket" ] || die "test endpoint must be a local Unix socket so Docker storage free space can be checked: $TARGET_ENDPOINT" ;;
  *) die 'remote Docker endpoints are not supported: local free-space checks cannot verify remote Docker storage' ;;
esac
for protected_endpoint in "$CURRENT_ENDPOINT" "$DEFAULT_ENDPOINT" "${DOCKER_HOST:-}" "unix:///var/run/docker.sock" "unix:///run/docker.sock"; do
  [ -n "$protected_endpoint" ] || continue
  if [ "$target_normalized" = "$(normalize_endpoint "$protected_endpoint")" ]; then
    die "refusing Docker endpoint matching the current/default host daemon: $TARGET_ENDPOINT"
  fi
done

target_daemon_id=$(docker_target 30 info --format '{{.ID}}') || die 'cannot read requested test daemon identity'
[ -n "$target_daemon_id" ] || die 'requested Docker daemon returned an empty identity'
[ "$target_daemon_id" = "$CONFIRM_DAEMON_ID" ] || die "test daemon identity mismatch (observed $target_daemon_id)"
for protected_context in "$CURRENT_CONTEXT" default; do
  protected_id=$(docker_call 30 --context "$protected_context" info --format '{{.ID}}') || die "cannot verify protected Docker daemon identity for context $protected_context"
  [ -n "$protected_id" ] || die "empty Docker daemon identity for protected context $protected_context"
  [ "$target_daemon_id" != "$protected_id" ] || die "refusing test context sharing daemon ID with protected context $protected_context"
done
if [ -n "${DOCKER_HOST:-}" ]; then
  protected_id=$(docker_call 30 --host "$DOCKER_HOST" info --format '{{.ID}}') || die 'cannot verify Docker daemon selected by DOCKER_HOST'
  [ -n "$protected_id" ] || die 'empty Docker daemon identity for DOCKER_HOST'
  [ "$target_daemon_id" != "$protected_id" ] || die 'refusing test endpoint sharing daemon ID with DOCKER_HOST'
fi
DOCKER_ROOT=$(docker_target 30 info --format '{{.DockerRootDir}}') || die 'cannot read test Docker data directory'
[ -d "$DOCKER_ROOT" ] || die "test Docker data directory is not visible locally: $DOCKER_ROOT"
MIN_FREE=4294967296
check_space() {
  local path available
  for path in "$DOCKER_ROOT" "$(dirname -- "$ASSET")"; do
    available=$(df -Pk "$path" | awk 'NR==2 { print $4 * 1024 }')
    [ -n "$available" ] || die "cannot determine free space at $path"
    [ "$available" -ge "$MIN_FREE" ] || die "less than 4 GiB free at $path; refusing pull/run"
    if [ "$DRY_RUN" = true ]; then printf 'FREE_SPACE path=%s bytes=%s\n' "$path" "$available"; fi
  done
}
printf 'TEST_DAEMON endpoint=%s id=%s current_context=%s current_endpoint=%s default_endpoint=%s\n' \
  "$TARGET_ENDPOINT" "$target_daemon_id" "$CURRENT_CONTEXT" "$CURRENT_ENDPOINT" "$DEFAULT_ENDPOINT"
if [ "$DRY_RUN" = true ]; then
  check_space
  printf 'TEST_DOCKER_DATA root=%s minimum_free_bytes=%s\n' "$DOCKER_ROOT" "$MIN_FREE"
  printf 'DRY_RUN passed read-only daemon and disk checks; no pull/create/start/remove was issued.\n'
  exit 0
fi

if [ -f "$ASSET.sha256" ]; then
  (cd -- "$(dirname -- "$ASSET")" && sha256sum -c "$(basename -- "$ASSET").sha256")
fi
ASSET_SHA=$(sha256sum "$ASSET" | awk '{print $1}')
ASSET_BYTES=$(stat -c '%s' "$ASSET")

uid=$(id -u)
gid=$(id -g)
if [ "$uid" -eq 0 ]; then uid=65534; gid=65534; fi
WORK=$(mktemp -d "${TMPDIR:-/tmp}/dca-compat.XXXXXX") || die 'cannot create compatibility scratch'
chmod 700 "$WORK"
CONTAINER_ID=
CURRENT_IMAGE=
CURRENT_IMAGE_ID=
CURRENT_IMAGE_PREEXISTED=true
RUN_LABEL="dca-compat-$(date +%s)-$$"
cleanup() {
  status=$?
  if [ -n "$CONTAINER_ID" ]; then
    label=$(docker inspect --format '{{ index .Config.Labels "disk-cleanup-agent.compat-smoke" }}' "$CONTAINER_ID" 2>/dev/null || true)
    if [ "$label" = "$RUN_LABEL" ]; then
      docker rm -f "$CONTAINER_ID" >/dev/null 2>&1 || printf 'compat-smoke: could not remove own container %s\n' "$CONTAINER_ID" >&2
    else
      printf 'compat-smoke: refusing to remove unexpectedly labeled container %s\n' "$CONTAINER_ID" >&2
    fi
  fi
  if [ -n "$CURRENT_IMAGE_ID" ] && [ "$CURRENT_IMAGE_PREEXISTED" = false ]; then
    current_id=$(docker image inspect --format '{{.Id}}' "$CURRENT_IMAGE" 2>/dev/null || true)
    users=$(docker ps -aq --filter "ancestor=$CURRENT_IMAGE_ID" 2>/dev/null || true)
    if [ "$current_id" = "$CURRENT_IMAGE_ID" ] && [ -z "$users" ]; then
    docker image rm "$CURRENT_IMAGE" >/dev/null 2>&1 || printf 'compat-smoke: could not remove newly pulled image %s\n' "$CURRENT_IMAGE" >&2
    else
      printf 'compat-smoke: leaving image %s; it changed or a container uses it\n' "$CURRENT_IMAGE" >&2
    fi
  fi
  if [ -n "$WORK" ] && [ -d "$WORK" ]; then rm -rf -- "$WORK"; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

pull_if_needed() {
  CURRENT_IMAGE=$1
  CURRENT_IMAGE_ID=
  CURRENT_IMAGE_PREEXISTED=false
  if docker image inspect "$CURRENT_IMAGE" >/dev/null 2>&1; then
    CURRENT_IMAGE_PREEXISTED=true
  else
    check_space
    printf 'Pulling official test image %s (free space preflight passed).\n' "$CURRENT_IMAGE"
    docker_long 360 pull "$CURRENT_IMAGE"
  fi
  check_space
  CURRENT_IMAGE_ID=$(docker image inspect --format '{{.Id}}' "$CURRENT_IMAGE") || die "cannot inspect image $CURRENT_IMAGE"
  image_bytes=$(docker image inspect --format '{{.Size}}' "$CURRENT_IMAGE") || die "cannot measure image $CURRENT_IMAGE"
  [ "$image_bytes" -lt 2147483648 ] || die "test image exceeds 2 GiB: $CURRENT_IMAGE ($image_bytes bytes)"
  printf 'IMAGE %s ID=%s IMAGE_BYTES=%s PREEXISTED=%s\n' "$CURRENT_IMAGE" "$CURRENT_IMAGE_ID" "$image_bytes" "$CURRENT_IMAGE_PREEXISTED"
}

start_container() {
  check_space
  local logfile=$1
  local cache=$2
  local started_ns ended_ns elapsed_ns peak_bytes sample
  started_ns=$(date +%s%N)
  set +e
  docker_long 360 start -a "$CONTAINER_ID" 2>&1 | tee "$logfile" &
  local monitor_pid=$!
  peak_bytes=0
  while kill -0 "$monitor_pid" 2>/dev/null; do
    sample=$(du -s -B1 "$cache" 2>/dev/null | awk '{print $1}' || true)
    if [[ "$sample" =~ ^[0-9]+$ ]] && (( sample > peak_bytes )); then peak_bytes=$sample; fi
    sleep 0.1
  done
  wait "$monitor_pid"
  local status=$?
  set -e
  ended_ns=$(date +%s%N)
  elapsed_ns=$((ended_ns - started_ns))
  sample=$(du -s -B1 "$cache" 2>/dev/null | awk '{print $1}' || true)
  if [[ "$sample" =~ ^[0-9]+$ ]] && (( sample > peak_bytes )); then peak_bytes=$sample; fi
  printf 'CONTAINER_EXIT=%s WALL_MS=%s EXTRACTION_PEAK_BYTES=%s\n' "$status" "$((elapsed_ns / 1000000))" "$peak_bytes"
  return "$status"
}

read_only_case() {
  local image=$1 key=$2
  local scratch="$WORK/$key" input="$WORK/$key/input" home="$WORK/$key/home"
  local tmp_options=rw,noexec,nosuid,nodev,size=256m
  if [ "$key" = debian-12 ]; then tmp_options=ro,noexec,nosuid,nodev,size=256m; fi
  mkdir -p "$input" "$home"
  printf 'compatibility control fixture\n' >"$input/control.txt"
  dd if=/dev/zero of="$input/qa-probe.bin" bs=1M count=65 status=none
  if [ "$(id -u)" -eq 0 ]; then chown -R "$uid:$gid" "$scratch"; fi

  local command='set -eux
mkdir -p /scratch/home
chmod 700 /scratch/home
export HOME=/scratch/home XDG_RUNTIME_DIR=/tmp TMPDIR=/tmp
ldd --version > /scratch/libc.txt 2>&1 || true
uname -m > /scratch/arch.txt
printf "%s\n" "$(id -u)" > /scratch/uid.txt
start=$(date +%s%N)
/usr/local/bin/disk-cleanup-agent --help >/scratch/help.txt
end=$(date +%s%N)
printf "%s\n" "$((end - start))" > /scratch/cold-start-ns.txt
start=$(date +%s%N)
/usr/local/bin/disk-cleanup-agent --help >/scratch/warm-help.txt
end=$(date +%s%N)
printf "%s\n" "$((end - start))" > /scratch/warm-start-ns.txt
for root in "$HOME"/.cache/disk-cleanup-agent/bundle-*; do bundle=$root; done
test -x "$bundle/bin/opencode" && test -x "$bundle/llama/llama-server"
"$bundle/bin/opencode" --version >/scratch/opencode-version.txt
"$bundle/llama/llama-server" --version >/scratch/llama-version.txt 2>&1
grep -q '^1\.14\.21$' /scratch/opencode-version.txt
grep -q "build 11160, commit 70c4e1582" /scratch/llama-version.txt
python=
for path in "$HOME"/.cache/disk-cleanup-agent/bundle-*/python/bin/python3 "$HOME"/.cache/disk-cleanup-agent/bundle-*/python/bin/python3.12; do
  if [ -x "$path" ]; then python=$path; break; fi
done
[ -n "$python" ]
export PYTHONHOME="$bundle/python" PYTHONPATH="$bundle/lib" LD_LIBRARY_PATH="$bundle/llama:${LD_LIBRARY_PATH:-}"
export DISKCLEANUP_BUNDLE_DIR="$bundle" DISKCLEANUP_RUNTIME_DIR="$HOME/.cache/disk-cleanup-agent"
export OPENCODE_BIN="$bundle/bin/opencode" LLAMA_SERVER_BIN="$bundle/llama/llama-server"
export CLEANUP_AGENT_MODEL_PATH="$bundle/model/Qwen3.5-0.8B-Q4_K_M.gguf"
run_cli() {
  name=$1
  shift
  "$python" - "$name" "$@" <<"PY"
import pathlib
import resource
import sys
from cleanup_agent.cli import main
name = sys.argv[1]
status = main(sys.argv[2:])
pathlib.Path("/scratch/" + name + "-maxrss-kib.txt").write_text(str(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss))
raise SystemExit(status)
PY
}
run_cli doctor doctor --json > /scratch/doctor.json
run_cli scan scan /scratch/input --output /scratch/scan.json --max-entries 100
run_cli report report /scratch/scan.json > /scratch/report.json
"$python" - /scratch/scan.json /scratch/consent.json <<"PY"
import json
import pathlib
import sys
snapshot = json.loads(pathlib.Path(sys.argv[1]).read_text())
target = "/scratch/input/qa-probe.bin"
items = [item for item in snapshot["scan"]["candidates"] if item.get("path") == target]
assert len(items) == 1
config = {"enabled_categories": [], "category_rules": [], "approved_paths": [{"path": target, "identity": items[0]["identity"], "required_consumer_checks": []}]}
pathlib.Path(sys.argv[2]).write_text(json.dumps(config))
pathlib.Path(sys.argv[2]).chmod(0o600)
PY
run_cli manual-plan manual-plan /scratch/scan.json --config /scratch/consent.json --output /scratch/plan.json
set +e
run_cli bind-apply apply /scratch/plan.json --config /scratch/consent.json --approve-path /scratch/input/qa-probe.bin --output /scratch/apply.json
apply_status=$?
set -e
[ "$apply_status" -eq 2 ]
test -f /scratch/input/qa-probe.bin
test -f /scratch/input/control.txt
du -s -B1 "$HOME/.cache/disk-cleanup-agent" | awk "{print \\$1}" > /scratch/extraction-bytes.txt
test -s /scratch/doctor.json && test -s /scratch/scan.json && test -s /scratch/report.json && test -s /scratch/plan.json && test -s /scratch/apply.json
if [ -r /sys/fs/cgroup/memory.peak ]; then cat /sys/fs/cgroup/memory.peak > /scratch/lightweight-memory-peak-bytes.txt; elif [ -r /sys/fs/cgroup/memory/memory.max_usage_in_bytes ]; then cat /sys/fs/cgroup/memory/memory.max_usage_in_bytes > /scratch/lightweight-memory-peak-bytes.txt; else printf unknown > /scratch/lightweight-memory-peak-bytes.txt; fi'

  local id
  id=$(docker create \
    --label "disk-cleanup-agent.compat-smoke=$RUN_LABEL" \
    --memory=8g --cpus=2 --pids-limit=512 --network=none \
    --user "$uid:$gid" --read-only \
    --cap-drop=ALL --security-opt=no-new-privileges \
    --tmpfs "/tmp:$tmp_options" \
    --mount "type=bind,src=$ASSET,dst=/usr/local/bin/disk-cleanup-agent,readonly" \
    --mount "type=bind,src=$scratch,dst=/scratch" \
    "$image" sh -c "$command") || die "could not create test container for $image"
  CONTAINER_ID=$id

  local config mounts
  config=$(docker inspect --format '{{json .HostConfig}}' "$id") || die 'cannot inspect test container configuration'
  mounts=$(docker inspect --format '{{json .Mounts}}' "$id") || die 'cannot inspect test container mounts'
  python3 - "$config" "$mounts" "$ASSET" "$scratch" <<'PY'
import json
import pathlib
import sys
config, mounts = json.loads(sys.argv[1]), json.loads(sys.argv[2])
assert config["Memory"] == 8 * 1024**3
assert config["NetworkMode"] == "none"
assert config["PidMode"] in ("private", "")
assert config["ReadonlyRootfs"] is True
expected = {
    (str(pathlib.Path(sys.argv[3]).resolve()), "/usr/local/bin/disk-cleanup-agent", True),
    (str(pathlib.Path(sys.argv[4]).resolve()), "/scratch", False),
}
observed = {(item["Source"], item["Destination"], not item["RW"]) for item in mounts}
assert observed == expected, observed
PY

  local logfile="$WORK/$key.log" status
  if start_container "$logfile" "$home/.cache/disk-cleanup-agent"; then status=0; else status=$?; fi
  if [ "$status" -ne 0 ]; then
    tail -80 "$logfile" >&2 || true
    die "supported-environment checks failed in $image (exit $status)"
  fi
  docker inspect --format 'CONTAINER_IMAGE={{.Config.Image}} PID_MODE={{.HostConfig.PidMode}} MEMORY={{.HostConfig.Memory}} READONLY={{.HostConfig.ReadonlyRootfs}} STATE={{.State.Status}}' "$id"
  python3 - "$scratch" "$ASSET_SHA" "$ASSET_BYTES" <<'PY'
import json
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
doctor = json.loads((root / "doctor.json").read_text())
scan = json.loads((root / "scan.json").read_text())
report = json.loads((root / "report.json").read_text())
plan = json.loads((root / "plan.json").read_text())
applied = json.loads((root / "apply.json").read_text())
uid = int((root / "uid.txt").read_text())
assert uid != 0
assert doctor["uid"] == uid
assert doctor["model"]["present"] and doctor["bundled_mode"]
assert doctor["loopback_bind"] == "available"
assert doctor["runtime_dir"]["executable"] is True
assert doctor["memory"]["cgroup"]["limit_bytes"] == 8 * 1024**3
assert scan["scan"]["status"] == "complete"
assert report["deletion_performed"] is False
assert plan["planning_mode"] == "manual_config" and plan["deletion_authorized"] is False
item = next(x for x in plan["items"] if x["path"] == "/scratch/input/qa-probe.bin")
assert "container_mount_process_visibility_unknown" in item["inspection"]["core_unknown"]
assert applied["deleted_count"] == 0
assert applied["results"][0]["status"] == "rejected"
assert applied["results"][0]["evidence"]["identity_matches_scan"] is True
assert "container_mount_process_visibility_unknown" in applied["results"][0]["evidence"]["core_unknown"]
assert (root / "input/qa-probe.bin").is_file()
assert (root / "input/control.txt").is_file()
cold_ns = int((root / "cold-start-ns.txt").read_text())
extraction_bytes = int((root / "extraction-bytes.txt").read_text())
memory_peak_text = (root / "lightweight-memory-peak-bytes.txt").read_text().strip()
memory_peak = int(memory_peak_text) if memory_peak_text.isdigit() else None
assert (root / "opencode-version.txt").read_text().strip() == "1.14.21"
assert "build 11160, commit 70c4e1582" in (root / "llama-version.txt").read_text()
print(json.dumps({"asset_sha256": sys.argv[2], "asset_bytes": int(sys.argv[3]),
                  "architecture": (root / "arch.txt").read_text().strip(),
                  "libc": (root / "libc.txt").read_text().splitlines()[0],
                  "uid": uid, "memory_limit_bytes": doctor["memory"]["cgroup"]["limit_bytes"],
                  "lightweight_memory_peak_bytes": memory_peak,
                  "doctor_maxrss_kib": int((root / "doctor-maxrss-kib.txt").read_text()),
                  "scan_maxrss_kib": int((root / "scan-maxrss-kib.txt").read_text()),
                  "report_maxrss_kib": int((root / "report-maxrss-kib.txt").read_text()),
                  "manual_plan_maxrss_kib": int((root / "manual-plan-maxrss-kib.txt").read_text()),
                  "bind_apply_maxrss_kib": int((root / "bind-apply-maxrss-kib.txt").read_text()),
                  "model_runtime_invoked": False,
                  "cold_help_ms": round(cold_ns / 1e6, 2),
                  "warm_help_ms": round(int((root / "warm-start-ns.txt").read_text()) / 1e6, 2),
                  "extraction_allocated_bytes": extraction_bytes,
                  "scan_status": scan["scan"]["status"], "bind_mount_apply": "rejected_unknown_visibility",
                  "pid_visibility": item["inspection"]["processes"]["process_visibility"]}, sort_keys=True))
PY
  docker rm "$id" >/dev/null || die "could not remove test container $id"
  CONTAINER_ID=
}

unsupported_case() {
  local image=$1 key=$2
  local scratch="$WORK/$key" home="$WORK/$key/home"
  mkdir -p "$home"
  if [ "$(id -u)" -eq 0 ]; then chown -R "$uid:$gid" "$scratch"; fi
  local command='set +e
mkdir -p /scratch/home
export HOME=/scratch/home XDG_RUNTIME_DIR=/tmp TMPDIR=/tmp
export DISKCLEANUP_RUNTIME_DIR=/scratch/home/.cache/disk-cleanup-agent
ldd --version > /scratch/libc.txt 2>&1
/usr/local/bin/disk-cleanup-agent --help > /scratch/help.txt 2> /scratch/app-error.txt
launcher_rc=$?
printf "%s\n" "$launcher_rc" > /scratch/app-exit.txt
for root in "$HOME"/.cache/disk-cleanup-agent/bundle-*; do bundle=$root; done
export LD_LIBRARY_PATH="$bundle/llama"
set +e
"$bundle/llama/llama-server" --version > /scratch/llama-version.txt 2> /scratch/llama-error.txt
llama_rc=$?
set -e
printf "%s\n" "$llama_rc" > /scratch/llama-exit.txt
exit 0'
  local id
  id=$(docker create \
    --label "disk-cleanup-agent.compat-smoke=$RUN_LABEL" \
    --memory=8g --cpus=2 --pids-limit=512 --network=none \
    --user "$uid:$gid" --read-only --cap-drop=ALL --security-opt=no-new-privileges \
    --tmpfs /tmp:ro,noexec,nosuid,nodev,size=256m \
    --mount "type=bind,src=$ASSET,dst=/usr/local/bin/disk-cleanup-agent,readonly" \
    --mount "type=bind,src=$scratch,dst=/scratch" \
    "$image" sh -c "$command") || die "could not create compatibility negative control for $image"
  CONTAINER_ID=$id
  if ! docker_long 120 start -a "$id"; then die "negative-control container setup failed: $image"; fi
  python3 - "$scratch" "$key" <<'PY'
import pathlib
import sys
root, key = pathlib.Path(sys.argv[1]), sys.argv[2]
rc = int((root / "llama-exit.txt").read_text())
stderr = (root / "llama-error.txt").read_text(errors="replace")
launcher_rc = int((root / "app-exit.txt").read_text())
libc = (root / "libc.txt").read_text(errors="replace")
assert rc != 0, f"bundled llama-server unexpectedly ran successfully: {key}"
if key == "ubuntu-20.04":
    assert launcher_rc == 0, f"CLI unexpectedly failed on Ubuntu 20.04: {(root / 'app-error.txt').read_text(errors='replace')}"
    assert "GLIBC_2.34" in stderr or "version `GLIBC_2.34' not found" in stderr, stderr
elif key == "alpine-3.21":
    combined = stderr + (root / "app-error.txt").read_text(errors="replace")
    assert launcher_rc != 0, "glibc-linked Python CLI unexpectedly ran on musl"
    assert "No such file or directory" in combined or "not found" in combined or "Error loading shared library" in combined, combined
print(f"NEGATIVE {key}: launcher_exit={launcher_rc}; llama_exit={rc}; libc={libc.splitlines()[0] if libc.splitlines() else 'unknown'}; {stderr.strip()}")
PY
  docker rm "$id" >/dev/null || die "could not remove test container $id"
  CONTAINER_ID=
}

for image in ${COMPAT_IMAGES:-ubuntu:22.04 debian:12-slim ubuntu:20.04 alpine:3.21}; do
  case "$image" in
    ubuntu:22.04) key=ubuntu-22.04; supported=true ;;
    debian:12-slim) key=debian-12; supported=true ;;
    ubuntu:20.04) key=ubuntu-20.04; supported=false ;;
    alpine:3.21) key=alpine-3.21; supported=false ;;
    *) die "unknown compatibility image $image; edit the explicit tested matrix first" ;;
  esac
  pull_if_needed "$image"
  if [ "$supported" = true ]; then
    read_only_case "$image" "$key"
  else
    unsupported_case "$image" "$key"
  fi
  if [ "$CURRENT_IMAGE_PREEXISTED" = false ]; then
    users=$(docker ps -aq --filter "ancestor=$CURRENT_IMAGE_ID" 2>/dev/null || true)
    if [ -z "$users" ] && [ "$(docker image inspect --format '{{.Id}}' "$CURRENT_IMAGE" 2>/dev/null || true)" = "$CURRENT_IMAGE_ID" ]; then
      docker image rm "$CURRENT_IMAGE" >/dev/null || die "could not remove newly pulled image $CURRENT_IMAGE"
      printf 'Removed only newly pulled unused image %s (%s).\n' "$CURRENT_IMAGE" "$CURRENT_IMAGE_ID"
    else
      printf 'Leaving newly pulled image %s because it changed or a container uses it.\n' "$CURRENT_IMAGE"
    fi
  fi
  CURRENT_IMAGE_ID=
done

pull_if_needed ubuntu:22.04
rootfs_command='set -eux
export HOME=/tmp/dca-rootfs-home
fixture=/var/tmp/dca-rootfs-fixture
candidate="$fixture/qa-probe.bin"
mkdir -p "$HOME" "$fixture"
dd if=/dev/zero of="$candidate" bs=1M count=65 status=none
printf "keep\n" >"$fixture/control.txt"
/usr/local/bin/disk-cleanup-agent doctor --json >"$fixture/doctor.json"
/usr/local/bin/disk-cleanup-agent scan "$fixture" --output "$fixture/scan.json" --max-entries 100
python=
for path in "$HOME"/.cache/disk-cleanup-agent/bundle-*/python/bin/python3 "$HOME"/.cache/disk-cleanup-agent/bundle-*/python/bin/python3.12; do
  if [ -x "$path" ]; then python=$path; break; fi
done
[ -n "$python" ]
bundle=${python%/python/bin/python3}
export PYTHONHOME="$bundle/python" PYTHONPATH="$bundle/lib" LD_LIBRARY_PATH="$bundle/llama"
export DISKCLEANUP_BUNDLE_DIR="$bundle" DISKCLEANUP_RUNTIME_DIR="$HOME/.cache/disk-cleanup-agent"
export OPENCODE_BIN="$bundle/bin/opencode" LLAMA_SERVER_BIN="$bundle/llama/llama-server"
export CLEANUP_AGENT_MODEL_PATH="$bundle/model/Qwen3.5-0.8B-Q4_K_M.gguf"
"$python" - "$fixture/scan.json" "$fixture/consent.json" <<"PY"
import json
import pathlib
import sys
snapshot = json.loads(pathlib.Path(sys.argv[1]).read_text())
target = str(pathlib.Path(sys.argv[1]).parent / ("qa-probe" + ".bin"))
item = next(x for x in snapshot["scan"]["candidates"] if x["path"] == target)
pathlib.Path(sys.argv[2]).write_text(json.dumps({"enabled_categories": [], "category_rules": [], "approved_paths": [{"path": target, "identity": item["identity"], "required_consumer_checks": []}]}))
PY
/usr/local/bin/disk-cleanup-agent manual-plan "$fixture/scan.json" --config "$fixture/consent.json" --output "$fixture/plan.json"
set +e
"$python" - "$fixture/plan.json" "$fixture/consent.json" "$fixture/apply.json" <<"PY"
import json
import pathlib
import sys
from cleanup_agent.cli import main
plan_path, config_path, output_path = sys.argv[1:]
plan = json.loads(pathlib.Path(plan_path).read_text())
candidate = plan["items"][0]["path"]
raise SystemExit(main(["apply", plan_path, "--config", config_path, "--approve-path", candidate, "--output", output_path]))
PY
apply_status=$?
set -e
"$python" - "$apply_status" <<"PY"
import json
import pathlib
import sys
fixture = pathlib.Path("/var/tmp/dca-rootfs-fixture")
data = json.loads((fixture / "apply.json").read_text())
candidate = fixture / ("qa-probe" + ".bin")
assert (fixture / "control.txt").is_file()
print("ROOTFS_APPLY_STATUS", sys.argv[1], json.dumps(data, sort_keys=True))
if data["deleted_count"] == 1:
    assert sys.argv[1] == "0" and data["results"][0]["status"] == "deleted"
    assert data["results"][0]["path"] == str(candidate)
    assert not candidate.exists()
elif data["deleted_count"] == 0:
    assert sys.argv[1] == "2" and data["results"][0]["status"] == "rejected"
    assert candidate.is_file()
else:
    raise AssertionError("unexpected container-rootfs apply count")
PY'
id=$(docker create \
  --label "disk-cleanup-agent.compat-smoke=$RUN_LABEL" \
  --memory=8g --cpus=2 --pids-limit=512 --network=none \
  --user "$uid:$gid" --cap-drop=ALL --security-opt=no-new-privileges \
  --mount "type=bind,src=$ASSET,dst=/usr/local/bin/disk-cleanup-agent,readonly" \
  "$CURRENT_IMAGE" sh -c "$rootfs_command") || die 'could not create rootfs-only fixture container'
CONTAINER_ID=$id
if ! docker_long 300 start -a "$id"; then die 'exactly approved container-rootfs fixture apply failed'; fi
docker inspect --size --format 'ROOTFS_RW_BYTES={{.SizeRw}} ROOTFS_PID_MODE={{.HostConfig.PidMode}} ROOTFS_MEMORY={{.HostConfig.Memory}} NETWORK={{.HostConfig.NetworkMode}}' "$id"
docker rm "$id" >/dev/null || die "could not remove rootfs fixture container $id"
CONTAINER_ID=
if [ "$CURRENT_IMAGE_PREEXISTED" = false ]; then
  users=$(docker ps -aq --filter "ancestor=$CURRENT_IMAGE_ID" 2>/dev/null || true)
  if [ -z "$users" ] && [ "$(docker image inspect --format '{{.Id}}' "$CURRENT_IMAGE" 2>/dev/null || true)" = "$CURRENT_IMAGE_ID" ]; then
    docker image rm "$CURRENT_IMAGE" >/dev/null || die 'could not remove newly pulled Ubuntu test image'
    printf 'Removed only newly pulled unused image ubuntu:22.04 (%s).\n' "$CURRENT_IMAGE_ID"
  fi
fi
CURRENT_IMAGE_ID=
printf 'COMPAT_DONE asset=%s sha256=%s bytes=%s; no external network, no production mount, no host apply.\n' "$(basename -- "$ASSET")" "$ASSET_SHA" "$ASSET_BYTES"
