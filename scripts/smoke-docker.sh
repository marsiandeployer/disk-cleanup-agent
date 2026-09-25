#!/bin/sh
set -eu

die() { printf 'docker smoke: %s\n' "$*" >&2; exit 1; }
[ "$#" -eq 1 ] || die 'usage: scripts/smoke-docker.sh PATH_TO_ONEFILE'
ASSET=$(CDPATH= cd -- "$(dirname -- "$1")" && pwd)/$(basename -- "$1")
[ -x "$ASSET" ] || die "one-file executable is missing or not executable: $ASSET"
command -v docker >/dev/null 2>&1 || die 'Docker CLI is required for container acceptance'
command -v timeout >/dev/null 2>&1 || die 'timeout is required for bounded container acceptance'
command -v python3 >/dev/null 2>&1 || die 'python3 is required to validate container reports'
command -v df >/dev/null 2>&1 || die 'df is required for disk-space preflight'

IMAGE=${DISKCLEANUP_DOCKER_IMAGE:-ubuntu:22.04}
DOCKER_ROOT=$(docker info --format '{{.DockerRootDir}}') || die 'cannot read Docker data directory'
check_space() {
  for path in "$DOCKER_ROOT" "$(dirname -- "$ASSET")"; do
    available=$(df -Pk "$path" | awk 'NR==2 { print $4 * 1024 }')
    [ -n "$available" ] || die "cannot determine free space at $path"
    [ "$available" -ge 4294967296 ] || die "refusing Docker pull/run: less than 4 GiB free at $path"
  done
}
check_space

image_preexisting=false
if docker image inspect "$IMAGE" >/dev/null 2>&1; then
  image_preexisting=true
fi
image_id=
container_id=
scratch=
cleanup() {
  status=$?
  if [ -n "$container_id" ]; then
    label=$(docker inspect --format '{{ index .Config.Labels "disk-cleanup-agent.packaging-smoke" }}' "$container_id" 2>/dev/null || true)
    if [ "$label" = "$run_label" ]; then
      docker rm -f "$container_id" >/dev/null 2>&1 || printf 'docker smoke: could not remove own container %s\n' "$container_id" >&2
    else
      printf 'docker smoke: refusing to remove container with unexpected label: %s\n' "$container_id" >&2
    fi
  fi
  if [ "$image_preexisting" = false ] && [ -n "$image_id" ]; then
    users=$(docker ps -aq --filter "ancestor=$image_id" 2>/dev/null || true)
    if [ -z "$users" ]; then
      docker image rm "$IMAGE" >/dev/null 2>&1 || printf 'docker smoke: leaving image %s because Docker reports it in use\n' "$IMAGE" >&2
    else
      printf 'docker smoke: leaving image %s; containers use image %s\n' "$IMAGE" "$image_id" >&2
    fi
  fi
  [ -z "$scratch" ] || rm -rf "$scratch"
  exit "$status"
}
run_label="dca-smoke-$(date +%s)-$$"
trap cleanup EXIT HUP INT TERM

if [ "$image_preexisting" = false ]; then
  printf 'Docker image %s is not present; pulling the official Ubuntu 22.04 image for a disposable compatibility check.\n' "$IMAGE"
  docker pull "$IMAGE"
fi
check_space
image_id=$(docker image inspect --format '{{.Id}}' "$IMAGE") || die "cannot inspect pulled image $IMAGE"
image_bytes=$(docker image inspect --format '{{.Size}}' "$IMAGE") || die 'cannot inspect pulled image size'
[ "$image_bytes" -lt 2147483648 ] || die "refusing image larger than 2 GiB ($image_bytes bytes)"
printf 'Docker smoke image: %s (%s, %s bytes)\n' "$IMAGE" "$image_id" "$image_bytes"

uid=$(id -u)
gid=$(id -g)
if [ "$uid" -eq 0 ]; then uid=65534; gid=65534; fi
scratch=$(mktemp -d "${TMPDIR:-/tmp}/dca-docker-smoke.XXXXXX") || die 'cannot create disposable Docker scratch directory'
mkdir -p "$scratch/input"
printf 'temporary Docker scan fixture\n' >"$scratch/input/probe.txt"
chmod 700 "$scratch" "$scratch/input"
if [ "$(id -u)" -eq 0 ]; then chown -R "$uid:$gid" "$scratch"; fi

container_command='set -eu
mkdir -p /scratch/home
runtime=/tmp/disk-cleanup-agent-smoke-runtime
mkdir -p "$runtime"
export DISKCLEANUP_RUNTIME_DIR="$runtime"
/usr/local/bin/disk-cleanup-agent doctor --json >/scratch/doctor.json
dd if=/dev/zero of=/scratch/input/qa-probe.bin bs=1M count=65 status=none
/usr/local/bin/disk-cleanup-agent scan /scratch/input --output /scratch/scan.json --max-entries 100
/usr/local/bin/disk-cleanup-agent report /scratch/scan.json >/scratch/report.txt
set +e
/usr/local/bin/disk-cleanup-agent scan /host-root --output /scratch/host-scan.json --max-entries 100
host_scan_status=$?
set -e
case "$host_scan_status" in 0|2) ;; *) exit "$host_scan_status" ;; esac
printf "%s\n" "$host_scan_status" >/scratch/host-scan-status.txt
python=
for candidate in "$runtime"/bundle-*/python/bin/python3 "$runtime"/bundle-*/python/bin/python3.12; do
  if [ -x "$candidate" ]; then python=$candidate; break; fi
done
[ -n "$python" ]
"$python" - /scratch/scan.json /scratch/consent.json <<'PY'
import json
import pathlib
import sys

snapshot = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
target = "/scratch/input/qa-probe.bin"
matches = [item for item in snapshot["scan"]["candidates"] if item.get("path") == target]
assert len(matches) == 1 and matches[0]["kind"] == "file"
consent = {
    "enabled_categories": [],
    "category_rules": [],
    "approved_paths": [{
        "path": target,
        "identity": matches[0]["identity"],
        "required_consumer_checks": [],
    }],
}
path = pathlib.Path(sys.argv[2])
path.write_text(json.dumps(consent), encoding="utf-8")
path.chmod(0o600)
PY
/usr/local/bin/disk-cleanup-agent manual-plan /scratch/scan.json --config /scratch/consent.json --output /scratch/plan.json
test -s /scratch/doctor.json
test -s /scratch/scan.json
test -s /scratch/report.txt
test -s /scratch/host-scan.json
test -s /scratch/plan.json
test -f /scratch/input/qa-probe.bin
test -f /scratch/input/probe.txt'
container_id=$(docker create \
  --label "disk-cleanup-agent.packaging-smoke=$run_label" \
  --memory="${DISKCLEANUP_DOCKER_MEMORY_LIMIT:-8g}" \
  --cpus=2 \
  --network=none \
  --user "$uid:$gid" \
  --mount "type=bind,src=$ASSET,dst=/usr/local/bin/disk-cleanup-agent,readonly" \
  --mount "type=bind,src=$scratch,dst=/scratch" \
  --mount "type=bind,src=/,dst=/host-root,readonly" \
  --env HOME=/scratch/home \
  "$IMAGE" sh -c "$container_command") || die 'could not create the disposable Docker acceptance container'
mounts=$(docker inspect --format '{{json .Mounts}}' "$container_id") || die 'cannot inspect acceptance container mounts'
python3 - "$mounts" "$ASSET" "$scratch" <<'PY'
import json
import pathlib
import sys

mounts = json.loads(sys.argv[1])
expected = {
    (str(pathlib.Path(sys.argv[2]).resolve()), "/usr/local/bin/disk-cleanup-agent", True),
    (str(pathlib.Path(sys.argv[3]).resolve()), "/scratch", False),
    (str(pathlib.Path("/").resolve()), "/host-root", True),
}
observed = {(item["Source"], item["Destination"], not item["RW"]) for item in mounts}
assert observed == expected, f"unexpected container visibility mounts: {observed!r}"
PY

timeout 240s docker start -a "$container_id" || die 'Docker doctor/scan/report/manual-plan smoke failed or timed out'
status=$(docker inspect --format '{{.State.Status}}' "$container_id") || die 'cannot inspect acceptance container status'
[ "$status" = exited ] || die "acceptance container ended in unexpected state: $status"
[ -f "$scratch/input/qa-probe.bin" ] || die 'scan or manual-plan changed the disposable QA file'
[ -f "$scratch/input/probe.txt" ] || die 'scan or manual-plan changed the control fixture'
python3 - "$scratch/doctor.json" "$scratch/scan.json" "$scratch/report.txt" \
  "$scratch/plan.json" "$scratch/host-scan.json" "$scratch/host-scan-status.txt" <<'PY'
import json
import pathlib
import sys

doctor = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
scan = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
report = json.loads(pathlib.Path(sys.argv[3]).read_text(encoding="utf-8"))
plan = json.loads(pathlib.Path(sys.argv[4]).read_text(encoding="utf-8"))
host_scan = json.loads(pathlib.Path(sys.argv[5]).read_text(encoding="utf-8"))
host_scan_status = int(pathlib.Path(sys.argv[6]).read_text(encoding="ascii"))
backup_note = "Перед началом очистки сделайте резервную копию через панель управления хостингом. Утилита не создаёт и не проверяет её."
assert doctor["bundled_mode"] is True
assert doctor["model"]["present"] is True
assert doctor["service_manager_required"] is False
assert doctor["runtime_dir"]["writable"] is True
assert doctor["loopback_bind"] == "available"
assert scan["scan"]["root"] == "/scratch/input"
assert scan["scan"]["status"] == "complete"
assert scan["scan"]["totals"]["files"] == 2
assert scan["scan"]["storage"]["docker"]["status"] == "unknown"
assert report["root"] == "/scratch/input"
assert report["deletion_performed"] is False
assert report["storage"]["docker"] == scan["scan"]["storage"]["docker"]
assert report["backup_recommendation"] == backup_note
assert any(item.get("path") == "/scratch/input/qa-probe.bin" for item in scan["scan"]["candidates"])
assert plan["planning_mode"] == "manual_config"
assert plan["backup_recommendation"] == backup_note
assert len([item for item in plan["items"] if item["path"] == "/scratch/input/qa-probe.bin"]) == 1
assert host_scan["scan"]["root"] == "/host-root"
assert host_scan["scan"]["status"] in {"complete", "partial"}
assert host_scan["scan"]["totals"]["entries"] <= 100
assert host_scan["scan"]["storage"]["docker"]["status"] == "unknown"
assert host_scan_status == (0 if host_scan["scan"]["status"] == "complete" else 2)
PY
printf 'Docker smoke passed: doctor, scan, report and manual-plan ran as UID %s in Ubuntu 22.04; the real host root was read-only, Docker Engine absence was explicit, and the writable scratch fixture remained unchanged.\n' "$uid"
