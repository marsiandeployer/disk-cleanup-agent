from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
GO = shutil.which("go")


@unittest.skipUnless(GO, "Go is required to build the packaging fixture")
class SelfExtractingReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.parent = pathlib.Path(tempfile.mkdtemp(prefix="dca packaging space ", dir="/tmp"))
        self.parent.chmod(0o755)
        self.bundle = self.parent / "fixture bundle"
        for relative in ("bin", "llama", "model", "python/bin", "lib/cleanup_agent", "licenses"):
            (self.bundle / relative).mkdir(parents=True, exist_ok=True)
        self._executable(self.bundle / "bin/opencode", "#!/bin/sh\nexit 0\n")
        self._executable(self.bundle / "llama/llama-server", "#!/bin/sh\nexit 0\n")
        self._executable(
            self.bundle / "python/bin/python3",
            "#!/bin/sh\nprintf '{\"bundle\":\"%s\",\"opencode\":\"%s\",\"llama\":\"%s\",\"model\":\"%s\",\"runtime\":\"%s\"}\\n' \"$DISKCLEANUP_BUNDLE_DIR\" \"$OPENCODE_BIN\" \"$LLAMA_SERVER_BIN\" \"$CLEANUP_AGENT_MODEL_PATH\" \"$DISKCLEANUP_RUNTIME_DIR\"\n",
        )
        (self.bundle / "model/Qwen3.5-0.8B-Q4_K_M.gguf").write_bytes(b"fixture-weights")
        (self.bundle / "lib/cleanup_agent/placeholder.py").write_text("# fixture\n", encoding="utf-8")
        (self.bundle / "licenses/example-LICENSE").write_text("fixture license\n", encoding="utf-8")
        (self.bundle / "ASSET-VERSIONS.txt").write_text("fixture\n", encoding="utf-8")
        self.output_dir = self.parent / "dist path"
        self.output_dir.mkdir()
        self.asset = self.output_dir / "disk cleanup agent"
        env = dict(os.environ, PATH=str(pathlib.Path(GO).parent) + os.pathsep + os.environ.get("PATH", ""))
        subprocess.run(
            ["sh", str(ROOT / "scripts/make-onefile.sh"), "--bundle", str(self.bundle), "--output", str(self.asset)],
            cwd=ROOT,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.parent, ignore_errors=True)

    @staticmethod
    def _executable(path: pathlib.Path, contents: str) -> None:
        path.write_text(contents, encoding="utf-8")
        path.chmod(0o755)

    def _run_unprivileged(self, runtime: pathlib.Path, *args: str, extra_env: dict[str, str] | None = None, asset: pathlib.Path | None = None) -> subprocess.CompletedProcess[str]:
        uid = 65534 if os.geteuid() == 0 else os.getuid()
        gid = 65534 if os.geteuid() == 0 else os.getgid()
        runtime.mkdir(mode=0o700, exist_ok=True)
        if os.geteuid() == 0:
            subprocess.run(["chown", f"{uid}:{gid}", str(runtime)], check=True)
        env = dict(os.environ, HOME=str(runtime), XDG_CACHE_HOME=str(runtime), DISKCLEANUP_RUNTIME_DIR=str(runtime))
        if extra_env:
            env.update(extra_env)
        command = [str(asset or self.asset), *args]
        if os.geteuid() == 0:
            if not shutil.which("runuser"):
                self.skipTest("runuser is required to drop from root to nobody")
            return subprocess.run(
                ["runuser", "-u", "nobody", "--", "env", *[f"{key}={value}" for key, value in env.items()], *command],
                capture_output=True,
                text=True,
                timeout=20,
            )
        return subprocess.run(command, env=env, capture_output=True, text=True, timeout=20)

    def test_runs_as_unprivileged_user_with_spaces_and_exact_runtime_paths(self) -> None:
        runtime = self.parent / "runtime space"
        result = self._run_unprivileged(runtime, "--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        reported = json.loads(result.stdout)
        bundle = runtime / ("bundle-" + self._payload_hash_prefix())
        self.assertEqual(reported["bundle"], str(bundle))
        self.assertEqual(reported["opencode"], str(bundle / "bin/opencode"))
        self.assertEqual(reported["llama"], str(bundle / "llama/llama-server"))
        self.assertEqual(reported["model"], str(bundle / "model/Qwen3.5-0.8B-Q4_K_M.gguf"))
        self.assertEqual(reported["runtime"], str(runtime))
        self.assertEqual((bundle / "model/Qwen3.5-0.8B-Q4_K_M.gguf").read_bytes(), b"fixture-weights")

    def test_tampered_embedded_archive_is_rejected_before_extraction(self) -> None:
        tampered = self.output_dir / "tampered executable"
        data = bytearray(self.asset.read_bytes())
        archive_size = int.from_bytes(data[-40:-32], "big")
        archive_start = len(data) - 48 - archive_size
        data[archive_start + archive_size // 2] ^= 0x01
        tampered.write_bytes(data)
        tampered.chmod(0o755)
        runtime = self.parent / "empty runtime"
        runtime.mkdir(mode=0o700)
        if os.geteuid() == 0:
            subprocess.run(["chown", "65534:65534", str(runtime)], check=True)
        result = self._run_unprivileged(runtime, "--help", asset=tampered)
        self.assertEqual(result.returncode, 2)
        self.assertIn("SHA-256 mismatch", result.stderr)
        self.assertEqual(list(runtime.iterdir()), [])

    def test_tampered_persistent_cache_is_rebuilt_from_verified_payload(self) -> None:
        runtime = self.parent / "cache runtime"
        first = self._run_unprivileged(runtime, "--help")
        bundle = pathlib.Path(json.loads(first.stdout)["bundle"])
        model = bundle / "model/Qwen3.5-0.8B-Q4_K_M.gguf"
        model.write_bytes(b"changed cache bytes")
        second = self._run_unprivileged(runtime, "--help")
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(json.loads(second.stdout)["bundle"], str(bundle))
        self.assertEqual(model.read_bytes(), b"fixture-weights")

    def test_explicit_shared_runtime_uses_private_child_and_symlink_is_rejected(self) -> None:
        shared = self.parent / "shared runtime"
        shared.mkdir(mode=0o755)
        shared.chmod(0o755)
        result = subprocess.run(
            [str(self.asset), "--help"],
            env=dict(os.environ, DISKCLEANUP_RUNTIME_DIR=str(shared)),
            capture_output=True,
            text=True,
            timeout=20,
            check=True,
        )
        runtime_path = pathlib.Path(json.loads(result.stdout)["runtime"])
        self.assertEqual(runtime_path, shared)
        self.assertEqual(runtime_path.stat().st_mode & 0o777, 0o700)

        symlink = self.parent / "runtime symlink"
        symlink.symlink_to(shared, target_is_directory=True)
        rejected = subprocess.run(
            [str(self.asset), "--help"],
            env=dict(os.environ, DISKCLEANUP_RUNTIME_DIR=str(symlink)),
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(rejected.returncode, 2)
        self.assertIn("not a symlink", rejected.stderr)

    def test_automatic_noexec_fallback_and_explicit_noexec_failure(self) -> None:
        if not shutil.which("findmnt"):
            self.skipTest("findmnt is required to inspect the host noexec mount")
        candidates = []
        if os.environ.get("XDG_RUNTIME_DIR"):
            candidates.append(pathlib.Path(os.environ["XDG_RUNTIME_DIR"]))
        candidates.extend((pathlib.Path("/run/user") / str(os.getuid()), pathlib.Path("/run/user/0"), pathlib.Path("/dev/shm")))
        noexec_parent = None
        for candidate in candidates:
            if not candidate.is_dir() or not os.access(candidate, os.W_OK | os.X_OK):
                continue
            options = subprocess.run(
                ["findmnt", "-no", "OPTIONS", "-T", str(candidate)],
                capture_output=True,
                text=True,
                check=True,
                timeout=5,
            ).stdout.strip().split(",")
            if "noexec" in options:
                noexec_parent = candidate
                break
        if noexec_parent is None:
            self.skipTest("no writable noexec runtime mount is available")
        noexec_cache = noexec_parent / f"dca-cache-test-{os.getpid()}-{os.getuid()}"
        noexec_cache.mkdir(mode=0o700)
        scratch = self.parent / "exec fallback scratch"
        scratch.mkdir(mode=0o700)
        try:
            fallback_env = dict(
                os.environ,
                XDG_CACHE_HOME=str(noexec_cache),
                XDG_RUNTIME_DIR=str(noexec_cache),
                TMPDIR=str(scratch),
                HOME=str(scratch),
            )
            fallback = subprocess.run(
                [str(self.asset), "--help"],
                env=fallback_env,
                capture_output=True,
                text=True,
                check=True,
                timeout=20,
            )
            runtime_path = pathlib.Path(json.loads(fallback.stdout)["runtime"])
            self.assertEqual(runtime_path.parent, scratch)
            self.assertFalse(runtime_path.exists(), "ephemeral extraction/runtime path should be removed after exit")

            explicit_env = dict(fallback_env, DISKCLEANUP_RUNTIME_DIR=str(noexec_cache))
            explicit = subprocess.run(
                [str(self.asset), "--help"],
                env=explicit_env,
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertEqual(explicit.returncode, 2)
            self.assertIn("possibly mounted noexec", explicit.stderr)
        finally:
            shutil.rmtree(noexec_cache, ignore_errors=True)

    def _payload_hash_prefix(self) -> str:
        data = self.asset.read_bytes()
        return __import__("hashlib").sha256(data[-48 - int.from_bytes(data[-40:-32], "big") : -48]).hexdigest()[:16]


class SourceInstallerInterfaceTests(unittest.TestCase):
    def test_help_is_offline_and_describes_user_prefix(self) -> None:
        result = subprocess.run(
            ["sh", str(ROOT / "scripts/install.sh"), "--help"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        self.assertIn("--prefix DIR", result.stdout)
        self.assertIn("does not use pip, root, PM2, or systemd", " ".join(result.stdout.split()))

    def test_default_prefix_requires_home_but_explicit_prefix_is_parsed(self) -> None:
        env = dict(os.environ)
        env.pop("HOME", None)
        result = subprocess.run(
            ["sh", str(ROOT / "scripts/install.sh")],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=5,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("set HOME or DISKCLEANUP_PREFIX", result.stderr)
