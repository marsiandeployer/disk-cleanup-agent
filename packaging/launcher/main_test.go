package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestCleanArchivePath(t *testing.T) {
	tests := []struct {
		name string
		good bool
	}{
		{"bin/opencode", true},
		{"python/", true},
		{"../outside", false},
		{"a/../../outside", false},
		{"/etc/passwd", false},
		{"./bin/opencode", false},
		{"bin\\opencode", false},
		{"", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := cleanArchivePath(tc.name)
			if (err == nil) != tc.good {
				t.Fatalf("cleanArchivePath(%q) err=%v, want good=%v", tc.name, err, tc.good)
			}
		})
	}
}

func TestExtractRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	archivePath := filepath.Join(root, "bundle.tar.gz")
	file, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gz)
	if err := tarWriter.WriteHeader(&tar.Header{Name: "../escape", Typeflag: tar.TypeReg, Mode: 0o600, Size: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(root, "out")
	if err := os.Mkdir(dest, 0o700); err != nil {
		t.Fatal(err)
	}
	err = extract(payload{path: archivePath, offset: 0, size: info.Size()}, dest)
	if err == nil {
		t.Fatal("extract accepted a traversal path")
	}
	if _, err := os.Stat(filepath.Join(root, "escape")); !os.IsNotExist(err) {
		t.Fatalf("traversal wrote outside the extraction directory: %v", err)
	}
}

func TestCleanupRegistryKillsOnlyVerifiedChildGroup(t *testing.T) {
	if os.Getenv("DCA_REGISTRY_TEST_HELPER") == "1" {
		for {
			time.Sleep(time.Hour)
		}
	}
	root := t.TempDir()
	bundle := filepath.Join(root, "bundle")
	binDir := filepath.Join(bundle, "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	opencode := filepath.Join(binDir, "opencode")
	runner, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(opencode, runner, 0o700); err != nil {
		t.Fatal(err)
	}
	llamaDir := filepath.Join(bundle, "llama")
	if err := os.Mkdir(llamaDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(llamaDir, "llama-server"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(opencode, "-test.run=^TestCleanupRegistryKillsOnlyVerifiedChildGroup$")
	cmd.Env = append(os.Environ(), "DCA_REGISTRY_TEST_HELPER=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()

	var helperUID uint32
	var helperPGID int
	var helperStart uint64
	var helperExe string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		uid, pgid, start, exe, identityErr := procIdentity(cmd.Process.Pid)
		if identityErr == nil {
			helperUID, helperPGID, helperStart, helperExe = uid, pgid, start, exe
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	canonical, err := filepath.EvalSymlinks(opencode)
	if err != nil {
		t.Fatal(err)
	}
	if helperUID != uint32(os.Getuid()) || helperPGID != cmd.Process.Pid || helperExe != canonical {
		t.Fatalf("helper identity is not the expected bundled child: uid=%d pgid=%d exe=%q", helperUID, helperPGID, helperExe)
	}
	registryPath := filepath.Join(root, "children.json")
	registry := childRegistry{Version: childRegistryVersion, Children: []childRecord{{
		PID: cmd.Process.Pid, PGID: helperPGID, StartTicks: helperStart, Executable: helperExe,
	}}}
	encoded, err := json.Marshal(registry)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(registryPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cleanupRegistry(registryPath, bundle); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(registryPath); !os.IsNotExist(err) {
		t.Fatalf("successful cleanup left registry behind: %v", err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("registry cleanup did not terminate the helper process")
	}
	waited = true
}

func TestEphemeralRuntimePreservedWhenChildRegistryRemains(t *testing.T) {
	base := t.TempDir()
	registry := filepath.Join(base, "children-42.json")
	if err := os.WriteFile(registry, []byte("unreadable registry state"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeEphemeralRuntime(base, registry); err == nil {
		t.Fatal("runtime cleanup should retain a nonempty orphan handoff directory")
	}
	if _, err := os.Stat(registry); err != nil {
		t.Fatalf("orphan registry was removed: %v", err)
	}
	if _, err := os.Stat(base); err != nil {
		t.Fatalf("runtime directory was removed: %v", err)
	}
}

func TestEphemeralRuntimeRemovedAfterRegistryIsGone(t *testing.T) {
	base := t.TempDir()
	registry := filepath.Join(base, "children-42.json")
	if err := removeEphemeralRuntime(base, registry); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(base); !os.IsNotExist(err) {
		t.Fatalf("ephemeral runtime directory remains: %v", err)
	}
}
