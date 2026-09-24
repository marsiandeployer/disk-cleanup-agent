//go:build linux && amd64

// The release launcher is a static ELF followed by a compressed bundle and a
// small authenticated footer. It extracts only relative regular files and
// symlinks, checks disk space and executable mounts, then starts bundled
// Python. It has no dependency on tar, gzip, or a shell on the target host.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const footerMagic = "DCAEND01"
const footerSize = 8 + 8 + sha256.Size
const bundleLimit = int64(2_147_483_648)
const childRegistryVersion = 1

// Set by make-onefile.sh from the already pinned and checked bundle contents.
var embeddedModelSHA256 string
var embeddedOpenCodeSHA256 string
var embeddedLlamaSHA256 string
var embeddedPythonSHA256 string

type payload struct {
	path   string
	offset int64
	size   int64
	hash   [sha256.Size]byte
}

type childRecord struct {
	PID        int    `json:"pid"`
	PGID       int    `json:"pgid"`
	StartTicks uint64 `json:"start_ticks"`
	Executable string `json:"exe"`
}

type childRegistry struct {
	Version  int           `json:"version"`
	Children []childRecord `json:"children"`
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--disk-cleanup-agent-exec-probe" {
		return
	}
	err := runMain()
	if err == nil {
		return
	}
	if exit, ok := err.(*exec.ExitError); ok {
		os.Exit(exit.ExitCode())
	}
	fmt.Fprintf(os.Stderr, "disk-cleanup-agent: %v\n", err)
	os.Exit(2)
}

func runMain() error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return errors.New("this release supports Linux x86_64 only")
	}
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate executable: %w", err)
	}
	archive, err := readPayload(self)
	if err != nil {
		return fmt.Errorf("invalid embedded bundle: %w", err)
	}
	base, ephemeral, err := runtimeBase(self, archive.offset)
	if err != nil {
		return fmt.Errorf("no usable writable runtime directory: %w", err)
	}
	registryPath := filepath.Join(base, fmt.Sprintf("children-%d.json", os.Getpid()))
	if ephemeral {
		defer func() {
			if cleanupErr := removeEphemeralRuntime(base, registryPath); cleanupErr != nil {
				fmt.Fprintf(os.Stderr, "disk-cleanup-agent: %v\n", cleanupErr)
			}
		}()
	}
	if err := ensureExecutableFS(base, self, archive.offset); err != nil {
		return fmt.Errorf("runtime directory cannot execute bundled programs (possibly mounted noexec): %v; set DISKCLEANUP_RUNTIME_DIR to an executable writable directory", err)
	}
	bundle := filepath.Join(base, "bundle-"+hex.EncodeToString(archive.hash[:8]))
	if err := ensureBundle(bundle, archive); err != nil {
		return fmt.Errorf("extract embedded bundle: %w", err)
	}
	if err := clearStaleRegistry(registryPath, bundle); err != nil {
		return fmt.Errorf("cannot safely handle stale child registry: %w", err)
	}
	return run(bundle, base, ephemeral)
}

func removeEphemeralRuntime(base, registryPath string) error {
	if _, err := os.Lstat(registryPath); err == nil {
		return fmt.Errorf("child registry remains at %s; runtime directory retained at %s", registryPath, base)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("cannot verify child registry at %s; runtime directory retained at %s: %w", registryPath, base, err)
	}
	if err := os.RemoveAll(base); err != nil {
		return fmt.Errorf("cannot remove ephemeral runtime directory %s: %w", base, err)
	}
	return nil
}

func readPayload(path string) (payload, error) {
	f, err := os.Open(path)
	if err != nil {
		return payload{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return payload{}, err
	}
	if st.Size() < footerSize {
		return payload{}, errors.New("missing footer")
	}
	footer := make([]byte, footerSize)
	if _, err := f.ReadAt(footer, st.Size()-footerSize); err != nil {
		return payload{}, err
	}
	if string(footer[:8]) != footerMagic {
		return payload{}, errors.New("footer marker does not match")
	}
	length := binary.BigEndian.Uint64(footer[8:16])
	if length == 0 || length > uint64(bundleLimit) || length > uint64(st.Size()-footerSize) {
		return payload{}, fmt.Errorf("embedded archive length %d is invalid", length)
	}
	p := payload{path: path, offset: st.Size() - footerSize - int64(length), size: int64(length)}
	copy(p.hash[:], footer[16:])
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(f, p.offset, p.size)); err != nil {
		return payload{}, err
	}
	if !bytes.Equal(h.Sum(nil), p.hash[:]) {
		return payload{}, errors.New("embedded archive SHA-256 mismatch")
	}
	return p, nil
}

func runtimeBase(probePath string, probeBytes int64) (string, bool, error) {
	if path := os.Getenv("DISKCLEANUP_RUNTIME_DIR"); path != "" {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return "", false, err
		}
		st, err := os.Lstat(path)
		if err != nil || st.Mode()&os.ModeSymlink != 0 {
			return "", false, errors.New("explicit runtime path must be a real directory, not a symlink")
		}
		if err := secureOwnedDir(path); err == nil {
			absolute, absErr := filepath.Abs(path)
			return absolute, false, absErr
		}
		dir, err := os.MkdirTemp(path, "disk-cleanup-agent-")
		if err != nil {
			return "", false, fmt.Errorf("explicit runtime directory is not private and no private scratch could be created: %w", err)
		}
		return dir, true, nil
	}
	for _, env := range []string{"XDG_CACHE_HOME", "XDG_RUNTIME_DIR", "TMPDIR"} {
		if path := os.Getenv(env); path != "" {
			if env == "XDG_CACHE_HOME" {
				path = filepath.Join(path, "disk-cleanup-agent")
				if err := os.MkdirAll(path, 0o700); err != nil {
					continue
				}
				if err := secureOwnedDir(path); err == nil {
					if err := ensureExecutableFS(path, probePath, probeBytes); err == nil {
						absolute, absErr := filepath.Abs(path)
						return absolute, false, absErr
					}
				}
				continue
			}
			dir, err := os.MkdirTemp(path, "disk-cleanup-agent-")
			if err == nil && ensureExecutableFS(dir, probePath, probeBytes) == nil {
				return dir, true, nil
			}
			if err == nil {
				_ = os.RemoveAll(dir)
			}
		}
	}
	if cache, err := os.UserCacheDir(); err == nil {
		path := filepath.Join(cache, "disk-cleanup-agent")
		if os.MkdirAll(path, 0o700) == nil && secureOwnedDir(path) == nil && ensureExecutableFS(path, probePath, probeBytes) == nil {
			absolute, absErr := filepath.Abs(path)
			return absolute, false, absErr
		}
	}
	for _, path := range []string{"/tmp", "/var/tmp"} {
		if dir, err := os.MkdirTemp(path, "disk-cleanup-agent-"); err == nil && ensureExecutableFS(dir, probePath, probeBytes) == nil {
			return dir, true, nil
		} else if err == nil {
			_ = os.RemoveAll(dir)
		}
	}
	return "", false, errors.New("set DISKCLEANUP_RUNTIME_DIR to a writable path")
}

func secureOwnedDir(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return errors.New("cache root is not a real directory")
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() {
		return errors.New("cache root is not owned by the current user")
	}
	if st.Mode()&os.ModeSticky != 0 || st.Mode().Perm()&0o022 != 0 {
		return errors.New("directory is shared or writable by other users")
	}
	if st.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(path, 0o700); err != nil {
			return errors.New("cache root is accessible by other users")
		}
	}
	return nil
}

func ensureExecutableFS(base, probePath string, probeBytes int64) error {
	source, err := os.Open(probePath)
	if err != nil {
		return err
	}
	defer source.Close()
	f, err := os.CreateTemp(base, ".exec-check-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err := io.Copy(f, io.NewSectionReader(source, 0, probeBytes)); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(0o700); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return exec.Command(name, "--disk-cleanup-agent-exec-probe").Run()
}

func ensureBundle(bundle string, p payload) error {
	marker := filepath.Join(bundle, ".bundle-sha256")
	if data, err := os.ReadFile(marker); err == nil && strings.TrimSpace(string(data)) == hex.EncodeToString(p.hash[:]) {
		if err := verifyBundle(bundle); err == nil {
			return nil
		}
	}
	if _, err := os.Lstat(bundle); err == nil {
		if err := os.RemoveAll(bundle); err != nil {
			return err
		}
	}
	tmp, err := os.MkdirTemp(filepath.Dir(bundle), ".bundle-extract-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if err := checkFreeSpace(p, tmp); err != nil {
		return err
	}
	if err := extract(p, tmp); err != nil {
		return err
	}
	if err := verifyBundle(tmp); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(tmp, ".bundle-sha256"), []byte(hex.EncodeToString(p.hash[:])+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, bundle); err != nil {
		if markerData, readErr := os.ReadFile(marker); readErr == nil && strings.TrimSpace(string(markerData)) == hex.EncodeToString(p.hash[:]) {
			return verifyBundle(bundle)
		}
		return err
	}
	return nil
}

func verifyBundle(bundle string) error {
	for _, item := range []struct {
		name       string
		want       string
		executable bool
	}{
		{"bin/opencode", embeddedOpenCodeSHA256, true},
		{"llama/llama-server", embeddedLlamaSHA256, true},
		{"model/Qwen3.5-0.8B-Q4_K_M.gguf", embeddedModelSHA256, false},
	} {
		if item.want == "" || len(item.want) != sha256.Size*2 {
			return fmt.Errorf("launcher is missing the expected hash for %s", item.name)
		}
		path := filepath.Join(bundle, item.name)
		st, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("required bundle file %s is missing: %w", item.name, err)
		}
		if !st.Mode().IsRegular() || (item.executable && st.Mode().Perm()&0o111 == 0) {
			return fmt.Errorf("required bundle file %s has an invalid type or mode", item.name)
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		h := sha256.New()
		_, hashErr := io.Copy(h, f)
		closeErr := f.Close()
		if hashErr != nil {
			return hashErr
		}
		if closeErr != nil {
			return closeErr
		}
		if hex.EncodeToString(h.Sum(nil)) != item.want {
			return fmt.Errorf("SHA-256 mismatch for extracted file %s", item.name)
		}
	}
	if embeddedPythonSHA256 == "" || len(embeddedPythonSHA256) != sha256.Size*2 {
		return errors.New("launcher is missing the expected hash for bundled Python")
	}
	for _, name := range []string{"python/bin/python3", "python/bin/python3.12"} {
		path := filepath.Join(bundle, name)
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			continue
		}
		if err := ensureInside(bundle, resolved); err != nil {
			continue
		}
		st, err := os.Stat(resolved)
		if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0o111 == 0 {
			continue
		}
		f, err := os.Open(resolved)
		if err != nil {
			return err
		}
		h := sha256.New()
		_, hashErr := io.Copy(h, f)
		closeErr := f.Close()
		if hashErr != nil {
			return hashErr
		}
		if closeErr != nil {
			return closeErr
		}
		if hex.EncodeToString(h.Sum(nil)) != embeddedPythonSHA256 {
			return errors.New("SHA-256 mismatch for extracted Python executable")
		}
		return nil
	}
	return errors.New("bundled Python executable is missing or not executable")
}

func extract(p payload, dest string) error {
	f, err := os.Open(p.path)
	if err != nil {
		return err
	}
	defer f.Close()
	section := io.NewSectionReader(f, p.offset, p.size)
	gz, err := gzip.NewReader(section)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		rel, err := cleanArchivePath(h.Name)
		if err != nil {
			return err
		}
		if h.Size < 0 || uint64(h.Size) > uint64(bundleLimit) {
			return errors.New("uncompressed archive exceeds the 2 GiB safety limit")
		}
		target := filepath.Join(dest, rel)
		if err := ensureInside(dest, target); err != nil {
			return err
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return err
			}
			mode := os.FileMode(0o600)
			if h.Mode&0o111 != 0 {
				mode = 0o700
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
			if err != nil {
				return err
			}
			_, copyErr := io.CopyN(out, tr, h.Size)
			closeErr := out.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
		case tar.TypeSymlink:
			if filepath.IsAbs(h.Linkname) || strings.ContainsRune(h.Linkname, '\\') {
				return fmt.Errorf("unsafe symlink target %q", h.Linkname)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return err
			}
			resolved := filepath.Clean(filepath.Join(filepath.Dir(rel), h.Linkname))
			if resolved == ".." || strings.HasPrefix(resolved, ".."+string(os.PathSeparator)) {
				return fmt.Errorf("symlink escapes bundle: %q", h.Name)
			}
			if err := os.Symlink(h.Linkname, target); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported archive entry type %d for %q", h.Typeflag, h.Name)
		}
	}
	return nil
}

func checkFreeSpace(p payload, dest string) error {
	f, err := os.Open(p.path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(io.NewSectionReader(f, p.offset, p.size))
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var total uint64
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if _, err := cleanArchivePath(h.Name); err != nil {
			return err
		}
		if h.Size < 0 || uint64(h.Size) > uint64(bundleLimit) || total+uint64(h.Size) > uint64(bundleLimit) {
			return errors.New("uncompressed archive exceeds the 2 GiB safety limit")
		}
		total += uint64(h.Size)
		if _, err := io.Copy(io.Discard, tr); err != nil {
			return err
		}
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(dest, &stat); err != nil {
		return err
	}
	available := uint64(stat.Bavail) * uint64(stat.Bsize)
	if available < total+32*1024*1024 {
		return fmt.Errorf("need at least %d bytes free, only %d available", total+32*1024*1024, available)
	}
	return nil
}

func cleanArchivePath(name string) (string, error) {
	if name == "" || filepath.IsAbs(name) || strings.ContainsRune(name, '\\') {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	trimmed := strings.TrimSuffix(name, "/")
	clean := filepath.Clean(trimmed)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) || clean != trimmed {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	return clean, nil
}

func ensureInside(root, target string) error {
	r, err := filepath.Rel(root, target)
	if err != nil || r == ".." || strings.HasPrefix(r, ".."+string(os.PathSeparator)) {
		return errors.New("archive entry escapes extraction directory")
	}
	return nil
}

func clearStaleRegistry(path, bundle string) error {
	if _, err := os.Lstat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return cleanupRegistry(path, bundle)
}

func cleanupRegistry(path, bundle string) error {
	st, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0o077 != 0 {
		return errors.New("registry is not a private regular file")
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() {
		return errors.New("registry is not owned by this user")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read child registry: %w", err)
	}
	var registry childRegistry
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&registry); err != nil {
		return fmt.Errorf("decode child registry: %w", err)
	}
	if registry.Version != childRegistryVersion {
		return fmt.Errorf("unsupported child registry version %d", registry.Version)
	}
	allowed := map[string]bool{}
	for _, rel := range []string{"bin/opencode", "llama/llama-server"} {
		path, err := filepath.EvalSymlinks(filepath.Join(bundle, rel))
		if err != nil {
			return fmt.Errorf("resolve bundled child path %s: %w", rel, err)
		}
		allowed[path] = true
	}
	for _, child := range registry.Children {
		if child.PID <= 1 || child.PGID != child.PID || !allowed[child.Executable] {
			return fmt.Errorf("refusing unrecognized child registry entry pid=%d pgid=%d exe=%q", child.PID, child.PGID, child.Executable)
		}
		uid, processGroup, start, executable, err := procIdentity(child.PID)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("cannot verify child %d through /proc: %w", child.PID, err)
		}
		if uid != uint32(os.Getuid()) || processGroup != child.PGID || start != child.StartTicks || executable != child.Executable {
			return fmt.Errorf("child %d identity no longer matches its registry entry", child.PID)
		}
		if err := syscall.Kill(-child.PGID, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			return fmt.Errorf("signal verified child group %d: %w", child.PGID, err)
		}
	}
	for _, child := range registry.Children {
		if err := waitGroupGone(child.PGID, 3*time.Second); err != nil {
			return err
		}
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove completed child registry: %w", err)
	}
	return nil
}

func procIdentity(pid int) (uint32, int, uint64, string, error) {
	root := filepath.Join("/proc", strconv.Itoa(pid))
	statData, err := os.ReadFile(filepath.Join(root, "stat"))
	if err != nil {
		return 0, 0, 0, "", err
	}
	closeParen := bytes.LastIndexByte(statData, ')')
	if closeParen < 0 {
		return 0, 0, 0, "", errors.New("malformed process stat")
	}
	fields := strings.Fields(string(statData[closeParen+1:]))
	if len(fields) <= 19 {
		return 0, 0, 0, "", errors.New("process stat lacks start time")
	}
	processGroup64, err := strconv.ParseInt(fields[2], 10, 32)
	if err != nil {
		return 0, 0, 0, "", err
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, 0, 0, "", err
	}
	statusData, err := os.ReadFile(filepath.Join(root, "status"))
	if err != nil {
		return 0, 0, 0, "", err
	}
	var uid uint32
	foundUID := false
	for _, line := range strings.Split(string(statusData), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			values := strings.Fields(strings.TrimPrefix(line, "Uid:"))
			if len(values) == 0 {
				break
			}
			parsed, err := strconv.ParseUint(values[0], 10, 32)
			if err != nil {
				return 0, 0, 0, "", err
			}
			uid, foundUID = uint32(parsed), true
			break
		}
	}
	if !foundUID {
		return 0, 0, 0, "", errors.New("process status lacks uid")
	}
	executable, err := os.Readlink(filepath.Join(root, "exe"))
	if err != nil {
		return 0, 0, 0, "", err
	}
	return uid, int(processGroup64), start, executable, nil
}

func waitGroupGone(pgid int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		active, err := processGroupHasLiveMembers(pgid)
		if err != nil {
			return fmt.Errorf("cannot verify child group %d through /proc: %w", pgid, err)
		}
		if !active {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("verified child group %d still exists after SIGKILL", pgid)
}

func processGroupHasLiveMembers(pgid int) (bool, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return false, err
		}
		closeParen := bytes.LastIndexByte(data, ')')
		if closeParen < 0 {
			return false, errors.New("malformed process stat")
		}
		fields := strings.Fields(string(data[closeParen+1:]))
		if len(fields) < 3 {
			return false, errors.New("process stat lacks process group")
		}
		group, err := strconv.Atoi(fields[2])
		if err != nil {
			return false, err
		}
		if group == pgid && fields[0] != "Z" && fields[0] != "X" {
			return true, nil
		}
	}
	return false, nil
}

func run(bundle, runtimeDir string, ephemeral bool) error {
	python := filepath.Join(bundle, "python", "bin", "python3")
	if _, err := os.Stat(python); err != nil {
		// python-build-standalone names the interpreter python3.12.
		python = filepath.Join(bundle, "python", "bin", "python3.12")
	}
	app := filepath.Join(bundle, "lib")
	registryPath := filepath.Join(runtimeDir, fmt.Sprintf("children-%d.json", os.Getpid()))
	args := append([]string{"-m", "cleanup_agent.cli"}, os.Args[1:]...)
	cli := exec.Command(python, args...)
	cli.Dir = bundle
	cli.Env = append(os.Environ(),
		"DISKCLEANUP_BUNDLE_DIR="+bundle,
		"OPENCODE_BIN="+filepath.Join(bundle, "bin", "opencode"),
		"LLAMA_SERVER_BIN="+filepath.Join(bundle, "llama", "llama-server"),
		"CLEANUP_AGENT_MODEL_PATH="+filepath.Join(bundle, "model", "Qwen3.5-0.8B-Q4_K_M.gguf"),
		"DISKCLEANUP_RUNTIME_DIR="+runtimeDir,
		"DISKCLEANUP_CHILD_REGISTRY="+registryPath,
		"PYTHONHOME="+filepath.Join(bundle, "python"),
		"PYTHONPATH="+app,
		"LD_LIBRARY_PATH="+filepath.Join(bundle, "llama")+":"+os.Getenv("LD_LIBRARY_PATH"),
		"OPENCODE_DISABLE_AUTOUPDATE=1",
		"OPENCODE_DISABLE_MODELS_FETCH=1",
		"OPENCODE_DISABLE_DEFAULT_PLUGINS=1",
	)
	cli.Stdin, cli.Stdout, cli.Stderr = os.Stdin, os.Stdout, os.Stderr
	cli.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cli.Start(); err != nil {
		return err
	}
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	done := make(chan error, 1)
	go func() { done <- cli.Wait() }()
	select {
	case err := <-done:
		signal.Stop(sigs)
		if cleanupErr := cleanupRegistry(registryPath, bundle); cleanupErr != nil {
			fmt.Fprintf(os.Stderr, "disk-cleanup-agent: child cleanup incomplete: %v\n", cleanupErr)
			return fmt.Errorf("child cleanup incomplete: %w", cleanupErr)
		}
		return err
	case <-sigs:
		// A Python KeyboardInterrupt enters runtime cleanup/finally blocks,
		// which stop both the OpenCode and llama.cpp process groups. SIGTERM
		// would kill Python immediately and skip that cleanup path.
		_ = syscall.Kill(-cli.Process.Pid, syscall.SIGINT)
		select {
		case err := <-done:
			signal.Stop(sigs)
			if cleanupErr := cleanupRegistry(registryPath, bundle); cleanupErr != nil {
				fmt.Fprintf(os.Stderr, "disk-cleanup-agent: child cleanup incomplete: %v\n", cleanupErr)
			}
			return err
		case <-time.After(15 * time.Second):
			if cleanupErr := cleanupRegistry(registryPath, bundle); cleanupErr != nil {
				fmt.Fprintf(os.Stderr, "disk-cleanup-agent: child cleanup incomplete; refusing broad process matching: %v\n", cleanupErr)
			}
			_ = syscall.Kill(-cli.Process.Pid, syscall.SIGKILL)
			err := <-done
			signal.Stop(sigs)
			if ephemeral {
				return err
			}
			return err
		}
	}
}
