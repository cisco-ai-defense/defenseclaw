// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0

package axis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// This package is a contributor-only feasibility prototype. It is not imported
// by DefenseClaw and does not constitute a supported AXIS runtime adapter.
const maxBinaryBytes = 512 << 20
const maxOutputBytes = 64 << 10

var errUnsupportedPlatform = errors.New("AXIS feasibility requires Linux")

type runtimePin struct {
	path   string
	sha256 string
}

type executionResult struct {
	exitCode       int
	timedOut       bool
	stdout, stderr string
	truncated      bool
}

func requireLinux(goos string) error {
	if goos != "linux" {
		return fmt.Errorf("%w; got %s (no runtime executed)", errUnsupportedPlatform, goos)
	}
	return nil
}

// Check local bytes without executing even --version. The operator must review
// the digest and its upstream provenance independently; hashing a downloaded
// file and immediately trusting that digest is not an artifact review.
func verifyRuntime(pin runtimePin) error {
	if !filepath.IsAbs(pin.path) {
		return errors.New("-axis-path must name an absolute reviewed executable")
	}
	expected, err := hex.DecodeString(pin.sha256)
	if err != nil || len(expected) != sha256.Size {
		return errors.New("-axis-sha256 must contain the reviewed 64-digit SHA256")
	}
	canonical, err := filepath.EvalSymlinks(pin.path)
	if err != nil {
		return fmt.Errorf("resolve AXIS executable: %w", err)
	}
	if filepath.Clean(canonical) != filepath.Clean(pin.path) {
		return errors.New("AXIS executable path must not traverse symbolic links")
	}
	f, err := os.Open(pin.path)
	if err != nil {
		return fmt.Errorf("open AXIS executable: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("inspect AXIS executable: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxBinaryBytes {
		return errors.New("AXIS executable must be a regular file no larger than 512 MiB")
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, maxBinaryBytes+1)); err != nil {
		return fmt.Errorf("hash AXIS executable: %w", err)
	}
	if !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), pin.sha256) {
		return errors.New("AXIS executable SHA256 mismatch (no runtime executed)")
	}
	return nil
}

type probeSession struct {
	root, home, workspace, temporary, socket, policy string
}

func newProbeSession() (*probeSession, error) {
	root, err := os.MkdirTemp("", "dc-axis-")
	if err != nil {
		return nil, err
	}
	s := &probeSession{
		root: root, home: filepath.Join(root, "home"),
		workspace: filepath.Join(root, "workspace"), temporary: filepath.Join(root, "tmp"),
		socket: filepath.Join(root, "unavailable.sock"), policy: filepath.Join(root, "probe.yaml"),
	}
	for _, path := range []string{s.home, s.workspace, s.temporary, filepath.Join(s.home, ".config"), filepath.Join(s.home, ".cache"), filepath.Join(s.home, ".local", "share")} {
		if err := os.MkdirAll(path, 0700); err != nil {
			_ = os.RemoveAll(root) // root was returned by MkdirTemp, never caller supplied.
			return nil, err
		}
	}
	if err := os.WriteFile(s.policy, []byte(s.policyYAML()), 0600); err != nil {
		_ = os.RemoveAll(root)
		return nil, err
	}
	return s, nil
}

func (s *probeSession) close() error { return os.RemoveAll(s.root) }

func (s *probeSession) policyYAML() string {
	// JSON strings are YAML scalars; never interpolate unquoted paths into YAML.
	quote := func(value string) string { b, _ := json.Marshal(value); return string(b) }
	return "version: 1\nname: defenseclaw-offline-probe\n" +
		"runtime:\n  containment: process\n  provider: mxc\n" +
		"filesystem:\n  compatibility: hard_requirement\n  read_only: [/usr, /lib, /lib64, /bin]\n  read_write: [" +
		quote(s.workspace) + ", " + quote(s.home) + ", " + quote(s.temporary) + "]\n" +
		"process:\n  max_processes: 0\n  max_memory_mb: 0\n  cpu_rate_percent: 0\n  timeout_sec: 15\n" +
		"network:\n  mode: block\n"
}

func (s *probeSession) environment() []string {
	// Construct from scratch. In particular, no host proxy, provider credential,
	// loader/runtime injection option, AXIS override, or real HOME is inherited.
	return []string{
		"PATH=/usr/bin:/bin", "LANG=C", "TERM=dumb", "HOME=" + s.home,
		"TMPDIR=" + s.temporary, "XDG_CONFIG_HOME=" + filepath.Join(s.home, ".config"),
		"XDG_CACHE_HOME=" + filepath.Join(s.home, ".cache"),
		"XDG_DATA_HOME=" + filepath.Join(s.home, ".local", "share"),
	}
}

func (s *probeSession) arguments(command ...string) ([]string, error) {
	if len(command) == 0 || !filepath.IsAbs(command[0]) {
		return nil, errors.New("probe requires an absolute payload executable")
	}
	if _, err := os.Lstat(s.socket); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("research standalone workaround requires an unavailable private socket")
	}
	// Pinned-source workaround ONLY: failed daemon connection selects standalone
	// in AXIS 0.3.5. This is not a stable upstream standalone-mode API.
	args := []string{"--socket", s.socket, "run", "--policy", s.policy, "--"}
	return append(args, command...), nil
}

// Do not allow an unexpected runtime diagnostic to consume unbounded memory.
// Write reports all bytes consumed so output truncation cannot deadlock a child.
type boundedOutput struct {
	mu        sync.Mutex
	data      []byte
	truncated bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	remaining := maxOutputBytes - len(b.data)
	if len(p) > remaining {
		p = p[:remaining]
		b.truncated = true
	}
	b.data = append(b.data, p...)
	return n, nil
}

func (b *boundedOutput) snapshot() (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.data), b.truncated
}
