// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/fleet/mqtt"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

const installedCompilerPath = "/usr/local/lib/defenseclaw/policy_compiler.py"

// ErrInvalidPolicy marks a request rejected because of its policy content or
// profile. Callers can return a client error without exposing compiler output.
var ErrInvalidPolicy = errors.New("invalid policy")

// ErrPolicyTooLarge and ErrMalformedPolicy retain ErrInvalidPolicy for callers
// that only distinguish client input from compiler infrastructure failures.
var ErrPolicyTooLarge = fmt.Errorf("%w: policy YAML exceeds 64 KiB", ErrInvalidPolicy)
var ErrMalformedPolicy = fmt.Errorf("%w: malformed policy content", ErrInvalidPolicy)

// ErrCompilerBusy means every policy compiler slot stayed in use; callers
// should retry later (HTTP 429).
var ErrCompilerBusy = errors.New("policy compiler busy")

// maxConcurrentCompiles bounds the number of policy compiler processes the
// gateway runs at once. compileSlotWait is how long a simulate request (which
// any authenticated tenant can issue) waits for a slot; pushCompileSlotWait is
// the longer wait for an operator policy push, which should queue behind other
// compiles rather than fail.
const maxConcurrentCompiles = 2

var compileSlotWait = 2 * time.Second

var pushCompileSlotWait = 60 * time.Second

var ErrPolicyVersionExhausted = fmt.Errorf("%w: policy version 65534 is the highest supported OTA version; provision a new device policy lineage", ErrInvalidPolicy)

// OTA's uint16 high-water stores 0xffff as erased flash. Never issue it.
const maxPolicyVersion uint32 = 65534

// sha256Sum returns the SHA-256 hash of data.
func sha256Sum(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// EmergencyCommand identifies an emergency action to push to a fleet.
type EmergencyCommand uint8

const (
	// EmergencyBlockAll tells all devices to flush caches and block ALL requests
	// until cleared or daemon restart.
	// C-side ota_receiver.c: case 0x01 — BLOCK_ALL.
	EmergencyBlockAll EmergencyCommand = 0x01

	// EmergencyRevokeSessions tells all devices to revoke all active sessions
	// (flushes caches and clears session table).
	// C-side ota_receiver.c: case 0x02 — REVOKE_HASH / REVOKE_SESSIONS.
	EmergencyRevokeSessions EmergencyCommand = 0x02

	// EmergencyForceSync tells all devices to flush their audit logs immediately.
	// C-side ota_receiver.c: case 0x03 — FORCE_SYNC.
	EmergencyForceSync EmergencyCommand = 0x03

	// EmergencyEnterLockdown tells all devices to enter lockdown mode
	// (flushes caches and blocks ALL requests, same effect as BLOCK_ALL).
	// C-side ota_receiver.c: case 0x04 — ENTER_LOCKDOWN.
	EmergencyEnterLockdown EmergencyCommand = 0x04

	// EmergencyReleaseLockdown clears the global block_all_active flag so
	EmergencyReleaseLockdown EmergencyCommand = 0x05
)

// PolicyHeader matches the C-side dclaw_policy_header_t structure (8 bytes, big-endian).
//
//	[0:2]  version         uint16
//	[2:4]  payload_len     uint16
//	[4:6]  canary_baseline uint16
//	[6:8]  _reserved       uint16
type PolicyHeader struct {
	Version        uint16
	PayloadLen     uint16
	CanaryBaseline uint16
}

// HeaderSize is the fixed size of the policy blob header.
const HeaderSize = 8

// EmergencyMsgSize is the size of the emergency wire format.
// Matches dclaw_emergency_msg_t in ota_receiver.c:
//
//	[0:4]    sequence    uint32
//	[4:8]    timestamp   uint32
//	[8]      command     uint8
//	[9]      scope       uint8
//	[10:42]  payload     [32]byte
//	[42:44]  _reserved   [2]byte
//	[44:48]  previous sequence for this fleet, uint32 big-endian
//	[48:112] signature [64]byte (HMAC-SHA256 in first 32, zero-padded)
const EmergencyMsgSize = 112

// ManagedMacOSPythonCandidates lists exact Python.org framework interpreters
// accepted for managed Fleet. Apple CLT Python is often too old for the
// policy compiler, and PATH must not redirect an installed compiler.
func ManagedMacOSPythonCandidates() []string {
	return []string{
		"/Library/Frameworks/Python.framework/Versions/3.14/bin/python3.14",
		"/Library/Frameworks/Python.framework/Versions/3.13/bin/python3.13",
		"/Library/Frameworks/Python.framework/Versions/3.12/bin/python3.12",
		"/Library/Frameworks/Python.framework/Versions/3.11/bin/python3.11",
		"/Library/Frameworks/Python.framework/Versions/3.10/bin/python3.10",
	}
}

// CheckManagedMacOSPython returns the same protected interpreter selected at
// runtime. The managed macOS installer calls it before admitting Fleet; the
// resolver verifies the protected path and an isolated PyYAML import.
func CheckManagedMacOSPython() (string, error) {
	if runtime.GOOS != "darwin" {
		return "", errors.New("managed macOS Python admission is available only on darwin")
	}
	return installedPythonInterpreter()
}

// CheckManagedLinuxPython returns the protected distro interpreter also used
// by the managed Linux gateway. Enterprise admission invokes it before
// enabling Fleet so an unavailable runtime fails before service mutation.
func CheckManagedLinuxPython() (string, error) {
	if runtime.GOOS != "linux" {
		return "", errors.New("managed Linux Python admission is available only on linux")
	}
	return installedPythonInterpreter()
}

// ParseHeader decodes the 8-byte policy blob header (big-endian).
func ParseHeader(data []byte) (*PolicyHeader, error) {
	if len(data) < HeaderSize {
		return nil, fmt.Errorf("policy blob too short for header: %d bytes", len(data))
	}
	return &PolicyHeader{
		Version:        binary.BigEndian.Uint16(data[0:2]),
		PayloadLen:     binary.BigEndian.Uint16(data[2:4]),
		CanaryBaseline: binary.BigEndian.Uint16(data[4:6]),
	}, nil
}

// Service manages policy compilation, signing, and distribution to edge devices.
//
// OTA policy and emergency commands use independent 32-byte HMAC secrets.
// The 64-byte signature field carries a 32-byte HMAC followed by zero padding.
type Service struct {
	store  PolicyStore
	signer Signer
	client mqtt.Client
	logger *log.Logger

	emergencySigner Signer

	// compilerPath is the absolute path to the Python policy_compiler.py
	// script, resolved once at construction; the validated path is the one
	// executed. An empty config value selects a trusted shipped compiler.
	compilerPath string

	// compileSlots bounds concurrent compiler processes.
	compileSlots chan struct{}

	// emergencySeq tracks the next emergency broadcast sequence number.
	// Must be strictly increasing per the C-side anti-replay (REQ-31).
	// Persisted in the PolicyStore to survive gateway restarts.
	emergencySeq uint32
	// policyMu serializes version allocation through durable SavePolicy. A
	// concurrent push must not read the same latest version and return a
	// spurious duplicate-version storage error after compilation.
	policyMu sync.Mutex

	emergencyMu  sync.Mutex
	emergencyErr error

	policyReplayMu sync.Mutex
	policyReplays  map[string]policyReplayAttempt

	emergencyReplayMu sync.Mutex
	emergencyReplays  map[string]*emergencyReplayState
}

// Emergency catch-up publishes to the fleet topic, so every device in the
// fleet receives each replayed command. Passes are coalesced per fleet: at
// most one runs at a time, a request already covered by a pass in the last
// emergencyReplayCooldown is skipped, and at most
// maxEmergencyReplaysPerWindow passes run per fleet per window. Each pass
// publishes a contiguous, ordered page of the fleet's history, so devices
// still apply commands in predecessor order.
const (
	emergencyReplayCooldown      = 30 * time.Second
	maxEmergencyReplaysPerWindow = 4
)

type emergencyReplayPass struct {
	after, last uint32
	at          time.Time
}

type emergencyReplayState struct {
	inFlight bool
	passes   []emergencyReplayPass
}

type policyReplayAttempt struct {
	version  uint32
	at       time.Time
	inFlight bool
}

// Config holds configuration for the policy Service.
type Config struct {
	// CompilerPath is the path to the Python policy_compiler.py.
	// Empty selects a trusted source or installed compiler.
	CompilerPath string
	// EmergencyKeyHex is the independent hex-encoded emergency HMAC secret.
	// Empty resolves DCLAW_EMERGENCY_KEY.
	EmergencyKeyHex string

	// Logger for policy operations. Defaults to log.Default().
	Logger *log.Logger
}

// NewService creates a new policy distribution service.
// On startup, it loads the last persisted emergency sequence number from the
// policy store to guarantee monotonically increasing values across restarts.
func NewService(store PolicyStore, signer Signer, client mqtt.Client, cfg *Config) *Service {
	s := &Service{
		store:         store,
		signer:        signer,
		client:        client,
		compilerPath:  defaultCompilerPath(),
		logger:        log.Default(),
		policyReplays: make(map[string]policyReplayAttempt),
		compileSlots:  make(chan struct{}, maxConcurrentCompiles),

		emergencyReplays: make(map[string]*emergencyReplayState),
	}
	if cfg != nil {
		if cfg.CompilerPath != "" {
			s.compilerPath = cfg.CompilerPath
		}
		if cfg.Logger != nil {
			s.logger = cfg.Logger
		}
	}

	// Resolve a relative compiler path once, against the gateway's working
	// directory at startup, so validation and execution use the same file.
	if s.compilerPath != "" {
		if abs, err := filepath.Abs(s.compilerPath); err == nil {
			s.compilerPath = abs
		} else {
			s.logger.Printf("[policy] WARNING: cannot resolve compiler path %q: %v", s.compilerPath, err)
			s.compilerPath = ""
		}
	}

	// Validate compiler path at construction time to fail fast on misconfiguration.
	if err := validateCompilerPath(s.compilerPath); err != nil {
		s.logger.Printf("[policy] WARNING: compiler path validation failed: %v — Compile() will re-validate at call time", err)
	}

	emergencyKeyHex := ""
	if cfg != nil {
		emergencyKeyHex = cfg.EmergencyKeyHex
	}
	emergencySigner, err := NewEmergencySignerFromKeyHex(emergencyKeyHex)
	if err != nil {
		s.logger.Printf("[policy] WARNING: emergency signer unavailable: %v", err)
	} else if otaSigner, ok := signer.(*HMACSigner); ok && otaSigner != nil && bytes.Equal(otaSigner.key, emergencySigner.key) {
		s.logger.Printf("[policy] WARNING: emergency signer unavailable: DCLAW_EMERGENCY_KEY must differ from DCLAW_OTA_HMAC_KEY")
	} else {
		s.emergencySigner = emergencySigner
	}

	if store != nil {
		if seq, err := store.GetEmergencySeq(); err != nil {
			s.emergencyErr = fmt.Errorf("load durable emergency sequence: %w", err)
			s.logger.Printf("[policy] ERROR: %v — emergency commands disabled", s.emergencyErr)
		} else if seq > 0 {
			s.emergencySeq = seq
			s.logger.Printf("[policy] loaded emergency sequence %d from store", seq)
		}
	}

	return s
}

// validateCompilerPath checks that the compiler path is safe to execute:
// it must resolve to an absolute path without traversal, point to an existing
// regular file (not a directory), and not contain embedded ".." sequences.
func validateCompilerPath(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid compiler path: %w", err)
	}
	// Must not contain path traversal
	if strings.Contains(abs, "..") {
		return fmt.Errorf("compiler path must not contain '..'")
	}
	info, err := os.Stat(abs)
	if err != nil {
		return fmt.Errorf("compiler not found: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("compiler path is a directory")
	}

	if !isUnderAllowedDir(abs) {
		return fmt.Errorf("compiler path %q is not an approved installed, private-home, or source-checkout compiler", abs)
	}

	return nil
}

// sourceCompilerPath returns the one compiler beside a gateway built in the
// repository root. It does not trust a compiler merely because cwd points at
// a source tree, which would let an installed gateway execute arbitrary code.
func sourceCompilerPath() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return ""
	}
	root := filepath.Dir(exe)
	if !trustedCompilerFile(exe, root) {
		return ""
	}
	module, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil || !bytes.HasPrefix(module, []byte("module github.com/defenseclaw/defenseclaw\n")) {
		return ""
	}
	candidate := filepath.Join(root, "edge-connector", "tools", "policy_compiler.py")
	if !trustedCompilerFile(candidate, root) {
		return ""
	}
	return candidate
}

// trustedCompilerFile rejects symlinks and group/other-writable components.
// For a checkout, stop at its executable directory; for an installed path,
// stop at the installation prefix (both are checked separately below).
func trustedCompilerFile(path, base string) bool {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != filepath.Clean(path) {
		return false
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || writableByOthers(info) {
		return false
	}
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() || writableByOthers(info) {
			return false
		}
		if dir == base {
			return true
		}
		if dir == filepath.Dir(dir) {
			return false
		}
	}
}

// Unix permission bits are not a faithful representation of Windows ACLs.
func writableByOthers(info os.FileInfo) bool {
	return runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0
}

// pythonForCompiler uses the installer's pinned Python environment for the
// bundled per-user compiler. Source and system packages use system Python.
func pythonForCompiler(compilerPath string) (string, error) {
	if homeCompiler := homeInstallerCompilerPath(); homeCompiler != "" && compilerPath == homeCompiler {
		home := homeInstallerRoot()
		interpreter := filepath.Join(home, ".venv", "bin", "python")
		if runtime.GOOS == "windows" {
			interpreter = filepath.Join(home, ".venv", "Scripts", "python.exe")
		}
		resolved, err := filepath.EvalSymlinks(interpreter)
		if err != nil || !trustedDirectory(filepath.Dir(interpreter), home) ||
			!trustedCompilerFile(resolved, filepath.VolumeName(resolved)+string(filepath.Separator)) {
			return "", fmt.Errorf("trusted policy compiler Python interpreter unavailable at %s", interpreter)
		}
		return interpreter, nil
	}
	// Source checkouts and unmanaged raw archives use the developer's Python.
	// Managed installations use a fixed admitted interpreter, never PATH.
	if !managedCompilerRuntime() {
		return "python3", nil
	}
	return installedPythonInterpreter()
}

func managedCompilerRuntime() bool {
	return managed.IsManagedEnterprise(managed.PinnedDeploymentMode()) || managed.IsStandaloneManagedHost()
}

func trustedDirectory(dir, base string) bool {
	for ; ; dir = filepath.Dir(dir) {
		resolved, err := filepath.EvalSymlinks(dir)
		if err != nil || resolved != dir {
			return false
		}
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() || writableByOthers(info) {
			return false
		}
		if dir == base {
			return true
		}
		if dir == filepath.Dir(dir) {
			return false
		}
	}
}

// homeInstallerRoot resolves the same per-user data directory used by config
// loading. A daemon launched without DEFENSECLAW_HOME still finds the
// installer under the user's default ~/.defenseclaw directory.
func homeInstallerRoot() string {
	home := config.DefaultDataPath()
	if !filepath.IsAbs(home) {
		return ""
	}
	return filepath.Clean(home)
}

// homeInstallerCompilerPath identifies the compiler atomically installed with
// the per-user gateway. It is accepted only under the actual private home.
func homeInstallerCompilerPath() string {
	home := homeInstallerRoot()
	if home == "" {
		return ""
	}
	candidate := filepath.Join(home, "installer", "policy_compiler.py")
	if !trustedCompilerFile(candidate, home) {
		return ""
	}
	return candidate
}

// defaultCompilerPath selects the compiler shipped with the source build,
// installed under DEFENSECLAW_HOME, or installed beside the gateway prefix.
func defaultCompilerPath() string {
	if !managedCompilerRuntime() {
		if source := sourceCompilerPath(); source != "" {
			return source
		}
		if homeCompiler := homeInstallerCompilerPath(); homeCompiler != "" {
			return homeCompiler
		}
	}
	for _, candidate := range installedCompilerPaths() {
		if trustedCompilerFile(candidate, filepath.Dir(filepath.Dir(filepath.Dir(candidate)))) {
			return candidate
		}
	}
	return installedCompilerPath
}

// installedCompilerPaths includes only compiler locations under the running
// executable's own installation prefix.
func installedCompilerPaths() []string {
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			prefix := filepath.Dir(filepath.Dir(resolved))
			paths := make([]string, 0, 2)
			for _, libdir := range []string{"lib", "lib64"} {
				paths = append(paths, filepath.Join(prefix, libdir, "defenseclaw", "policy_compiler.py"))
			}
			return paths
		}
	}
	return nil
}

// isUnderAllowedDir checks the resolved path against installed/home locations
// and the exact compiler beside the running source-checkout gateway binary.
func isUnderAllowedDir(abs string) bool {
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return false
	}
	absPath, err := filepath.Abs(resolved)
	if err != nil {
		return false
	}
	if !managedCompilerRuntime() {
		if source := sourceCompilerPath(); source != "" {
			if resolvedSource, err := filepath.EvalSymlinks(source); err == nil && absPath == resolvedSource {
				return true
			}
		}
		if homeCompiler := homeInstallerCompilerPath(); homeCompiler != "" && absPath == homeCompiler {
			return true
		}
	}
	for _, installed := range installedCompilerPaths() {
		base := filepath.Dir(filepath.Dir(filepath.Dir(installed)))
		if trustedCompilerFile(installed, base) && absPath == installed {
			return true
		}
	}
	if managedCompilerRuntime() {
		return false
	}

	allowed := []string{
		"/usr/local/lib/defenseclaw/",
		"/usr/local/lib64/defenseclaw/",
		"/usr/lib/defenseclaw/",
		"/usr/lib64/defenseclaw/",
	}

	if home, err := os.UserHomeDir(); err == nil {
		allowed = append(allowed, filepath.Join(home, ".defenseclaw")+string(filepath.Separator))
	}
	if dclawHome := os.Getenv("DEFENSECLAW_HOME"); dclawHome != "" {
		allowed = append(allowed, dclawHome+string(filepath.Separator))
	}

	for _, d := range allowed {
		resolvedDir, err := filepath.EvalSymlinks(d)
		if err != nil {
			continue
		}
		absDir, err := filepath.Abs(resolvedDir)
		if err != nil {
			continue
		}
		if strings.HasPrefix(absPath, absDir+string(filepath.Separator)) || absPath == absDir {
			return true
		}
	}
	return false
}

// Compile invokes the Python policy compiler to transform YAML policy bytes
// into the binary blob format expected by the C-side OTA receiver.
//
// The compiler is called as:
//
//	python3 policy_compiler.py --input <tmpfile> --profile <profile> --version <version> --output-binary <outfile>
//
// Returns the raw binary blob (header + payload, no signature).
func (s *Service) Compile(yamlBytes []byte, profile string, version uint32) ([]byte, error) {
	return s.compile(yamlBytes, profile, version, compileSlotWait)
}

func (s *Service) compile(yamlBytes []byte, profile string, version uint32, slotWait time.Duration) ([]byte, error) {
	// Version zero is a dry-run compiler input used by /policy/simulate; it
	// is never signed or stored as an OTA policy.
	if version > maxPolicyVersion {
		return nil, ErrPolicyVersionExhausted
	}
	if s.compilerPath == "" {
		return nil, errors.New("policy compiler path not configured")
	}

	if len(yamlBytes) > 65536 {
		return nil, ErrPolicyTooLarge
	}

	// Validate profile
	switch profile {
	case "minimal", "standard", "edge":
		// ok
	default:
		return nil, fmt.Errorf("%w: unknown profile %q: must be minimal, standard, or edge", ErrInvalidPolicy, profile)
	}

	absPath := s.compilerPath
	if !filepath.IsAbs(absPath) {
		return nil, fmt.Errorf("compiler path %q is not absolute", absPath)
	}
	if strings.Contains(absPath, "..") {
		return nil, fmt.Errorf("compiler path must not contain '..'")
	}
	info, err := os.Stat(absPath)
	if err != nil {
		return nil, fmt.Errorf("compiler not found: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("compiler path is not a regular file: %s", absPath)
	}
	if !isUnderAllowedDir(absPath) {
		return nil, fmt.Errorf("compiler path %q is not an approved installed, private-home, or source-checkout compiler", absPath)
	}
	// Bound concurrent compiler work (interpreter checks and the compile
	// itself); any authenticated tenant can trigger it via /policy/simulate.
	if s.compileSlots != nil {
		timer := time.NewTimer(slotWait)
		select {
		case s.compileSlots <- struct{}{}:
			timer.Stop()
			defer func() { <-s.compileSlots }()
		case <-timer.C:
			return nil, ErrCompilerBusy
		}
	}
	python, err := pythonForCompiler(absPath)
	if err != nil {
		return nil, err
	}

	// Create temp directory for compiler I/O
	tmpDir, err := makeTempDir()
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}
	defer removeAll(tmpDir)

	inputPath := filepath.Join(tmpDir, "policy.yaml")
	outputPath := filepath.Join(tmpDir, "policy.bin")

	if err := writeFile(inputPath, yamlBytes); err != nil {
		return nil, fmt.Errorf("write temp policy: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, "-I", absPath,
		"--input", filepath.Base(inputPath),
		"--profile", profile,
		"--version", fmt.Sprintf("%d", version),
		"--output-binary", filepath.Base(outputPath),
		"--output-header", "policy_tables.h",
	)
	cmd.Dir = tmpDir
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"LANG=C.UTF-8",
		"TMPDIR=" + os.TempDir(),
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 65 {
			return nil, fmt.Errorf("%w: policy compiler rejected input: %s", ErrMalformedPolicy, output)
		}
		return nil, fmt.Errorf("policy compiler failed: %w\noutput: %s", err, output)
	}

	blob, err := readFile(filepath.Join(tmpDir, filepath.Base(outputPath)))
	if err != nil {
		return nil, fmt.Errorf("read compiled policy: %w", err)
	}

	// Strip the dev-stub signature appended by policy_compiler.py when no
	// signing key is available. Format: [0x00, 0xDE, 0xED, SHA-256(blob)..., zeros].
	// Detection: blob[stubStart] == 0x00 && [1]==0xDE && [2]==0xED && SHA-256 match.
	const devStubSize = 64
	if len(blob) >= HeaderSize+devStubSize {
		stubStart := len(blob) - devStubSize
		if blob[stubStart] == 0x00 && blob[stubStart+1] == 0xDE && blob[stubStart+2] == 0xED {
			unsigned := blob[:stubStart]
			h := sha256Sum(unsigned)
			if bytes.Equal(blob[stubStart+3:stubStart+35], h[:32]) {
				s.logger.Printf("[policy] stripping 64-byte dev stub from compiler output")
				blob = blob[:stubStart]
			}
		}
	}

	// Validate the header
	if _, err := ParseHeader(blob); err != nil {
		return nil, fmt.Errorf("compiled blob has invalid header: %w", err)
	}

	s.logger.Printf("[policy] compiled %d-byte blob (version=%d, profile=%s)", len(blob), version, profile)
	return blob, nil
}

// Sign creates a signed policy blob by appending an HMAC-SHA256 signature
// to the raw policy binary. The signed format matches what the C-side
// mqtt_client.c OTA handler expects:
//
//	Total signed blob layout:
//	  [0:8]         header  (dclaw_policy_header_t, big-endian)
//	  [8:8+N]       payload (N = header.payload_len)
//	  [8+N:8+N+64]  signature field (64 bytes)
//
//	Signature field breakdown:
//	  [0:32]  HMAC-SHA256(key, header+payload)
//	  [32:64] zero padding (reserved for Ed25519 slot)
//
//	C-side split (mqtt_client.c line ~547):
//	  blob_len  = total - 64
//	  signature = blob + blob_len
//	  dclaw_apply_policy(blob, blob_len, signature)
//
//	C-side verify (ota_receiver.c):
//	  HMAC-SHA256(ota_key, blob[0:blob_len]) compared to signature[0:32]
func (s *Service) Sign(policyBin []byte) ([]byte, error) {
	if len(policyBin) < HeaderSize {
		return nil, errors.New("policy binary too short to sign")
	}

	// Validate that header.payload_len matches the actual payload size.
	// Without this check, a malformed blob could pass signing but be
	// rejected by the C-side apply_policy length validation.
	hdr, err := ParseHeader(policyBin)
	if err != nil {
		return nil, fmt.Errorf("parse header before signing: %w", err)
	}
	expectedBlobLen := HeaderSize + int(hdr.PayloadLen)
	if expectedBlobLen != len(policyBin) {
		return nil, fmt.Errorf("header.payload_len (%d) does not match blob size (%d): expected blob_len=%d",
			hdr.PayloadLen, len(policyBin), expectedBlobLen)
	}

	if s.signer == nil {
		return nil, errors.New("policy signer not configured — set DCLAW_OTA_HMAC_KEY")
	}
	sig, err := s.signer.Sign(policyBin)
	if err != nil {
		return nil, fmt.Errorf("sign policy: %w", err)
	}

	// Append exactly 64 bytes: 32-byte HMAC-SHA256 + 32 bytes zero
	// padding, matching the C-side 64-byte signature field.
	const sigFieldSize = 64
	signed := make([]byte, len(policyBin)+sigFieldSize)
	copy(signed, policyBin)
	n := len(sig)
	if n > 32 {
		n = 32
	}
	copy(signed[len(policyBin):], sig[:n])
	// signed[len(policyBin)+32 : len(policyBin)+64] stays zero — Ed25519 padding
	return signed, nil
}

// Distribute publishes a signed policy blob to the fleet's OTA topic via MQTT.
// Topic format: defenseclaw/{tenant}/{fleet}/ota/policy
func (s *Service) Distribute(ctx context.Context, tenantID, fleetID uint64, signedPolicy []byte) error {
	if s.client == nil {
		return errors.New("MQTT not configured")
	}
	if len(signedPolicy) < HeaderSize+32 {
		return errors.New("signed policy too short")
	}

	topic := fmt.Sprintf("defenseclaw/%d/%d/ota/policy", tenantID, fleetID)

	if err := s.client.Publish(ctx, topic, 1, signedPolicy); err != nil {
		return fmt.Errorf("MQTT publish to %s: %w", topic, err)
	}

	// Parse version from the blob header for logging
	hdr, _ := ParseHeader(signedPolicy)
	if hdr != nil {
		s.logger.Printf("[policy] distributed version=%d to %s (%d bytes)", hdr.Version, topic, len(signedPolicy))
	}

	return nil
}

// DistributeEmergency publishes an emergency command to the fleet.
// Topic format: defenseclaw/{tenant}/{fleet}/ota/emergency
//
// The wire format matches dclaw_emergency_msg_t in ota_receiver.c:
//
//	[0:4]   sequence    uint32  (big-endian, strictly increasing)
//	[4:8]   timestamp   uint32  (big-endian, Unix epoch)
//	[8]     command     uint8
//	[9]     scope       uint8   (0 = fleet-wide)
//	[10:42] payload     [32]byte (zeros for now)
//	[42:44] _reserved   [2]byte
//	[44:48]  prior sequence in this fleet (uint32 big-endian)
//	[48:112] signature [64]byte (HMAC-SHA256 in first 32, zero-padded)
func (s *Service) DistributeEmergency(ctx context.Context, tenantID, fleetID uint64, cmd EmergencyCommand) error {
	if s.client == nil {
		return errors.New("MQTT not configured")
	}
	if s.store == nil {
		return errors.New("policy store not configured for durable emergency delivery")
	}
	if s.emergencySigner == nil {
		return errors.New("emergency signer not configured — set DCLAW_EMERGENCY_KEY")
	}

	s.emergencyMu.Lock()
	defer s.emergencyMu.Unlock()
	if s.emergencyErr != nil {
		return s.emergencyErr
	}

	if s.emergencySeq == ^uint32(0) {
		return errors.New("emergency sequence counter exhausted (uint32 overflow)")
	}
	seq := s.emergencySeq + 1

	// Build the message: 48 bytes of data + 64-byte signature field = 112 bytes.
	// The signature field holds 32 bytes of HMAC-SHA256 followed by 32 bytes of
	// zero padding, matching the C-side dclaw_emergency_msg_t which reserves a
	// 64-byte Ed25519 signature field.
	msg := make([]byte, EmergencyMsgSize)

	// Sequence (big-endian)
	binary.BigEndian.PutUint32(msg[0:4], seq)

	// Timestamp (big-endian)
	binary.BigEndian.PutUint32(msg[4:8], uint32(time.Now().Unix()))

	// Command
	msg[8] = uint8(cmd)

	// Scope: 0 = fleet-wide
	msg[9] = 0

	// Payload [10:42] and reserved [42:44] are zero-filled. A signed
	// predecessor links this command to the previous one in its fleet, so a
	// device cannot miss BLOCK_ALL then accept a later FORCE_SYNC.
	previous, err := s.store.GetLastEmergency(tenantID, fleetID)
	if err != nil {
		return fmt.Errorf("read emergency predecessor: %w", err)
	}
	if previous != nil {
		binary.BigEndian.PutUint32(msg[44:48], previous.Sequence)
	}

	// Sign the first 48 bytes of the emergency message (everything before
	// the 64-byte signature field). The C verifier passes exactly msg[0:48]
	// to verify_emergency_signature(), so the HMAC input MUST match.
	sig, err := s.emergencySigner.Sign(msg[:48])
	if err != nil {
		return fmt.Errorf("sign emergency msg: %w", err)
	}

	// Copy HMAC-SHA256 (32 bytes) into the first half of the 64-byte signature
	n := 32
	if len(sig) < n {
		n = len(sig)
	}
	copy(msg[48:48+n], sig[:n])

	// Bytes 80-112 are zero-padded (reserved for Ed25519 signature).

	topic := fmt.Sprintf("defenseclaw/%d/%d/ota/emergency", tenantID, fleetID)

	if err := s.store.SaveEmergency(tenantID, fleetID, seq, msg); err != nil {
		return fmt.Errorf("persist emergency sequence %d and command: %w", seq, err)
	}
	s.emergencySeq = seq

	if err := s.client.Publish(ctx, topic, 1, msg); err != nil {
		return fmt.Errorf("MQTT publish emergency to %s: %w", topic, err)
	}

	s.logger.Printf("[policy] emergency cmd=%d seq=%d distributed to %s", cmd, seq, topic)
	return nil
}

// ReplayLatestForDevice repairs a clean-session device's missed OTA messages.
// A broker PUBACK confirms only broker receipt. The signed heartbeat reports
// the device's installed policy version and durable last emergency sequence.
// At most 32 emergency commands are sent per call; subsequent heartbeats
// request the next page after the device has actually applied those commands.
func (s *Service) ReplayLatestForDevice(ctx context.Context, tenantID, fleetID uint64, devicePolicyVersion uint16, deviceEmergencySeq uint32) (uint32, error) {
	if s.store == nil || s.client == nil {
		return deviceEmergencySeq, nil
	}
	latest, err := s.store.GetLatestPolicy(tenantID, fleetID)
	if err != nil {
		return deviceEmergencySeq, fmt.Errorf("read latest policy for replay: %w", err)
	}
	if latest != nil && latest.Version > uint32(devicePolicyVersion) && s.beginPolicyReplay(tenantID, fleetID, latest.Version) {
		published := false
		defer func() { s.completePolicyReplay(tenantID, fleetID, latest.Version, published) }()
		if len(latest.PolicyBin) < HeaderSize || len(latest.Signature) != 64 {
			return deviceEmergencySeq, fmt.Errorf("stored policy version %d has invalid signed content", latest.Version)
		}
		hdr, err := ParseHeader(latest.PolicyBin)
		if err != nil || uint32(hdr.Version) != latest.Version {
			return deviceEmergencySeq, fmt.Errorf("stored policy version %d has mismatched header", latest.Version)
		}
		signed := make([]byte, 0, len(latest.PolicyBin)+len(latest.Signature))
		signed = append(signed, latest.PolicyBin...)
		signed = append(signed, latest.Signature...)
		if err := s.Distribute(ctx, tenantID, fleetID, signed); err != nil {
			return deviceEmergencySeq, fmt.Errorf("replay policy version %d: %w", latest.Version, err)
		}
		published = true
		s.logger.Printf("[policy] replayed version=%d for lagging device (reported=%d)", latest.Version, devicePolicyVersion)
	}
	if !s.beginEmergencyReplay(tenantID, fleetID, deviceEmergencySeq) {
		return deviceEmergencySeq, nil
	}
	lastPublished := deviceEmergencySeq
	completed := false
	defer func() {
		s.completeEmergencyReplay(tenantID, fleetID, deviceEmergencySeq, lastPublished, completed)
	}()
	records, err := s.store.GetEmergenciesAfter(tenantID, fleetID, deviceEmergencySeq, 32)
	if err != nil {
		return deviceEmergencySeq, fmt.Errorf("read emergency history for replay: %w", err)
	}
	topic := fmt.Sprintf("defenseclaw/%d/%d/ota/emergency", tenantID, fleetID)
	for _, record := range records {
		if err := s.client.Publish(ctx, topic, 1, record.Message); err != nil {
			return lastPublished, fmt.Errorf("replay emergency sequence %d: %w", record.Sequence, err)
		}
		lastPublished = record.Sequence
		s.logger.Printf("[policy] replayed emergency seq=%d to %s", record.Sequence, topic)
	}
	completed = true
	return lastPublished, nil
}

// beginEmergencyReplay admits an emergency catch-up pass for a device that
// last applied afterSeq, unless a pass is already running for the fleet, a
// recent pass already republished the commands after afterSeq, or the
// fleet's per-window pass budget is spent. A skipped device retries on a
// later heartbeat.
func (s *Service) beginEmergencyReplay(tenantID, fleetID uint64, afterSeq uint32) bool {
	key := fleetKey(tenantID, fleetID)
	now := time.Now()
	s.emergencyReplayMu.Lock()
	defer s.emergencyReplayMu.Unlock()
	st := s.emergencyReplays[key]
	if st == nil {
		st = &emergencyReplayState{}
		s.emergencyReplays[key] = st
	}
	live := st.passes[:0]
	for _, p := range st.passes {
		if now.Sub(p.at) < emergencyReplayCooldown {
			live = append(live, p)
		}
	}
	st.passes = live
	if st.inFlight {
		return false
	}
	for _, p := range st.passes {
		if p.after <= afterSeq && afterSeq < p.last {
			return false
		}
	}
	if len(st.passes) >= maxEmergencyReplaysPerWindow {
		return false
	}
	st.inFlight = true
	return true
}

// completeEmergencyReplay records a finished pass. A failed pass is not
// recorded, so the next heartbeat retries it.
func (s *Service) completeEmergencyReplay(tenantID, fleetID uint64, afterSeq, lastSeq uint32, completed bool) {
	key := fleetKey(tenantID, fleetID)
	s.emergencyReplayMu.Lock()
	defer s.emergencyReplayMu.Unlock()
	st := s.emergencyReplays[key]
	if st == nil {
		return
	}
	st.inFlight = false
	if completed && lastSeq > afterSeq {
		st.passes = append(st.passes, emergencyReplayPass{after: afterSeq, last: lastSeq, at: time.Now()})
	}
	if len(st.passes) == 0 {
		delete(s.emergencyReplays, key)
	}
}

// One stale or compromised device can otherwise force a fleet-wide policy
// broadcast for every signed registration with increasing uptime. A new
// version bypasses the cooldown, while retries after a publish failure do too.
func (s *Service) beginPolicyReplay(tenantID, fleetID uint64, version uint32) bool {
	key := fleetKey(tenantID, fleetID)
	s.policyReplayMu.Lock()
	defer s.policyReplayMu.Unlock()
	last := s.policyReplays[key]
	if last.version == version && (last.inFlight || time.Since(last.at) < 30*time.Second) {
		return false
	}
	s.policyReplays[key] = policyReplayAttempt{version: version, inFlight: true}
	return true
}

func (s *Service) completePolicyReplay(tenantID, fleetID uint64, version uint32, published bool) {
	key := fleetKey(tenantID, fleetID)
	s.policyReplayMu.Lock()
	defer s.policyReplayMu.Unlock()
	if !published {
		delete(s.policyReplays, key)
		return
	}
	s.policyReplays[key] = policyReplayAttempt{version: version, at: time.Now()}
}

// CompileSignAndStore is a convenience method that compiles a YAML policy,
// signs it, stores the result, and returns the signed blob ready for distribution.
func (s *Service) CompileSignAndStore(yamlBytes []byte, profile string, tenantID, fleetID uint64) ([]byte, uint32, error) {
	s.policyMu.Lock()
	defer s.policyMu.Unlock()

	if s.signer == nil {
		return nil, 0, errors.New("policy signer not configured — set DCLAW_OTA_HMAC_KEY")
	}

	// Determine version from latest stored policy
	latest, err := s.store.GetLatestPolicy(tenantID, fleetID)
	if err != nil {
		return nil, 0, fmt.Errorf("get latest policy: %w", err)
	}

	var version uint32 = 1
	if latest != nil {
		if latest.Version >= maxPolicyVersion {
			return nil, 0, ErrPolicyVersionExhausted
		}
		version = latest.Version + 1
	}

	// Compile
	blob, err := s.compile(yamlBytes, profile, version, pushCompileSlotWait)
	if err != nil {
		return nil, 0, fmt.Errorf("compile: %w", err)
	}

	// Sign
	signed, err := s.Sign(blob)
	if err != nil {
		return nil, 0, fmt.Errorf("sign: %w", err)
	}

	// Store
	sig := signed[len(blob):]
	if err := s.store.SavePolicy(tenantID, fleetID, version, blob, sig, profile); err != nil {
		return nil, 0, fmt.Errorf("store: %w", err)
	}

	return signed, version, nil
}

// Store returns the policy store for direct queries (e.g., listing versions).
func (s *Service) Store() PolicyStore {
	return s.store
}

// BuildPolicyBlob manually constructs a policy binary blob matching the
// C-side format. Used only in tests.
//
// The blob format matches generate_binary_blob() in policy_compiler.py:
//
//	Header (8 bytes, big-endian):
//	  [0:2] version
//	  [2:4] payload_len
//	  [4:6] canary_baseline
//	  [6:8] reserved (0x0000)
//	Payload:
//	  Severity rules, sequence rules, etc.
func BuildPolicyBlob(version uint16, canaryBaseline uint16, payload []byte) []byte {
	if len(payload) > 65535 {
		panic("BuildPolicyBlob: payload exceeds uint16 max (65535 bytes)")
	}
	header := make([]byte, HeaderSize)
	binary.BigEndian.PutUint16(header[0:2], version)
	binary.BigEndian.PutUint16(header[2:4], uint16(len(payload)))
	binary.BigEndian.PutUint16(header[4:6], canaryBaseline)
	// [6:8] reserved, zero

	return append(header, payload...)
}
