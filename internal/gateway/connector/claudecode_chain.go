// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/hookguard"
	"github.com/defenseclaw/defenseclaw/internal/hookruntime"
	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

const claudeChainGuardName = "defenseclaw-hook-guard.exe"
const claudeChainApprovedName = "defenseclaw-hook-guard.approved"
const claudeChainMaxGuardBytes = 64 << 20

var claudeChainMu sync.Mutex

// claudeChainDir is outside the replaceable install tree. A registered
// command stays valid while the installer swaps its binaries.
var claudeChainDir = func() string {
	if runtime.GOOS != "windows" {
		return ""
	}
	paths, err := hookruntime.CurrentUserPaths()
	if err != nil {
		return ""
	}
	return filepath.Join(paths.Root, "claude-code-chain")
}

type claudeChainFiles struct{ guard, approved, record string }

func claudeChainFilesIn(dir string) claudeChainFiles {
	return claudeChainFiles{
		guard: filepath.Join(dir, claudeChainGuardName), approved: filepath.Join(dir, claudeChainApprovedName),
		record: filepath.Join(dir, "chain.json"),
	}
}

type claudeChainRecord struct {
	Launcher string `json:"launcher"`
	Digest   string `json:"guard_sha256"`
}

func readClaudeChainRecord(files claudeChainFiles) (claudeChainRecord, bool) {
	var record claudeChainRecord
	file, err := os.Open(files.record)
	if err != nil {
		return record, false
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 64<<10+1))
	if err != nil || len(data) > 64<<10 || json.Unmarshal(data, &record) != nil ||
		!hookguard.AbsoluteHookExecutable(record.Launcher) || len(record.Digest) != 64 {
		return claudeChainRecord{}, false
	}
	if _, err := hex.DecodeString(record.Digest); err != nil {
		return claudeChainRecord{}, false
	}
	return record, true
}

func claudeWrapperSafe(path string) bool {
	if !hookguard.Guardable(path) || !hookguard.IsWindowsAbsolutePath(path) && !filepath.IsAbs(path) {
		return false
	}
	// Go quotes arguments with whitespace. An unquoted shell metacharacter
	// would otherwise be read by cmd.exe as a separator or redirection.
	return strings.ContainsAny(path, " \t") || !strings.ContainsAny(path, "&|<>^(),;=")
}

// claudeChainSource selects the small guard installed with either supported
// Windows layout. A custom hook layout without it keeps its released form.
var claudeChainSource = func(launcher string) string {
	if !hookguard.AbsoluteHookExecutable(launcher) {
		return ""
	}
	candidates := []string{filepath.Join(filepath.Dir(launcher), windowsHookGuardBinaryName)}
	if stable, installed := canonicalNativeWindowsHookBinary(), canonicalNativeWindowsInstalledHookBinary(); stable != "" && installed != "" && pathidentity.Same(launcher, stable) {
		// Packaged installs ship this distinct small program in their signed
		// inventory. A spare file beside HookRuntime's stable launcher is not
		// the installer source for this layout.
		candidates = []string{filepath.Join(filepath.Dir(installed), windowsHookGuardBinaryName)}
	}
	for _, candidate := range candidates {
		if info, err := os.Lstat(candidate); err == nil && info.Mode().IsRegular() && info.Size() <= claudeChainMaxGuardBytes {
			return candidate
		}
	}
	return ""
}

func claudeFileDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > claudeChainMaxGuardBytes {
		return "", fmt.Errorf("the guard copy is not a regular file of supported size")
	}
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func claudeFileMatches(path, digest string) bool {
	got, err := claudeFileDigest(path)
	return err == nil && strings.EqualFold(got, digest)
}

func writeClaudeChainFile(path string, body []byte) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".claude-chain-*.exe")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if _, err := temp.Write(body); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := safefile.ProtectFile(temp.Name()); err != nil {
		return err
	}
	return safefile.ReplaceFileAtomically(temp.Name(), path)
}

// claudeChainProbe verifies the exact bytes that will be installed, before a
// new chain becomes a registered command. Tests replace it with a fixture.
var claudeChainProbe = func(program, dir string) error {
	absent := filepath.Join(dir, "absent", windowsHookBinaryName)
	for _, check := range []struct {
		args    []string
		code    int
		message string
	}{
		{claudeGuardEventArgs(absent, []string{"hook", "--connector", "claudecode"}, "PreToolUse", false), 2, hookguard.MissingMessage},
		{claudeGuardEventArgs(absent, []string{"hook", "--connector", "claudecode"}, "UserPromptSubmit", true), 2, hookguard.MissingMessage},
		{claudeGuardEventArgs(absent, []string{"hook", "--connector", "claudecode"}, "Stop", true), hookguard.WrappedExitBase + 1, hookguard.NonBlockingExitMessage},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cmd := exec.CommandContext(ctx, program, check.args...)
		cmd.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse"}`)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		cancel()
		if cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != check.code || stdout.Len() != 0 ||
			strings.TrimSpace(stderr.String()) != check.message {
			return fmt.Errorf("guard did not give the expected unavailable answer: %v", err)
		}
	}
	return nil
}

// ensureClaudeChain publishes a guard and a separate approved copy before
// Setup writes the wrapper. A bad new source never replaces a working chain.
func ensureClaudeChain(launcher string) error {
	dir := claudeChainDir()
	if dir == "" || !claudeWrapperSafe(launcher) {
		return nil
	}
	files := claudeChainFilesIn(dir)
	if !claudeWrapperSafe(files.guard) || !claudeWrapperSafe(files.approved) {
		return fmt.Errorf("the Claude Code hook chain path cannot be rendered by cmd.exe")
	}
	claudeChainMu.Lock()
	defer claudeChainMu.Unlock()
	if err := safefile.ProtectDirectory(dir); err != nil {
		return fmt.Errorf("protect Claude Code hook chain: %w", err)
	}
	record, present := readClaudeChainRecord(files)
	if present && !pathidentity.Same(record.Launcher, launcher) {
		present = false
	}
	source := claudeChainSource(launcher)
	if source == "" {
		if present && claudeFileMatches(files.approved, record.Digest) {
			return restoreClaudeChainGuard(files, record.Digest)
		}
		if stable := canonicalNativeWindowsHookBinary(); stable != "" && pathidentity.Same(launcher, stable) {
			return fmt.Errorf("the packaged Claude Code hook guard is unavailable; run the DefenseClaw installer again")
		}
		return nil
	}
	info, err := os.Lstat(source)
	if err != nil || !info.Mode().IsRegular() || info.Size() > claudeChainMaxGuardBytes {
		return fmt.Errorf("the installed Claude Code guard is unavailable; run the DefenseClaw installer again")
	}
	body, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf("read installed Claude Code guard: %w", err)
	}
	if len(body) == 0 || len(body) > claudeChainMaxGuardBytes {
		return fmt.Errorf("the installed Claude Code guard is not a regular file of supported size")
	}
	digest := sha256.Sum256(body)
	want := hex.EncodeToString(digest[:])
	if present && strings.EqualFold(record.Digest, want) && claudeFileMatches(files.approved, want) {
		return restoreClaudeChainGuard(files, want)
	}
	staged := filepath.Join(dir, ".claude-chain-probe-"+strconv.FormatInt(time.Now().UnixNano(), 10)+".exe")
	if err := writeClaudeChainFile(staged, body); err != nil {
		return fmt.Errorf("stage Claude Code guard: %w", err)
	}
	defer os.Remove(staged)
	if err := claudeChainProbe(staged, dir); err != nil {
		if present && claudeFileMatches(files.approved, record.Digest) {
			return restoreClaudeChainGuard(files, record.Digest)
		}
		return fmt.Errorf("installed Claude Code guard cannot start; run the DefenseClaw installer again: %w", err)
	}
	if err := writeClaudeChainFile(files.approved, body); err != nil {
		return fmt.Errorf("publish approved Claude Code guard: %w", err)
	}
	if err := writeClaudeChainFile(files.guard, body); err != nil {
		return fmt.Errorf("publish Claude Code guard: %w", err)
	}
	encoded, err := json.Marshal(claudeChainRecord{Launcher: launcher, Digest: want})
	if err != nil {
		return err
	}
	return writeClaudeChainFile(files.record, append(encoded, '\n'))
}

// EnsureClaudeCodeChain restores the registered per-user guard from its
// approved copy. The gateway's existing hook audit calls it while Claude Code
// is active, so a missing guard is repaired without changing hook settings.
func EnsureClaudeCodeChain(opts SetupOpts) error {
	if runtime.GOOS != "windows" || opts.ManagedEnterprise {
		return nil
	}
	launcher := strings.TrimSpace(opts.HookExecutable)
	if launcher == "" {
		launcher = defenseclawHookBinary()
	}
	return ensureClaudeChain(launcher)
}

func restoreClaudeChainGuard(files claudeChainFiles, digest string) error {
	if claudeFileMatches(files.guard, digest) {
		return nil
	}
	body, err := os.ReadFile(files.approved)
	if err != nil {
		return err
	}
	return writeClaudeChainFile(files.guard, body)
}

// claudeChainFor returns the recorded chain even when one file disappeared:
// the registered wrapper must report that failure instead of falling back to
// the older launcher-only form.
var claudeChainFor = func(launcher string) (guard, approved string) {
	dir := claudeChainDir()
	if dir == "" || !claudeWrapperSafe(launcher) {
		return "", ""
	}
	files := claudeChainFilesIn(dir)
	record, ok := readClaudeChainRecord(files)
	if !ok || !pathidentity.Same(record.Launcher, launcher) ||
		!claudeWrapperSafe(files.guard) || !claudeWrapperSafe(files.approved) {
		return "", ""
	}
	return files.guard, files.approved
}

func claudeGuardEventArgs(launcher string, hookArgs []string, event string, wrapped bool) []string {
	command := hookguard.Subcommand
	if wrapped {
		command = hookguard.WrappedSubcommand
	}
	args := append([]string{command, launcher}, hookArgs...)
	return append(args, "--event", event)
}

func claudeGuardCompareProgram() string {
	return strings.TrimRight(windowsSystemDirectory(), `\/`) + `\fc.exe`
}

func claudeGuardWrapperArgs(guard, approved, launcher, event string, hookArgs []string) []string {
	code := "2"
	if hookguard.NeutralEvent(event) {
		code = "1"
	}
	return claudeGuardWrapperArgsWith(claudeGuardCompareProgram(), guard, approved, launcher, event, hookArgs, code)
}

func claudeGuardWrapperArgsWith(compare, guard, approved, launcher, event string, hookArgs []string, failCode string) []string {
	warning := []string{"echo", "DefenseClaw", "could", "not", "start", "its", "Claude", "Code", "hook", "guard.",
		"Run", "the", "DefenseClaw", "installer", "again", "to", "repair", "it.", "1>&2", "&", "exit", "/b", failCode}
	fail := func() []string { return append([]string(nil), warning...) }
	args := []string{"/d", "/v:on", "/c", "if", "not", "exist", guard, "("}
	args = append(args, fail()...)
	args = append(args, ")", "&", compare, "/b", guard, approved, ">nul", "2>&1", "||", "(")
	args = append(args, fail()...)
	args = append(args, ")", "&", guard)
	args = append(args, claudeGuardEventArgs(launcher, hookArgs, event, true)...)
	args = append(args,
		"&", "set", "dc_hook_status=!errorlevel!",
		"&", "if", "!dc_hook_status!", "equ", "0", "exit", "/b", "0",
		"&", "if", "!dc_hook_status!", "equ", "2", "exit", "/b", "2",
		"&", "if", "!dc_hook_status!", "geq", strconv.Itoa(hookguard.WrappedExitBase+1),
		"if", "!dc_hook_status!", "leq", strconv.Itoa(2*hookguard.WrappedExitBase-1),
		"(", "set", "/a", "dc_hook_result=!dc_hook_status!-"+strconv.Itoa(hookguard.WrappedExitBase), ">nul",
		"&", "exit", "/b", "!dc_hook_result!", ")", "&")
	return append(args, fail()...)
}

func claudeGuardWrapperParts(hook map[string]interface{}) (string, []string, bool) {
	command, _ := hook["command"].(string)
	if normalizeWindowsHookExecutable(command) != normalizeWindowsHookExecutable(claudeCodeWindowsCommandProcessor()) {
		return "", nil, false
	}
	args, ok := claudeCodeNativeExecArguments(hook)
	if !ok || len(args) < 20 || !slices.Equal(args[:6], []string{"/d", "/v:on", "/c", "if", "not", "exist"}) {
		return "", nil, false
	}
	guard := args[6]
	if !claudeWrapperSafe(guard) || !strings.EqualFold(guard[strings.LastIndexAny(guard, `\/`)+1:], claudeChainGuardName) {
		return "", nil, false
	}
	compare, approved := claudeGuardCompareProgram(), ""
	for i := 8; i+3 < len(args); i++ {
		if normalizeWindowsHookExecutable(args[i]) == normalizeWindowsHookExecutable(compare) &&
			args[i+1] == "/b" && args[i+2] == guard {
			approved = args[i+3]
			break
		}
	}
	if !claudeWrapperSafe(approved) || !strings.EqualFold(approved[strings.LastIndexAny(approved, `\/`)+1:], claudeChainApprovedName) {
		return "", nil, false
	}
	for i := 0; i+7 < len(args); i++ {
		if args[i] != guard || args[i+1] != hookguard.WrappedSubcommand {
			continue
		}
		launcher, hookArgs, event, wrapped, valid := hookguard.ParseInvocation(args[i+1 : i+8])
		if !valid || !wrapped || !claudeWrapperSafe(launcher) {
			return "", nil, false
		}
		code := "2"
		if hookguard.NeutralEvent(event) {
			code = "1"
		}
		if slices.Equal(args, claudeGuardWrapperArgsWith(compare, guard, approved, launcher, event, hookArgs, code)) {
			return launcher, hookArgs, true
		}
	}
	return "", nil, false
}
