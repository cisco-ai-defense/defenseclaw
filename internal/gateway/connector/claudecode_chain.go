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
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

const claudeChainGuardName = "defenseclaw-hook-guard.exe"
const claudeChainApprovedName = "defenseclaw-hook-guard.approved"
const claudeChainMaxGuardBytes = 64 << 20

var claudeChainMu sync.Mutex
var claudeChainGatewayExecutable = os.Executable

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
	Launcher   string `json:"launcher"`
	Digest     string `json:"guard_sha256"`
	Generation string `json:"generation"`
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
		!hookguard.AbsoluteHookExecutable(record.Launcher) || len(record.Digest) != 64 ||
		!claudeChainGenerationName(record.Generation) {
		return claudeChainRecord{}, false
	}
	if _, err := hex.DecodeString(record.Digest); err != nil {
		return claudeChainRecord{}, false
	}
	return record, true
}

func claudeChainGenerationName(name string) bool {
	if !strings.HasPrefix(name, "chain-") || len(name) <= len("chain-") {
		return false
	}
	for _, c := range name[len("chain-"):] {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func claudeChainVersionFiles(root string, record claudeChainRecord) claudeChainFiles {
	return claudeChainFilesIn(filepath.Join(root, record.Generation))
}

func claudeWrapperSafe(path string) bool {
	if !hookguard.Guardable(path) || !hookguard.IsWindowsAbsolutePath(path) && !filepath.IsAbs(path) {
		return false
	}
	// Go quotes arguments with whitespace. An unquoted shell metacharacter
	// would otherwise be read by cmd.exe as a separator or redirection.
	return strings.ContainsAny(path, " \t") || !strings.ContainsAny(path, "&|<>^(),;=")
}

// claudeChainSource selects the guard to install; a test replaces it.
var claudeChainSource = claudeChainGuardSource

// claudeChainGuardSource selects the small guard installed with the launcher or
// the running gateway. A custom launcher may live outside the gateway's bin.
func claudeChainGuardSource(launcher string) string {
	if !hookguard.AbsoluteHookExecutable(launcher) {
		return ""
	}
	candidates := []string{filepath.Join(filepath.Dir(launcher), windowsHookGuardBinaryName)}
	if gateway, err := claudeChainGatewayExecutable(); err == nil && strings.EqualFold(filepath.Base(gateway), windowsGatewayBinaryName) {
		candidates = append(candidates, filepath.Join(filepath.Dir(gateway), windowsHookGuardBinaryName))
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
		{claudeGuardEventArgs(absent, []string{"hook", "--connector", "claudecode"}, "PreToolUse", false, true), 1, hookguard.OpenExitMessage},
		{claudeGuardEventArgs(absent, []string{"hook", "--connector", "claudecode"}, "UserPromptSubmit", true, true), hookguard.WrappedExitBase + 1, hookguard.OpenExitMessage},
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

// ensureClaudeChain publishes a new guard pair before Setup writes the wrapper.
// Existing registrations keep their pair throughout an update.
func ensureClaudeChain(launcher string) error {
	dir := claudeChainDir()
	if dir == "" {
		return nil
	}
	if !claudeWrapperSafe(launcher) {
		return fmt.Errorf("the Claude Code hook launcher path cannot be rendered by cmd.exe")
	}
	rootFiles := claudeChainFilesIn(dir)
	if !claudeWrapperSafe(rootFiles.guard) || !claudeWrapperSafe(rootFiles.approved) {
		return fmt.Errorf("the Claude Code hook chain path cannot be rendered by cmd.exe")
	}
	claudeChainMu.Lock()
	defer claudeChainMu.Unlock()
	if err := safefile.ProtectDirectory(dir); err != nil {
		return fmt.Errorf("protect Claude Code hook chain: %w", err)
	}
	record, present := readClaudeChainRecord(rootFiles)
	previousGeneration := ""
	if present {
		previousGeneration = record.Generation
	}
	if present && !pathidentity.Same(record.Launcher, launcher) {
		present = false
	}
	var files claudeChainFiles
	if present {
		files = claudeChainVersionFiles(dir, record)
	}
	source := claudeChainSource(launcher)
	if source == "" {
		if present && claudeFileMatches(files.approved, record.Digest) {
			return restoreProbedClaudeChainGuard(files, record.Digest, dir)
		}
		return fmt.Errorf("the Claude Code hook guard is unavailable; run the DefenseClaw installer again")
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
		return restoreProbedClaudeChainGuard(files, want, dir)
	}
	staged := filepath.Join(dir, ".claude-chain-probe-"+strconv.FormatInt(time.Now().UnixNano(), 10)+".exe")
	if err := writeClaudeChainFile(staged, body); err != nil {
		return fmt.Errorf("stage Claude Code guard: %w", err)
	}
	defer os.Remove(staged)
	if err := claudeChainProbe(staged, dir); err != nil {
		if present && claudeFileMatches(files.approved, record.Digest) {
			return restoreProbedClaudeChainGuard(files, record.Digest, dir)
		}
		return fmt.Errorf("installed Claude Code guard cannot start; run the DefenseClaw installer again: %w", err)
	}
	generation, reused := reuseClaudeChainFolder(dir, want, body)
	if !reused {
		versionDir, err := os.MkdirTemp(dir, "chain-")
		if err != nil {
			return fmt.Errorf("stage Claude Code guard pair: %w", err)
		}
		published := false
		defer func() {
			if !published {
				_ = os.RemoveAll(versionDir)
			}
		}()
		if err := safefile.ProtectDirectory(versionDir); err != nil {
			return fmt.Errorf("protect Claude Code guard pair: %w", err)
		}
		newFiles := claudeChainFilesIn(versionDir)
		if err := writeClaudeChainFile(newFiles.approved, body); err != nil {
			return fmt.Errorf("publish approved Claude Code guard: %w", err)
		}
		if err := writeClaudeChainFile(newFiles.guard, body); err != nil {
			return fmt.Errorf("publish Claude Code guard: %w", err)
		}
		generation = filepath.Base(versionDir)
		if err := writeClaudeChainRecord(rootFiles, launcher, want, generation); err != nil {
			return err
		}
		published = true
	} else if err := writeClaudeChainRecord(rootFiles, launcher, want, generation); err != nil {
		return err
	}
	pruneClaudeChain(dir, generation, previousGeneration)
	return nil
}

func writeClaudeChainRecord(rootFiles claudeChainFiles, launcher, digest, generation string) error {
	encoded, err := json.Marshal(claudeChainRecord{Launcher: launcher, Digest: digest, Generation: generation})
	if err != nil {
		return err
	}
	return writeClaudeChainFile(rootFiles.record, append(encoded, '\n'))
}

// claudeChainPruneGrace keeps a folder younger than this: another process
// (the CLI beside the gateway) may be publishing it and has not written the
// record yet.
var claudeChainPruneGrace = 10 * time.Minute

// claudeChainGenerations lists the chain-<n> folders of dir, newest first.
// A link or a file with such a name is not one.
func claudeChainGenerations(dir string) []os.DirEntry {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []os.DirEntry
	for _, e := range entries {
		if e.IsDir() && claudeChainGenerationName(e.Name()) {
			out = append(out, e)
		}
	}
	modified := func(e os.DirEntry) time.Time {
		if info, err := e.Info(); err == nil {
			return info.ModTime()
		}
		return time.Time{}
	}
	slices.SortStableFunc(out, func(a, b os.DirEntry) int { return modified(b).Compare(modified(a)) })
	return out
}

// reuseClaudeChainFolder finds a folder whose approved copy holds the guard
// with digest want, repairs its working copy if needed, and returns its name.
// Every upgrade, downgrade or rollback to a guard an earlier folder holds
// reuses it instead of writing a second 4.8 MB pair (GAP-1075).
func reuseClaudeChainFolder(dir, want string, body []byte) (string, bool) {
	for _, e := range claudeChainGenerations(dir) {
		files := claudeChainFilesIn(filepath.Join(dir, e.Name()))
		if !claudeFileMatches(files.approved, want) {
			continue
		}
		if !claudeFileMatches(files.guard, want) && writeClaudeChainFile(files.guard, body) != nil {
			continue
		}
		return e.Name(), true
	}
	return "", false
}

// claudeChainSettingsText is what the folders in use are read from: the user
// settings file Claude Code reads and the local one beside it. Setup writes
// the wrapper command into them after the chain is published, so at publish
// time they still name the folder the registered hooks run from.
var claudeChainSettingsText = func() string {
	path := claudeCodeSettingsPath()
	var text strings.Builder
	for _, p := range []string{path, filepath.Join(filepath.Dir(path), "settings.local.json")} {
		if data, err := os.ReadFile(p); err == nil && len(data) <= 8<<20 {
			text.Write(data)
		}
	}
	return text.String()
}

// pruneClaudeChain removes the chain-<n> folders nothing uses: it keeps the
// folder just recorded (current), the one the record named before it (the
// previous release's, for a rollback), every folder a settings file names and
// every folder younger than claudeChainPruneGrace. Best effort: a folder a
// running hook still holds open stays until a later publish.
func pruneClaudeChain(dir, current, previous string) {
	settings := claudeChainSettingsText()
	for _, e := range claudeChainGenerations(dir) {
		name := e.Name()
		if name == current || name == previous || strings.Contains(settings, name) {
			continue
		}
		if info, err := e.Info(); err != nil || time.Since(info.ModTime()) < claudeChainPruneGrace {
			continue
		}
		_ = os.RemoveAll(filepath.Join(dir, name))
	}
}

func restoreProbedClaudeChainGuard(files claudeChainFiles, digest, dir string) error {
	if err := restoreClaudeChainGuard(files, digest); err != nil {
		return err
	}
	if err := claudeChainProbe(files.guard, dir); err != nil {
		return fmt.Errorf("installed Claude Code guard cannot answer the current mode; run the DefenseClaw installer again: %w", err)
	}
	return nil
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
	rootFiles := claudeChainFilesIn(dir)
	record, ok := readClaudeChainRecord(rootFiles)
	files := claudeChainVersionFiles(dir, record)
	if !ok || !pathidentity.Same(record.Launcher, launcher) ||
		!claudeWrapperSafe(files.guard) || !claudeWrapperSafe(files.approved) {
		return "", ""
	}
	return files.guard, files.approved
}

func claudeGuardEventArgs(launcher string, hookArgs []string, event string, wrapped bool, unavailableOpen ...bool) []string {
	command := hookguard.Subcommand
	if wrapped {
		command = hookguard.WrappedSubcommand
	}
	args := append([]string{command, launcher}, hookArgs...)
	args = append(args, "--event", event)
	if len(unavailableOpen) > 0 && unavailableOpen[0] {
		args = append(args, "--unavailable-mode", "open")
	}
	return args
}

func claudeGuardCompareProgram() string {
	return strings.TrimRight(windowsSystemDirectory(), `\/`) + `\fc.exe`
}

// claudeWrapperStatusWords reads the status the guard answered with and maps
// it to the hook status: 0 and 2 pass through, a status offset by
// WrappedExitBase is the native hook status, and anything else (cmd.exe could
// not start the guard) falls through to the caller's warning and its code.
// The status is stored with set /a: "set name=!errorlevel! &" keeps the space
// before the "&" in the value, so "0 " never equals 0 and every answer of the
// guard was read as "could not start".
//
// cmd.exe reads everything after an unparenthesized if on the same line as the
// body of that if, so a later "&" never runs when the condition is false: the
// first form of this wrapper exited 0 without starting the guard whenever the
// guard existed. Each if therefore sits in its own parentheses, and the whole
// guarded run is the else branch of the missing-guard if.
func claudeWrapperStatusWords() []string {
	return []string{
		"&", "set", "/a", "dc_hook_status=!errorlevel!", ">nul",
		"&", "(", "if", "!dc_hook_status!", "equ", "0", "exit", "/b", "0", ")",
		"&", "(", "if", "!dc_hook_status!", "equ", "2", "exit", "/b", "2", ")",
		"&", "(", "if", "!dc_hook_status!", "geq", strconv.Itoa(hookguard.WrappedExitBase + 1),
		"if", "!dc_hook_status!", "leq", strconv.Itoa(2*hookguard.WrappedExitBase - 1),
		"(", "set", "/a", "dc_hook_result=!dc_hook_status!-" + strconv.Itoa(hookguard.WrappedExitBase), ">nul",
		"&", "exit", "/b", "!dc_hook_result!", ")", ")", "&",
	}
}

func claudeGuardWrapperArgs(guard, approved, launcher, event string, hookArgs []string, unavailableOpen ...bool) []string {
	open := len(unavailableOpen) > 0 && unavailableOpen[0]
	return claudeGuardWrapperArgsWith(claudeGuardCompareProgram(), guard, approved, launcher, event, hookArgs, open)
}

func claudeGuardWrapperArgsWith(compare, guard, approved, launcher, event string, hookArgs []string, unavailableOpen bool) []string {
	failCode := "2"
	if hookguard.NeutralEvent(event) || unavailableOpen {
		failCode = "1"
	}
	warning := []string{"echo", "DefenseClaw", "could", "not", "start", "its", "Claude", "Code", "hook", "guard.",
		"Run", "the", "DefenseClaw", "installer", "again", "to", "repair", "it.", "1>&2", "&", "exit", "/b", failCode}
	fail := func() []string { return append([]string(nil), warning...) }
	args := []string{"/d", "/v:on", "/c", "if", "not", "exist", guard, "("}
	args = append(args, fail()...)
	args = append(args, ")", "else", "(", compare, "/b", guard, approved, ">nul", "2>&1", "||", "(")
	args = append(args, fail()...)
	args = append(args, ")", "&", guard)
	args = append(args, claudeGuardEventArgs(launcher, hookArgs, event, true, unavailableOpen)...)
	args = append(args, claudeWrapperStatusWords()...)
	args = append(args, fail()...)
	return append(args, ")")
}

func claudeManagedGuardPath(launcher string) string {
	last := strings.LastIndexAny(launcher, `\/`)
	if last < 0 {
		return ""
	}
	return launcher[:last+1] + windowsHookGuardBinaryName
}

// claudeManagedGuardOfLauncher reports whether guard is the guard image of
// launcher: the file windowsHookGuardBinaryName in the launcher's folder.
// Setup renders both by their long names. An administrator's HKLM matrix can
// spell either by its 8.3 short names; that spelling names the same file by
// the same names (winpath.SameNamedFile), as the exec form's command does
// for verify and enrolment (GAP-2244). A copy, a junction or a hard link in
// another folder is not the guard.
func claudeManagedGuardOfLauncher(launcher, guard string) bool {
	want := claudeManagedGuardPath(launcher)
	if want == "" || guard == "" {
		return false
	}
	return want == guard || winpath.SameNamedFile(guard, want)
}

// The managed policy keeps cmd.exe as the registered parent. The small
// installed guard checks whether the full hook starts and preserves its
// answer. If the guard itself cannot start, cmd.exe gives the same event's
// documented unavailable answer.
func claudeManagedGuardWrapperInvocation(event, launcher string, hookArgs []string) (string, []string) {
	return claudeManagedGuardWrapperInvocationTexts(event, launcher, hookArgs, false)
}

// claudeManagedGuardWrapperInvocationTexts is claudeManagedGuardWrapperInvocation
// with the texts 1.0.9 Setup wrote when texts109 is set
// (SetupOpts.ClaudeManagedGuardTexts109).
func claudeManagedGuardWrapperInvocationTexts(event, launcher string, hookArgs []string, texts109 bool) (string, []string) {
	if !slices.Equal(hookArgs, []string{"hook", "--connector", "claudecode", "--enterprise-managed"}) ||
		!hookguard.AbsoluteHookExecutable(launcher) || !claudeWrapperSafe(launcher) {
		return launcher, hookArgs
	}
	guard := claudeManagedGuardPath(launcher)
	if !claudeWrapperSafe(guard) {
		return launcher, hookArgs
	}
	if texts109 {
		return claudeCodeWindowsCommandProcessor(), claudeManagedGuardWrapperArgs109(guard, launcher, event, hookArgs)
	}
	return claudeCodeWindowsCommandProcessor(), claudeManagedGuardWrapperArgs(guard, launcher, event, hookArgs)
}

// The managed wrapper prints claudeManagedGuardMissingWords when the guard
// image is absent from the install folder and claudeManagedGuardStartWords
// when the guard is there but does not run. Each text names its own
// condition: when Claude Code reports a block or a hook error it shows the
// whole registered command beside the hook's own answer, so both texts are on
// screen whichever branch ran. Worded as plain claims they told a user whose
// credentials were not accepted yet that the guard was missing and sent them
// to an administrator repair (rel-1-0-10 GAP-0119). Only Setup carries the
// guard payload: the installed CLI has no source to copy it from and refuses
// a repair while the recorded guard is missing. No word may hold a cmd.exe
// metacharacter, since the texts sit inside the wrapper's parenthesised
// blocks. The Python mirrors are _CLAUDE_MANAGED_GUARD_MISSING and
// _CLAUDE_MANAGED_GUARD_START in cli/defenseclaw/hook_integrity.py.
var claudeManagedGuardMissingWords = strings.Fields("If " + windowsHookGuardBinaryName + " is missing from the install folder: " +
	ClaudeCodeManagedGuardUnavailableText + " " + managed.WindowsStandaloneSetupName + " /repair to restore it. " +
	managed.WindowsSetupSource + ".")

var claudeManagedGuardStartWords = strings.Fields("If " + windowsHookGuardBinaryName + " is in the install folder but does not run: " +
	ClaudeCodeManagedGuardUnavailableText + " " + managed.WindowsStandaloneSetupName + " /repair.")

// ClaudeCodeManagedGuardUnavailableText is in both texts the managed wrapper
// prints when its guard gives no answer. The Windows hook image self test
// reads it as a guard that did not start.
const ClaudeCodeManagedGuardUnavailableText = "DefenseClaw cannot check Claude Code until an administrator runs"

// The texts 1.0.9 Setup wrote. A 1.0.9 managed policy runs the same branches
// with the same answers, so it still reads as DefenseClaw's managed guard
// (enterprise status, the exec view, uninstall) until Setup renders it again.
// Keep them while 1.0.9 is a supported upgrade source.
var claudeManagedGuardMissingWords109 = strings.Fields("DefenseClaw could not start its Claude Code hook guard defenseclaw-hook-guard.exe " +
	"because it is missing from the install folder. Run DefenseClawSetup-Enterprise-Standalone-x64.exe /repair " +
	"as an administrator to restore it. Setup is not installed on this computer: use the copy in your MDM package or the release download.")

var claudeManagedGuardStartWords109 = strings.Fields("DefenseClaw could not start its Claude Code hook guard. " +
	"Run the DefenseClaw installer again to repair it.")

func claudeManagedGuardWrapperArgs(guard, launcher, event string, hookArgs []string) []string {
	return claudeManagedGuardWrapperArgsWith(claudeManagedGuardMissingWords, claudeManagedGuardStartWords, guard, launcher, event, hookArgs)
}

// claudeManagedGuardWrapperArgs109 is the wrapper 1.0.9 Setup wrote.
func claudeManagedGuardWrapperArgs109(guard, launcher, event string, hookArgs []string) []string {
	return claudeManagedGuardWrapperArgsWith(claudeManagedGuardMissingWords109, claudeManagedGuardStartWords109, guard, launcher, event, hookArgs)
}

func claudeManagedGuardWrapperArgsWith(missingWords, startWords []string, guard, launcher, event string, hookArgs []string) []string {
	failCode := "2"
	if hookguard.NeutralEvent(event) {
		failCode = "1"
	}
	answer := func(words []string) []string {
		out := append([]string{"echo"}, words...)
		return append(out, "1>&2", "&", "exit", "/b", failCode)
	}
	args := []string{"/d", "/v:on", "/c", "if", "not", "exist", guard, "("}
	args = append(args, answer(missingWords)...)
	args = append(args, ")", "else", "(", guard)
	args = append(args, claudeGuardEventArgs(launcher, hookArgs, event, true)...)
	args = append(args, claudeWrapperStatusWords()...)
	args = append(args, answer(startWords)...)
	return append(args, ")")
}

// claudeManagedGuardWrapperKnown reports args as the managed form this
// release renders or the one 1.0.9 Setup wrote.
func claudeManagedGuardWrapperKnown(args []string, guard, launcher, event string, hookArgs []string) bool {
	return slices.Equal(args, claudeManagedGuardWrapperArgs(guard, launcher, event, hookArgs)) ||
		slices.Equal(args, claudeManagedGuardWrapperArgs109(guard, launcher, event, hookArgs))
}

// ClaudeCodeManagedGuardLauncher reads a managed policy handler that is
// exactly the guarded cmd.exe form Windows managed Setup writes (or the 1.0.9
// form, claudeManagedGuardWrapperKnown), and returns
// the launcher and hook arguments it runs. The policy checks of the enterprise
// status read the handler through it, so the form they verify is the form
// Setup installs.
func ClaudeCodeManagedGuardLauncher(handler map[string]interface{}) (string, []string, bool) {
	return claudeManagedGuardWrapperParts(handler)
}

func claudeManagedGuardWrapperParts(hook map[string]interface{}) (string, []string, bool) {
	command, _ := hook["command"].(string)
	if normalizeWindowsHookExecutable(command) != normalizeWindowsHookExecutable(claudeCodeWindowsCommandProcessor()) {
		return "", nil, false
	}
	args, ok := claudeCodeNativeExecArguments(hook)
	if !ok || len(args) < 25 || !slices.Equal(args[:6], []string{"/d", "/v:on", "/c", "if", "not", "exist"}) {
		return "", nil, false
	}
	guard := args[6]
	for i := 8; i+8 < len(args); i++ {
		if args[i] != guard || args[i+1] != hookguard.WrappedSubcommand {
			continue
		}
		launcher, hookArgs, event, wrapped, open, valid := hookguard.ParseInvocationMode(args[i+1 : i+9])
		if valid && wrapped && !open &&
			slices.Equal(hookArgs, []string{"hook", "--connector", "claudecode", "--enterprise-managed"}) &&
			claudeManagedGuardOfLauncher(launcher, guard) &&
			claudeManagedGuardWrapperKnown(args, guard, launcher, event, hookArgs) {
			return launcher, hookArgs, true
		}
	}
	return "", nil, false
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
		for _, width := range []int{7, 9} {
			if i+1+width > len(args) {
				continue
			}
			launcher, hookArgs, event, wrapped, open, valid := hookguard.ParseInvocationMode(args[i+1 : i+1+width])
			if valid && wrapped && claudeWrapperSafe(launcher) &&
				slices.Equal(args, claudeGuardWrapperArgsWith(compare, guard, approved, launcher, event, hookArgs, open)) {
				return launcher, hookArgs, true
			}
		}
	}
	return "", nil, false
}
