//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"crypto/rand"
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
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// An agent such as Claude Code treats a hook command that cannot start as a
// non-blocking error, so while defenseclaw-hook.exe is missing (an antivirus
// quarantine, for example), empty or not the recorded release every tool
// call runs unchecked. The standalone guardian keeps a protected copy of the
// recorded hook binary in its own administrator-only folder and puts it back
// before each reconcile, which fails on the missing file, and within
// windowsHookBinaryCheckInterval between reconciles (GAP-0935, GAP-0680).
// Setup stops the guardian before it replaces the binaries, so a newer
// release is never taken for a damaged one.

// windowsInstallFileSDDL is the InstallFile contract of the lifecycle:
// SYSTEM and Administrators full control, Users read and execute, protected.
const windowsInstallFileSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)"

func init() {
	previousBefore := enterpriseHookBeforeWatchReconcile
	enterpriseHookBeforeWatchReconcile = func(stderr io.Writer) {
		previousBefore(stderr)
		if enterprisehooks.WindowsStandaloneProcess() {
			keepWindowsStandaloneHookBinary(stderr, false)
			keepWindowsStandaloneClaudeDropIn(stderr)
		}
	}
	previous := enterpriseHookAfterWatchReconcile
	enterpriseHookAfterWatchReconcile = func(ctx context.Context, stderr io.Writer, run enterpriseHookReconcileRun) {
		previous(ctx, stderr, run)
		if enterprisehooks.WindowsStandaloneProcess() {
			removeWindowsStandaloneReplacementCopies(stderr)
		}
	}
}

// windowsHookBinaryCheckInterval is how often the guardian checks, between
// reconciles, that the hook binary is still in place.
var windowsHookBinaryCheckInterval = 5 * time.Second

// windowsHookBinaryMu serializes the restore between the check and the
// reconcile; windowsHookBinaryLastErr keeps the check from logging the same
// failure every interval.
var (
	windowsHookBinaryMu                sync.Mutex
	windowsHookBinaryLastErr           string
	windowsHookBinaryDigestRefusal     string
	windowsHookBinaryLastDigestRefusal string
	windowsHookBinarySharedDigestOK    bool
	windowsHookBinaryLstat             = os.Lstat
)

// watchWindowsStandaloneHookBinary restores a damaged hook binary, and an
// edited or deleted Claude Code drop-in, within one check interval for the
// life of the guardian watch loop.
func watchWindowsStandaloneHookBinary(ctx context.Context, stderr io.Writer) {
	if !enterprisehooks.WindowsStandaloneProcess() {
		return
	}
	ticker := time.NewTicker(windowsHookBinaryCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			keepWindowsStandaloneHookBinary(stderr, true)
			keepWindowsStandaloneClaudeDropIn(stderr)
		}
	}
}

// windowsReplacementCopyPattern is the copy an upgrade keeps of a binary a
// running program still used: <binary>.backup.<32 hex>.
var windowsReplacementCopyPattern = lazyregexp.New(`^(?i:defenseclaw[a-z0-9-]*\.exe)\.backup\.[0-9a-f]{32}$`)

// removeWindowsStandaloneReplacementCopies removes, as soon as no program
// runs it any more, the copy an upgrade kept of a binary an editor's ACP
// thread still ran. Only an upgrade or uninstall used to remove it, so a
// no-op ensure and a guardian restart left it in bin (GAP-0934, GAP-0937).
func removeWindowsStandaloneReplacementCopies(stderr io.Writer) {
	roots, err := windowsManagedLayout.roots(managed.ProfileStandalone)
	if err != nil || !strings.HasPrefix(strings.ToLower(filepath.Clean(enterpriseHookManifest)), strings.ToLower(roots.StateRoot)+`\`) {
		return
	}
	for _, removed := range removeWindowsReplacementCopies(filepath.Join(roots.InstallRoot, "bin")) {
		fmt.Fprintf(stderr, "[hook-guardian] removed %s, which no program runs any more\n", removed)
	}
}

// removeWindowsReplacementCopies deletes each replacement copy in dir that
// no program holds open and returns the ones it removed.
func removeWindowsReplacementCopies(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var removed []string
	for _, entry := range entries {
		if !windowsReplacementCopyPattern.MatchString(entry.Name()) || !entry.Type().IsRegular() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if windowsImageBackupTooFresh(path) {
			// The guardian's own swap made it a moment ago (GAP-0656).
			continue
		}
		if err := os.Remove(path); err == nil {
			forgetWindowsImageBackup(path)
			removed = append(removed, path)
		}
	}
	return removed
}

// keepWindowsStandaloneHookBinary keeps the guardian copy of the recorded
// hook binary and restores the binary from it when it is damaged. With
// onlyWhenDamaged it does not refresh the copy. The audit rows of the
// guardian's handle closes go to the gateway after windowsHookBinaryMu is
// released, so a gateway that is down or slow never holds up the guardian.
func keepWindowsStandaloneHookBinary(stderr io.Writer, onlyWhenDamaged bool) {
	windowsHookBinaryKeep(stderr, onlyWhenDamaged)
	flushWindowsHolderAudit(stderr)
}

// windowsHookBinaryKeep is the guardian's check under windowsHookBinaryMu;
// tests replace it to run the wrapper above with a hold pass of their own.
var windowsHookBinaryKeep = keepWindowsStandaloneHookBinaryLocked

func keepWindowsStandaloneHookBinaryLocked(stderr io.Writer, onlyWhenDamaged bool) {
	roots, err := windowsManagedLayout.roots(managed.ProfileStandalone)
	if err != nil || !strings.HasPrefix(strings.ToLower(filepath.Clean(enterpriseHookManifest)), strings.ToLower(roots.StateRoot)+`\`) {
		return
	}
	target := filepath.Join(roots.InstallRoot, "bin", "defenseclaw-hook.exe")
	setWindowsHolderAuditPath(filepath.Join(roots.StateRoot, "hook-guardian", "holder-audit-queue.json"))
	windowsHookBinaryMu.Lock()
	defer windowsHookBinaryMu.Unlock()
	// A backup an earlier swap kept goes at a later check, once no program
	// runs it (GAP-0656).
	for _, removed := range removeDueWindowsImageBackups() {
		fmt.Fprintf(stderr, "[hook-guardian] removed %s, which no program runs any more\n", removed)
	}
	want, err := windowsRecordedArtifactHash(roots.MetadataPath, "hook")
	if err != nil || want == "" {
		return
	}
	copyPath := filepath.Join(roots.StateRoot, "hook-guardian", "payload", "defenseclaw-hook.exe")
	damage, err := keepWindowsManagedFileCopy(target, copyPath, want, !onlyWhenDamaged)
	reportWindowsHookBinaryDigestRefusal(stderr, target)
	reportWindowsImageSwapLinkRefusal(stderr, target)
	reportWindowsImageBackupRestrictFailure(stderr)
	reportWindowsHeldSwapNotice(stderr, target)
	// The runtime files a hook start reads besides the binary: the same
	// bounded close, per file, after the binary's check and restore and for a
	// bounded number of held files, so a user who holds many of them cannot
	// delay the binary (GAP-0755).
	keepWindowsHookRuntimeFiles(stderr)
	writeWindowsHolderLog(stderr)
	if err != nil {
		if message := err.Error(); message != windowsHookBinaryLastErr {
			windowsHookBinaryLastErr = message
			fmt.Fprintf(stderr, "[hook-guardian] %s\n", message)
		}
		return
	}
	windowsHookBinaryLastErr = ""
	if damage != "" {
		fmt.Fprintf(stderr, "[hook-guardian] tamper: restored the hook binary %s, which was %s, from the guardian's protected copy (sha256 %s)\n", target, damage, want)
	}
}

// windowsImageSwapLinkRefusal is set when a restore found the volume
// refusing the swap's backup link and replaced the hook the older way;
// windowsImageSwapLinkRefusalLogged keeps it to one line per refusal.
var (
	windowsImageSwapLinkRefusal       string
	windowsImageSwapLinkRefusalLogged string
)

// reportWindowsImageSwapLinkRefusal logs, once, that the hook was restored
// without the one-step swap: a start in that moment can fail (GAP-0369).
func reportWindowsImageSwapLinkRefusal(stderr io.Writer, target string) {
	refusal := windowsImageSwapLinkRefusal
	windowsImageSwapLinkRefusal = ""
	if refusal == "" || refusal == windowsImageSwapLinkRefusalLogged {
		return
	}
	windowsImageSwapLinkRefusalLogged = refusal
	fmt.Fprintf(stderr, "[hook-guardian] notice: restored the hook binary %s without the one-step swap: %s; an agent starting it in that moment can get an error (GAP-0369)\n", target, refusal)
}

// windowsImageBackupRestrictFailure is set when a swap could not close the
// backup name to users; windowsImageBackupRestrictLogged keeps one line per
// error until a later restriction succeeds.
var (
	windowsImageBackupRestrictFailure struct{ backup, err string }
	windowsImageBackupRestrictLogged  string
)

// reportWindowsImageBackupRestrictFailure logs, once per error, that the old
// hook image kept under its backup name stays startable by users until the
// backup is deleted.
func reportWindowsImageBackupRestrictFailure(stderr io.Writer) {
	failure := windowsImageBackupRestrictFailure
	windowsImageBackupRestrictFailure.backup, windowsImageBackupRestrictFailure.err = "", ""
	if failure.err == "" || failure.err == windowsImageBackupRestrictLogged {
		return
	}
	windowsImageBackupRestrictLogged = failure.err
	fmt.Fprintf(stderr, "[hook-guardian] notice: could not close the backup %s of the replaced hook binary to administrators: %s; until the guardian deletes it, users can start the old hook from that name; logged once until a swap closes a backup\n", failure.backup, failure.err)
}

// The guardian calls this while holding windowsHookBinaryMu, once after each
// target check. A repeated refusal with a healthy plain-read verdict is
// reported once; a successful shared digest resets the suppression.
func reportWindowsHookBinaryDigestRefusal(stderr io.Writer, target string) {
	if windowsHookBinarySharedDigestOK {
		windowsHookBinaryLastDigestRefusal = ""
	} else if windowsHookBinaryDigestRefusal != "" && windowsHookBinaryDigestRefusal != windowsHookBinaryLastDigestRefusal {
		windowsHookBinaryLastDigestRefusal = windowsHookBinaryDigestRefusal
		fmt.Fprintf(stderr, "[hook-guardian] shared digest refused the hook binary %s: %s; a plain read verified its recorded hash and file structure\n", target, windowsHookBinaryDigestRefusal)
	}
}

// windowsRestoreClaudeDropIn puts DefenseClaw's Claude Code drop-in back
// from its ownership record; tests replace it.
var windowsRestoreClaudeDropIn = enterprisehooks.RestoreWindowsClaudeManagedPolicyDrift

// windowsClaudeDropInLastErr keeps the drop-in check from logging the same
// failure every interval.
var windowsClaudeDropInLastErr string

// keepWindowsStandaloneClaudeDropIn puts DefenseClaw's own Claude Code
// drop-in (90-defenseclaw.json) back when it was edited or deleted, as the
// Unix guardian does (GAP-1178). The Windows guardian left it changed, so
// every enrolled user's Claude Code prompt failed closed and the reconcile
// and Setup /repair refused the file as an administrator edit (GAP-1108).
func keepWindowsStandaloneClaudeDropIn(stderr io.Writer) {
	roots, err := windowsManagedLayout.roots(managed.ProfileStandalone)
	if err != nil || !strings.HasPrefix(strings.ToLower(filepath.Clean(enterpriseHookManifest)), strings.ToLower(roots.StateRoot)+`\`) {
		return
	}
	windowsHookBinaryMu.Lock()
	defer windowsHookBinaryMu.Unlock()
	restored, err := windowsRestoreClaudeDropIn()
	if err != nil {
		if message := err.Error(); message != windowsClaudeDropInLastErr {
			windowsClaudeDropInLastErr = message
			fmt.Fprintf(stderr, "[hook-guardian] %s\n", message)
		}
		return
	}
	windowsClaudeDropInLastErr = ""
	if restored {
		fmt.Fprintf(stderr, "[hook-guardian] tamper: put back DefenseClaw's Claude Code drop-in, which was changed or removed outside DefenseClaw\n")
	}
}

// windowsRecordedArtifactHash reads the SHA-256 the deployment metadata
// records for an artifact.
func windowsRecordedArtifactHash(metadataPath, name string) (string, error) {
	body, err := readWindowsEnterpriseBoundedFile(metadataPath, 1<<20)
	if err != nil {
		return "", err
	}
	var metadata struct {
		Hashes map[string]string `json:"hashes"`
	}
	if err := json.Unmarshal(trimWindowsJSONBOM(body), &metadata); err != nil {
		return "", err
	}
	return strings.ToLower(strings.TrimSpace(metadata.Hashes[name])), nil
}

// keepWindowsManagedFileCopy refreshes copyPath from target while target is
// the recorded file (sha256 want) and refresh is set, and restores target
// from a copy that still is when target is missing, non-regular, empty or another file.
// It reports what was wrong with the target it restored, or "".
func keepWindowsManagedFileCopy(target, copyPath, want string, refresh bool) (string, error) {
	damage := ""
	missing := false
	windowsHookBinaryDigestRefusal = ""
	windowsHookBinarySharedDigestOK = false
	// Any check that does not find the hook held by a handle that allows no
	// deletion starts the two checks of the next such hold again (GAP-0755).
	holdSeen := false
	defer func() {
		if !holdSeen {
			windowsHolderGate.free()
		}
	}()
	info, err := windowsHookBinaryLstat(target)
	classification, err := classifyGuardianTargetLstat(info, err)
	if err != nil {
		return "", fmt.Errorf("inspect the hook binary %s: %w", target, err)
	}
	damage, missing = classification.damage, classification.missing
	switch {
	case damage != "":
		// The protected copy is verified below before a damaged entry is touched.
	case info.Size() == 0:
		damage = "empty (0 bytes)"
	default:
		verdict, err := decideGuardianTargetDigest(target, want,
			guardianTargetHookSHA256Hex, windowsFileSHA256Hex, windowsHookBinaryStructuralDamage)
		held := ""
		if err != nil {
			// GAP-0755: a handle that shares nothing refuses the guardian's own
			// reads as well as every start,
			// so the digest cannot be read and this used to end the
			// pass with a read error before the held check ran. When a
			// start-style open is refused too, the hook is held, whatever
			// the digest read said.
			if held = windowsHookBinaryHeldOpen(target); held == "" {
				return "", err
			}
		} else {
			windowsHookBinarySharedDigestOK = verdict.refusal == ""
			damage, missing = verdict.damage, verdict.missing
			if damage != "" {
				break
			}
			held = windowsHookBinaryHeldOpen(target)
		}
		// GAP-0656 review M2: a handle another program holds open for
		// writing (sharing read and delete) leaves the bytes and the single
		// name intact, but Windows refuses every start of the image, so each
		// tool call runs unchecked. The swap moves the name to a fresh
		// object; the handle keeps the old one. A sharing violation on the
		// start-style open does not say which kind of handle it is (a writer,
		// or a reader that shares no reading), so the verdict is "held
		// open".
		if held != "" && windowsHolderCloserEnabled() && windowsHookBinaryDeleteBlocked(target) {
			// GAP-0755: a handle that shares no deletion cannot be swapped
			// around: the rename that
			// puts the new file at the name fails for as long as the handle
			// lives. On the standalone profile the guardian closes that
			// handle in its owner instead, inside the bounds listed at
			// enterprise_hooks_hook_holders_policy_windows.go: it waits for the second check, never
			// closes a service's, a protected or a session 0 process's
			// handle, closes one handle at a time and backs off from a
			// holder that takes it again. The file stays as it is.
			holdSeen = true
			closed, holdErr := endWindowsExclusiveHold(target)
			if holdErr == nil && closed == 0 {
				return "", nil
			}
			if holdErr == nil && !windowsHookBinaryOpenRefused(target) {
				return "", nil
			}
			reason := fmt.Sprintf("the hook binary %s is %s, and the guardian did not end the hold", target, held)
			if holdErr != nil {
				reason += " (" + holdErr.Error() + ")"
			} else {
				reason += fmt.Sprintf(" (it closed %d handle(s), but a start is still refused)", closed)
			}
			if err != nil {
				return "", fmt.Errorf("%s: %w", reason, err)
			}
			return "", errors.New(reason)
		}
		if held != "" {
			// The same verdict comes from a handle that shares no reading
			// (a program can open the hook that way), and the swap cannot
			// end that hold. So the swaps of one path are bounded: a
			// backoff between them and a cap on the backups still pending.
			if allowed, why := windowsHeldSwapAllowed(); !allowed {
				windowsHeldSwaps.notice = why
				return "", nil
			}
			damage = held
			break
		}
		windowsHookBinaryDigestRefusal = verdict.refusal
		if !refresh {
			return "", nil
		}
		if sum, err := guardianCopyHookSHA256Hex(copyPath); err == nil && sum == want {
			return "", nil
		}
		if err := os.MkdirAll(filepath.Dir(copyPath), 0o700); err != nil {
			return "", fmt.Errorf("keep a protected copy of %s: %w", target, err)
		}
		// The copy is never started, so it needs no image swap.
		return "", copyWindowsManagedFile(target, copyPath, "", true, false)
	}
	// The protected copy has no periodic reread of its own. It is never
	// executed, and its bytes are checked afresh before every restore; a
	// hidden change with an unchanged identity is found when needed.
	if sum, err := windowsFileSHA256Hex(copyPath); err != nil || sum != want {
		// Only Setup carries a payload to restore it from; the installed CLI
		// does not (cowork-1-0-8 GAP-0095). This guardian is the standalone
		// profile's, so the instruction names where Setup comes from.
		return "", fmt.Errorf("the hook binary %s is %s and the guardian has no copy of the recorded release; agents run tool calls without DefenseClaw until %s restores it from an elevated PowerShell prompt.%s",
			target, damage, windowsEnterpriseSetupCommand("/repair", "JSON=1"), windowsEnterpriseSetupSourceNote)
	}
	// A missing binary is put back without replacing one that appeared
	// meanwhile. A non-regular entry needs a narrow fallback when Windows
	// cannot replace a directory entry with a file.
	var restoreErr error
	if !missing && info != nil && !info.Mode().IsRegular() {
		restoreErr = restoreWindowsNonRegularHookBinary(copyPath, target)
	} else {
		restoreErr = copyWindowsManagedFile(copyPath, target, windowsInstallFileSDDL, !missing, true)
	}
	if restoreErr != nil {
		return "", fmt.Errorf("restore the hook binary %s, which is %s: %w", target, damage, restoreErr)
	}
	structuralDamage, err := windowsHookBinaryStructuralDamage(target)
	if err != nil {
		_ = os.Remove(target)
		return "", fmt.Errorf("inspect the restored hook binary %s: %w", target, err)
	}
	if structuralDamage != "" {
		_ = os.Remove(target)
		return "", fmt.Errorf("restore the hook binary %s: restored file structure is invalid (%s)", target, structuralDamage)
	}
	if sum, err := windowsFileSHA256Hex(target); err != nil || sum != want {
		_ = os.Remove(target)
		return "", fmt.Errorf("restore the hook binary %s: the restored file does not match the recorded release", target)
	}
	return damage, nil
}

// restoreWindowsNonRegularHookBinary first replaces a file-like entry through
// the usual secured temporary sibling. Windows cannot replace a directory
// entry with a file, so only then remove the link or empty directory entry.
// A non-empty real directory is moved aside intact; its contents are never deleted.
func restoreWindowsNonRegularHookBinary(copyPath, target string) error {
	replaceErr := copyWindowsManagedFile(copyPath, target, windowsInstallFileSDDL, true, true)
	if replaceErr == nil {
		return nil
	}
	info, err := os.Lstat(target)
	if errors.Is(err, os.ErrNotExist) {
		return copyWindowsManagedFile(copyPath, target, windowsInstallFileSDDL, false, true)
	}
	if err != nil {
		return fmt.Errorf("inspect target after failed replacement: %w", err)
	}
	if info.Mode().IsRegular() {
		return replaceErr // another writer changed the entry; re-evaluate next tick
	}
	removeErr := os.Remove(target)
	if removeErr == nil {
		return copyWindowsManagedFile(copyPath, target, windowsInstallFileSDDL, false, true)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("remove non-regular target after failed replacement: %w", removeErr)
	}
	name, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	attributes, err := windows.GetFileAttributes(name)
	if err != nil {
		return err
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("remove reparse point after failed replacement: %w", removeErr)
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	aside := target + ".damaged-" + hex.EncodeToString(suffix)
	to, err := windows.UTF16PtrFromString(aside)
	if err != nil {
		return err
	}
	if err := windows.MoveFileEx(name, to, windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return fmt.Errorf("move non-empty directory aside: %w", err)
	}
	return copyWindowsManagedFile(copyPath, target, windowsInstallFileSDDL, false, true)
}

// windowsHookBinaryHeldOpen opens path for reading as a program start does
// (sharing only read and delete) and reports a handle that has it open in a
// way that refuses the start, or "". A sharing violation is a writer, or a
// handle that opened the file with no read sharing: the probe cannot tell
// them apart, so the text does not claim a writer.
func windowsHookBinaryHeldOpen(path string) string {
	if windowsHookBinaryOpenRefused(path) {
		return "held open by another program (a write handle, or one that shares no reading), so no agent can start it"
	}
	return ""
}

// windowsHookBinaryOpenRefused is the start-style open; tests replace it.
var windowsHookBinaryOpenRefused = func(path string) bool {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		return true
	}
	if err == nil {
		_ = windows.CloseHandle(handle)
	}
	return false
}

// The swaps a held-open verdict causes (GAP-0656). A handle that
// holds the hook open and shares deletion keeps every start off until the
// guardian swaps (a writer opened with FileShare.ReadWrite | Delete); the
// swap moves the name to a fresh file. A handle that shares no deletion (an
// ordinary writer, which the C runtime and Go open without delete sharing, or
// a reader that shares nothing) cannot be swapped around, because the rename
// that puts the new file at the name fails for as long as it lives, so on
// the standalone profile the guardian closes it in its owner, inside the
// bounds listed at the top of enterprise_hooks_hook_holders_policy_windows.go (GAP-0755). A swap cannot end a
// hold: the holder reopens the new object, and its handle on the old object
// blocks the backup's deletion. Unbounded, that is a full-size backup every
// check. So these swaps back off exponentially for the same path, stop when
// windowsHeldSwapBackupCap backups are still pending, and say so once. That
// any user may hold a hook image they may start is a known limit; the cap
// bounds the cost, not the hold.
var (
	windowsHeldSwapBackoffBase = 10 * time.Second
	windowsHeldSwapBackoffMax  = 5 * time.Minute
	// windowsHeldSwapStreakEnd is how long without a held verdict ends the
	// backoff, so a hold much later starts again at the first delay.
	windowsHeldSwapStreakEnd = 10 * time.Minute
	windowsHeldSwapBackupCap = 8
	windowsHeldSwapNow       = time.Now
)

// windowsHeldSwaps is the backoff state, guarded by windowsHookBinaryMu.
var windowsHeldSwaps windowsHeldSwapState

type windowsHeldSwapState struct {
	streak int       // swaps made in this streak
	last   time.Time // the last held verdict
	next   time.Time // no swap before this
	notice string    // why the last held verdict did not swap, until logged
	logged bool      // the notice of this streak was logged
}

// windowsHeldSwapAllowed decides, for a held-open verdict, whether the
// guardian swaps now, and records the swap. When it does not, why says so.
func windowsHeldSwapAllowed() (bool, string) {
	state := &windowsHeldSwaps
	now := windowsHeldSwapNow()
	// The streak ends, and with it the logged flag, ten minutes after the
	// last held verdict, whether or not that streak ever swapped: a cap or a
	// backoff can stop the very first verdict.
	if !state.last.IsZero() && now.Sub(state.last) > windowsHeldSwapStreakEnd {
		*state = windowsHeldSwapState{}
	}
	state.last = now
	if pending := pendingWindowsImageBackups(); pending >= windowsHeldSwapBackupCap {
		return false, fmt.Sprintf("%d backups of earlier swaps are still held open, so the guardian makes no new one until a holder lets go", pending)
	}
	if state.streak > 0 && now.Before(state.next) {
		return false, fmt.Sprintf("swaps of this path back off (%d so far); the next one is not before %s", state.streak, state.next.Format("15:04:05"))
	}
	state.streak++
	state.next = now.Add(windowsHeldSwapDelay(state.streak))
	return true, ""
}

// windowsHeldSwapDelay is the wait after the nth swap of a streak: the base,
// doubled each time, up to the maximum.
func windowsHeldSwapDelay(swaps int) time.Duration {
	delay := windowsHeldSwapBackoffBase
	for i := 1; i < swaps && delay < windowsHeldSwapBackoffMax; i++ {
		delay *= 2
	}
	return min(delay, windowsHeldSwapBackoffMax)
}

// reportWindowsHeldSwapNotice logs, once per streak, that a held-open hook
// was not swapped at this check. The guardian calls it holding
// windowsHookBinaryMu after each check.
func reportWindowsHeldSwapNotice(stderr io.Writer, target string) {
	state := &windowsHeldSwaps
	notice := state.notice
	state.notice = ""
	if notice == "" || state.logged {
		return
	}
	state.logged = true
	fmt.Fprintf(stderr, "[hook-guardian] notice: the hook binary %s is held open by another program, and the guardian swaps it less often while that lasts: %s; this is logged once until the hold ends\n", target, notice)
}

// windowsHookBinaryStructuralDamage inspects the named file without opening
// its data. A matching plain hash cannot make a hard link or reparse point a
// healthy managed target.
func windowsHookBinaryStructuralDamage(path string) (string, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	handle, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return "", err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		return "not a plain regular file (reparse point or directory)", nil
	}
	if info.NumberOfLinks != 1 {
		return fmt.Sprintf("linked to another name (links=%d)", info.NumberOfLinks), nil
	}
	return "", nil
}

// copyWindowsManagedFile copies source to destination through a temporary
// sibling, with the protected access list sddl when it is not empty, and
// renames it into place, replacing a file already there only with replace.
// With launchable (the hook binary agents start), a regular file already
// there is replaced with swapWindowsProgramImage, so an agent starting the
// hook meanwhile starts the old program or the new one; Windows refuses the
// MoveFileEx replacement used before while any hook call runs the old image
// (GAP-0656). The MoveFileEx rename serves a missing or non-regular
// destination, the guardian's own copy (never started) and a volume that
// refuses the swap's hard link (GAP-0369).
func copyWindowsManagedFile(source, destination, sddl string, replace, launchable bool) error {
	body, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	temporary := destination + ".restore-" + hex.EncodeToString(suffix)
	if err := os.WriteFile(temporary, body, 0o600); err != nil {
		return err
	}
	if sddl != "" {
		descriptor, err := windows.SecurityDescriptorFromString(sddl)
		if err == nil {
			var dacl *windows.ACL
			if dacl, _, err = descriptor.DACL(); err == nil {
				err = windows.SetNamedSecurityInfo(temporary, windows.SE_FILE_OBJECT,
					windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
			}
		}
		if err != nil {
			_ = os.Remove(temporary)
			return err
		}
	}
	from, err := windows.UTF16PtrFromString(temporary)
	if err != nil {
		_ = os.Remove(temporary)
		return err
	}
	to, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		_ = os.Remove(temporary)
		return err
	}
	linkRefusal := ""
	if replace && launchable {
		if info, err := os.Lstat(destination); err == nil && info.Mode().IsRegular() {
			backup, err := swapWindowsProgramImage(temporary, destination)
			switch {
			case err == nil:
				deferWindowsImageBackupRemoval(backup)
				return nil
			case errors.Is(err, errWindowsImageSwapLinkRefused):
				linkRefusal = err.Error()
			default:
				_ = os.Remove(temporary)
				return err
			}
		}
	}
	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if replace {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}
	if err := windows.MoveFileEx(from, to, flags); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	// The notice claims a restore without the one-step swap, so it is set
	// only now that the older replacement has succeeded: a
	// MoveFileEx the running hook refuses leaves the hook as it was and the
	// guardian retries at the next check.
	if linkRefusal != "" {
		windowsImageSwapLinkRefusal = linkRefusal
	}
	return nil
}

func windowsFileSHA256Hex(path string) (string, error) {
	// The guardian hashes the installed hook while hook calls run; a
	// delete-sharing open lets an installer replace it meanwhile (GAP-0200).
	file, err := winpath.OpenReadShared(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
