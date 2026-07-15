// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"golang.org/x/sys/windows"
)

const atomicTransformV2HardExitCode = 91

type atomicTransformV2ExitBoundary struct {
	phase      atomicTransformPhase
	occurrence int
}

func atomicTransformV2HardExitPayload() []byte {
	return bytes.Repeat([]byte("N"), atomicTransformMaxIntentBytes*3)
}

func atomicTransformV2HardExitEnv(overrides ...string) []string {
	const controlPrefix = "DEFENSECLAW_V2_HARD_EXIT_"
	env := make([]string, 0, len(os.Environ())+len(overrides))
	for _, entry := range os.Environ() {
		name, _, found := strings.Cut(entry, "=")
		if found && len(name) >= len(controlPrefix) &&
			strings.EqualFold(name[:len(controlPrefix)], controlPrefix) {
			continue
		}
		env = append(env, entry)
	}
	return append(env, overrides...)
}

func TestAtomicTransformWindowsDeleteOnCloseHardLinkProbe(t *testing.T) {
	root := t.TempDir()
	tempName := "delete-on-close-source"
	finalPath := filepath.Join(root, "published")
	parent, err := bindAtomicTransformDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	attributes, err := atomicTransformBoundObjectAttributes(parent.file, tempName, nil)
	if err != nil {
		t.Fatal(err)
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(
		&handle, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.DELETE|windows.SYNCHRONIZE,
		attributes, &status, nil, 0, windows.FILE_SHARE_READ,
		windows.FILE_CREATE,
		windows.FILE_NON_DIRECTORY_FILE|windows.FILE_DELETE_ON_CLOSE|windows.FILE_SYNCHRONOUS_IO_NONALERT,
		0, 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(handle), tempName)
	if _, err := file.Write([]byte("complete")); err != nil {
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(root, tempName), finalPath); err != nil {
		_ = file.Close()
		t.Skipf("hard-link publication from delete-on-close handle unavailable: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(finalPath)
	if err != nil || string(data) != "complete" {
		t.Fatalf("hard-linked publication after delete-on-close = %q, %v", data, err)
	}
}

func TestAtomicTransformV2HardExitHelper(t *testing.T) {
	if os.Getenv("DEFENSECLAW_V2_HARD_EXIT_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	path := os.Getenv("DEFENSECLAW_V2_HARD_EXIT_PATH")
	stateDir := os.Getenv("DEFENSECLAW_V2_HARD_EXIT_STATE")
	operation := os.Getenv("DEFENSECLAW_V2_HARD_EXIT_OPERATION")
	wantPhase := atomicTransformPhase(os.Getenv("DEFENSECLAW_V2_HARD_EXIT_PHASE"))
	wantOccurrence, err := strconv.Atoi(os.Getenv("DEFENSECLAW_V2_HARD_EXIT_OCCURRENCE"))
	if err != nil || wantOccurrence < 1 {
		wantOccurrence = 1
	}
	seen := 0
	hookPath, err := canonicalAtomicTransformTargetPath(path)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "canonicalize hard-exit helper target: %v\n", err)
		os.Exit(94)
	}
	forceShortRepair := os.Getenv("DEFENSECLAW_V2_FORCE_SHORT_REPAIR") == "1"
	if forceShortRepair {
		restoreShortFixture := installAtomicTransformV2PrePublicationHookForTest(
			hookPath, atomicTransformV2ForcePreRepairShortNamesForTest,
		)
		defer restoreShortFixture()
	}
	forceReadyStageShortName := func(state atomicTransformPhaseState) error {
		dir, err := bindAtomicTransformDirectory(filepath.Dir(state.StagedFinal))
		if err != nil {
			return err
		}
		defer dir.Close()
		name := filepath.Base(state.StagedFinal)
		expected, err := atomicTransformBoundInspectFilePrivate(
			dir, name, atomicTransformMaxConfigBytes,
		)
		if err != nil || !expected.exists || expected.linkCount != 1 {
			if err == nil {
				err = fmt.Errorf("deterministic StageFinal alias fixture has no exact single-link Stage")
			}
			return err
		}
		file, err := openAtomicTransformV2ReplaceGuard(dir, name, true)
		if err != nil {
			return err
		}
		current, stateErr := atomicTransformBoundStateFromOpen(file, name, atomicTransformMaxConfigBytes)
		if stateErr != nil || !atomicTransformArtifactStatesEqualExact(current, expected) {
			_ = file.Close()
			if stateErr == nil {
				stateErr = fmt.Errorf("deterministic StageFinal alias handle changed identity")
			}
			return stateErr
		}
		currentShort, err := atomicTransformV2WindowsShortNameFromOpen(file)
		if err == nil && currentShort != "" && !atomicTransformPathsEqual(currentShort, "DSTAGE~1") {
			err = setAtomicTransformV2WindowsShortNameOnOpen(file, "")
		}
		if err == nil && !atomicTransformPathsEqual(currentShort, "DSTAGE~1") {
			err = setAtomicTransformV2WindowsShortNameOnOpen(file, "DSTAGE~1")
		}
		if err == nil {
			err = windows.FlushFileBuffers(windows.Handle(file.Fd()))
		}
		verifiedShort := ""
		if err == nil {
			verifiedShort, err = atomicTransformV2WindowsShortNameFromOpen(file)
		}
		closeErr := file.Close()
		if err == nil {
			err = syncAtomicTransformBoundDirectoryPlatform(dir.file)
		}
		if err := errors.Join(err, closeErr); err != nil {
			return err
		}
		if !atomicTransformPathsEqual(verifiedShort, "DSTAGE~1") {
			return fmt.Errorf("deterministic StageFinal short name = %q; want DSTAGE~1", verifiedShort)
		}
		alias, err := atomicTransformBoundInspect(dir, "DSTAGE~1", atomicTransformMaxConfigBytes)
		if err != nil || alias.identity != expected.identity {
			if err == nil {
				err = fmt.Errorf("deterministic StageFinal alias resolves to a different inode")
			}
			return err
		}
		return nil
	}
	forceAbort := os.Getenv("DEFENSECLAW_V2_HARD_EXIT_ABORT") == "1"
	forceSafeAbort := os.Getenv("DEFENSECLAW_V2_HARD_EXIT_SAFE_ABORT") == "1"
	postPReparseTarget := os.Getenv("DEFENSECLAW_V2_POST_P_REPARSE_TARGET")
	postPReparseInstalled := false
	recreate1177Payload := os.Getenv("DEFENSECLAW_V2_1177_RECREATE_LIVE")
	recreated1177Live := false
	readyStageShortForced := false
	abortInjected := false
	setAtomicTransformPhaseHookForTest(hookPath, func(
		phase atomicTransformPhase, state atomicTransformPhaseState,
	) error {
		if (forceAbort || forceSafeAbort) && !abortInjected && phase == atomicTransformPhaseIntentPersisted {
			abortInjected = true
			if forceSafeAbort {
				// Rp is durable and live is still exact Old. Returning a conflict
				// forces the caller's ordinary recovery path to publish Rt(abort)
				// without manufacturing an operator mutation.
				return errAtomicTransformConflict
			}
			// Rp is durable but P has not been reached and the raw namespace
			// transition has not started. Mutating the
			// exact live object forces the prepared recovery path to choose Rt(abort)
			// without relying on a legacy detach window that ReplaceFileW removes.
			file, openErr := os.OpenFile(state.TargetPath, os.O_WRONLY|os.O_TRUNC, 0)
			if openErr != nil {
				_, _ = fmt.Fprintf(os.Stderr, "inject prepared conflict: %v\n", openErr)
				os.Exit(96)
			}
			_, writeErr := file.Write([]byte("foreign-before-abort"))
			syncErr := file.Sync()
			closeErr := file.Close()
			if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "persist prepared conflict: %v\n", err)
				os.Exit(96)
			}
		}
		if forceShortRepair && !readyStageShortForced && phase == atomicTransformPhaseStageFinalized {
			readyStageShortForced = true
			if err := forceReadyStageShortName(state); err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "force deterministic StageFinal short name: %v\n", err)
				os.Exit(99)
			}
		}
		if postPReparseTarget != "" && !postPReparseInstalled &&
			phase == atomicTransformPhaseFinalPublicationValidated {
			postPReparseInstalled = true
			if err := os.Remove(state.TargetPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				_, _ = fmt.Fprintf(os.Stderr, "remove live before post-P reparse replacement: %v\n", err)
				os.Exit(97)
			}
			if err := os.Symlink(postPReparseTarget, state.TargetPath); err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "install post-P reparse replacement: %v\n", err)
				os.Exit(97)
			}
		}
		if recreate1177Payload != "" && !recreated1177Live &&
			phase == atomicTransformPhase("replace-"+atomicTransformV2ReplaceBoundaryBefore1177Restore) {
			recreated1177Live = true
			file, err := os.OpenFile(state.TargetPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err == nil {
				_, err = file.Write([]byte(recreate1177Payload))
			}
			if err == nil {
				err = file.Sync()
			}
			if file != nil {
				err = errors.Join(err, file.Close())
			}
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "inject live recreate at 1177 restore seam: %v\n", err)
				os.Exit(98)
			}
		}
		if phase != wantPhase {
			return nil
		}
		seen++
		if seen == wantOccurrence {
			os.Exit(atomicTransformV2HardExitCode)
		}
		return nil
	})
	if os.Getenv("DEFENSECLAW_V2_HARD_EXIT_RECOVER") == "1" {
		if err := recoverAtomicTransformV2(path, stateDir); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "fresh recovery helper: %v\n", err)
			os.Exit(92)
		}
		return
	}
	result := atomicTransformResult{Data: atomicTransformV2HardExitPayload()}
	if operation == "remove" {
		result = atomicTransformResult{Remove: true}
	}
	if err := atomicTransformFileWithStateDir(
		path, stateDir, 0o600,
		func(_ []byte, _ bool) (atomicTransformResult, error) { return result, nil },
	); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "hard-exit helper transform: %v\n", err)
		os.Exit(92)
	}
	_, _ = fmt.Fprintf(os.Stderr, "hard-exit phase %s occurrence %d was not reached\n", wantPhase, wantOccurrence)
	os.Exit(93)
}

func TestAtomicTransformV2ProtocolLockHelper(t *testing.T) {
	if os.Getenv("DEFENSECLAW_V2_LOCK_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	path := os.Getenv("DEFENSECLAW_V2_LOCK_PATH")
	stateDir := os.Getenv("DEFENSECLAW_V2_LOCK_STATE")
	payload := []byte(os.Getenv("DEFENSECLAW_V2_LOCK_PAYLOAD"))
	ready := os.Getenv("DEFENSECLAW_V2_LOCK_READY")
	release := os.Getenv("DEFENSECLAW_V2_LOCK_RELEASE")
	waitForRelease := func() error {
		if ready == "" {
			return nil
		}
		if err := os.WriteFile(ready, []byte("ready"), 0o600); err != nil {
			return err
		}
		if os.Getenv("DEFENSECLAW_V2_LOCK_EXIT_HELD") == "1" {
			os.Exit(95)
		}
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(release); err == nil {
				return nil
			}
			time.Sleep(10 * time.Millisecond)
		}
		return fmt.Errorf("timed out waiting for protocol-lock release signal")
	}
	if os.Getenv("DEFENSECLAW_V2_LOCK_ONLY") == "1" {
		prepared, err := prepareAtomicTransformStateDir(stateDir)
		if err != nil {
			t.Fatal(err)
		}
		if err := prepareAtomicTransformV2TargetParent(path); err != nil {
			t.Fatal(err)
		}
		if err := withAtomicTransformV2ProtocolLock(path, prepared, nil, func(string) error {
			return waitForRelease()
		}); err != nil {
			t.Fatalf("protocol-lock helper: %v", err)
		}
		return
	}
	if ready != "" {
		holdPhase := atomicTransformPhaseAllocationPersisted
		if configured := os.Getenv("DEFENSECLAW_V2_LOCK_HOLD_PHASE"); configured != "" {
			holdPhase = atomicTransformPhase(configured)
		}
		setAtomicTransformPhaseHookForTest(path, func(
			phase atomicTransformPhase, _ atomicTransformPhaseState,
		) error {
			if phase != holdPhase {
				return nil
			}
			if os.Getenv("DEFENSECLAW_V2_LOCK_HIDE_TARGET") != "1" {
				return waitForRelease()
			}
			hidden := path + ".protocol-lock-hidden"
			if err := os.Rename(path, hidden); err != nil {
				return fmt.Errorf("temporarily hide target alias under protocol lock: %w", err)
			}
			waitErr := waitForRelease()
			restoreErr := os.Rename(hidden, path)
			return errors.Join(waitErr, restoreErr)
		})
	}
	if err := atomicTransformFileWithStateDir(
		path, stateDir, 0o600,
		func(_ []byte, _ bool) (atomicTransformResult, error) {
			return atomicTransformResult{Data: payload}, nil
		},
	); err != nil {
		t.Fatalf("protocol-lock helper transform: %v", err)
	}
}

func TestAtomicTransformV2SerializesLongAndShortAliasProcesses(t *testing.T) {
	root := t.TempDir()
	longPath := filepath.Join(root, "config", "Long Configuration Settings.json")
	stateDir := filepath.Join(root, "protected-state")
	if err := os.MkdirAll(filepath.Dir(longPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(longPath, []byte("initial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := safefile.ProtectFile(longPath); err != nil {
		t.Fatal(err)
	}
	pointer, err := windows.UTF16PtrFromString(longPath)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]uint16, 2048)
	length, err := windows.GetShortPathName(pointer, &buffer[0], uint32(len(buffer)))
	if err != nil || length == 0 || length >= uint32(len(buffer)) {
		t.Skipf("8.3 aliases are unavailable: length=%d err=%v", length, err)
	}
	shortPath := windows.UTF16ToString(buffer[:length])
	if atomicTransformPathsEqual(shortPath, longPath) || !strings.Contains(filepath.Base(shortPath), "~") {
		t.Skipf("target leaf has no distinct 8.3 alias: %s", shortPath)
	}
	ready := filepath.Join(root, "first-ready")
	release := filepath.Join(root, "release-first")
	command := func(path, payload string, hold bool) (*exec.Cmd, *bytes.Buffer) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestAtomicTransformV2ProtocolLockHelper$")
		output := new(bytes.Buffer)
		cmd.Stdout, cmd.Stderr = output, output
		env := []string{
			"DEFENSECLAW_V2_LOCK_HELPER=1",
			"DEFENSECLAW_V2_LOCK_ONLY=1",
			"DEFENSECLAW_V2_LOCK_PATH=" + path,
			"DEFENSECLAW_V2_LOCK_STATE=" + stateDir,
			"DEFENSECLAW_V2_LOCK_PAYLOAD=" + payload,
		}
		if hold {
			env = append(env,
				"DEFENSECLAW_V2_LOCK_READY="+ready,
				"DEFENSECLAW_V2_LOCK_RELEASE="+release,
			)
		}
		cmd.Env = append(os.Environ(), env...)
		return cmd, output
	}
	first, firstOutput := command(shortPath, "first", true)
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.WriteFile(release, []byte("release"), 0o600)
		if first.Process != nil {
			_ = first.Process.Kill()
		}
	})
	firstDone := make(chan error, 1)
	go func() { firstDone <- first.Wait() }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first alias process did not reach the held-lock phase")
		}
		time.Sleep(10 * time.Millisecond)
	}
	second, secondOutput := command(longPath, "second", false)
	if err := second.Start(); err != nil {
		t.Fatal(err)
	}
	secondDone := make(chan error, 1)
	go func() { secondDone <- second.Wait() }()
	select {
	case err := <-secondDone:
		t.Fatalf("long-alias contender escaped held physical lock: %v\n%s", err, secondOutput)
	case <-time.After(500 * time.Millisecond):
	}
	if err := os.WriteFile(release, []byte("release"), 0o600); err != nil {
		t.Fatal(err)
	}
	for label, item := range map[string]struct {
		done   <-chan error
		output *bytes.Buffer
	}{"first": {firstDone, firstOutput}, "second": {secondDone, secondOutput}} {
		select {
		case err := <-item.done:
			if err != nil {
				t.Fatalf("%s alias process: %v\n%s", label, err, item.output)
			}
		case <-time.After(20 * time.Second):
			t.Fatalf("%s alias process did not finish", label)
		}
	}
	data, err := os.ReadFile(longPath)
	if err != nil || string(data) != "initial" {
		t.Fatalf("lock-only alias contention mutated target = %q, %v", data, err)
	}
}

func TestAtomicTransformV2UpdatesThroughShortLeafAlias(t *testing.T) {
	root := t.TempDir()
	longPath := filepath.Join(root, "config", "Long Configuration Settings.json")
	stateDir := filepath.Join(root, "protected-state")
	if err := os.MkdirAll(filepath.Dir(longPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(longPath, []byte("initial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := safefile.ProtectFile(longPath); err != nil {
		t.Fatal(err)
	}
	pointer, err := windows.UTF16PtrFromString(longPath)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]uint16, 2048)
	length, err := windows.GetShortPathName(pointer, &buffer[0], uint32(len(buffer)))
	if err != nil || length == 0 || length >= uint32(len(buffer)) {
		t.Skipf("8.3 aliases are unavailable: length=%d err=%v", length, err)
	}
	shortPath := windows.UTF16ToString(buffer[:length])
	if atomicTransformPathsEqual(shortPath, longPath) || !strings.Contains(filepath.Base(shortPath), "~") {
		t.Skipf("target leaf has no distinct 8.3 alias: %s", shortPath)
	}

	calls := 0
	if err := atomicTransformFileWithStateDir(
		shortPath, stateDir, 0o600,
		func(current []byte, exists bool) (atomicTransformResult, error) {
			calls++
			if !exists || string(current) != "initial" {
				return atomicTransformResult{}, fmt.Errorf(
					"short-alias snapshot = exists:%v bytes:%q", exists, current,
				)
			}
			return atomicTransformResult{Data: []byte("updated")}, nil
		},
	); err != nil {
		t.Fatalf("transform through distinct 8.3 target leaf: %v", err)
	}
	if calls != 1 {
		t.Fatalf("short-alias transform callback calls = %d, want 1", calls)
	}
	data, err := os.ReadFile(longPath)
	if err != nil || string(data) != "updated" {
		t.Fatalf("long target after short-alias update = %q, %v", data, err)
	}
	assertAtomicTransformV2NoArtifacts(t, longPath, stateDir)
}

func TestAtomicTransformV2PrivateNoopPreservesIdentityAndTimestamps(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "config", "settings.json")
	stateDir := filepath.Join(root, "protected-state")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"unchanged":true}`)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := safefile.ProtectFile(path); err != nil {
		t.Fatal(err)
	}
	type witness struct {
		identity   string
		protection string
		created    windows.Filetime
		written    windows.Filetime
	}
	inspect := func() (witness, error) {
		file, err := os.Open(path)
		if err != nil {
			return witness{}, err
		}
		identity, identityErr := atomicTransformOpenFileIdentity(file)
		protection, protectionErr := atomicTransformProtectionDigest(file)
		var info windows.ByHandleFileInformation
		infoErr := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info)
		closeErr := file.Close()
		if err := errors.Join(identityErr, protectionErr, infoErr, closeErr); err != nil {
			return witness{}, err
		}
		return witness{
			identity: identity, protection: protection,
			created: info.CreationTime, written: info.LastWriteTime,
		}, nil
	}
	before, err := inspect()
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	if err := atomicTransformFileWithStateDir(
		path, stateDir, 0o600,
		func(current []byte, exists bool) (atomicTransformResult, error) {
			calls++
			if !exists || !bytes.Equal(current, payload) {
				return atomicTransformResult{}, fmt.Errorf("unexpected no-op snapshot: exists:%v bytes:%q", exists, current)
			}
			return atomicTransformResult{Data: append([]byte(nil), current...)}, nil
		},
	); err != nil {
		t.Fatal(err)
	}
	after, err := inspect()
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || before != after {
		t.Fatalf("private no-op changed witness or retried: calls=%d before=%+v after=%+v", calls, before, after)
	}
	assertAtomicTransformV2NoArtifacts(t, path, stateDir)
}

func TestAtomicTransformV2ConvergesUnsafeDACLBeforeFirstReceipt(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "config", "settings.json")
	stateDir := filepath.Join(root, "protected-state")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	entry := func(sid *windows.SID, sidType windows.TRUSTEE_TYPE, mask windows.ACCESS_MASK) windows.EXPLICIT_ACCESS {
		return windows.EXPLICIT_ACCESS{
			AccessPermissions: mask,
			AccessMode:        windows.GRANT_ACCESS,
			Trustee: windows.TRUSTEE{
				TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: sidType,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		}
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		entry(currentUser.User.Sid, windows.TRUSTEE_IS_USER, windows.GENERIC_ALL),
		entry(everyone, windows.TRUSTEE_IS_WELL_KNOWN_GROUP, windows.GENERIC_READ),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil,
	); err != nil {
		t.Fatal(err)
	}
	if err := safefile.ValidatePrivateFile(path); err == nil {
		t.Fatal("unsafe fixture unexpectedly satisfies the private-file contract")
	}
	receiptSawPrivate := false
	restore := setAtomicTransformPhaseHookForTest(path, func(
		phase atomicTransformPhase, _ atomicTransformPhaseState,
	) error {
		if phase != atomicTransformPhaseAllocationPersisted {
			return nil
		}
		if err := safefile.ValidatePrivateFile(path); err != nil {
			return fmt.Errorf("allocation receipt preceded DACL convergence: %w", err)
		}
		receiptSawPrivate = true
		return nil
	})
	defer restore()
	calls := 0
	if err := atomicTransformFileWithStateDir(
		path, stateDir, 0o600,
		func(_ []byte, _ bool) (atomicTransformResult, error) {
			calls++
			return atomicTransformResult{Data: []byte("new")}, nil
		},
	); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("transform calls across pre-receipt DACL convergence = %d, want 2", calls)
	}
	if !receiptSawPrivate {
		t.Fatal("allocation receipt hook did not observe the converged private destination")
	}
	if err := safefile.ValidatePrivateFile(path); err != nil {
		t.Fatalf("replacement destination is not private: %v", err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "new" {
		t.Fatalf("replacement after DACL convergence = %q, %v", data, err)
	}
	assertAtomicTransformV2NoArtifacts(t, path, stateDir)
}

func TestAtomicTransformV2WaiterResolvesShortAliasOnlyAfterProtocolLock(t *testing.T) {
	root := t.TempDir()
	longPath := filepath.Join(root, "config", "Long Configuration Settings.json")
	stateDir := filepath.Join(root, "protected-state")
	if err := os.MkdirAll(filepath.Dir(longPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(longPath, []byte("initial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := safefile.ProtectFile(longPath); err != nil {
		t.Fatal(err)
	}
	pointer, err := windows.UTF16PtrFromString(longPath)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]uint16, 2048)
	length, err := windows.GetShortPathName(pointer, &buffer[0], uint32(len(buffer)))
	if err != nil || length == 0 || length >= uint32(len(buffer)) {
		t.Skipf("8.3 aliases are unavailable: length=%d err=%v", length, err)
	}
	shortPath := windows.UTF16ToString(buffer[:length])
	if atomicTransformPathsEqual(shortPath, longPath) || !strings.Contains(filepath.Base(shortPath), "~") {
		t.Skipf("target leaf has no distinct 8.3 alias: %s", shortPath)
	}
	ready := filepath.Join(root, "owner-detached")
	release := filepath.Join(root, "release-owner")
	command := func(target, payload string, hold bool) (*exec.Cmd, *bytes.Buffer) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestAtomicTransformV2ProtocolLockHelper$")
		output := new(bytes.Buffer)
		cmd.Stdout, cmd.Stderr = output, output
		env := []string{
			"DEFENSECLAW_V2_LOCK_HELPER=1",
			"DEFENSECLAW_V2_LOCK_PATH=" + target,
			"DEFENSECLAW_V2_LOCK_STATE=" + stateDir,
			"DEFENSECLAW_V2_LOCK_PAYLOAD=" + payload,
		}
		if hold {
			env = append(env,
				"DEFENSECLAW_V2_LOCK_READY="+ready,
				"DEFENSECLAW_V2_LOCK_RELEASE="+release,
				"DEFENSECLAW_V2_LOCK_HOLD_PHASE="+string(atomicTransformPhaseIntentPersisted),
				"DEFENSECLAW_V2_LOCK_HIDE_TARGET=1",
			)
		}
		cmd.Env = append(os.Environ(), env...)
		return cmd, output
	}
	owner, ownerOutput := command(longPath, "owner", true)
	if err := owner.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.WriteFile(release, []byte("release"), 0o600)
		if owner.Process != nil {
			_ = owner.Process.Kill()
		}
	})
	ownerDone := make(chan error, 1)
	go func() { ownerDone <- owner.Wait() }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("owner did not pause with the 8.3 target temporarily hidden\n%s", ownerOutput)
		}
		time.Sleep(10 * time.Millisecond)
	}
	waiter, waiterOutput := command(shortPath, "waiter", false)
	if err := waiter.Start(); err != nil {
		t.Fatal(err)
	}
	waiterDone := make(chan error, 1)
	go func() { waiterDone <- waiter.Wait() }()
	select {
	case err := <-waiterDone:
		t.Fatalf("8.3 waiter resolved or escaped while owner held protocol lock: %v\n%s", err, waiterOutput)
	case <-time.After(500 * time.Millisecond):
	}
	if err := os.WriteFile(release, []byte("release"), 0o600); err != nil {
		t.Fatal(err)
	}
	for label, item := range map[string]struct {
		done   <-chan error
		output *bytes.Buffer
	}{"owner": {ownerDone, ownerOutput}, "waiter": {waiterDone, waiterOutput}} {
		select {
		case err := <-item.done:
			if err != nil {
				t.Fatalf("%s process: %v\n%s", label, err, item.output)
			}
		case <-time.After(20 * time.Second):
			t.Fatalf("%s process did not finish", label)
		}
	}
	data, err := os.ReadFile(longPath)
	if err != nil || string(data) != "waiter" {
		t.Fatalf("canonical target after detached 8.3 waiter = %q, %v", data, err)
	}
	assertAtomicTransformV2NoArtifacts(t, longPath, stateDir)
}

func TestAtomicTransformV2BoundProtocolLockResistsAliasesAndRename(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "config", "settings.json")
	stateDir := filepath.Join(root, "protected-state")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("initial"), 0o600); err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareAtomicTransformStateDir(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(prepared, ".defenseclaw-v2-protocol.lock")
	hardlinkPath := filepath.Join(prepared, ".defenseclaw-v2-protocol-hardlink")
	// Materialize the persistent lock before probing conflicting pre-open
	// handle shapes.
	if err := withAtomicTransformV2ProtocolLock(path, prepared, nil, func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	lockPointer, err := windows.UTF16PtrFromString(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	deletePreopen, err := windows.CreateFile(
		lockPointer, windows.GENERIC_READ|windows.DELETE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0,
	)
	if err != nil {
		t.Fatalf("preopen protocol lock with DELETE/share-all: %v", err)
	}
	lockErr := withAtomicTransformV2ProtocolLock(path, prepared, nil, func(string) error {
		return fmt.Errorf("acquired protocol lock despite pre-open DELETE handle")
	})
	if closeErr := windows.CloseHandle(deletePreopen); closeErr != nil {
		t.Fatal(closeErr)
	}
	if !errors.Is(lockErr, windows.ERROR_SHARING_VIOLATION) &&
		!errors.Is(lockErr, windows.STATUS_SHARING_VIOLATION) {
		t.Fatalf("protocol acquisition with pre-open DELETE handle = %v, want sharing violation", lockErr)
	}
	tryImmediate := func(alias string) {
		t.Helper()
		file, err := os.OpenFile(alias, os.O_RDWR, 0o600)
		if err != nil {
			t.Fatalf("open lock alias %s: %v", alias, err)
		}
		defer file.Close()
		overlapped := new(windows.Overlapped)
		err = windows.LockFileEx(
			windows.Handle(file.Fd()),
			windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
			0, 1, 0, overlapped,
		)
		if err == nil {
			_ = windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, overlapped)
			t.Fatalf("alias acquired a second byte lock: %s", alias)
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			t.Fatalf("alias lock error = %v, want lock violation: %s", err, alias)
		}
	}
	if err := withAtomicTransformV2ProtocolLock(path, prepared, nil, func(string) error {
		original, err := os.Stat(lockPath)
		if err != nil {
			return err
		}
		if err := os.Rename(lockPath, lockPath+".renamed"); err == nil {
			return fmt.Errorf("renamed held protocol lock")
		}
		current, err := os.Stat(lockPath)
		if err != nil || !os.SameFile(original, current) {
			return fmt.Errorf("protocol lock identity changed after rejected rename: %w", err)
		}
		// Exercise the modern POSIX-semantics rename information class directly
		// on a non-DELETE alias opened after acquisition. This syscall is expected
		// to fail for missing DELETE access; paired with the pre-open DELETE/share-
		// all shape above, it covers both possible handle orderings.
		renameHandle, renameErr := os.OpenFile(lockPath, os.O_RDWR, 0)
		if renameErr != nil {
			return fmt.Errorf("open held lock for explicit POSIX rename probe: %w", renameErr)
		}
		stateBound, bindErr := bindAtomicTransformDirectory(prepared)
		if bindErr != nil {
			_ = renameHandle.Close()
			return bindErr
		}
		type fileRenameInformationEx struct {
			Flags          uint32
			RootDirectory  windows.Handle
			FileNameLength uint32
			FileName       [1]uint16
		}
		newLeaf, utfErr := windows.UTF16FromString(".defenseclaw-v2-protocol-posix-renamed.lock")
		if utfErr != nil {
			_ = stateBound.Close()
			_ = renameHandle.Close()
			return utfErr
		}
		newLeaf = newLeaf[:len(newLeaf)-1]
		var layout fileRenameInformationEx
		buffer := make([]byte, int(unsafe.Offsetof(layout.FileName))+len(newLeaf)*2)
		info := (*fileRenameInformationEx)(unsafe.Pointer(&buffer[0]))
		info.Flags = windows.FILE_RENAME_REPLACE_IF_EXISTS | windows.FILE_RENAME_POSIX_SEMANTICS
		info.RootDirectory = windows.Handle(stateBound.file.Fd())
		info.FileNameLength = uint32(len(newLeaf) * 2)
		copy(unsafe.Slice(&info.FileName[0], len(newLeaf)), newLeaf)
		var renameStatus windows.IO_STATUS_BLOCK
		const fileRenameInformationExClass = 65
		renameErr = windows.NtSetInformationFile(
			windows.Handle(renameHandle.Fd()), &renameStatus, &buffer[0], uint32(len(buffer)),
			fileRenameInformationExClass,
		)
		closeErr := errors.Join(stateBound.Close(), renameHandle.Close())
		if renameErr == nil {
			return errors.Join(fmt.Errorf("FileRenameInformationEx POSIX rename moved held protocol lock"), closeErr)
		}
		if closeErr != nil {
			return closeErr
		}
		current, err = os.Stat(lockPath)
		if err != nil || !os.SameFile(original, current) {
			return fmt.Errorf("protocol lock identity changed after rejected POSIX rename: %w", err)
		}
		tryImmediate(strings.ToUpper(lockPath))
		if err := os.Link(lockPath, hardlinkPath); err != nil {
			return fmt.Errorf("create protocol-lock hardlink alias: %w", err)
		}
		tryImmediate(hardlinkPath)
		pointer, pointerErr := windows.UTF16PtrFromString(lockPath)
		if pointerErr != nil {
			return pointerErr
		}
		short := make([]uint16, 2048)
		length, shortErr := windows.GetShortPathName(pointer, &short[0], uint32(len(short)))
		if shortErr == nil && length > 0 && length < uint32(len(short)) {
			shortPath := windows.UTF16ToString(short[:length])
			if !atomicTransformPathsEqual(shortPath, lockPath) {
				tryImmediate(shortPath)
			}
		}
		lockPointer, pointerErr := windows.UTF16PtrFromString(lockPath)
		deleteHandle, deleteErr := windows.CreateFile(
			lockPointer, windows.DELETE,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
			nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0,
		)
		if deleteErr == nil {
			_ = windows.CloseHandle(deleteHandle)
			return fmt.Errorf("opened held protocol lock for DELETE")
		}
		if !errors.Is(deleteErr, windows.ERROR_SHARING_VIOLATION) {
			return fmt.Errorf("DELETE-open error = %w, want sharing violation", deleteErr)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(hardlinkPath); err != nil {
		t.Fatal(err)
	}
}

func TestAtomicTransformV2BoundProtocolLockReleasesAfterOwnerExit(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "config", "settings.json")
	stateDir := filepath.Join(root, "protected-state")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("initial"), 0o600); err != nil {
		t.Fatal(err)
	}
	ready := filepath.Join(root, "owner-ready")
	command := exec.Command(os.Args[0], "-test.run=^TestAtomicTransformV2ProtocolLockHelper$")
	command.Env = append(os.Environ(),
		"DEFENSECLAW_V2_LOCK_HELPER=1",
		"DEFENSECLAW_V2_LOCK_ONLY=1",
		"DEFENSECLAW_V2_LOCK_EXIT_HELD=1",
		"DEFENSECLAW_V2_LOCK_PATH="+path,
		"DEFENSECLAW_V2_LOCK_STATE="+stateDir,
		"DEFENSECLAW_V2_LOCK_READY="+ready,
	)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("owner process did not acquire protocol lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	err := command.Wait()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 95 {
		t.Fatalf("held-lock owner exit = %v, want 95", err)
	}
	lockPath := filepath.Join(stateDir, ".defenseclaw-v2-protocol.lock")
	before, err := os.Stat(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareAtomicTransformStateDir(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	acquired := false
	if err := withAtomicTransformV2ProtocolLock(path, prepared, nil, func(string) error {
		acquired = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(lockPath)
	same := err == nil && os.SameFile(before, after)
	if !same || !acquired {
		t.Fatalf("successor lock identity/acquisition = same:%v acquired:%v err:%v", same, acquired, err)
	}
}

func TestAtomicTransformV2FreshProcessExitMatrix(t *testing.T) {
	phaseOccurrences := func(phase atomicTransformPhase, count int) []atomicTransformV2ExitBoundary {
		result := make([]atomicTransformV2ExitBoundary, 0, count)
		for occurrence := 1; occurrence <= count; occurrence++ {
			result = append(result, atomicTransformV2ExitBoundary{phase, occurrence})
		}
		return result
	}
	bootstrap := append(phaseOccurrences(atomicTransformPhaseAllocationBootstrap, 6),
		atomicTransformV2ExitBoundary{atomicTransformPhaseAllocationPersisted, 1})
	preReceipt := []atomicTransformV2ExitBoundary{
		{atomicTransformPhasePreReceiptArtifact, 1},
		{atomicTransformPhasePreReceiptArtifact, 2},
		{atomicTransformPhasePreReceiptArtifact, 3},
		{atomicTransformPhasePreReceiptArtifact, 4},
		{atomicTransformPhasePreReceiptArtifact, 5},
	}
	commonTargetBootstrap := phaseOccurrences(atomicTransformPhaseTerminalMarkerBootstrap, 6)
	replacementTargetBootstrap := append(
		append(phaseOccurrences(atomicTransformPhasePayloadMarkerBootstrap, 6),
			phaseOccurrences(atomicTransformPhaseStageMarkerBootstrap, 6)...),
		phaseOccurrences(atomicTransformPhaseReadyMarkerBootstrap, 6)...,
	)
	stagingReceiptBootstrap := phaseOccurrences(atomicTransformPhaseStagingBootstrap, 6)
	preparedReceiptBootstrap := phaseOccurrences(atomicTransformPhasePreparedBootstrap, 6)
	staged := []atomicTransformV2ExitBoundary{
		{atomicTransformPhaseStagingLocated, 1},
		{atomicTransformPhaseStagePartial, 1},
		{atomicTransformPhaseStageFinalized, 1},
		{atomicTransformPhaseIntentPersisted, 1},
	}
	published := []atomicTransformV2ExitBoundary{
		{atomicTransformPhasePublished, 1},
		{atomicTransformPhaseFinalPublicationValidated, 1},
		{atomicTransformPhaseTerminalWitnessed, 1},
		{atomicTransformPhaseCleanupStarted, 1},
		{atomicTransformPhaseMarkerEstablished, 1},
		{atomicTransformPhaseMarkerEstablished, 2},
		{atomicTransformPhaseMarkerEstablished, 3},
		{atomicTransformPhaseCompleted, 1},
		{atomicTransformPhaseCompleteRetired, 1},
		{atomicTransformPhaseAllocationRetired, 1},
		{atomicTransformPhaseMarkerRetired, 1},
		{atomicTransformPhaseMarkerRetired, 2},
		{atomicTransformPhaseMarkerRetired, 3},
		{atomicTransformPhaseStagingRetired, 1},
		{atomicTransformPhasePreparedRetired, 1},
		{atomicTransformPhaseTerminalRetired, 1},
	}
	published = append(
		append(phaseOccurrences(atomicTransformPhaseTerminalBootstrap, 6),
			phaseOccurrences(atomicTransformPhaseCompleteBootstrap, 6)...),
		published...,
	)
	for _, operation := range []string{"create", "update", "remove"} {
		boundaries := append([]atomicTransformV2ExitBoundary(nil), published...)
		early := append(append(append([]atomicTransformV2ExitBoundary{}, bootstrap...), commonTargetBootstrap...),
			stagingReceiptBootstrap...)
		switch operation {
		case "create":
			early = append(early, replacementTargetBootstrap...)
			early = append(early, preReceipt...)
			early = append(early, preparedReceiptBootstrap...)
			boundaries = append(append(early, staged...), boundaries...)
			boundaries = removeAtomicTransformV2ExitBoundaries(boundaries,
				atomicTransformPhaseDetached, atomicTransformPhaseCleanupStarted)
		case "update":
			early = append(early, replacementTargetBootstrap...)
			early = append(early, preReceipt...)
			early = append(early, preparedReceiptBootstrap...)
			boundaries = append(append(early, staged...), boundaries...)
			for _, boundary := range []string{
				atomicTransformV2ReplaceBoundaryBeforeTargetFlush,
				atomicTransformV2ReplaceBoundaryAfterTargetFlush,
				atomicTransformV2ReplaceBoundaryBeforeBackupFlush,
				atomicTransformV2ReplaceBoundaryAfterBackupFlush,
				atomicTransformV2ReplaceBoundaryBeforeDirectorySync,
				atomicTransformV2ReplaceBoundaryAfterDirectorySync,
			} {
				boundaries = append(boundaries, atomicTransformV2ExitBoundary{
					phase: atomicTransformPhase("replace-" + boundary), occurrence: 1,
				})
			}
		case "remove":
			removePreReceipt := append([]atomicTransformV2ExitBoundary(nil), preReceipt[:2]...)
			early = append(early, removePreReceipt...)
			early = append(early, preparedReceiptBootstrap...)
			boundaries = append(early, boundaries...)
			boundaries = removeAtomicTransformV2ExitBoundaries(boundaries,
				atomicTransformPhaseStagingLocated, atomicTransformPhaseStagePartial,
				atomicTransformPhaseStageFinalized)
			boundaries = capAtomicTransformV2ExitOccurrences(boundaries,
				atomicTransformPhaseMarkerEstablished, atomicTransformPhaseMarkerRetired)
		}
		for _, point := range boundaries {
			point := point
			name := fmt.Sprintf("%s/%s-%d", operation, point.phase, point.occurrence)
			t.Run(name, func(t *testing.T) {
				root := t.TempDir()
				path := filepath.Join(root, "config", "settings.json")
				stateDir := filepath.Join(root, "protected-state")
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				initialExists := operation != "create"
				initial := []byte(`{"old":true}`)
				if initialExists {
					if err := os.WriteFile(path, initial, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				command := exec.Command(os.Args[0], "-test.run=^TestAtomicTransformV2HardExitHelper$")
				command.Env = atomicTransformV2HardExitEnv(
					"DEFENSECLAW_V2_HARD_EXIT_HELPER=1",
					"DEFENSECLAW_V2_HARD_EXIT_PATH="+path,
					"DEFENSECLAW_V2_HARD_EXIT_STATE="+stateDir,
					"DEFENSECLAW_V2_HARD_EXIT_OPERATION="+operation,
					"DEFENSECLAW_V2_HARD_EXIT_PHASE="+string(point.phase),
					fmt.Sprintf("DEFENSECLAW_V2_HARD_EXIT_OCCURRENCE=%d", point.occurrence),
				)
				output, runErr := command.CombinedOutput()
				var exitErr *exec.ExitError
				if !errors.As(runErr, &exitErr) || exitErr.ExitCode() != atomicTransformV2HardExitCode {
					t.Fatalf("helper exit = %v; want %d\n%s", runErr, atomicTransformV2HardExitCode, output)
				}
				committed, err := atomicTransformV2BoundaryCommittedAfterExit(path, stateDir, operation, point)
				if err != nil {
					t.Fatalf("classify fresh-process decision: %v", err)
				}
				if err := recoverAtomicTransformV2(path, stateDir); err != nil {
					t.Fatalf("fresh-process recovery: %v", err)
				}

				data, readErr := os.ReadFile(path)
				switch {
				case committed && operation == "remove":
					if !errors.Is(readErr, os.ErrNotExist) {
						t.Fatalf("committed removal target exists: %v", readErr)
					}
				case committed:
					if readErr != nil || !bytes.Equal(data, atomicTransformV2HardExitPayload()) {
						t.Fatalf("committed result mismatch: bytes=%d err=%v", len(data), readErr)
					}
				case initialExists:
					if readErr != nil || !bytes.Equal(data, initial) {
						t.Fatalf("aborted result mismatch: %q err=%v", data, readErr)
					}
				default:
					if !errors.Is(readErr, os.ErrNotExist) {
						t.Fatalf("aborted create left target: %v", readErr)
					}
				}
				assertAtomicTransformV2NoArtifacts(t, path, stateDir)
			})
		}
	}
}

func TestAtomicTransformV2CompleteBootstrapDecisionAwareRecovery(t *testing.T) {
	point := atomicTransformV2ExitBoundary{
		phase: atomicTransformPhaseCompleteBootstrap, occurrence: 3,
	}
	for _, test := range []struct {
		name           string
		forceSafeAbort bool
		wantCommitted  bool
	}{
		{name: "commit", wantCommitted: true},
		{name: "safe-abort", forceSafeAbort: true},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// A caller's test-control environment must never silently select the
			// helper's abort path. The safe-abort case opts in again explicitly
			// after atomicTransformV2HardExitEnv removes this inherited value.
			t.Setenv("DEFENSECLAW_V2_HARD_EXIT_SAFE_ABORT", "1")
			root := t.TempDir()
			path := filepath.Join(root, "config", "settings.json")
			stateDir := filepath.Join(root, "protected-state")
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			initial := []byte(`{"old":true}`)
			if err := os.WriteFile(path, initial, 0o600); err != nil {
				t.Fatal(err)
			}

			env := []string{
				"DEFENSECLAW_V2_HARD_EXIT_HELPER=1",
				"DEFENSECLAW_V2_HARD_EXIT_PATH=" + path,
				"DEFENSECLAW_V2_HARD_EXIT_STATE=" + stateDir,
				"DEFENSECLAW_V2_HARD_EXIT_OPERATION=update",
				"DEFENSECLAW_V2_HARD_EXIT_PHASE=" + string(point.phase),
				fmt.Sprintf("DEFENSECLAW_V2_HARD_EXIT_OCCURRENCE=%d", point.occurrence),
			}
			if test.forceSafeAbort {
				env = append(env, "DEFENSECLAW_V2_HARD_EXIT_SAFE_ABORT=1")
			}
			command := exec.Command(os.Args[0], "-test.run=^TestAtomicTransformV2HardExitHelper$")
			command.Env = atomicTransformV2HardExitEnv(env...)
			output, runErr := command.CombinedOutput()
			var exitErr *exec.ExitError
			if !errors.As(runErr, &exitErr) || exitErr.ExitCode() != atomicTransformV2HardExitCode {
				t.Fatalf("helper exit = %v; want %d\n%s", runErr, atomicTransformV2HardExitCode, output)
			}

			committed, err := atomicTransformV2BoundaryCommittedAfterExit(path, stateDir, "update", point)
			if err != nil {
				t.Fatal(err)
			}
			if committed != test.wantCommitted {
				t.Fatalf("durable decision committed = %t; want %t", committed, test.wantCommitted)
			}
			if err := recoverAtomicTransformV2(path, stateDir); err != nil {
				t.Fatalf("fresh-process recovery: %v", err)
			}
			want := initial
			if test.wantCommitted {
				want = atomicTransformV2HardExitPayload()
			}
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("recovered bytes = %d, %v; want %d", len(got), err, len(want))
			}
			assertAtomicTransformV2NoArtifacts(t, path, stateDir)
		})
	}
}

func TestAtomicTransformV2AmbiguousPreparedStateIsIdempotent(t *testing.T) {
	for _, mutation := range []string{"edit", "recreate", "delete"} {
		t.Run(mutation, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "config", "settings.json")
			stateDir := filepath.Join(root, "protected-state")
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := safefile.ProtectFile(path); err != nil {
				t.Fatal(err)
			}
			canonical, err := canonicalAtomicTransformTargetPath(path)
			if err != nil {
				t.Fatal(err)
			}
			mutated := false
			restore := setAtomicTransformPhaseHookForTest(canonical, func(
				phase atomicTransformPhase, state atomicTransformPhaseState,
			) error {
				if phase != atomicTransformPhaseIntentPersisted || mutated {
					return nil
				}
				mutated = true
				switch mutation {
				case "edit":
					return os.WriteFile(state.TargetPath, []byte("operator-edit"), 0o600)
				case "recreate":
					if err := os.Remove(state.TargetPath); err != nil {
						return err
					}
					return os.WriteFile(state.TargetPath, []byte("operator-recreate"), 0o600)
				case "delete":
					return os.Remove(state.TargetPath)
				}
				return nil
			})
			defer restore()
			if err := atomicTransformFileWithStateDir(
				path, stateDir, 0o600,
				func([]byte, bool) (atomicTransformResult, error) {
					return atomicTransformResult{Data: atomicTransformV2HardExitPayload()}, nil
				},
			); err == nil {
				t.Fatal("ambiguous prepared mutation unexpectedly committed")
			}
			if !mutated {
				t.Fatal("prepared mutation seam was not reached")
			}

			snapshot := func() map[string]string {
				t.Helper()
				result := map[string]string{}
				for _, dir := range []string{filepath.Dir(path), stateDir} {
					entries, readErr := os.ReadDir(dir)
					if errors.Is(readErr, os.ErrNotExist) {
						continue
					}
					if readErr != nil {
						t.Fatal(readErr)
					}
					for _, entry := range entries {
						if entry.IsDir() {
							continue
						}
						file, openErr := os.Open(filepath.Join(dir, entry.Name()))
						if openErr != nil {
							t.Fatal(openErr)
						}
						identity, identityErr := atomicTransformOpenFileIdentity(file)
						data, dataErr := io.ReadAll(file)
						closeErr := file.Close()
						if err := errors.Join(identityErr, dataErr, closeErr); err != nil {
							t.Fatal(err)
						}
						result[dir+"|"+entry.Name()] = identity + "|" + atomicTransformDigest(data)
					}
				}
				return result
			}
			before := snapshot()
			hasReceipt := false
			for name := range before {
				if strings.Contains(filepath.Base(name), atomicTransformV2ReceiptPrefix) {
					hasReceipt = true
				}
			}
			if !hasReceipt {
				t.Fatal("ambiguous state did not retain recovery receipts")
			}
			for recovery := 0; recovery < 2; recovery++ {
				if err := recoverAtomicTransformV2(path, stateDir); err == nil {
					t.Fatalf("ambiguous recovery %d unexpectedly succeeded", recovery+1)
				}
				after := snapshot()
				if !reflect.DeepEqual(after, before) {
					t.Fatalf("ambiguous recovery %d mutated names/IDs/bytes\nbefore=%v\nafter=%v", recovery+1, before, after)
				}
			}
		})
	}
}

func TestAtomicTransformV2TerminalRecoveryPreservesOperatorLive(t *testing.T) {
	occurrences := func(phase atomicTransformPhase, first, last int) []atomicTransformV2ExitBoundary {
		points := make([]atomicTransformV2ExitBoundary, 0, last-first+1)
		for occurrence := first; occurrence <= last; occurrence++ {
			points = append(points, atomicTransformV2ExitBoundary{phase, occurrence})
		}
		return points
	}
	boundaries := append(occurrences(atomicTransformPhaseTerminalBootstrap, 4, 6),
		occurrences(atomicTransformPhaseCompleteBootstrap, 1, 6)...)
	boundaries = append(boundaries,
		atomicTransformV2ExitBoundary{atomicTransformPhaseTerminalWitnessed, 1},
		atomicTransformV2ExitBoundary{atomicTransformPhaseCleanupStarted, 1},
	)
	boundaries = append(boundaries, occurrences(atomicTransformPhaseMarkerEstablished, 1, 3)...)
	boundaries = append(boundaries,
		atomicTransformV2ExitBoundary{atomicTransformPhaseCompleted, 1},
		atomicTransformV2ExitBoundary{atomicTransformPhaseCompleteRetired, 1},
	)
	boundaries = append(boundaries, occurrences(atomicTransformPhaseMarkerRetired, 1, 3)...)
	boundaries = append(boundaries,
		atomicTransformV2ExitBoundary{atomicTransformPhaseAllocationRetired, 1},
		atomicTransformV2ExitBoundary{atomicTransformPhaseStagingRetired, 1},
		atomicTransformV2ExitBoundary{atomicTransformPhasePreparedRetired, 1},
		atomicTransformV2ExitBoundary{atomicTransformPhaseTerminalRetired, 1},
	)

	for _, decision := range []string{"commit", "abort"} {
		for _, point := range boundaries {
			for _, mutation := range []string{"edit", "recreate", "delete"} {
				decision, point, mutation := decision, point, mutation
				t.Run(fmt.Sprintf("%s/%s-%d/%s", decision, point.phase, point.occurrence, mutation), func(t *testing.T) {
					root := t.TempDir()
					path := filepath.Join(root, "config", "settings.json")
					stateDir := filepath.Join(root, "protected-state")
					if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
						t.Fatal(err)
					}
					if err := safefile.ProtectFile(path); err != nil {
						t.Fatal(err)
					}
					crash := exec.Command(os.Args[0], "-test.run=^TestAtomicTransformV2HardExitHelper$")
					crash.Env = atomicTransformV2HardExitEnv(
						"DEFENSECLAW_V2_HARD_EXIT_HELPER=1",
						"DEFENSECLAW_V2_HARD_EXIT_PATH="+path,
						"DEFENSECLAW_V2_HARD_EXIT_STATE="+stateDir,
						"DEFENSECLAW_V2_HARD_EXIT_OPERATION=update",
						"DEFENSECLAW_V2_HARD_EXIT_PHASE="+string(point.phase),
						fmt.Sprintf("DEFENSECLAW_V2_HARD_EXIT_OCCURRENCE=%d", point.occurrence),
					)
					if decision == "abort" {
						crash.Env = append(crash.Env, "DEFENSECLAW_V2_HARD_EXIT_SAFE_ABORT=1")
					}
					output, runErr := crash.CombinedOutput()
					var exitErr *exec.ExitError
					if !errors.As(runErr, &exitErr) || exitErr.ExitCode() != atomicTransformV2HardExitCode {
						t.Fatalf("terminal helper exit = %v; want %d\n%s", runErr, atomicTransformV2HardExitCode, output)
					}

					operatorBytes := []byte(fmt.Sprintf("operator-%s-%d-%s", point.phase, point.occurrence, mutation))
					switch mutation {
					case "edit":
						if err := os.WriteFile(path, operatorBytes, 0o600); err != nil {
							t.Fatal(err)
						}
					case "recreate":
						if err := os.Remove(path); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(path, operatorBytes, 0o600); err != nil {
							t.Fatal(err)
						}
					case "delete":
						if err := os.Remove(path); err != nil {
							t.Fatal(err)
						}
					}
					wantExists := mutation != "delete"
					wantIdentity := ""
					if wantExists {
						file, err := os.Open(path)
						if err != nil {
							t.Fatal(err)
						}
						wantIdentity, err = atomicTransformOpenFileIdentity(file)
						closeErr := file.Close()
						if err := errors.Join(err, closeErr); err != nil {
							t.Fatal(err)
						}
					}
					for recovery := 0; recovery < 2; recovery++ {
						recoverProcess := exec.Command(os.Args[0], "-test.run=^TestAtomicTransformV2HardExitHelper$")
						recoverProcess.Env = atomicTransformV2HardExitEnv(
							"DEFENSECLAW_V2_HARD_EXIT_HELPER=1",
							"DEFENSECLAW_V2_HARD_EXIT_RECOVER=1",
							"DEFENSECLAW_V2_HARD_EXIT_PATH="+path,
							"DEFENSECLAW_V2_HARD_EXIT_STATE="+stateDir,
						)
						if output, err := recoverProcess.CombinedOutput(); err != nil {
							t.Fatalf("fresh terminal recovery %d: %v\n%s", recovery+1, err, output)
						}
					}
					file, err := os.Open(path)
					if !wantExists {
						if !errors.Is(err, os.ErrNotExist) {
							if file != nil {
								_ = file.Close()
							}
							t.Fatalf("terminal recovery recreated deleted live: %v", err)
						}
					} else {
						if err != nil {
							t.Fatal(err)
						}
						identity, identityErr := atomicTransformOpenFileIdentity(file)
						data, readErr := io.ReadAll(file)
						closeErr := file.Close()
						if err := errors.Join(identityErr, readErr, closeErr); err != nil {
							t.Fatal(err)
						}
						if identity != wantIdentity || !bytes.Equal(data, operatorBytes) {
							t.Fatalf("terminal recovery changed live identity/bytes: %s/%s %q", identity, wantIdentity, data)
						}
					}
					assertAtomicTransformV2NoArtifacts(t, path, stateDir)
				})
			}
		}
	}
}

func TestAtomicTransformV2TerminalCleanupIgnoresPostPReparseLeaf(t *testing.T) {
	probeRoot := t.TempDir()
	probeTarget := filepath.Join(probeRoot, "probe-target")
	probeLink := filepath.Join(probeRoot, "probe-link")
	if err := os.WriteFile(probeTarget, []byte("probe"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(probeTarget, probeLink); err != nil {
		t.Skipf("file reparse-point creation unavailable: %v", err)
	}
	if err := os.Remove(probeLink); err != nil {
		t.Fatal(err)
	}

	points := []atomicTransformV2ExitBoundary{
		{atomicTransformPhaseTerminalWitnessed, 1},
		{atomicTransformPhaseCompleted, 1},
		{atomicTransformPhaseCompleteRetired, 1},
	}
	for _, point := range points {
		t.Run(string(point.phase), func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "config", "settings.json")
			stateDir := filepath.Join(root, "protected-state")
			reparseTarget := filepath.Join(root, "operator-owned-target")
			operatorData := []byte("operator-owned-reparse-target-" + string(point.phase))
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := safefile.ProtectFile(path); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(reparseTarget, operatorData, 0o600); err != nil {
				t.Fatal(err)
			}
			operator, err := os.Open(reparseTarget)
			if err != nil {
				t.Fatal(err)
			}
			operatorIdentity, identityErr := atomicTransformOpenFileIdentity(operator)
			operatorCloseErr := operator.Close()
			if err := errors.Join(identityErr, operatorCloseErr); err != nil {
				t.Fatal(err)
			}

			crash := exec.Command(os.Args[0], "-test.run=^TestAtomicTransformV2HardExitHelper$")
			crash.Env = atomicTransformV2HardExitEnv(
				"DEFENSECLAW_V2_HARD_EXIT_HELPER=1",
				"DEFENSECLAW_V2_HARD_EXIT_PATH="+path,
				"DEFENSECLAW_V2_HARD_EXIT_STATE="+stateDir,
				"DEFENSECLAW_V2_HARD_EXIT_OPERATION=update",
				"DEFENSECLAW_V2_POST_P_REPARSE_TARGET="+reparseTarget,
				"DEFENSECLAW_V2_HARD_EXIT_PHASE="+string(point.phase),
				fmt.Sprintf("DEFENSECLAW_V2_HARD_EXIT_OCCURRENCE=%d", point.occurrence),
			)
			output, runErr := crash.CombinedOutput()
			var exitErr *exec.ExitError
			if !errors.As(runErr, &exitErr) || exitErr.ExitCode() != atomicTransformV2HardExitCode {
				t.Fatalf("post-P reparse helper exit = %v; want %d\n%s", runErr, atomicTransformV2HardExitCode, output)
			}
			linkInfo, err := os.Lstat(path)
			if err != nil || linkInfo.Mode()&os.ModeSymlink == 0 {
				t.Fatalf("post-P live leaf is not the operator reparse point: mode=%v err=%v", linkInfo, err)
			}
			linkTarget, err := os.Readlink(path)
			if err != nil || !atomicTransformPathsEqual(linkTarget, reparseTarget) {
				t.Fatalf("post-P reparse target = %q, %v; want %q", linkTarget, err, reparseTarget)
			}

			for recovery := 0; recovery < 2; recovery++ {
				if output, err := atomicTransformV2RunFreshRecoveryForTest(t, path, stateDir); err != nil {
					t.Fatalf("fresh reparse-leaf recovery %d: %v\n%s", recovery+1, err, output)
				}
			}
			linkInfo, err = os.Lstat(path)
			if err != nil || linkInfo.Mode()&os.ModeSymlink == 0 {
				t.Fatalf("terminal cleanup changed operator reparse leaf: mode=%v err=%v", linkInfo, err)
			}
			linkTarget, err = os.Readlink(path)
			if err != nil || !atomicTransformPathsEqual(linkTarget, reparseTarget) {
				t.Fatalf("terminal cleanup changed reparse target = %q, %v", linkTarget, err)
			}
			operator, err = os.Open(reparseTarget)
			if err != nil {
				t.Fatal(err)
			}
			identity, identityErr := atomicTransformOpenFileIdentity(operator)
			data, readErr := io.ReadAll(operator)
			operatorCloseErr = operator.Close()
			if err := errors.Join(identityErr, readErr, operatorCloseErr); err != nil {
				t.Fatal(err)
			}
			if identity != operatorIdentity || !bytes.Equal(data, operatorData) {
				t.Fatalf("terminal cleanup followed/changed reparse target: id=%s/%s data=%q",
					identity, operatorIdentity, data)
			}
			assertAtomicTransformV2NoArtifacts(t, path, stateDir)

			transformCalled := false
			err = atomicTransformFileWithStateDir(
				path, stateDir, 0o600,
				func(_ []byte, _ bool) (atomicTransformResult, error) {
					transformCalled = true
					return atomicTransformResult{Data: []byte("must-not-follow")}, nil
				},
			)
			if err == nil || transformCalled {
				t.Fatalf("new transform through reparse leaf = called:%t err:%v; want pre-callback rejection", transformCalled, err)
			}
			finalData, err := os.ReadFile(reparseTarget)
			if err != nil || !bytes.Equal(finalData, operatorData) {
				t.Fatalf("rejected new transform changed reparse target = %q, %v", finalData, err)
			}
		})
	}
}

func TestAtomicTransformV2RecoversAcrossShortAndLongLeafAliases(t *testing.T) {
	for _, phase := range []atomicTransformPhase{
		atomicTransformPhaseIntentPersisted, atomicTransformPhasePublished,
	} {
		t.Run(string(phase), func(t *testing.T) {
			root := t.TempDir()
			longPath := filepath.Join(root, "config", "Long Configuration Settings.json")
			stateDir := filepath.Join(root, "protected-state")
			if err := os.MkdirAll(filepath.Dir(longPath), 0o700); err != nil {
				t.Fatal(err)
			}
			initial := []byte(`{"old":true}`)
			if err := os.WriteFile(longPath, initial, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := safefile.ProtectFile(longPath); err != nil {
				t.Fatal(err)
			}
			longPointer, err := windows.UTF16PtrFromString(longPath)
			if err != nil {
				t.Fatal(err)
			}
			buffer := make([]uint16, 2048)
			length, err := windows.GetShortPathName(longPointer, &buffer[0], uint32(len(buffer)))
			if err != nil || length == 0 || length >= uint32(len(buffer)) {
				t.Skipf("8.3 aliases are unavailable: length=%d err=%v", length, err)
			}
			shortPath := windows.UTF16ToString(buffer[:length])
			if atomicTransformPathsEqual(shortPath, longPath) || !strings.Contains(filepath.Base(shortPath), "~") {
				t.Skipf("target leaf has no distinct 8.3 alias: %s", shortPath)
			}

			command := exec.Command(os.Args[0], "-test.run=^TestAtomicTransformV2HardExitHelper$")
			command.Env = atomicTransformV2HardExitEnv(
				"DEFENSECLAW_V2_HARD_EXIT_HELPER=1",
				"DEFENSECLAW_V2_HARD_EXIT_PATH="+shortPath,
				"DEFENSECLAW_V2_HARD_EXIT_STATE="+stateDir,
				"DEFENSECLAW_V2_HARD_EXIT_OPERATION=update",
				"DEFENSECLAW_V2_HARD_EXIT_PHASE="+string(phase),
				"DEFENSECLAW_V2_HARD_EXIT_OCCURRENCE=1",
			)
			output, runErr := command.CombinedOutput()
			var exitErr *exec.ExitError
			if !errors.As(runErr, &exitErr) || exitErr.ExitCode() != atomicTransformV2HardExitCode {
				t.Fatalf("short-alias helper exit = %v; want %d\n%s", runErr, atomicTransformV2HardExitCode, output)
			}
			if err := recoverAtomicTransformV2(longPath, stateDir); err != nil {
				t.Fatalf("recover short-name transaction through long name: %v", err)
			}
			data, err := os.ReadFile(longPath)
			want := initial
			if phase == atomicTransformPhasePublished {
				want = atomicTransformV2HardExitPayload()
			}
			if err != nil || !bytes.Equal(data, want) {
				t.Fatalf("alias recovery live state = %q, %v; want %q", data, err, want)
			}
			assertAtomicTransformV2NoArtifacts(t, longPath, stateDir)
		})
	}
}

func atomicTransformV2DistinctShortLeafPathForTest(t *testing.T, longPath string) string {
	t.Helper()
	pointer, err := windows.UTF16PtrFromString(longPath)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]uint16, 2048)
	length, err := windows.GetShortPathName(pointer, &buffer[0], uint32(len(buffer)))
	if err != nil || length == 0 || length >= uint32(len(buffer)) {
		t.Skipf("8.3 aliases are unavailable: length=%d err=%v", length, err)
	}
	shortLeaf := strings.ToUpper(filepath.Base(windows.UTF16ToString(buffer[:length])))
	if atomicTransformPathsEqual(shortLeaf, filepath.Base(longPath)) || !strings.Contains(shortLeaf, "~") {
		t.Skipf("target leaf has no distinct 8.3 alias: %s", shortLeaf)
	}
	return filepath.Join(filepath.Dir(longPath), shortLeaf)
}

func atomicTransformV2RunShortRepairCrashForTest(
	t *testing.T, ownerPath, stateDir string, boundary string,
) []byte {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestAtomicTransformV2HardExitHelper$")
	command.Env = atomicTransformV2HardExitEnv(
		"DEFENSECLAW_V2_HARD_EXIT_HELPER=1",
		"DEFENSECLAW_V2_HARD_EXIT_PATH="+ownerPath,
		"DEFENSECLAW_V2_HARD_EXIT_STATE="+stateDir,
		"DEFENSECLAW_V2_HARD_EXIT_OPERATION=update",
		"DEFENSECLAW_V2_FORCE_SHORT_REPAIR=1",
		"DEFENSECLAW_V2_HARD_EXIT_PHASE=replace-"+boundary,
		"DEFENSECLAW_V2_HARD_EXIT_OCCURRENCE=1",
	)
	output, runErr := command.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(runErr, &exitErr) || exitErr.ExitCode() != atomicTransformV2HardExitCode {
		t.Fatalf("short-repair helper exit = %v; want %d\n%s", runErr, atomicTransformV2HardExitCode, output)
	}
	return output
}

func atomicTransformV2RunFreshRecoveryForTest(t *testing.T, path, stateDir string) ([]byte, error) {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestAtomicTransformV2HardExitHelper$")
	command.Env = atomicTransformV2HardExitEnv(
		"DEFENSECLAW_V2_HARD_EXIT_HELPER=1",
		"DEFENSECLAW_V2_HARD_EXIT_RECOVER=1",
		"DEFENSECLAW_V2_HARD_EXIT_PATH="+path,
		"DEFENSECLAW_V2_HARD_EXIT_STATE="+stateDir,
	)
	return command.CombinedOutput()
}

func TestAtomicTransformV2ShortNameRepairFreshProcessMatrix(t *testing.T) {
	boundaries := []string{
		atomicTransformV2ReplaceBoundaryBackupShortCleared,
		atomicTransformV2ReplaceBoundaryTargetShortSet,
		atomicTransformV2ReplaceBoundaryShortFlushed,
	}
	for _, owner := range []string{"short-owner", "long-owner"} {
		for _, boundary := range boundaries {
			t.Run(owner+"/"+boundary, func(t *testing.T) {
				root := t.TempDir()
				longPath := filepath.Join(root, "config", "Long Configuration Settings.json")
				stateDir := filepath.Join(root, "protected-state")
				if err := os.MkdirAll(filepath.Dir(longPath), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(longPath, []byte(`{"old":true}`), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := safefile.ProtectFile(longPath); err != nil {
					t.Fatal(err)
				}
				shortPath := atomicTransformV2DistinctShortLeafPathForTest(t, longPath)
				ownerPath := longPath
				if owner == "short-owner" {
					ownerPath = shortPath
				}
				atomicTransformV2RunShortRepairCrashForTest(t, ownerPath, stateDir, boundary)
				if boundary == atomicTransformV2ReplaceBoundaryBackupShortCleared {
					if _, err := os.Stat(shortPath); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("recorded short locator at missing-alias boundary = %v; want absent", err)
					}
				}
				if output, err := atomicTransformV2RunFreshRecoveryForTest(t, shortPath, stateDir); err != nil {
					t.Fatalf("fresh recovery through recorded short locator: %v\n%s", err, output)
				}
				longFile, err := os.Open(longPath)
				if err != nil {
					t.Fatal(err)
				}
				longIdentity, identityErr := atomicTransformOpenFileIdentity(longFile)
				longData, readErr := io.ReadAll(longFile)
				longCloseErr := longFile.Close()
				shortFile, shortErr := os.Open(shortPath)
				if shortErr != nil {
					t.Fatal(shortErr)
				}
				shortIdentity, shortIdentityErr := atomicTransformOpenFileIdentity(shortFile)
				shortData, shortReadErr := io.ReadAll(shortFile)
				shortCloseErr := shortFile.Close()
				if err := errors.Join(identityErr, readErr, longCloseErr, shortIdentityErr, shortReadErr, shortCloseErr); err != nil {
					t.Fatal(err)
				}
				want := atomicTransformV2HardExitPayload()
				if longIdentity != shortIdentity || !bytes.Equal(longData, want) || !bytes.Equal(shortData, want) {
					t.Fatalf("repaired alias does not name exact committed inode: long=%s short=%s bytes=%d/%d",
						longIdentity, shortIdentity, len(longData), len(shortData))
				}
				if output, err := atomicTransformV2RunFreshRecoveryForTest(t, shortPath, stateDir); err != nil {
					t.Fatalf("idempotent fresh recovery through repaired short locator: %v\n%s", err, output)
				}
				assertAtomicTransformV2NoArtifacts(t, longPath, stateDir)
			})
		}
	}
}

func TestAtomicTransformV2EmptyOldShortNameFreshProcessRepair(t *testing.T) {
	for _, boundary := range []string{
		atomicTransformV2ReplaceBoundaryTargetShortSet,
		atomicTransformV2ReplaceBoundaryShortFlushed,
	} {
		t.Run(boundary, func(t *testing.T) {
			var path, stateDir string
			reached := false
			for attempt := 0; attempt < 8 && !reached; attempt++ {
				root := t.TempDir()
				path = filepath.Join(root, "config", fmt.Sprintf("Long Configuration Without Old Alias %d.json", attempt))
				stateDir = filepath.Join(root, "protected-state")
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(`{"old":true}`), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := safefile.ProtectFile(path); err != nil {
					t.Fatal(err)
				}
				dir, err := bindAtomicTransformDirectory(filepath.Dir(path))
				if err != nil {
					t.Fatal(err)
				}
				file, err := openAtomicTransformV2ReplaceGuard(dir, filepath.Base(path), true)
				if err != nil {
					_ = dir.Close()
					t.Fatal(err)
				}
				if err := setAtomicTransformV2WindowsShortNameOnOpen(file, ""); err != nil {
					_ = file.Close()
					_ = dir.Close()
					t.Skipf("8.3 short-name mutation unavailable: %v", err)
				}
				flushErr := windows.FlushFileBuffers(windows.Handle(file.Fd()))
				closeErr := file.Close()
				syncErr := syncAtomicTransformBoundDirectoryPlatform(dir.file)
				dirCloseErr := dir.Close()
				if err := errors.Join(flushErr, closeErr, syncErr, dirCloseErr); err != nil {
					t.Fatal(err)
				}

				command := exec.Command(os.Args[0], "-test.run=^TestAtomicTransformV2HardExitHelper$")
				command.Env = atomicTransformV2HardExitEnv(
					"DEFENSECLAW_V2_HARD_EXIT_HELPER=1",
					"DEFENSECLAW_V2_HARD_EXIT_PATH="+path,
					"DEFENSECLAW_V2_HARD_EXIT_STATE="+stateDir,
					"DEFENSECLAW_V2_HARD_EXIT_OPERATION=update",
					"DEFENSECLAW_V2_FORCE_SHORT_REPAIR=1",
					"DEFENSECLAW_V2_HARD_EXIT_PHASE=replace-"+boundary,
					"DEFENSECLAW_V2_HARD_EXIT_OCCURRENCE=1",
				)
				output, runErr := command.CombinedOutput()
				var exitErr *exec.ExitError
				if errors.As(runErr, &exitErr) && exitErr.ExitCode() == atomicTransformV2HardExitCode {
					reached = true
					break
				}
				if errors.As(runErr, &exitErr) && exitErr.ExitCode() == 93 {
					// 8.3 generation is per-name and filesystem-dependent. This
					// candidate had no Stage alias, so there was correctly nothing
					// to clear; try a fresh randomized transaction name.
					continue
				}
				t.Fatalf("empty-alias helper exit = %v; want %d\n%s", runErr, atomicTransformV2HardExitCode, output)
			}
			if !reached {
				t.Skip("filesystem did not generate a Stage 8.3 alias in eight fresh transactions")
			}
			if output, err := atomicTransformV2RunFreshRecoveryForTest(t, path, stateDir); err != nil {
				t.Fatalf("fresh empty-alias recovery: %v\n%s", err, output)
			}
			dir, err := bindAtomicTransformDirectory(filepath.Dir(path))
			if err != nil {
				t.Fatal(err)
			}
			file, err := openAtomicTransformV2ReplaceGuard(dir, filepath.Base(path), false)
			if err != nil {
				_ = dir.Close()
				t.Fatal(err)
			}
			shortName, shortErr := atomicTransformV2WindowsShortNameFromOpen(file)
			closeErr := file.Close()
			dirCloseErr := dir.Close()
			content, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			identity, identityErr := atomicTransformOpenFileIdentity(content)
			data, readErr := io.ReadAll(content)
			contentCloseErr := content.Close()
			if err := errors.Join(shortErr, closeErr, dirCloseErr, identityErr, readErr, contentCloseErr); err != nil {
				t.Fatal(err)
			}
			if shortName != "" || identity == "" || !bytes.Equal(data, atomicTransformV2HardExitPayload()) {
				t.Fatalf("empty Old alias recovery = short:%q id:%q bytes:%d", shortName, identity, len(data))
			}
			if output, err := atomicTransformV2RunFreshRecoveryForTest(t, path, stateDir); err != nil {
				t.Fatalf("idempotent fresh empty-alias recovery: %v\n%s", err, output)
			}
			assertAtomicTransformV2NoArtifacts(t, path, stateDir)
		})
	}
}

type atomicTransformV21177Fixture struct {
	path     string
	stateDir string
	receipt  atomicTransformV2Receipt
	old      atomicTransformArtifactState
	stage    atomicTransformArtifactState
}

func prepareAtomicTransformV21177FixtureForTest(
	t *testing.T, knownMergedMetadata, unknownPartialMetadata bool,
) atomicTransformV21177Fixture {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "config", "settings.json")
	stateDir := filepath.Join(root, "protected-state")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("old-1177"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := safefile.ProtectFile(path); err != nil {
		t.Fatal(err)
	}
	preparedStateDir, err := prepareAtomicTransformStateDir(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := readAtomicFileSnapshot(path)
	if err != nil {
		t.Fatal(err)
	}
	txn, err := beginAtomicTransformV2(
		path, path, preparedStateDir, snapshot,
		atomicTransformResult{Data: []byte("new-1177")}, 0o600,
	)
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = txn.close()
		}
	})
	receipt := txn.receipt
	targetName := filepath.Base(receipt.TargetPath)
	target, err := atomicTransformBoundInspect(txn.targetDir, targetName, atomicTransformMaxConfigBytes)
	if err != nil {
		t.Fatal(err)
	}
	if knownMergedMetadata {
		attempt, invokeErr := invokeAtomicTransformV2Replacement(txn.targetDir, receipt, nil)
		if invokeErr != nil || attempt.Disposition != atomicTransformV2ReplaceReadyForPublication {
			t.Fatalf("prepare known-merged 1177 raw Replace = disposition:%d err:%v summary:%s",
				attempt.Disposition, invokeErr, atomicTransformV2ReplaceObservationSummary(receipt, attempt.Observed))
		}
		if err := flushAtomicTransformV2ReplacementForPublication(
			txn.targetDir, receipt, attempt.Observed,
		); err != nil {
			t.Fatal(err)
		}
		stage, renameErr := atomicTransformBoundRenameNoReplace(
			txn.targetDir, targetName, receipt.StageFinalName, attempt.Observed.Target,
		)
		if renameErr != nil {
			t.Fatal(renameErr)
		}
		if !atomicTransformV2PublishedTargetMatches(receipt, stage) {
			t.Fatalf("raw Replace Stage is not a known merged witness: %s",
				atomicTransformV2ReplaceObservationSummary(receipt, attempt.Observed))
		}
		if err := txn.close(); err != nil {
			t.Fatal(err)
		}
		closed = true
		return atomicTransformV21177Fixture{
			path: path, stateDir: preparedStateDir, receipt: receipt,
			old: attempt.Observed.Backup, stage: stage,
		}
	}
	old, err := atomicTransformBoundRenameNoReplace(
		txn.targetDir, targetName, receipt.TombstoneName, target,
	)
	if err != nil {
		t.Fatal(err)
	}
	if unknownPartialMetadata {
		stagePath := filepath.Join(filepath.Dir(receipt.TargetPath), receipt.StageFinalName)
		pointer, pointerErr := windows.UTF16PtrFromString(stagePath)
		if pointerErr != nil {
			t.Fatal(pointerErr)
		}
		attributes, attributeErr := windows.GetFileAttributes(pointer)
		if attributeErr != nil {
			t.Fatal(attributeErr)
		}
		if attributeErr = windows.SetFileAttributes(pointer, attributes|windows.FILE_ATTRIBUTE_HIDDEN); attributeErr != nil {
			t.Fatal(attributeErr)
		}
		stageHandle, openErr := openAtomicTransformV2ReplaceGuard(txn.targetDir, receipt.StageFinalName, true)
		if openErr != nil {
			t.Fatal(openErr)
		}
		flushErr := windows.FlushFileBuffers(windows.Handle(stageHandle.Fd()))
		closeErr := stageHandle.Close()
		syncErr := syncAtomicTransformBoundDirectoryPlatform(txn.targetDir.file)
		if err := errors.Join(flushErr, closeErr, syncErr); err != nil {
			t.Fatal(err)
		}
	}
	stage, err := atomicTransformBoundInspect(txn.targetDir, receipt.StageFinalName, atomicTransformMaxConfigBytes)
	if err != nil {
		t.Fatal(err)
	}
	if stage.identity != receipt.Stage.Identity || stage.digest != receipt.Stage.SHA256 ||
		stage.ownerGroupDigest != receipt.Stage.OwnerGroupSHA256 || stage.linkCount != 1 {
		t.Fatalf("partial-metadata Stage lost durable ownership witness: stage=%+v receipt=%+v", stage, receipt.Stage)
	}
	if err := txn.close(); err != nil {
		t.Fatal(err)
	}
	closed = true
	return atomicTransformV21177Fixture{
		path: path, stateDir: preparedStateDir, receipt: receipt, old: old, stage: stage,
	}
}

func snapshotAtomicTransformV2NamespaceForTest(
	t *testing.T, fixture atomicTransformV21177Fixture,
) map[string]string {
	t.Helper()
	result := map[string]string{}
	for _, directory := range []string{filepath.Dir(fixture.path), fixture.stateDir} {
		dir, bindErr := bindAtomicTransformDirectory(directory)
		if bindErr != nil {
			t.Fatal(bindErr)
		}
		entries, err := os.ReadDir(directory)
		if errors.Is(err, os.ErrNotExist) {
			_ = dir.Close()
			continue
		}
		if err != nil {
			_ = dir.Close()
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if strings.EqualFold(entry.Name(), ".defenseclaw-v2-protocol.lock") {
				continue
			}
			path := filepath.Join(directory, entry.Name())
			state, inspectErr := atomicTransformBoundInspect(dir, entry.Name(), atomicTransformMaxConfigBytes)
			if inspectErr != nil {
				_ = dir.Close()
				t.Fatal(inspectErr)
			}
			shortName := ""
			if atomicTransformPathsEqual(directory, filepath.Dir(fixture.path)) {
				file, openErr := openAtomicTransformV2ReplaceGuard(dir, entry.Name(), false)
				if openErr != nil {
					_ = dir.Close()
					t.Fatal(openErr)
				}
				shortName, inspectErr = atomicTransformV2WindowsShortNameFromOpen(file)
				closeErr := file.Close()
				if err := errors.Join(inspectErr, closeErr); err != nil {
					_ = dir.Close()
					t.Fatal(err)
				}
			}
			result[path] = fmt.Sprintf("%s|%s|%s|%d|%s|%s|short=%s",
				state.identity, state.digest, state.ownerGroupDigest, state.linkCount,
				state.protectionDigest, state.preservedMetadataDigest, shortName)
		}
		if err := dir.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return result
}

func assertAtomicTransformV2WitnessForTest(
	t *testing.T, label string, got, want atomicTransformArtifactState,
) {
	t.Helper()
	if !got.exists || got.identity != want.identity || got.digest != want.digest ||
		got.ownerGroupDigest != want.ownerGroupDigest || got.linkCount != want.linkCount {
		t.Fatalf("%s witness changed: got{id=%s digest=%s owner-group=%s links=%d} want{id=%s digest=%s owner-group=%s links=%d}",
			label, got.identity, got.digest, got.ownerGroupDigest, got.linkCount,
			want.identity, want.digest, want.ownerGroupDigest, want.linkCount)
	}
}

func TestAtomicTransformV21177RestoreFreshProcessMatrix(t *testing.T) {
	for _, form := range []string{"exact", "known-merged"} {
		for _, boundary := range []string{
			atomicTransformV2ReplaceBoundaryBefore1177Restore,
			atomicTransformV2ReplaceBoundary1177OldRestored,
		} {
			t.Run(form+"/"+boundary, func(t *testing.T) {
				fixture := prepareAtomicTransformV21177FixtureForTest(t, form == "known-merged", false)
				command := exec.Command(os.Args[0], "-test.run=^TestAtomicTransformV2HardExitHelper$")
				command.Env = atomicTransformV2HardExitEnv(
					"DEFENSECLAW_V2_HARD_EXIT_HELPER=1",
					"DEFENSECLAW_V2_HARD_EXIT_RECOVER=1",
					"DEFENSECLAW_V2_HARD_EXIT_PATH="+fixture.path,
					"DEFENSECLAW_V2_HARD_EXIT_STATE="+fixture.stateDir,
					"DEFENSECLAW_V2_HARD_EXIT_PHASE=replace-"+boundary,
					"DEFENSECLAW_V2_HARD_EXIT_OCCURRENCE=1",
				)
				output, runErr := command.CombinedOutput()
				var exitErr *exec.ExitError
				if !errors.As(runErr, &exitErr) || exitErr.ExitCode() != atomicTransformV2HardExitCode {
					t.Fatalf("1177 midpoint helper exit = %v; want %d\n%s", runErr, atomicTransformV2HardExitCode, output)
				}
				dir, err := bindAtomicTransformDirectory(filepath.Dir(fixture.path))
				if err != nil {
					t.Fatal(err)
				}
				target, targetErr := atomicTransformBoundInspect(dir, filepath.Base(fixture.path), atomicTransformMaxConfigBytes)
				tomb, tombErr := atomicTransformBoundInspect(dir, fixture.receipt.TombstoneName, atomicTransformMaxConfigBytes)
				stage, stageErr := atomicTransformBoundInspect(dir, fixture.receipt.StageFinalName, atomicTransformMaxConfigBytes)
				closeErr := dir.Close()
				if err := errors.Join(targetErr, tombErr, stageErr, closeErr); err != nil {
					t.Fatal(err)
				}
				assertAtomicTransformV2WitnessForTest(t, "1177 partial-metadata Stage", stage, fixture.stage)
				if boundary == atomicTransformV2ReplaceBoundaryBefore1177Restore {
					if target.exists {
						t.Fatal("pre-restore crash unexpectedly recreated live Old")
					}
					assertAtomicTransformV2WitnessForTest(t, "1177 Old tomb", tomb, fixture.old)
				} else {
					assertAtomicTransformV2WitnessForTest(t, "1177 restored Old", target, fixture.old)
					if tomb.exists {
						t.Fatal("post-restore crash left Old at both live and tomb names")
					}
				}

				for recovery := 0; recovery < 2; recovery++ {
					if output, err := atomicTransformV2RunFreshRecoveryForTest(t, fixture.path, fixture.stateDir); err != nil {
						t.Fatalf("fresh 1177 recovery %d: %v\n%s", recovery+1, err, output)
					}
				}
				dir, err = bindAtomicTransformDirectory(filepath.Dir(fixture.path))
				if err != nil {
					t.Fatal(err)
				}
				live, liveErr := atomicTransformBoundInspect(dir, filepath.Base(fixture.path), atomicTransformMaxConfigBytes)
				closeErr = dir.Close()
				if err := errors.Join(liveErr, closeErr); err != nil {
					t.Fatal(err)
				}
				assertAtomicTransformV2WitnessForTest(t, "converged 1177 Old", live, fixture.old)
				assertAtomicTransformV2NoArtifacts(t, fixture.path, fixture.stateDir)
			})
		}
	}
}

func TestAtomicTransformV21177UnknownPartialMetadataRestoresOldThenRetains(t *testing.T) {
	fixture := prepareAtomicTransformV21177FixtureForTest(t, false, true)
	command := exec.Command(os.Args[0], "-test.run=^TestAtomicTransformV2HardExitHelper$")
	command.Env = atomicTransformV2HardExitEnv(
		"DEFENSECLAW_V2_HARD_EXIT_HELPER=1",
		"DEFENSECLAW_V2_HARD_EXIT_RECOVER=1",
		"DEFENSECLAW_V2_HARD_EXIT_PATH="+fixture.path,
		"DEFENSECLAW_V2_HARD_EXIT_STATE="+fixture.stateDir,
		"DEFENSECLAW_V2_HARD_EXIT_PHASE=replace-"+atomicTransformV2ReplaceBoundary1177OldRestored,
		"DEFENSECLAW_V2_HARD_EXIT_OCCURRENCE=1",
	)
	output, runErr := command.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(runErr, &exitErr) || exitErr.ExitCode() != atomicTransformV2HardExitCode {
		t.Fatalf("partial-metadata 1177 restore helper exit = %v; want %d\n%s", runErr, atomicTransformV2HardExitCode, output)
	}
	before := snapshotAtomicTransformV2NamespaceForTest(t, fixture)
	for recovery := 0; recovery < 2; recovery++ {
		output, err := atomicTransformV2RunFreshRecoveryForTest(t, fixture.path, fixture.stateDir)
		if err == nil {
			t.Fatalf("unknown partial-metadata 1177 recovery %d succeeded\n%s", recovery+1, output)
		}
		after := snapshotAtomicTransformV2NamespaceForTest(t, fixture)
		if !reflect.DeepEqual(after, before) {
			t.Fatalf("unknown partial-metadata 1177 recovery %d mutated namespace\nbefore=%v\nafter=%v",
				recovery+1, before, after)
		}
	}
	dir, err := bindAtomicTransformDirectory(filepath.Dir(fixture.path))
	if err != nil {
		t.Fatal(err)
	}
	live, liveErr := atomicTransformBoundInspect(dir, filepath.Base(fixture.path), atomicTransformMaxConfigBytes)
	stage, stageErr := atomicTransformBoundInspect(dir, fixture.receipt.StageFinalName, atomicTransformMaxConfigBytes)
	closeErr := dir.Close()
	if err := errors.Join(liveErr, stageErr, closeErr); err != nil {
		t.Fatal(err)
	}
	assertAtomicTransformV2WitnessForTest(t, "partial-metadata restored Old", live, fixture.old)
	assertAtomicTransformV2WitnessForTest(t, "retained unknown partial-metadata Stage", stage, fixture.stage)
	loaded, err := loadAtomicTransformV2(fixture.path, fixture.stateDir)
	if err != nil || !loaded.exists || loaded.terminal.exists {
		t.Fatalf("unknown partial-metadata 1177 receipts not retained: exists=%t terminal=%t err=%v",
			loaded.exists, loaded.terminal.exists, err)
	}
}

func TestAtomicTransformV21177ForeignStageAndLiveRecreateFailClosed(t *testing.T) {
	t.Run("foreign-stage", func(t *testing.T) {
		fixture := prepareAtomicTransformV21177FixtureForTest(t, false, false)
		stagePath := filepath.Join(filepath.Dir(fixture.path), fixture.receipt.StageFinalName)
		parkedStage := stagePath + ".operator-recorded-stage"
		if err := os.Rename(stagePath, parkedStage); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(stagePath, []byte("foreign-stage-1177"), 0o600); err != nil {
			t.Fatal(err)
		}
		before := snapshotAtomicTransformV2NamespaceForTest(t, fixture)
		for recovery := 0; recovery < 2; recovery++ {
			output, err := atomicTransformV2RunFreshRecoveryForTest(t, fixture.path, fixture.stateDir)
			if err == nil {
				t.Fatalf("foreign-Stage 1177 recovery %d succeeded\n%s", recovery+1, output)
			}
			after := snapshotAtomicTransformV2NamespaceForTest(t, fixture)
			if !reflect.DeepEqual(after, before) {
				t.Fatalf("foreign-Stage 1177 recovery %d mutated namespace\nbefore=%v\nafter=%v", recovery+1, before, after)
			}
		}
		loaded, err := loadAtomicTransformV2(fixture.path, fixture.stateDir)
		if err != nil || !loaded.exists || loaded.terminal.exists {
			t.Fatalf("foreign-Stage 1177 receipts not retained: exists=%t terminal=%t err=%v",
				loaded.exists, loaded.terminal.exists, err)
		}
	})

	t.Run("live-recreate-at-restore-seam", func(t *testing.T) {
		fixture := prepareAtomicTransformV21177FixtureForTest(t, false, false)
		operatorData := "operator-live-at-1177-restore"
		command := exec.Command(os.Args[0], "-test.run=^TestAtomicTransformV2HardExitHelper$")
		command.Env = atomicTransformV2HardExitEnv(
			"DEFENSECLAW_V2_HARD_EXIT_HELPER=1",
			"DEFENSECLAW_V2_HARD_EXIT_RECOVER=1",
			"DEFENSECLAW_V2_HARD_EXIT_PATH="+fixture.path,
			"DEFENSECLAW_V2_HARD_EXIT_STATE="+fixture.stateDir,
			"DEFENSECLAW_V2_1177_RECREATE_LIVE="+operatorData,
		)
		output, runErr := command.CombinedOutput()
		var exitErr *exec.ExitError
		if !errors.As(runErr, &exitErr) || exitErr.ExitCode() != 92 {
			t.Fatalf("1177 live-recreate helper exit = %v; want fail-closed 92\n%s", runErr, output)
		}
		dir, err := bindAtomicTransformDirectory(filepath.Dir(fixture.path))
		if err != nil {
			t.Fatal(err)
		}
		operator, inspectErr := atomicTransformBoundInspect(dir, filepath.Base(fixture.path), atomicTransformMaxConfigBytes)
		closeErr := dir.Close()
		if err := errors.Join(inspectErr, closeErr); err != nil || !operator.exists || operator.digest != atomicTransformDigest([]byte(operatorData)) ||
			operator.ownerGroupDigest == "" || operator.linkCount != 1 {
			t.Fatalf("operator live recreate witness = %+v, %v", operator, err)
		}
		before := snapshotAtomicTransformV2NamespaceForTest(t, fixture)
		for recovery := 0; recovery < 2; recovery++ {
			output, err := atomicTransformV2RunFreshRecoveryForTest(t, fixture.path, fixture.stateDir)
			if err == nil {
				t.Fatalf("live-recreated 1177 recovery %d succeeded\n%s", recovery+1, output)
			}
			after := snapshotAtomicTransformV2NamespaceForTest(t, fixture)
			if !reflect.DeepEqual(after, before) {
				t.Fatalf("live-recreated 1177 recovery %d mutated namespace\nbefore=%v\nafter=%v", recovery+1, before, after)
			}
		}
		dir, err = bindAtomicTransformDirectory(filepath.Dir(fixture.path))
		if err != nil {
			t.Fatal(err)
		}
		live, inspectErr := atomicTransformBoundInspect(dir, filepath.Base(fixture.path), atomicTransformMaxConfigBytes)
		closeErr = dir.Close()
		err = errors.Join(inspectErr, closeErr)
		if err != nil {
			t.Fatal(err)
		}
		assertAtomicTransformV2WitnessForTest(t, "operator live recreate", live, operator)
	})
}

func TestAtomicTransformV2MissingShortNameForeignClaimantIsRetained(t *testing.T) {
	for _, owner := range []string{"short-owner", "long-owner"} {
		t.Run(owner, func(t *testing.T) {
			root := t.TempDir()
			longPath := filepath.Join(root, "config", "Long Configuration Settings.json")
			stateDir := filepath.Join(root, "protected-state")
			if err := os.MkdirAll(filepath.Dir(longPath), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(longPath, []byte(`{"old":true}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := safefile.ProtectFile(longPath); err != nil {
				t.Fatal(err)
			}
			shortPath := atomicTransformV2DistinctShortLeafPathForTest(t, longPath)
			ownerPath := longPath
			if owner == "short-owner" {
				ownerPath = shortPath
			}
			atomicTransformV2RunShortRepairCrashForTest(
				t, ownerPath, stateDir, atomicTransformV2ReplaceBoundaryBackupShortCleared,
			)
			if _, err := os.Stat(shortPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("recorded short locator before foreign claim = %v; want absent", err)
			}

			foreignPath := filepath.Join(filepath.Dir(longPath), "Foreign Operator Claimant.txt")
			foreignData := []byte("foreign-short-name-claimant")
			if err := os.WriteFile(foreignPath, foreignData, 0o600); err != nil {
				t.Fatal(err)
			}
			dir, err := bindAtomicTransformDirectory(filepath.Dir(longPath))
			if err != nil {
				t.Fatal(err)
			}
			foreign, err := openAtomicTransformV2ReplaceGuard(dir, filepath.Base(foreignPath), true)
			if err != nil {
				_ = dir.Close()
				t.Fatal(err)
			}
			currentShort, err := atomicTransformV2WindowsShortNameFromOpen(foreign)
			if err == nil && currentShort != "" {
				err = setAtomicTransformV2WindowsShortNameOnOpen(foreign, "")
			}
			if err == nil {
				err = setAtomicTransformV2WindowsShortNameOnOpen(foreign, filepath.Base(shortPath))
			}
			if err == nil {
				err = windows.FlushFileBuffers(windows.Handle(foreign.Fd()))
			}
			foreignIdentity, identityErr := atomicTransformOpenFileIdentity(foreign)
			closeErr := foreign.Close()
			if err == nil {
				err = syncAtomicTransformBoundDirectoryPlatform(dir.file)
			}
			dirCloseErr := dir.Close()
			if err := errors.Join(err, identityErr, closeErr, dirCloseErr); err != nil {
				t.Fatal(err)
			}

			for attempt := 0; attempt < 2; attempt++ {
				output, recoverErr := atomicTransformV2RunFreshRecoveryForTest(t, shortPath, stateDir)
				if recoverErr == nil {
					t.Fatalf("foreign-claimant recovery %d succeeded; want fail closed\n%s", attempt+1, output)
				}
				loaded, loadErr := loadAtomicTransformV2(longPath, stateDir)
				if loadErr != nil || !loaded.exists || loaded.terminal.exists {
					t.Fatalf("foreign-claimant recovery %d receipt state: exists=%t terminal=%t err=%v",
						attempt+1, loaded.exists, loaded.terminal.exists, loadErr)
				}
				claim, openErr := os.Open(shortPath)
				if openErr != nil {
					t.Fatal(openErr)
				}
				identity, claimIdentityErr := atomicTransformOpenFileIdentity(claim)
				data, claimReadErr := io.ReadAll(claim)
				claimCloseErr := claim.Close()
				if err := errors.Join(claimIdentityErr, claimReadErr, claimCloseErr); err != nil {
					t.Fatal(err)
				}
				if identity != foreignIdentity || !bytes.Equal(data, foreignData) {
					t.Fatalf("foreign-claimant recovery %d changed claimant: id=%s/%s data=%q",
						attempt+1, identity, foreignIdentity, data)
				}
			}
		})
	}
}

func TestAtomicTransformV2FinalPublicationPreservesFinalSeamMutations(t *testing.T) {
	for _, operation := range []string{"create", "update", "remove"} {
		for _, mutation := range []string{"edit", "recreate", "delete"} {
			t.Run(operation+"/"+mutation, func(t *testing.T) {
				root := t.TempDir()
				path := filepath.Join(root, "config", "settings.json")
				stateDir := filepath.Join(root, "protected-state")
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if operation != "create" {
					if err := os.WriteFile(path, []byte(`{"old":true}`), 0o600); err != nil {
						t.Fatal(err)
					}
					if err := safefile.ProtectFile(path); err != nil {
						t.Fatal(err)
					}
				}
				canonical, err := canonicalAtomicTransformTargetPath(path)
				if err != nil {
					t.Fatal(err)
				}
				operatorBytes := []byte("operator-" + operation + "-" + mutation)
				mutated := false
				var wantIdentity string
				var wantExists bool
				restore := setAtomicTransformPhaseHookForTest(canonical, func(
					phase atomicTransformPhase, state atomicTransformPhaseState,
				) error {
					if phase != atomicTransformPhaseFinalPublicationValidated || mutated {
						return nil
					}
					mutated = true
					switch mutation {
					case "edit":
						if err := os.WriteFile(state.TargetPath, operatorBytes, 0o600); err != nil {
							return err
						}
					case "recreate":
						if err := os.Remove(state.TargetPath); err != nil && !errors.Is(err, os.ErrNotExist) {
							return err
						}
						if err := os.WriteFile(state.TargetPath, operatorBytes, 0o600); err != nil {
							return err
						}
					case "delete":
						if err := os.Remove(state.TargetPath); err != nil && !errors.Is(err, os.ErrNotExist) {
							return err
						}
					}
					file, openErr := os.Open(state.TargetPath)
					if errors.Is(openErr, os.ErrNotExist) {
						wantExists = false
						return nil
					}
					if openErr != nil {
						return openErr
					}
					defer file.Close()
					wantIdentity, openErr = atomicTransformOpenFileIdentity(file)
					wantExists = openErr == nil
					return openErr
				})
				defer restore()

				result := atomicTransformResult{Data: atomicTransformV2HardExitPayload()}
				if operation == "remove" {
					result = atomicTransformResult{Remove: true}
				}
				if err := atomicTransformFileWithStateDir(
					path, stateDir, 0o600,
					func([]byte, bool) (atomicTransformResult, error) { return result, nil },
				); err != nil {
					t.Fatalf("transform across final-publication seam: %v", err)
				}
				if !mutated {
					t.Fatal("final-publication seam was not reached")
				}
				for recovery := 0; recovery < 2; recovery++ {
					if err := recoverAtomicTransformV2(path, stateDir); err != nil {
						t.Fatalf("recovery %d: %v", recovery+1, err)
					}
				}
				file, openErr := os.Open(path)
				if !wantExists {
					if !errors.Is(openErr, os.ErrNotExist) {
						if file != nil {
							_ = file.Close()
						}
						t.Fatalf("post-publication deletion was revoked: %v", openErr)
					}
				} else {
					if openErr != nil {
						t.Fatal(openErr)
					}
					identity, identityErr := atomicTransformOpenFileIdentity(file)
					data, readErr := io.ReadAll(file)
					closeErr := file.Close()
					if err := errors.Join(identityErr, readErr, closeErr); err != nil {
						t.Fatal(err)
					}
					if identity != wantIdentity || !bytes.Equal(data, operatorBytes) {
						t.Fatalf("post-P live changed: identity %s/%s bytes %q", identity, wantIdentity, data)
					}
				}
				assertAtomicTransformV2NoArtifacts(t, path, stateDir)
			})
		}
	}
}

func TestAtomicTransformV2RejectsHardlinkedOldBeforeReceipt(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "config", "settings.json")
	peer := filepath.Join(root, "config", "settings-peer.json")
	stateDir := filepath.Join(root, "protected-state")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	initial := []byte(`{"old":true}`)
	if err := os.WriteFile(path, initial, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := safefile.ProtectFile(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, peer); err != nil {
		t.Skipf("NTFS hard links unavailable: %v", err)
	}
	err := atomicTransformFileWithStateDir(
		path, stateDir, 0o600,
		func([]byte, bool) (atomicTransformResult, error) {
			return atomicTransformResult{Data: []byte(`{"new":true}`)}, nil
		},
	)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "hard link") {
		t.Fatalf("hardlinked Old error = %v", err)
	}
	for _, name := range []string{path, peer} {
		data, readErr := os.ReadFile(name)
		if readErr != nil || !bytes.Equal(data, initial) {
			t.Fatalf("hardlinked Old peer %s changed: %q, %v", name, data, readErr)
		}
	}
	loaded, loadErr := loadAtomicTransformV2(path, stateDir)
	if loadErr != nil || loaded.exists {
		t.Fatalf("hardlinked Old created a receipt: exists=%t err=%v", loaded.exists, loadErr)
	}
}

func TestAtomicTransformV2StageHardlinkRaceIsRetained(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "config", "settings.json")
	peer := filepath.Join(root, "config", "stage-external-peer")
	stateDir := filepath.Join(root, "protected-state")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	initial := []byte(`{"old":true}`)
	if err := os.WriteFile(path, initial, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := safefile.ProtectFile(path); err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalAtomicTransformTargetPath(path)
	if err != nil {
		t.Fatal(err)
	}
	var stagePath string
	restore := setAtomicTransformPhaseHookForTest(canonical, func(
		phase atomicTransformPhase, state atomicTransformPhaseState,
	) error {
		if phase != atomicTransformPhaseIntentPersisted || stagePath != "" {
			return nil
		}
		stagePath = state.StagedFinal
		return os.Link(stagePath, peer)
	})
	defer restore()
	err = atomicTransformFileWithStateDir(
		path, stateDir, 0o600,
		func([]byte, bool) (atomicTransformResult, error) {
			return atomicTransformResult{Data: atomicTransformV2HardExitPayload()}, nil
		},
	)
	if err == nil {
		t.Fatal("hardlinked Stage unexpectedly published")
	}
	if stagePath == "" {
		t.Fatal("Rp hardlink seam was not reached")
	}
	beforeStage, inspectErr := inspectAtomicTransformArtifactBounded(stagePath, atomicTransformMaxConfigBytes)
	beforePeer, peerErr := inspectAtomicTransformArtifactBounded(peer, atomicTransformMaxConfigBytes)
	if inspectErr != nil || peerErr != nil || !beforeStage.exists || !beforePeer.exists ||
		beforeStage.identity != beforePeer.identity || beforeStage.digest != beforePeer.digest {
		t.Fatalf("hardlinked Stage witness invalid: stage=%+v peer=%+v errs=%v/%v", beforeStage, beforePeer, inspectErr, peerErr)
	}
	for recovery := 0; recovery < 2; recovery++ {
		if err := recoverAtomicTransformV2(path, stateDir); err == nil {
			t.Fatalf("hardlinked Stage recovery %d unexpectedly succeeded", recovery+1)
		}
		afterStage, stageErr := inspectAtomicTransformArtifactBounded(stagePath, atomicTransformMaxConfigBytes)
		afterPeer, afterPeerErr := inspectAtomicTransformArtifactBounded(peer, atomicTransformMaxConfigBytes)
		if stageErr != nil || afterPeerErr != nil || afterStage.identity != beforeStage.identity ||
			afterPeer.identity != beforePeer.identity || afterStage.digest != beforeStage.digest ||
			afterPeer.digest != beforePeer.digest {
			t.Fatalf("hardlinked Stage recovery %d mutated exact peers", recovery+1)
		}
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil || !bytes.Equal(data, initial) {
		t.Fatalf("hardlinked Stage race changed live Old: %q, %v", data, readErr)
	}
}

func TestAtomicTransformV2FinalPublicationHardlinkPersists(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "config", "settings.json")
	peer := filepath.Join(root, "config", "published-peer.json")
	stateDir := filepath.Join(root, "protected-state")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := safefile.ProtectFile(path); err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalAtomicTransformTargetPath(path)
	if err != nil {
		t.Fatal(err)
	}
	linked := false
	restore := setAtomicTransformPhaseHookForTest(canonical, func(
		phase atomicTransformPhase, state atomicTransformPhaseState,
	) error {
		if phase == atomicTransformPhaseFinalPublicationValidated && !linked {
			linked = true
			return os.Link(state.TargetPath, peer)
		}
		return nil
	})
	defer restore()
	if err := atomicTransformFileWithStateDir(
		path, stateDir, 0o600,
		func([]byte, bool) (atomicTransformResult, error) {
			return atomicTransformResult{Data: []byte("new")}, nil
		},
	); err != nil {
		t.Fatal(err)
	}
	if !linked {
		t.Fatal("post-P hardlink seam was not reached")
	}
	target, targetErr := inspectAtomicTransformArtifactBounded(path, atomicTransformMaxConfigBytes)
	linkedPeer, peerErr := inspectAtomicTransformArtifactBounded(peer, atomicTransformMaxConfigBytes)
	targetFile, openErr := os.Open(path)
	if openErr != nil {
		t.Fatal(openErr)
	}
	targetLinks, linkErr := atomicTransformBoundLinkCountPlatform(targetFile)
	closeErr := targetFile.Close()
	if targetErr != nil || peerErr != nil || target.identity != linkedPeer.identity ||
		target.digest != linkedPeer.digest || targetLinks != 2 || linkErr != nil || closeErr != nil {
		t.Fatalf("post-P hardlink not preserved: target=%+v peer=%+v links=%d errs=%v/%v/%v/%v", target, linkedPeer, targetLinks, targetErr, peerErr, linkErr, closeErr)
	}
	assertAtomicTransformV2NoArtifacts(t, path, stateDir)
}

func TestAtomicTransformV2PrePublicationMutationsFailClosed(t *testing.T) {
	for _, mutation := range []string{"edit", "recreate", "delete", "hardlink"} {
		t.Run(mutation, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "config", "Long Configuration Settings.json")
			stateDir := filepath.Join(root, "protected-state")
			peer := filepath.Join(root, "config", "operator-peer")
			parked := filepath.Join(root, "config", "operator-parked-new")
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := safefile.ProtectFile(path); err != nil {
				t.Fatal(err)
			}
			canonical, err := canonicalAtomicTransformTargetPath(path)
			if err != nil {
				t.Fatal(err)
			}
			fired := false
			restore := installAtomicTransformV2PrePublicationHookForTest(
				canonical,
				func(dir *atomicTransformBoundDirectory, target, _ *os.File, receipt atomicTransformV2Receipt) error {
					if fired {
						return fmt.Errorf("pre-publication mutation hook fired twice")
					}
					fired = true
					switch mutation {
					case "edit":
						if err := target.Truncate(0); err != nil {
							return err
						}
						if _, err := target.Seek(0, 0); err != nil {
							return err
						}
						if _, err := target.Write([]byte("operator-edit")); err != nil {
							return err
						}
						return target.Sync()
					case "recreate":
						if err := renameAtomicTransformBoundFilePlatform(
							dir.file, target, filepath.Base(parked), false,
						); err != nil {
							return err
						}
						return os.WriteFile(receipt.TargetPath, []byte("operator-recreate"), 0o600)
					case "delete":
						return deleteAtomicTransformBoundFilePlatform(
							dir.file, target, filepath.Base(receipt.TargetPath),
						)
					case "hardlink":
						return os.Link(receipt.TargetPath, peer)
					}
					return nil
				},
			)
			defer restore()
			err = atomicTransformFileWithStateDir(
				path, stateDir, 0o600,
				func([]byte, bool) (atomicTransformResult, error) {
					return atomicTransformResult{Data: []byte("new")}, nil
				},
			)
			if err == nil {
				t.Fatal("pre-P mutation unexpectedly committed")
			}
			if !fired {
				t.Fatal("pre-publication mutation seam was not reached")
			}

			snapshot := func() map[string]string {
				t.Helper()
				result := map[string]string{}
				for _, dir := range []string{filepath.Dir(path), stateDir} {
					entries, readErr := os.ReadDir(dir)
					if readErr != nil {
						t.Fatal(readErr)
					}
					for _, entry := range entries {
						if entry.IsDir() {
							continue
						}
						file, openErr := os.Open(filepath.Join(dir, entry.Name()))
						if openErr != nil {
							t.Fatal(openErr)
						}
						identity, identityErr := atomicTransformOpenFileIdentity(file)
						data, dataErr := io.ReadAll(file)
						closeErr := file.Close()
						if err := errors.Join(identityErr, dataErr, closeErr); err != nil {
							t.Fatal(err)
						}
						result[dir+"|"+entry.Name()] = identity + "|" + atomicTransformDigest(data)
					}
				}
				return result
			}
			before := snapshot()
			for recovery := 0; recovery < 2; recovery++ {
				if err := recoverAtomicTransformV2(path, stateDir); err == nil {
					t.Fatalf("pre-P recovery %d unexpectedly succeeded", recovery+1)
				}
				after := snapshot()
				if !reflect.DeepEqual(after, before) {
					t.Fatalf("pre-P recovery %d mutated names/IDs/bytes\nbefore=%v\nafter=%v", recovery+1, before, after)
				}
			}
		})
	}
}

func TestAtomicTransformV2AllocationArtifactWithADSIsNeverDeleted(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "config", "settings.json")
	stateDir := filepath.Join(root, "protected-state")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := safefile.ProtectFile(path); err != nil {
		t.Fatal(err)
	}
	crash := exec.Command(os.Args[0], "-test.run=^TestAtomicTransformV2HardExitHelper$")
	crash.Env = atomicTransformV2HardExitEnv(
		"DEFENSECLAW_V2_HARD_EXIT_HELPER=1",
		"DEFENSECLAW_V2_HARD_EXIT_PATH="+path,
		"DEFENSECLAW_V2_HARD_EXIT_STATE="+stateDir,
		"DEFENSECLAW_V2_HARD_EXIT_OPERATION=update",
		"DEFENSECLAW_V2_HARD_EXIT_PHASE="+string(atomicTransformPhasePreReceiptArtifact),
		"DEFENSECLAW_V2_HARD_EXIT_OCCURRENCE=1",
	)
	output, runErr := crash.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(runErr, &exitErr) || exitErr.ExitCode() != atomicTransformV2HardExitCode {
		t.Fatalf("allocation helper exit = %v; want %d\n%s", runErr, atomicTransformV2HardExitCode, output)
	}
	loaded, err := loadAtomicTransformV2(path, stateDir)
	if err != nil || !loaded.allocation.located || loaded.staging.located {
		t.Fatalf("allocation-only chain = allocation:%t staging:%t err:%v", loaded.allocation.located, loaded.staging.located, err)
	}
	artifactPath := filepath.Join(filepath.Dir(path), loaded.receipt.TerminalMarker.Name)
	artifact, err := os.Open(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	wantIdentity, identityErr := atomicTransformOpenFileIdentity(artifact)
	wantMain, readErr := io.ReadAll(artifact)
	closeErr := artifact.Close()
	if err := errors.Join(identityErr, readErr, closeErr); err != nil {
		t.Fatal(err)
	}
	adsPath := artifactPath + ":operator-retained"
	wantADS := []byte("valuable-same-principal-ADS")
	if err := os.WriteFile(adsPath, wantADS, 0o600); err != nil {
		t.Skipf("NTFS alternate streams unavailable: %v", err)
	}
	for recovery := 0; recovery < 2; recovery++ {
		if err := recoverAtomicTransformV2(path, stateDir); err == nil {
			t.Fatalf("ADS-bearing allocation recovery %d unexpectedly succeeded", recovery+1)
		}
		current, openErr := os.Open(artifactPath)
		if openErr != nil {
			t.Fatalf("ADS-bearing artifact disappeared: %v", openErr)
		}
		identity, identityErr := atomicTransformOpenFileIdentity(current)
		main, mainErr := io.ReadAll(current)
		closeErr := current.Close()
		ads, adsErr := os.ReadFile(adsPath)
		if err := errors.Join(identityErr, mainErr, closeErr, adsErr); err != nil {
			t.Fatal(err)
		}
		if identity != wantIdentity || !bytes.Equal(main, wantMain) || !bytes.Equal(ads, wantADS) {
			t.Fatalf("recovery %d changed ADS-bearing artifact: id=%s/%s main=%q ads=%q", recovery+1, identity, wantIdentity, main, ads)
		}
	}
}

func TestAtomicTransformV2ReceiptSchemaRejectsMalformedStageWitnesses(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "config", "settings.json")
	stateDir := filepath.Join(root, "protected-state")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := safefile.ProtectFile(path); err != nil {
		t.Fatal(err)
	}
	crash := exec.Command(os.Args[0], "-test.run=^TestAtomicTransformV2HardExitHelper$")
	crash.Env = atomicTransformV2HardExitEnv(
		"DEFENSECLAW_V2_HARD_EXIT_HELPER=1",
		"DEFENSECLAW_V2_HARD_EXIT_PATH="+path,
		"DEFENSECLAW_V2_HARD_EXIT_STATE="+stateDir,
		"DEFENSECLAW_V2_HARD_EXIT_OPERATION=update",
		"DEFENSECLAW_V2_HARD_EXIT_PHASE="+string(atomicTransformPhaseIntentPersisted),
		"DEFENSECLAW_V2_HARD_EXIT_OCCURRENCE=1",
	)
	output, runErr := crash.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(runErr, &exitErr) || exitErr.ExitCode() != atomicTransformV2HardExitCode {
		t.Fatalf("schema helper exit = %v; want %d\n%s", runErr, atomicTransformV2HardExitCode, output)
	}
	loaded, err := loadAtomicTransformV2(path, stateDir)
	if err != nil || !loaded.prepared.located || !loaded.staging.located {
		t.Fatalf("prepared schema fixture = prepared:%t staging:%t err:%v", loaded.prepared.located, loaded.staging.located, err)
	}
	validDigest := strings.Repeat("0", sha256HexLength)
	tests := []struct {
		name    string
		receipt atomicTransformV2Receipt
	}{
		{name: "prepared-link-zero", receipt: loaded.prepared.receipt},
		{name: "prepared-link-two", receipt: loaded.prepared.receipt},
		{name: "prepared-protection-empty", receipt: loaded.prepared.receipt},
		{name: "prepared-owner-group-empty", receipt: loaded.prepared.receipt},
		{name: "prepared-nonregular-mode", receipt: loaded.prepared.receipt},
		{name: "staging-premature-full", receipt: loaded.staging.receipt},
		{name: "staging-only-complete-premature-full", receipt: loaded.staging.receipt},
		{name: "remove-retains-stage", receipt: loaded.prepared.receipt},
	}
	tests[0].receipt.Stage.LinkCount = 0
	tests[1].receipt.Stage.LinkCount = 2
	tests[2].receipt.Stage.ProtectionSHA256 = ""
	tests[3].receipt.Stage.OwnerGroupSHA256 = ""
	tests[4].receipt.Stage.Mode = uint32(os.ModeDir | 0o600)
	tests[5].receipt.Stage.MetadataSHA256 = validDigest
	tests[6].receipt.Phase = atomicTransformV2Complete
	tests[6].receipt.StagingReceiptID = loaded.staging.state.identity
	tests[6].receipt.PreparedReceiptID = ""
	tests[6].receipt.TerminalReceiptID = ""
	tests[6].receipt.Decision = atomicTransformV2DecisionAbort
	tests[6].receipt.Stage.StageOwnedMetadataSHA256 = validDigest
	tests[7].receipt.Remove = true
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateAtomicTransformV2Receipt(
				test.receipt, loaded.logical, loaded.receipt.StateDir,
				loaded.base, loaded.prepared.path,
			); err == nil {
				t.Fatal("malformed receipt unexpectedly validated")
			}
		})
	}
	if err := recoverAtomicTransformV2(path, stateDir); err != nil {
		t.Fatalf("cleanup valid schema fixture: %v", err)
	}
}

func TestAtomicTransformV2RejectsRetargetableJunctionLocators(t *testing.T) {
	root := t.TempDir()
	realConfigDir := filepath.Join(root, "real-config")
	realStateDir := filepath.Join(root, "real-state")
	configJunction := filepath.Join(root, "config-junction")
	stateJunction := filepath.Join(root, "state-junction")
	for _, directory := range []string{realConfigDir, realStateDir} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	createJunction := func(link, target string) {
		t.Helper()
		output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", link, target).CombinedOutput()
		if err != nil {
			t.Skipf("junction creation unavailable: %v (%s)", err, output)
		}
		t.Cleanup(func() { _ = os.Remove(link) })
	}
	createJunction(configJunction, realConfigDir)
	createJunction(stateJunction, realStateDir)
	realPath := filepath.Join(realConfigDir, "settings.json")
	if err := os.WriteFile(realPath, []byte(`{"old":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	transform := func(_ []byte, _ bool) (atomicTransformResult, error) {
		return atomicTransformResult{Data: []byte(`{"new":true}`)}, nil
	}
	if err := atomicTransformFileWithStateDir(
		filepath.Join(configJunction, "settings.json"), filepath.Join(root, "direct-state"), 0o600, transform,
	); err == nil || !strings.Contains(strings.ToLower(err.Error()), "reparse") {
		t.Fatalf("config junction error = %v, want explicit reparse rejection", err)
	}
	if err := atomicTransformFileWithStateDir(
		realPath, stateJunction, 0o600, transform,
	); err == nil || !strings.Contains(strings.ToLower(err.Error()), "reparse") {
		t.Fatalf("state junction error = %v, want explicit reparse rejection", err)
	}
	data, err := os.ReadFile(realPath)
	if err != nil || string(data) != `{"old":true}` {
		t.Fatalf("junction rejection mutated live config: %q, %v", data, err)
	}
}

func TestAtomicTransformV2RejectsSUBSTVolumeLocator(t *testing.T) {
	root := t.TempDir()
	realConfigDir := filepath.Join(root, "config")
	if err := os.Mkdir(realConfigDir, 0o700); err != nil {
		t.Fatal(err)
	}
	realPath := filepath.Join(realConfigDir, "settings.json")
	initial := []byte(`{"old":true}`)
	if err := os.WriteFile(realPath, initial, 0o600); err != nil {
		t.Fatal(err)
	}
	drive := ""
	for letter := 'Z'; letter >= 'P'; letter-- {
		candidate := fmt.Sprintf("%c:", letter)
		pointer, err := windows.UTF16PtrFromString(candidate)
		if err != nil {
			t.Fatal(err)
		}
		buffer := make([]uint16, 256)
		if _, err := windows.QueryDosDevice(pointer, &buffer[0], uint32(len(buffer))); err != nil {
			drive = candidate
			break
		}
	}
	if drive == "" {
		t.Skip("no free drive letter for SUBST validation")
	}
	output, err := exec.Command("subst.exe", drive, root).CombinedOutput()
	if err != nil {
		t.Skipf("SUBST unavailable: %v (%s)", err, output)
	}
	t.Cleanup(func() { _, _ = exec.Command("subst.exe", drive, "/D").CombinedOutput() })
	aliasPath := filepath.Join(drive+`\`, "config", "settings.json")
	err = atomicTransformFileWithStateDir(
		aliasPath, filepath.Join(root, "protected-state"), 0o600,
		func(_ []byte, _ bool) (atomicTransformResult, error) {
			return atomicTransformResult{Data: []byte(`{"new":true}`)}, nil
		},
	)
	if err == nil || (!strings.Contains(strings.ToLower(err.Error()), "subst") &&
		!strings.Contains(strings.ToLower(err.Error()), "dos-device") &&
		!strings.Contains(strings.ToLower(err.Error()), "mount manager")) {
		t.Fatalf("SUBST locator error = %v, want explicit retargetable-volume rejection", err)
	}
	data, readErr := os.ReadFile(realPath)
	if readErr != nil || !bytes.Equal(data, initial) {
		t.Fatalf("SUBST rejection mutated physical config: %q, %v", data, readErr)
	}
}

func atomicTransformV2BoundaryCommitted(operation string, point atomicTransformV2ExitBoundary) bool {
	phase := point.phase
	if phase == atomicTransformPhasePublished {
		return true
	}
	switch phase {
	case atomicTransformPhaseFinalPublicationValidated,
		atomicTransformPhase("replace-" + atomicTransformV2ReplaceBoundaryBeforeTargetFlush),
		atomicTransformPhase("replace-" + atomicTransformV2ReplaceBoundaryAfterTargetFlush),
		atomicTransformPhase("replace-" + atomicTransformV2ReplaceBoundaryBeforeBackupFlush),
		atomicTransformPhase("replace-" + atomicTransformV2ReplaceBoundaryAfterBackupFlush),
		atomicTransformPhase("replace-" + atomicTransformV2ReplaceBoundaryBeforeDirectorySync),
		atomicTransformPhase("replace-" + atomicTransformV2ReplaceBoundaryAfterDirectorySync),
		atomicTransformPhaseTerminalWitnessed,
		atomicTransformPhaseTerminalBootstrap,
		atomicTransformPhaseCompleteBootstrap,
		atomicTransformPhaseCleanupStarted,
		atomicTransformPhaseMarkerEstablished,
		atomicTransformPhaseCompleted,
		atomicTransformPhaseCompleteRetired,
		atomicTransformPhaseAllocationRetired,
		atomicTransformPhaseMarkerRetired,
		atomicTransformPhaseStagingRetired,
		atomicTransformPhasePreparedRetired,
		atomicTransformPhaseTerminalRetired:
		return true
	default:
		return false
	}
}

func atomicTransformV2BoundaryCommittedAfterExit(
	path, stateDir, operation string, point atomicTransformV2ExitBoundary,
) (bool, error) {
	committed := atomicTransformV2BoundaryCommitted(operation, point)
	if !committed {
		return false, nil
	}
	loaded, err := loadAtomicTransformV2(path, stateDir)
	if err != nil {
		return false, err
	}
	decision := ""
	if loaded.complete.located {
		decision = loaded.complete.receipt.Decision
	} else if loaded.terminal.located {
		decision = loaded.terminal.receipt.Decision
	}
	switch decision {
	case atomicTransformV2DecisionCommit:
		return true, nil
	case atomicTransformV2DecisionAbort:
		return false, nil
	case "":
		// The earliest terminal-bootstrap cut points precede durable receipt
		// publication. At every boundary the matrix otherwise calls committed,
		// live is already the validated terminal outcome, so it disambiguates a
		// commit from an abort without changing production instrumentation.
		data, readErr := os.ReadFile(path)
		switch operation {
		case "create":
			switch {
			case readErr == nil && bytes.Equal(data, atomicTransformV2HardExitPayload()):
				return true, nil
			case errors.Is(readErr, os.ErrNotExist):
				return false, nil
			}
		case "update":
			switch {
			case readErr == nil && bytes.Equal(data, atomicTransformV2HardExitPayload()):
				return true, nil
			case readErr == nil && bytes.Equal(data, []byte(`{"old":true}`)):
				return false, nil
			}
		case "remove":
			switch {
			case errors.Is(readErr, os.ErrNotExist):
				return true, nil
			case readErr == nil && bytes.Equal(data, []byte(`{"old":true}`)):
				return false, nil
			}
		}
		return false, fmt.Errorf(
			"shared terminal boundary has no durable decision and live outcome is unrecognized: operation=%s bytes=%d err=%v",
			operation, len(data), readErr,
		)
	default:
		return false, fmt.Errorf("unsupported durable V2 decision %q", decision)
	}
}

func removeAtomicTransformV2ExitBoundaries(
	boundaries []atomicTransformV2ExitBoundary, phases ...atomicTransformPhase,
) []atomicTransformV2ExitBoundary {
	remove := map[atomicTransformPhase]bool{}
	for _, phase := range phases {
		remove[phase] = true
	}
	result := boundaries[:0]
	for _, boundary := range boundaries {
		if !remove[boundary.phase] {
			result = append(result, boundary)
		}
	}
	return result
}

func capAtomicTransformV2ExitOccurrences(
	boundaries []atomicTransformV2ExitBoundary, phases ...atomicTransformPhase,
) []atomicTransformV2ExitBoundary {
	capPhase := map[atomicTransformPhase]bool{}
	for _, phase := range phases {
		capPhase[phase] = true
	}
	result := boundaries[:0]
	for _, boundary := range boundaries {
		if !capPhase[boundary.phase] || boundary.occurrence == 1 {
			result = append(result, boundary)
		}
	}
	return result
}

func assertAtomicTransformV2NoArtifacts(t *testing.T, path, stateDir string) {
	t.Helper()
	for _, directory := range []string{filepath.Dir(path), stateDir} {
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			name := strings.ToLower(entry.Name())
			if strings.HasPrefix(name, atomicTransformV2ReceiptPrefix) ||
				strings.HasPrefix(name, atomicTransformV2NamePrefix) {
				t.Fatalf("recovery left V2 artifact %s in %s", entry.Name(), directory)
			}
		}
	}
}
