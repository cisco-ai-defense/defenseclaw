// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookruntime

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"golang.org/x/sys/windows"
)

const delegationHelperEnvironment = "DEFENSECLAW_HOOK_DELEGATION_TEST_HELPER"

const delegatedAdmissionHelperEnvironment = "DEFENSECLAW_HOOK_DELEGATED_ADMISSION_TEST_ROOT"

type delegationFixture struct {
	paths      Paths
	source     string
	hook       string
	gateway    string
	dataRoot   string
	executable string
}

type delegationHelperReport struct {
	Args  []string `json:"args"`
	CWD   string   `json:"cwd"`
	Input string   `json:"input"`
	Env   string   `json:"env"`
}

func TestHookDelegationHelper(t *testing.T) {
	if os.Getenv(delegationHelperEnvironment) != "1" {
		return
	}
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(98)
	}
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(97)
	}
	if err := json.NewEncoder(os.Stdout).Encode(delegationHelperReport{
		Args:  os.Args[1:],
		CWD:   cwd,
		Input: string(input),
		Env:   os.Getenv("DEFENSECLAW_DELEGATION_ENV_SENTINEL"),
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(96)
	}
	fmt.Fprint(os.Stderr, "delegated-stderr")
	os.Exit(37)
}

func TestTrustedDelegatedAdmissionHelper(t *testing.T) {
	root := os.Getenv(delegatedAdmissionHelperEnvironment)
	if root == "" {
		return
	}
	paths := Paths{
		Root:     root,
		Launcher: filepath.Join(root, LauncherName),
		State:    filepath.Join(root, StateName),
	}
	executable, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(95)
	}
	if samePath(executable, paths.Launcher) {
		os.Exit(delegateAt(
			paths,
			executable,
			[]string{"-test.run=^TestTrustedDelegatedAdmissionHelper$"},
			os.Stdin,
			os.Stdout,
			os.Stderr,
		))
	}
	marker, _ := lookupDelegationGeneration(os.Environ())
	state, recognized, admissionErr := readTrustedDelegatedForExecutableAt(
		paths,
		executable,
		marker,
		liveCanonicalDelegatingParent,
	)
	report := struct {
		Recognized    bool   `json:"recognized"`
		Active        bool   `json:"active"`
		TransactionID string `json:"transaction_id"`
		Error         string `json:"error,omitempty"`
	}{
		Recognized:    recognized,
		Active:        state.Active(),
		TransactionID: state.TransactionID,
	}
	if admissionErr != nil {
		report.Error = admissionErr.Error()
	}
	if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(94)
	}
	os.Exit(0)
}

func TestDelegatedChildUsesExactParentVerifiedGenerationWithoutSecondFullImageRead(t *testing.T) {
	paths := testRuntimePaths(t)
	launcherSource := copyDelegationTestExecutableAs(t, HookLauncherName)
	hook := copyDelegationTestExecutable(t)
	if err := publishAt(
		paths,
		launcherSource,
		hook,
		writeRuntimeGateway(t, "MZ-delegated-admission-gateway"),
		filepath.Join(t.TempDir(), "data"),
		stableRuntimeTransactionOne,
	); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(paths.Launcher, "-test.run=^TestTrustedDelegatedAdmissionHelper$")
	cmd.Env = append(
		os.Environ(),
		delegatedAdmissionHelperEnvironment+"="+paths.Root,
		delegationGenerationEnvName+"=spoofed-project-value",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run exact stable-parent delegation: %v: %s", err, output)
	}
	var report struct {
		Recognized    bool   `json:"recognized"`
		Active        bool   `json:"active"`
		TransactionID string `json:"transaction_id"`
		Error         string `json:"error"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(output), &report); err != nil {
		t.Fatalf("decode delegated admission report %q: %v", output, err)
	}
	if !report.Recognized || !report.Active || report.Error != "" ||
		report.TransactionID != stableRuntimeTransactionOne {
		t.Fatalf("delegated admission report = %+v", report)
	}
}

func TestDelegatedAdmissionFailsClosedForSpoofedParentAndGenerationRotation(t *testing.T) {
	fixture := newDelegationFixture(t)
	state, _, err := readTrustedAt(fixture.paths, fixture.paths.Launcher)
	if err != nil {
		t.Fatal(err)
	}
	marker := delegationGenerationPrefix + "1:" + state.TransactionID + ":" + state.HookSHA256

	t.Run("direct spoofed marker has no parent authority", func(t *testing.T) {
		got, recognized, err := readTrustedDelegatedForExecutableAt(
			fixture.paths,
			fixture.hook,
			marker,
			func(string, windows.Handle) (bool, error) { return false, nil },
		)
		if err != nil || recognized || got.Active() {
			t.Fatalf("spoofed direct admission = %+v, recognized=%t, err=%v", got, recognized, err)
		}
	})

	t.Run("live wrong parent has no launcher authority", func(t *testing.T) {
		proof, proofErr := inheritableCurrentProcessProof()
		if proofErr != nil {
			t.Fatal(proofErr)
		}
		defer windows.CloseHandle(proof)
		trusted, err := liveCanonicalDelegatingParent(fixture.paths.Launcher, proof)
		if err == nil && trusted {
			t.Fatal("non-launcher test parent authenticated as the protected stable launcher")
		}
	})

	t.Run("malformed parent marker", func(t *testing.T) {
		_, recognized, err := readTrustedDelegatedForExecutableAt(
			fixture.paths,
			fixture.hook,
			delegationGenerationPrefix+"1:malformed:"+strings.Repeat("a", 64),
			func(string, windows.Handle) (bool, error) { return true, nil },
		)
		if !recognized || err == nil || !strings.Contains(err.Error(), "malformed") {
			t.Fatalf("malformed marker recognized=%t, err=%v", recognized, err)
		}
	})

	t.Run("digest mismatch", func(t *testing.T) {
		wrong := delegationGenerationPrefix + "1:" + state.TransactionID + ":" + strings.Repeat("c", 64)
		_, recognized, err := readTrustedDelegatedForExecutableAt(
			fixture.paths,
			fixture.hook,
			wrong,
			func(string, windows.Handle) (bool, error) { return true, nil },
		)
		if !recognized || err == nil || !strings.Contains(err.Error(), "no longer matches") {
			t.Fatalf("digest mismatch recognized=%t, err=%v", recognized, err)
		}
	})

	t.Run("target path mismatch", func(t *testing.T) {
		_, recognized, err := readTrustedDelegatedForExecutableAt(
			fixture.paths,
			filepath.Join(t.TempDir(), LauncherName),
			marker,
			func(string, windows.Handle) (bool, error) { return true, nil },
		)
		if !recognized || err == nil || !strings.Contains(err.Error(), "no longer matches") {
			t.Fatalf("target mismatch recognized=%t, err=%v", recognized, err)
		}
	})

	t.Run("protected generation rotates after parent start", func(t *testing.T) {
		rotated := state
		rotated.TransactionID = stableRuntimeTransactionTwo
		if err := writeState(fixture.paths, rotated); err != nil {
			t.Fatal(err)
		}
		_, recognized, err := readTrustedDelegatedForExecutableAt(
			fixture.paths,
			fixture.hook,
			marker,
			func(string, windows.Handle) (bool, error) { return true, nil },
		)
		if !recognized || err == nil || !strings.Contains(err.Error(), "no longer matches") {
			t.Fatalf("rotated generation recognized=%t, err=%v", recognized, err)
		}
	})
}

func TestPreparedDelegatedGenerationRefreshRequiresExactProtectedState(t *testing.T) {
	fixture := newDelegationFixture(t)
	prepared, recognized, err := readTrustedForExecutableAt(fixture.paths, fixture.hook)
	if err != nil || !recognized || !prepared.Active() {
		t.Fatalf("initial full-hook admission = %+v, recognized=%t, err=%v", prepared, recognized, err)
	}
	refreshed, err := revalidatePreparedGenerationForExecutableAt(
		fixture.paths,
		fixture.hook,
		prepared,
	)
	if err != nil || refreshed != prepared {
		t.Fatalf("unchanged prepared generation refresh = %+v, err=%v", refreshed, err)
	}

	rotated := prepared
	rotated.TransactionID = stableRuntimeTransactionTwo
	if err := writeState(fixture.paths, rotated); err != nil {
		t.Fatal(err)
	}
	if _, err := revalidatePreparedGenerationForExecutableAt(
		fixture.paths,
		fixture.hook,
		prepared,
	); err == nil || !strings.Contains(err.Error(), "generation changed") {
		t.Fatalf("rotated protected state refresh error = %v", err)
	}
}

func TestActiveDelegationPreservesArgumentsCWDStdioEnvironmentAndExit(t *testing.T) {
	fixture := newDelegationFixture(t)
	t.Setenv(delegationHelperEnvironment, "1")
	t.Setenv("DEFENSECLAW_DELEGATION_ENV_SENTINEL", "inherited")
	cwd := t.TempDir()
	previousCWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(previousCWD) })

	args := []string{
		"-test.run=^TestHookDelegationHelper$",
		"hook",
		"--connector",
		"two words",
		`quote"value`,
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := delegateAt(
		fixture.paths,
		fixture.executable,
		args,
		strings.NewReader("delegated-stdin"),
		&stdout,
		&stderr,
	)
	if exitCode != 37 {
		t.Fatalf("delegated exit code = %d, want 37; stderr=%q", exitCode, stderr.String())
	}
	if stderr.String() != "delegated-stderr" {
		t.Fatalf("delegated stderr = %q", stderr.String())
	}
	var report delegationHelperReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("decode delegated output %q: %v", stdout.String(), err)
	}
	if strings.Join(report.Args, "\x00") != strings.Join(args, "\x00") {
		t.Fatalf("delegated args = %q, want %q", report.Args, args)
	}
	if !samePath(report.CWD, cwd) {
		t.Fatalf("delegated CWD = %q, want %q", report.CWD, cwd)
	}
	if report.Input != "delegated-stdin" || report.Env != "inherited" {
		t.Fatalf("delegated stdio/environment report = %+v", report)
	}
}

func TestDelegationFailsClosedBeforeLaunchingForInactiveOrUnsafeState(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, delegationFixture)
	}{
		{
			name: "disabled",
			mutate: func(t *testing.T, fixture delegationFixture) {
				if err := disableAt(fixture.paths, stableRuntimeTransactionTwo); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "publishing",
			mutate: func(t *testing.T, fixture delegationFixture) {
				state, _, err := readTrustedAt(fixture.paths, fixture.executable)
				if err != nil {
					t.Fatal(err)
				}
				state.Status = StatusPublishing
				if err := writeState(fixture.paths, state); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "missing-state",
			mutate: func(t *testing.T, fixture delegationFixture) {
				if err := os.Remove(fixture.paths.State); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "malformed-state",
			mutate: func(t *testing.T, fixture delegationFixture) {
				if err := os.WriteFile(fixture.paths.State, []byte("{"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "launcher-digest-mismatch",
			mutate: func(t *testing.T, fixture delegationFixture) {
				if err := os.WriteFile(fixture.paths.Launcher, []byte("changed"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "hook-digest-mismatch",
			mutate: func(t *testing.T, fixture delegationFixture) {
				if err := os.WriteFile(fixture.hook, []byte("changed"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "hook-private-dacl-mismatch",
			mutate: func(t *testing.T, fixture delegationFixture) {
				addDACLDrift(t, fixture.hook, windows.GENERIC_READ)
			},
		},
		{
			name: "hook-path-mismatch",
			mutate: func(t *testing.T, fixture delegationFixture) {
				state, _, err := readTrustedAt(fixture.paths, fixture.executable)
				if err != nil {
					t.Fatal(err)
				}
				state.HookPath = filepath.Join(t.TempDir(), LauncherName)
				if err := writeState(fixture.paths, state); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDelegationFixture(t)
			test.mutate(t, fixture)
			t.Setenv(delegationHelperEnvironment, "1")
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			exitCode := delegateAt(
				fixture.paths,
				fixture.executable,
				[]string{"-test.run=^TestHookDelegationHelper$"},
				nil,
				&stdout,
				&stderr,
			)
			if exitCode != 0 || stdout.Len() != 0 || stderr.Len() != 0 {
				t.Fatalf(
					"fail-closed delegation = exit %d, stdout %q, stderr %q",
					exitCode,
					stdout.String(),
					stderr.String(),
				)
			}
		})
	}
}

func TestDelegationQueuedBehindDisableDoesNotLaunch(t *testing.T) {
	fixture := newDelegationFixture(t)
	t.Setenv(delegationHelperEnvironment, "1")
	disableEntered := make(chan struct{})
	finishDisable := make(chan struct{})
	disableDone := make(chan error, 1)
	go func() {
		disableDone <- WithGatewayStartLock(t.Context(), func() error {
			close(disableEntered)
			<-finishDisable
			return disableAt(fixture.paths, stableRuntimeTransactionTwo)
		})
	}()
	<-disableEntered

	type delegationResult struct {
		code   int
		stdout string
		stderr string
	}
	delegationDone := make(chan delegationResult, 1)
	go func() {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		code := delegateAt(
			fixture.paths,
			fixture.executable,
			[]string{"-test.run=^TestHookDelegationHelper$"},
			nil,
			&stdout,
			&stderr,
		)
		delegationDone <- delegationResult{code: code, stdout: stdout.String(), stderr: stderr.String()}
	}()
	close(finishDisable)
	if err := <-disableDone; err != nil {
		t.Fatal(err)
	}
	result := <-delegationDone
	if result.code != 0 || result.stdout != "" || result.stderr != "" {
		t.Fatalf("delegation crossed disable barrier: %+v", result)
	}
}

func TestDisabledDelegatedChildRemainsRecognizedAndFailClosed(t *testing.T) {
	fixture := newDelegationFixture(t)
	if err := disableAt(fixture.paths, stableRuntimeTransactionTwo); err != nil {
		t.Fatal(err)
	}
	state, recognized, err := readTrustedForExecutableAt(fixture.paths, fixture.hook)
	if err != nil || !recognized || state.Active() || !state.DelegatesTo(fixture.hook) {
		t.Fatalf("disabled delegated child = state %+v, recognized %t, error %v", state, recognized, err)
	}
}

func TestLockVerifiedHookRejectsReparseOwnerDACLAndReplacement(t *testing.T) {
	t.Run("replacement", func(t *testing.T) {
		fixture := newDelegationFixture(t)
		state, _, err := readTrustedAt(fixture.paths, fixture.executable)
		if err != nil {
			t.Fatal(err)
		}
		locked, err := LockVerifiedHook(state)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fixture.hook, []byte("replacement"), 0o700); err == nil {
			_ = locked.Close()
			t.Fatal("full-hook replacement succeeded while validated handle was pinned")
		}
		if err := locked.Close(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("reparse-final-path", func(t *testing.T) {
		fixture := newDelegationFixture(t)
		state, _, err := readTrustedAt(fixture.paths, fixture.executable)
		if err != nil {
			t.Fatal(err)
		}
		aliasRoot := filepath.Join(t.TempDir(), "installed")
		if output, err := execCommand("cmd.exe", "/d", "/c", "mklink", "/J", aliasRoot, filepath.Dir(fixture.hook)); err != nil {
			t.Skipf("junction creation unavailable: %v (%s)", err, output)
		}
		defer os.Remove(aliasRoot)
		state.HookPath = filepath.Join(aliasRoot, LauncherName)
		if locked, err := LockVerifiedHook(state); err == nil {
			_ = locked.Close()
			t.Fatal("reparse-resolved full hook was accepted")
		}
	})

	t.Run("dacl", func(t *testing.T) {
		fixture := newDelegationFixture(t)
		state, _, err := readTrustedAt(fixture.paths, fixture.executable)
		if err != nil {
			t.Fatal(err)
		}
		addDACLDrift(t, fixture.hook, windows.GENERIC_READ)
		if locked, err := LockVerifiedHook(state); err == nil {
			_ = locked.Close()
			t.Fatal("full hook with non-private DACL was accepted")
		}
	})

	t.Run("owner", func(t *testing.T) {
		fixture := newDelegationFixture(t)
		path, err := windows.UTF16PtrFromString(fixture.hook)
		if err != nil {
			t.Fatal(err)
		}
		handle, err := windows.CreateFile(
			path,
			windows.GENERIC_READ|windows.READ_CONTROL,
			windows.FILE_SHARE_READ,
			nil,
			windows.OPEN_EXISTING,
			windows.FILE_ATTRIBUTE_NORMAL,
			0,
		)
		if err != nil {
			t.Fatal(err)
		}
		defer windows.CloseHandle(handle)
		descriptor, err := windows.GetSecurityInfo(
			handle,
			windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION,
		)
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, err := descriptor.DACL()
		if err != nil {
			t.Fatal(err)
		}
		system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
		if err != nil {
			t.Fatal(err)
		}
		safe, err := privateDACLForCurrentUserIsSafe(system, dacl)
		if err != nil {
			t.Fatal(err)
		}
		if safe {
			t.Fatal("foreign-owned full-hook security descriptor was accepted")
		}
	})
}

func TestStableRuntimeUpgradesLegacyFullToTrampolineAndRollsBack(t *testing.T) {
	paths := testRuntimePaths(t)
	fullHook := copyDelegationTestExecutable(t)
	gateway := writeRuntimeGateway(t, "MZ-gateway")
	dataRoot := filepath.Join(t.TempDir(), "data")
	if err := publishAt(
		paths,
		fullHook,
		fullHook,
		gateway,
		dataRoot,
		stableRuntimeTransactionOne,
	); err != nil {
		t.Fatal(err)
	}
	legacy, _, err := readTrustedAt(paths, paths.Launcher)
	if err != nil || legacy.DelegationCapable() {
		t.Fatalf("legacy full state = %+v, error %v", legacy, err)
	}

	small := filepath.Join(t.TempDir(), HookLauncherName)
	if err := os.WriteFile(small, []byte("MZ-small-trampoline"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := publishAt(
		paths,
		small,
		fullHook,
		gateway,
		dataRoot,
		stableRuntimeTransactionTwo,
	); err != nil {
		t.Fatal(err)
	}
	upgraded, _, err := readTrustedAt(paths, paths.Launcher)
	if err != nil || !upgraded.Active() || !upgraded.DelegatesTo(fullHook) {
		t.Fatalf("trampoline state = %+v, error %v", upgraded, err)
	}
	if body, err := os.ReadFile(paths.Launcher); err != nil || string(body) != "MZ-small-trampoline" {
		t.Fatalf("stable trampoline bytes = %q, error %v", body, err)
	}

	if err := publishAt(
		paths,
		fullHook,
		fullHook,
		gateway,
		dataRoot,
		stableRuntimeTransactionOne,
	); err != nil {
		t.Fatal(err)
	}
	rolledBack, _, err := readTrustedAt(paths, paths.Launcher)
	if err != nil || !rolledBack.Active() || rolledBack.DelegationCapable() ||
		rolledBack.LauncherKind != "" || rolledBack.HookPath != "" || rolledBack.HookSHA256 != "" {
		t.Fatalf("rolled-back full state = %+v, error %v", rolledBack, err)
	}
}

func TestSchemaTwoTrampolineFieldsRemainReadableByLegacyFullStateShape(t *testing.T) {
	fixture := newDelegationFixture(t)
	state, _, err := readTrustedAt(fixture.paths, fixture.executable)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	var legacy struct {
		SchemaVersion  int    `json:"schema_version"`
		Status         string `json:"status"`
		RuntimeRoot    string `json:"runtime_root"`
		LauncherPath   string `json:"launcher_path"`
		LauncherSHA256 string `json:"launcher_sha256"`
		DataRoot       string `json:"data_root,omitempty"`
		GatewayPath    string `json:"gateway_path,omitempty"`
		GatewaySHA256  string `json:"gateway_sha256,omitempty"`
		TransactionID  string `json:"transaction_id"`
	}
	if err := json.Unmarshal(body, &legacy); err != nil {
		t.Fatalf("legacy full launcher could not ignore additive fields: %v", err)
	}
	if legacy.SchemaVersion != SchemaVersion || legacy.Status != StatusActive ||
		legacy.RuntimeRoot != state.RuntimeRoot || legacy.LauncherPath != state.LauncherPath ||
		legacy.LauncherSHA256 != state.LauncherSHA256 || legacy.DataRoot != state.DataRoot ||
		legacy.GatewayPath != state.GatewayPath || legacy.GatewaySHA256 != state.GatewaySHA256 ||
		legacy.TransactionID != state.TransactionID {
		t.Fatalf("legacy full state shape changed: %+v", legacy)
	}
}

func TestTrampolinePublicationRejectsLauncherOverSizeContract(t *testing.T) {
	paths := testRuntimePaths(t)
	source := filepath.Join(t.TempDir(), HookLauncherName)
	file, err := os.Create(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(MaxHookLauncherBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	err = publishAt(
		paths,
		source,
		copyDelegationTestExecutable(t),
		writeRuntimeGateway(t, "MZ-gateway"),
		filepath.Join(t.TempDir(), "data"),
		stableRuntimeTransactionOne,
	)
	if err == nil || !strings.Contains(err.Error(), "maximum") {
		t.Fatalf("oversize trampoline publication error = %v", err)
	}
}

func newDelegationFixture(t *testing.T) delegationFixture {
	t.Helper()
	paths := testRuntimePaths(t)
	source := filepath.Join(t.TempDir(), HookLauncherName)
	if err := os.WriteFile(source, []byte("MZ-small-trampoline"), 0o700); err != nil {
		t.Fatal(err)
	}
	hook := copyDelegationTestExecutable(t)
	gateway := writeRuntimeGateway(t, "MZ-delegation-gateway")
	dataRoot := filepath.Join(t.TempDir(), "data")
	if err := publishAt(
		paths,
		source,
		hook,
		gateway,
		dataRoot,
		stableRuntimeTransactionOne,
	); err != nil {
		t.Fatal(err)
	}
	return delegationFixture{
		paths:      paths,
		source:     source,
		hook:       hook,
		gateway:    gateway,
		dataRoot:   dataRoot,
		executable: paths.Launcher,
	}
}

func copyDelegationTestExecutable(t *testing.T) string {
	return copyDelegationTestExecutableAs(t, LauncherName)
}

func copyDelegationTestExecutableAs(t *testing.T, name string) string {
	t.Helper()
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), name)
	input, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	output, err := os.Create(target)
	if err != nil {
		_ = input.Close()
		t.Fatal(err)
	}
	_, copyErr := io.Copy(output, input)
	closeInputErr := input.Close()
	closeOutputErr := output.Close()
	if err := errors.Join(copyErr, closeInputErr, closeOutputErr); err != nil {
		t.Fatal(err)
	}
	return target
}

func execCommand(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

func TestCanonicalCachedHookPathAndNamesRemainStable(t *testing.T) {
	paths, err := CurrentUserPaths()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(paths.Launcher) != "defenseclaw-hook.exe" ||
		filepath.Base(paths.Root) != "HookRuntime" ||
		filepath.Base(filepath.Dir(paths.Root)) != "DefenseClaw" {
		t.Fatalf("canonical cached hook paths changed: %+v", paths)
	}
	if HookLauncherName != "defenseclaw-hook-launcher.exe" {
		t.Fatalf("packaged trampoline name changed: %s", HookLauncherName)
	}
}

func TestPublishedFullHookHasPrivateHandleSecurity(t *testing.T) {
	fixture := newDelegationFixture(t)
	if err := safefile.ValidatePrivateFile(fixture.hook); err != nil {
		t.Fatal(err)
	}
	state, _, err := readTrustedAt(fixture.paths, fixture.executable)
	if err != nil {
		t.Fatal(err)
	}
	locked, err := LockVerifiedHook(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := locked.Close(); err != nil {
		t.Fatal(err)
	}
}
