// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// GAP-0132: an upgrade replaces the scanner runtime while a scan still runs
// the installed image (Windows refuses to overwrite a mapped image).
func TestCopyWindowsScannerRuntimeReplacesARunningImage(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "defenseclaw-scanners.exe")
	copyFile := func(from, to string) {
		in, err := os.Open(from)
		if err != nil {
			t.Fatal(err)
		}
		defer in.Close()
		out, err := os.Create(to)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(out, in); err != nil {
			t.Fatal(err)
		}
		_ = out.Close()
	}
	copyFile(filepath.Join(os.Getenv("SystemRoot"), "System32", "PING.EXE"), target)
	running := exec.Command(target, "-n", "20", "127.0.0.1")
	if err := running.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = running.Process.Kill(); _, _ = running.Process.Wait() })
	time.Sleep(500 * time.Millisecond)

	source := filepath.Join(t.TempDir(), "new.exe")
	if err := os.WriteFile(source, []byte("new runtime"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := copyWindowsScannerRuntime(source, target, root, ""); err != nil {
		t.Fatalf("replace a running scanner runtime: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(got, []byte("new runtime")) {
		t.Fatalf("installed runtime = %q, %v", got, err)
	}
}

// Every scan fails closed without the scanner runtime, so a missing one fails
// verify, warns in status, and is reported by a repair from the installed CLI,
// which has no Setup payload to install it from (GAP-0294).
func TestWindowsScannerRuntimeMissingIsReported(t *testing.T) {
	seam := windowsScannerRuntimeDir
	t.Cleanup(func() { windowsScannerRuntimeDir = seam })
	root := t.TempDir()
	windowsScannerRuntimeDir = func() (string, error) { return root, nil }
	for _, action := range []string{"verify", "status", "repair", "recover"} {
		result := enterprisestatus.New(action, managed.ProfileStandalone, "windows", "1.0.0")
		result.Installed = true
		applyWindowsStandaloneScannerRuntime(result, &windowsEnterpriseLifecycleOptions{})
		messages := result.Warnings
		if action == "verify" || action == "recover" {
			messages = result.Errors
		}
		reported := false
		for _, message := range messages {
			reported = reported || message.Code == "scanner_runtime_unavailable"
		}
		if !reported || result.Scanners == nil || result.Scanners.State != "missing" {
			t.Fatalf("%s: errors=%+v warnings=%+v scanners=%+v", action, result.Errors, result.Warnings, result.Scanners)
		}
	}

	// GAP-0686: a prepared runtime the gateway service cannot run fails
	// verify too; before, verify said ok while every rescan failed. GAP-1361:
	// so does an ensure from the installed CLI (an ancestor of the runtime
	// lost the service's read entry), which reported success.
	readerSeam, checkSeam := windowsScannerRuntimeReader, windowsScannerRuntimeServiceCheck
	t.Cleanup(func() { windowsScannerRuntimeReader, windowsScannerRuntimeServiceCheck = readerSeam, checkSeam })
	windowsScannerRuntimeReader = func() *enterprisestatus.ScannerRuntime {
		return &enterprisestatus.ScannerRuntime{State: "ready", JudgeModel: "judge"}
	}
	windowsScannerRuntimeServiceCheck = func() error {
		return errors.New("the gateway service account cannot list or read the permissions of the parent folder C:\\ProgramData")
	}
	for _, action := range []string{"verify", "ensure", "recover"} {
		result := enterprisestatus.New(action, managed.ProfileStandalone, "windows", "1.0.0")
		result.Installed = true
		applyWindowsStandaloneScannerRuntime(result, &windowsEnterpriseLifecycleOptions{})
		if len(result.Errors) != 1 || result.Errors[0].Code != "scanner_runtime_unavailable" ||
			!strings.Contains(result.Errors[0].Message, "parent folder") {
			t.Fatalf("%s with a runtime the gateway cannot run: errors=%+v", action, result.Errors)
		}
	}
}

// GAP-0727: status and verify must not run a scanner executable from a
// runtime directory that an unprivileged user can modify.
func TestWindowsScannerRuntimeRejectsWritableRoot(t *testing.T) {
	seam := windowsScannerRuntimeDir
	t.Cleanup(func() { windowsScannerRuntimeDir = seam })
	root := t.TempDir()
	target := filepath.Join(root, managed.StandaloneWindowsScannerRuntimeName)
	if err := os.WriteFile(target, []byte("not an executable"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Grant standard users write access without changing the directory owner,
	// so this test also runs from an unelevated Windows CI account.
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(root, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	windowsScannerRuntimeDir = func() (string, error) { return root, nil }
	// GAP-0827: not run, and not reported as missing either: the state and
	// the advice name the access that keeps it from running.
	got := readWindowsScannerRuntime()
	if got.State != "untrusted" || got.Problem == "" {
		t.Fatalf("writable scanner runtime = %+v, want untrusted with the access problem", got)
	}
	if message := windowsScannerRuntimeUnavailable(got); !strings.Contains(message, got.Problem) ||
		!strings.Contains(message, "other than SYSTEM and Administrators") || !strings.Contains(message, "/repair") {
		t.Fatalf("writable scanner runtime advice = %q", message)
	}
}

// GAP-1016: an admin config with scanners.skill_scanner.use_llm: false runs
// no judge, so status names none and warns, even with llm.model set; an
// absent key keeps the judge.
func TestWindowsStandaloneScannerJudgeFollowsUseLLM(t *testing.T) {
	seam := readWindowsStandaloneScannerConfig
	t.Cleanup(func() { readWindowsStandaloneScannerConfig = seam })
	for _, tc := range []struct {
		name, config, judge string
	}{
		{"judge off", "llm:\n  model: bedrock/claude\nscanners:\n  skill_scanner:\n    use_llm: false\n", ""},
		{"default", "llm:\n  model: bedrock/claude\nscanners:\n  skill_scanner:\n    policy: quiet\n", "bedrock/claude"},
	} {
		config := tc.config
		readWindowsStandaloneScannerConfig = func() ([]byte, error) { return []byte(config), nil }
		if _, judge := readWindowsStandaloneScannerSettings(); judge != tc.judge {
			t.Fatalf("%s: judge = %q, want %q", tc.name, judge, tc.judge)
		}
		readerSeam, checkSeam := windowsScannerRuntimeReader, windowsScannerRuntimeServiceCheck
		windowsScannerRuntimeReader = func() *enterprisestatus.ScannerRuntime {
			_, judge := readWindowsStandaloneScannerSettings()
			return &enterprisestatus.ScannerRuntime{State: "ready", JudgeModel: judge}
		}
		windowsScannerRuntimeServiceCheck = func() error { return nil }
		result := enterprisestatus.New("status", managed.ProfileStandalone, "windows", "1.0.2")
		result.Installed = true
		applyWindowsStandaloneScannerRuntime(result, &windowsEnterpriseLifecycleOptions{})
		windowsScannerRuntimeReader, windowsScannerRuntimeServiceCheck = readerSeam, checkSeam
		warned := ""
		for _, warning := range result.Warnings {
			if warning.Code == "scanner_judge_missing" {
				warned = warning.Message
			}
		}
		if tc.judge == "" && !strings.Contains(warned, "use_llm is false") {
			t.Fatalf("%s: warnings = %+v, want scanner_judge_missing naming use_llm", tc.name, result.Warnings)
		}
		if tc.judge != "" && warned != "" {
			t.Fatalf("%s: warnings = %+v, want no scanner_judge_missing", tc.name, result.Warnings)
		}
	}
}

// GAP-0311: the staged scanner executable is admitted like every other
// payload file before the lifecycle copies it into the protected root and
// runs it as an administrator. An unsigned one is refused in authenticode
// mode, and in hash_pinned mode unless the payload manifest pins its digest.
func TestWindowsScannerRuntimeIsAdmittedByThePayloadTrustPolicy(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("the scanner runtime root is administrator-only; run elevated")
	}
	dirSeam, accountSeam, sourceSeam := windowsScannerRuntimeDir, windowsScannerGatewayAccount, windowsScannerSourceCheck
	t.Cleanup(func() {
		windowsScannerRuntimeDir, windowsScannerGatewayAccount, windowsScannerSourceCheck = dirSeam, accountSeam, sourceSeam
	})
	root := filepath.Join(t.TempDir(), "DefenseClaw-ScannerRuntime")
	windowsScannerRuntimeDir = func() (string, error) { return root, nil }
	// The gateway service is not installed here; any service SID will do.
	windowsScannerGatewayAccount = `NT SERVICE\TrustedInstaller`
	// The staged folder stands for an administrator-only payload folder.
	windowsScannerSourceCheck = func(string, string) error { return nil }
	payload := t.TempDir()
	installer := filepath.Join(payload, "install-enterprise.ps1")
	source := filepath.Join(payload, managed.StandaloneWindowsScannerRuntimeName)
	for _, path := range []string{installer, source} {
		if err := os.WriteFile(path, []byte("unsigned "+filepath.Base(path)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	digest, err := windowsEnterpriseFileSHA256(source)
	if err != nil {
		t.Fatal(err)
	}
	setWindowsScannerRuntimeDeploymentTest(t, func() winpath.EnterpriseDeployment {
		return winpath.EnterpriseDeployment{State: winpath.EnterpriseDeploymentInstalled, ProductVersion: "1.0.0"}
	})
	for _, opts := range []*windowsEnterpriseLifecycleOptions{
		{resolvedInstaller: installer, trustMode: windowsEnterpriseTrustAuthenticode, productVersion: "1.0.0"},
		{resolvedInstaller: installer, trustMode: windowsEnterpriseTrustHashPinned, productVersion: "1.0.0",
			payloadPins: map[string]string{managed.StandaloneWindowsScannerRuntimeName: strings.Repeat("0", 64)}},
	} {
		result := enterprisestatus.New("ensure", managed.ProfileStandalone, "windows", "1.0.0")
		applyWindowsStandaloneScannerRuntime(result, opts)
		_, statErr := os.Lstat(filepath.Join(root, managed.StandaloneWindowsScannerRuntimeName))
		// GAP-1063: the run fails, naming the repair, instead of ok=true
		// with a warning while every install stays blocked.
		if !errors.Is(statErr, os.ErrNotExist) || len(result.Errors) != 1 || result.Errors[0].Code != "scanner_runtime_unavailable" ||
			!strings.Contains(result.Errors[0].Message, "not admitted by the standalone payload trust policy") ||
			!strings.Contains(result.Errors[0].Message, "/repair JSON=1 as LocalSystem") {
			t.Fatalf("trust mode %s: installed=%v, errors %+v", opts.trustMode, statErr == nil, result.Errors)
		}
	}
	pinned := &windowsEnterpriseLifecycleOptions{trustMode: windowsEnterpriseTrustHashPinned,
		payloadPins: map[string]string{managed.StandaloneWindowsScannerRuntimeName: digest}}
	if _, err := admitWindowsScannerRuntimePayload(source, digest, pinned); err != nil {
		t.Fatalf("a pinned digest was refused: %v", err)
	}
}

// GAP-0297: a prepare the deadline killed says it timed out, instead of the
// bare "exit status 1" Windows reports for a killed process.
func TestWindowsScannerRuntimeTimeoutIsNamed(t *testing.T) {
	if os.Getenv("DC_SCANNER_RUNTIME_HELPER") == "sleep" {
		time.Sleep(30 * time.Second)
		return
	}
	seam, progressSeam, heartbeatSeam := windowsScannerPrepareTimeout, windowsScannerProgress, windowsScannerHeartbeat
	t.Cleanup(func() {
		windowsScannerPrepareTimeout, windowsScannerProgress, windowsScannerHeartbeat = seam, progressSeam, heartbeatSeam
	})
	windowsScannerPrepareTimeout = 500 * time.Millisecond
	// GAP-0642: the wait reports itself while it runs.
	var progress bytes.Buffer
	windowsScannerProgress, windowsScannerHeartbeat = &progress, 100*time.Millisecond
	t.Setenv("DC_SCANNER_RUNTIME_HELPER", "sleep")
	err := runWindowsScannerRuntime(os.Args[0], "-test.run=^TestWindowsScannerRuntimeTimeoutIsNamed$")
	if err == nil || !strings.Contains(err.Error(), "timed out after 500ms") {
		t.Fatalf("err = %v, want it to name the timeout", err)
	}
	if !strings.Contains(progress.String(), "is still running") || !strings.Contains(progress.String(), "stopped after 500ms") {
		t.Fatalf("progress = %q, want the elapsed time and the bound while it waits", progress.String())
	}
}

// GAP-1069: scanner runtime progress never reaches stderr, which Intune
// reads as a failed platform script: a person gets it on stdout, and a JSON
// run keeps each line for the lifecycle log.
func TestWindowsScannerProgressStaysOffStderr(t *testing.T) {
	if windowsScannerProgress != io.Writer(os.Stdout) {
		t.Fatalf("scanner progress goes to %T, want standard output", windowsScannerProgress)
	}
	opts := &windowsEnterpriseLifecycleOptions{jsonOutput: true}
	sink := &windowsScannerDiagnostics{opts: opts}
	fmt.Fprintf(sink, "[scanners] preparing the scanner runtime\n[scanners] prepare is still")
	fmt.Fprintf(sink, " running\n")
	if len(opts.diagnostics) != 2 || opts.diagnostics[1] != "[scanners] prepare is still running" {
		t.Fatalf("diagnostics = %q, want both progress lines", opts.diagnostics)
	}
}

// A timed-out prepare must end the Python worker that inherited its streams.
func TestWindowsScannerRuntimeTimeoutStopsWorker(t *testing.T) {
	switch os.Getenv("DC_PREPARE_CANCEL_ROLE") {
	case "child":
		time.Sleep(10 * time.Second)
		return
	case "parent":
		child := exec.Command(os.Args[0], "-test.run=^TestWindowsScannerRuntimeTimeoutStopsWorker$")
		child.Env = append(os.Environ(), "DC_PREPARE_CANCEL_ROLE=child")
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if err := child.Start(); err != nil {
			os.Exit(20)
		}
		if err := testenv.PublishFile(os.Getenv("DC_PREPARE_CHILD_MARKER"), []byte("ready")); err != nil {
			os.Exit(21)
		}
		time.Sleep(10 * time.Second)
		return
	}
	dir := t.TempDir()
	wrapper := filepath.Join(dir, "prepare.cmd")
	script := fmt.Sprintf("@echo off\r\n\"%s\" -test.run=^TestWindowsScannerRuntimeTimeoutStopsWorker$\r\n", os.Args[0])
	if err := os.WriteFile(wrapper, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "child.ready")
	t.Setenv("DC_PREPARE_CANCEL_ROLE", "parent")
	t.Setenv("DC_PREPARE_CHILD_MARKER", marker)
	originalTimeout, originalProgress := windowsScannerPrepareTimeout, windowsScannerProgress
	t.Cleanup(func() { windowsScannerPrepareTimeout, windowsScannerProgress = originalTimeout, originalProgress })
	windowsScannerPrepareTimeout = 2 * time.Second
	windowsScannerProgress = io.Discard
	start := time.Now()
	err := runWindowsScannerRuntime(wrapper, "prepare")
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("prepare error = %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("prepare kept waiting for its Python worker")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("prepare helper did not launch worker: %v", err)
	}
}

// GAP-0311: an installed scanner executable replaced in place (an
// administrator copied another program over it) is not run by status,
// verify, or a repair or ensure from the installed CLI: they report it, and
// only the copy the payload trust policy admitted runs again.
func TestWindowsScannerRuntimeChangedInPlaceIsNotRun(t *testing.T) {
	dirSeam, aclSeam := windowsScannerRuntimeDir, windowsScannerRuntimeACLCheck
	t.Cleanup(func() { windowsScannerRuntimeDir, windowsScannerRuntimeACLCheck = dirSeam, aclSeam })
	root := t.TempDir()
	windowsScannerRuntimeDir = func() (string, error) { return root, nil }
	windowsScannerRuntimeACLCheck = func(string, string) error { return nil }
	target := filepath.Join(root, managed.StandaloneWindowsScannerRuntimeName)
	if err := os.WriteFile(target, []byte("admitted runtime"), 0o755); err != nil {
		t.Fatal(err)
	}
	admitted, err := windowsEnterpriseFileSHA256(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := managed.WriteScannerRuntimeAdmission(root, admitted, managed.ScannerRuntimeTrustAuthenticode); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("another program"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"verify", "repair"} {
		result := enterprisestatus.New(action, managed.ProfileStandalone, "windows", "1.0.0")
		result.Installed = true
		applyWindowsStandaloneScannerRuntime(result, &windowsEnterpriseLifecycleOptions{})
		messages := append(append([]enterprisestatus.Message{}, result.Errors...), result.Warnings...)
		if result.Scanners == nil || result.Scanners.State != "untrusted" ||
			!strings.Contains(fmt.Sprint(messages), "scanner_runtime_unavailable") ||
			strings.Contains(fmt.Sprint(messages), "prepare the scanner runtime") {
			t.Fatalf("%s ran or accepted a changed runtime: scanners=%+v messages=%+v", action, result.Scanners, messages)
		}
	}
	if err := os.WriteFile(target, []byte("admitted runtime"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := readWindowsScannerRuntime(); got.State != "not_prepared" {
		t.Fatalf("the admitted runtime state = %q, want it run (not_prepared: this one cannot report versions)", got.State)
	}
}

// newWindowsScannerRuntimeRemovalTest points the scanner step at a runtime
// root with a file in it; removal needs no elevation.
func newWindowsScannerRuntimeRemovalTest(t *testing.T) (root, runtimeFile string) {
	t.Helper()
	seam := windowsScannerRuntimeDir
	t.Cleanup(func() { windowsScannerRuntimeDir = seam })
	root = filepath.Join(t.TempDir(), "DefenseClaw-ScannerRuntime")
	windowsScannerRuntimeDir = func() (string, error) { return root, nil }
	runtimeFile = filepath.Join(root, managed.StandaloneWindowsScannerRuntimeName)
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runtimeFile, []byte("runtime"), 0o600); err != nil {
		t.Fatal(err)
	}
	return root, runtimeFile
}

// GAP-1166 review: an uninstall whose scanner step runs after a later
// install keeps that install's runtime, and one that cannot read the
// deployment record keeps it too; the runtime goes only while no deployment
// is installed, its lock with it. Before, the step removed the folder
// whatever was installed.
func TestWindowsScannerRuntimeUninstallKeepsALaterInstallsRuntime(t *testing.T) {
	root, runtimeFile := newWindowsScannerRuntimeRemovalTest(t)
	seam := windowsScannerRuntimeDeployment
	t.Cleanup(func() { windowsScannerRuntimeDeployment = seam })
	for _, tc := range []struct {
		name   string
		record winpath.EnterpriseDeployment
		err    error
		kept   string
	}{
		{name: "a later install", record: winpath.EnterpriseDeployment{State: winpath.EnterpriseDeploymentInstalled, ProductVersion: "1.0.4"}, kept: "was kept: a later lifecycle run installed DefenseClaw 1.0.4"},
		{name: "an unreadable record", record: winpath.EnterpriseDeployment{State: winpath.EnterpriseDeploymentUnknown}, kept: "could not be removed"},
		{name: "a record that cannot be inspected", err: errors.New("access denied"), kept: "could not be removed"},
	} {
		record, recordErr := tc.record, tc.err
		windowsScannerRuntimeDeployment = func(*windowsEnterpriseLifecycleOptions) (winpath.EnterpriseDeployment, error) {
			return record, recordErr
		}
		result := enterprisestatus.New("uninstall", managed.ProfileStandalone, "windows", "1.0.4")
		applyWindowsStandaloneScannerRuntime(result, &windowsEnterpriseLifecycleOptions{productVersion: "1.0.4"})
		if _, err := os.Stat(runtimeFile); err != nil {
			t.Fatalf("%s: the uninstall removed the runtime: %v", tc.name, err)
		}
		if !windowsEnterpriseResultHasWarning(result, "scanner_runtime_left") || !strings.Contains(fmt.Sprint(result.Warnings), tc.kept) {
			t.Fatalf("%s: warnings %+v, want scanner_runtime_left saying %q", tc.name, result.Warnings, tc.kept)
		}
	}
	for _, state := range []winpath.EnterpriseDeploymentState{winpath.EnterpriseDeploymentTombstone, winpath.EnterpriseDeploymentAbsent} {
		if err := os.MkdirAll(root, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(runtimeFile, []byte("runtime"), 0o600); err != nil {
			t.Fatal(err)
		}
		record := winpath.EnterpriseDeployment{State: state}
		windowsScannerRuntimeDeployment = func(*windowsEnterpriseLifecycleOptions) (winpath.EnterpriseDeployment, error) {
			return record, nil
		}
		result := enterprisestatus.New("uninstall", managed.ProfileStandalone, "windows", "1.0.4")
		applyWindowsStandaloneScannerRuntime(result, &windowsEnterpriseLifecycleOptions{productVersion: "1.0.4"})
		if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) || len(result.Warnings) != 0 {
			t.Fatalf("%s: the runtime folder stays (%v) or warned %+v", state, err, result.Warnings)
		}
	}
}

// GAP-1166 review: the uninstall step waits for a scanner step that holds
// the scanner runtime lock, and removes the runtime only after it.
func TestWindowsScannerRuntimeRemovalWaitsForAScannerStep(t *testing.T) {
	root, runtimeFile := newWindowsScannerRuntimeRemovalTest(t)
	seam := windowsScannerRuntimeDeployment
	t.Cleanup(func() { windowsScannerRuntimeDeployment = seam })
	windowsScannerRuntimeDeployment = func(*windowsEnterpriseLifecycleOptions) (winpath.EnterpriseDeployment, error) {
		return winpath.EnterpriseDeployment{State: winpath.EnterpriseDeploymentTombstone}, nil
	}
	release, err := lockWindowsScannerRuntime(root)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := retireWindowsScannerRuntime(&windowsEnterpriseLifecycleOptions{})
		done <- err
	}()
	select {
	case err := <-done:
		release()
		t.Fatalf("the removal did not wait for the scanner step that holds the lock: %v", err)
	case <-time.After(750 * time.Millisecond):
	}
	if _, err := os.Stat(runtimeFile); err != nil {
		release()
		t.Fatalf("the removal changed the runtime while a scanner step held the lock: %v", err)
	}
	release()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the removal did not finish after the lock was released")
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the runtime folder stays after the removal: %v", err)
	}
}

// GAP-1166 review: a repair from the installed CLI (no payload) does not
// prepare a runtime whose deployment a later run uninstalled.
func TestWindowsScannerRuntimeRepreparesOnlyItsOwnDeployment(t *testing.T) {
	root, _ := newWindowsScannerRuntimeRemovalTest(t)
	readerSeam, deploymentSeam := windowsScannerRuntimeReader, windowsScannerRuntimeDeployment
	t.Cleanup(func() { windowsScannerRuntimeReader, windowsScannerRuntimeDeployment = readerSeam, deploymentSeam })
	windowsScannerRuntimeReader = func() *enterprisestatus.ScannerRuntime {
		return &enterprisestatus.ScannerRuntime{State: "not_prepared"}
	}
	windowsScannerRuntimeDeployment = func(*windowsEnterpriseLifecycleOptions) (winpath.EnterpriseDeployment, error) {
		return winpath.EnterpriseDeployment{State: winpath.EnterpriseDeploymentTombstone}, nil
	}
	result := enterprisestatus.New("repair", managed.ProfileStandalone, "windows", "1.0.4")
	result.Installed = true
	applyWindowsStandaloneScannerRuntime(result, &windowsEnterpriseLifecycleOptions{productVersion: "1.0.4"})
	if len(result.Errors) != 0 || !windowsEnterpriseResultHasWarning(result, "scanner_runtime_superseded") {
		t.Fatalf("errors %+v warnings %+v, want only scanner_runtime_superseded", result.Errors, result.Warnings)
	}
	if _, err := os.Stat(root); err != nil {
		t.Fatal(err)
	}
}

// Review loop round 3: a certification-scope run leaves the scanner runtime
// alone. The folder, its admission record and its gateway ACL are the
// production deployment's, while the run reads and writes its own
// deployment record. No scope option, action or record state lets it
// install, admit, prepare, prune or remove anything there, or report that
// runtime as its own. Before, a certification install over a production one
// published its (possibly unsigned) scanner and admission record, and a
// certification uninstall removed the folder while production stayed
// installed. The production control at the end shows the fixture is
// removable.
func TestWindowsScannerRuntimeCertificationScopeLeavesTheProductionRuntime(t *testing.T) {
	root, _ := newWindowsScannerRuntimeRemovalTest(t)
	if err := os.WriteFile(filepath.Join(root, "admitted-scanner.json"), []byte(`{"sha256":"production"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot := func() map[string]string {
		files := map[string]string{}
		_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return err
			}
			raw, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			files[path] = string(raw)
			return nil
		})
		return files
	}
	want := snapshot()
	payload := t.TempDir()
	installer := filepath.Join(payload, "install-enterprise.ps1")
	source := filepath.Join(payload, managed.StandaloneWindowsScannerRuntimeName)
	for _, path := range []string{installer, source} {
		if err := os.WriteFile(path, []byte("unsigned "+filepath.Base(path)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	readerSeam, deploymentSeam, sourceSeam := windowsScannerRuntimeReader, windowsScannerRuntimeDeployment, windowsScannerSourceCheck
	t.Cleanup(func() {
		windowsScannerRuntimeReader, windowsScannerRuntimeDeployment, windowsScannerSourceCheck = readerSeam, deploymentSeam, sourceSeam
	})
	reads := 0
	windowsScannerRuntimeReader = func() *enterprisestatus.ScannerRuntime {
		reads++
		return &enterprisestatus.ScannerRuntime{State: "not_prepared"}
	}
	windowsScannerSourceCheck = func(string, string) error { return nil }
	// Each scope's own record: installed for the mutations (the old step
	// then published into the shared folder), gone after its uninstall (the
	// old step then removed the shared folder).
	recordReads := 0
	recordState := winpath.EnterpriseDeploymentInstalled
	windowsScannerRuntimeDeployment = func(*windowsEnterpriseLifecycleOptions) (winpath.EnterpriseDeployment, error) {
		recordReads++
		return winpath.EnterpriseDeployment{State: recordState, ProductVersion: "1.0.4"}, nil
	}
	scopes := map[string]func(*windowsEnterpriseLifecycleOptions){
		"state root": func(o *windowsEnterpriseLifecycleOptions) {
			o.stateRoot = `C:\ProgramData\Cisco\DefenseClaw-Cert\run1\state`
		},
		"install root": func(o *windowsEnterpriseLifecycleOptions) {
			o.installRoot = `C:\Program Files\Cisco\DefenseClaw-Cert\run1\install`
		},
		"gateway service name": func(o *windowsEnterpriseLifecycleOptions) { o.gatewayServiceName = "DefenseClawGatewayCert1" },
		"guardian service":     func(o *windowsEnterpriseLifecycleOptions) { o.guardianServiceName = "DefenseClawGuardianCert1" },
		"unsigned certification": func(o *windowsEnterpriseLifecycleOptions) {
			o.allowUnsigned, o.certificationCodexHome = true, `C:\dc-cert\codex-home`
		},
	}
	for name, scope := range scopes {
		for _, tc := range []struct {
			action    string
			installer string
			record    winpath.EnterpriseDeploymentState
		}{
			{"install", installer, winpath.EnterpriseDeploymentInstalled},
			{"upgrade", installer, winpath.EnterpriseDeploymentInstalled},
			{"repair", installer, winpath.EnterpriseDeploymentInstalled},
			{"ensure", installer, winpath.EnterpriseDeploymentInstalled},
			// From the installed CLI: no payload, so the old step prepared
			// the shared runtime again.
			{"repair", "", winpath.EnterpriseDeploymentInstalled},
			{"ensure", "", winpath.EnterpriseDeploymentInstalled},
			{"uninstall", installer, winpath.EnterpriseDeploymentTombstone},
			{"uninstall", "", winpath.EnterpriseDeploymentAbsent},
			{"status", "", winpath.EnterpriseDeploymentInstalled},
			{"verify", "", winpath.EnterpriseDeploymentInstalled},
		} {
			label := name + " " + tc.action
			if tc.installer == "" {
				label += " (installed CLI)"
			}
			recordState, recordReads, reads = tc.record, 0, 0
			opts := &windowsEnterpriseLifecycleOptions{resolvedInstaller: tc.installer, productVersion: "1.0.4",
				trustMode:   windowsEnterpriseTrustHashPinned,
				payloadPins: map[string]string{managed.StandaloneWindowsScannerRuntimeName: strings.Repeat("0", 64)}}
			scope(opts)
			result := enterprisestatus.New(tc.action, managed.ProfileStandalone, "windows", "1.0.4")
			result.Installed = tc.action != "uninstall"
			applyWindowsStandaloneScannerRuntime(result, opts)
			if got := snapshot(); fmt.Sprint(got) != fmt.Sprint(want) {
				t.Fatalf("%s changed the production scanner runtime: %v, want %v", label, got, want)
			}
			if recordReads != 0 || reads != 0 || result.Scanners != nil {
				t.Fatalf("%s read the shared runtime as its own: %d record reads, %d runtime reads, scanners %+v", label, recordReads, reads, result.Scanners)
			}
			if len(result.Errors) != 0 || !windowsEnterpriseResultHasWarning(result, "scanner_runtime_not_scoped") {
				t.Fatalf("%s: errors %+v warnings %+v, want only scanner_runtime_not_scoped", label, result.Errors, result.Warnings)
			}
		}
	}
	// Control: the production uninstall of the same fixture removes it.
	recordState = winpath.EnterpriseDeploymentTombstone
	result := enterprisestatus.New("uninstall", managed.ProfileStandalone, "windows", "1.0.4")
	applyWindowsStandaloneScannerRuntime(result, &windowsEnterpriseLifecycleOptions{productVersion: "1.0.4"})
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) || len(result.Warnings) != 0 {
		t.Fatalf("the production uninstall kept the runtime folder (%v) or warned %+v", err, result.Warnings)
	}
}
