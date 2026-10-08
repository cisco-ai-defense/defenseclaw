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
	for _, action := range []string{"verify", "status", "repair"} {
		result := enterprisestatus.New(action, managed.ProfileStandalone, "windows", "1.0.0")
		result.Installed = true
		applyWindowsStandaloneScannerRuntime(result, &windowsEnterpriseLifecycleOptions{})
		messages := result.Warnings
		if action == "verify" {
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
	// verify too; before, verify said ok while every rescan failed.
	readerSeam, checkSeam := windowsScannerRuntimeReader, windowsScannerRuntimeServiceCheck
	t.Cleanup(func() { windowsScannerRuntimeReader, windowsScannerRuntimeServiceCheck = readerSeam, checkSeam })
	windowsScannerRuntimeReader = func() *enterprisestatus.ScannerRuntime {
		return &enterprisestatus.ScannerRuntime{State: "ready", JudgeModel: "judge"}
	}
	windowsScannerRuntimeServiceCheck = func() error { return errors.New("the gateway service account cannot read it") }
	result := enterprisestatus.New("verify", managed.ProfileStandalone, "windows", "1.0.0")
	result.Installed = true
	applyWindowsStandaloneScannerRuntime(result, &windowsEnterpriseLifecycleOptions{})
	if len(result.Errors) != 1 || result.Errors[0].Code != "scanner_runtime_unavailable" ||
		!strings.Contains(result.Errors[0].Message, "cannot read it") {
		t.Fatalf("a runtime the gateway cannot run: errors=%+v", result.Errors)
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
	if got := readWindowsScannerRuntime(); got.State != "missing" {
		t.Fatalf("writable scanner runtime state = %q, want missing", got.State)
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
	for _, opts := range []*windowsEnterpriseLifecycleOptions{
		{resolvedInstaller: installer, trustMode: windowsEnterpriseTrustAuthenticode},
		{resolvedInstaller: installer, trustMode: windowsEnterpriseTrustHashPinned,
			payloadPins: map[string]string{managed.StandaloneWindowsScannerRuntimeName: strings.Repeat("0", 64)}},
	} {
		result := enterprisestatus.New("ensure", managed.ProfileStandalone, "windows", "1.0.0")
		applyWindowsStandaloneScannerRuntime(result, opts)
		_, statErr := os.Lstat(filepath.Join(root, managed.StandaloneWindowsScannerRuntimeName))
		if !errors.Is(statErr, os.ErrNotExist) || !strings.Contains(fmt.Sprint(result.Warnings), "not admitted by the standalone payload trust policy") {
			t.Fatalf("trust mode %s: installed=%v, warnings %+v", opts.trustMode, statErr == nil, result.Warnings)
		}
	}
	pinned := &windowsEnterpriseLifecycleOptions{trustMode: windowsEnterpriseTrustHashPinned,
		payloadPins: map[string]string{managed.StandaloneWindowsScannerRuntimeName: digest}}
	if err := admitWindowsScannerRuntimePayload(source, digest, pinned); err != nil {
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
	if err := managed.WriteScannerRuntimeAdmission(root, admitted); err != nil {
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
