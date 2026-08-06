// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/hookruntime"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"golang.org/x/sys/windows"
)

type recoveryRoundTripper struct {
	requests int
}

func (transport *recoveryRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	transport.requests++
	if transport.requests == 1 {
		return nil, syscall.ECONNREFUSED
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body: io.NopCloser(strings.NewReader(
			`{"action":"allow","hook_output":{}}`,
		)),
		Header: make(http.Header),
	}, nil
}

func TestTrustedGatewayStartCommandIsExactBoundAndWindowless(t *testing.T) {
	dataRoot := filepath.Join(t.TempDir(), "managed data")
	state := hookruntime.State{
		GatewayPath: filepath.Join(t.TempDir(), hookruntime.GatewayName),
		DataRoot:    dataRoot,
	}
	t.Setenv("DEFENSECLAW_HOME", `C:\project-controlled`)
	t.Setenv("DEFENSECLAW_CONFIG", `C:\project-controlled\config.yaml`)
	t.Setenv("OPENCLAW_GATEWAY_TOKEN", "project-token")
	t.Setenv("PYTHONPATH", `C:\project-controlled\python`)

	cmd := newTrustedNativeGatewayStartCommand(context.Background(), state)
	if cmd.Path != state.GatewayPath || len(cmd.Args) != 2 || cmd.Args[0] != state.GatewayPath || cmd.Args[1] != "start" {
		t.Fatalf("gateway start argv = %q, want exact recorded executable plus start", cmd.Args)
	}
	if cmd.Dir != dataRoot {
		t.Fatalf("gateway start directory = %q, want %q", cmd.Dir, dataRoot)
	}
	joined := strings.Join(cmd.Env, "\n")
	for _, forbidden := range []string{
		`DEFENSECLAW_CONFIG=C:\project-controlled\config.yaml`,
		"OPENCLAW_GATEWAY_TOKEN=project-token",
		`PYTHONPATH=C:\project-controlled\python`,
	} {
		if strings.Contains(strings.ToUpper(joined), strings.ToUpper(forbidden)) {
			t.Fatalf("project-controlled environment survived gateway start sanitization: %q", forbidden)
		}
	}
	if !strings.Contains(joined, "DEFENSECLAW_HOME="+dataRoot) {
		t.Fatalf("recorded DEFENSECLAW_HOME missing from gateway environment: %s", joined)
	}
	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.HideWindow ||
		cmd.SysProcAttr.CreationFlags&windows.CREATE_NO_WINDOW == 0 {
		t.Fatalf("gateway start command can allocate a console: %+v", cmd.SysProcAttr)
	}
}

func TestTrustedNativeGatewayRecoveryReusesPreparedHookRuntimeAdmission(t *testing.T) {
	executable := filepath.Join(t.TempDir(), hookruntime.LauncherName)
	previousExecutable := hookExecutableOverride
	hookExecutableOverride = executable
	t.Cleanup(func() { hookExecutableOverride = previousExecutable })

	state := hookruntime.State{
		SchemaVersion:  hookruntime.SchemaVersion,
		Status:         hookruntime.StatusActive,
		DataRoot:       filepath.Clean(t.TempDir()),
		GatewayPath:    filepath.Join(t.TempDir(), hookruntime.GatewayName),
		GatewaySHA256:  strings.Repeat("a", 64),
		LauncherPath:   executable,
		LauncherSHA256: strings.Repeat("b", 64),
	}
	delegatedReads := 0
	fullImageReads := 0
	stubNativeDelegatedHookRuntimeReader(t, func(gotExecutable string) (hookruntime.State, bool, error) {
		delegatedReads++
		if gotExecutable != executable {
			t.Fatalf("delegated runtime reader executable = %q, want %q", gotExecutable, executable)
		}
		return state, true, nil
	})
	stubNativeHookRuntimeReader(t, func(gotExecutable string) (hookruntime.State, bool, error) {
		fullImageReads++
		if gotExecutable != executable {
			t.Fatalf("runtime reader executable = %q, want %q", gotExecutable, executable)
		}
		return state, true, nil
	})

	if NativeHookRuntimeNoop() {
		t.Fatal("trusted active hook runtime was classified as a no-op")
	}
	if recovery := trustedNativeGatewayRecovery(); recovery == nil {
		t.Fatal("prepared cold-start-capable runtime did not install recovery")
	}
	if delegatedReads != 1 || fullImageReads != 0 {
		t.Fatalf(
			"runtime admission reads = delegated %d, full-image %d; want one parent-bound read and no second full hash",
			delegatedReads,
			fullImageReads,
		)
	}
}

func TestTrustedNativeGatewayRecoveryRefreshesDelegatedGenerationWithoutFullImageRead(t *testing.T) {
	executable := filepath.Join(t.TempDir(), hookruntime.LauncherName)
	stableLauncher := filepath.Join(t.TempDir(), hookruntime.LauncherName)
	previousExecutable := hookExecutableOverride
	hookExecutableOverride = executable
	t.Cleanup(func() { hookExecutableOverride = previousExecutable })

	state := hookruntime.State{
		SchemaVersion:  hookruntime.SchemaVersion,
		Status:         hookruntime.StatusActive,
		RuntimeRoot:    filepath.Dir(stableLauncher),
		LauncherPath:   stableLauncher,
		LauncherSHA256: strings.Repeat("b", 64),
		LauncherKind:   hookruntime.LauncherKindTrampoline,
		HookPath:       executable,
		HookSHA256:     strings.Repeat("c", 64),
		DataRoot:       filepath.Clean(t.TempDir()),
		GatewayPath:    filepath.Join(t.TempDir(), hookruntime.GatewayName),
		GatewaySHA256:  strings.Repeat("a", 64),
		TransactionID:  strings.Repeat("d", 32),
	}
	stubNativeDelegatedHookRuntimeReader(t, func(string) (hookruntime.State, bool, error) {
		return state, true, nil
	})
	fullImageReads := 0
	stubNativeHookRuntimeReader(t, func(string) (hookruntime.State, bool, error) {
		fullImageReads++
		return state, true, nil
	})
	previousRevalidator := nativePreparedHookRuntimeRevalidator
	revalidations := 0
	nativePreparedHookRuntimeRevalidator = func(gotExecutable string, gotState hookruntime.State) (hookruntime.State, error) {
		revalidations++
		if gotExecutable != executable || gotState != state {
			t.Fatalf("generation refresh input = %q, %+v", gotExecutable, gotState)
		}
		return state, nil
	}
	t.Cleanup(func() { nativePreparedHookRuntimeRevalidator = previousRevalidator })

	if NativeHookRuntimeNoop() {
		t.Fatal("trusted delegated runtime was classified as a no-op")
	}
	got, recognized, err := refreshedNativeHookRuntimeForRecovery(executable)
	if err != nil || !recognized || got != state {
		t.Fatalf("generation refresh = %+v, recognized=%t, err=%v", got, recognized, err)
	}
	if revalidations != 1 || fullImageReads != 0 {
		t.Fatalf(
			"recovery reads = generation %d, full-image %d; want one exact-generation refresh and no full-image rehash",
			revalidations,
			fullImageReads,
		)
	}
}

func TestTrustedNativeGatewayRecoveryRejectsChangedDelegatedGenerationWithoutFallback(t *testing.T) {
	executable := filepath.Join(t.TempDir(), hookruntime.LauncherName)
	previousExecutable := hookExecutableOverride
	hookExecutableOverride = executable
	t.Cleanup(func() { hookExecutableOverride = previousExecutable })
	state := hookruntime.State{
		SchemaVersion:  hookruntime.SchemaVersion,
		Status:         hookruntime.StatusActive,
		RuntimeRoot:    filepath.Clean(t.TempDir()),
		LauncherPath:   filepath.Join(t.TempDir(), hookruntime.LauncherName),
		LauncherSHA256: strings.Repeat("b", 64),
		LauncherKind:   hookruntime.LauncherKindTrampoline,
		HookPath:       executable,
		HookSHA256:     strings.Repeat("c", 64),
		DataRoot:       filepath.Clean(t.TempDir()),
		GatewayPath:    filepath.Join(t.TempDir(), hookruntime.GatewayName),
		GatewaySHA256:  strings.Repeat("a", 64),
		TransactionID:  strings.Repeat("d", 32),
	}
	stubNativeDelegatedHookRuntimeReader(t, func(string) (hookruntime.State, bool, error) {
		return state, true, nil
	})
	fullImageReads := 0
	stubNativeHookRuntimeReader(t, func(string) (hookruntime.State, bool, error) {
		fullImageReads++
		return state, true, nil
	})
	previousRevalidator := nativePreparedHookRuntimeRevalidator
	nativePreparedHookRuntimeRevalidator = func(string, hookruntime.State) (hookruntime.State, error) {
		return hookruntime.State{}, errors.New("protected generation rotated")
	}
	t.Cleanup(func() { nativePreparedHookRuntimeRevalidator = previousRevalidator })
	previousLock := nativeGatewayStartLock
	nativeGatewayStartLock = func(_ context.Context, run func() error) error { return run() }
	t.Cleanup(func() { nativeGatewayStartLock = previousLock })
	previousRunner := nativeGatewayStartRunner
	starts := 0
	nativeGatewayStartRunner = func(context.Context, hookruntime.State) error {
		starts++
		return nil
	}
	t.Cleanup(func() { nativeGatewayStartRunner = previousRunner })

	if NativeHookRuntimeNoop() {
		t.Fatal("trusted delegated runtime was classified as a no-op")
	}
	recovery := trustedNativeGatewayRecovery()
	if recovery == nil {
		t.Fatal("prepared delegated runtime did not install recovery")
	}
	err := recovery(context.Background(), syscall.ECONNREFUSED)
	if err == nil || !strings.Contains(err.Error(), "rotated") {
		t.Fatalf("rotated generation recovery error=%v", err)
	}
	if fullImageReads != 0 || starts != 0 {
		t.Fatalf(
			"rotated prepared generation full-image reads=%d gateway starts=%d",
			fullImageReads,
			starts,
		)
	}
}

func TestCursorColdRequestUsesProductionRecoveryCallbackWithinNativeDeadline(t *testing.T) {
	executable := filepath.Join(t.TempDir(), hookruntime.LauncherName)
	previousExecutable := hookExecutableOverride
	hookExecutableOverride = executable
	t.Cleanup(func() { hookExecutableOverride = previousExecutable })
	state := hookruntime.State{
		SchemaVersion:  hookruntime.SchemaVersion,
		Status:         hookruntime.StatusActive,
		RuntimeRoot:    filepath.Clean(t.TempDir()),
		LauncherPath:   filepath.Join(t.TempDir(), hookruntime.LauncherName),
		LauncherSHA256: strings.Repeat("b", 64),
		LauncherKind:   hookruntime.LauncherKindTrampoline,
		HookPath:       executable,
		HookSHA256:     strings.Repeat("c", 64),
		DataRoot:       filepath.Clean(t.TempDir()),
		GatewayPath:    filepath.Join(t.TempDir(), hookruntime.GatewayName),
		GatewaySHA256:  strings.Repeat("a", 64),
		TransactionID:  strings.Repeat("d", 32),
	}
	stubNativeDelegatedHookRuntimeReader(t, func(string) (hookruntime.State, bool, error) {
		return state, true, nil
	})
	fullImageReads := 0
	stubNativeHookRuntimeReader(t, func(string) (hookruntime.State, bool, error) {
		fullImageReads++
		return state, true, nil
	})
	previousRevalidator := nativePreparedHookRuntimeRevalidator
	nativePreparedHookRuntimeRevalidator = func(string, hookruntime.State) (hookruntime.State, error) {
		return state, nil
	}
	t.Cleanup(func() { nativePreparedHookRuntimeRevalidator = previousRevalidator })
	previousLock := nativeGatewayStartLock
	locks := 0
	nativeGatewayStartLock = func(_ context.Context, run func() error) error {
		locks++
		return run()
	}
	t.Cleanup(func() { nativeGatewayStartLock = previousLock })
	previousRunner := nativeGatewayStartRunner
	starts := 0
	var recoveryBudget time.Duration
	nativeGatewayStartRunner = func(ctx context.Context, got hookruntime.State) error {
		starts++
		if got != state {
			t.Fatalf("cold-start state = %+v, want prepared generation", got)
		}
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("production recovery callback lost the hook deadline")
		}
		recoveryBudget = time.Until(deadline)
		return nil
	}
	t.Cleanup(func() { nativeGatewayStartRunner = previousRunner })
	if NativeHookRuntimeNoop() {
		t.Fatal("trusted delegated runtime was classified as a no-op")
	}
	recovery := trustedNativeGatewayRecovery()
	if recovery == nil {
		t.Fatal("prepared delegated runtime did not install recovery")
	}

	transport := &recoveryRoundTripper{}
	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	started := time.Now()
	code := hookexec.Run(ctx, hookexec.Options{
		Connector:       "cursor",
		Event:           "sessionStart",
		APIAddr:         "127.0.0.1:1",
		FailMode:        "open",
		Home:            state.DataRoot,
		HookDir:         filepath.Join(state.DataRoot, "hooks"),
		Token:           "test-token",
		Stdin:           strings.NewReader(`{"hook_event_name":"sessionStart"}`),
		Stdout:          &stdout,
		Stderr:          &stderr,
		HTTPClient:      &http.Client{Transport: transport},
		GatewayRecovery: recovery,
	})
	elapsed := time.Since(started)
	if code != 0 || strings.TrimSpace(stdout.String()) != "{}" || stderr.Len() != 0 {
		t.Fatalf("cold Cursor request code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if transport.requests != 2 || locks != 1 || starts != 1 || fullImageReads != 0 {
		t.Fatalf(
			"cold Cursor path requests=%d locks=%d starts=%d full-image=%d",
			transport.requests,
			locks,
			starts,
			fullImageReads,
		)
	}
	if recoveryBudget <= 0 || recoveryBudget > 10*time.Second || elapsed >= 30*time.Second {
		t.Fatalf("cold Cursor recovery budget=%s elapsed=%s", recoveryBudget, elapsed)
	}
	t.Logf(
		"cold Cursor recovery elapsed=%s budget=%s requests=%d locks=%d starts=%d full-image-reads=%d",
		elapsed,
		recoveryBudget,
		transport.requests,
		locks,
		starts,
		fullImageReads,
	)
}

func TestLegacyNativeGatewayRecoveryRetainsFullExecutableAdmission(t *testing.T) {
	executable := filepath.Join(t.TempDir(), hookruntime.LauncherName)
	previousExecutable := hookExecutableOverride
	hookExecutableOverride = executable
	t.Cleanup(func() { hookExecutableOverride = previousExecutable })
	state := hookruntime.State{
		SchemaVersion:  hookruntime.SchemaVersion,
		Status:         hookruntime.StatusActive,
		DataRoot:       filepath.Clean(t.TempDir()),
		GatewayPath:    filepath.Join(t.TempDir(), hookruntime.GatewayName),
		GatewaySHA256:  strings.Repeat("a", 64),
		LauncherPath:   executable,
		LauncherSHA256: strings.Repeat("b", 64),
	}
	stubNativeDelegatedHookRuntimeReader(t, func(string) (hookruntime.State, bool, error) {
		return state, true, nil
	})
	fullImageReads := 0
	stubNativeHookRuntimeReader(t, func(string) (hookruntime.State, bool, error) {
		fullImageReads++
		return state, true, nil
	})
	previousRevalidator := nativePreparedHookRuntimeRevalidator
	revalidations := 0
	nativePreparedHookRuntimeRevalidator = func(string, hookruntime.State) (hookruntime.State, error) {
		revalidations++
		return state, nil
	}
	t.Cleanup(func() { nativePreparedHookRuntimeRevalidator = previousRevalidator })

	if NativeHookRuntimeNoop() {
		t.Fatal("trusted legacy runtime was classified as a no-op")
	}
	got, recognized, err := refreshedNativeHookRuntimeForRecovery(executable)
	if err != nil || !recognized || got != state {
		t.Fatalf("legacy recovery admission = %+v, recognized=%t, err=%v", got, recognized, err)
	}
	if fullImageReads != 1 || revalidations != 0 {
		t.Fatalf("legacy recovery full-image=%d generation=%d", fullImageReads, revalidations)
	}
}

func TestTrustedGatewayStartRunsPinnedNativeExecutableAndHonorsDeadline(t *testing.T) {
	gateway := buildColdStartGatewayHelper(t)
	digest := testFileSHA256(t, gateway)

	t.Run("exact executable and recorded home", func(t *testing.T) {
		dataRoot := t.TempDir()
		state := testColdStartState(gateway, digest, dataRoot)
		t.Setenv("DEFENSECLAW_HOME", filepath.Join(t.TempDir(), "project-home"))
		t.Setenv("DEFENSECLAW_CONFIG", filepath.Join(t.TempDir(), "project-config.yaml"))
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := runTrustedNativeGatewayStart(ctx, state); err != nil {
			t.Fatal(err)
		}
		marker, err := os.ReadFile(filepath.Join(dataRoot, "cold-start-marker.txt"))
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.TrimSpace(string(marker)); got != dataRoot+"|" {
			t.Fatalf("helper observed home/config = %q, want recorded home and no project config", got)
		}
	})

	t.Run("deadline kills management process", func(t *testing.T) {
		dataRoot := t.TempDir()
		if err := os.WriteFile(filepath.Join(dataRoot, "sleep-before-ready"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		state := testColdStartState(gateway, digest, dataRoot)
		ctx, cancel := context.WithTimeout(context.Background(), 125*time.Millisecond)
		defer cancel()
		started := time.Now()
		err := runTrustedNativeGatewayStart(ctx, state)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("deadline start error = %v, want deadline exceeded", err)
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("gateway start ignored hook deadline: %s", elapsed)
		}
		if _, err := os.Stat(filepath.Join(dataRoot, "cold-start-marker.txt")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("deadline-expired helper reached ready marker: %v", err)
		}
	})
}

func TestTrustedGatewayStartRejectsDisabledAndForeignImageIdentity(t *testing.T) {
	gateway := buildColdStartGatewayHelper(t)
	dataRoot := t.TempDir()
	digest := testFileSHA256(t, gateway)

	disabled := testColdStartState(gateway, digest, dataRoot)
	disabled.Status = hookruntime.StatusDisabled
	disabled.GatewayPath = ""
	disabled.GatewaySHA256 = ""
	if err := runTrustedNativeGatewayStart(context.Background(), disabled); err == nil {
		t.Fatal("disabled/uninstalled state started a gateway")
	}

	foreign := testColdStartState(gateway, strings.Repeat("0", 64), dataRoot)
	if err := runTrustedNativeGatewayStart(context.Background(), foreign); err == nil {
		t.Fatal("gateway whose digest differs from installer state was executed")
	}
	if _, err := os.Stat(filepath.Join(dataRoot, "cold-start-marker.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected foreign gateway executed: %v", err)
	}
}

func buildColdStartGatewayHelper(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	source := filepath.Join(dir, "main.go")
	body := `package main
import (
 "os"
 "os/exec"
 "path/filepath"
 "time"
)
func main() {
 home := os.Getenv("DEFENSECLAW_HOME")
 if len(os.Args) == 2 && os.Args[1] == "daemon" {
  marker := []byte(home + "|" + os.Getenv("DEFENSECLAW_CONFIG"))
  if os.WriteFile(filepath.Join(home, "cold-start-marker.txt"), marker, 0600) != nil { os.Exit(8) }
  return
 }
 if len(os.Args) != 2 || os.Args[1] != "start" { os.Exit(7) }
 if _, err := os.Stat(filepath.Join(home, "sleep-before-ready")); err == nil {
  time.Sleep(5 * time.Second)
 }
 child := exec.Command(os.Args[0], "daemon")
 child.Env = os.Environ()
 if child.Run() != nil { os.Exit(9) }
}
`
	if err := os.WriteFile(source, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	gateway := filepath.Join(dir, hookruntime.GatewayName)
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w -H=windowsgui", "-o", gateway, source)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build native cold-start helper: %v: %s", err, output)
	}
	if err := safefile.ProtectFile(gateway); err != nil {
		t.Fatal(err)
	}
	return gateway
}

func testColdStartState(gateway, digest, dataRoot string) hookruntime.State {
	return hookruntime.State{
		SchemaVersion: hookruntime.SchemaVersion,
		Status:        hookruntime.StatusActive,
		DataRoot:      filepath.Clean(dataRoot),
		GatewayPath:   filepath.Clean(gateway),
		GatewaySHA256: digest,
	}
}

func testFileSHA256(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}
