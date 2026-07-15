// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/hookruntime"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"golang.org/x/sys/windows"
)

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
