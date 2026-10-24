// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// hermesPerUserProbeFixture is a per-user Windows install: SetupOpts carries
// no HookExecutable and the packaged launcher (answerHermesProbeForTest) is
// the one hookInvocationCommandFor registers.
func hermesPerUserProbeFixture(t *testing.T) (*hookOnlyConnector, SetupOpts, string) {
	t.Helper()
	root := testenv.PrivateTempDir(t)
	previous := HermesConfigPathOverride
	HermesConfigPathOverride = filepath.Join(root, "hermes-home", "config.yaml")
	t.Cleanup(func() { HermesConfigPathOverride = previous })
	launcher := answerHermesProbeForTest(t)
	opts := prepareHermesSetupAdmissionFixture(t, SetupOpts{
		DataDir:  filepath.Join(root, ".defenseclaw"),
		APIAddr:  "127.0.0.1:18970",
		APIToken: "tok-test",
	})
	conn := NewHermesConnector()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	return conn, opts, launcher
}

// GAP-0837: a per-user Windows install leaves HookExecutable empty, and
// Verify probed the whole registered command line as a file path, so every
// Hermes Setup and every upgrade with Hermes failed and rolled back.
func TestHermesPerUserWindowsVerifyProbesThePackagedLauncher(t *testing.T) {
	conn, opts, launcher := hermesPerUserProbeFixture(t)
	if got, want := conn.hookCommand(opts), windowsHermesDirectHookCommand(launcher); got != want {
		t.Fatalf("registered command = %q, want %q", got, want)
	}
	if present, err := OwnedHooksPresent(conn, opts); err != nil || !present {
		t.Fatalf("OwnedHooksPresent after per-user Setup = %v, %v; want present", present, err)
	}
	// Setup's own command is what an upgraded 1.0.2 registration holds; a
	// second Setup (the new gateway's boot) keeps it verified.
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("second Setup: %v", err)
	}
	if present, err := OwnedHooksPresent(conn, opts); err != nil || !present {
		t.Fatalf("OwnedHooksPresent after the second Setup = %v, %v; want present", present, err)
	}
}

// The probe still runs only the launcher the registration names, and only one
// that answers as the active hook runtime.
func TestHermesPerUserWindowsVerifyRefusesALauncherThatDoesNotAnswer(t *testing.T) {
	for name, mutate := range map[string]func(t *testing.T, launcher string){
		"launcher no longer answers": func(t *testing.T, _ string) {
			t.Setenv(testHermesProbeLauncherEnv, "silent")
		},
		"launcher replaced by a non-executable image": func(t *testing.T, launcher string) {
			if err := os.WriteFile(launcher, []byte("MZ not an image"), 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"launcher removed": func(t *testing.T, launcher string) {
			if err := os.Remove(launcher); err != nil {
				t.Fatal(err)
			}
		},
		"another launcher than the registered one": func(t *testing.T, launcher string) {
			t.Cleanup(PinNativeHookExecutableForTest(filepath.Join(filepath.Dir(launcher), "other", windowsHookBinaryName)))
		},
	} {
		t.Run(name, func(t *testing.T) {
			conn, opts, launcher := hermesPerUserProbeFixture(t)
			mutate(t, launcher)
			if present, err := OwnedHooksPresent(conn, opts); err != nil || present {
				t.Fatalf("OwnedHooksPresent = %v, %v; want absent", present, err)
			}
		})
	}
}
