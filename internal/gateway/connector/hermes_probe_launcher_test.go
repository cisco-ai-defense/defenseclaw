// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// answerHermesProbeForTest gives a Windows per-user Hermes registration a
// launcher that answers Verify's execution probe: the packaged launcher the
// command names is pinned to a copy of this test binary, which TestMain turns
// into the probe's answer (testHermesProbeLauncherEnv). Unix Hermes runs the
// data-dir script Setup writes, so there is nothing to pin. It returns the
// launcher, "" on Unix.
func answerHermesProbeForTest(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		return ""
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	image, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	launcher := filepath.Join(testenv.PrivateTempDir(t), "bin", windowsHookBinaryName)
	if err := os.MkdirAll(filepath.Dir(launcher), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(launcher, image, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(PinNativeHookExecutableForTest(launcher))
	t.Setenv(testHermesProbeLauncherEnv, "1")
	return launcher
}
