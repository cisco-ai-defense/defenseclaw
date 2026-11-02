// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/cli"
)

const preMainHelperEnv = "DEFENSECLAW_HOOK_PREMAIN_HELPER"

// TestPreMainHelper is the child process of TestHookBinaryInitWritesNothingToStderr
// and, in panic mode, of TestRecoverHookPanicReplacesStackDump.
func TestPreMainHelper(t *testing.T) {
	switch os.Getenv(preMainHelperEnv) {
	case "1":
	case "panic":
		defer cli.RecoverHookPanic()
		panic("hook-panic-marker")
	default:
		t.Skip("helper process only")
	}
}

// A recovered hook panic exits 2 with one line instead of Go's stack dump.
func TestRecoverHookPanicReplacesStackDump(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestPreMainHelper$")
	cmd.Env = append(os.Environ(), preMainHelperEnv+"=panic")
	var stderr bytes.Buffer
	cmd.Stdout = &bytes.Buffer{}
	cmd.Stderr = &stderr
	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 2 {
		t.Fatalf("helper exit = %v, want 2 (stderr %q)", err, stderr.String())
	}
	if got := stderr.String(); strings.Contains(got, "goroutine") || strings.Count(got, "\n") != 1 ||
		!strings.Contains(got, "hook-panic-marker") {
		t.Fatalf("stderr = %q, want one internal-error line", got)
	}
}

// Package initialization of everything the hook links must not read the
// provider overlay: a malformed overlay (or an override from the agent's
// environment) would otherwise print to stderr before main runs, and agents
// show hook stderr to the user.
func TestHookBinaryInitWritesNothingToStderr(t *testing.T) {
	overlay := filepath.Join(t.TempDir(), "custom-providers.json")
	if err := os.WriteFile(overlay, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestPreMainHelper$")
	cmd.Env = append(os.Environ(),
		preMainHelperEnv+"=1",
		"DEFENSECLAW_CUSTOM_PROVIDERS_PATH="+overlay,
	)
	var stderr bytes.Buffer
	cmd.Stdout = &bytes.Buffer{}
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("helper process: %v (stderr %q)", err, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("hook binary wrote to stderr during init: %q", stderr.String())
	}
}
