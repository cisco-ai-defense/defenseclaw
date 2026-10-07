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
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestTetragonIntentFromTheDropIn(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	lookup := func(values map[string]string) func(string) (string, bool) {
		return func(name string) (string, bool) { v, ok := values[name]; return v, ok }
	}
	// No drop-in: the defaults.
	config := tetragonIntent(lookup(nil), logger)
	if config.Mode != "consume" || config.BurnIn != 168*time.Hour || config.EnforceAck != "" || config.EnforceConnectors != nil {
		t.Fatalf("defaults %+v", config)
	}
	config = tetragonIntent(lookup(map[string]string{
		envTetragonMode: "enforce", envTetragonBurnIn: "24h", envTetragonEnforceAck: "sha256:3f9c2a7d41b0",
		envTetragonEnforceConnectors: "claudecode, Codex,claudecode,,bad connector",
	}), logger)
	if config.Mode != "enforce" || config.BurnIn != 24*time.Hour || config.EnforceAck != "sha256:3f9c2a7d41b0" ||
		!reflect.DeepEqual(config.EnforceConnectors, []string{"claudecode", "codex"}) {
		t.Fatalf("rendered drop-in %+v", config)
	}
	if config := tetragonIntent(lookup(map[string]string{envTetragonBurnIn: "0"}), logger); config.BurnIn != 0 {
		t.Fatalf("burn_in 0: %v", config.BurnIn)
	}
	// Malformed values fall back to the narrow side, never wider.
	for name, value := range map[string]string{
		envTetragonMode: "enforce-everything", envTetragonBurnIn: "12h", envTetragonEnforceAck: "sha256:XYZ",
	} {
		config := tetragonIntent(lookup(map[string]string{name: value}), logger)
		if config.Mode != "consume" || config.BurnIn != 168*time.Hour || config.EnforceAck != "" {
			t.Fatalf("%s=%q: %+v", name, value, config)
		}
	}
	for _, burnIn := range []string{"3000h", "-1h", "a week"} {
		if config := tetragonIntent(lookup(map[string]string{envTetragonBurnIn: burnIn}), logger); config.BurnIn != 168*time.Hour {
			t.Fatalf("burn_in %q: %v", burnIn, config.BurnIn)
		}
	}
	if config := tetragonIntent(lookup(map[string]string{envTetragonMode: " OFF "}), logger); config.Mode != "off" {
		t.Fatalf("mode off: %+v", config)
	}
}

func TestManifestTargetsCarryUIDAndConnector(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the guardian manifest is a unix standalone input")
	}
	restore := validateManifestTrust
	validateManifestTrust = func(string) error { return nil }
	defer func() { validateManifestTrust = restore }()
	path := filepath.Join(t.TempDir(), "targets.yaml")
	body := `version: 1
targets:
  - user: alice
    user_home: /home/alice
    uid: 1001
    connector: ClaudeCode
  - user: alice
    user_home: /home/alice
    uid: 1001
    connector: codex
  - user: bob
    user_home: /home/bob
    uid: 1002
    connector: codex
    enabled: false
  - user: carol
    user_home: /
    connector: codex
`
	if err := os.WriteFile(path, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
	targets, digest, err := manifestTargets(path)
	if err != nil || len(digest) != 64 {
		t.Fatalf("%v %q", err, digest)
	}
	if len(targets) != 2 || targets[0].Connector != "claudecode" || targets[1].Connector != "codex" ||
		targets[0].UID == nil || *targets[0].UID != 1001 || targets[0].Home != "/home/alice" {
		t.Fatalf("targets %+v", targets)
	}
	if targets, _, err := manifestTargets(""); err != nil || targets != nil {
		t.Fatalf("no manifest: %v %v", targets, err)
	}
}

func TestTetragonCleanupFlag(t *testing.T) {
	saved := kernelPolicy
	defer func() { kernelPolicy = saved }()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	var out bytes.Buffer

	kernelPolicy = kernelPolicyHooks{}
	err := runTetragonCleanup(true, &out, logger)
	if runtime.GOOS != "linux" {
		if err != nil || !strings.Contains(out.String(), "not applicable") {
			t.Fatalf("outside Linux: %v %q", err, out.String())
		}
		return
	}
	if err == nil {
		t.Fatal("--check succeeded on a build with no cleanup")
	}

	called := 0
	kernelPolicy.cleanup = func(_ context.Context, out io.Writer, _ *slog.Logger) error {
		called++
		_, err := io.WriteString(out, "removed defenseclaw-controls-0a1b2c3d\n")
		return err
	}
	out.Reset()
	if err := runTetragonCleanup(true, &out, logger); err != nil || called != 0 || !strings.Contains(out.String(), "supported") {
		t.Fatalf("--check: %v, %d calls, %q", err, called, out.String())
	}
	out.Reset()
	if err := runTetragonCleanup(false, &out, logger); err != nil || called != 1 || !strings.Contains(out.String(), "removed") {
		t.Fatalf("cleanup: %v, %d calls, %q", err, called, out.String())
	}
	kernelPolicy.cleanup = func(context.Context, io.Writer, *slog.Logger) error { return errors.New("tetragon unreachable") }
	if err := runTetragonCleanup(false, &out, logger); err == nil {
		t.Fatal("a failed cleanup exited 0")
	}
}

// TestCleanupFlagsThroughMain runs the helper binary the way preremove.sh
// does: --check alone is refused, and --tetragon-cleanup never opens the
// broker socket.
func TestCleanupFlagsThroughMain(t *testing.T) {
	if _, stderr, code := runHelperBinary(t, "--check"); code == 0 || !strings.Contains(stderr, "--check needs --tetragon-cleanup") {
		t.Fatalf("--check alone exited %d: %q", code, stderr)
	}
	stdout, stderr, code := runHelperBinary(t, "--tetragon-cleanup", "--check")
	switch {
	case runtime.GOOS == "linux" && kernelPolicy.cleanup == nil:
		// A build that links no reconciler is the "older helper"
		// preremove.sh falls back for.
		if code == 0 || !strings.Contains(stderr, "no Tetragon cleanup") {
			t.Fatalf("--tetragon-cleanup --check exited %d: %q %q", code, stdout, stderr)
		}
	case runtime.GOOS == "linux":
		if code != 0 || !strings.Contains(stdout, "supported") {
			t.Fatalf("--tetragon-cleanup --check exited %d: %q %q", code, stdout, stderr)
		}
	default:
		if code != 0 || !strings.Contains(stdout, "not applicable") {
			t.Fatalf("--tetragon-cleanup --check exited %d: %q %q", code, stdout, stderr)
		}
	}
}
