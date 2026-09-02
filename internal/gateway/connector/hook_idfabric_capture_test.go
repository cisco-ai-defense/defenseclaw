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

package connector

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// identityFabricShellHooks are the connectors whose Unix hooks capture
// Identity Fabric telemetry.
var identityFabricShellHooks = map[string]string{
	"hooks/cursor-hook.sh":      "cursor",
	"hooks/codex-hook.sh":       "codex",
	"hooks/claude-code-hook.sh": "claudecode",
}

func renderShellHookForTest(t *testing.T, name string, data templateData) string {
	t.Helper()
	source, err := hookFS.ReadFile(name)
	if err != nil {
		t.Fatalf("read embedded hook %s: %v", name, err)
	}
	rendered, err := renderTemplate(string(source), data)
	if err != nil {
		t.Fatalf("render embedded hook %s: %v", name, err)
	}
	return rendered
}

func identityFabricTemplateData(managed bool) templateData {
	return templateData{
		APIAddr:      "127.0.0.1:18970",
		FailMode:     "closed",
		TokenFile:    ".hook-test.token",
		ScopedToken:  true,
		Managed:      managed,
		HookBinarySH: "/opt/defenseclaw/bin/defenseclaw",
	}
}

// TestManagedShellHooksCaptureIdentityFabric covers the gap that made macOS
// and Linux invisible to Identity Fabric: the .sh hooks POST to the gateway
// with curl and never run the native `hook` command, so the inline capture
// there never executed on those platforms.
func TestManagedShellHooksCaptureIdentityFabric(t *testing.T) {
	for name, connectorName := range identityFabricShellHooks {
		t.Run(name, func(t *testing.T) {
			rendered := renderShellHookForTest(t, name, identityFabricTemplateData(true))

			call := "defenseclaw_capture_identity_fabric '/opt/defenseclaw/bin/defenseclaw' " + connectorName
			if !strings.Contains(rendered, call) {
				t.Errorf("managed hook does not capture Identity Fabric telemetry: want %q", call)
			}
			// Skipping rather than failing keeps a helper/script version skew
			// from turning a missing record into a broken guardrail.
			if !strings.Contains(rendered, "declare -F defenseclaw_capture_identity_fabric") {
				t.Error("capture call is not guarded on the helper defining the function")
			}
			if !strings.Contains(rendered, `"$PAYLOAD"`) {
				t.Error("capture is not handed the payload the gateway receives")
			}
		})
	}
}

// TestUnmanagedShellHooksDoNotCaptureIdentityFabric pins the gating. Capture
// is an enterprise feature, and an unmanaged endpoint must not gain a
// background process or a spool directory from installing DefenseClaw.
func TestUnmanagedShellHooksDoNotCaptureIdentityFabric(t *testing.T) {
	for name := range identityFabricShellHooks {
		t.Run(name, func(t *testing.T) {
			rendered := renderShellHookForTest(t, name, identityFabricTemplateData(false))
			if strings.Contains(rendered, "defenseclaw_capture_identity_fabric") {
				t.Error("unmanaged hook captures Identity Fabric telemetry")
			}
		})
	}
}

// TestIdentityFabricCaptureIsDetachedFromTheHook pins the two properties that
// keep capture off the critical path: the child is backgrounded, and its
// streams are closed so a connector reading the hook's stdout to EOF (Cursor
// does) never waits on the inherited descriptor.
func TestIdentityFabricCaptureIsDetachedFromTheHook(t *testing.T) {
	helper, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatalf("read embedded hook hardening helper: %v", err)
	}
	source := string(helper)
	if !strings.Contains(source, "defenseclaw_capture_identity_fabric() {") {
		t.Fatal("hardening helper does not define defenseclaw_capture_identity_fabric")
	}
	if !strings.Contains(source, "} </dev/null >/dev/null 2>&1 &") {
		t.Error("capture child is not detached with its streams closed")
	}
	if !strings.Contains(source, "idfabric capture") {
		t.Error("capture does not invoke the CLI capture subcommand")
	}
}

// TestClaudeCodeCapturesAfterCursorOriginBail keeps one user action from being
// reported twice. Cursor can import Claude Code hooks from
// ~/.claude/settings.json, and the existing bail hands those invocations to
// the native Cursor hook. Capturing before it would emit the same action as
// both cursor and claudecode.
func TestClaudeCodeCapturesAfterCursorOriginBail(t *testing.T) {
	rendered := renderShellHookForTest(t, "hooks/claude-code-hook.sh", identityFabricTemplateData(true))
	bail := strings.Index(rendered, "unset CURSOR_ORIGIN_VERSION")
	capture := strings.Index(rendered, "defenseclaw_capture_identity_fabric")
	if bail < 0 || capture < 0 {
		t.Fatalf("hook is missing the Cursor-origin bail (%d) or the capture call (%d)", bail, capture)
	}
	if capture < bail {
		t.Error("capture runs before the Cursor-origin bail, double-reporting imported Cursor invocations")
	}
}

// TestCodexCapturesAfterEventBinding keeps a record from claiming an event the
// hook rejected: the event name is part of what the record asserts happened.
func TestCodexCapturesAfterEventBinding(t *testing.T) {
	rendered := renderShellHookForTest(t, "hooks/codex-hook.sh", identityFabricTemplateData(true))
	binding := strings.Index(rendered, `if [ "$PAYLOAD_EVENT" != "$BOUND_EVENT" ]; then`)
	capture := strings.Index(rendered, "defenseclaw_capture_identity_fabric")
	if binding < 0 || capture < 0 {
		t.Fatalf("hook is missing event binding (%d) or the capture call (%d)", binding, capture)
	}
	if capture < binding {
		t.Error("capture runs before event binding, recording events the hook refused")
	}
}

// TestShellSingleQuoteBodyEscapesEmbeddedQuote covers an install path holding
// an apostrophe. Interpolating it raw would end the shell literal and splice
// the remainder of the path into the command.
func TestShellSingleQuoteBodyEscapesEmbeddedQuote(t *testing.T) {
	got := shellSingleQuoteBody(`/Users/o'brien/bin/defenseclaw`)
	want := `/Users/o'\''brien/bin/defenseclaw`
	if got != want {
		t.Fatalf("shellSingleQuoteBody = %q, want %q", got, want)
	}
	if plain := shellSingleQuoteBody("/opt/defenseclaw/bin/defenseclaw"); plain != "/opt/defenseclaw/bin/defenseclaw" {
		t.Errorf("shellSingleQuoteBody altered a quote-free path: %q", plain)
	}
}

// TestIdentityFabricCaptureRunsWithTheUsersRealHome is the behavioral guard on
// the interaction between capture and defenseclaw_harden_env.
//
// Hardening repoints HOME at an empty per-hook sandbox and deletes it on exit.
// That is right for tools the hook shells out to and wrong for capture, whose
// entire job is to report the user's connector config, account email, and
// device identity - all of which live in the real profile. Inheriting the
// sandbox does not fail loudly; it spools a well-formed record asserting the
// user has no MCP servers.
func TestIdentityFabricCaptureRunsWithTheUsersRealHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts are not used on Windows")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is unavailable")
	}

	dir := t.TempDir()
	helper, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatalf("read embedded hook hardening helper: %v", err)
	}
	helperPath := filepath.Join(dir, "_hardening.sh")
	if err := os.WriteFile(helperPath, helper, 0o600); err != nil {
		t.Fatalf("write hardening helper: %v", err)
	}

	realHome := filepath.Join(dir, "real-home")
	if err := os.MkdirAll(realHome, 0o700); err != nil {
		t.Fatalf("create real home: %v", err)
	}
	observed := filepath.Join(dir, "observed")

	// Stands in for the CLI: records the HOME and stdin it was handed.
	stub := filepath.Join(dir, "defenseclaw-stub")
	stubBody := "#!/bin/bash\n" +
		"{ printf 'home=%s\\n' \"$HOME\"; printf 'args=%s\\n' \"$*\"; printf 'stdin='; cat; } > " +
		shellQuoteForTest(observed) + "\n"
	if err := os.WriteFile(stub, []byte(stubBody), 0o700); err != nil {
		t.Fatalf("write stub CLI: %v", err)
	}

	driverBody := "#!/bin/bash\nset -euo pipefail\n" +
		"export HOME=" + shellQuoteForTest(realHome) + "\n" +
		". " + shellQuoteForTest(helperPath) + "\n" +
		"defenseclaw_harden_env\n" +
		"defenseclaw_capture_identity_fabric " + shellQuoteForTest(stub) +
		" cursor sessionStart '{\"hook_event_name\":\"sessionStart\"}'\n" +
		// The hook never waits; the test does, to stay deterministic.
		"wait\n"
	driver := filepath.Join(dir, "driver.sh")
	if err := os.WriteFile(driver, []byte(driverBody), 0o700); err != nil {
		t.Fatalf("write driver: %v", err)
	}

	if out, err := exec.Command(bash, driver).CombinedOutput(); err != nil {
		t.Fatalf("driver failed: %v\n%s", err, out)
	}

	got, err := os.ReadFile(observed)
	if err != nil {
		t.Fatalf("capture did not run: %v", err)
	}
	record := string(got)
	if !strings.Contains(record, "home="+realHome+"\n") {
		t.Errorf("capture ran with the hardened sandbox home, not the user's profile:\n%s", record)
	}
	if !strings.Contains(record, "idfabric capture") ||
		!strings.Contains(record, "--connector cursor") ||
		!strings.Contains(record, "--enterprise-managed") {
		t.Errorf("capture was invoked with unexpected arguments:\n%s", record)
	}
	if !strings.Contains(record, `stdin={"hook_event_name":"sessionStart"}`) {
		t.Errorf("capture did not receive the payload on stdin:\n%s", record)
	}
}

func shellQuoteForTest(value string) string {
	return "'" + shellSingleQuoteBody(value) + "'"
}

// TestRenderedShellHooksParseUnderBash guards the capture snippets and the new
// helper against a syntax error, which under these hooks' fail-closed default
// would block every tool call rather than merely lose telemetry.
func TestRenderedShellHooksParseUnderBash(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts are not used on Windows")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is unavailable")
	}
	dir := t.TempDir()

	helper, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatalf("read embedded hook hardening helper: %v", err)
	}
	files := map[string][]byte{"_hardening.sh": helper}
	for name := range identityFabricShellHooks {
		for _, managed := range []bool{true, false} {
			suffix := "unmanaged"
			if managed {
				suffix = "managed"
			}
			rendered := renderShellHookForTest(t, name, identityFabricTemplateData(managed))
			files[filepath.Base(name)+"."+suffix] = []byte(rendered)
		}
	}

	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		out, err := exec.Command(bash, "-n", path).CombinedOutput()
		if err != nil {
			t.Errorf("bash -n %s failed: %v\n%s", name, err, out)
		}
	}
}
