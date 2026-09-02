// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// identityHookScripts is every shipped connector hook, discovered rather than
// listed.
//
// A hand-maintained list is what allowed seven of these hooks to ship with no
// identity reader at all: the three that had one passed, and the omission was
// invisible because a hook that reports nothing behaves exactly like one that
// reports correctly. Globbing means a newly added connector is covered the day
// it lands, and dropping the reader from an existing one fails here.
//
// The glob deliberately excludes hooks/inspect-*.sh, which are proxy
// inspection entry points rather than per-user connector hooks.
func identityHookScripts(t *testing.T) []string {
	t.Helper()
	scripts, err := fs.Glob(hookFS, "hooks/*-hook.sh")
	if err != nil {
		t.Fatalf("glob hooks: %v", err)
	}
	if len(scripts) < 10 {
		t.Fatalf("found only %d connector hooks (%q); the glob is no longer matching them", len(scripts), scripts)
	}
	return scripts
}

// TestUserIdentityArgsEmitBothHeadersUnderTheSystemShell runs the helper under
// the shell the endpoint actually has.
//
// The whole per-user attribution feature reaches the gateway through these two
// headers, and every failure mode in the helper is silent by design — it runs
// inside a guardrail hook under errexit, where a nonzero return would turn a
// missing telemetry field into a wrongly blocked tool call. So a helper that
// emits nothing looks exactly like a healthy one from the hook's side, and the
// only place the difference is visible is here.
func TestUserIdentityArgsEmitBothHeadersUnderTheSystemShell(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows hooks report identity from hookexec, not from the shell helper")
	}
	shell := systemBashForTest(t)
	helperPath := materializeHookAssetForTest(t, "hooks/_hardening.sh")

	out, err := exec.Command(
		shell, "-c", `set -e; source "$0"; defenseclaw_user_identity_args`, helperPath,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("helper failed under %s: %v\n%s", shell, err, out)
	}

	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	wantID := "X-DefenseClaw-User-Id: " + strconv.Itoa(os.Geteuid())
	want := []string{"-H", wantID, "-H"}
	if len(lines) != 4 {
		t.Fatalf("helper emitted %d lines, want 4 (a -H and a value per header): %q", len(lines), lines)
	}
	for i, expected := range want {
		if lines[i] != expected {
			t.Fatalf("line %d = %q, want %q (all lines: %q)", i, lines[i], expected, lines)
		}
	}
	if !strings.HasPrefix(lines[3], "X-DefenseClaw-User-Name: ") {
		t.Fatalf("line 3 = %q, want an account-name header", lines[3])
	}
	for _, line := range lines {
		if strings.ContainsAny(line, "\r") {
			t.Fatalf("header line %q carries a carriage return, which would let it append a second header", line)
		}
	}
}

// TestIdentityHeadersSurviveTheSystemShellsReader executes each shipped hook's
// own reader block against the helper, under the system shell.
//
// This exists because the first implementation read the helper with
// `mapfile`, which does not exist in bash 3.2 — the version macOS ships as
// /bin/bash. The hooks ran, the tool calls were allowed, the gateway answered
// normally, and every hook event on every stock macOS endpoint carried no user
// identity at all. Nothing failed; the feature was simply absent. A test that
// exercises the reader on the real shell is the only thing that catches that.
func TestIdentityHeadersSurviveTheSystemShellsReader(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows hooks report identity from hookexec, not from the shell helper")
	}
	shell := systemBashForTest(t)
	helperPath := materializeHookAssetForTest(t, "hooks/_hardening.sh")

	// Matches the reader block each hook uses, so a hook that changes how it
	// reads the helper is exercised here rather than silently going quiet.
	readerPattern := regexp.MustCompile(
		`(?s)IDENTITY_HEADER_ARGS=\(\).*?defenseclaw_user_identity_args\).*?\nfi\n`,
	)

	for _, script := range identityHookScripts(t) {
		t.Run(filepath.Base(script), func(t *testing.T) {
			body, err := hookFS.ReadFile(script)
			if err != nil {
				t.Fatalf("read embed: %v", err)
			}
			reader := readerPattern.Find(body)
			if reader == nil {
				t.Fatalf(
					"%s has no identity reader block, so every event from this "+
						"connector reaches AI Defense with no user attribution",
					script,
				)
			}

			program := `set -euo pipefail
source "$1"
` + string(reader) + `
printf '%s\n' "${#IDENTITY_HEADER_ARGS[@]}"
printf '%s\n' "${IDENTITY_HEADER_ARGS[@]+"${IDENTITY_HEADER_ARGS[@]}"}"
`
			out, err := exec.Command(shell, "-c", program, shell, helperPath).CombinedOutput()
			if err != nil {
				t.Fatalf("reader failed under %s: %v\n%s", shell, err, out)
			}
			lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
			if lines[0] != "4" {
				t.Fatalf(
					"%s collected %s identity arguments under %s, want 4 — "+
						"the endpoint would send no user identity at all\noutput: %q",
					script, lines[0], shell, string(out),
				)
			}
			if !strings.Contains(string(out), "X-DefenseClaw-User-Id: "+strconv.Itoa(os.Geteuid())) {
				t.Fatalf("%s did not carry the caller's uid: %q", script, string(out))
			}

			// Collecting the arguments and never passing them to curl fails
			// exactly as quietly as not collecting them.
			if !strings.Contains(string(body), `"${IDENTITY_HEADER_ARGS[@]+"${IDENTITY_HEADER_ARGS[@]}"}"`) {
				t.Fatalf(
					"%s builds IDENTITY_HEADER_ARGS but never expands it into its request",
					script,
				)
			}
		})
	}
}

// TestPluginTransportsReportIdentityToo covers the connectors that do not go
// through a shell hook at all.
//
// amp, opencode, and omnigent POST to the gateway from inside the agent's own
// runtime, so they bypass both _hardening.sh and hookexec. They were the other
// half of the same gap: three connectors whose events reached AI Defense with
// no user on them, for the same reason and with the same silence.
func TestPluginTransportsReportIdentityToo(t *testing.T) {
	for _, asset := range []string{
		"hooks/amp-plugin.ts",
		"hooks/opencode-plugin.js",
		"hooks/omnigent-policy.py",
	} {
		t.Run(filepath.Base(asset), func(t *testing.T) {
			body, err := hookFS.ReadFile(asset)
			if err != nil {
				t.Fatalf("read embed: %v", err)
			}
			for _, header := range []string{"X-DefenseClaw-User-Id", "X-DefenseClaw-User-Name"} {
				if !strings.Contains(string(body), header) {
					t.Errorf("%s never sets %s, so its events carry no user", asset, header)
				}
			}
			// Each of these runs on Windows too, where there is no POSIX uid.
			// Reporting the -1 that the runtime returns there would place a
			// value in user.id belonging to neither identifier namespace.
			if !strings.Contains(string(body), ">= 0") && !strings.Contains(string(body), "uid >= 0") {
				t.Errorf("%s does not guard against a negative uid on Windows", asset)
			}
		})
	}
}

// systemBashForTest returns /bin/bash rather than whatever bash is first on
// PATH. On macOS those differ: PATH commonly leads to a Homebrew bash 5, while
// the hooks' shebang is #!/bin/bash and resolves to the 3.2 the OS ships.
// Testing the PATH one would pass while every real endpoint failed.
func systemBashForTest(t *testing.T) string {
	t.Helper()
	const shell = "/bin/bash"
	if _, err := os.Stat(shell); err != nil {
		t.Skipf("%s not available: %v", shell, err)
	}
	return shell
}

func materializeHookAssetForTest(t *testing.T, name string) string {
	t.Helper()
	body, err := hookFS.ReadFile(name)
	if err != nil {
		t.Fatalf("read embed %s: %v", name, err)
	}
	path := filepath.Join(t.TempDir(), filepath.Base(name))
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}
