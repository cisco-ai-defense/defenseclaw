// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/contracttest"
	"github.com/defenseclaw/defenseclaw/internal/enterpriseunix"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// contractHostCommands answers `systemctl --version` as a supported systemd
// host does, and the service account lookups as a device the package has not
// installed yet does (getent exit 2, dscl eDSRecordNotFound). It runs no
// other host command.
type contractHostCommands struct{ noHostCommands }

func (c contractHostCommands) Run(ctx context.Context, name string, args ...string) (enterpriseunix.CommandResult, error) {
	switch {
	case name == "systemctl" && len(args) == 1 && args[0] == "--version":
		return enterpriseunix.CommandResult{Stdout: []byte("systemd 252 (252-46.el9)\n")}, nil
	case name == "getent" && len(args) == 2 && args[0] == "passwd":
		return enterpriseunix.CommandResult{ExitCode: 2}, errors.New("exit status 2")
	case name == "dscl" && len(args) == 4 && args[1] == "-read":
		return enterpriseunix.CommandResult{ExitCode: 56}, errors.New("eDSRecordNotFound")
	}
	return c.noHostCommands.Run(ctx, name, args...)
}

// contractUnixEnv points the Linux and macOS lifecycle at an empty device
// tree that a root caller runs against. On Linux the tree and the host
// commands show systemd as the running init system, as on a supported host,
// so both platforms report the same device that is not installed yet.
func contractUnixEnv(t *testing.T) (root string, layout managed.StandaloneLayout) {
	t.Helper()
	goos := enterpriseunix.CurrentGOOS()
	layout, err := managed.StandaloneLayoutFor(goos)
	if err != nil {
		t.Skip(err)
	}
	root = t.TempDir()
	if goos == "linux" {
		if err := os.MkdirAll(filepath.Join(root, "run", "systemd", "system"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	previous := newUnixLifecycleEnv
	newUnixLifecycleEnv = func(goos string) (*enterpriseunix.Env, error) {
		// The test runs unprivileged: ownership changes are no-ops, as root
		// on a real device makes them succeed.
		return &enterpriseunix.Env{GOOS: goos, Root: root, Layout: layout, Geteuid: func() int { return 0 }, Runner: contractHostCommands{},
			Lchown: func(string, int, int) error { return nil }, Fchown: func(*os.File, int, int) error { return nil }}, nil
	}
	t.Cleanup(func() { newUnixLifecycleEnv = previous })
	return root, layout
}

func contractUnixPlatform() string {
	if enterpriseunix.CurrentGOOS() == "darwin" {
		return "macos"
	}
	return "linux"
}

// TestManagementContractUnixStatusAndSecrets validates `enterprise <os>
// status`, `enterprise secret status` and `enterprise secret set` as a root
// caller prints them on a device that is not installed yet (contract 5.0).
func TestManagementContractUnixStatusAndSecrets(t *testing.T) {
	schemas := contracttest.Compile(t)
	root, layout := contractUnixEnv(t)

	cmd := &cobra.Command{}
	cmd.SetContext(t.Context())
	var out bytes.Buffer
	cmd.SetOut(&out)
	err := runUnixLifecycle(cmd, contractUnixPlatform(), "status", &unixLifecycleOptions{json: true})
	doc := schemas.Validate(t, "lifecycle-result.schema.json", out.Bytes())
	requireExit(t, doc, runExit(err), 0)
	if doc["ok"] != true || doc["installed"] != false {
		t.Fatalf("status of an empty device = %s", out.String())
	}

	const value = "contract-test-credential-value"
	set := newEnterpriseSecretCommand("set", "")
	set.SetContext(t.Context())
	out.Reset()
	set.SetOut(&out)
	set.SetIn(strings.NewReader(value + "\n"))
	err = runEnterpriseSecret(set, "set", &enterpriseSecretOptions{name: "ai-defense-api-key", fromStdin: true, json: true})
	if strings.Contains(out.String(), value) {
		t.Fatalf("the credential value was printed: %s", out.String())
	}
	doc = schemas.Validate(t, "secret-result.schema.json", out.Bytes())
	requireExit(t, doc, runExit(err), 0)

	secrets := root + layout.SecretsDir
	if err := os.MkdirAll(secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secrets, "splunk-hec-token"), []byte("contract-status-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	status := newEnterpriseSecretCommand("status", "")
	out.Reset()
	status.SetOut(&out)
	if err := runEnterpriseSecret(status, "status", &enterpriseSecretOptions{json: true}); err != nil {
		t.Fatalf("secret status: %v", err)
	}
	if strings.Contains(out.String(), "contract-status-value") {
		t.Fatalf("secret status printed a value: %s", out.String())
	}
	schemas.Validate(t, "secret-result.schema.json", out.Bytes())
}

// secretReadFails is a stdin whose read fails (EIO), as a broken pipe or a
// revoked terminal does.
type secretReadFails struct{}

func (secretReadFails) Read([]byte) (int, error) { return 0, syscall.EIO }

// TestManagementContractUnixSecretFailuresPrintOneDocument enumerates every
// Linux and macOS secret failure class: with --json each prints exactly one
// secret-result document on stdout, with the code and exit of the guide
// (4.7), never the value, and stores nothing. A secret set whose agent was
// stopped while it read stdin (the pipe closed with no value) printed only
// "credential is empty" on stderr and an empty stdout (mgmt-agent-api
// GAP-0031): it is change_failed, exit 1, and the agent resends.
func TestManagementContractUnixSecretFailuresPrintOneDocument(t *testing.T) {
	schemas := contracttest.Compile(t)
	root, layout := contractUnixEnv(t)
	contractEnv := newUnixLifecycleEnv
	const value = "s3cr3t-value-never-printed"
	closedPipe := func(t *testing.T) io.Reader {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		_ = w.Close()
		t.Cleanup(func() { _ = r.Close() })
		return r
	}
	// openPipe is a stdin whose sender keeps its end open and sends
	// nothing: a stopped (SIGSTOP) agent, or a process the agent started
	// that still holds the pipe.
	openPipe := func(t *testing.T) io.Reader {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = w.Close(); _ = r.Close() })
		return r
	}
	// partValue is a stdin that ends after part of a value, without a
	// newline: the agent exited while it sent it.
	partValue := func(t *testing.T) io.Reader {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(value[:4])); err != nil {
			t.Fatal(err)
		}
		_ = w.Close()
		t.Cleanup(func() { _ = r.Close() })
		return r
	}
	// callerStops makes the parent exit once this command started: the
	// first lookup is the agent, every later one init.
	callerStops := func() {
		calls := 0
		secretCallerPID = func() int {
			if calls++; calls == 1 {
				return 4242
			}
			return 1
		}
	}
	// callerExitsLate is a parent exit as macOS shows it: the agent's end
	// of the pipe closes first and init becomes the parent only later, so
	// the end of stdin arrives while the agent still looks alive
	// (mgmt-agent-api GAP-0040).
	callerExitsLate := func() {
		var exited time.Time
		secretCallerPID = func() int {
			if exited.IsZero() {
				exited = time.Now().Add(150 * time.Millisecond)
			}
			if time.Now().Before(exited) {
				return 4242
			}
			return 1
		}
	}
	// senderStops makes stdin wait short: the agent stopped without
	// sending or closing stdin.
	senderStops := func() { secretStdinWait = 200 * time.Millisecond }
	envFails := func() {
		newUnixLifecycleEnv = func(string) (*enterpriseunix.Env, error) { return nil, errors.New("the layout cannot be resolved") }
	}
	notRoot := func() {
		newUnixLifecycleEnv = func(goos string) (*enterpriseunix.Env, error) {
			env, err := contractEnv(goos)
			if env != nil {
				env.Geteuid = func() int { return 1000 }
			}
			return env, err
		}
	}
	untrusted := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(untrusted, []byte(value+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(untrusted, 0o666); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, action string
		opts         enterpriseSecretOptions
		stdin        func(*testing.T) io.Reader
		setup        func()
		schema, code string
		exit         int
	}{
		{name: "closed pipe after the agent stopped", action: "set", opts: enterpriseSecretOptions{name: "ok-name", fromStdin: true},
			stdin: closedPipe, setup: callerStops, code: "change_failed", exit: 1},
		{name: "closed pipe before the agent's exit shows", action: "set", opts: enterpriseSecretOptions{name: "ok-name", fromStdin: true},
			stdin: closedPipe, setup: callerExitsLate, code: "change_failed", exit: 1},
		{name: "part of a value, then the agent exited", action: "set", opts: enterpriseSecretOptions{name: "ok-name", fromStdin: true},
			stdin: partValue, setup: callerExitsLate, code: "change_failed", exit: 1},
		{name: "agent exited, another process holds stdin open", action: "set", opts: enterpriseSecretOptions{name: "ok-name", fromStdin: true},
			stdin: openPipe, setup: callerExitsLate, code: "change_failed", exit: 1},
		{name: "agent stopped without sending or closing stdin", action: "set", opts: enterpriseSecretOptions{name: "ok-name", fromStdin: true},
			stdin: openPipe, setup: senderStops, code: "change_failed", exit: 1},
		{name: "unterminated blank value", action: "set", opts: enterpriseSecretOptions{name: "ok-name", fromStdin: true},
			stdin: func(*testing.T) io.Reader { return strings.NewReader("  ") }, code: "invalid_arguments", exit: 2},
		{name: "closed pipe, empty value", action: "set", opts: enterpriseSecretOptions{name: "ok-name", fromStdin: true},
			stdin: closedPipe, code: "invalid_arguments", exit: 2},
		{name: "blank line", action: "set", opts: enterpriseSecretOptions{name: "ok-name", fromStdin: true},
			stdin: func(*testing.T) io.Reader { return strings.NewReader("\n") }, code: "invalid_arguments", exit: 2},
		{name: "two lines", action: "set", opts: enterpriseSecretOptions{name: "ok-name", fromStdin: true},
			stdin: func(*testing.T) io.Reader { return strings.NewReader(value + "\nmore\n") }, code: "invalid_arguments", exit: 2},
		{name: "oversized", action: "set", opts: enterpriseSecretOptions{name: "ok-name", fromStdin: true},
			stdin: func(*testing.T) io.Reader { return strings.NewReader(strings.Repeat("x", 17<<10)) }, code: "invalid_arguments", exit: 2},
		{name: "unreadable stdin", action: "set", opts: enterpriseSecretOptions{name: "ok-name", fromStdin: true},
			stdin: func(*testing.T) io.Reader { return secretReadFails{} }, code: "invalid_arguments", exit: 2},
		{name: "unreadable stdin after the agent stopped", action: "set", opts: enterpriseSecretOptions{name: "ok-name", fromStdin: true},
			stdin: func(*testing.T) io.Reader { return secretReadFails{} }, setup: callerStops, code: "change_failed", exit: 1},
		{name: "bad name", action: "set", opts: enterpriseSecretOptions{name: "BAD_NAME", fromStdin: true}, code: "invalid_arguments", exit: 2},
		{name: "no source", action: "set", opts: enterpriseSecretOptions{name: "ok-name"}, code: "invalid_arguments", exit: 2},
		{name: "two sources", action: "set", opts: enterpriseSecretOptions{name: "ok-name", fromStdin: true, fromFile: untrusted}, code: "invalid_arguments", exit: 2},
		{name: "untrusted --from-file", action: "set", opts: enterpriseSecretOptions{name: "ok-name", fromFile: untrusted}, code: "invalid_arguments", exit: 2},
		{name: "lock wait over 15m", action: "set", opts: enterpriseSecretOptions{name: "ok-name", fromStdin: true, lockWait: 16 * time.Minute}, code: "invalid_arguments", exit: 2},
		{name: "set not root", action: "set", opts: enterpriseSecretOptions{name: "ok-name", fromStdin: true}, setup: notRoot, code: "not_root", exit: 1},
		{name: "set without a layout", action: "set", opts: enterpriseSecretOptions{name: "ok-name", fromStdin: true}, setup: envFails, code: "state_invalid", exit: 1},
		{name: "remove bad name", action: "remove", opts: enterpriseSecretOptions{name: "../escape"}, code: "invalid_arguments", exit: 2},
		{name: "remove not root", action: "remove", opts: enterpriseSecretOptions{name: "ok-name"}, setup: notRoot, code: "not_root", exit: 1},
		{name: "remove lock wait negative", action: "remove", opts: enterpriseSecretOptions{name: "ok-name", lockWait: -time.Second}, code: "invalid_arguments", exit: 2},
		{name: "status without a layout", action: "status", setup: envFails, code: "state_invalid", exit: 1},
		// The lifecycle ran: its result v2 names the failure.
		{name: "agent stopped while set waited for the lock", action: "set", opts: enterpriseSecretOptions{name: "ok-name", fromStdin: true},
			stdin: func(*testing.T) io.Reader { return strings.NewReader(value + "\n") }, setup: callerStops, schema: "lifecycle", code: "change_failed", exit: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			savedEnv, savedCaller := newUnixLifecycleEnv, secretCallerPID
			savedWait, savedSettle := secretStdinWait, secretCallerSettle
			t.Cleanup(func() {
				newUnixLifecycleEnv, secretCallerPID = savedEnv, savedCaller
				secretStdinWait, secretCallerSettle = savedWait, savedSettle
			})
			secretCallerPID = func() int { return 4242 }
			secretStdinWait, secretCallerSettle = 10*time.Second, 500*time.Millisecond
			if tc.setup != nil {
				tc.setup()
			}
			stdin := io.Reader(strings.NewReader(value + "\n"))
			if tc.stdin != nil {
				stdin = tc.stdin(t)
			}
			cmd := newEnterpriseSecretCommand(tc.action, "")
			cmd.SetContext(t.Context())
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetIn(stdin)
			opts := tc.opts
			opts.json = true
			started := time.Now()
			err := runEnterpriseSecret(cmd, tc.action, &opts)
			if took := time.Since(started); took > 5*time.Second {
				t.Fatalf("the failure took %s; a sender that stopped or exited must not hold secret set", took)
			}
			if strings.Contains(out.String(), value) || (err != nil && strings.Contains(err.Error(), value)) {
				t.Fatalf("the credential value was printed: %s", out.String())
			}
			doc := schemas.Validate(t, "secret-result.schema.json", out.Bytes())
			requireExit(t, doc, runExit(err), tc.exit)
			errs, _ := doc["errors"].([]any)
			first, _ := func() (map[string]any, bool) {
				if len(errs) == 0 {
					return nil, false
				}
				m, ok := errs[0].(map[string]any)
				return m, ok
			}()
			if doc["ok"] != false || first == nil || first["code"] != tc.code {
				t.Fatalf("document %s, want errors[0].code %s", out.String(), tc.code)
			}
			wantSchema := json.Number("1")
			if tc.schema == "lifecycle" {
				wantSchema = json.Number("2")
			}
			if doc["schema_version"] != wantSchema {
				t.Fatalf("schema_version %v, want %s: %s", doc["schema_version"], wantSchema, out.String())
			}
			if _, statErr := os.Stat(filepath.Join(root+layout.SecretsDir, "ok-name")); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("a failed %s stored the credential: %v", tc.action, statErr)
			}
		})
	}
}

// A value that ends without a newline (printf '%s' "$key" |) while the
// agent is still there is stored whole, also when the agent sends it in two
// writes; secret set waits for its parent only after such a value
// (mgmt-agent-api GAP-0040).
func TestManagementContractUnixSecretSetStoresAnUnterminatedValue(t *testing.T) {
	schemas := contracttest.Compile(t)
	root, layout := contractUnixEnv(t)
	const value = "s3cr3t-value-never-printed"
	savedCaller, savedSettle := secretCallerPID, secretCallerSettle
	t.Cleanup(func() { secretCallerPID, secretCallerSettle = savedCaller, savedSettle })
	secretCallerPID = func() int { return 4242 }
	secretCallerSettle = 100 * time.Millisecond
	for _, tc := range []struct {
		name  string
		stdin func(*testing.T) io.Reader
	}{
		{name: "one write", stdin: func(*testing.T) io.Reader { return strings.NewReader(value) }},
		{name: "two writes with a pause", stdin: func(t *testing.T) io.Reader {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = r.Close() })
			go func() {
				defer w.Close()
				_, _ = w.Write([]byte(value[:4]))
				time.Sleep(100 * time.Millisecond)
				_, _ = w.Write([]byte(value[4:]))
			}()
			return r
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name := "unterminated-" + strings.ReplaceAll(tc.name, " ", "-")
			cmd := newEnterpriseSecretCommand("set", "")
			cmd.SetContext(t.Context())
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetIn(tc.stdin(t))
			err := runEnterpriseSecret(cmd, "set", &enterpriseSecretOptions{name: name, fromStdin: true, json: true})
			doc := schemas.Validate(t, "secret-result.schema.json", out.Bytes())
			requireExit(t, doc, runExit(err), 0)
			stored, readErr := os.ReadFile(filepath.Join(root+layout.SecretsDir, name))
			if readErr != nil || string(stored) != value {
				t.Fatalf("stored %d bytes (%v), want the whole value", len(stored), readErr)
			}
		})
	}
}

// A flag error of a Linux or macOS secret verb, with --json anywhere on the
// command line, prints the failure document too (cobra stops parsing at the
// bad flag, so opts.json is not set yet).
func TestManagementContractUnixSecretFlagErrorsPrintTheFailureDocument(t *testing.T) {
	schemas := contracttest.Compile(t)
	contractUnixEnv(t)
	saved := secretRawArgs
	t.Cleanup(func() { secretRawArgs = saved })
	for _, action := range []string{"set", "remove", "status"} {
		cmd := newEnterpriseSecretCommand(action, "")
		args := []string{"--bogus", "--json"}
		secretRawArgs = func() []string { return append([]string{"enterprise", "secret", action}, args...) }
		var out bytes.Buffer
		cmd.SetOut(&out)
		parseErr := cmd.ParseFlags(args)
		if parseErr == nil {
			t.Fatalf("secret %s accepted --bogus", action)
		}
		err := cmd.FlagErrorFunc()(cmd, parseErr)
		doc := schemas.Validate(t, "secret-result.schema.json", out.Bytes())
		requireExit(t, doc, runExit(err), 2)
		if errs, _ := doc["errors"].([]any); len(errs) != 1 || errs[0].(map[string]any)["code"] != "invalid_arguments" {
			t.Fatalf("secret %s flag error: %s", action, out.String())
		}
		// Without --json the flag error prints nothing on stdout.
		secretRawArgs = func() []string { return []string{"enterprise", "secret", action, "--bogus"} }
		out.Reset()
		cmd = newEnterpriseSecretCommand(action, "")
		cmd.SetOut(&out)
		if err := cmd.FlagErrorFunc()(cmd, cmd.ParseFlags([]string{"--bogus"})); runExit(err) != 2 || out.Len() != 0 {
			t.Fatalf("secret %s text flag error: exit %d, stdout %q", action, runExit(err), out.String())
		}
	}
}

// TestManagementContractBundleApplyArgumentErrors: on a managed device, a
// `bundle apply --json` argument error prints one refusal document with
// invalid_arguments and exits 2, also when --json follows the bad argument
// (the parse stopped before it). Without --json stdout stays empty.
func TestManagementContractBundleApplyArgumentErrors(t *testing.T) {
	schemas := contracttest.Compile(t)
	e := newBundleCLIEnv(t)
	bundleDevice(t, e)
	savedArgs := secretRawArgs
	t.Cleanup(func() { secretRawArgs = savedArgs })
	bundle := filepath.Join(e.dir, "policy.dcbundle")
	for name, args := range map[string][]string{
		"no --bundle":           {"apply", "--json"},
		"--bundle and --inbox":  {"apply", "--bundle", bundle, "--inbox", "--json"},
		"--lock-wait over 15m":  {"apply", "--bundle", bundle, "--lock-wait", "16m", "--json"},
		"negative --lock-wait":  {"apply", "--bundle", bundle, "--lock-wait", "-1s", "--json"},
		"unknown flag":          {"apply", "--bundle", bundle, "--bogus", "--json"},
		"stray argument":        {"apply", "--bundle", bundle, "extra", "--json"},
		"malformed --lock-wait": {"apply", "--bundle", bundle, "--lock-wait", "soon", "--json"},
		// F10: --delivery-id is 1 to 128 of A-Z a-z 0-9 . _ : -.
		"empty --delivery-id":            {"apply", "--bundle", bundle, "--delivery-id", "", "--json"},
		"--delivery-id over 128 bytes":   {"apply", "--bundle", bundle, "--delivery-id", strings.Repeat("a", 129), "--json"},
		"--delivery-id with a space":     {"apply", "--bundle", bundle, "--delivery-id", "agent 7", "--json"},
		"--delivery-id with a control":   {"apply", "--bundle", bundle, "--delivery-id", "agent\x1b7", "--json"},
		"--delivery-id with a slash":     {"apply", "--bundle", bundle, "--delivery-id", "agent/7", "--json"},
		"--delivery-id with a non-ASCII": {"apply", "--bundle", bundle, "--delivery-id", "agent\u00e97", "--json"},
	} {
		t.Run(name, func(t *testing.T) {
			secretRawArgs = func() []string { return append([]string{"enterprise", "bundle"}, args...) }
			out, code := runBundle(t, args...)
			doc := schemas.Validate(t, "bundle-refused.schema.json", []byte(out))
			errs, _ := doc["errors"].([]any)
			if code != 2 || len(errs) != 1 || errs[0].(map[string]any)["code"] != "invalid_arguments" || strings.Count(out, `"schema_version"`) != 1 {
				t.Fatalf("apply %v: exit %d, stdout %q; want exit 2 and one invalid_arguments document", args, code, out)
			}
			secretRawArgs = func() []string { return nil }
			text := args[:len(args)-1]
			if out, code := runBundle(t, text...); out != "" || code != 2 {
				t.Fatalf("apply %v without --json: exit %d, stdout %q; want exit 2 and no stdout", text, code, out)
			}
		})
	}
	out, code := runBundle(t, "verify", "--json")
	if code != 2 || !strings.Contains(out, `"invalid_arguments"`) {
		t.Fatalf("verify without --bundle: exit %d, stdout %q; want a JSON invalid_arguments document", code, out)
	}
}

// TestManagementContractAnchorsInstallRefusals validates the refusals of
// `enterprise bundle anchors install` before it reads the source.
func TestManagementContractAnchorsInstallRefusals(t *testing.T) {
	schemas := contracttest.Compile(t)
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	for name, setup := range map[string]func(){
		"not managed":   func() { bundleManagedDevice = func() bool { return false } },
		"secure client": func() { bundleSecureClient = func() bool { return true } },
	} {
		t.Run(name, func(t *testing.T) {
			savedDevice, savedSC := bundleManagedDevice, bundleSecureClient
			t.Cleanup(func() { bundleManagedDevice, bundleSecureClient = savedDevice, savedSC })
			setup()
			out, code := runBundle(t, "anchors", "install", "--file", e.anchors, "--json")
			doc := schemas.Validate(t, "anchors-install.schema.json", []byte(out))
			requireExit(t, doc, code, bundleFailureExitCode())
		})
	}
}

// TestManagementContractAnchorsInstallResults validates every result of
// `enterprise bundle anchors install` on a managed device: installed,
// unchanged, replaced, and the refusals an agent acts on (insecure or
// invalid source, usage, busy, not root).
func TestManagementContractAnchorsInstallResults(t *testing.T) {
	schemas := contracttest.Compile(t)
	root, layout, euid := anchorsInstallDevice(t)
	install := func(want int, args ...string) map[string]any {
		t.Helper()
		out, code := runBundle(t, append([]string{"anchors", "install"}, args...)...)
		doc := schemas.Validate(t, "anchors-install.schema.json", []byte(out))
		requireExit(t, doc, code, want)
		return doc
	}
	errorCode := func(doc map[string]any) any {
		errs, _ := doc["errors"].([]any)
		if len(errs) == 0 {
			return nil
		}
		return errs[0].(map[string]any)["code"]
	}
	first := testAnchorsFile(t, "active", "retired")
	if doc := install(0, "--file", first, "--json"); doc["result"] != "installed" {
		t.Fatalf("first install: %v", doc)
	}
	if doc := install(0, "--file", first, "--json"); doc["result"] != "unchanged" {
		t.Fatalf("same file again: %v", doc)
	}
	if doc := install(0, "--file", testAnchorsFile(t, "active", "revoked"), "--json"); doc["result"] != "replaced" || doc["previous_sha256"] == nil {
		t.Fatalf("other file: %v", doc)
	}

	invalid := filepath.Join(t.TempDir(), "bundle-anchors.json")
	if err := os.WriteFile(invalid, []byte(`{"schema_version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if doc := install(1, "--file", invalid, "--json"); errorCode(doc) != "anchor_invalid" {
		t.Fatalf("invalid source: %v", doc)
	}

	insecure := testAnchorsFile(t, "active")
	trusting := newUnixLifecycleEnv
	t.Cleanup(func() { newUnixLifecycleEnv = trusting })
	newUnixLifecycleEnv = func(goos string) (*enterpriseunix.Env, error) {
		env, err := trusting(goos)
		if err == nil {
			env.Trust = func(path string, _ enterpriseunix.TrustKind) error {
				if path == insecure {
					return errors.New("the file is writable by group staff")
				}
				return nil
			}
		}
		return env, err
	}
	if doc := install(1, "--file", insecure, "--json"); errorCode(doc) != "anchor_insecure" {
		t.Fatalf("insecure source: %v", doc)
	}
	newUnixLifecycleEnv = trusting

	install(2, "--json")
	install(2, "--file", first, "--lock-wait", "1h", "--json")

	lock, err := os.OpenFile(filepath.Join(root, layout.LifecycleDir, "lifecycle.lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	if doc := install(75, "--file", first, "--lock-wait", "1s", "--json"); errorCode(doc) != "lifecycle_busy" {
		t.Fatalf("busy: %v", doc)
	}
	_ = lock.Close()

	*euid = 1000
	if doc := install(1, "--file", first, "--json"); errorCode(doc) != "not_root" {
		t.Fatalf("not root: %v", doc)
	}
}

// TestBundleApplyForwardsDeliveryID pins F10 on Linux and macOS: apply takes
// --delivery-id (empty by default) and hands it to the ensure run that
// writes the receipt.
func TestBundleApplyForwardsDeliveryID(t *testing.T) {
	cmd := newEnterpriseBundleApplyCommand()
	if got, err := cmd.Flags().GetString("delivery-id"); err != nil || got != "" {
		t.Fatalf("--delivery-id default %q, %v", got, err)
	}
	if err := cmd.Flags().Parse([]string{"--bundle", "/x.dcbundle", "--delivery-id", "agent-7:d.1"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := cmd.Flags().GetString("delivery-id"); got != "agent-7:d.1" {
		t.Fatalf("--delivery-id parsed as %q", got)
	}
	for _, want := range []string{"", "agent-7:d.1"} {
		opts := unixBundleApplyOptions(&bundleApplyOptions{inbox: true, reason: "management", deliveryID: want}, "")
		if opts.DeliveryID != want || !opts.BundleInbox || opts.Reason != "management" || opts.Action != enterpriseunix.ActionEnsure {
			t.Fatalf("options %+v, want delivery id %q", opts, want)
		}
	}
}
