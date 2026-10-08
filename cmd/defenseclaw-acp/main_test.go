// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"testing"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"time"
)

// An editor entry left over after `acp remove` starts a guard whose contract
// lock is gone. The editor must get a JSON-RPC error with a next step, not a
// closed pipe and an internal term on stderr (GAP-2197).
func TestRemovedBindingAnswersInitializeWithPlainError(t *testing.T) {
	dir := t.TempDir()
	err := run([]string{
		"--client", "zed", "--agent", "kiro", "--profile", "vb9kiro", "--mode", "action",
		"--contract-lock", filepath.Join(dir, "missing.lock.json"),
		"--token-file", filepath.Join(dir, "token"),
		"--", filepath.Join(dir, "kiro-cli"),
	})
	var startup *startupError
	if !errors.As(err, &startup) {
		t.Fatalf("run() error = %v, want a startup error", err)
	}
	for _, want := range []string{
		"not set up for zed/kiro",
		"defenseclaw acp setup --client zed --agent kiro --profile vb9kiro --activate",
		"delete this editor entry",
	} {
		if !strings.Contains(startup.message, want) {
			t.Fatalf("message %q does not contain %q", startup.message, want)
		}
	}
	if strings.Contains(startup.message, "unsafe") {
		t.Fatalf("message %q still uses internal wording", startup.message)
	}

	in := strings.NewReader(`{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":1}}` + "\n")
	var out bytes.Buffer
	if !answerFirstRequest(in, &out, startup.message, time.Second) {
		t.Fatal("answerFirstRequest wrote no response")
	}
	var resp struct {
		ID    json.RawMessage `json:"id"`
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &resp); err != nil {
		t.Fatalf("response %q is not JSON: %v", out.String(), err)
	}
	if string(resp.ID) != "0" || resp.Error.Code != startupErrorCode || resp.Error.Message != startup.message {
		t.Fatalf("unexpected response %s", out.String())
	}
}

// A managed host has only the gateway binary; the guard told its users to
// run the Python CLI commands of a per-user install (GAP-0270).
func TestManagedGuardStartFailureNamesTheGatewaySetup(t *testing.T) {
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	dir := t.TempDir()
	gateway, want := filepath.Join(dir, "defenseclaw-gateway"), ""
	if runtime.GOOS == "windows" {
		gateway = filepath.Join(dir, "defenseclaw.exe")
		want = "& \"" + gateway + "\" enterprise acp setup --client zed --agent hermes --profile ih3acp"
	} else {
		want = gateway + " enterprise acp setup --client zed --agent hermes --profile ih3acp"
	}
	lock := filepath.Join(dir, "zed-hermes.contract-lock.json")
	for path, body := range map[string]string{gateway: "gateway\n", lock: `{"guard":{"managed_custody":true}}`} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	previous, previousLayout, previousLoad := guardExecutable, managedACPStandaloneLayout, loadACPStandaloneDescriptor
	t.Cleanup(func() {
		guardExecutable, managedACPStandaloneLayout, loadACPStandaloneDescriptor = previous, previousLayout, previousLoad
	})
	guardExecutable = func() (string, error) { return filepath.Join(dir, "defenseclaw-acp"), nil }
	// Windows has no runtime descriptor: a guard in the standalone bin
	// folder is managed (GAP-0902).
	managedACPStandaloneLayout = func() (managed.StandaloneLayout, error) {
		return managed.StandaloneLayout{DescriptorPath: filepath.Join(dir, "managed-runtime.json"), BinDir: dir}, nil
	}
	loadACPStandaloneDescriptor = func(string) (*managed.RuntimeDescriptor, error) { return nil, managed.ErrNoRuntimeDescriptor }
	missing := &tokenCopyError{path: filepath.Join(dir, "zed-hermes.token"), err: errors.New("stat token file: no such file")}
	var startup *startupError
	if !errors.As(newStartupError(missing, "zed", "hermes", "ih3acp", "observe", lock), &startup) {
		t.Fatal("want a startup error")
	}
	if !strings.Contains(startup.message, "enroll you again (enterprise acp enroll)") || !strings.Contains(startup.message, want) ||
		!strings.Contains(startup.message, "setup cannot restore it") || strings.Contains(startup.message, "defenseclaw acp ") {
		t.Fatalf("the managed remediation names commands this host lacks or sends the user to setup: %q", startup.message)
	}
}

// An explicit Secure Client profile keeps main's available setup guidance
// byte for byte, even with an old managed-custody lock and adjacent gateway.
func TestSecureClientGuardStartupKeepsMainErrorBytes(t *testing.T) {
	dir := t.TempDir()
	gateway := filepath.Join(dir, "defenseclaw-gateway")
	if runtime.GOOS == "windows" {
		gateway = filepath.Join(dir, "defenseclaw.exe")
	}
	lock := filepath.Join(dir, "binding.json")
	for path, body := range map[string]string{
		gateway: "gateway", lock: `{"guard":{"managed_custody":true}}`,
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileSecureClient)
	previous := guardExecutable
	t.Cleanup(func() { guardExecutable = previous })
	guardExecutable = func() (string, error) { return filepath.Join(dir, "defenseclaw-acp"), nil }
	for _, test := range []struct {
		err  error
		want string
	}{
		{acp.ErrRuntimeContractMissing,
			"DefenseClaw ACP guard is not set up for zed/hermes (the binding was removed). Run 'defenseclaw acp setup --client zed --agent hermes --profile locked', or delete this editor entry."},
		{errors.New("stat token file: no such file"),
			"DefenseClaw ACP guard could not start for zed/hermes: stat token file: no such file. Run 'defenseclaw acp verify', then 'defenseclaw acp setup --client zed --agent hermes --profile locked', or delete this editor entry."},
	} {
		startup := newStartupError(test.err, "zed", "hermes", "locked", "observe", lock)
		if startup.Error() != test.want {
			t.Fatalf("startup error = %q, want %q", startup, test.want)
		}
		in := strings.NewReader(`{"jsonrpc":"2.0","id":0,"method":"initialize"}` + "\n")
		var out bytes.Buffer
		if !answerFirstRequest(in, &out, startup.Error(), time.Second) {
			t.Fatal("no JSON-RPC response")
		}
		wantResponse := fmt.Sprintf(`{"jsonrpc":"2.0","id":0,"error":{"code":%d,"message":%q}}`+"\n", startupErrorCode, test.want)
		if out.String() != wantResponse {
			t.Fatalf("JSON-RPC bytes = %q, want %q", out.String(), wantResponse)
		}
	}
}

func TestAnswerFirstRequestGivesUpWithoutARequest(t *testing.T) {
	reader, writer := io.Pipe()
	defer writer.Close()
	var out bytes.Buffer
	if answerFirstRequest(reader, &out, "x", 20*time.Millisecond) || out.Len() != 0 {
		t.Fatalf("expected no response, got %q", out.String())
	}
}
