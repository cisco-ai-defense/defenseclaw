// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// cursorTestSetup wires the cursor connector to a temp config path and returns
// a connector + opts ready for Setup. The path override is reset on cleanup so
// it never leaks across tests in this package.
func cursorTestSetup(t *testing.T) (Connector, SetupOpts, string) {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "hooks.json")
	prev := CursorHooksPathOverride
	CursorHooksPathOverride = cfgPath
	t.Cleanup(func() { CursorHooksPathOverride = prev })
	opts := SetupOpts{
		DataDir:      t.TempDir(),
		APIAddr:      "127.0.0.1:18970",
		APIToken:     "tok-test",
		WorkspaceDir: t.TempDir(),
	}
	return NewCursorConnector(), opts, cfgPath
}

func TestHookConfigPathsForConnector_ResolvesOverride(t *testing.T) {
	conn, opts, cfgPath := cursorTestSetup(t)

	paths := HookConfigPathsForConnector(conn, opts)
	if len(paths) != 1 {
		t.Fatalf("HookConfigPathsForConnector = %v, want exactly the cursor hooks path", paths)
	}
	if paths[0] != cfgPath {
		t.Fatalf("HookConfigPathsForConnector[0] = %q, want %q", paths[0], cfgPath)
	}
}

func TestHookConfigPathsForConnector_ProxyConnectorsAreInert(t *testing.T) {
	opts := SetupOpts{DataDir: t.TempDir(), ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970"}
	for _, conn := range []Connector{NewOpenClawConnector(), NewZeptoClawConnector()} {
		if paths := HookConfigPathsForConnector(conn, opts); paths != nil {
			t.Errorf("%s: HookConfigPathsForConnector = %v, want nil (proxy/plugin connector must be inert)", conn.Name(), paths)
		}
	}
}

func TestHookConfigPathsForConnector_NilConnector(t *testing.T) {
	if paths := HookConfigPathsForConnector(nil, SetupOpts{}); paths != nil {
		t.Fatalf("HookConfigPathsForConnector(nil) = %v, want nil", paths)
	}
}

func TestOwnedHooksPresent_TrueAfterSetup_FalseAfterRemoval(t *testing.T) {
	conn, opts, cfgPath := cursorTestSetup(t)

	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	present, err := OwnedHooksPresent(conn, opts)
	if err != nil {
		t.Fatalf("OwnedHooksPresent after Setup: %v", err)
	}
	if !present {
		data, _ := os.ReadFile(cfgPath)
		t.Fatalf("OwnedHooksPresent=false after Setup; config:\n%s", data)
	}

	// Strip the hook block: an empty JSON object no longer references our
	// hook command.
	if err := os.WriteFile(cfgPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("strip config: %v", err)
	}
	present, err = OwnedHooksPresent(conn, opts)
	if err != nil {
		t.Fatalf("OwnedHooksPresent after strip: %v", err)
	}
	if present {
		t.Fatal("OwnedHooksPresent=true after stripping the hook block; want false")
	}
}

func TestOwnedHooksPresent_FalseWhenFileMissing(t *testing.T) {
	conn, opts, cfgPath := cursorTestSetup(t)

	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if err := os.Remove(cfgPath); err != nil {
		t.Fatalf("remove config: %v", err)
	}

	present, err := OwnedHooksPresent(conn, opts)
	if err != nil {
		t.Fatalf("OwnedHooksPresent with missing file returned error: %v", err)
	}
	if present {
		t.Fatal("OwnedHooksPresent=true for a deleted config file; want false")
	}
}

func TestOwnedHooksPresent_ProxyConnectorReportsPresent(t *testing.T) {
	// Proxy/plugin connectors have no guarded hook config paths, so they
	// are reported present (never heal-eligible).
	opts := SetupOpts{DataDir: t.TempDir(), ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970"}
	present, err := OwnedHooksPresent(NewOpenClawConnector(), opts)
	if err != nil {
		t.Fatalf("OwnedHooksPresent: %v", err)
	}
	if !present {
		t.Fatal("OwnedHooksPresent=false for proxy connector; want true (inert)")
	}
}

// TestOwnedHookNeedles_WindowsSurvivesConfigEscaping guards the Windows
// presence-detection path. On Windows the agent config stores the native
// invocation (`"C:\...\defenseclaw-gateway.exe" hook --connector <name>`),
// whose backslashes and quotes are escaped when serialized into JSON/TOML.
// The needle must therefore key on an escaping-invariant marker, not the full
// command, or OwnedHooksPresent would false-negative on every check and the
// guard would spuriously re-install hooks. This test runs on any host because
// the OS is parameterized.
func TestOwnedHookNeedles_WindowsSurvivesConfigEscaping(t *testing.T) {
	opts := SetupOpts{DataDir: `C:\Users\me\AppData\Local\defenseclaw`}
	conn := NewCursorConnector()

	needles := ownedHookCommandNeedlesFor("windows", opts, conn)
	if len(needles) != 1 || needles[0] != nativeHookFlag+conn.Name() {
		t.Fatalf("windows needles = %v, want [%q]", needles, nativeHookFlag+conn.Name())
	}

	// What Setup actually writes on Windows: the native command embedded in a
	// JSON config, where the exe path's backslashes/quotes get escaped.
	winCmd := `"C:\Users\me\AppData\Local\defenseclaw\defenseclaw-gateway.exe" ` + nativeHookFlag + conn.Name()
	encoded, err := json.Marshal(map[string]string{"command": winCmd})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// The full raw command must NOT appear in the escaped bytes (this is the
	// failure mode the marker avoids) ...
	if bytes.Contains(encoded, []byte(winCmd)) {
		t.Fatalf("precondition: expected JSON to escape the windows command, but it appeared verbatim:\n%s", encoded)
	}
	// ... while the escaping-invariant marker IS present.
	for _, n := range needles {
		if !bytes.Contains(encoded, []byte(n)) {
			t.Fatalf("windows needle %q not found in escaped config:\n%s", n, encoded)
		}
	}
}

func TestConfigFileReferencesHookIgnoresDecoyPathOutsideCommandField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	needle := "/home/alice/.defenseclaw/hooks/cursor-hook.sh"
	data := []byte(`{"hooks":{"beforeSubmitPrompt":[{"note":"` + needle + `"}]}}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write hook config: %v", err)
	}
	present, err := configFileReferencesHook(path, []string{needle})
	if err != nil {
		t.Fatalf("configFileReferencesHook: %v", err)
	}
	if present {
		t.Fatal("decoy path outside command field was treated as a managed hook")
	}
}

func TestConfigFileReferencesHookRejectsWrapperCommand(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	needle := "/home/alice/.defenseclaw/hooks/cursor-hook.sh"
	data := []byte(`{"hooks":{"beforeSubmitPrompt":[{"command":"echo ` + needle + `"}]}}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write hook config: %v", err)
	}
	present, err := configFileReferencesHook(path, []string{needle})
	if err != nil {
		t.Fatalf("configFileReferencesHook: %v", err)
	}
	if present {
		t.Fatal("wrapper command was treated as an enforcing managed hook")
	}
}

func TestConfigFileReferencesHookAcceptsManagedCommandField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	needle := "/home/alice/.defenseclaw/hooks/cursor-hook.sh"
	data := []byte(`{"hooks":{"beforeSubmitPrompt":[{"command":"'` + needle + `'"}]}}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write hook config: %v", err)
	}
	present, err := configFileReferencesHook(path, []string{needle})
	if err != nil {
		t.Fatalf("configFileReferencesHook: %v", err)
	}
	if !present {
		t.Fatal("managed command field was not detected")
	}
}

func TestConfigFileReferencesHookAcceptsNestedTOMLCommand(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.toml")
	needle := "/home/alice/.defenseclaw/hooks/codex-hook.sh"
	data := []byte("[[hooks.beforeSubmitPrompt]]\ncommand = \"'" + needle + "'\"\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write hook config: %v", err)
	}
	present, err := configFileReferencesHook(path, []string{needle})
	if err != nil {
		t.Fatalf("configFileReferencesHook: %v", err)
	}
	if !present {
		t.Fatal("nested TOML command field was not detected")
	}
}
