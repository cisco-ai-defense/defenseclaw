// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/hookruntime"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

const ownedCodexOTLPFixture = `[otel.exporter.otlp-http]
endpoint = "http://127.0.0.1:18970/v1/logs"

[otel.exporter.otlp-http.headers]
x-defenseclaw-source = "codex"
x-defenseclaw-client = "codex-otel/1.0"
`

// connectorConfigHomeTempDir returns a real path on macOS, where the Go test
// root is commonly reported below /var even though /var is a system symlink to
// /private/var. Lifecycle config-home validation intentionally rejects every
// symlink in the supplied path, so security tests must not accidentally use
// that ambient alias as their supposedly safe fixture root.
func connectorConfigHomeTempDir(t *testing.T) string {
	t.Helper()
	root := testenv.PrivateTempDir(t)
	if runtime.GOOS == "windows" {
		return root
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("resolve temporary config-home root: %v", err)
	}
	return resolved
}

func TestBindConnectorLifecycleConfigHomeOverridesAmbientAndRestoresIt(t *testing.T) {
	root := connectorConfigHomeTempDir(t)
	ambient := filepath.Join(root, "ambient")
	bound := filepath.Join(root, "bound")
	t.Setenv("CODEX_HOME", ambient)
	connectorFlagConfigHome = bound
	t.Cleanup(func() { connectorFlagConfigHome = "" })

	restore, err := bindConnectorLifecycleConfigHome("codex")
	if err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("CODEX_HOME"); got != bound {
		t.Fatalf("bound CODEX_HOME = %q, want %q", got, bound)
	}
	restore()
	if got := os.Getenv("CODEX_HOME"); got != ambient {
		t.Fatalf("restored CODEX_HOME = %q, want %q", got, ambient)
	}
}

func TestBindWindsurfLifecycleProfileOverridesAmbientAndRestoresIt(t *testing.T) {
	root := connectorConfigHomeTempDir(t)
	ambient := filepath.Join(root, "ambient-profile")
	bound := filepath.Join(root, "bound-profile")
	for _, path := range []string{ambient, bound} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	homeEnv := "HOME"
	switch runtime.GOOS {
	case "windows":
		homeEnv = "USERPROFILE"
	case "plan9":
		homeEnv = "home"
	}
	t.Setenv(homeEnv, ambient)
	connectorFlagConfigHome = bound
	t.Cleanup(func() { connectorFlagConfigHome = "" })

	restore, err := bindConnectorLifecycleConfigHome("windsurf")
	if err != nil {
		t.Fatal(err)
	}
	wantBound := filepath.Join(bound, ".codeium", "windsurf", "hooks.json")
	if got := connector.NewWindsurfConnector().Capabilities(
		connector.SetupOpts{},
	).Hooks.ConfigPath; filepath.Clean(got) != filepath.Clean(wantBound) {
		t.Fatalf("bound Windsurf hooks path = %q, want %q", got, wantBound)
	}
	restore()
	wantAmbient := filepath.Join(ambient, ".codeium", "windsurf", "hooks.json")
	if got := connector.NewWindsurfConnector().Capabilities(
		connector.SetupOpts{},
	).Hooks.ConfigPath; filepath.Clean(got) != filepath.Clean(wantAmbient) {
		t.Fatalf("restored Windsurf hooks path = %q, want ambient %q", got, wantAmbient)
	}
}

func TestBindAntigravityLifecycleConfigHomeUsesHiddenOptsWithoutVendorEnv(t *testing.T) {
	root := connectorConfigHomeTempDir(t)
	ambient := filepath.Join(root, "ambient")
	bound := filepath.Join(root, ".gemini", "config")
	t.Setenv("ANTIGRAVITY_CONFIG_DIR", ambient)
	t.Setenv("GEMINI_CONFIG_DIR", filepath.Join(root, "gemini-ambient"))
	connectorFlagConfigHome = bound
	t.Cleanup(func() { connectorFlagConfigHome = "" })

	restore, err := bindConnectorLifecycleConfigHome("antigravity")
	if err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("ANTIGRAVITY_CONFIG_DIR"); got != ambient {
		t.Fatalf("ANTIGRAVITY_CONFIG_DIR was mutated to %q", got)
	}
	opts := resolveConnectorOpts("")
	if got := connector.NewAntigravityConnector().Capabilities(opts).Hooks.ConfigPath; got != filepath.Join(bound, "hooks.json") {
		t.Fatalf("hidden Antigravity config home resolved to %q", got)
	}
	restore()
	if got := os.Getenv("ANTIGRAVITY_CONFIG_DIR"); got != ambient {
		t.Fatalf("restored ANTIGRAVITY_CONFIG_DIR = %q, want %q", got, ambient)
	}
}

func TestBindOpenCodeLifecycleConfigHomeOverridesAmbientAndRestoresIt(t *testing.T) {
	ambient := filepath.Join(connectorConfigHomeTempDir(t), "ambient-opencode")
	bound := filepath.Join(connectorConfigHomeTempDir(t), "bound-opencode")
	t.Setenv("OPENCODE_CONFIG_DIR", ambient)
	connectorFlagConfigHome = bound
	t.Cleanup(func() { connectorFlagConfigHome = "" })

	restore, err := bindConnectorLifecycleConfigHome("opencode")
	if err != nil {
		t.Fatalf("bind OpenCode config home: %v", err)
	}
	if got := os.Getenv("OPENCODE_CONFIG_DIR"); got != bound {
		t.Fatalf("OPENCODE_CONFIG_DIR = %q, want %q", got, bound)
	}
	restore()
	if got := os.Getenv("OPENCODE_CONFIG_DIR"); got != ambient {
		t.Fatalf("restored OPENCODE_CONFIG_DIR = %q, want %q", got, ambient)
	}
}

func TestBindHermesLifecycleConfigHomeOverridesAmbientAndRestoresIt(t *testing.T) {
	root := connectorConfigHomeTempDir(t)
	ambient := filepath.Join(root, "ambient-hermes")
	bound := filepath.Join(root, "bound-hermes")
	t.Setenv("HERMES_HOME", ambient)
	connectorFlagConfigHome = bound
	connectorFlagHookExe = filepath.Join(root, "HookRuntime", "defenseclaw-hook.exe")
	previousPaths := connectorHookRuntimePaths
	connectorHookRuntimePaths = func() (hookruntime.Paths, error) {
		return hookruntime.Paths{Launcher: connectorFlagHookExe}, nil
	}
	t.Cleanup(func() {
		connectorFlagConfigHome = ""
		connectorFlagHookExe = ""
		connectorHookRuntimePaths = previousPaths
	})

	restore, err := bindConnectorLifecycleConfigHome("hermes")
	if err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("HERMES_HOME"); got != bound {
		t.Fatalf("bound HERMES_HOME = %q, want %q", got, bound)
	}
	restore()
	if got := os.Getenv("HERMES_HOME"); got != ambient {
		t.Fatalf("restored HERMES_HOME = %q, want %q", got, ambient)
	}
}

func TestHermesLifecycleHookExecutableBindingRequiresExactNativePath(t *testing.T) {
	root := connectorConfigHomeTempDir(t)
	home := filepath.Join(root, "hermes")
	valid := filepath.Join(root, "HookRuntime", "defenseclaw-hook.exe")
	previousPaths := connectorHookRuntimePaths
	connectorHookRuntimePaths = func() (hookruntime.Paths, error) {
		return hookruntime.Paths{Launcher: valid}, nil
	}
	t.Cleanup(func() { connectorHookRuntimePaths = previousPaths })
	for name, executable := range map[string]string{
		"missing":        "",
		"relative":       filepath.Join("HookRuntime", "defenseclaw-hook.exe"),
		"wrong basename": filepath.Join(root, "HookRuntime", "defenseclaw-gateway.exe"),
		"foreign path":   filepath.Join(root, "OtherRuntime", "defenseclaw-hook.exe"),
		"quoted":         `"` + valid + `"`,
		"newline":        valid + "\nother.exe",
	} {
		t.Run(name, func(t *testing.T) {
			connectorFlagHookExe = executable
			t.Cleanup(func() { connectorFlagHookExe = "" })
			if err := validateConnectorLifecycleHookExecutable("hermes", home); err == nil {
				t.Fatalf("unsafe Hermes maintenance hook executable %q was accepted", executable)
			}
		})
	}

	connectorFlagHookExe = valid
	t.Cleanup(func() { connectorFlagHookExe = "" })
	if err := validateConnectorLifecycleHookExecutable("hermes", home); err != nil {
		t.Fatalf("valid Hermes maintenance hook executable rejected: %v", err)
	}
	opts := resolveConnectorOpts(filepath.Join(root, "data"))
	if opts.HookExecutable != valid {
		t.Fatalf("resolved HookExecutable = %q, want exact %q", opts.HookExecutable, valid)
	}
}

func TestBindConnectorLifecycleConfigHomeRejectsUnsafeTargets(t *testing.T) {
	root := connectorConfigHomeTempDir(t)
	unnormalized := root + string(filepath.Separator) + "child" + string(filepath.Separator) + ".." + string(filepath.Separator) + "codex"
	for _, test := range []struct {
		name      string
		home      string
		connector string
		want      string
	}{
		{name: "relative", home: "relative", connector: "codex", want: "absolute normalized path"},
		{name: "unnormalized", home: unnormalized, connector: "codex", want: "absolute normalized path"},
		{name: "newline", home: root + "\nother", connector: "codex", want: "absolute normalized path"},
		{name: "unsupported", home: filepath.Join(root, "home"), connector: "openclaw", want: "unsupported for connector"},
	} {
		t.Run(test.name, func(t *testing.T) {
			connectorFlagConfigHome = test.home
			t.Cleanup(func() { connectorFlagConfigHome = "" })
			_, err := bindConnectorLifecycleConfigHome(test.connector)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestConnectorVerifyUsesExplicitConfigHomeWithoutMutation(t *testing.T) {
	root := connectorConfigHomeTempDir(t)
	dataDir := filepath.Join(root, "data")
	ambient := filepath.Join(root, "ambient")
	bound := filepath.Join(root, "bound")
	if err := os.MkdirAll(bound, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(bound, "config.toml")
	wantConfig := []byte(ownedCodexOTLPFixture)
	if err := os.WriteFile(configPath, wantConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CODEX_HOME", ambient)
	defer withConnectorState(t, dataDir, "codex")()

	stdout, stderr, exitCode := runConnectorCmd(
		t,
		"verify",
		"--connector", "codex",
		"--data-dir", dataDir,
		"--config-home", bound,
		"--json",
	)
	if exitCode != 1 || stderr != "" || !strings.Contains(stdout, "config.toml [otel]") {
		t.Fatalf("explicit-home verify: exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	gotConfig, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotConfig, wantConfig) {
		t.Fatal("explicit-home verification mutated the live configuration fixture")
	}
	if got := os.Getenv("CODEX_HOME"); got != ambient {
		t.Fatalf("CODEX_HOME after verify = %q, want restored ambient %q", got, ambient)
	}
}

func TestCursorVerifyUsesExplicitConfigHomeWithoutVendorEnvironmentOverride(t *testing.T) {
	root := connectorConfigHomeTempDir(t)
	dataDir := connectorConfigHomeTempDir(t)
	bound := filepath.Join(root, "cursor")
	if err := os.MkdirAll(bound, 0o700); err != nil {
		t.Fatal(err)
	}
	adapterName := "cursor-hook.sh"
	commandPrefix := "'"
	commandSuffix := "'"
	if runtime.GOOS == "windows" {
		adapterName = "cursor-hook.ps1"
		commandPrefix = "& '"
	}
	adapter := filepath.Join(dataDir, "hooks", adapterName)
	config := []byte(`{"version":1,"hooks":{"preToolUse":[{"type":"command","command":"` +
		commandPrefix + strings.ReplaceAll(adapter, `\`, `\\`) + commandSuffix +
		`","timeout":30,"failClosed":false}]}}`)
	configPath := filepath.Join(bound, "hooks.json")
	if err := os.WriteFile(configPath, config, 0o600); err != nil {
		t.Fatal(err)
	}
	defer withConnectorState(t, dataDir, "cursor")()

	stdout, stderr, exitCode := runConnectorCmd(
		t,
		"verify",
		"--connector", "cursor",
		"--data-dir", dataDir,
		"--config-home", bound,
		"--json",
	)
	if exitCode != 1 || stderr != "" ||
		!strings.Contains(stdout, `"clean":false`) ||
		!strings.Contains(stdout, "cursor-hook") {
		t.Fatalf("Cursor explicit-home verify: exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	gotConfig, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotConfig, config) {
		t.Fatal("Cursor explicit-home verification mutated hooks.json")
	}
	if _, exists := os.LookupEnv("CURSOR_HOME"); exists {
		t.Fatal("Cursor maintenance invented a vendor CURSOR_HOME environment override")
	}
}

func TestCursorReconcileWritesOnlyExplicitConfigHome(t *testing.T) {
	root := connectorConfigHomeTempDir(t)
	dataDir := connectorConfigHomeTempDir(t)
	bound := filepath.Join(root, "cursor")
	for _, path := range []string{bound} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := validateConnectorLifecycleConfigHomePath(dataDir); err != nil {
		t.Fatal(err)
	}
	defer withConnectorState(t, dataDir, "cursor")()
	if _, err := connector.EnsureHookAPIToken(dataDir, "cursor"); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, _ := runConnectorCmd(
		t,
		"reconcile",
		"--connector", "cursor",
		"--data-dir", dataDir,
		"--config-home", bound,
		"--json",
	)
	if !strings.Contains(stdout, `"connector":"cursor"`) ||
		!strings.Contains(stdout, `"fail_mode":"open"`) ||
		(stderr != "" && !strings.Contains(stderr, "preview on ")) {
		t.Fatalf("Cursor reconcile: stdout=%q stderr=%q", stdout, stderr)
	}
	hooksPath := filepath.Join(bound, "hooks.json")
	hooks, err := os.ReadFile(hooksPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(hooks, []byte(`"failClosed": false`)) ||
		!bytes.Contains(hooks, []byte(`"preToolUse"`)) {
		t.Fatalf("Cursor reconcile wrote an incomplete registration: %s", hooks)
	}
	if lock := connector.LoadHookContractLockEntry(dataDir, "cursor"); lock.HookFailMode != "open" {
		t.Fatalf("Cursor observe lock fail mode = %q, want open", lock.HookFailMode)
	}
}

func TestConnectorConfigHomeFlagIsMaintenanceOnly(t *testing.T) {
	flag := connectorCmd.PersistentFlags().Lookup("config-home")
	if flag == nil || !flag.Hidden {
		t.Fatal("config-home flag must remain hidden from the operator surface")
	}
}

func TestConnectorHookExecutableFlagIsMaintenanceOnly(t *testing.T) {
	flag := connectorCmd.PersistentFlags().Lookup("hook-executable")
	if flag == nil || !flag.Hidden {
		t.Fatal("hook-executable flag must remain hidden from the operator surface")
	}
}

func TestBindConnectorLifecycleConfigHomeRejectsSymlinkChain(t *testing.T) {
	root := connectorConfigHomeTempDir(t)
	target := filepath.Join(root, "target")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("synthetic symlink fixture unavailable: %v", err)
	}
	connectorFlagConfigHome = filepath.Join(link, "child")
	t.Cleanup(func() { connectorFlagConfigHome = "" })
	_, err := bindConnectorLifecycleConfigHome("codex")
	if err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("error = %v, want unsafe path refusal", err)
	}
}
