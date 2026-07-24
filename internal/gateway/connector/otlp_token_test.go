// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// TestIsValidOTLPScope_NegativeCases protects the lazy-reload path
// in api.go's lookupOTLPPathToken: every disk-touching code path is
// gated by IsValidOTLPScope, so a regression that accepts arbitrary
// strings here would turn the OTLP auth check into a per-request
// disk syscall stampede primitive — exactly the M1 risk we are
// closing.
//
// The cases below cover the four shape classes we expect attackers
// to probe with: path traversal, case mismatches, control characters,
// and length / Unicode tricks. Anything that returns true must be in
// OTLPPathTokenScopes() and pass the on-disk regex; every other shape
// must return false.
func TestIsValidOTLPScope_NegativeCases(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		scope OTLPPathTokenScope
		want  bool
	}{
		{"empty", "", false},
		{"validCodex", OTLPScopeCodex, true},
		{"validGemini", OTLPScopeGeminiCLI, true},
		{"validCodex", OTLPScopeCodex, true},
		{"validClaude", OTLPScopeClaude, true},
		{"upper", "GEMINICLI", false},
		{"trailingSpace", "geminicli ", false},
		{"leadingSpace", " geminicli", false},
		{"pathTraversal", "../etc/passwd", false},
		{"forwardSlash", "geminicli/extra", false},
		{"newline", "geminicli\nclaude", false},
		{"nul", "\x00", false},
		{"nulSuffix", "geminicli\x00", false},
		{"unicodeHomoglyph", "geminіcli", false}, // contains Cyrillic 'і' (U+0456)
		{"plus", "gemini+cli", false},
		{"unknownVendor", "openai", false},
		{"length128", OTLPPathTokenScope(repeat('a', 128)), false},
		{"underscore", "gemini_cli", false}, // underscore not in scope list
		{"dotPrefix", ".geminicli", false},
		{"dashOnly", "-", false},
		{"singleChar", "g", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsValidOTLPScope(tc.scope)
			if got != tc.want {
				t.Errorf("IsValidOTLPScope(%q) = %v, want %v", string(tc.scope), got, tc.want)
			}
		})
	}
}

func TestEnsureOTLPPathToken_IsolatesConnectorScopes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	codex, err := EnsureOTLPPathToken(dir, OTLPScopeCodex)
	if err != nil {
		t.Fatalf("EnsureOTLPPathToken(codex): %v", err)
	}
	gemini, err := EnsureOTLPPathToken(dir, OTLPScopeGeminiCLI)
	if err != nil {
		t.Fatalf("EnsureOTLPPathToken(geminicli): %v", err)
	}
	if codex == "" || gemini == "" || codex == gemini {
		t.Fatal("connector OTLP scopes did not receive distinct non-empty credentials")
	}
	for _, scope := range []OTLPPathTokenScope{OTLPScopeCodex, OTLPScopeGeminiCLI} {
		path, err := OTLPPathTokenFilePath(dir, scope)
		if err != nil {
			t.Fatalf("OTLPPathTokenFilePath(%s): %v", scope, err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat scoped token %s: %v", scope, err)
		}
		if got := info.Mode().Perm(); runtime.GOOS != "windows" && got != 0o600 {
			t.Errorf("scoped token %s mode=%#o want 0600", scope, got)
		}
	}
}

func TestRemoveOTLPPathToken_RevokesAndNextEnsureRotates(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	first, err := EnsureOTLPPathToken(dir, OTLPScopeCodex)
	if err != nil {
		t.Fatalf("initial EnsureOTLPPathToken: %v", err)
	}
	if err := RemoveOTLPPathToken(dir, OTLPScopeCodex); err != nil {
		t.Fatalf("RemoveOTLPPathToken: %v", err)
	}
	if got, err := LoadOTLPPathToken(dir, OTLPScopeCodex); err != nil || got != "" {
		t.Fatalf("removed token still loadable: present=%v err=%v", got != "", err)
	}
	second, err := EnsureOTLPPathToken(dir, OTLPScopeCodex)
	if err != nil {
		t.Fatalf("second EnsureOTLPPathToken: %v", err)
	}
	if second == "" || second == first {
		t.Fatal("re-provisioned Codex OTLP token was not rotated")
	}
}

func TestCodexScopedOTLPToken_SetupTeardownRace(t *testing.T) {
	dir := t.TempDir()
	for iteration := 0; iteration < 50; iteration++ {
		start := make(chan struct{})
		errors := make(chan error, 2)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, err := EnsureOTLPPathToken(dir, OTLPScopeCodex)
			errors <- err
		}()
		go func() {
			defer wg.Done()
			<-start
			errors <- RemoveOTLPPathToken(dir, OTLPScopeCodex)
		}()
		close(start)
		wg.Wait()
		close(errors)
		for err := range errors {
			if err != nil {
				t.Fatalf("iteration %d concurrent setup/teardown: %v", iteration, err)
			}
		}
	}
	final, err := EnsureOTLPPathToken(dir, OTLPScopeCodex)
	if err != nil || final == "" {
		t.Fatalf("final setup failed after race: present=%v err=%v", final != "", err)
	}
	loaded, err := LoadOTLPPathToken(dir, OTLPScopeCodex)
	if err != nil || loaded != final {
		t.Fatalf("race left mismatched token state: matched=%v err=%v", loaded == final, err)
	}
	tokenPath, err := OTLPPathTokenFilePath(dir, OTLPScopeCodex)
	if err != nil {
		t.Fatal(err)
	}
	var temps []string
	for _, prefix := range otlpPathTokenOwnedTempPrefixes(tokenPath) {
		matches, globErr := filepath.Glob(filepath.Join(filepath.Dir(tokenPath), prefix+"*"))
		if globErr != nil {
			t.Fatalf("glob token temp files: %v", globErr)
		}
		temps = append(temps, matches...)
	}
	if len(temps) != 0 {
		t.Fatalf("race left token temp files: count=%d", len(temps))
	}
}

func TestCodexScopedOTLPToken_CrossProcessSetupTeardownRace(t *testing.T) {
	dir := t.TempDir()
	for iteration := 0; iteration < 10; iteration++ {
		setup := exec.Command(os.Args[0], "-test.run=^TestOTLPPathTokenCrossProcessHelper$")
		setup.Env = append(os.Environ(), "DEFENSECLAW_OTLP_TOKEN_HELPER=ensure", "DEFENSECLAW_OTLP_TOKEN_HELPER_DIR="+dir)
		teardown := exec.Command(os.Args[0], "-test.run=^TestOTLPPathTokenCrossProcessHelper$")
		teardown.Env = append(os.Environ(), "DEFENSECLAW_OTLP_TOKEN_HELPER=remove", "DEFENSECLAW_OTLP_TOKEN_HELPER_DIR="+dir)
		if err := setup.Start(); err != nil {
			t.Fatalf("iteration %d start setup helper: %v", iteration, err)
		}
		teardownErr := teardown.Run()
		setupErr := setup.Wait()
		if setupErr != nil || teardownErr != nil {
			t.Fatalf("iteration %d cross-process setup=%v teardown=%v", iteration, setupErr, teardownErr)
		}
	}
	final, err := EnsureOTLPPathToken(dir, OTLPScopeCodex)
	if err != nil || final == "" {
		t.Fatalf("final setup after cross-process race: present=%v err=%v", final != "", err)
	}
	loaded, err := LoadOTLPPathToken(dir, OTLPScopeCodex)
	if err != nil || loaded != final {
		t.Fatalf("cross-process race left invalid token: matched=%v err=%v", loaded == final, err)
	}
}

func TestOTLPPathTokenCrossProcessHelper(t *testing.T) {
	action := os.Getenv("DEFENSECLAW_OTLP_TOKEN_HELPER")
	if action == "" {
		t.Skip("subprocess helper")
	}
	dir := os.Getenv("DEFENSECLAW_OTLP_TOKEN_HELPER_DIR")
	var err error
	switch action {
	case "ensure":
		_, err = EnsureOTLPPathToken(dir, OTLPScopeCodex)
	case "remove":
		err = RemoveOTLPPathToken(dir, OTLPScopeCodex)
	default:
		t.Fatalf("unknown helper action")
	}
	if err != nil {
		t.Fatalf("%s scoped token: %v", action, err)
	}
}

// TestCodexLifecycle_CrossProcessSetupTeardownTransaction starts the two full
// connector lifecycles behind one barrier. The final winner is scheduler-
// dependent, but it must be one complete serial state: either installed config
// plus its matching live token, or restored config plus no token. The partial
// state this regression guards against is a successful Setup publishing the
// token Teardown revoked between EnsureOTLPPathToken and config.toml rename.
func TestCodexLifecycle_CrossProcessSetupTeardownTransaction(t *testing.T) {
	defer func() { CodexConfigPathOverride = "" }()
	for iteration := 0; iteration < 12; iteration++ {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "config.toml")
		if err := os.WriteFile(configPath, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
			t.Fatalf("iteration %d write initial config: %v", iteration, err)
		}
		CodexConfigPathOverride = configPath
		opts := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:18970", APIToken: "hook-token"}
		if err := NewCodexConnector().Setup(context.Background(), opts); err != nil {
			t.Fatalf("iteration %d initial Setup: %v", iteration, err)
		}

		barrier := filepath.Join(dir, "lifecycle-start")
		teardownReady := filepath.Join(dir, "teardown-ready")
		setupReady := filepath.Join(dir, "setup-ready")
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		teardown, teardownOutput := codexLifecycleHelperCommand(
			ctx, "teardown", dir, configPath, barrier, teardownReady,
		)
		setup, setupOutput := codexLifecycleHelperCommand(
			ctx, "setup", dir, configPath, barrier, setupReady,
		)
		if err := teardown.Start(); err != nil {
			cancel()
			t.Fatalf("iteration %d start Teardown helper: %v", iteration, err)
		}
		if err := setup.Start(); err != nil {
			_ = teardown.Process.Kill()
			cancel()
			t.Fatalf("iteration %d start Setup helper: %v", iteration, err)
		}
		if err := waitForCodexLifecycleFile(ctx, teardownReady); err != nil {
			_ = teardown.Process.Kill()
			_ = setup.Process.Kill()
			cancel()
			t.Fatalf("iteration %d Teardown readiness: %v", iteration, err)
		}
		if err := waitForCodexLifecycleFile(ctx, setupReady); err != nil {
			_ = teardown.Process.Kill()
			_ = setup.Process.Kill()
			cancel()
			t.Fatalf("iteration %d Setup readiness: %v", iteration, err)
		}
		if err := os.WriteFile(barrier, []byte("start\n"), 0o600); err != nil {
			_ = teardown.Process.Kill()
			_ = setup.Process.Kill()
			cancel()
			t.Fatalf("iteration %d release lifecycle barrier: %v", iteration, err)
		}

		type processResult struct {
			name string
			err  error
		}
		results := make(chan processResult, 2)
		go func() { results <- processResult{name: "teardown", err: teardown.Wait()} }()
		go func() { results <- processResult{name: "setup", err: setup.Wait()} }()
		for range 2 {
			result := <-results
			if result.err != nil {
				cancel()
				t.Fatalf(
					"iteration %d %s helper: %v\nteardown output:\n%s\nsetup output:\n%s",
					iteration, result.name, result.err, teardownOutput.String(), setupOutput.String(),
				)
			}
		}
		cancel()

		managed, err := codexConfigHasManagedOTLPEndpoint(configPath, opts)
		if err != nil {
			t.Fatalf("iteration %d inspect final config: %v", iteration, err)
		}
		token, err := LoadOTLPPathToken(dir, OTLPScopeCodex)
		if err != nil {
			t.Fatalf("iteration %d load final token: %v", iteration, err)
		}
		if managed {
			if token == "" {
				t.Fatalf("iteration %d stranded managed Codex config on a revoked token", iteration)
			}
			raw, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatalf("iteration %d read installed config: %v", iteration, err)
			}
			if got := strings.Count(string(raw), "Bearer "+token); got != 3 {
				t.Fatalf("iteration %d config references live scoped bearer %d times, want 3", iteration, got)
			}
			if strings.Contains(string(raw), "/otlp/codex/"+token) {
				t.Fatalf("iteration %d config leaked the scoped bearer into an OTLP endpoint", iteration)
			}
		} else if token != "" {
			t.Fatalf("iteration %d left an orphaned scoped token after restored config", iteration)
		}
	}
}

func codexLifecycleHelperCommand(
	ctx context.Context,
	action, dir, configPath, barrier, ready string,
) (*exec.Cmd, *bytes.Buffer) {
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCodexLifecycleCrossProcessHelper$")
	cmd.Env = append(
		os.Environ(),
		"DEFENSECLAW_CODEX_LIFECYCLE_HELPER="+action,
		"DEFENSECLAW_CODEX_LIFECYCLE_DIR="+dir,
		"DEFENSECLAW_CODEX_LIFECYCLE_CONFIG="+configPath,
		"DEFENSECLAW_CODEX_LIFECYCLE_BARRIER="+barrier,
		"DEFENSECLAW_CODEX_LIFECYCLE_READY="+ready,
	)
	output := &bytes.Buffer{}
	cmd.Stdout = output
	cmd.Stderr = output
	return cmd, output
}

func waitForCodexLifecycleFile(ctx context.Context, path string) error {
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		} else if !os.IsNotExist(err) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Millisecond):
		}
	}
}

func TestCodexLifecycleCrossProcessHelper(t *testing.T) {
	action := os.Getenv("DEFENSECLAW_CODEX_LIFECYCLE_HELPER")
	if action == "" {
		t.Skip("subprocess helper")
	}
	dir := os.Getenv("DEFENSECLAW_CODEX_LIFECYCLE_DIR")
	configPath := os.Getenv("DEFENSECLAW_CODEX_LIFECYCLE_CONFIG")
	barrier := os.Getenv("DEFENSECLAW_CODEX_LIFECYCLE_BARRIER")
	ready := os.Getenv("DEFENSECLAW_CODEX_LIFECYCLE_READY")
	CodexConfigPathOverride = configPath
	defer func() { CodexConfigPathOverride = "" }()
	if err := os.WriteFile(ready, []byte("ready\n"), 0o600); err != nil {
		t.Fatalf("publish helper readiness: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := waitForCodexLifecycleFile(ctx, barrier); err != nil {
		t.Fatalf("wait for lifecycle barrier: %v", err)
	}
	opts := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:18970", APIToken: "hook-token"}
	connector := NewCodexConnector()
	var err error
	switch action {
	case "setup":
		err = connector.Setup(ctx, opts)
	case "teardown":
		err = connector.Teardown(ctx, opts)
	default:
		t.Fatalf("unknown lifecycle action %q", action)
	}
	if err != nil {
		t.Fatalf("%s Codex lifecycle: %v", action, err)
	}
}

func repeat(b byte, n int) string {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = b
	}
	return string(buf)
}

func TestLoadOTLPPathToken_RejectsUnsafeFiles(t *testing.T) {
	t.Parallel()
	token := strings.Repeat("a", 64) + "\n"
	cases := []struct {
		name  string
		setup func(t *testing.T, path string)
	}{
		{
			name: "wide_mode",
			setup: func(t *testing.T, path string) {
				t.Helper()
				if runtime.GOOS == "windows" {
					t.Skip("POSIX mode bits do not represent an NTFS DACL; see native DACL coverage")
				}
				if err := os.WriteFile(path, []byte(token), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "symlink",
			setup: func(t *testing.T, path string) {
				t.Helper()
				if runtime.GOOS == "windows" {
					hooksDir := filepath.Dir(path)
					targetHooksDir := filepath.Join(t.TempDir(), "hooks")
					if err := os.Mkdir(targetHooksDir, 0o700); err != nil {
						t.Fatalf("create redirected hooks directory: %v", err)
					}
					target := filepath.Join(targetHooksDir, filepath.Base(path))
					if err := safefile.WritePrivate(target, []byte(token)); err != nil {
						t.Fatalf("write redirected token: %v", err)
					}
					if err := os.Remove(hooksDir); err != nil {
						t.Fatalf("remove empty hooks directory: %v", err)
					}
					createTestDirectoryRedirect(t, hooksDir, targetHooksDir)
					return
				}
				target := filepath.Join(filepath.Dir(path), "target.token")
				if err := os.WriteFile(target, []byte(token), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "non_hex",
			setup: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, []byte(strings.Repeat("z", 64)+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "oversized",
			setup: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, []byte(strings.Repeat("a", otlpPathTokenMaxReadBytes+1)), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			hooks := filepath.Join(dir, "hooks")
			if err := os.MkdirAll(hooks, 0o700); err != nil {
				t.Fatal(err)
			}
			path, err := OTLPPathTokenFilePath(dir, OTLPScopeGeminiCLI)
			if err != nil {
				t.Fatal(err)
			}
			tc.setup(t, path)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read unsafe token before provisioning attempt: %v", err)
			}
			if got, err := LoadOTLPPathToken(dir, OTLPScopeGeminiCLI); err == nil {
				t.Fatalf("LoadOTLPPathToken succeeded with token %q, want error", got)
			}
			if got, err := EnsureOTLPPathToken(dir, OTLPScopeGeminiCLI); err == nil {
				t.Fatalf("EnsureOTLPPathToken succeeded with token %q, want error", got)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read unsafe token after provisioning attempt: %v", err)
			}
			if !bytes.Equal(after, before) {
				t.Fatal("rejected provisioning modified the existing unsafe token")
			}
		})
	}
}

func TestLoadOTLPPathToken_AcceptsStrictTokenFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path, err := OTLPPathTokenFilePath(dir, OTLPScopeGeminiCLI)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	want := strings.Repeat("b", 64)
	if err := os.WriteFile(path, []byte(want+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadOTLPPathToken(dir, OTLPScopeGeminiCLI)
	if err != nil {
		t.Fatalf("LoadOTLPPathToken: %v", err)
	}
	if got != want {
		t.Fatalf("token = %q, want %q", got, want)
	}
}

func TestRemoveOTLPPathTokenRevokesAndIsIdempotent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	first, err := EnsureOTLPPathToken(dir, OTLPScopeCodex)
	if err != nil {
		t.Fatal(err)
	}
	path, err := OTLPPathTokenFilePath(dir, OTLPScopeCodex)
	if err != nil {
		t.Fatal(err)
	}
	if err := safefile.WritePrivate(path+".tmp", []byte(strings.Repeat("d", 64)+"\n")); err != nil {
		t.Fatal(err)
	}
	currentTemp := filepath.Join(filepath.Dir(path), otlpPathTokenTempPrefix(path)+"abc123")
	priorTemp := filepath.Join(filepath.Dir(path), "."+otlpPathTokenTempPrefix(path)+strings.Repeat("a", 32))
	foreignLookalike := filepath.Join(filepath.Dir(path), otlpPathTokenTempPrefix(path)+"not.owned")
	for _, artifact := range []string{currentTemp, priorTemp, foreignLookalike} {
		if err := safefile.WritePrivate(artifact, []byte(strings.Repeat("e", 64)+"\n")); err != nil {
			t.Fatal(err)
		}
	}

	if err := RemoveOTLPPathToken(dir, OTLPScopeCodex); err != nil {
		t.Fatalf("RemoveOTLPPathToken: %v", err)
	}
	for _, artifact := range []string{path, path + ".tmp", currentTemp, priorTemp} {
		if _, err := os.Lstat(artifact); !os.IsNotExist(err) {
			t.Fatalf("token artifact survived removal: %s (err=%v)", artifact, err)
		}
	}
	if _, err := os.Lstat(foreignLookalike); err != nil {
		t.Fatalf("non-owned token temp lookalike was removed: %v", err)
	}
	if got, err := LoadOTLPPathToken(dir, OTLPScopeCodex); err != nil || got != "" {
		t.Fatalf("LoadOTLPPathToken after removal = %q, %v", got, err)
	}
	if err := RemoveOTLPPathToken(dir, OTLPScopeCodex); err != nil {
		t.Fatalf("idempotent RemoveOTLPPathToken: %v", err)
	}
	second, err := EnsureOTLPPathToken(dir, OTLPScopeCodex)
	if err != nil {
		t.Fatal(err)
	}
	if second == first {
		t.Fatal("token was reused after revocation")
	}
}

func TestOTLPPathTokenScopeForConnector(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		scope OTLPPathTokenScope
		ok    bool
	}{
		{name: "codex", scope: OTLPScopeCodex, ok: true},
		{name: " ClaudeCode ", scope: OTLPScopeClaude, ok: true},
		{name: "geminicli", scope: OTLPScopeGeminiCLI, ok: true},
		{name: "cursor", ok: false},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := OTLPPathTokenScopeForConnector(tc.name)
			if got != tc.scope || ok != tc.ok {
				t.Fatalf("OTLPPathTokenScopeForConnector(%q) = %q, %v; want %q, %v", tc.name, got, ok, tc.scope, tc.ok)
			}
		})
	}
}

func TestResolveSetupOTLPPathTokenUsesSuppliedTokenWithoutLocalSidecar(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	want := strings.Repeat("c", 64)
	got, err := resolveSetupOTLPPathToken(dir, OTLPScopeCodex, "  "+want+"\n")
	if err != nil {
		t.Fatalf("resolveSetupOTLPPathToken: %v", err)
	}
	if got != want {
		t.Fatalf("token = %q, want supplied token", got)
	}
	path, err := OTLPPathTokenFilePath(dir, OTLPScopeCodex)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("per-user token sidecar exists after supplied token: %v", err)
	}
}

func TestResolveSetupOTLPPathTokenRejectsInvalidSuppliedToken(t *testing.T) {
	t.Parallel()
	if _, err := resolveSetupOTLPPathToken(t.TempDir(), OTLPScopeClaude, "not-a-token"); err == nil {
		t.Fatal("resolveSetupOTLPPathToken accepted an invalid supplied token")
	}
}
