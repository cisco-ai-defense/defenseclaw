// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// writePathTokenFile is a tiny helper that mirrors what
// connector.EnsureOTLPPathToken writes — an owner-only file containing a
// hex-encoded token plus trailing newline — without taking the package-
// local mutex. We want the test to model the on-disk state the way
// `defenseclaw setup geminicli` leaves it: present, non-empty, mode 0o600.
func writePathTokenFile(t *testing.T, dataDir string, scope connector.OTLPPathTokenScope, token string) string {
	t.Helper()
	dir := filepath.Join(dataDir, "hooks")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir hooks dir: %v", err)
	}
	path, err := connector.OTLPPathTokenFilePath(dataDir, scope)
	if err != nil {
		t.Fatalf("OTLPPathTokenFilePath: %v", err)
	}
	if err := safefile.WritePrivate(path, []byte(token+"\n")); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	return path
}

// TestLookupOTLPPathToken_LazyReloadOnMiss is the F4 regression test:
// when the sidecar boots with no scoped tokens loaded and the operator
// subsequently runs `defenseclaw setup geminicli` (which mints a token
// on disk), the very next loopback OTLP request must succeed. Previously
// the in-memory snapshot only refreshed at sidecar boot, so every Gemini
// OTLP export returned 401 until the next gateway restart even though
// settings.json and the on-disk token were correct.
func TestLookupOTLPPathToken_LazyReloadOnMiss(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	const minted = "deadbeef" + "cafef00d" + "deadbeef" + "cafef00d" +
		"deadbeef" + "cafef00d" + "deadbeef" + "cafef00d"
	writePathTokenFile(t, tmp, connector.OTLPScopeGeminiCLI, minted)

	cfg := &config.Config{}
	cfg.DataDir = tmp
	api := &APIServer{scannerCfg: cfg}
	// Intentionally do NOT call SetOTLPPathTokens — this is the
	// boot-vs-setup race we are fixing: gateway came up first, setup
	// minted the token after.

	got := api.lookupOTLPPathToken(string(connector.OTLPScopeGeminiCLI))
	if got != minted {
		t.Fatalf("lookupOTLPPathToken returned %q on first miss; want %q (lazy reload broken)", got, minted)
	}

	// Second call must serve from cache inside the bounded validation window.
	if got := api.lookupOTLPPathToken(string(connector.OTLPScopeGeminiCLI)); got != minted {
		t.Fatalf("second lookup returned %q; cache miss (want %q)", got, minted)
	}
}

// TestLookupOTLPPathToken_IgnoresUnknownScopes ensures the lazy reload
// path NEVER touches disk for source segments outside the closed scope
// allow-list. A fuzzer / attacker probing /otlp/<random>/<token>/v1/* must
// not be able to convert the auth path into a disk-stampede primitive.
func TestLookupOTLPPathToken_IgnoresUnknownScopes(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	cfg := &config.Config{}
	cfg.DataDir = tmp
	api := &APIServer{scannerCfg: cfg}

	bogus := []string{
		"../etc/passwd",
		"unknown-vendor",
		"GEMINI", // wrong case — not in OTLPPathTokenScopes()
		"",
		"geminicli ",
		"\x00", // NUL byte
		"geminicli/extra",
		"geminicli\nclaude", // CRLF injection attempt
	}
	for _, s := range bogus {
		if got := api.lookupOTLPPathToken(s); got != "" {
			t.Errorf("lookupOTLPPathToken(%q) = %q, want \"\" (unknown scope must skip disk)", s, got)
		}
	}
	// And no .otlp-* token file may have been touched by the lookup
	// for an unknown scope.
	hooksDir := filepath.Join(tmp, "hooks")
	if entries, err := os.ReadDir(hooksDir); err == nil && len(entries) != 0 {
		t.Errorf("hooks dir contains %d entries after unknown-scope lookups; want 0 (lazy reload touched disk)", len(entries))
	}
}

// TestLookupOTLPPathToken_StatThrottlesRepeatedMisses guards against a
// pathological caller (or a misconfigured connector) that hammers
// /otlp/geminicli/<random>/v1/... with no on-disk token file: after the
// first miss attempts a stat we must NOT keep re-stating disk on every
// subsequent miss. The throttle is otlpPathTokenLastStatAt (not the
// reload-at map, which only records actual full reloads).
func TestLookupOTLPPathToken_StatThrottlesRepeatedMisses(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	cfg := &config.Config{}
	cfg.DataDir = tmp
	api := &APIServer{scannerCfg: cfg}

	// First miss — must attempt the stat, no token to find.
	if got := api.lookupOTLPPathToken(string(connector.OTLPScopeGeminiCLI)); got != "" {
		t.Fatalf("first lookup = %q, want \"\" (no token file present)", got)
	}
	api.otlpPathTokenMu.RLock()
	first := api.otlpPathTokenLastStatAt[connector.OTLPScopeGeminiCLI]
	api.otlpPathTokenMu.RUnlock()
	if first.IsZero() {
		t.Fatalf("first miss did not record a stat timestamp; throttle inert")
	}

	// Second + third miss within the refractory window — must NOT
	// update the stat timestamp. The fast-path miss branch (no
	// cached token, recent stat) returns "" without taking the
	// write lock or hitting disk, so the timestamp stays pinned at
	// `first` and proves the syscall was elided.
	for i, label := range []string{"second", "third"} {
		if got := api.lookupOTLPPathToken(string(connector.OTLPScopeGeminiCLI)); got != "" {
			t.Fatalf("%s lookup (i=%d) = %q, want \"\"", label, i, got)
		}
		api.otlpPathTokenMu.RLock()
		again := api.otlpPathTokenLastStatAt[connector.OTLPScopeGeminiCLI]
		api.otlpPathTokenMu.RUnlock()
		if !again.Equal(first) {
			t.Fatalf("%s lookup mutated stat timestamp (first=%v now=%v); throttle did not elide disk syscall",
				label, first, again)
		}
	}

	// No on-disk side-effects from the throttled misses.
	hooksDir := filepath.Join(tmp, "hooks")
	if entries, err := os.ReadDir(hooksDir); err == nil && len(entries) != 0 {
		t.Errorf("hooks dir contains %d entries after throttled misses; want 0", len(entries))
	}
}

// TestLookupOTLPPathToken_ReloadAfterWindowAllowsRetry verifies that
// after the refractory window elapses, the next miss DOES attempt a
// fresh load — which is required for operator flows like "I ran
// setup again to rotate the token, the gateway should pick it up
// within a second."
func TestLookupOTLPPathToken_ReloadAfterWindowAllowsRetry(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	cfg := &config.Config{}
	cfg.DataDir = tmp
	api := &APIServer{scannerCfg: cfg}

	// First miss with no file on disk.
	if got := api.lookupOTLPPathToken(string(connector.OTLPScopeGeminiCLI)); got != "" {
		t.Fatalf("first lookup = %q, want \"\"", got)
	}

	// Drop a token file on disk after the boot snapshot — same as
	// the F4 boot race.
	const minted = "0011223344556677" + "8899aabbccddeeff" +
		"0011223344556677" + "8899aabbccddeeff"
	writePathTokenFile(t, tmp, connector.OTLPScopeGeminiCLI, minted)

	// Backdate the single authoritative validation timestamp to simulate the
	// window elapsing.
	api.otlpPathTokenMu.Lock()
	if api.otlpPathTokenLastStatAt == nil {
		api.otlpPathTokenLastStatAt = map[connector.OTLPPathTokenScope]time.Time{}
	}
	api.otlpPathTokenLastStatAt[connector.OTLPScopeGeminiCLI] =
		time.Now().Add(-2 * otlpPathTokenStatMinInterval)
	api.otlpPathTokenMu.Unlock()

	if got := api.lookupOTLPPathToken(string(connector.OTLPScopeGeminiCLI)); got != minted {
		t.Errorf("lookup after window elapsed = %q, want minted token %q (operator rotate flow broken)", got, minted)
	}
}

// TestLookupOTLPPathToken_NoDataDirSkipsReload guards the defensive
// dataDir guard: if scannerCfg.DataDir is empty (test fixtures that
// haven't wired a real config), lookupOTLPPathToken must NOT panic or
// touch the working directory.
func TestLookupOTLPPathToken_NoDataDirSkipsReload(t *testing.T) {
	t.Parallel()
	api := &APIServer{scannerCfg: &config.Config{}}
	if got := api.lookupOTLPPathToken(string(connector.OTLPScopeGeminiCLI)); got != "" {
		t.Errorf("lookup with empty DataDir returned %q, want \"\"", got)
	}
}

// TestLookupOTLPPathToken_DetectsRotation is the M1 regression test:
// when an operator regenerates the on-disk token while the gateway
// keeps running (post-rotation policy or security-incident response),
// the in-memory cache MUST securely reload the file content. Without
// this check the gateway keeps authenticating the old token and every
// loopback OTLP request 401s after the rotation until restart.
func TestLookupOTLPPathToken_DetectsRotation(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	const original = "aaaaaaaaaaaaaaaa" + "bbbbbbbbbbbbbbbb" +
		"cccccccccccccccc" + "dddddddddddddddd"
	const rotated = "1111111111111111" + "2222222222222222" +
		"3333333333333333" + "4444444444444444"

	writePathTokenFile(t, tmp, connector.OTLPScopeGeminiCLI, original)
	cfg := &config.Config{}
	cfg.DataDir = tmp
	api := &APIServer{scannerCfg: cfg}
	api.SetOTLPPathTokens(map[connector.OTLPPathTokenScope]string{
		connector.OTLPScopeGeminiCLI: original,
	})

	// Steady-state hit: original token returned from cache.
	if got := api.lookupOTLPPathToken(string(connector.OTLPScopeGeminiCLI)); got != original {
		t.Fatalf("pre-rotation lookup = %q, want %q", got, original)
	}

	// Operator rotates the token. The explicit timestamp change retains the
	// historical coverage; same-mtime replacement has its own regression below.
	writePathTokenFile(t, tmp, connector.OTLPScopeGeminiCLI, rotated)
	path, _ := connector.OTLPPathTokenFilePath(tmp, connector.OTLPScopeGeminiCLI)
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	// Force the stat throttle to expire so the next lookup actually
	// stats the file.
	api.otlpPathTokenMu.Lock()
	api.otlpPathTokenLastStatAt[connector.OTLPScopeGeminiCLI] =
		time.Now().Add(-2 * otlpPathTokenStatMinInterval)
	api.otlpPathTokenMu.Unlock()

	if got := api.lookupOTLPPathToken(string(connector.OTLPScopeGeminiCLI)); got != rotated {
		t.Errorf("post-rotation lookup = %q, want rotated token %q (M1 rotation refresh broken)", got, rotated)
	}
}

func TestLookupOTLPPathToken_DetectsSameMtimeAtomicReplacement(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	original := strings.Repeat("a", 64)
	rotated := strings.Repeat("b", 64)
	path := writePathTokenFile(t, tmp, connector.OTLPScopeCodex, original)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat original token: %v", err)
	}
	cfg := &config.Config{DataDir: tmp}
	cfg.Gateway.Token = "gateway-master"
	api := &APIServer{scannerCfg: cfg}
	api.SetOTLPPathTokens(map[connector.OTLPPathTokenScope]string{connector.OTLPScopeCodex: original})
	if got := api.lookupOTLPPathToken(string(connector.OTLPScopeCodex)); got != original {
		t.Fatal("initial token lookup failed")
	}

	temp := path + ".replacement"
	if err := os.WriteFile(temp, []byte(rotated+"\n"), 0o600); err != nil {
		t.Fatalf("write replacement: %v", err)
	}
	if err := os.Chtimes(temp, info.ModTime(), info.ModTime()); err != nil {
		t.Fatalf("preserve replacement mtime: %v", err)
	}
	if err := os.Rename(temp, path); err != nil {
		t.Fatalf("atomic replacement: %v", err)
	}
	expireOTLPTokenValidation(t, api, connector.OTLPScopeCodex)
	if got := api.lookupOTLPPathToken(string(connector.OTLPScopeCodex)); got != rotated {
		t.Fatal("same-mtime atomic replacement did not rotate cached token")
	}
	assertScopedOTLPAuth(t, api, original, http.StatusUnauthorized)
	assertScopedOTLPAuth(t, api, rotated, http.StatusOK)
}

func TestLookupOTLPPathToken_DetectsDeleteRecreateWithoutIntermediateLookup(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	original := strings.Repeat("c", 64)
	rotated := strings.Repeat("d", 64)
	path := writePathTokenFile(t, tmp, connector.OTLPScopeCodex, original)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat original token: %v", err)
	}
	cfg := &config.Config{DataDir: tmp}
	cfg.Gateway.Token = "gateway-master"
	api := &APIServer{scannerCfg: cfg}
	api.SetOTLPPathTokens(map[connector.OTLPPathTokenScope]string{connector.OTLPScopeCodex: original})
	if got := api.lookupOTLPPathToken(string(connector.OTLPScopeCodex)); got != original {
		t.Fatal("initial token lookup failed")
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("delete token: %v", err)
	}
	if err := os.WriteFile(path, []byte(rotated+"\n"), 0o600); err != nil {
		t.Fatalf("recreate token: %v", err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatalf("preserve recreated mtime: %v", err)
	}
	// No lookup occurs between delete and recreate.
	expireOTLPTokenValidation(t, api, connector.OTLPScopeCodex)
	if got := api.lookupOTLPPathToken(string(connector.OTLPScopeCodex)); got != rotated {
		t.Fatal("delete+recreate did not rotate cached token")
	}
	assertScopedOTLPAuth(t, api, original, http.StatusUnauthorized)
	assertScopedOTLPAuth(t, api, rotated, http.StatusOK)
}

func TestLookupOTLPPathToken_RejectsSymlinkReplacement(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	original := strings.Repeat("e", 64)
	rotated := strings.Repeat("f", 64)
	path := writePathTokenFile(t, tmp, connector.OTLPScopeCodex, original)
	cfg := &config.Config{DataDir: tmp}
	cfg.Gateway.Token = "gateway-master"
	api := &APIServer{scannerCfg: cfg}
	api.SetOTLPPathTokens(map[connector.OTLPPathTokenScope]string{connector.OTLPScopeCodex: original})
	if got := api.lookupOTLPPathToken(string(connector.OTLPScopeCodex)); got != original {
		t.Fatal("initial token lookup failed")
	}
	target := filepath.Join(tmp, "attacker-token")
	if err := os.WriteFile(target, []byte(rotated+"\n"), 0o600); err != nil {
		t.Fatalf("write symlink target: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove token for symlink replacement: %v", err)
	}
	if err := os.Symlink(target, path); err != nil {
		if os.IsPermission(err) || (runtime.GOOS == "windows" && errors.Is(err, syscall.Errno(1314))) {
			t.Skipf("symlink creation unavailable: %v", err)
		}
		t.Fatalf("replace token with symlink: %v", err)
	}
	expireOTLPTokenValidation(t, api, connector.OTLPScopeCodex)
	if got := api.lookupOTLPPathToken(string(connector.OTLPScopeCodex)); got != "" {
		t.Fatal("symlink replacement retained or loaded an authorized token")
	}
	assertScopedOTLPAuth(t, api, original, http.StatusUnauthorized)
	assertScopedOTLPAuth(t, api, rotated, http.StatusUnauthorized)
}

func expireOTLPTokenValidation(t *testing.T, api *APIServer, scope connector.OTLPPathTokenScope) {
	t.Helper()
	api.otlpPathTokenMu.Lock()
	api.otlpPathTokenLastStatAt[scope] = time.Now().Add(-2 * otlpPathTokenStatMinInterval)
	api.otlpPathTokenMu.Unlock()
}

func assertScopedOTLPAuth(t *testing.T, api *APIServer, token string, want int) {
	t.Helper()
	called := false
	handler := api.tokenAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	request := httptest.NewRequest(http.MethodPost, "/otlp/codex/"+token+"/v1/logs", nil)
	request.RemoteAddr = "127.0.0.1:54321"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != want {
		t.Fatalf("scoped token auth status=%d want=%d", response.Code, want)
	}
	if called != (want == http.StatusOK) {
		t.Fatalf("scoped token handler called=%v want=%v", called, want == http.StatusOK)
	}
}

// TestLookupOTLPPathToken_DropsCacheOnFileRemoval verifies the
// fail-closed branch: if the operator removes the on-disk token (tore
// down the connector, security incident, etc.) the in-memory cache
// MUST drop the stale entry so subsequent requests 401 rather than
// continuing to authenticate a removed token.
func TestLookupOTLPPathToken_DropsCacheOnFileRemoval(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	const minted = "feedface" + "feedface" + "feedface" + "feedface" +
		"feedface" + "feedface" + "feedface" + "feedface"
	writePathTokenFile(t, tmp, connector.OTLPScopeGeminiCLI, minted)
	cfg := &config.Config{}
	cfg.DataDir = tmp
	cfg.Gateway.Token = "gateway-master"
	api := &APIServer{scannerCfg: cfg}
	api.SetOTLPPathTokens(map[connector.OTLPPathTokenScope]string{
		connector.OTLPScopeGeminiCLI: minted,
	})
	if got := api.lookupOTLPPathToken(string(connector.OTLPScopeGeminiCLI)); got != minted {
		t.Fatalf("pre-removal lookup = %q, want %q", got, minted)
	}

	// Operator removes the token. Force stat throttle to expire.
	path, _ := connector.OTLPPathTokenFilePath(tmp, connector.OTLPScopeGeminiCLI)
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove token file: %v", err)
	}
	api.otlpPathTokenMu.Lock()
	api.otlpPathTokenLastStatAt[connector.OTLPScopeGeminiCLI] =
		time.Now().Add(-2 * otlpPathTokenStatMinInterval)
	api.otlpPathTokenMu.Unlock()

	if got := api.lookupOTLPPathToken(string(connector.OTLPScopeGeminiCLI)); got != "" {
		t.Errorf("post-removal lookup = %q, want \"\" (cache must drop on file removal)", got)
	}
	assertScopedOTLPAuth(t, api, minted, http.StatusUnauthorized)
}

func TestLookupOTLPPathToken_ConcurrentDueRemovalNeverReturnsStale(t *testing.T) {
	const workers = 64
	for attempt := 0; attempt < 20; attempt++ {
		tmp := t.TempDir()
		minted := strings.Repeat(string(rune('a'+attempt%6)), 64)
		path := writePathTokenFile(t, tmp, connector.OTLPScopeCodex, minted)
		cfg := &config.Config{DataDir: tmp}
		cfg.Gateway.Token = "gateway-master"
		api := &APIServer{scannerCfg: cfg}
		api.SetOTLPPathTokens(map[connector.OTLPPathTokenScope]string{
			connector.OTLPScopeCodex: minted,
		})
		if got := api.lookupOTLPPathToken(string(connector.OTLPScopeCodex)); got != minted {
			t.Fatalf("attempt %d initial lookup=%q want minted token", attempt, got)
		}
		if err := os.Remove(path); err != nil {
			t.Fatalf("attempt %d remove token: %v", attempt, err)
		}
		expireOTLPTokenValidation(t, api, connector.OTLPScopeCodex)

		start := make(chan struct{})
		results := make(chan string, workers)
		var wg sync.WaitGroup
		wg.Add(workers)
		for range workers {
			go func() {
				defer wg.Done()
				<-start
				results <- api.lookupOTLPPathToken(string(connector.OTLPScopeCodex))
			}()
		}
		close(start)
		wg.Wait()
		close(results)
		for got := range results {
			if got != "" {
				t.Fatalf("attempt %d concurrent due lookup returned revoked token %q", attempt, got)
			}
		}
	}
}

// TestLookupOTLPPathToken_ConcurrentRotation is a race-detector smoke
// test: many goroutines call lookupOTLPPathToken concurrently while
// another rotates the on-disk token. None of the lookups should see a
// torn / partial token, and no goroutine should panic on map mutation.
//
// Run with `go test -race` to catch the unsynchronised-map class of
// regressions in lookupOTLPPathToken's slow path.
func TestLookupOTLPPathToken_ConcurrentRotation(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	const a = "aaaaaaaa" + "aaaaaaaa" + "aaaaaaaa" + "aaaaaaaa" +
		"aaaaaaaa" + "aaaaaaaa" + "aaaaaaaa" + "aaaaaaaa"
	const b = "bbbbbbbb" + "bbbbbbbb" + "bbbbbbbb" + "bbbbbbbb" +
		"bbbbbbbb" + "bbbbbbbb" + "bbbbbbbb" + "bbbbbbbb"
	writePathTokenFile(t, tmp, connector.OTLPScopeGeminiCLI, a)
	cfg := &config.Config{}
	cfg.DataDir = tmp
	api := &APIServer{scannerCfg: cfg}

	const workers = 24
	const iters = 50

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				select {
				case <-stop:
					return
				default:
				}
				tok := api.lookupOTLPPathToken(string(connector.OTLPScopeGeminiCLI))
				if tok != "" && tok != a && tok != b {
					t.Errorf("torn token observed: %q", tok)
					return
				}
			}
		}()
	}

	// Rotate the file a few times while readers run.
	for i := 0; i < 8; i++ {
		val := a
		if i%2 == 0 {
			val = b
		}
		writePathTokenFile(t, tmp, connector.OTLPScopeGeminiCLI, val)
		path, _ := connector.OTLPPathTokenFilePath(tmp, connector.OTLPScopeGeminiCLI)
		future := time.Now().Add(time.Duration(i+1) * time.Second)
		_ = os.Chtimes(path, future, future)
		time.Sleep(5 * time.Millisecond)
	}
	close(stop)
	wg.Wait()
}
