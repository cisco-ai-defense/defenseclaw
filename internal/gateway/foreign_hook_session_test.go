// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

type foreignSessionResult struct {
	Deny   bool   `json:"deny"`
	Reason string `json:"reason"`
}

// The guardian's ledger is read at every exchange, with no cache: a
// replacement of the same size and time, written in place or renamed over
// the old one, is seen by the next exchange.
func TestForeignHookRemovalSourceReadsTheLedgerAtEveryExchange(t *testing.T) {
	previous := validateManagedGuardianAuthorization
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	t.Cleanup(func() { validateManagedGuardianAuthorization = previous })
	alice, bob := "1001", "1002"
	at := time.Now().UTC().Format(time.RFC3339)
	makeLedger := func(t *testing.T, identity string) []byte {
		t.Helper()
		data, err := enterprisepolicy.EncodeForeignHookRemovals(nil, []enterprisepolicy.ForeignHookRemoval{{
			Identity: identity, Connector: "claudecode", Path: "/home/alice/.claude/settings.json",
			At: at, Mark: runtime.GOOS + ":b:200",
		}}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	for _, tc := range []struct {
		name    string
		replace func(t *testing.T, path string, data []byte, mod time.Time)
	}{
		{"rewritten in place", func(t *testing.T, path string, data []byte, mod time.Time) {
			if err := os.WriteFile(path, data, 0o640); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(path, mod, mod); err != nil {
				t.Fatal(err)
			}
		}},
		{"replaced atomically", func(t *testing.T, path string, data []byte, mod time.Time) {
			tmp := filepath.Join(filepath.Dir(path), "replacement")
			if err := os.WriteFile(tmp, data, 0o640); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(tmp, mod, mod); err != nil {
				t.Fatal(err)
			}
			if err := safefile.ReplaceFile(tmp, path); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			first, second := makeLedger(t, bob), makeLedger(t, alice)
			if len(first) != len(second) {
				t.Fatalf("fixture ledger sizes differ: %d, %d", len(first), len(second))
			}
			path := filepath.Join(dir, enterprisepolicy.ForeignHookRemovalsFile)
			if err := os.WriteFile(path, first, 0o640); err != nil {
				t.Fatal(err)
			}
			var source foreignHookRemovalSource
			if got, err := source.forIdentity(dir, alice); err != nil || len(got) != 0 {
				t.Fatalf("first ledger = %+v, %v", got, err)
			}
			before, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			tc.replace(t, path, second, before.ModTime())
			after, err := os.Stat(path)
			if err != nil || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
				t.Fatalf("fixture metadata changed: before=%v after=%v err=%v", before, after, err)
			}
			if got, err := source.forIdentity(dir, alice); err != nil || len(got) != 1 || got[0].Identity != alice {
				t.Fatalf("a replacement of the same size and time was missed: %+v, %v", got, err)
			}
		})
	}
}

func TestForeignHookSessionGatewayPersistsAndBindsTheCaller(t *testing.T) {
	ledger := &userScopedTestLedger{}
	alice, bob := "1001", "1002"
	if runtime.GOOS == "windows" {
		alice, bob = "S-1-5-21-1111-2222-3333-1001", "S-1-5-21-1111-2222-3333-1002"
		ledger.set(
			managedHookLedgerTarget{User: "alice", SID: alice, Connector: "claudecode", OK: true},
			managedHookLedgerTarget{User: "bob", SID: bob, Connector: "claudecode", OK: true},
		)
	} else {
		ledger.set(
			managedHookLedgerTarget{User: "alice", UID: userScopedTestUID(1001), Connector: "claudecode", OK: true},
			managedHookLedgerTarget{User: "bob", UID: userScopedTestUID(1002), Connector: "claudecode", OK: true},
		)
	}
	guardianDir := t.TempDir()
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, guardianDir)
	restoreValidate := validateManagedGuardianAuthorization
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	t.Cleanup(func() { validateManagedGuardianAuthorization = restoreValidate })
	api, _, _ := newUserScopedTestServer(t, true, ledger, map[string]string{alice: "alice", bob: "bob"})
	handler := api.tokenAuth(api.managedHookSocketMux())
	aliceToken := userScopedTestToken(t, connector.UserScopedHookCredential, "claudecode", alice)
	bobToken := userScopedTestToken(t, connector.UserScopedHookCredential, "claudecode", bob)
	path := "/api/v1/foreign-hook-session/claudecode"
	// The loopback caller account each per-user credential belongs to.
	peerUIDs := map[string]int{aliceToken: 1001, bobToken: 1002}
	call := func(h http.Handler, token string, update map[string]any, claimedID string) (int, foreignSessionResult) {
		t.Helper()
		data, err := json.Marshal(update)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(data))
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-DefenseClaw-Client", "foreign-hook-guard/1.0")
		req.Header.Set("Authorization", "Bearer "+token)
		if uid, ok := peerUIDs[token]; ok {
			req = req.WithContext(context.WithValue(req.Context(), acpConnPeerKey{}, &acpConnPeer{uid: uid, known: true}))
		}
		if claimedID != "" {
			req.Header.Set(llmEventUserIDHeader, claimedID)
		}
		response := newDeadlineRecorder()
		h.ServeHTTP(response, req)
		var decision foreignSessionResult
		_ = json.Unmarshal(response.Body.Bytes(), &decision)
		return response.Code, decision
	}
	blocked := map[string]any{
		"key":           map[string]any{"connector": "claudecode", "session": "s-1", "process": "process-1"},
		"session_start": true,
		"decision": map[string]any{"deny": true, "reason": "enterprise_foreign_hook_blocked: project hook",
			"findings": []map[string]any{{"connector": "claudecode", "scope": "project", "path": "/repo/.claude/settings.json", "digest": "abcd"}}},
	}
	if status, result := call(handler, aliceToken, blocked, ""); status != http.StatusOK || !result.Deny {
		t.Fatalf("record blocked session: %d %+v", status, result)
	}
	clean := map[string]any{
		"key":           map[string]any{"connector": "claudecode", "session": "s-1", "process": "process-1"},
		"session_start": false,
		"decision":      map[string]any{"deny": false},
	}
	if status, result := call(handler, aliceToken, clean, bob); status != http.StatusForbidden || result.Deny {
		t.Fatalf("identity mismatch must be refused: %d %+v", status, result)
	}
	if status, result := call(handler, bobToken, clean, ""); status != http.StatusOK || result.Deny {
		t.Fatalf("another user must have separate state: %d %+v", status, result)
	}
	if status, _ := call(handler, "gateway-master-token", clean, ""); status != http.StatusForbidden {
		t.Fatalf("master token must not access the session route: %d", status)
	}
	// The guardian removed alice's Claude Code hook at clock 200 (and a Codex
	// one later): only her Claude Code processes started before then are
	// denied, naming the file. Bob's earlier Codex removals, however many and
	// however long the paths he chose (and one incomplete entry), never make
	// the ledger unreadable, which would deny everyone's calls.
	removed := "/home/alice/.claude/settings.json"
	earlier := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	flood := []enterprisepolicy.ForeignHookRemoval{{Identity: bob, Connector: "codex", At: earlier, Mark: runtime.GOOS + ":b:900"}}
	for i := 0; i < 2000; i++ {
		flood = append(flood, enterprisepolicy.ForeignHookRemoval{Identity: bob, Connector: "codex",
			Path: "/home/bob/" + strconv.Itoa(i) + strings.Repeat("<", 480), At: earlier, Mark: runtime.GOOS + ":b:900"})
	}
	data, err := enterprisepolicy.EncodeForeignHookRemovals(flood, []enterprisepolicy.ForeignHookRemoval{
		{Identity: alice, Connector: "claudecode", Path: removed, At: time.Now().UTC().Format(time.RFC3339), Mark: runtime.GOOS + ":b:200"},
		{Identity: alice, Connector: "codex", Path: "/home/alice/.codex/hooks.json", At: time.Now().UTC().Format(time.RFC3339), Mark: runtime.GOOS + ":b:900"},
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(guardianDir, enterprisepolicy.ForeignHookRemovalsFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	withProcess := func(process string) map[string]any {
		return map[string]any{
			"key":           map[string]any{"connector": "claudecode", "session": "s-3", "process": process},
			"session_start": true,
			"decision":      map[string]any{"deny": false},
		}
	}
	if _, result := call(handler, aliceToken, withProcess(runtime.GOOS+":b:4242:100"), ""); !result.Deny || !strings.Contains(result.Reason, removed) || !strings.Contains(result.Reason, "restart the agent") {
		t.Fatalf("an agent process that started before the removal must be denied, naming the file: %+v", result)
	}
	if _, result := call(handler, aliceToken, withProcess(runtime.GOOS+":b:4343:300"), ""); result.Deny {
		t.Fatalf("an agent process that started after the removal (and before the other connector's) must be allowed: %+v", result)
	}
	if _, result := call(handler, bobToken, withProcess(runtime.GOOS+":b:4444:100"), ""); result.Deny {
		t.Fatalf("another account's agent must not be affected: %+v", result)
	}

	// The record survives a gateway process restart because it is stored in
	// the gateway data directory, not in an APIServer memory cache.
	restarted := NewAPIServer("", nil, nil, nil, nil, api.scannerCfg)
	restarted.userScopedCredentials = api.userScopedCredentials
	restartedHandler := restarted.tokenAuth(restarted.managedHookSocketMux())
	if status, result := call(restartedHandler, aliceToken, clean, ""); status != http.StatusOK || !result.Deny || !strings.Contains(result.Reason, "restart the agent") {
		t.Fatalf("gateway restart lost the block: %d %+v", status, result)
	}
}

// deadlineRecorder is a ResponseRecorder whose connection can bound a
// write, as the connection of every gateway listener can.
type deadlineRecorder struct{ *httptest.ResponseRecorder }

func newDeadlineRecorder() deadlineRecorder { return deadlineRecorder{httptest.NewRecorder()} }

func (deadlineRecorder) SetWriteDeadline(time.Time) error { return nil }

type pausedForeignHookResponse struct {
	http.ResponseWriter
	entered chan struct{}
	resume  chan struct{}
}

func (w pausedForeignHookResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w pausedForeignHookResponse) Write(data []byte) (int, error) {
	close(w.entered)
	<-w.resume
	return w.ResponseWriter.Write(data)
}

// foreignHookGuardianDirForTest is a guardian authorization folder the
// gateway trusts without the ownership checks.
func foreignHookGuardianDirForTest(t *testing.T) string {
	t.Helper()
	guardianDir := t.TempDir()
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, guardianDir)
	previous := validateManagedGuardianAuthorization
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	t.Cleanup(func() { validateManagedGuardianAuthorization = previous })
	return guardianDir
}

// lockForeignHookAccountRemovalForTest takes identity's removal lock as the
// hook guardian does, within timeout. drained reports that no exchange of
// the account was inside when it went on.
func lockForeignHookAccountRemovalForTest(t *testing.T, dataDir, identity string, timeout time.Duration) (release func(), drained bool, err error) {
	t.Helper()
	// The drain ignores the caller's context (it always waits its whole
	// time for an exchange inside), so the probe shortens the drain itself.
	restore := enterprisepolicy.OverrideForeignHookRemovalDrainWaitForTest(timeout)
	defer restore()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return enterprisepolicy.LockForeignHookAccountRemoval(ctx, dataDir, identity)
}

// foreignHookPipeListener serves HTTP over synchronous in-memory pipes: a
// write blocks until the peer reads, as a socket write does once a client
// has stopped reading and the socket buffers are full.
type foreignHookPipeListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newForeignHookPipeListener() *foreignHookPipeListener {
	return &foreignHookPipeListener{conns: make(chan net.Conn), closed: make(chan struct{})}
}

func (l *foreignHookPipeListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *foreignHookPipeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *foreignHookPipeListener) Addr() net.Addr { return &net.UnixAddr{Name: "pipe", Net: "pipe"} }

func (l *foreignHookPipeListener) dial() (net.Conn, error) {
	server, client := net.Pipe()
	select {
	case l.conns <- server:
		return client, nil
	case <-l.closed:
		_ = server.Close()
		_ = client.Close()
		return nil, net.ErrClosed
	}
}

// A client that stops reading a large allow, or reads it a byte at a time,
// must not hold its account's removal lock past
// foreignHookFencedWriteTimeout: the guardian's removal of the account still
// drains the lock, another account's exchange is still answered although
// the same account has a second slow exchange queued, and neither slow
// client receives a complete allow (GAP-0348).
func TestForeignHookSessionSlowAllowReaderDoesNotHoldTheAccountLock(t *testing.T) {
	foreignHookGuardianDirForTest(t)
	api, _, _ := newUserScopedTestServer(t, true, &userScopedTestLedger{}, nil)
	dataDir := api.configDataDir()
	alice, bob := "1001", "1002"
	if runtime.GOOS == "windows" {
		alice, bob = "S-1-5-21-1111-2222-3333-1001", "S-1-5-21-1111-2222-3333-1002"
	}
	listener := newForeignHookPipeListener()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := withAuthenticatedHookConnector(r.Context(), "claudecode")
		ctx = context.WithValue(ctx, verifiedUserScopedIdentityContextKey{}, r.Header.Get("X-Test-Identity"))
		// Every gateway listener reaches the handler through the metrics
		// middleware's writer.
		api.handleForeignHookSession(&statusWriter{ResponseWriter: w, status: http.StatusOK}, r.WithContext(ctx))
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	// The allow echoes the caller's findings: far more than any server-side
	// write buffer holds.
	findings := make([]map[string]any, 200)
	for i := range findings {
		findings[i] = map[string]any{"connector": "claudecode", "scope": "project", "digest": "abcd", "allowed": true,
			"path": "/repo/" + strconv.Itoa(i) + "/" + strings.Repeat("a", 400)}
	}
	request := func(identity string, n int) *http.Request {
		t.Helper()
		data, err := json.Marshal(map[string]any{
			"key":           map[string]any{"connector": "claudecode", "session": "s-" + strconv.Itoa(n), "process": runtime.GOOS + ":b:4242:100"},
			"session_start": true,
			"decision":      map[string]any{"deny": false, "findings": findings},
		})
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequest(http.MethodPost, "http://gateway/api/v1/foreign-hook-session/claudecode", bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Test-Identity", identity)
		return req
	}

	// Alice's first client never reads; her second reads a byte at a time.
	stalled, err := listener.dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stalled.Close() })
	go func(req *http.Request) { _ = req.Write(stalled) }(request(alice, 1))
	trickle, err := listener.dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = trickle.Close() })
	trickled := make(chan []byte, 1)
	go func(req *http.Request) {
		if err := req.Write(trickle); err != nil {
			trickled <- nil
			return
		}
		var got []byte
		one := make([]byte, 1)
		for {
			if _, err := trickle.Read(one); err != nil {
				trickled <- got
				return
			}
			got = append(got, one[0])
			time.Sleep(10 * time.Millisecond)
		}
	}(request(alice, 2))

	// Wait until a slow allow holds alice's lock: a removal probe then
	// finds an exchange inside.
	deadline := time.Now().Add(5 * time.Second)
	for {
		release, drained, err := lockForeignHookAccountRemovalForTest(t, dataDir, alice, 10*time.Millisecond)
		if err == nil {
			release()
			if !drained {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("no slow allow took the account's removal lock")
		}
		time.Sleep(time.Millisecond)
	}

	// The guardian's removal waits for at most one bounded write.
	release, drained, err := lockForeignHookAccountRemovalForTest(t, dataDir, alice, 3*time.Second)
	if err != nil || !drained {
		t.Fatalf("the guardian's removal did not drain the lock past a slow allow: drained %v, %v", drained, err)
	}
	release()

	// Bob's exchange is answered at once, ahead of alice's second slow
	// exchange.
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) { return listener.dial() },
	}}
	t.Cleanup(client.CloseIdleConnections)
	response, err := client.Do(request(bob, 3))
	if err != nil {
		t.Fatal(err)
	}
	var decision enterprisepolicy.GuardDecision
	decodeErr := json.NewDecoder(response.Body).Decode(&decision)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || decodeErr != nil || decision.Deny || len(decision.Findings) != len(findings) {
		t.Fatalf("another identity's exchange behind a slow allow: status %d, decode %v, %+v", response.StatusCode, decodeErr, decision.Reason)
	}

	// The gateway cut both slow responses: the client that never read finds
	// the connection closed, and the slow reader got an incomplete allow.
	deadline = time.Now().Add(5 * time.Second)
	for {
		_ = stalled.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
		_, err := stalled.Write([]byte("\n"))
		if errors.Is(err, io.ErrClosedPipe) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the gateway kept a never-read allow open: %v", err)
		}
	}
	select {
	case got := <-trickled:
		resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(got)), nil)
		if err == nil {
			_, err = io.ReadAll(resp.Body)
		}
		if err == nil {
			t.Fatalf("a slow reader received a complete allow (%d bytes)", len(got))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the gateway kept a slowly read allow open")
	}
}

// A connection that cannot bound the write gets no allow while the account's
// removal lock is held: the call is refused and the lock is free at once. A
// denial needs no bound and is still answered.
func TestForeignHookSessionRefusesAnAllowItCannotBound(t *testing.T) {
	foreignHookGuardianDirForTest(t)
	api, _, _ := newUserScopedTestServer(t, true, &userScopedTestLedger{}, nil)
	identity := foreignHookTestIdentities(1)[0]
	exchange := func(session string, deny bool) *httptest.ResponseRecorder {
		t.Helper()
		body := `{"key":{"connector":"claudecode","session":"` + session + `","process":"` + runtime.GOOS + `:b:4242:100"},"session_start":true,"decision":{"deny":` + strconv.FormatBool(deny) + `,"reason":"enterprise_foreign_hook_blocked: project hook"}}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/foreign-hook-session/claudecode", strings.NewReader(body))
		ctx := withAuthenticatedHookConnector(req.Context(), "claudecode")
		ctx = context.WithValue(ctx, verifiedUserScopedIdentityContextKey{}, identity)
		// A plain recorder, like a writer wrapper without Unwrap, cannot set
		// a write deadline.
		recorder := httptest.NewRecorder()
		api.handleForeignHookSession(recorder, req.WithContext(ctx))
		return recorder
	}
	allow := exchange("s-1", false)
	if allow.Code != http.StatusServiceUnavailable || !strings.Contains(allow.Body.String(), "foreign_hook_response_unbounded") || strings.Contains(allow.Body.String(), `"deny":false`) {
		t.Fatalf("unbounded allow: %d %s", allow.Code, allow.Body.String())
	}
	release, drained, err := lockForeignHookAccountRemovalForTest(t, api.configDataDir(), identity, 100*time.Millisecond)
	if err != nil || !drained {
		t.Fatalf("the refused allow kept the account's removal lock: drained %v, %v", drained, err)
	}
	release()
	if deny := exchange("s-2", true); deny.Code != http.StatusOK || !strings.Contains(deny.Body.String(), `"deny":true`) {
		t.Fatalf("denial: %d %s", deny.Code, deny.Body.String())
	}
}

func foreignHookTestIdentities(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = strconv.Itoa(1001 + i)
		if runtime.GOOS == "windows" {
			out[i] = "S-1-5-21-1111-2222-3333-" + out[i]
		}
	}
	return out
}

func foreignHookAllowRequest(identity, session string) *http.Request {
	body := `{"key":{"connector":"claudecode","session":"` + session + `","process":"` + runtime.GOOS + `:b:4242:100"},"session_start":true,"decision":{"deny":false}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/foreign-hook-session/claudecode", strings.NewReader(body))
	ctx := withAuthenticatedHookConnector(req.Context(), "claudecode")
	ctx = context.WithValue(ctx, verifiedUserScopedIdentityContextKey{}, identity)
	return req.WithContext(ctx)
}

// Allows of two accounts whose clients read slowly each hold only their own
// account's removal lock, and a third account's exchange is answered at
// once. A removal of either account still waits for that account's allow,
// and drains as soon as it is written.
func TestForeignHookSessionSlowAllowsOfOtherIdentitiesDoNotRefuseAnExchange(t *testing.T) {
	foreignHookGuardianDirForTest(t)
	api, _, _ := newUserScopedTestServer(t, true, &userScopedTestLedger{}, nil)
	dataDir := api.configDataDir()
	ids := foreignHookTestIdentities(3)

	type slowAllow struct {
		recorder *httptest.ResponseRecorder
		paused   pausedForeignHookResponse
		resume   func()
		answered chan struct{}
	}
	slow := make([]slowAllow, 2)
	for i := range slow {
		recorder := httptest.NewRecorder()
		paused := pausedForeignHookResponse{ResponseWriter: deadlineRecorder{recorder}, entered: make(chan struct{}), resume: make(chan struct{})}
		slow[i] = slowAllow{recorder: recorder, paused: paused, resume: sync.OnceFunc(func() { close(paused.resume) }), answered: make(chan struct{})}
		t.Cleanup(slow[i].resume)
		go func(s slowAllow, identity string) {
			api.handleForeignHookSession(s.paused, foreignHookAllowRequest(identity, "s-slow"))
			close(s.answered)
		}(slow[i], ids[i])
	}
	for i, s := range slow {
		select {
		case <-s.paused.entered:
		case <-time.After(3 * time.Second):
			t.Fatalf("identity %d's allow did not reach its response write while another identity's allow was being written", i)
		}
		// WriteHeader ran before the paused Write in the handler's goroutine.
		if s.recorder.Code != http.StatusOK {
			t.Fatalf("identity %d was refused behind another identity's slow allow: %d", i, s.recorder.Code)
		}
	}

	third := make(chan deadlineRecorder, 1)
	go func() {
		response := newDeadlineRecorder()
		api.handleForeignHookSession(response, foreignHookAllowRequest(ids[2], "s-third"))
		third <- response
	}()
	select {
	case response := <-third:
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"deny":false`) {
			t.Fatalf("a third identity behind two slow allows: %d %s", response.Code, response.Body.String())
		}
	case <-time.After(foreignHookExchangeWait):
		t.Fatal("a third identity's exchange waited on two slow allows of other identities")
	}

	for i, s := range slow {
		release, drained, err := lockForeignHookAccountRemovalForTest(t, dataDir, ids[i], 100*time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		release()
		if drained {
			t.Fatalf("a removal of identity %d drained its lock while its allow was being written", i)
		}
		s.resume()
		<-s.answered
		if s.recorder.Code != http.StatusOK || !strings.Contains(s.recorder.Body.String(), `"deny":false`) {
			t.Fatalf("slow allow %d: %d %s", i, s.recorder.Code, s.recorder.Body.String())
		}
		release, drained, err = lockForeignHookAccountRemovalForTest(t, dataDir, ids[i], 100*time.Millisecond)
		if err != nil || !drained {
			t.Fatalf("the removal of identity %d did not drain its lock after the allow: drained %v, %v", i, drained, err)
		}
		release()
	}
}

// slowForeignHookResponse takes delay to write each response, as a client
// that reads slowly but within the write deadline does.
type slowForeignHookResponse struct {
	http.ResponseWriter
	delay   time.Duration
	written *time.Time
}

func (w slowForeignHookResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w slowForeignHookResponse) Write(data []byte) (int, error) {
	time.Sleep(w.delay)
	n, err := w.ResponseWriter.Write(data)
	*w.written = time.Now()
	return n, err
}

// publishForeignHookRemovalsForTest replaces the ledger as the guardian
// does, with an atomic rename, removing the given identities' hooks.
func publishForeignHookRemovalsForTest(t *testing.T, guardianDir string, identities ...string) {
	t.Helper()
	removals := make([]enterprisepolicy.ForeignHookRemoval, 0, len(identities))
	for _, identity := range identities {
		removals = append(removals, enterprisepolicy.ForeignHookRemoval{
			Identity: identity, Connector: "claudecode", Path: "/home/user/.claude/settings.json",
			At: time.Now().UTC().Format(time.RFC3339), Mark: runtime.GOOS + ":b:200",
		})
	}
	data, err := enterprisepolicy.EncodeForeignHookRemovals(nil, removals, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(guardianDir, ".staged-ledger")
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := safefile.ReplaceFile(tmp, filepath.Join(guardianDir, enterprisepolicy.ForeignHookRemovalsFile)); err != nil {
		t.Fatal(err)
	}
}

// A guardian removal of one account lands while exchanges of several
// accounts arrive without a pause (GAP-0348, GAP-0414). The removal takes
// the account's lock within a bounded wait, every allow of the removed
// account was written before the removal held the lock, no exchange of the
// account that started after that is allowed, and the other accounts are
// never denied or refused.
func TestForeignHookSessionRemovalCommitLandsUnderSustainedExchanges(t *testing.T) {
	guardianDir := foreignHookGuardianDirForTest(t)
	api, _, _ := newUserScopedTestServer(t, true, &userScopedTestLedger{}, nil)
	dataDir := api.configDataDir()
	ids := foreignHookTestIdentities(4)
	alice := ids[0]

	type outcome struct {
		identity string
		code     int
		allow    bool
		deny     bool
		started  time.Time
		written  time.Time
	}
	var mu sync.Mutex
	var outcomes []outcome
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i, identity := range ids {
		wg.Add(1)
		go func(i int, identity string) {
			defer wg.Done()
			time.Sleep(time.Duration(i) * 20 * time.Millisecond)
			for n := 0; ; n++ {
				select {
				case <-stop:
					return
				default:
				}
				recorder := httptest.NewRecorder()
				var written time.Time
				w := slowForeignHookResponse{ResponseWriter: deadlineRecorder{recorder}, delay: 80 * time.Millisecond, written: &written}
				started := time.Now()
				api.handleForeignHookSession(w, foreignHookAllowRequest(identity, "s-"+strconv.Itoa(n)))
				body := recorder.Body.String()
				mu.Lock()
				outcomes = append(outcomes, outcome{
					identity: identity, code: recorder.Code, started: started, written: written,
					allow: recorder.Code == http.StatusOK && strings.Contains(body, `"deny":false`),
					deny:  recorder.Code == http.StatusOK && strings.Contains(body, `"deny":true`),
				})
				mu.Unlock()
			}
		}(i, identity)
	}
	stopped := sync.OnceFunc(func() {
		close(stop)
		wg.Wait()
	})
	t.Cleanup(stopped)
	count := func(match func(outcome) bool) int {
		mu.Lock()
		defer mu.Unlock()
		n := 0
		for _, o := range outcomes {
			if match(o) {
				n++
			}
		}
		return n
	}
	waitFor := func(what string, n int, match func(outcome) bool) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for count(match) < n {
			if time.Now().After(deadline) {
				t.Fatalf("only %d of %d %s", count(match), n, what)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	waitFor("exchanges served", 8, func(outcome) bool { return true })

	asked := time.Now()
	release, drained, err := lockForeignHookAccountRemovalForTest(t, dataDir, alice, 5*time.Second)
	lockedAt := time.Now()
	if err != nil {
		t.Fatal(err)
	}
	publishForeignHookRemovalsForTest(t, guardianDir, alice)
	release()
	finishedAt := time.Now()
	if elapsed := lockedAt.Sub(asked); !drained || elapsed > enterprisepolicy.ForeignHookRemovalDrainWait+time.Second {
		t.Fatalf("sustained exchanges held the guardian for %v (drained %v)", elapsed, drained)
	}
	waitFor("of alice's exchanges after the removal denied", 3, func(o outcome) bool {
		return o.identity == alice && o.deny && o.started.After(finishedAt)
	})
	waitFor("exchanges of other identities after the removal", 3, func(o outcome) bool {
		return o.identity != alice && o.started.After(finishedAt)
	})
	stopped()
	for i, o := range outcomes {
		if o.code != http.StatusOK {
			t.Fatalf("exchange %d of %s was refused (%d) around a removal", i, o.identity, o.code)
		}
		if o.identity != alice {
			if !o.allow {
				t.Fatalf("exchange %d of %s, whose hooks were not removed, was denied", i, o.identity)
			}
			continue
		}
		if o.allow && !o.written.Before(lockedAt) {
			t.Fatalf("alice's allow %d was written after the guardian took her removal lock", i)
		}
		if o.allow && o.started.After(lockedAt) {
			t.Fatalf("alice's exchange %d started after the guardian took her removal lock and was allowed", i)
		}
	}
}

// An allow is answered only within foreignHookExchangeHold of taking the
// account's lock, because a removal waits no longer than
// ForeignHookRemovalDrainWait for it: an exchange that decided allow past
// the hold answers a denial instead (it cannot verify the session's record),
// and the lock is free at once. A denial is not bound by the hold.
func TestForeignHookSessionAllowPastItsHoldIsDenied(t *testing.T) {
	if foreignHookFencedWriteTimeout >= enterprisepolicy.ForeignHookExchangeHold ||
		enterprisepolicy.ForeignHookExchangeHold >= enterprisepolicy.ForeignHookRemovalDrainWait {
		t.Fatal("the write timeout, the exchange hold and the guardian's drain wait are out of order")
	}
	if foreignHookExchangeHold != enterprisepolicy.ForeignHookExchangeHold || foreignHookExchangeWait != enterprisepolicy.ForeignHookExchangeWait {
		t.Fatal("the gateway's exchange hold and wait are not the guardian's")
	}
	foreignHookGuardianDirForTest(t)
	previousHold := foreignHookExchangeHold
	foreignHookExchangeHold = 0
	t.Cleanup(func() { foreignHookExchangeHold = previousHold })
	api, _, _ := newUserScopedTestServer(t, true, &userScopedTestLedger{}, nil)
	identity := foreignHookTestIdentities(1)[0]
	allow := newDeadlineRecorder()
	api.handleForeignHookSession(allow, foreignHookAllowRequest(identity, "s-1"))
	if allow.Code != http.StatusOK || !strings.Contains(allow.Body.String(), `"deny":true`) || !strings.Contains(allow.Body.String(), "cannot verify this agent session") {
		t.Fatalf("allow past its hold: %d %s", allow.Code, allow.Body.String())
	}
	release, drained, err := lockForeignHookAccountRemovalForTest(t, api.configDataDir(), identity, 100*time.Millisecond)
	if err != nil || !drained {
		t.Fatalf("the denied allow kept the account's removal lock: drained %v, %v", drained, err)
	}
	release()
	body := `{"key":{"connector":"claudecode","session":"s-2","process":"` + runtime.GOOS + `:b:4242:100"},"session_start":true,"decision":{"deny":true,"reason":"enterprise_foreign_hook_blocked: project hook"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/foreign-hook-session/claudecode", strings.NewReader(body))
	reqCtx := withAuthenticatedHookConnector(req.Context(), "claudecode")
	reqCtx = context.WithValue(reqCtx, verifiedUserScopedIdentityContextKey{}, identity)
	deny := newDeadlineRecorder()
	api.handleForeignHookSession(deny, req.WithContext(reqCtx))
	if deny.Code != http.StatusOK || !strings.Contains(deny.Body.String(), `"deny":true`) || !strings.Contains(deny.Body.String(), "project hook") {
		t.Fatalf("denial: %d %s", deny.Code, deny.Body.String())
	}
}

// A broken gate or lock is a verification failure, not a removal in
// progress. The failed account must not change another account's decision.
func TestForeignHookAccountLockUnavailableDeniesTheExchange(t *testing.T) {
	for _, tc := range []struct {
		name string
		pick func(gate, lock string) string
	}{
		{"gate is a directory", func(gate, _ string) string { return gate }},
		{"lock is a directory", func(_, lock string) string { return lock }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			foreignHookGuardianDirForTest(t)
			api, _, _ := newUserScopedTestServer(t, true, &userScopedTestLedger{}, nil)
			identities := foreignHookTestIdentities(2)
			gate, lock, ok := enterprisepolicy.ForeignHookAccountLockPaths(api.configDataDir(), identities[0])
			if !ok {
				t.Fatal("no account lock paths")
			}
			if err := os.MkdirAll(tc.pick(gate, lock), 0o700); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			_, lockErr := foreignHookAccountExchangeLock(ctx, api.configDataDir(), identities[0])
			cancel()
			if lockErr == nil || errors.Is(lockErr, enterprisepolicy.ErrForeignHookRemovalPending) {
				t.Fatalf("fixture lock error = %v; want a non-pending error", lockErr)
			}
			denied := newDeadlineRecorder()
			api.handleForeignHookSession(denied, foreignHookAllowRequest(identities[0], "s-1"))
			if body := denied.Body.String(); denied.Code != http.StatusOK || !strings.Contains(body, `"deny":true`) ||
				!strings.Contains(body, "cannot verify this agent session") || strings.Contains(body, "is removing") {
				t.Fatalf("account with broken lock: %d %s", denied.Code, body)
			}
			allowed := newDeadlineRecorder()
			api.handleForeignHookSession(allowed, foreignHookAllowRequest(identities[1], "s-2"))
			if allowed.Code != http.StatusOK || !strings.Contains(allowed.Body.String(), `"deny":false`) {
				t.Fatalf("other account: %d %s", allowed.Code, allowed.Body.String())
			}
		})
	}
}
