package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// tokenGateway is an OpenClaw gateway that accepts one token and records the
// token of every connect attempt.
type tokenGateway struct {
	mu     sync.Mutex
	tokens []string
}

func (g *tokenGateway) seen() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.tokens...)
}

func newTokenGateway(t *testing.T, accept string) (*tokenGateway, *url.URL) {
	t.Helper()
	g := &tokenGateway{}
	upgrader := websocket.Upgrader{}
	srv := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		cp, _ := json.Marshal(ChallengePayload{Nonce: "test-nonce", Ts: 1700000000000})
		challenge, _ := json.Marshal(EventFrame{Type: "event", Event: "connect.challenge", Payload: cp})
		_ = conn.WriteMessage(websocket.TextMessage, challenge)
		_, raw, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var req struct {
			ID     string `json:"id"`
			Params struct {
				Auth struct {
					Token string `json:"token"`
				} `json:"auth"`
			} `json:"params"`
		}
		_ = json.Unmarshal(raw, &req)
		g.mu.Lock()
		g.tokens = append(g.tokens, req.Params.Auth.Token)
		g.mu.Unlock()
		var resp ResponseFrame
		if req.Params.Auth.Token == accept {
			hello, _ := json.Marshal(HelloOK{Type: "hello-ok", Protocol: openClawMaxProtocol})
			resp = ResponseFrame{Type: "res", ID: req.ID, OK: true, Payload: hello}
		} else {
			resp = ResponseFrame{Type: "res", ID: req.ID, OK: false,
				Error: &FrameError{Code: "INVALID_REQUEST", Message: "unauthorized: gateway token mismatch (provide gateway auth token)"}}
		}
		out, _ := json.Marshal(resp)
		_ = conn.WriteMessage(websocket.TextMessage, out)
		time.Sleep(200 * time.Millisecond)
	}))
	u, _ := url.Parse(srv.URL)
	return g, u
}

func newTokenClient(t *testing.T, u *url.URL, home, token string) *Client {
	t.Helper()
	port, _ := strconv.Atoi(u.Port())
	dataDir := testenv.PrivateTempDir(t)
	client, err := NewClient(&config.GatewayConfig{
		Host:           u.Hostname(),
		Port:           port,
		OpenClawToken:  token,
		ClawHome:       home,
		DeviceKeyFile:  filepath.Join(dataDir, "device.key"),
		ReconnectMs:    10,
		MaxReconnectMs: 20,
	}, dataDir)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client.tokenRetryEvery = time.Hour
	client.tokenWatch = 10 * time.Millisecond
	t.Cleanup(func() { client.Close() })
	return client
}

// The wait for a persisted token ends when the file gets one. The token is
// loaded before the next attempt, so that attempt is the one that connects: no
// attempt sends the old token and waits out a backoff before the new one
// (GAP-0847: persisted-token reconnect took ~20 s, not ~5 s).
func TestConnectWithRetryLoadsAPersistedTokenBeforeTheNextAttempt(t *testing.T) {
	const persisted = "persisted-token"
	gw, u := newTokenGateway(t, persisted)
	home := t.TempDir()
	writeOpenClawJSON(t, home, `{"gateway":{"auth":{"mode":"token"}}}`)
	client := newTokenClient(t, u, home, "saved-openclaw-token")

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- client.ConnectWithRetry(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for len(gw.seen()) < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	writeOpenClawJSON(t, home, "{gateway: {auth: {mode: 'token', token: '"+persisted+"',},},}")
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ConnectWithRetry: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ConnectWithRetry did not connect after openclaw.json got a token")
	}
	if got, want := gw.seen(), []string{"saved-openclaw-token", persisted}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("tokens sent = %v, want %v (the persisted token must be the next attempt, not the one after a rejection)", got, want)
	}
	if got := client.wsToken(); got != persisted {
		t.Errorf("wsToken() = %q, want the persisted token", got)
	}
}

// A token adopted from openclaw.json has not been tried yet, so the wait
// before it is the base interval, not the backoff the old token earned. With a
// 1 s base the two adopted tokens cost 2 s; a grown backoff (1 s, then 1.7 s)
// would cost 2.7 s.
func TestConnectWithRetryRestartsTheBackoffWhenTheTokenChanges(t *testing.T) {
	gw, u := newTokenGateway(t, "rotated-token")
	home := t.TempDir()
	writeOpenClawJSON(t, home, `{"gateway":{"auth":{"token":"stale-file-token"}}}`)
	client := newTokenClient(t, u, home, "saved-openclaw-token")
	client.cfg.ReconnectMs = 1000
	client.cfg.MaxReconnectMs = 600000

	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- client.ConnectWithRetry(ctx) }()

	// The first rejection adopts the file token. Rotate the file before the
	// retry so the second rejection adopts the rotated one.
	deadline := time.Now().Add(5 * time.Second)
	for len(gw.seen()) < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	writeOpenClawJSON(t, home, "{gateway:{auth:{token:'rotated-token'}}}")
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ConnectWithRetry: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("ConnectWithRetry did not reach the rotated token; sent %v", gw.seen())
	}
	if got := gw.seen(); got[len(got)-1] != "rotated-token" {
		t.Errorf("last token sent = %q, want the rotated token; all %v", got[len(got)-1], got)
	}
	if elapsed := time.Since(started); elapsed > 2400*time.Millisecond {
		t.Errorf("reaching the rotated token took %s, want about 2s: a changed token must restart the backoff", elapsed)
	}
}

// The operator step for a token DefenseClaw cannot read is one that works for
// the background gateway: a saved key, then a restart. A variable exported in
// the shell never reaches the daemon, so no hint may offer it as the way.
func TestGatewayTokenHintsNameTheStepThatReachesTheDaemon(t *testing.T) {
	for name, text := range map[string]string{
		"rejected":      openClawTokenRejectedHint,
		"not persisted": openClawTokenNotPersistedHint,
		"env rejected":  openClawTokenEnvRejectedHint,
		"unreadable":    errOpenClawTokenUnreadable.Error(),
	} {
		for _, want := range []string{"defenseclaw keys set OPENCLAW_GATEWAY_TOKEN", "defenseclaw-gateway restart", "does not reach the background gateway"} {
			if !strings.Contains(text, want) {
				t.Errorf("%s hint lacks %q: %s", name, want, text)
			}
		}
	}
}

// A token the file already holds can be rotated while the wait after its
// rejection runs. The wait ends when the file changes, so the rotated token is
// the next attempt even though the backoff has grown to seconds (GAP-0847).
func TestConnectWithRetryAttemptsARotatedPersistedTokenWithoutWaitingOutTheBackoff(t *testing.T) {
	gw, u := newTokenGateway(t, "fresh-token")
	home := t.TempDir()
	writeOpenClawJSON(t, home, "{gateway:{auth:{mode:'token',token:'stale-token'}}}")
	client := newTokenClient(t, u, home, "stale-token")
	client.cfg.ReconnectMs = 2500
	client.cfg.MaxReconnectMs = 60000
	configPath := filepath.Join(home, ".openclaw", "openclaw.json")
	rotated := make(chan error, 1)
	var once sync.Once
	client.OnConnectError = func(_ error, _ string) {
		once.Do(func() {
			rotated <- os.WriteFile(configPath, []byte("{gateway:{auth:{mode:'token',token:'fresh-token'}}}"), 0o600)
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- client.ConnectWithRetry(ctx) }()
	select {
	case err := <-rotated:
		if err != nil {
			t.Fatalf("rotate the token: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the first attempt was not rejected")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ConnectWithRetry: %v", err)
		}
	case <-time.After(900 * time.Millisecond):
		t.Fatalf("the rotated token was not tried within 900ms of a 10ms watch interval; sent %v", gw.seen())
	}
	if got := client.wsToken(); got != "fresh-token" {
		t.Errorf("wsToken() = %q, want the rotated token", got)
	}
}

// Benign twin: a rejected token that the file still holds changes nothing, so
// the retry waits out its backoff and no extra attempt is made.
func TestConnectWithRetryKeepsTheBackoffWhenThePersistedTokenIsUnchanged(t *testing.T) {
	gw, u := newTokenGateway(t, "fresh-token")
	home := t.TempDir()
	writeOpenClawJSON(t, home, "{gateway:{auth:{mode:'token',token:'stale-token'}}}")
	client := newTokenClient(t, u, home, "stale-token")
	client.cfg.ReconnectMs = 2500
	client.cfg.MaxReconnectMs = 60000
	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()
	if err := client.ConnectWithRetry(ctx); err == nil {
		t.Fatal("ConnectWithRetry connected with a token the gateway rejects")
	}
	if got := gw.seen(); len(got) != 1 {
		t.Errorf("attempts = %v, want exactly one while the file token is unchanged", got)
	}
}

// R-TOK: the WebSocket connect presents the OpenClaw credential, never the
// DefenseClaw gateway token. With OPENCLAW_GATEWAY_TOKEN saved it sends that;
// without it, the openclaw.json gateway.auth.token. cfg.Token (the master)
// is never sent, so OpenClaw and its plugins never learn it.
func TestConnectPresentsTheOpenClawCredentialNeverTheMaster(t *testing.T) {
	for _, tc := range []struct {
		name, saved, want string
	}{
		{"saved OPENCLAW_GATEWAY_TOKEN", "saved-oc-token", "saved-oc-token"},
		{"openclaw.json gateway.auth.token", "", "json-oc-token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gw, u := newTokenGateway(t, tc.want)
			home := t.TempDir()
			writeOpenClawJSON(t, home, `{"gateway":{"auth":{"mode":"token","token":"json-oc-token"}}}`)
			client := newTokenClient(t, u, home, tc.saved)
			client.cfg.Token = "master-token"
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := client.ConnectWithRetry(ctx); err != nil {
				t.Fatalf("ConnectWithRetry: %v", err)
			}
			for _, sent := range gw.seen() {
				if sent == "master-token" {
					t.Fatalf("the DefenseClaw gateway token was sent to OpenClaw: %v", gw.seen())
				}
			}
			if got := gw.seen(); len(got) != 1 || got[0] != tc.want {
				t.Fatalf("tokens sent = %v, want [%s]", got, tc.want)
			}
		})
	}
}

// An openclaw.json SecretRef that names DEFENSECLAW_GATEWAY_TOKEN is not
// resolved: OpenClaw would then hold the DefenseClaw gateway token.
func TestOpenClawTokenReaderRefusesAReferenceToTheMaster(t *testing.T) {
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "master-token")
	home := t.TempDir()
	writeOpenClawJSON(t, home, `{"gateway":{"auth":{"token":{"source":"env","id":"DEFENSECLAW_GATEWAY_TOKEN"}}}}`)
	token, ok, err := readOpenClawGatewayToken(home)
	if ok || token != "" || !errors.Is(err, errOpenClawTokenUnreadable) {
		t.Fatalf("token = %q, ok = %v, err = %v; want the reference refused", token, ok, err)
	}
}
