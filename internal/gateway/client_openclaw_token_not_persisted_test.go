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
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

const tokenMismatchRejection = "unauthorized: gateway token mismatch (provide gateway auth token) (INVALID_REQUEST)"

func writeOpenClawJSON(t *testing.T, home, body string) {
	t.Helper()
	dir := filepath.Join(home, ".openclaw")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "openclaw.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func rejectionClient(t *testing.T, home string) *Client {
	t.Helper()
	dataDir := testenv.PrivateTempDir(t)
	client, err := NewClient(&config.GatewayConfig{
		Token:         "defenseclaw-own-token",
		ClawHome:      home,
		DeviceKeyFile: filepath.Join(dataDir, "device.key"),
	}, dataDir)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

// OpenClaw without a persisted gateway.auth.token issues a new random token at
// every start, so a token rejection cannot be fixed by re-reading
// openclaw.json. The operator step must say so.
func TestTokenRejectionWithoutPersistedOpenClawTokenNamesTheCause(t *testing.T) {
	for name, body := range map[string]string{
		"auth block without a token": `{"gateway":{"mode":"local","auth":{"mode":"token"}}}`,
		"no gateway block":           `{}`,
		"null token":                 `{"gateway":{"auth":{"token":null}}}`,
		"empty token":                `{"gateway":{"auth":{"token":""}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			writeOpenClawJSON(t, home, body)
			client := rejectionClient(t, home)
			for _, rejection := range []string{tokenMismatchRejection, "connect rejected (token_missing)"} {
				if hint := client.handleConnectRejection(errors.New(rejection)); hint != openClawTokenNotPersistedHint {
					t.Errorf("%s: hint = %q, want the not-persisted step", rejection, hint)
				}
			}
		})
	}
}

// Benign twin: every other rejection keeps its own operator step.
func TestTokenRejectionKeepsItsStepWhenOpenClawHoldsAToken(t *testing.T) {
	t.Run("persisted token is adopted", func(t *testing.T) {
		home := t.TempDir()
		writeOpenClawJSON(t, home, `{"gateway":{"auth":{"token":"persisted-token"}}}`)
		client := rejectionClient(t, home)
		if hint := client.handleConnectRejection(errors.New(tokenMismatchRejection)); hint != openClawTokenRejectedHint {
			t.Errorf("hint = %q, want the token step", hint)
		}
		if client.cfg.Token != "persisted-token" {
			t.Errorf("token = %q, want the persisted token adopted", client.cfg.Token)
		}
	})
	t.Run("openclaw.json missing", func(t *testing.T) {
		client := rejectionClient(t, t.TempDir())
		if hint := client.handleConnectRejection(errors.New(tokenMismatchRejection)); hint != openClawTokenRejectedHint {
			t.Errorf("hint = %q, want the token step", hint)
		}
	})
	t.Run("pairing and non-token rejections", func(t *testing.T) {
		home := t.TempDir()
		writeOpenClawJSON(t, home, `{"gateway":{"auth":{"mode":"token"}}}`)
		client := rejectionClient(t, home)
		pairing := "gateway: connect handshake: pairing required: device pairing required (NOT_PAIRED)"
		if hint := client.handleConnectRejection(errors.New(pairing)); hint != openClawPairingApprovalHint(client.device.DeviceID) {
			t.Errorf("pairing hint = %q", hint)
		}
		if hint := client.handleConnectRejection(errors.New("gateway: connect: unauthorized (UNAUTHORIZED)")); hint == openClawTokenNotPersistedHint {
			t.Errorf("a rejection that names no token got the not-persisted step")
		}
		if hint := client.handleConnectRejection(errors.New("connection refused")); hint != "" {
			t.Errorf("connection refused hint = %q, want none", hint)
		}
	})
}

// The reconnect loop must not hammer OpenClaw while no token can match, and
// must connect soon after the operator persists one.
func TestConnectWithRetryStopsSpinningUntilOpenClawPersistsAToken(t *testing.T) {
	const persisted = "persisted-token"
	var attempts atomic.Int32
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
		attempts.Add(1)
		var req struct {
			ID     string `json:"id"`
			Params struct {
				Auth struct {
					Token string `json:"token"`
				} `json:"auth"`
			} `json:"params"`
		}
		_ = json.Unmarshal(raw, &req)
		var resp ResponseFrame
		if req.Params.Auth.Token == persisted {
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
	port, _ := strconv.Atoi(u.Port())

	home := t.TempDir()
	writeOpenClawJSON(t, home, `{"gateway":{"auth":{"mode":"token"}}}`)
	dataDir := testenv.PrivateTempDir(t)
	client, err := NewClient(&config.GatewayConfig{
		Host:           u.Hostname(),
		Port:           port,
		Token:          "defenseclaw-own-token",
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

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- client.ConnectWithRetry(ctx) }()

	time.Sleep(600 * time.Millisecond)
	if got := attempts.Load(); got != 1 {
		t.Fatalf("connect attempts while OpenClaw holds no token = %d, want 1 (the loop must wait)", got)
	}
	select {
	case err := <-done:
		t.Fatalf("ConnectWithRetry returned early: %v", err)
	default:
	}

	writeOpenClawJSON(t, home, `{"gateway":{"auth":{"mode":"token","token":"`+persisted+`"}}}`)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ConnectWithRetry after the token was persisted: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ConnectWithRetry did not connect after openclaw.json got a token")
	}
	if client.cfg.Token != persisted {
		t.Errorf("token = %q, want the persisted token", client.cfg.Token)
	}
}
