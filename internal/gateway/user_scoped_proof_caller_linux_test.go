// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// The kernel TCP peer lookup must reject a real second-account process, not
// just a mocked caller ID. The proof is derived from the protected user's
// credential, so even a challenge with no bearer must stay in that account.
func TestListenerProofRejectsRealSecondAccountCaller(t *testing.T) {
	if _, err := exec.LookPath("sudo"); err != nil {
		t.Skip("sudo is required for a second-account TCP caller")
	}
	if err := exec.Command("sudo", "-n", "-u", "nobody", "true").Run(); err != nil {
		t.Skipf("cannot run a second-account TCP caller: %v", err)
	}
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	uid, err := strconv.Atoi(current.Uid)
	if err != nil || uid < 0 {
		t.Fatalf("current UID %q: %v", current.Uid, err)
	}
	if uid == 65534 {
		t.Skip("test caller already has the nobody UID")
	}
	ledger := &userScopedTestLedger{}
	ledger.set(managedHookLedgerTarget{User: current.Username, UID: userScopedTestUID(uid), Connector: "opencode", OK: true})
	api, _, _ := newUserScopedTestServer(t, true, ledger, map[string]string{current.Uid: current.Username})
	credential := userScopedTestToken(t, connector.UserScopedHookCredential, "opencode", current.Uid)
	keyID := connector.UserScopedCredentialKeyID(credential)
	server := httptest.NewServer(CorrelationMiddleware(NewAgentRegistry("", ""))(api.tokenAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("proof request escaped authentication")
	}))))
	t.Cleanup(server.Close)
	url := server.URL + connector.UserScopedListenerProofPath

	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-DefenseClaw-Connector", "opencode")
	request.Header.Set(connector.UserScopedListenerKeyIDHeader, keyID)
	request.Header.Set(connector.UserScopedListenerNonceHeader, listenerProofTestNonce)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent || response.Header.Get(connector.UserScopedListenerProofHeader) == "" {
		t.Fatalf("same-account proof: status=%d proof=%q", response.StatusCode, response.Header.Get(connector.UserScopedListenerProofHeader))
	}

	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sudo", "-n", "-u", "nobody", "curl", "--noproxy", "*", "-sS", "--max-time", "10", "-D", "-", "-o", os.DevNull,
		"-H", "X-DefenseClaw-Connector: opencode",
		"-H", connector.UserScopedListenerKeyIDHeader+": "+keyID,
		"-H", connector.UserScopedListenerNonceHeader+": "+listenerProofTestNonce,
		url)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("second-account proof request: %v: %s", err, output)
	}
	answer := strings.ToLower(string(output))
	if !strings.HasPrefix(answer, "http/1.1 401 ") || strings.Contains(answer, strings.ToLower(connector.UserScopedListenerProofHeader)+":") {
		t.Fatalf("second account received a proof or unexpected status: %q", answer)
	}
}
