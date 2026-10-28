// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// until 1.1 (G-deadcode loop round 2): the token handling of the OpenHands
// hook 1.0.0 through 1.0.3 rendered (openhands-hook.sh at 1.0.3: HOOK_DIR,
// the missing-token check, the token read and the post). It reads its token
// from the folder it is in; with none it lets the call run in fail mode open
// before it contacts the gateway (exit 0); with one it posts the call to
// /api/v1/openhands/hook and blocks (exit 2) on a block verdict. Delete with
// connector/removed.go in 1.1.
const retiredOpenHandsTokenHook = `#!/bin/sh
# defenseclaw-managed-hook v6
# DefenseClaw OpenHands hook: the token handling of 1.0.3
HOOK_DIR="$(cd -P -- "$(dirname -- "$0")" 2>/dev/null && pwd)" || exit 2
FAIL_MODE="${DEFENSECLAW_FAIL_MODE:-open}"
if [ ! -f "${HOOK_DIR}/.hook-openhands.token" ]; then
  [ "$FAIL_MODE" = "closed" ] && exit 2
  exit 0
fi
IFS= read -r API_TOKEN < "${HOOK_DIR}/.hook-openhands.token" || true
PAYLOAD="$(cat)"
RESPONSE="$(curl -sS --max-time 20 -X POST -H "Authorization: Bearer ${API_TOKEN}" -H "Content-Type: application/json" --data "$PAYLOAD" "${RETIRED_HOOK_TEST_GATEWAY}/api/v1/openhands/hook")" || {
  [ "$FAIL_MODE" = "closed" ] && exit 2
  exit 0
}
case "$RESPONSE" in
  *'"action":"block"'*) printf '%s\n' "$RESPONSE"; exit 2 ;;
esac
exit 0
`

// Review fix (G-deadcode loop round 2): a copy of the 1.0.3 OpenHands hook
// under another name in the hooks folder, which hooks.json runs, reads the
// token the teardown used to revoke. Without it, the copy let every call
// run in fail mode open before it contacted the gateway. The upgrade keeps
// the OpenHands hook token, so the copy still reaches the retired route and
// a call the policy would block is blocked: after the upgrade, after a
// gateway restart, in fail mode open and closed. The token authenticates no
// other route, and the leftovers say when it may go.
func TestUpgradeKeepsACopiedOpenHandsHookBlocking(t *testing.T) {
	curl, err := exec.LookPath("curl")
	if err != nil {
		t.Skip("the 1.0.3 OpenHands hook posts with curl, which is not installed")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	h := stageRetiredOpenHands(t)
	hooks := filepath.Dir(h.script)
	copied := filepath.Join(hooks, "openhands-hook-mine.sh")
	writeRetiredFile(t, copied, retiredOpenHandsTokenHook)
	if err := os.Chmod(copied, 0o700); err != nil {
		t.Fatal(err)
	}
	writeRetiredFile(t, h.hooksPath, `{"pre_tool_use":[{"matcher":"*","hooks":[{"type":"command","command":"`+copied+`","timeout":60}]}]}`)
	token, err := connector.LoadHookAPIToken(h.dataDir, "openhands")
	if err != nil || token == "" {
		t.Fatalf("staged openhands token = %q, %v", token, err)
	}

	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil)
	api.scannerCfg = &config.Config{}
	api.scannerCfg.Gateway.Token = "master-token"
	api.scannerCfg.DataDir = h.dataDir
	server := httptest.NewServer(api.tokenAuth(http.NotFoundHandler()))
	t.Cleanup(server.Close)

	// A call the 1.0.3 policy blocks: a destructive shell command.
	payload := `{"hook_event_name":"PreToolUse","tool_name":"execute_bash","tool_input":{"command":"rm -rf ~/.ssh"}}`
	requireBlocked := func(what string) {
		t.Helper()
		for _, mode := range []string{"open", "closed"} {
			cmd := exec.Command(sh, copied)
			cmd.Env = append(os.Environ(), "DEFENSECLAW_FAIL_MODE="+mode, "RETIRED_HOOK_TEST_GATEWAY="+server.URL,
				"PATH="+filepath.Dir(curl)+string(os.PathListSeparator)+os.Getenv("PATH"))
			cmd.Stdin = strings.NewReader(payload)
			var out bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &out
			err := cmd.Run()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 2 {
				t.Fatalf("%s, fail mode %s: the copied hook ran with %v (%s); want the block (exit 2)", what, mode, err, out.String())
			}
			if mode == "open" && !strings.Contains(out.String(), "OpenHands support was removed in DefenseClaw 1.0.4") {
				t.Fatalf("%s: the copied hook blocked without the removal reason: %s", what, out.String())
			}
		}
	}
	requireBlocked("before the upgrade")

	if err := connector.SaveActiveConnector(h.dataDir, "openhands"); err != nil {
		t.Fatal(err)
	}
	opts := connector.SetupOpts{DataDir: h.dataDir}
	if err := teardownPreviousConnector(connector.NewDefaultRegistry(), "codex", opts, context.Background()); err != nil {
		t.Fatalf("teardown of the removed connector: %v", err)
	}
	if body, err := os.ReadFile(h.script); err != nil || !strings.Contains(string(body), "disabled tombstone") {
		t.Fatalf("%s = %q, %v; want the stub", h.script, body, err)
	}
	if body, err := os.ReadFile(copied); err != nil || string(body) != retiredOpenHandsTokenHook {
		t.Fatalf("the teardown changed the copy %s: %q, %v", copied, body, err)
	}
	requireTokenKept := func(what string) {
		t.Helper()
		if got, err := connector.LoadHookAPIToken(h.dataDir, "openhands"); err != nil || got != token {
			t.Fatalf("%s: openhands token = %q, %v; want the one the old hooks read kept", what, got, err)
		}
	}
	requireBlocked("after the upgrade")
	requireTokenKept("after the upgrade")

	// A gateway restart runs the cleanup of the removed connector again.
	if !removedConnectorAlreadyTornDown(connector.SetupOpts{DataDir: h.dataDir}, "openhands") {
		t.Fatal("after the upgrade the removed OpenHands connector still has teardown work, so every start would retry it")
	}
	if err := retireOrDropUnregisteredConnector(context.Background(), connector.NewDefaultRegistry(), connector.SetupOpts{DataDir: h.dataDir}, "openhands", "lock", nil); err != nil {
		t.Fatalf("restart cleanup: %v", err)
	}
	requireTokenKept("after a restart")
	requireBlocked("after a restart")

	// The kept token authenticates no route of a connector 1.0.4 ships.
	request := httptest.NewRequest(http.MethodPost, "/api/v1/codex/hook", strings.NewReader(`{}`))
	request.RemoteAddr = "127.0.0.1:40000"
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	api.tokenAuth(http.NotFoundHandler()).ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("codex hook with the kept openhands token: status %d, want 401", response.Code)
	}

	tokenPath, err := connector.HookAPITokenFilePath(h.dataDir, "openhands")
	if err != nil {
		t.Fatal(err)
	}
	leftovers, _ := connector.RemovedConnectorLeftovers("openhands", opts)
	for _, item := range leftovers {
		if item.Path == tokenPath {
			if !strings.Contains(item.What, "DefenseClaw keeps") || !strings.Contains(item.Step, "delete it only once no OpenHands hooks.json") {
				t.Fatalf("the kept token is listed as %+v", item)
			}
			return
		}
	}
	t.Fatalf("leftovers %+v do not list the kept token %s", leftovers, tokenPath)
}
