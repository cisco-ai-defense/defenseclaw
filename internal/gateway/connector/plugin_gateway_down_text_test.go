// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// pluginGatewayDownCase is one gateway state a per-user in-agent plugin
// meets when it fails closed, and the words its denial must say.
type pluginGatewayDownCase struct {
	name     string
	failMode string
	marker   string // a data-directory marker: .install.lock or gateway.stopped
	status   int    // the gateway's 5xx answer; 0 for a stopped gateway
	want     []string
}

var pluginGatewayDownCases = []pluginGatewayDownCase{
	{name: "gateway not running", failMode: "closed",
		want: []string{"this account's DefenseClaw gateway is not running", "`defenseclaw-gateway start`", "`defenseclaw-gateway status`"}},
	{name: "gateway stopped by the user", failMode: "closed", marker: "gateway.stopped",
		want: []string{"stopped with `defenseclaw-gateway stop`", "`defenseclaw-gateway start`"}},
	{name: "install in progress, closed", failMode: "closed", marker: ".install.lock",
		want: []string{"being installed or upgraded", "run the installer again", "`defenseclaw-gateway status`"}},
	{name: "install in progress, open", failMode: "open", marker: ".install.lock",
		want: []string{"being installed or upgraded", "run the installer again", "`defenseclaw-gateway status`"}},
	{name: "gateway answers 503", failMode: "closed", status: http.StatusServiceUnavailable,
		want: []string{"gateway answered HTTP 503", "`defenseclaw-gateway status`"}},
}

// pluginGatewayDownFixture writes a per-user data directory with the
// connector's hook credential and the case's marker, and returns the
// render data of a plugin whose gateway is in the case's state.
func pluginGatewayDownFixture(t *testing.T, connector string, tc pluginGatewayDownCase) templateData {
	t.Helper()
	dataDir := testenv.PrivateTempDir(t)
	token := filepath.Join(dataDir, "hooks", ".hook-"+connector+".token")
	if err := os.MkdirAll(filepath.Dir(token), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(token, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	switch tc.marker {
	case ".install.lock":
		if err := os.Mkdir(filepath.Join(dataDir, tc.marker), 0o700); err != nil {
			t.Fatal(err)
		}
	case "gateway.stopped":
		if err := os.WriteFile(filepath.Join(dataDir, tc.marker), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(tc.status)
	}))
	t.Cleanup(server.Close)
	if tc.status == 0 {
		server.Close()
	}
	return templateData{APIAddr: strings.TrimPrefix(server.URL, "http://"),
		TokenFileJS: javaScriptStringContent(token), FailMode: tc.failMode}
}

// GAP-0850: a per-user OpenCode or Amp plugin that failed closed during an
// outage showed only the runtime's network error ("fetch failed", "Unable to
// connect"), which names neither the gateway nor the fix. Its denial now
// names the gateway's state (not running, stopped by the user, an install or
// upgrade, a 5xx answer) and the command that brings it back, as the native
// and shell hooks do.
func TestPerUserPluginOutageDenialNamesTheGatewayAndTheFix(t *testing.T) {
	for _, tc := range pluginGatewayDownCases {
		t.Run("opencode/"+tc.name, func(t *testing.T) {
			lines := runOpenCodePluginHarness(t, pluginGatewayDownFixture(t, "opencode", tc), 1)
			if len(lines) == 0 || !strings.HasPrefix(lines[0], "block:DefenseClaw blocked this tool call: ") {
				t.Fatalf("OpenCode %s: %q, want a DefenseClaw block", tc.name, lines)
			}
			for _, want := range tc.want {
				if !strings.Contains(lines[0], want) {
					t.Fatalf("OpenCode %s denial %q does not say %q", tc.name, lines[0], want)
				}
			}
		})
		t.Run("amp/"+tc.name, func(t *testing.T) {
			path := writeRenderedPlugin(t, "amp-plugin.ts", "defenseclaw.mts", pluginGatewayDownFixture(t, "amp", tc))
			lines := runNodeHarness(t, ampInstallLockHarness, path)
			last := ""
			if len(lines) > 0 {
				last = lines[len(lines)-1]
			}
			if !strings.Contains(last, `"action":"reject-and-continue"`) ||
				!strings.Contains(last, "DefenseClaw blocked this tool call: ") {
				t.Fatalf("Amp %s: %q, want a DefenseClaw block", tc.name, lines)
			}
			for _, want := range tc.want {
				if !strings.Contains(last, want) {
					t.Fatalf("Amp %s denial %q does not say %q", tc.name, last, want)
				}
			}
		})
	}
}
