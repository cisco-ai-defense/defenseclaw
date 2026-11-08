// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// POSIX permissions emulate the managed gateway that cannot read the user
// project, and links are retargeted the way an agent racing its own patch
// would.

//go:build !windows

package gateway

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// retargetTransport is the managed hook client talking to the real gateway
// handler over a loopback connection: the gateway answers with the user home
// locked (it reads nothing in it), then the swap runs at the chosen point
// after that answer. The connection is real because the hook asks for a
// delivery receipt, which an in-process handler cannot give: without it the
// gateway can only call the answer unconfirmed.
type retargetTransport struct {
	api     *APIServer
	connect string
	home    string
	swap    func()

	once   sync.Once
	server *httptest.Server
	inner  *http.Transport
	mu     sync.Mutex
	got    bytes.Buffer
}

func (rt *retargetTransport) start() {
	rt.once.Do(func() {
		root := filepath.Dir(rt.home)
		rt.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r = r.WithContext(withManagedHookPeer(r.Context(), managedHookPeer{Home: rt.home}))
			_ = os.Chmod(root, 0)
			rt.api.handleAgentHook(rt.connect).ServeHTTP(w, r)
		}))
		rt.inner = &http.Transport{DisableKeepAlives: true}
	})
}

func (rt *retargetTransport) close() {
	if rt.server != nil {
		rt.server.Close()
		rt.inner.CloseIdleConnections()
	}
}

// answered is the answer body the gateway sent.
func (rt *retargetTransport) answered() string {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.got.String()
}

func (rt *retargetTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.start()
	forward := req.Clone(req.Context())
	target := *req.URL
	target.Scheme, target.Host = "http", rt.server.Listener.Addr().String()
	forward.URL = &target
	forward.Host = target.Host
	resp, err := rt.inner.RoundTrip(forward)
	// The gateway has judged the call when its answer arrives; give the user
	// home back before the hook reads it again.
	_ = os.Chmod(filepath.Dir(rt.home), 0o700)
	if err != nil {
		return nil, err
	}
	resp.Body = &retargetTee{ReadCloser: resp.Body, rt: rt}
	// A hook that asks for a delivery receipt keeps the connection open until
	// it has judged the answer, so "close" has no later moment than "answer"
	// at which the swap still lands before the hook reads its targets again:
	// both run the swap as the answer arrives.
	if rt.swap != nil {
		rt.swap()
	}
	return resp, nil
}

// retargetTee keeps the answer body for the test to read.
type retargetTee struct {
	io.ReadCloser
	rt *retargetTransport
}

func (t *retargetTee) Read(p []byte) (int, error) {
	n, err := t.ReadCloser.Read(p)
	t.rt.mu.Lock()
	t.rt.got.Write(p[:n])
	t.rt.mu.Unlock()
	return n, err
}

// retargetWriter makes the swap in the Write that carries the answer to the
// agent, as a retarget that lands while the answer is written.
type retargetWriter struct {
	bytes.Buffer
	swap func()
	saw  bool
}

func (w *retargetWriter) Write(p []byte) (int, error) {
	if !w.saw {
		w.saw = true
		w.swap()
	}
	return w.Buffer.Write(p)
}

// retargetRun runs the real managed hook of connector (the hook client, then
// the gateway handler) for a patch of the project link "link", which leads to
// the ordinary file out.txt, and retargets the link to protected at point
// ("answer": once the gateway has answered; "close": as the answer closes;
// "write": while the allow is written to the agent). An empty point leaves the
// link as it was; point "same" saves the link again to the same ordinary file.
func retargetRun(t *testing.T, connector, pack, point, protected string) (stdout, gatewayAnswer string, code int, wrote bool) {
	t.Helper()
	home, project := hermesPatchHome(t)
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	ordinary := filepath.Join(project, "out.txt")
	target := filepath.Join(home, filepath.FromSlash(protected))
	if protected != "" {
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(target); err != nil {
			if err := os.WriteFile(target, []byte("x\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.WriteFile(ordinary, []byte("# base\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(project, "link.txt")
	if err := os.Symlink(ordinary, link); err != nil {
		t.Fatal(err)
	}
	retarget := func() {
		to := target
		if point == "same" {
			to = ordinary
		}
		if err := os.Remove(link); err != nil {
			t.Error(err)
		}
		if err := os.Symlink(to, link); err != nil {
			t.Error(err)
		}
	}

	var body, event string
	switch connector {
	case "hermes":
		body = hermesPatchBody(t, project, "patch", map[string]any{"mode": "patch", "patch": hermesV4AUpdate("link.txt")})
		event = "pre_tool_call"
	default:
		body = opencodeV2PatchBody(t, project, "patch", "*** Begin Patch\n*** Update File: link.txt\n@@\n # base\n+changed\n*** End Patch\n")
		event = "tool.execute.before"
	}
	// The gateway keeps a durable audit record of the call before it offers
	// the answer to a hook that asks for a delivery receipt.
	fixture := newManagedHookAuditFixtureFor(t, connector, nil)
	fixture.api.scannerCfg.Guardrail.RulePack = pack
	rt := &retargetTransport{api: fixture.api, connect: connector, home: home}
	t.Cleanup(rt.close)
	writer := &retargetWriter{swap: retarget}
	var stdoutW io.Writer = &writer.Buffer
	switch point {
	case "answer", "close", "same":
		rt.swap = retarget
	case "write":
		stdoutW = writer
	}
	hookHome := t.TempDir()
	if err := os.MkdirAll(filepath.Join(hookHome, "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hookHome, "hooks", ".token"), []byte("DEFENSECLAW_GATEWAY_TOKEN=\"tkn\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	code = hookexec.Run(t.Context(), hookexec.Options{
		Connector: connector, Event: event, APIAddr: "127.0.0.1:8787", FailMode: "closed",
		ManagedEnterprise: true, Home: hookHome, HookDir: filepath.Join(hookHome, "hooks"),
		Stdin: strings.NewReader(body), Stdout: stdoutW, Stderr: &stderr, HTTPClient: &http.Client{Transport: rt},
	})
	return writer.String(), rt.answered(), code, writer.saw
}

func retargetRefused(code int, stdout string) bool {
	compact := strings.ReplaceAll(stdout, " ", "")
	for _, refusal := range []string{`"action":"block"`, `"decision":"block"`, `"decision":"deny"`, `"permissionDecision":"deny"`} {
		if strings.Contains(compact, refusal) {
			return true
		}
	}
	return code != 0
}

// A Hermes V4A patch (and the OpenCode patch) of an ordinary project symlink
// that the hook read and the gateway allowed (balanced and permissive trust the
// hook reading of a link; strict does not), then retargeted to the SSH keys
// file or to DefenseClaw state or configuration once the gateway has answered,
// as the answer closes or while the allow is written, is refused by the real
// hook in every profile. This is the end-to-end closure of a retarget the
// gateway cannot see behind ProtectHome (direct gateway replays are in
// TestCFRDirectGatewayReplayOfHermesLinkHeaderAfterRetarget). The twin:
// the same link saved again to the same ordinary file keeps its allow in the
// profiles that allow an ordinary link, and an unchanged link too.
func TestRealHookRefusesAHermesLinkRetargetedAfterTheGatewayAnswer(t *testing.T) {
	protectedFiles := []string{".ssh/authorized_keys", ".defenseclaw/config.yaml", ".defenseclaw/policies/rule.rego"}
	for _, connector := range []string{"hermes", "opencode"} {
		for _, pack := range []string{"", "permissive", "strict"} {
			// The strict policy tier does not trust a Hermes link it cannot
			// read again: the gateway itself blocks an ordinary Hermes link.
			gatewayAllowsLink := connector != "hermes" || pack != "strict"
			points := []string{"answer", "close", "write"}
			for _, protected := range protectedFiles {
				for _, point := range points {
					t.Run(connector+"/pack="+pack+"/"+protected+"/"+point, func(t *testing.T) {
						stdout, answered, code, wrote := retargetRun(t, connector, pack, point, protected)
						if point == "write" && !wrote {
							t.Fatal("the allow was not written, so the retarget never ran")
						}
						if gatewayAllowsLink && retargetRefused(0, answered) {
							t.Fatalf("the gateway blocked the ordinary link before the retarget: %.300s", answered)
						}
						if !retargetRefused(code, stdout) {
							t.Errorf("retargeted link was not refused: code=%d stdout=%q gateway=%.200s", code, stdout, answered)
						}
					})
				}
			}
		}
	}
	for _, connector := range []string{"hermes", "opencode"} {
		for _, pack := range []string{"", "permissive", "strict"} {
			for _, point := range []string{"", "same"} {
				t.Run(connector+"/pack="+pack+"/ordinary link/"+point, func(t *testing.T) {
					stdout, answered, code, _ := retargetRun(t, connector, pack, point, "")
					want := connector != "hermes" || pack != "strict"
					if got := !retargetRefused(code, stdout); got != want {
						t.Errorf("ordinary link allowed=%t, want %t: code=%d stdout=%q gateway=%.200s", got, want, code, stdout, answered)
					}
				})
			}
		}
	}
}
