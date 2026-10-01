// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// openCodeStubGateway answers the plugin's load heartbeat with allow and each
// tool call with the next response.
func openCodeStubGateway(t *testing.T, responses ...string) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload struct {
			Event string `json:"hook_event_name"`
		}
		_ = json.Unmarshal(body, &payload)
		w.Header().Set("Content-Type", "application/json")
		if payload.Event != "tool.execute.before" {
			_, _ = io.WriteString(w, `{"action":"allow","mode":"action"}`)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if len(responses) == 0 {
			_, _ = io.WriteString(w, `{"action":"allow","mode":"action"}`)
			return
		}
		_, _ = io.WriteString(w, responses[0])
		responses = responses[1:]
	}))
	t.Cleanup(server.Close)
	return server
}

// renderOpenCodePluginTemplate renders the current OpenCode plugin template
// the way Setup does.
func renderOpenCodePluginTemplate(t *testing.T, data templateData) string {
	t.Helper()
	return renderPluginAssetForTest(t, "opencode-plugin.js", data)
}

// renderPluginAssetForTest renders one embedded plugin template.
func renderPluginAssetForTest(t *testing.T, asset string, data templateData) string {
	t.Helper()
	tmpl, err := hookFS.ReadFile("hooks/" + asset)
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := renderTemplate(string(tmpl), data)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rendered, "{{") {
		t.Fatal("rendered plugin retains a template action")
	}
	return rendered
}

func openCodePluginTestData(t *testing.T, server *httptest.Server) templateData {
	t.Helper()
	root := testenv.PrivateTempDir(t)
	token := filepath.Join(root, ".hook-opencode.token")
	if err := os.WriteFile(token, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return templateData{
		APIAddr:     strings.TrimPrefix(server.URL, "http://"),
		TokenFileJS: javaScriptStringContent(token),
		FailMode:    "closed",
	}
}

// nodeHarnessTimeout bounds one node run of a plugin harness. It covers
// node's start, which on a busy Windows runner can take many seconds when
// it is the job's first node process.
const nodeHarnessTimeout = 60 * time.Second

// nodeForTest returns the node binary, or skips the test when there is none.
func nodeForTest(t *testing.T) string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required for the in-agent plugin tests")
	}
	return node
}

// runNodeHarness runs an ES module harness with node and returns its output
// lines. The test fails if node fails.
func runNodeHarness(t *testing.T, harness string, args ...string) []string {
	t.Helper()
	node := nodeForTest(t)
	ctx, cancel := context.WithTimeout(context.Background(), nodeHarnessTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, append([]string{"--input-type=module", "-e", harness}, args...)...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("node: %v\nstdout=%s\nstderr=%s", err, out, stderr.String())
	}
	return strings.Split(strings.TrimSpace(string(out)), "\n")
}

// nodeHarnessReady is the line an interactive harness prints once its
// plugins are loaded and it reads requests from stdin.
const nodeHarnessReady = "harness-ready"

// nodeHarnessReplyTimeout bounds one reply of a ready harness. It covers
// the plugin's own 10s gateway timeout with room to spare.
const nodeHarnessReplyTimeout = 30 * time.Second

// nodeHarnessSession is a running interactive harness: each request line
// written to it is answered with one stdout line. Node's start is bounded
// apart from the replies (the first node.exe launch on a fresh Windows
// runner pays the image load and antivirus scan), and a failure reports
// the step, how node exited, and its whole stderr.
type nodeHarnessSession struct {
	t      *testing.T
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	lines  chan string
	exited chan struct{}
	stderr bytes.Buffer // written by exec until exited is closed
	err    error        // cmd.Wait's result, set before exited is closed
}

// startNodeHarnessSession starts an ES module harness with node and waits
// for its ready line.
func startNodeHarnessSession(t *testing.T, harness string, args ...string) *nodeHarnessSession {
	t.Helper()
	node := nodeForTest(t)
	s := &nodeHarnessSession{
		t:      t,
		cmd:    exec.Command(node, append([]string{"--input-type=module", "-e", harness}, args...)...),
		lines:  make(chan string, 16),
		exited: make(chan struct{}),
	}
	s.cmd.Stderr = &s.stderr
	stdin, err := s.cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := s.cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	s.stdin = stdin
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			s.lines <- scanner.Text()
		}
		close(s.lines)
		s.err = s.cmd.Wait()
		close(s.exited)
	}()
	t.Cleanup(func() { _ = s.stop() })
	if got := s.next("start", nodeHarnessTimeout); got != nodeHarnessReady {
		t.Fatalf("start: node printed %q before its ready line; %s", got, s.stop())
	}
	return s
}

// request writes one request line and returns the harness's reply.
func (s *nodeHarnessSession) request(step, line string) string {
	s.t.Helper()
	if _, err := io.WriteString(s.stdin, line+"\n"); err != nil {
		s.t.Fatalf("%s: write request: %v; %s", step, err, s.stop())
	}
	return s.next(step, nodeHarnessReplyTimeout)
}

// close ends the session, failing if the harness printed more or exited
// with an error.
func (s *nodeHarnessSession) close() {
	s.t.Helper()
	if err := s.stdin.Close(); err != nil {
		s.t.Fatalf("close stdin: %v; %s", err, s.stop())
	}
	select {
	case line, ok := <-s.lines:
		if ok {
			s.t.Fatalf("exit: node printed unexpected %q; %s", line, s.stop())
		}
	case <-time.After(nodeHarnessReplyTimeout):
		s.t.Fatalf("exit: node did not exit within %s of stdin closing; %s", nodeHarnessReplyTimeout, s.stop())
	}
	if report, ok := s.wait(); !ok || s.err != nil {
		s.t.Fatalf("exit: %s", report)
	}
}

func (s *nodeHarnessSession) next(step string, timeout time.Duration) string {
	s.t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case line, ok := <-s.lines:
		if !ok {
			report, _ := s.wait()
			s.t.Fatalf("%s: node closed stdout without a reply; %s", step, report)
		}
		return line
	case <-timer.C:
		s.t.Fatalf("%s: node did not reply within %s; %s", step, timeout, s.stop())
	}
	return ""
}

// stop kills node and reports how it ended.
func (s *nodeHarnessSession) stop() string {
	_ = s.cmd.Process.Kill()
	report, _ := s.wait()
	return "killed by the test; " + report
}

// wait waits a bounded time for node to exit and reports how it ended; ok
// is false when it did not exit, and node is then killed.
func (s *nodeHarnessSession) wait() (report string, ok bool) {
	go func() {
		for range s.lines {
		}
	}()
	select {
	case <-s.exited:
		return fmt.Sprintf("node exit=%v (%v); stderr=%q", s.err, s.cmd.ProcessState, s.stderr.String()), true
	case <-time.After(nodeHarnessReplyTimeout):
		_ = s.cmd.Process.Kill()
		return fmt.Sprintf("node did not exit within %s", nodeHarnessReplyTimeout), false
	}
}

// writeRenderedPlugin renders one embedded plugin template into a private
// temporary file named name and returns its path.
func writeRenderedPlugin(t *testing.T, asset, name string, data templateData) string {
	t.Helper()
	path := filepath.Join(testenv.PrivateTempDir(t), name)
	if err := os.WriteFile(path, []byte(renderPluginAssetForTest(t, asset, data)), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// openCodePluginHarness loads a rendered OpenCode plugin with a stub TUI
// client, applies its config hook, runs tool.execute.before `calls` times and
// prints one verdict per call, then the toasts it showed.
const openCodePluginHarness = `
import { pathToFileURL } from "node:url";
const toasts = [];
const client = { tui: { showToast: async (arg) => { toasts.push(arg && arg.body ? arg.body : arg); return true; } } };
const href = pathToFileURL(process.argv[1]).href;
const loaded = await import(href);
const plugin = await loaded.DefenseClaw({ directory: "", client });
await plugin.config({ plugin_origins: [{ spec: href }], mcp: {} });
for (let i = 0; i < Number(process.argv[2]); i++) {
  try {
    await plugin["tool.execute.before"]({ tool: "bash", sessionID: "S", messageID: "M", callID: "C" + i }, { args: { command: "echo marker" } });
    console.log("allow");
  } catch (error) {
    console.log("block:" + String(error && error.message || error));
  }
}
await new Promise((resolve) => setTimeout(resolve, 50));
console.log("toasts:" + JSON.stringify(toasts));
`

func runOpenCodePluginHarness(t *testing.T, data templateData, calls int) []string {
	t.Helper()
	return runOpenCodePluginAssetHarness(t, "opencode-plugin.js", data, calls)
}

func runOpenCodePluginAssetHarness(t *testing.T, asset string, data templateData, calls int) []string {
	t.Helper()
	return runNodeHarness(t, openCodePluginHarness, writeRenderedPlugin(t, asset, "defenseclaw.mjs", data), strconv.Itoa(calls))
}

// ampPluginLoadHarness registers a rendered Amp plugin against a minimal
// plugin API and prints the handlers it installed.
const ampPluginLoadHarness = `
import { pathToFileURL } from "node:url";
const loaded = await import(pathToFileURL(process.argv[1]).href);
const handlers = {};
loaded.default({
  system: { workspaceRoot: "", executor: { kind: "" }, user: {} },
  helpers: { filePathFromURI: (uri) => uri, isPluginUINotAvailableError: () => true },
  on: (event, handler) => { handlers[event] = typeof handler; },
  activeThread: { current: null },
  ui: { notify: async () => {} },
});
console.log(JSON.stringify(Object.keys(handlers).sort().map((event) => event + ":" + handlers[event])));
`

// The Amp plugin must be a module Amp's runtime can load: a template that
// does not parse leaves every Amp session without DefenseClaw. Node strips
// the TypeScript types the way Bun does. Both the per-user render and the
// Windows standalone render (foreign-hook guard, install marker and listener
// proof) must register every event.
func TestAmpPluginTemplateLoadsAndRegistersEveryEvent(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	want := `["agent.end:function","agent.start:function","session.start:function","tool.call:function","tool.result:function"]`
	for name, data := range map[string]templateData{
		"per-user": {
			APIAddr:     "127.0.0.1:18970",
			TokenFileJS: javaScriptStringContent(filepath.Join(root, ".hook-amp.token")),
			FailMode:    "open",
		},
		"windows standalone": {
			APIAddr:            "127.0.0.1:18970",
			TokenFileJS:        javaScriptStringContent(filepath.Join(root, ".hook-amp.token")),
			ForeignHookGuardJS: javaScriptStringContent(filepath.Join(root, "missing", "defenseclaw-hook.exe")),
			InstallMarkerJS:    javaScriptStringContent(filepath.Join(root, "DefenseClaw-HookRuntime")),
			ListenerProofJS:    "1",
			FailMode:           "closed",
			Managed:            true,
		},
	} {
		path := writeRenderedPlugin(t, "amp-plugin.ts", strings.ReplaceAll(name, " ", "-")+".mts", data)
		if got := runNodeHarness(t, ampPluginLoadHarness, path); len(got) != 1 || got[0] != want {
			t.Fatalf("%s: registered handlers %q, want %s", name, got, want)
		}
	}
}
