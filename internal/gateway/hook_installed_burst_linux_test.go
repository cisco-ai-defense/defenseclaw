// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

// TestInstalledClaudeBurstAnswersAndRecovers exercises the rendered entry
// point and its native POST helper, including process startup and admission.
// It uses the four calls per each of 32 sessions made by dcperf's burst32.
// Run the test binary with taskset on two CPUs and GOMAXPROCS=2.
func TestInstalledClaudeBurstAnswersAndRecovers(t *testing.T) {
	if runtime.GOMAXPROCS(0) != 2 {
		t.Skip("run with GOMAXPROCS=2")
	}
	installCorrelationHMACForTest()
	installDefaultProfileConnector(t, "claudecode")
	fixture := newSidecarRuntimeFixture(t, true)
	logger := audit.NewLogger(fixture.store)
	fingerprints, err := observabilityredaction.NewEngine(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	logger.SetRuntimeV8Emitter(&sidecarOwnedObservabilityV8Runtime{runtime: fixture.runtime, redactionEngine: fingerprints})
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, fixture.store, logger, cfg)
	bindHookLifecycleV8(t, api, fixture.runtime)
	var handled atomic.Int64
	hook := api.handleAgentHook("claudecode")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r, release := api.admitHookCaller(w, r, "installed-burst-user", r.URL.Path)
		if release == nil {
			return
		}
		defer release()
		// Model the short store wait observed on the two-processor host.
		// Holding a run slot across it serializes 32 otherwise independent
		// calls beyond the installed hook's fixed four-second cap.
		time.Sleep(75 * time.Millisecond)
		hook.ServeHTTP(w, r)
		handled.Add(1)
	}))
	defer server.Close()

	home := t.TempDir()
	data := filepath.Join(home, ".defenseclaw")
	hookDir := filepath.Join(data, "hooks")
	work := filepath.Join(home, "work")
	if err := os.MkdirAll(work, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "hello.txt"), []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := connector.WriteHookScriptsForConnectorObjectWithOpts(hookDir, connector.SetupOpts{
		DataDir: data, APIAddr: strings.TrimPrefix(server.URL, "http://"), APIToken: "scoped-test-token", HookFailMode: "open",
	}, connector.NewClaudeCodeConnector()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "config.yaml"), []byte("config_version: 9\nobservability: {}\nguardrail:\n  mode: action\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "gateway.pid"), []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o600); err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, binary := range []struct{ name, pkg string }{
		{"defenseclaw-hook-post", "./cmd/defenseclaw-hook-post"},
		{"defenseclaw-gateway", "./cmd/defenseclaw"},
	} {
		build := exec.Command("go", "build", "-o", filepath.Join(binDir, binary.name), binary.pkg)
		build.Dir = filepath.Join("..", "..")
		if output, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v: %s", binary.name, err, output)
		}
	}
	if err := os.WriteFile(filepath.Join(hookDir, ".gateway-helper"), []byte(filepath.Join(binDir, "defenseclaw-gateway")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	call := func(session string, index int) (time.Duration, string, error) {
		body, err := json.Marshal(map[string]any{
			"session_id": session, "hook_event_name": "PreToolUse", "cwd": work,
			"permission_mode": "default", "tool_name": "Read", "tool_use_id": fmt.Sprintf("toolu_%s_%d", session, index),
			"tool_input": map[string]any{"file_path": filepath.Join(work, "hello.txt")},
		})
		if err != nil {
			return 0, "", err
		}
		cmd := exec.Command("bash", filepath.Join(hookDir, "claude-code-hook.sh"))
		cmd.Dir = work
		cmd.Stdin = bytes.NewReader(body)
		cmd.Env = []string{"HOME=" + home, "DEFENSECLAW_HOME=" + data, "DEFENSECLAW_GATEWAY_AUTOSTART=0", "PATH=/usr/local/bin:/usr/bin:/bin", "GOMAXPROCS=2"}
		began := time.Now()
		out, err := cmd.CombinedOutput()
		return time.Since(began), string(out), err
	}
	for i := range 3 {
		if _, out, err := call("warm", i); err != nil || strings.Contains(out, "deny") {
			t.Fatalf("warm hook %d: %v %q", i, err, out)
		}
	}
	type result struct {
		took time.Duration
		out  string
		err  error
	}
	results := make([]result, 128)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for lane := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for n := range 4 {
				index := lane*4 + n
				results[index].took, results[index].out, results[index].err = call(fmt.Sprintf("burst-%d", lane), n)
			}
		}()
	}
	close(start)
	wg.Wait()
	bad, worst := 0, time.Duration(0)
	var examples []string
	for _, got := range results {
		if got.took > worst {
			worst = got.took
		}
		if got.err != nil || strings.Contains(got.out, `"permissionDecision":"deny"`) || strings.Contains(got.out, "not checking this session") {
			bad++
			if len(examples) < 4 {
				examples = append(examples, fmt.Sprintf("%s err=%v out=%q", got.took, got.err, got.out))
			}
		}
	}
	for i := range 4 {
		if _, out, err := call("recovery", i); err != nil || strings.Contains(out, "deny") || strings.Contains(out, "not checking this session") {
			t.Errorf("recovery call %d: %v %q", i, err, out)
		}
	}
	var failures []byte
	failures, _ = os.ReadFile(filepath.Join(data, "logs", "hook-failures.jsonl"))
	t.Logf("burst 128/32: unanswered=%d worst=%s handled=%d failure_bytes=%d examples=%v", bad, worst, handled.Load(), len(failures), examples)
	if bad != 0 || len(failures) != 0 {
		t.Errorf("healthy installed hooks must receive gateway answers: %d unanswered, failures %q", bad, failures)
	}
}
