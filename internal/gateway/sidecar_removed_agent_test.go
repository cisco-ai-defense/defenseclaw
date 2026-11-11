// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// isolateAgentHome points HOME (and the config folder Claude Desktop's
// engine is found under) at an empty folder, next to the test's own PATH, so
// whether an agent "may exist now" reads only this test's files, never an
// agent binary or Claude Desktop engine in the runner's real home.
func isolateAgentHome(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		// The Windows layout reads the profile and AppData folders; those
		// tests keep their current environment.
		return
	}
	t.Setenv("HOME", testenv.PrivateTempDir(t))
	t.Setenv("XDG_CONFIG_HOME", "")
}

// GAP-0492: an agent removed outside DefenseClaw (discovery no longer finds
// it) must stop only its own connector. The start keeps the other connector
// guarding, names the missing agent and its fix, keeps the earlier hooks and
// lock entry, and guards it again once the agent is back.
func TestRunGuardrailMultiRemovedAgentKeepsOtherConnectors(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("per-user Codex setup on Windows needs protected executable evidence")
	}
	f := newAgentSettingsRefusalFixture(t)
	// Only Claude Code's pack knows this marker. A skipped connector has no
	// fresh per-connector publication, so an accidental global-rule fallback
	// would allow its hook when the agent returns in the same process.
	f.cfg.Guardrail.Connectors["claudecode"] = config.PerConnectorGuardrailConfig{
		RulePackDir: meetRulePackDir(t, testenv.PrivateTempDir(t), "CF492"),
	}
	f.cfg.Guardrail.Connectors["codex"] = config.PerConnectorGuardrailConfig{
		RulePackDir: meetRulePackDir(t, testenv.PrivateTempDir(t), "CF492-PEER"), BlockAt: "HIGH",
	}
	discovery := filepath.Join(f.dataDir, "agent_discovery.json")
	installed := readAgentFile(t, discovery)

	s, err := f.boot(t)
	if err != nil || !reflect.DeepEqual(f.running(s), []string{"claudecode", "codex"}) {
		t.Fatalf("first start: err=%v running=%v", err, f.running(s))
	}
	lockPath := filepath.Join(f.dataDir, "hook_contract_lock.json")
	lockBefore := readAgentFile(t, lockPath)
	settingsBefore := readAgentFile(t, f.claudeSettings)

	removed := []byte(`{"agents":{"claudecode":{"version":"","binary_path":"","installed":false},"codex":{"version":"codex-cli 0.142.4"}}}`)
	if err := os.WriteFile(discovery, removed, 0o600); err != nil {
		t.Fatal(err)
	}
	// Simulate a new gateway process without the prior process's rule store.
	RemoveConnectorRulePackOverrides("claudecode")
	binDir := testenv.PrivateTempDir(t)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+"/usr/bin"+string(os.PathListSeparator)+"/bin")
	isolateAgentHome(t)
	s, err = f.boot(t)
	if err != nil {
		t.Fatalf("one removed agent stopped the gateway for every connector: %v", err)
	}
	snap := s.health.Snapshot()
	if snap.Guardrail.State != StateRunning || !reflect.DeepEqual(f.running(s), []string{"codex"}) {
		t.Fatalf("guardrail state=%s running=%v (%s), want codex running", snap.Guardrail.State, f.running(s), snap.Guardrail.LastError)
	}
	refused := fmt.Sprint(snap.Guardrail.Details[GuardrailAgentSettingsRefused])
	for _, want := range []string{"claudecode:", "the agent is not installed for this account", "discovery did not find it", "defenseclaw setup remove claudecode"} {
		if !strings.Contains(refused, want) {
			t.Errorf("health does not say %q: %s", want, refused)
		}
	}
	if notStarted := fmt.Sprint(snap.Guardrail.Details["connectors_not_started"]); !strings.Contains(notStarted, "claudecode") {
		t.Errorf("connectors_not_started = %s, want claudecode", notStarted)
	}
	if after := readAgentFile(t, f.claudeSettings); !bytes.Equal(after, settingsBefore) {
		t.Errorf("the start rewrote Claude Code settings:\nbefore:\n%s\nafter:\n%s", settingsBefore, after)
	}
	if after := readAgentFile(t, lockPath); !bytes.Equal(jsonConnectorEntry(t, after, "claudecode"), jsonConnectorEntry(t, lockBefore, "claudecode")) {
		t.Error("the start changed the claudecode hook contract lock entry")
	}
	if active := connector.LoadActiveConnectors(f.dataDir); !reflect.DeepEqual(active, []string{"claudecode", "codex"}) {
		t.Errorf("active connectors = %v, want claudecode kept for when its agent returns", active)
	}
	// The retained registration reaches this same gateway after the binary
	// returns. Both protected and benign calls must receive the same named
	// block until a new gateway process admits it.
	if err := os.WriteFile(filepath.Join(binDir, "claude"), []byte("agent"), 0o700); err != nil {
		t.Fatal(err)
	}
	api := &APIServer{health: s.health, scannerCfg: f.cfg}
	for _, tc := range []struct {
		command, action string
	}{
		{"echo benign", "allow"},
		{"rm -rf /", "block"},
	} {
		if verdict := removedAgentHookVerdict(t, api, "codex", tc.command); verdict.Action != tc.action {
			t.Fatalf("surviving Codex %q answer = %+v, want %s", tc.command, verdict, tc.action)
		}
	}
	for _, command := range []string{"echo CF492_fixture_marker", "echo benign"} {
		verdict := removedAgentHookVerdict(t, api, "claudecode", command)
		if verdict.Action != "block" || !strings.Contains(verdict.Reason, "defenseclaw-gateway restart") ||
			!strings.Contains(verdict.Reason, "defenseclaw setup remove claudecode") {
			t.Fatalf("returned agent %q answer = %+v, want named block until restart", command, verdict)
		}
	}
	// A config reload reruns the guardrail on this Sidecar. It may refresh
	// files and health, but cannot re-admit a connector skipped at process start.
	if err := os.WriteFile(discovery, installed, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rerunRemovedAgentGuardrail(t, s); err != nil {
		t.Fatalf("same-process guardrail reload: %v", err)
	}
	if got := f.running(s); !reflect.DeepEqual(got, []string{"codex"}) {
		t.Fatalf("same-process reload running=%v, want only codex", got)
	}
	if verdict := removedAgentHookVerdict(t, api, "claudecode", "echo benign"); verdict.Action != "block" ||
		!strings.Contains(verdict.Reason, "defenseclaw-gateway restart") {
		t.Fatalf("same-process reload re-admitted skipped connector: %+v", verdict)
	}

	s, err = f.boot(t)
	if err != nil || !reflect.DeepEqual(f.running(s), []string{"claudecode", "codex"}) {
		t.Fatalf("start after the agent is back: err=%v running=%v", err, f.running(s))
	}
	if refused, ok := s.health.Snapshot().Guardrail.Details[GuardrailAgentSettingsRefused]; ok {
		t.Errorf("start after the agent is back still reports %v", refused)
	}
	if ids := findingIDs(ScanAllRulesForConnector("claudecode", "CF492_fixture_marker", "Bash")); !containsRuleID(ids, "CF492-FIXTURE") {
		t.Fatalf("re-admitted connector rule ids = %v, want its own marker rule", ids)
	}
	api = &APIServer{health: s.health, scannerCfg: f.cfg}
	hook := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", strings.NewReader(
		`{"hook_event_name":"PreToolUse","session_id":"admitted-agent","tool_name":"Bash","tool_input":{"command":"echo benign"}}`))
	answer := httptest.NewRecorder()
	api.handleAgentHook("claudecode").ServeHTTP(answer, hook)
	var admitted struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal(answer.Body.Bytes(), &admitted); err != nil || admitted.Action != "allow" {
		t.Fatalf("admitted agent answer %d: %+v, error=%v", answer.Code, admitted, err)
	}
}

type removedAgentVerdict struct {
	Action string `json:"action"`
	Reason string `json:"reason"`
}

func removedAgentHookVerdict(t *testing.T, api *APIServer, name, command string) removedAgentVerdict {
	t.Helper()
	path := "/api/v1/claude-code/hook"
	if name == "codex" {
		path = "/api/v1/codex/hook"
	}
	body, err := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse", "session_id": "removed-agent-test",
		"tool_name": "Bash", "tool_input": map[string]string{"command": command},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	if name == "codex" {
		setTestCodexHookBinding(request, "PreToolUse", api.hookProfileForRequest(t.Context(), "codex").ContractID)
	}
	answer := httptest.NewRecorder()
	api.handleAgentHook(name).ServeHTTP(answer, request)
	var verdict removedAgentVerdict
	if err := json.Unmarshal(answer.Body.Bytes(), &verdict); err != nil {
		t.Fatalf("%s hook answer %d: %v: %s", name, answer.Code, err, answer.Body.String())
	}
	if verdict.Action == "" {
		t.Fatalf("%s hook answer %d has no action: %s", name, answer.Code, answer.Body.String())
	}
	return verdict
}

func rerunRemovedAgentGuardrail(t *testing.T, s *Sidecar) error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	s.health.SetGuardrail(StateStarting, "", nil)
	go func() { done <- s.runGuardrailMulti(ctx) }()
	deadline := time.After(time.Minute)
	for s.health.Snapshot().Guardrail.State != StateRunning {
		select {
		case err := <-done:
			return err
		case <-time.After(10 * time.Millisecond):
		case <-deadline:
			cancel()
			<-done
			return errors.New("same-process guardrail reload did not finish within a minute")
		}
	}
	cancel()
	return <-done
}

// GAP-0492: on Windows the executable that setup selected is protected
// evidence; deleting it (the Amp npm package) makes executable admission
// refuse before Setup writes anything. Only that connector is skipped. An
// executable that is still there but changed keeps failing the refresh.
func TestSetupConnectorsIsolatedSkipsAnActiveConnectorWhoseAgentExecutableIsGone(t *testing.T) {
	for _, tc := range []struct {
		name                                                                                  string
		present, onPath, offPath, knownDir, stale, recordedPath, lstatError, changed, skipped bool
	}{
		{name: "selected path gone without current absence proof"},
		{name: "executable changed", present: true},
		{name: "moved executable on PATH", onPath: true},
		{name: "moved executable outside search paths", offPath: true},
		{name: "moved executable in known install directory", knownDir: true},
		{name: "stale discovery miss with executable on PATH", stale: true, onPath: true},
		{name: "stale discovery after custom move", stale: true, offPath: true, recordedPath: true},
		{name: "stale discovery but setup changed state before failure", stale: true, changed: true},
		{name: "discovery confirms no selected executable", stale: true, skipped: true},
		{name: "setup changed state before failure", changed: true},
		{name: "Lstat error other than missing", lstatError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if (tc.lstatError || tc.knownDir) && runtime.GOOS == "windows" {
				t.Skip("the home-directory and symlink-loop fixtures are Unix-only")
			}
			s := multiBootSidecar(t)
			s.cfg.DataDir = testenv.PrivateTempDir(t)
			s.health = NewSidecarHealth()
			binDir := testenv.PrivateTempDir(t)
			t.Setenv("PATH", binDir)
			isolateAgentHome(t)
			executable := filepath.Join(testenv.PrivateTempDir(t), "npm", "node_modules", "agent", "claude")
			if tc.lstatError {
				loop := filepath.Join(testenv.PrivateTempDir(t), "loop")
				if err := os.Symlink("loop", loop); err != nil {
					t.Fatal(err)
				}
				executable = filepath.Join(loop, "claude")
			}
			if tc.onPath {
				binary := "claude"
				if runtime.GOOS == "windows" {
					binary += ".exe"
				}
				if err := os.WriteFile(filepath.Join(binDir, binary), []byte("agent"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if tc.offPath {
				binary := "claude"
				if runtime.GOOS == "windows" {
					binary += ".exe"
				}
				if err := os.WriteFile(filepath.Join(testenv.PrivateTempDir(t), binary), []byte("agent"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if tc.knownDir {
				home := testenv.PrivateTempDir(t)
				t.Setenv("HOME", home)
				known := filepath.Join(home, ".local", "bin", "claude")
				if err := os.MkdirAll(filepath.Dir(known), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(known, []byte("agent"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if tc.present {
				if err := os.MkdirAll(filepath.Dir(executable), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(executable, []byte("agent"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			lock := stageAdmissionFixture(t, s.cfg.DataDir)
			if tc.recordedPath {
				lock.AgentExecutable = executable
			}
			signal := map[string]any{"version": admissionFixtureAgentVersion, "binary_path": executable}
			if tc.stale {
				signal = map[string]any{"version": "", "binary_path": "", "installed": false}
			}
			raw, err := json.Marshal(map[string]any{"agents": map[string]any{"claudecode": signal}})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(s.cfg.DataDir, "agent_discovery.json"), raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := connector.SaveHookContractLockEntry(s.cfg.DataDir, lock); err != nil {
				t.Fatal(err)
			}
			if err := connector.SaveActiveConnectors(s.cfg.DataDir, []string{"claudecode", "codex"}); err != nil {
				t.Fatal(err)
			}
			setupErr := fmt.Errorf("Amp executable admission: inspect selected executable: lstat %s: %w",
				executable, connector.ErrExecutableAdmission)
			if tc.stale {
				setupErr = fmt.Errorf("discovery did not find the agent: %w", ErrHookContractAdmission)
			}
			if tc.changed {
				setupErr = errors.New("setup wrote state before it failed")
			}
			gone := &bootStubConnector{
				stubConnector: stubConnector{name: "claudecode"},
				setupErr:      setupErr,
			}
			peer := &bootStubConnector{stubConnector: stubConnector{name: "codex"}}
			transaction, err := s.setupConnectorsIsolatedTransaction(
				context.Background(), []connector.Connector{gone, peer},
				"tok", "127.0.0.1:0", "127.0.0.1:0", "master", guardrail.NewRulePackCache(),
			)
			if !tc.skipped {
				if err == nil || !strings.Contains(err.Error(), "connector claudecode refresh failed") {
					t.Fatalf("refresh error = %v, want the present, moved, uncertain or changed agent to fail the refresh", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("a removed agent failed the start for every connector: %v", err)
			}
			if want := []string{"codex"}; !reflect.DeepEqual(transaction.succeeded, want) {
				t.Fatalf("survivors=%v, want %v", transaction.succeeded, want)
			}
			if want := []string{"claudecode"}; !reflect.DeepEqual(transaction.keptRegistrations, want) {
				t.Fatalf("keptRegistrations=%v, want %v", transaction.keptRegistrations, want)
			}
			reason := transaction.agentSettingsRefused["claudecode"]
			for _, want := range []string{"the agent is not installed for this account", "discovery did not find it", "defenseclaw-gateway restart", "defenseclaw setup remove claudecode"} {
				if !strings.Contains(reason, want) {
					t.Errorf("reason %q does not say %q", reason, want)
				}
			}
			if transaction.notStartedReasons["claudecode"] != reason {
				t.Errorf("not-started reason = %q, want %q", transaction.notStartedReasons["claudecode"], reason)
			}
			if gone.teardownCalls != 0 {
				t.Errorf("teardownCalls=%d, want 0 (keep the earlier hooks)", gone.teardownCalls)
			}
		})
	}
}

type waitingAbsentConnector struct {
	bootStubConnector
	entered chan struct{}
	release chan struct{}
}

func (b *waitingAbsentConnector) Setup(ctx context.Context, _ connector.SetupOpts) error {
	close(b.entered)
	select {
	case <-b.release:
		return b.setupErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestPendingAbsentConnectorRetainedHookIsDenied(t *testing.T) {
	s := multiBootSidecar(t)
	s.cfg.DataDir = testenv.PrivateTempDir(t)
	s.cfg.Guardrail.HookFailMode = "closed"
	s.health = NewSidecarHealth()
	t.Setenv("PATH", testenv.PrivateTempDir(t))
	isolateAgentHome(t)
	lock := stageAdmissionFixture(t, s.cfg.DataDir)
	if err := connector.SaveHookContractLockEntry(s.cfg.DataDir, lock); err != nil {
		t.Fatal(err)
	}
	if err := connector.SaveActiveConnectors(s.cfg.DataDir, []string{"claudecode", "codex"}); err != nil {
		t.Fatal(err)
	}
	discovery, err := json.Marshal(map[string]any{"agents": map[string]any{
		"claudecode": map[string]any{"version": "", "binary_path": "", "installed": false},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.cfg.DataDir, "agent_discovery.json"), discovery, 0o600); err != nil {
		t.Fatal(err)
	}
	absent := &waitingAbsentConnector{
		bootStubConnector: bootStubConnector{
			stubConnector: stubConnector{name: "claudecode"},
			setupErr:      fmt.Errorf("discovery did not find the agent: %w", ErrHookContractAdmission),
		},
		entered: make(chan struct{}), release: make(chan struct{}),
	}
	peer := &bootStubConnector{stubConnector: stubConnector{name: "codex"}}
	type result struct {
		transaction multiConnectorSetupTransaction
		err         error
	}
	done := make(chan result, 1)
	go func() {
		transaction, err := s.setupConnectorsIsolatedTransaction(context.Background(),
			[]connector.Connector{absent, peer}, "tok", "127.0.0.1:0", "127.0.0.1:0", "master", guardrail.NewRulePackCache())
		done <- result{transaction, err}
	}()
	released := false
	defer func() {
		if !released {
			close(absent.release)
		}
	}()
	select {
	case <-absent.entered:
	case <-time.After(time.Minute):
		t.Fatal("absent connector setup did not begin")
	}
	api := &APIServer{health: s.health, scannerCfg: s.cfg}
	for _, command := range []string{"echo CF492_fixture_marker", "echo benign"} {
		if verdict := removedAgentHookVerdict(t, api, "claudecode", command); verdict.Action != "block" ||
			!strings.Contains(verdict.Reason, "setup is pending") {
			t.Fatalf("retained hook during pending setup for %q = %+v, want pending block", command, verdict)
		}
	}
	close(absent.release)
	released = true
	select {
	case got := <-done:
		if got.err != nil || !reflect.DeepEqual(got.transaction.succeeded, []string{"codex"}) {
			t.Fatalf("setup result: err=%v succeeded=%v", got.err, got.transaction.succeeded)
		}
	case <-time.After(time.Minute):
		t.Fatal("absent connector setup did not finish")
	}
	for _, command := range []string{"echo CF492_fixture_marker", "echo benign"} {
		if verdict := removedAgentHookVerdict(t, api, "claudecode", command); verdict.Action != "block" ||
			!strings.Contains(verdict.Reason, "agent is not installed") ||
			!strings.Contains(verdict.Reason, "defenseclaw-gateway restart") {
			t.Fatalf("skipped hook for %q = %+v, want absent-agent block", command, verdict)
		}
	}
}

func TestPendingConnectorHookFollowsOutageMode(t *testing.T) {
	f := newAgentSettingsRefusalFixture(t)
	f.cfg.Guardrail.Mode = "observe"
	health := NewSidecarHealth()
	health.beginConnectorSetup([]string{"claudecode", "codex"})
	api := NewAPIServer("127.0.0.1:0", health, nil, nil, nil, f.cfg)
	benign := func() removedAgentVerdict {
		return removedAgentHookVerdict(t, api, "claudecode", "echo benign")
	}
	if got := benign(); got.Action != "allow" || !strings.Contains(got.Reason, "setup is pending") {
		t.Fatalf("default pending answer = %+v, want allowed with setup notice", got)
	}
	if got := removedAgentHookVerdict(t, api, "codex", "echo benign"); got.Action != "allow" {
		t.Fatalf("peer pending answer = %+v, want allowed", got)
	}
	health.finishConnectorSetup(nil, []string{"claudecode"})
	if got := benign(); got.Action != "allow" || !strings.Contains(got.Reason, "setup did not finish") ||
		strings.Contains(got.Reason, "setup is pending") {
		t.Fatalf("failed setup answer = %+v, want the completed state", got)
	}
	f.cfg.Guardrail.HookFailMode = "closed"
	if got := benign(); got.Action != "block" || !strings.Contains(got.Reason, "setup did not finish") {
		t.Fatalf("saved closed answer = %+v, want block", got)
	}
	f.cfg.Guardrail.HookFailMode = ""
	f.cfg.DeploymentMode = string(config.DeploymentModeManagedEnterprise)
	if got := benign(); got.Action != "block" {
		t.Fatalf("managed answer = %+v, want block", got)
	}
	f.cfg.DeploymentMode = ""
	health.finishConnectorSetup([]string{"claudecode", "codex"}, nil)
	if got := benign(); got.Action != "allow" || strings.Contains(got.Reason, "setup") {
		t.Fatalf("completed setup answer = %+v, want ordinary allow", got)
	}
}
