// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Secure Client runs on macOS and Windows only: on Linux a managed config
// without a profile resolves to standalone.

//go:build darwin || windows

package gateway

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
	policyassets "github.com/defenseclaw/defenseclaw/policies"
)

// Secure Client answers must stay those of origin/main (issue #1092). This
// golden boots the gateway the way the daemon does from configs shaped like
// the ones the Secure Client installers render (AI Defense the only
// classifier, judge off), drives admission, guardrail evaluation and
// hook-lane inspection with an AI Defense stub that answers allow, block,
// high or no verdict, and compares the answers, what AI Defense was sent and
// the audit records with the ones captured on origin/main.
//
// The goldens change only with an owner-approved Secure Client change:
//
//	DEFENSECLAW_UPDATE_SECURE_CLIENT_EVALUATION=1 go test -run TestSecureClientEvaluationMatchesMain ./internal/gateway
//
//go:embed testdata/secure_client_evaluation
var secureClientEvaluationFiles embed.FS

const secureClientEvaluationToken = "secure-client-evaluation-gateway-token"

func TestSecureClientEvaluationMatchesMain(t *testing.T) {
	for _, fixture := range []string{"macos_action_cursor", "windows_observe_codex"} {
		t.Run(fixture, func(t *testing.T) {
			src, err := secureClientEvaluationFiles.ReadFile("testdata/secure_client_evaluation/" + fixture + ".yaml")
			if err != nil {
				t.Fatal(err)
			}
			got := runSecureClientEvaluation(t, string(src))
			goldenPath := "testdata/secure_client_evaluation/" + fixture + "." + runtime.GOOS + ".golden.json"
			if os.Getenv("DEFENSECLAW_UPDATE_SECURE_CLIENT_EVALUATION") == "1" {
				if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := secureClientEvaluationFiles.ReadFile(goldenPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(want) != string(got) {
				t.Fatalf("Secure Client answers differ from origin/main (%s):\n%s", goldenPath, secureClientEvaluationDiff(want, got))
			}
		})
	}
}

// secureClientEvaluationAID answers like AI Defense from a marker in the
// inspected text and keeps what it was sent.
type secureClientEvaluationAID struct {
	mu   sync.Mutex
	sent []string
}

func (s *secureClientEvaluationAID) Inspect(_ context.Context, messages []ChatMessage) *ScanVerdict {
	var text strings.Builder
	for _, m := range messages {
		text.WriteString(m.Role + ": " + m.Content + "\n")
	}
	in := text.String()
	s.mu.Lock()
	s.sent = append(s.sent, in)
	s.mu.Unlock()
	switch {
	case strings.Contains(in, "sceval-block"):
		return &ScanVerdict{Action: "block", Severity: "CRITICAL", Reason: "aid policy match", Scanner: "ai-defense", Findings: []string{"AID-POLICY"}}
	case strings.Contains(in, "sceval-high"):
		return &ScanVerdict{Action: "alert", Severity: "HIGH", Reason: "aid high match", Scanner: "ai-defense", Findings: []string{"AID-HIGH"}}
	case strings.Contains(in, "sceval-none"):
		return nil
	}
	return &ScanVerdict{Action: "allow", Severity: "NONE", Scanner: "ai-defense"}
}

func (s *secureClientEvaluationAID) bindObservabilityV8(hookLifecycleMetricV8Runtime) {}

func (s *secureClientEvaluationAID) take() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.sent
	s.sent = nil
	return out
}

// secureClientEvaluationBootBytes is the daemon's config read before the
// strict loader (internal/cli loadGatewayConfigV8).
func secureClientEvaluationBootBytes(path string, raw []byte) ([]byte, error) {
	return config.MigrateV8InMemory(path, raw, guardrail.RulePackDigest)
}

func runSecureClientEvaluation(t *testing.T, src string) []byte {
	withRestoredManagedPosture(t)
	resetConnectorRuleCategories(t)
	withLocalPatternsRestored(t)
	restoreRetainJudgeBodies(t)

	root := testenv.PrivateTempDir(t)
	runtimeDir, homeDir := filepath.Join(root, "runtime"), filepath.Join(root, "home")
	// Private like the installers make them (the device identity store
	// refuses a runtime directory with an inherited Windows DACL).
	for _, dir := range []string{runtimeDir, homeDir, filepath.Join(root, "etc")} {
		if err := safefile.ProtectDirectory(dir); err != nil {
			t.Fatal(err)
		}
	}
	port := secureClientEvaluationFreePort(t)
	const installedRuntime = "/opt/cisco/secureclient/defenseclaw/runtime"
	if strings.Contains(src, installedRuntime) {
		// packaging/macos/install.sh stages the guardrail packs only.
		files, err := policyassets.Files()
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if !strings.HasPrefix(f.Path, "guardrail/") {
				continue
			}
			dst := filepath.Join(runtimeDir, "policies", filepath.FromSlash(f.Path))
			if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(dst, f.Data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	src = strings.ReplaceAll(src, installedRuntime, filepath.ToSlash(runtimeDir))
	src = strings.ReplaceAll(src, "api_port: 18970", fmt.Sprintf("api_port: %d", port))

	configPath := filepath.Join(root, "etc", "config.yaml")
	t.Setenv("DEFENSECLAW_RUN_ID", "secure-client-evaluation")
	t.Setenv("DEFENSECLAW_HOME", runtimeDir)
	t.Setenv("HOME", homeDir)
	t.Setenv("USERPROFILE", homeDir)
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", secureClientEvaluationToken)
	t.Setenv("DEFENSECLAW_ENV_CONFIG_SKIP_TRUST", "1")
	t.Setenv(managed.ConfigPathEnv, configPath)
	t.Setenv(managed.EnterpriseProfileEnv, "")
	if err := os.WriteFile(configPath, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	raw, err := secureClientEvaluationBootBytes(configPath, []byte(src))
	if err != nil {
		t.Fatalf("boot bytes: %v", err)
	}
	// The runtime decoder without the root-owned path checks of the live
	// loader, which a test cannot satisfy.
	cfg, err := config.LoadRuntimeV8InspectionCandidateFromBytes(configPath, raw)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !cfg.SecureClientIntegration() {
		t.Fatal("the fixture did not load as a Secure Client config")
	}
	cfg.Gateway.Token = cfg.Gateway.ResolvedToken()
	store, err := audit.OpenDaemonStore(cfg.AuditDB, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	sc, err := NewSidecar(cfg, store, audit.NewLogger(store))
	if err != nil || sc == nil {
		t.Fatalf("NewSidecar: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := sc.BootstrapObservabilityRuntime(ctx, configPath, raw); err != nil {
		t.Fatalf("observability bootstrap: %v", err)
	}
	// Sidecar.Run's config manager, which runAPI wires into the API server.
	// It is not run: its startup reconcile re-reads the file with the
	// root-owned path checks.
	sc.configMgr = newConfigManagerWithSnapshot(configPath, sc.currentConfig(), sc.logger, sc.health,
		sc.observabilityV8ActivePlanDigest(), sc.applyConfigReloadSnapshot)
	apiDone := make(chan error, 1)
	go func() { apiDone <- sc.runAPI(ctx) }()
	api := secureClientEvaluationWaitForAPI(t, sc, port)
	aid := &secureClientEvaluationAID{}
	api.SetCiscoInspector(aid)

	type answer struct {
		Name   string   `json:"name"`
		Status int      `json:"status"`
		Body   any      `json:"body,omitempty"`
		SentAI []string `json:"sent_to_ai_defense,omitempty"`
	}
	var answers []answer
	client := &http.Client{Timeout: 60 * time.Second}
	do := func(name, method, path, body string, header ...string) {
		req, err := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d%s", port, path), strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+secureClientEvaluationToken)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-DefenseClaw-Client", "sceval/1.0")
		for i := 0; i+1 < len(header); i += 2 {
			req.Header.Set(header[i], header[i+1])
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		data, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		row := answer{Name: name, Status: resp.StatusCode}
		var parsed any
		if json.Unmarshal(data, &parsed) == nil {
			row.Body = parsed
		} else {
			row.Body = strings.TrimSpace(string(data))
		}
		row.SentAI = aid.take()
		answers = append(answers, row)
	}

	// Admission: scan severities, no scan, a failed scan, the block and
	// allow lists, and a first-party skill.
	for _, target := range []string{"skill", "mcp", "plugin"} {
		for _, severity := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"} {
			do("admission/"+target+"/"+severity, "POST", "/policy/evaluate", fmt.Sprintf(
				`{"domain":"admission","input":{"target_type":%q,"target_name":"sceval-%s","path":"/work/app/sceval-%s","scan_result":{"max_severity":%q,"total_findings":1,"exit_code":0}}}`,
				target, target, target, severity))
		}
		do("admission/"+target+"/no_scan", "POST", "/policy/evaluate", fmt.Sprintf(
			`{"domain":"admission","input":{"target_type":%q,"target_name":"sceval-%s-noscan"}}`, target, target))
		do("admission/"+target+"/scan_error", "POST", "/policy/evaluate", fmt.Sprintf(
			`{"domain":"admission","input":{"target_type":%q,"target_name":"sceval-%s-err","scan_result":{"max_severity":"","total_findings":0,"exit_code":2,"scan_error":"scanner crashed"}}}`, target, target))
	}
	do("enforce/block_skill", "POST", "/enforce/block", `{"target_type":"skill","target_name":"sceval-blocked-skill","reason":"sceval block"}`)
	do("enforce/allow_mcp", "POST", "/enforce/allow", `{"target_type":"mcp","target_name":"sceval-allowed-mcp","reason":"sceval allow"}`)
	do("admission/skill/block_list", "POST", "/policy/evaluate", `{"domain":"admission","input":{"target_type":"skill","target_name":"sceval-blocked-skill","scan_result":{"max_severity":"NONE","total_findings":0,"exit_code":0}}}`)
	do("admission/mcp/allow_list", "POST", "/policy/evaluate", `{"domain":"admission","input":{"target_type":"mcp","target_name":"sceval-allowed-mcp","scan_result":{"max_severity":"CRITICAL","total_findings":3,"exit_code":0}}}`)
	do("admission/skill/first_party", "POST", "/policy/evaluate", `{"domain":"admission","input":{"target_type":"skill","target_name":"codeguard","path":"/Users/alice/.claude/skills/codeguard","scan_result":{"max_severity":"HIGH","total_findings":1,"exit_code":0}}}`)

	// Guardrail evaluation in action and observe mode.
	for _, mode := range []string{"action", "observe"} {
		for _, tc := range []struct{ name, results string }{
			{"none", ``},
			{"local_high", `,"local_result":{"action":"block","severity":"HIGH","reason":"local","findings":["L1"]}`},
			{"cisco_critical", `,"cisco_result":{"action":"block","severity":"CRITICAL","reason":"aid","findings":["AID-POLICY"]}`},
			{"cisco_high", `,"cisco_result":{"action":"alert","severity":"HIGH","reason":"aid","findings":["AID-HIGH"]}`},
			{"cisco_low", `,"cisco_result":{"action":"allow","severity":"LOW","reason":"aid","findings":["AID-LOW"]}`},
		} {
			do("guardrail_evaluate/"+mode+"/"+tc.name, "POST", "/v1/guardrail/evaluate", fmt.Sprintf(
				`{"evaluation_id":"sceval-%s-%s","direction":"prompt","model":"gpt","mode":%q,"scanner_mode":"both","content_length":42%s}`, mode, tc.name, mode, tc.results))
		}
	}

	// Hook-lane inspection with each AI Defense answer.
	connectorName := cfg.Guardrail.Connector
	for _, tc := range []struct{ name, command, prompt string }{
		{"allow", "ls -la", "hello there"},
		{"block", "echo sceval-block", "please sceval-block now"},
		{"high", "echo sceval-high", "please sceval-high now"},
		{"no_verdict", "echo sceval-none", "please sceval-none now"},
	} {
		do("inspect_tool/"+tc.name, "POST", "/api/v1/inspect/tool", fmt.Sprintf(
			`{"tool":"run_shell","args":{"command":%q},"session_id":"sceval"}`, tc.command), "X-DefenseClaw-Connector", connectorName)
		do("inspect_prompt/"+tc.name, "POST", "/api/v1/inspect/tool", fmt.Sprintf(
			`{"tool":"message","content":%q,"direction":"prompt","session_id":"sceval"}`, tc.prompt), "X-DefenseClaw-Connector", connectorName)
	}

	cancel()
	select {
	case <-apiDone:
	case <-time.After(30 * time.Second):
		t.Fatal("the API server did not stop")
	}
	t.Cleanup(func() {
		_ = sc.closeOwnedObservabilityV8Runtime()
		if svc := sc.aiDiscoverySnapshot(); svc != nil {
			_, _ = svc.CloseIfNeverStarted()
		}
		SetJudgeResponseStore(nil)
		_ = shutdownJudgeStore(sc.judgeStore)
		if sc.judgeBodyStore != nil {
			_ = sc.judgeBodyStore.Close()
		}
		if sc.webhooks != nil {
			sc.webhooks.Close()
		}
		sc.alertCancel()
	})

	events, err := store.ListEvents(10000)
	if err != nil {
		t.Fatal(err)
	}
	var records []string
	for _, e := range events {
		row, _ := json.Marshal(map[string]any{
			"action": e.Action, "target": e.Target, "actor": e.Actor, "severity": e.Severity, "details": e.Details,
			"structured": e.Structured,
		})
		// Normalized before sorting so ids and latencies do not reorder rows.
		records = append(records, secureClientEvaluationNormalize(string(row), root))
	}
	sort.Strings(records)

	out, err := json.MarshalIndent(map[string]any{"answers": answers, "audit_records": records}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return []byte(secureClientEvaluationNormalize(string(out), root) + "\n")
}

func secureClientEvaluationFreePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func secureClientEvaluationWaitForAPI(t *testing.T, sc *Sidecar, port int) *APIServer {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		sc.apiMu.Lock()
		api := sc.apiServer
		sc.apiMu.Unlock()
		if api != nil {
			if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond); err == nil {
				_ = c.Close()
				return api
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the API server did not start")
	return nil
}

var secureClientEvaluationVolatile = []struct {
	re   *regexp.Regexp
	with string
}{
	{regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`), "<UUID>"},
	{regexp.MustCompile(`\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?`), "<TS>"},
	{regexp.MustCompile(`\b\d+(\.\d+)?(ns|µs|us|ms|s)\b`), "<DUR>"},
	{regexp.MustCompile(`("[A-Za-z0-9_.]*(?:_ms|_ns|elapsed|latency|duration)"\s*:\s*)[0-9.eE+-]+`), `$1"<N>"`},
	// Redaction and fingerprints are keyed by the per-install secret.
	{regexp.MustCompile(`\b(key|hmac)=[0-9a-f]{6,}`), `$1=<K>`},
	{regexp.MustCompile(`("[A-Za-z0-9_.]*fingerprint"\s*:\s*)"[0-9a-f]+"`), `$1"<K>"`},
}

// secureClientEvaluationCardInUUID finds a random id whose run of 13 or more
// digits the audit redaction took for a payment card number (GAP-0255, on
// origin/main too), which made the goldens fail now and then. The token keeps
// the redacted length, so a match that spans exactly a UUID is an id.
var secureClientEvaluationCardInUUID = regexp.MustCompile(`([0-9a-fA-F-]*)\\+u003credacted type=pii\.payment_card v=\d+ key=\S*? len=(\d+) hmac=\S*?\\+u003e([0-9a-fA-F-]*)`)

// secureClientEvaluationNormalize removes what changes from run to run: the
// temp root, ids, timestamps and durations.
func secureClientEvaluationNormalize(text, root string) string {
	for _, r := range []string{strings.ReplaceAll(root, `\`, `\\\\`), strings.ReplaceAll(root, `\`, `\\`), filepath.ToSlash(root), root} {
		text = strings.ReplaceAll(text, "/private"+r, "<ROOT>")
		text = strings.ReplaceAll(text, r, "<ROOT>")
	}
	// The audit redaction hashes a Windows temp folder name of 20 or more
	// characters (testenv.PrivateTempDir's), in a JSON-escaped record.
	if parent := filepath.Dir(root); strings.Contains(parent, `\`) {
		escaped := regexp.QuoteMeta(strings.ReplaceAll(parent, `\`, `\\`))
		text = regexp.MustCompile(escaped+`\\\\\\u003credacted [^\\]*\\u003e`).ReplaceAllString(text, "<ROOT>")
	}
	text = secureClientEvaluationCardInUUID.ReplaceAllStringFunc(text, func(match string) string {
		parts := secureClientEvaluationCardInUUID.FindStringSubmatch(match)
		if n, err := strconv.Atoi(parts[2]); err != nil || len(parts[1])+n+len(parts[3]) != 36 {
			return match
		}
		return "<UUID>"
	})
	for _, v := range secureClientEvaluationVolatile {
		text = v.re.ReplaceAllString(text, v.with)
	}
	return text
}

// secureClientEvaluationDiff lists the golden lines that changed.
func secureClientEvaluationDiff(want, got []byte) string {
	w, g := strings.Split(string(want), "\n"), strings.Split(string(got), "\n")
	var b strings.Builder
	for i := 0; i < len(w) || i < len(g); i++ {
		var wl, gl string
		if i < len(w) {
			wl = w[i]
		}
		if i < len(g) {
			gl = g[i]
		}
		if wl != gl {
			fmt.Fprintf(&b, "line %d\n  main: %s\n  now:  %s\n", i+1, wl, gl)
			if b.Len() > 8000 {
				b.WriteString("...\n")
				break
			}
		}
	}
	return b.String()
}
