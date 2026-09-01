// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"github.com/defenseclaw/defenseclaw/internal/scanoutput"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

func TestMarshalScanResultV7Shape(t *testing.T) {
	t.Parallel()
	version.ResetForTesting()
	version.SetBinaryVersion("0.0.0-test")
	version.SetContentHash([]byte("hello"))

	r := &scanner.ScanResult{
		Scanner:   "codeguard",
		Target:    "/tmp/x.go",
		Timestamp: time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC),
		Duration:  50 * time.Millisecond,
		Findings: []scanner.Finding{
			{
				ID:          "R1",
				Severity:    scanner.SeverityHigh,
				Title:       "t",
				Description: "d",
				Location:    "x.go:42",
				Remediation: "fix",
				Scanner:     "codeguard",
				Tags:        []string{"a"},
				Confidence:  0.87,
			},
		},
	}
	b, err := marshalScanResultV7(r, "0.0.0-test")
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"scanner", "target", "timestamp", "findings", "schema_version", "scan_id"} {
		if _, ok := top[k]; !ok {
			t.Fatalf("missing key %q", k)
		}
	}
	var output scanResultV7
	if err := json.Unmarshal(b, &output); err != nil {
		t.Fatal(err)
	}
	if len(output.Findings) != 1 || output.Findings[0].Confidence == nil ||
		*output.Findings[0].Confidence != 0.87 {
		t.Fatalf("finding confidence was not preserved: %+v", output.Findings)
	}
}

func TestScanResultSchemaEmbedded(t *testing.T) {
	t.Parallel()
	if len(scanResultSchemaJSON) < 100 {
		t.Fatal("embedded scan-result schema missing or too small")
	}
}

func TestScanFixtureFileJSONSchemaPython(t *testing.T) {
	// Integration-style check: when pytest+jsonschema runs in CI, this is redundant.
	tmp := t.TempDir()
	p := filepath.Join(tmp, "sample.go")
	if err := os.WriteFile(p, []byte(`password = "0123456789abcdef0123456789abcdef"`), 0o600); err != nil {
		t.Fatal(err)
	}
	cg := scanner.NewCodeGuardScanner("")
	res, err := cg.Scan(t.Context(), p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := marshalScanResultV7(res, "test")
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
}

// TestScanResultV7RedactsSecretsFromFindingText is the #797 regression:
// detector-recognized substrings must disappear without replacing the whole
// description/remediation/location fields that machine consumers need.
func TestScanResultV7RedactsSecretsFromFindingText(t *testing.T) {
	t.Parallel()
	version.ResetForTesting()
	version.SetBinaryVersion("0.0.0-test")

	const secret = "sk-test1234567890abcdef1234567890abcdef1234567890ab"
	r := &scanner.ScanResult{
		Scanner:   "codeguard",
		Target:    "/tmp/leak.go",
		Timestamp: time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC),
		Duration:  10 * time.Millisecond,
		Findings: []scanner.Finding{
			{
				ID:          "RX",
				Severity:    scanner.SeverityHigh,
				Title:       "Hardcoded API key detected", // rule-name only
				Description: "matched line: api_key = \"" + secret + "\"",
				Location:    "/tmp/leak.go:42",
				Remediation: "rotate " + secret + " immediately",
				Scanner:     "codeguard",
			},
		},
	}
	b, err := marshalScanResultV7(r, "0.0.0-test")
	if err != nil {
		t.Fatal(err)
	}
	if string(b) == "" {
		t.Fatal("marshalScanResultV7 returned empty body")
	}
	if strings.Contains(string(b), secret) {
		t.Fatalf("scan v7 JSON contains raw secret %q (must be redacted before persistence/output):\n%s", secret, string(b))
	}
	var top struct {
		Target   string `json:"target"`
		Findings []struct {
			Severity    string `json:"severity"`
			Scanner     string `json:"scanner"`
			RuleID      string `json:"rule_id"`
			Description string `json:"description"`
			Location    string `json:"location"`
			Remediation string `json:"remediation"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(b, &top); err != nil {
		t.Fatalf("v7 JSON not parseable: %v", err)
	}
	if len(top.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(top.Findings))
	}
	if got := top.Findings[0].Severity; got == "" {
		t.Fatal("severity round-trip lost: got empty")
	} else if !strings.EqualFold(got, "high") {
		t.Fatalf("severity round-trip wrong: got %q, want HIGH-equivalent", got)
	}
	if got := top.Findings[0].Scanner; got != "codeguard" {
		t.Fatalf("scanner round-trip lost: got %q", got)
	}
	if got := top.Findings[0].RuleID; got == "" {
		t.Fatal("rule_id should be populated by EnsureRuleID")
	}
	if top.Target != "/tmp/leak.go" || top.Findings[0].Location != "/tmp/leak.go:42" {
		t.Fatalf("safe path context was lost: target=%q location=%q", top.Target, top.Findings[0].Location)
	}
	if strings.Contains(string(b), `"file"`) {
		t.Fatalf("v7 output added an undeclared field and broke strict consumers: %s", b)
	}
	if !strings.Contains(top.Findings[0].Description, "matched line: api_key = \"") ||
		!strings.Contains(top.Findings[0].Description, "<redacted type=credentials.api_token") ||
		!strings.HasSuffix(top.Findings[0].Description, "\"") {
		t.Fatalf("description did not retain safe context around token: %q", top.Findings[0].Description)
	}
	if !strings.HasPrefix(top.Findings[0].Remediation, "rotate ") ||
		!strings.HasSuffix(top.Findings[0].Remediation, " immediately") {
		t.Fatalf("remediation did not retain safe context: %q", top.Findings[0].Remediation)
	}
}

func TestScanResultV7SafeFieldsAndExplicitLineRemainExact(t *testing.T) {
	line := 9
	r := &scanner.ScanResult{
		Scanner: "codeguard", Target: `C:\work\repo\main.go`, Timestamp: time.Now(),
		Findings: []scanner.Finding{{
			ID: "CG-SAFE", Severity: scanner.SeverityMedium, Title: "Unsafe command",
			Description: "Command substitution is present", Location: `C:\work\repo\main.go:9`,
			Remediation: "Use an argument vector", Scanner: "codeguard", LineNumber: &line,
		}},
	}
	redactor, err := scanoutput.LoadRedactor(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b, err := marshalScanResultV7WithOptions(r, "test", scanResultV7Options{Redactor: redactor})
	if err != nil {
		t.Fatal(err)
	}
	var got scanResultV7
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	finding := got.Findings[0]
	if got.Target != r.Target || finding.Title != r.Findings[0].Title ||
		finding.Description == nil || *finding.Description != r.Findings[0].Description ||
		finding.Location == nil || *finding.Location != r.Findings[0].Location ||
		finding.Remediation == nil || *finding.Remediation != r.Findings[0].Remediation ||
		finding.LineNumber == nil || *finding.LineNumber != line {
		t.Fatalf("safe v7 projection changed values: %+v", got)
	}
}

func TestScanResultV7DefaultIgnoresLegacyRevealEnvironment(t *testing.T) {
	t.Setenv("DEFENSECLAW_REVEAL_PII", "1")
	const secret = "sk-test1234567890abcdef1234567890abcdef1234567890ab"
	r := &scanner.ScanResult{Scanner: "codeguard", Findings: []scanner.Finding{{
		ID: "CG-SECRET", Severity: scanner.SeverityHigh, Scanner: "codeguard",
		Description: "api_key=\"" + secret + "\"",
	}}}
	b, err := marshalScanResultV7(r, "test")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), secret) || !strings.Contains(string(b), "redacted type=") {
		t.Fatalf("legacy reveal environment bypassed scan projection: %s", b)
	}
}

func TestScanResultV7ExplicitRawOptionIsLocalProjectionOnly(t *testing.T) {
	const secret = "sk-test1234567890abcdef1234567890abcdef1234567890ab"
	r := &scanner.ScanResult{Scanner: "codeguard", Target: "/tmp/raw.go", Findings: []scanner.Finding{{
		ID: "CG-SECRET", Severity: scanner.SeverityHigh, Scanner: "codeguard",
		Description: "value=" + secret, Location: "/tmp/raw.go:7",
	}}}
	b, err := marshalScanResultV7WithOptions(r, "test", scanResultV7Options{Raw: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), secret) || !strings.Contains(string(b), `"location": "/tmp/raw.go:7"`) ||
		strings.Contains(string(b), `"file"`) {
		t.Fatalf("explicit raw projection did not retain local values: %s", b)
	}
}

func TestScanResultV7SynthesizesRuleIDBeforeRedaction(t *testing.T) {
	const title = "Prompt injection: role override attempt"
	r := &scanner.ScanResult{
		Scanner: "clawshield-injection",
		Findings: []scanner.Finding{{
			ID:       "CS-INJ-role-override",
			Severity: scanner.SeverityHigh,
			Title:    title,
			Scanner:  "clawshield-injection",
		}},
	}
	want := scanner.SynthesizeRuleID("clawshield-injection", "", title, r.Findings[0].ID)

	ruleID := func(t *testing.T, options scanResultV7Options) string {
		t.Helper()
		body, err := marshalScanResultV7WithOptions(r, "test", options)
		if err != nil {
			t.Fatal(err)
		}
		var output scanResultV7
		if err := json.Unmarshal(body, &output); err != nil {
			t.Fatal(err)
		}
		if len(output.Findings) != 1 || output.Findings[0].RuleID == nil {
			t.Fatalf("missing rule identity in output: %s", body)
		}
		return *output.Findings[0].RuleID
	}

	redactorA, err := scanoutput.LoadRedactor(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	redactorB, err := scanoutput.LoadRedactor(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string]string{
		"raw":        ruleID(t, scanResultV7Options{Raw: true}),
		"redacted-a": ruleID(t, scanResultV7Options{Redactor: redactorA}),
		"redacted-b": ruleID(t, scanResultV7Options{Redactor: redactorB}),
	} {
		if got != want {
			t.Errorf("%s rule_id = %q, want canonical synthesis %q", name, got, want)
		}
		if strings.Contains(got, "redacted") || strings.Contains(got, "hmac=") || strings.Contains(got, "key=") {
			t.Errorf("%s rule_id contains projection material: %q", name, got)
		}
	}
	if r.Findings[0].RuleID != "" {
		t.Fatalf("rendering mutated input rule_id: %q", r.Findings[0].RuleID)
	}
}

func TestScanNoRedactRequiresJSON(t *testing.T) {
	oldJSON, oldRaw := scanOutputJSON, scanNoRedact
	t.Cleanup(func() { scanOutputJSON, scanNoRedact = oldJSON, oldRaw })
	scanOutputJSON, scanNoRedact = false, true
	if err := runScanCode(nil, []string{"unused"}); err == nil || err.Error() != "--no-redact requires --json" {
		t.Fatalf("validation error = %v", err)
	}
}

func TestScanRedactorRequirementMatchesOutputBoundary(t *testing.T) {
	oldJSON, oldRaw := scanOutputJSON, scanNoRedact
	t.Cleanup(func() { scanOutputJSON, scanNoRedact = oldJSON, oldRaw })

	for _, test := range []struct {
		name     string
		json     bool
		raw      bool
		persist  bool
		required bool
	}{
		{name: "human output", required: false},
		{name: "raw local JSON", json: true, raw: true, required: false},
		{name: "protected JSON", json: true, required: true},
		{name: "protected persistence", raw: true, persist: true, required: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			scanOutputJSON, scanNoRedact = test.json, test.raw
			if got := scanNeedsRedactor(test.persist); got != test.required {
				t.Fatalf("scanNeedsRedactor(%v) = %v, want %v", test.persist, got, test.required)
			}
		})
	}
}

func TestScanResultV7PreservesFindingScanner(t *testing.T) {
	version.ResetForTesting()
	version.SetBinaryVersion("0.0.0-test")

	r := &scanner.ScanResult{
		Scanner:   "codeguard",
		Target:    "/tmp/payload.sh",
		Timestamp: time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC),
		Duration:  10 * time.Millisecond,
		Findings: []scanner.Finding{
			{
				ID:       "CS-MAL-RS-DEVTCP",
				Severity: scanner.SeverityCritical,
				Title:    "Malicious signature",
				Scanner:  "clawshield-malware",
				Category: "reverse_shell",
			},
		},
	}
	b, err := marshalScanResultV7(r, "0.0.0-test")
	if err != nil {
		t.Fatal(err)
	}
	var top struct {
		Scanner  string `json:"scanner"`
		Findings []struct {
			Scanner string `json:"scanner"`
			RuleID  string `json:"rule_id"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(b, &top); err != nil {
		t.Fatal(err)
	}
	if top.Scanner != "codeguard" {
		t.Fatalf("top-level scanner = %q, want codeguard", top.Scanner)
	}
	if len(top.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(top.Findings))
	}
	if top.Findings[0].Scanner != "clawshield-malware" {
		t.Fatalf("finding scanner = %q, want clawshield-malware", top.Findings[0].Scanner)
	}
	if !strings.HasPrefix(top.Findings[0].RuleID, "clawshield-malware.") {
		t.Fatalf("rule_id = %q, want clawshield-malware prefix", top.Findings[0].RuleID)
	}
}

func TestRunScanCodePersistsStandaloneFindingLifecycle(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "exec.py")
	if err := os.WriteFile(target, []byte("os.system(cmd)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := audit.NewStore(filepath.Join(dataDir, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	previousConfig, previousStore, previousLog := cfg, auditStore, auditLog
	previousJSON, previousRaw, previousSchema := scanOutputJSON, scanNoRedact, scanPrintSchema
	previousFindingScanner, previousFindingTarget := auditFindingsScanner, auditFindingsTarget
	previousFindingSince, previousFindingNewOnly := auditFindingsSince, auditFindingsNewOnly
	previousFindingResolved, previousFindingLimit := auditFindingsIncludeResolved, auditFindingsLimit
	t.Cleanup(func() {
		cfg, auditStore, auditLog = previousConfig, previousStore, previousLog
		scanOutputJSON, scanNoRedact, scanPrintSchema = previousJSON, previousRaw, previousSchema
		auditFindingsScanner, auditFindingsTarget = previousFindingScanner, previousFindingTarget
		auditFindingsSince, auditFindingsNewOnly = previousFindingSince, previousFindingNewOnly
		auditFindingsIncludeResolved, auditFindingsLimit = previousFindingResolved, previousFindingLimit
		_ = store.Close()
	})

	localConfig := config.DefaultConfig()
	localConfig.DataDir = dataDir
	localConfig.AuditDB = filepath.Join(dataDir, "audit.db")
	localConfig.Scanners.CodeGuard = ""
	cfg, auditStore, auditLog = localConfig, store, audit.NewLogger(store)
	scanOutputJSON, scanNoRedact, scanPrintSchema = false, false, false
	workingDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	scanArgument := target
	if relativeTarget, relativeErr := filepath.Rel(workingDir, target); relativeErr == nil &&
		!filepath.IsAbs(relativeTarget) {
		scanArgument = relativeTarget
	}

	for run := 1; run <= 2; run++ {
		if err := runScanCode(nil, []string{scanArgument}); err != nil {
			t.Fatalf("standalone scan %d: %v", run, err)
		}
	}
	counts, err := store.GetCounts()
	if err != nil {
		t.Fatal(err)
	}
	if counts.TotalScans != 2 {
		t.Fatalf("scan_results count = %d, want 2", counts.TotalScans)
	}
	states, err := store.ListFindingStates("codeguard", target, false, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) == 0 {
		t.Fatal("standalone scan left finding_states empty")
	}
	for _, state := range states {
		if state.OccurrenceCount != 2 || state.State != "active" || state.Target != target ||
			!filepath.IsAbs(state.FilePath) {
			t.Fatalf("finding state was not deduplicated across scans: %+v", state)
		}
	}

	auditFindingsScanner = "codeguard"
	auditFindingsTarget = target
	auditFindingsSince = ""
	auditFindingsNewOnly = false
	auditFindingsIncludeResolved = false
	auditFindingsLimit = 100
	var output bytes.Buffer
	command := &cobra.Command{}
	command.SetOut(&output)
	if err := runAuditFindings(command, nil); err != nil {
		t.Fatalf("audit findings after standalone scan: %v", err)
	}
	var report auditFindingsReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatalf("decode audit findings report: %v\n%s", err, output.String())
	}
	if report.Count != int64(len(states)) || report.Returned != len(states) {
		t.Fatalf("audit findings report count/returned = %d/%d, want %d: %s",
			report.Count, report.Returned, len(states), output.String())
	}
}

func TestMarshalScanResultV7PreservesPersistedScanID(t *testing.T) {
	const scanID = "f24a58bd-e929-4cc8-a5c8-9c0399340f5a"
	result := &scanner.ScanResult{
		ScanID: scanID, Scanner: "codeguard", Target: "/repo/main.py",
		Timestamp: time.Now().UTC(),
	}
	body, err := marshalScanResultV7WithOptions(result, "test", scanResultV7Options{Raw: true})
	if err != nil {
		t.Fatal(err)
	}
	var output scanResultV7
	if err := json.Unmarshal(body, &output); err != nil {
		t.Fatal(err)
	}
	if output.ScanID == nil || *output.ScanID != scanID {
		t.Fatalf("machine output scan_id = %v, want persisted %q", output.ScanID, scanID)
	}
}
