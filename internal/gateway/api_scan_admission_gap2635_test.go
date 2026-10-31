// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// GAP-2635: an administrator's REST skill scan reports what install
// admission would decide, as the per-user skill scan's policy line does: a
// CRITICAL skill is rejected, an INFO-only skill is admitted, and the audit
// scan row carries that verdict instead of warn for any finding.
func TestSkillScanReportsTheAdmissionDecision(t *testing.T) {
	source := filepath.Join(t.TempDir(), "scanner.go")
	program := `package main
import (
	"fmt"
	"os"
	"strings"
)
func main() {
	severity := "INFO"
	if strings.Contains(strings.Join(os.Args, " "), "risky") {
		severity = "CRITICAL"
	}
	fmt.Printf("{\"findings\":[{\"rule_id\":\"TEST_RULE\",\"severity\":\"%s\",\"description\":\"test finding\"}]}", severity)
}
`
	if err := os.WriteFile(source, []byte(program), 0o600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "skill-scanner")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	if output, err := exec.Command("go", "build", "-o", binary, source).CombinedOutput(); err != nil {
		t.Fatalf("build scanner fixture: %v\n%s", err, output)
	}
	cfg := &config.Config{}
	cfg.Scanners.SkillScanner.Binary = binary
	api := &APIServer{scannerCfg: cfg}

	for name, want := range map[string]struct{ verdict, audit string }{
		"risky-skill": {"rejected", "block"},
		"clean-skill": {"allowed", "clean"},
	} {
		target := filepath.Join(t.TempDir(), name)
		if err := os.MkdirAll(target, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(target, "SKILL.md"), []byte("---\nname: "+name+"\n---\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(skillScanRequest{Target: target})
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		api.handleSkillScan(w, httptest.NewRequest(http.MethodPost, "/v1/skill/scan", bytes.NewReader(body)))
		if w.Code != http.StatusOK {
			t.Fatalf("%s: response %d %s", name, w.Code, w.Body.String())
		}
		var response struct {
			Admission *struct {
				Verdict       string `json:"verdict"`
				Reason        string `json:"reason"`
				InstallAction string `json:"install_action"`
			} `json:"admission"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.Admission == nil || response.Admission.Verdict != want.verdict || response.Admission.Reason == "" {
			t.Fatalf("%s: admission = %+v, want verdict %s with a reason (%s)", name, response.Admission, want.verdict, w.Body.String())
		}
		// The audit scan row keeps this verdict; its enum is what dashboards read.
		if got := scanner.NormalizeVerdictEnum(response.Admission.Verdict); got != want.audit {
			t.Fatalf("%s: audit verdict %q, want %q", name, got, want.audit)
		}
	}
	if got := scanAdmissionVerdict(nil); got != "" {
		t.Fatalf("no preview must leave the audit verdict to the findings rule, got %q", got)
	}
}
