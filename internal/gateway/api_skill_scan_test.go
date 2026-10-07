// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestHandleSkillScanRejectsBundledSystemSkillBeforeScanner(t *testing.T) {
	codexHome := filepath.Join(t.TempDir(), "codex-home")
	t.Setenv("CODEX_HOME", codexHome)
	target := filepath.Join(codexHome, "skills", ".system", "imagegen")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(skillScanRequest{Target: target, Name: "imagegen"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/skill/scan", bytes.NewReader(body))
	w := httptest.NewRecorder()

	(&APIServer{}).handleSkillScan(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusConflict, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "discovery-only") {
		t.Fatalf("response = %q, want bundled discovery-only refusal", w.Body.String())
	}
}

func TestBundledSkillScanPathDoesNotTrustArbitrarySystemDirectory(t *testing.T) {
	t.Setenv("CODEX_HOME", filepath.Join(t.TempDir(), "codex-home"))
	target := filepath.Join(t.TempDir(), "skills", ".system", "operator-skill")
	if isBundledSkillScanPath(target) {
		t.Fatalf("arbitrary .system path was incorrectly exempted: %s", target)
	}
}

func TestHandleSkillScanRejectsOnlySourceBoundHermesBundle(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HERMES_HOME", home)
	root := filepath.Join(home, "skills")
	target := filepath.Join(root, "productivity", "vendor-docs")
	source := filepath.Join(home, "hermes-agent", "skills", "productivity", "vendor-docs")
	marker := []byte("---\nname: vendor-docs\n---\n")
	for _, path := range []string{target, source} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "SKILL.md"), marker, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	origin := md5.Sum(append([]byte("SKILL.md"), marker...)) // #nosec G401 -- Hermes fixture.
	if err := os.WriteFile(
		filepath.Join(root, ".bundled_manifest"),
		[]byte(fmt.Sprintf("vendor-docs:%x\n", origin)),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(skillScanRequest{Target: target, Name: "vendor-docs"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/skill/scan", bytes.NewReader(body))
	w := httptest.NewRecorder()

	(&APIServer{}).handleSkillScan(w, req)

	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "discovery-only") {
		t.Fatalf("Hermes bundle response = %d %q", w.Code, w.Body.String())
	}
}

func TestBundledSkillScanPathDoesNotTrustHermesManifestWithoutInstalledSource(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HERMES_HOME", home)
	root := filepath.Join(home, "skills")
	target := filepath.Join(root, "productivity", "manifest-only")
	marker := []byte("---\nname: manifest-only\n---\n")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "SKILL.md"), marker, 0o600); err != nil {
		t.Fatal(err)
	}
	origin := md5.Sum(append([]byte("SKILL.md"), marker...)) // #nosec G401 -- Hermes fixture.
	if err := os.WriteFile(
		filepath.Join(root, ".bundled_manifest"),
		[]byte(fmt.Sprintf("manifest-only:%x\n", origin)),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	if isBundledSkillScanPath(target) {
		t.Fatal("user-writable Hermes manifest alone created a scanner bypass")
	}
}

// A folder the gateway's own account cannot read gets one actionable line, not
// the scanner's Python traceback (GAP-0229).
func TestHandleSkillScanNamesAFolderTheGatewayCannotRead(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a POSIX permission denial for a non-root user")
	}
	locked := filepath.Join(t.TempDir(), "locked")
	target := filepath.Join(locked, "skill")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	body, err := json.Marshal(skillScanRequest{Target: target})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()

	(&APIServer{}).handleSkillScan(w, httptest.NewRequest(http.MethodPost, "/v1/skill/scan", bytes.NewReader(body)))

	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "service account cannot read") {
		t.Fatalf("response = %d %q, want 403 naming the unreadable folder", w.Code, w.Body.String())
	}
	// Secure Client runs the scanner as main did, and reports its failure
	// (GAP-0280).
	t.Setenv("PATH", "")
	w = httptest.NewRecorder()
	secureClient := &APIServer{scannerCfg: &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}}
	secureClient.handleSkillScan(w, httptest.NewRequest(http.MethodPost, "/v1/skill/scan", bytes.NewReader(body)))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("Secure Client response = %d %q, want the scanner failure", w.Code, w.Body.String())
	}
}

// A missing folder, or a skill whose SKILL.md the gateway cannot read, is named in
// one sentence without the scanner's process name or exit code (GAP-0256).
func TestHandleSkillScanSaysAMissingFolderAndAnUnreadableSkillFile(t *testing.T) {
	scan := func(target string) *httptest.ResponseRecorder {
		body, err := json.Marshal(skillScanRequest{Target: target})
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		(&APIServer{}).handleSkillScan(w, httptest.NewRequest(http.MethodPost, "/v1/skill/scan", bytes.NewReader(body)))
		return w
	}

	missing := filepath.Join(t.TempDir(), "does-not-exist")
	w := scan(missing)
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "the folder does not exist: ") ||
		strings.Contains(w.Body.String(), "exited") {
		t.Fatalf("missing folder response = %d %q, want 404 with a plain sentence", w.Code, w.Body.String())
	}
	// Secure Client keeps the scan answers of main: the scanner runs and fails (issue #1092).
	t.Setenv("PATH", "")
	body, err := json.Marshal(skillScanRequest{Target: missing})
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	secureClient := &APIServer{scannerCfg: &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}}
	secureClient.handleSkillScan(w, httptest.NewRequest(http.MethodPost, "/v1/skill/scan", bytes.NewReader(body)))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("Secure Client missing folder = %d %q, want the scanner failure", w.Code, w.Body.String())
	}

	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		return // a deny-read file needs a POSIX permission denial for a non-root user
	}
	skill := t.TempDir()
	file := filepath.Join(skill, "SKILL.md")
	if err := os.WriteFile(file, []byte("---\nname: x\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(file, 0o600) })
	w = scan(skill)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "cannot read "+file) {
		t.Fatalf("unreadable SKILL.md response = %d %q, want 403 naming the file", w.Code, w.Body.String())
	}
}
