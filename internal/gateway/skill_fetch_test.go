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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestF3287_SkillFetch_RejectsOutsideRoots is a regression test for
// . The /v1/skill/fetch handler must refuse any target
// directory that does not live under one of the configured skill or
// plugin roots, even if the gateway process can read the path.
func TestF3287_SkillFetch_RejectsOutsideRoots(t *testing.T) {
	skillRoot := t.TempDir()
	approvedSkill := filepath.Join(skillRoot, "approved")
	if err := os.Mkdir(approvedSkill, 0o755); err != nil {
		t.Fatalf("mkdir approved: %v", err)
	}
	if err := os.WriteFile(filepath.Join(approvedSkill, "skill.md"),
		[]byte("# allowed\n"), 0o644); err != nil {
		t.Fatalf("write skill.md: %v", err)
	}

	// A directory outside the configured skill root, populated with
	// what would be an attractive exfiltration target.
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "id_rsa"),
		[]byte("PRIVATE KEY"), 0o600); err != nil {
		t.Fatalf("write id_rsa: %v", err)
	}

	// SkillDirs() resolves to <home_dir>/skills for the OpenClaw
	// (default) connector, so we point home_dir at a parent and
	// stash the approved skill under <home_dir>/skills/<name>.
	homeDir := t.TempDir()
	skillsParent := filepath.Join(homeDir, "skills")
	if err := os.Rename(skillRoot, skillsParent); err != nil {
		t.Fatalf("rename skill root: %v", err)
	}
	approvedSkill = filepath.Join(skillsParent, "approved")
	cfg := &config.Config{}
	cfg.Claw.HomeDir = homeDir
	store, logger := testStoreAndLogger(t)
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)

	doFetch := func(target string) *httptest.ResponseRecorder {
		body := []byte(`{"target":"` + target + `"}`)
		req := httptest.NewRequest(http.MethodPost, "/v1/skill/fetch",
			bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		api.handleSkillFetch(w, req)
		return w
	}

	t.Run("approved-skill-allowed", func(t *testing.T) {
		w := doFetch(approvedSkill)
		// 200 (tarball) is the success path. We just need to confirm
		// it isn't 403.
		if w.Result().StatusCode == http.StatusForbidden {
			t.Fatalf("approved skill was rejected (status=403)")
		}
	})

	t.Run("outside-root-blocked", func(t *testing.T) {
		w := doFetch(outside)
		if w.Result().StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 for out-of-root target, got %d, body=%s",
				w.Result().StatusCode, w.Body.String())
		}
	})

	t.Run("home-ssh-blocked", func(t *testing.T) {
		// Common exfil target — must be blocked.
		w := doFetch("/etc")
		if w.Result().StatusCode != http.StatusForbidden &&
			w.Result().StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 403/400 for /etc, got %d, body=%s",
				w.Result().StatusCode, w.Body.String())
		}
	})
}

// TestF3287_SkillFetch_SymlinkEscapeBlocked verifies the handler
// rejects a target that itself is a directory but symlinked to a
// path outside the configured roots — the realpath check should
// catch it.
func TestF3287_SkillFetch_SymlinkEscapeBlocked(t *testing.T) {
	homeDir := t.TempDir()
	skillRoot := filepath.Join(homeDir, "skills")
	if err := os.MkdirAll(skillRoot, 0o755); err != nil {
		t.Fatalf("mkdir skill root: %v", err)
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"),
		[]byte("nope"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	// Plant a symlink inside the skill root that points outside.
	link := filepath.Join(skillRoot, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink not supported on this platform: %v", err)
	}

	cfg := &config.Config{}
	cfg.Claw.HomeDir = homeDir
	store, logger := testStoreAndLogger(t)
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)

	body := []byte(`{"target":"` + link + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/skill/fetch",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.handleSkillFetch(w, req)
	if w.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for symlink escape, got %d, body=%s",
			w.Result().StatusCode, w.Body.String())
	}
}
