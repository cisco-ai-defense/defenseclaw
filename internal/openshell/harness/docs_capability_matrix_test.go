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

package harness

import (
	"encoding/json"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// TestDocsCapabilityMatrixSandboxColumn keeps the docs capability matrix's
// OpenShell sandbox column a checked projection of the harness registry: a
// harness row shows its artifacts' tamper tier, the hook config file the
// harness reads (root-owned for the managed tier; for the user tier the
// workload's copy, or a root-owned file the launcher forces, as for Kiro's
// agent), the default image pin, the verification status with the reason
// an unverified harness is unverified (the lead clause of its
// Verification.Note), and the sign-in paths not tested live (credential
// profiles with an Unverified reason, then "login" for an unverified
// in-sandbox login); every other row is pending. internal/gateway/connector
// checks the status against SandboxArtifactsSupported.
func TestDocsCapabilityMatrixSandboxColumn(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("OpenShell sandbox artifacts are not rendered on Windows hosts")
	}
	var documented struct {
		Connectors []struct {
			ID      string `json:"id"`
			Sandbox struct {
				Status     string `json:"status"`
				TamperTier string `json:"tamperTier"`
				HookConfig string `json:"hookConfig"`
				HarnessPin string `json:"harnessPin"`
				Verified   string `json:"verified"`
				// UnverifiedReason and UntestedAuth are rendered on the
				// capability matrix page's sandbox harness table.
				UnverifiedReason string   `json:"unverifiedReason"`
				UntestedAuth     []string `json:"untestedAuth"`
			} `json:"sandbox"`
		} `json:"connectors"`
	}
	if err := json.Unmarshal([]byte(docsFile(t, "docs-site", "data", "capability-matrix.json")), &documented); err != nil {
		t.Fatalf("decode the capability matrix: %v", err)
	}

	seen := map[string]bool{}
	for _, row := range documented.Connectors {
		sb := row.Sandbox
		spec, ok := Get(row.ID)
		if !ok {
			if sb.Status != "pending" || sb.TamperTier != "" || sb.HookConfig != "" || sb.HarnessPin != "" || sb.Verified != "" ||
				sb.UnverifiedReason != "" || len(sb.UntestedAuth) != 0 {
				t.Errorf("%s has no sandbox harness but documents sandbox %+v; want only status pending", row.ID, sb)
			}
			continue
		}
		seen[row.ID] = true
		artifacts := artifactsFor(t, spec)
		if sb.Status != "artifacts" {
			t.Errorf("%s sandbox.status=%q want artifacts", row.ID, sb.Status)
		}
		if sb.TamperTier != artifacts.TamperTier {
			t.Errorf("%s sandbox.tamperTier=%q want %q", row.ID, sb.TamperTier, artifacts.TamperTier)
		}
		if sb.HarnessPin != spec.DefaultVersion {
			t.Errorf("%s sandbox.harnessPin=%q want %q", row.ID, sb.HarnessPin, spec.DefaultVersion)
		}
		verification := spec.Verification()
		if sb.Verified != verification.Status {
			t.Errorf("%s sandbox.verified=%q want %q", row.ID, sb.Verified, verification.Status)
		}
		wantReason := ""
		if verification.Status == Unverified {
			wantReason = docsVerificationReason(verification.Note)
		}
		if sb.UnverifiedReason != wantReason {
			t.Errorf("%s sandbox.unverifiedReason=%q want %q (the lead clause of its Verification.Note)", row.ID, sb.UnverifiedReason, wantReason)
		}
		if want := docsUntestedAuth(spec); !slices.Equal(sb.UntestedAuth, want) {
			t.Errorf("%s sandbox.untestedAuth=%q want %q", row.ID, sb.UntestedAuth, want)
		}
		// A managed registration is a root-owned file; a user-tier one is
		// the file in the image HOME the harness reads, or a root-owned file
		// the launcher points the harness at (Kiro's agent directory).
		found := false
		for _, file := range artifacts.Files {
			if file.Path == sb.HookConfig && (file.Owner == connector.SandboxOwnerRoot || artifacts.TamperTier == connector.SandboxTamperTierUser) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s sandbox.hookConfig=%q is not a hook config file of its %s-tier sandbox artifacts", row.ID, sb.HookConfig, artifacts.TamperTier)
		}
	}
	for _, name := range Names() {
		if !seen[name] {
			t.Errorf("harness %s is missing from the docs capability matrix", name)
		}
	}
}

// docsVerificationReason is how the docs state why a harness is unverified:
// the lead clause of its Verification.Note (up to the first ": "), without
// code backticks and starting with a capital letter.
func docsVerificationReason(note string) string {
	lead, _, _ := strings.Cut(note, ": ")
	lead = strings.TrimSpace(strings.ReplaceAll(lead, "`", ""))
	if lead == "" {
		return ""
	}
	return strings.ToUpper(lead[:1]) + lead[1:]
}

// docsUntestedAuth lists the harness's sign-in paths no live run exercised:
// the credential profiles with an Unverified reason, in registry order, then
// "login" when its in-sandbox login is unverified.
func docsUntestedAuth(spec *Spec) []string {
	var out []string
	for _, cp := range spec.CredentialProfiles("") {
		if cp.Unverified != "" {
			out = append(out, cp.ProfileID)
		}
	}
	if login, ok := spec.Login(); ok && login.Unverified != "" {
		out = append(out, "login")
	}
	return out
}
