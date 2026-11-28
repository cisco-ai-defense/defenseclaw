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

package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/workspace"
	osw "github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

// B1 S9a: a gateway that predates upload_scan, or an admin's hold_back,
// keeps holding files back; replace picks the placeholder form.
func TestB1UploadScanSettingsMapToCopy(t *testing.T) {
	if rw, _, _ := substrateUploadScan(nil); rw != "" {
		t.Fatalf("old gateway: rewrite %q, want hold back", rw)
	}
	if rw, _, _ := substrateUploadScan(&api.LauncherUploadScan{SecretAction: "hold_back"}); rw != "" {
		t.Fatalf("hold_back: rewrite %q", rw)
	}
	rw, max, budget := substrateUploadScan(&api.LauncherUploadScan{SecretAction: "replace", PlaceholderForm: "env", MaxFileBytes: 1 << 20, TimeBudget: "30s"})
	if rw != osw.PlaceholderEnv || max != 1<<20 || budget != 30*time.Second {
		t.Fatalf("replace: %q %d %s", rw, max, budget)
	}
}

func TestB1RunReportNamesReplacedSecrets(t *testing.T) {
	res := &workspace.StartResult{CopyRecord: &osw.CopyRecord{SecretLines: []osw.SecretLine{
		{Rel: "config.py", Placeholder: "DC_SECRET_1"}, {Rel: "config.py", Placeholder: "DC_SECRET_2"},
		{Rel: "deploy/aws.ini", Placeholder: "DC_SECRET_3", Signing: true},
	}}}
	got := strings.Join(res.ReplacedLines(), "\n")
	for _, want := range []string{"2 secrets replaced in config.py", "1 secret replaced in deploy/aws.ini", "deploy/aws.ini held a signing key"} {
		if !strings.Contains(got, want) {
			t.Fatalf("report %q lacks %q", got, want)
		}
	}
	t.Logf("sample run output:\n%s", got)
}
