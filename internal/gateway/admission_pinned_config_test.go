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
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/policy"
)

// GAP-0873: an admission request pinned to a generation reads that
// generation's asset_policy lists, not those of a reload that published a
// newer config while the request ran.
func TestAdmissionListsComeFromThePinnedGeneration(t *testing.T) {
	pinned := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	pinned.AssetPolicy.Skill.Denied = []config.AssetPolicyRule{{Name: "pinned-deny"}}
	reloaded := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	api := &APIServer{scannerCfg: reloaded, configSnapshot: func() *config.Config { return reloaded }}
	input := policy.AdmissionInput{TargetType: "skill", TargetName: "pinned-deny",
		ScanResult: &policy.ScanResultInput{MaxSeverity: "NONE"}}

	ctx := withPinnedGeneration(context.Background(), &Generation{Config: pinned, N: 1})
	out, err := api.evaluateAdmissionPolicy(ctx, input, "")
	if err != nil || out == nil || out.Verdict != "blocked" {
		t.Fatalf("pinned request = %+v (err %v), want the pinned generation's block", out, err)
	}
	if out, _ := api.evaluateAdmissionPolicy(context.Background(), input, ""); out == nil || out.Verdict == "blocked" {
		t.Fatalf("unpinned request = %+v, want the live config (no deny)", out)
	}
}
