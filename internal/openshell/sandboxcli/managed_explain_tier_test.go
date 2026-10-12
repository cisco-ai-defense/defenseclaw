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

//go:build !windows

package sandboxcli

import (
	"reflect"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

func managedRowText(rows []managedRow, label string) string {
	for _, r := range rows {
		if r.label == label {
			return r.text
		}
	}
	return ""
}

// GAP-0477: a stop on silent hooks binds the agents whose hooks a user can
// change; an agent with managed hooks only raises an alert, and an explain
// of one agent says that agent's answer.
func TestManagedHooksRowFollowsTheAgentsTier(t *testing.T) {
	m := &sandboxapi.ManagedExplain{Allowed: true, AllowedHarnesses: []string{"claudecode", "codex", "opencode", "hermes"},
		OnSilence: "stop", MaxSilenceAfter: "5m", PolicyDigest: "sha256:1"}
	now := time.Now()
	if got, want := managedRowText(managedExplainRowsFor(m, nil, "", now), "Hooks"),
		"opencode and hermes: a stop after 5m of agent work without hooks; claude and codex: an alert after 5m of agent work without hooks (managed hooks)"; got != want {
		t.Fatalf("all agents: %q\nwant %q", got, want)
	}
	if got, want := managedRowText(managedExplainRowsFor(m, nil, "claude", now), "Hooks"),
		"claude: an alert after 5m of agent work without hooks (managed hooks)"; got != want {
		t.Fatalf("--harness claude: %q", got)
	}
	if got := silenceTexts("alert", "", nil); !reflect.DeepEqual(got, []string{"an alert after a while of agent work without hooks"}) {
		t.Fatalf("alert: %q", got)
	}
}

// GAP-0179, GAP-0438: the Pack row says the pack the managed gateway
// resolved and what of the floor decided it.
func TestManagedPackRow(t *testing.T) {
	ex := &sandboxapi.Explain{Pack: "balanced", NetworkMode: "deny", Approvals: "manual", Settings: []sandboxapi.Setting{
		{Key: "pack", Value: "balanced", Source: "default", Origin: "default pack"},
		{Key: "profile", Value: "strict", Source: "admin", Origin: "openshell.admin.min_profile"},
	}}
	if got, want := managedPackText(ex), "balanced; network deny, approvals manual (your organization requires at least the strict network profile)"; got != want {
		t.Fatalf("min profile: %q", got)
	}
	ex = &sandboxapi.Explain{Pack: "contractors", NetworkMode: "allowlist", Approvals: "manual", Settings: []sandboxapi.Setting{
		{Key: "pack", Value: "contractors", Source: "admin", Origin: "openshell.admin.required_pack"},
	}}
	if got := managedPackText(ex); got != "contractors (required); network allowlist, approvals manual" {
		t.Fatalf("required pack: %q", got)
	}
	if managedPackText(nil) != "" {
		t.Fatal("no posture, no row")
	}
}
