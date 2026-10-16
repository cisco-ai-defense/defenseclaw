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

package manager

import (
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// #1246/GAP-0129: a host the repository policy blocks reached the agent as
// "on the sandbox's block list", so the agent sent the user to a list they
// never set (the feed and the destinations already named the repository
// policy, GAP-0125). The agent's note names the repository policy and how
// the block is lifted, at once, from the proxy's refusal of the CONNECT.
func TestEgressRefusalNamesTheRepositoryPolicy(t *testing.T) {
	e := newEnv(t, nil)
	writeFile(t, filepath.Join(e.project, packs.RepoPolicyPath), "version: 1\negress: {block: [dynamodb.us-east-1.amazonaws.com]}\n")
	ex, err := e.m.Explain(t.Context(), sandboxapi.ExplainRequest{Harness: "claudecode", Project: e.project})
	must(t, err)
	e.live(sandboxapi.CreateRequest{Name: "repoblock", RepoPolicyDigest: ex.RepoPolicy.Digest})
	b := e.binding("repoblock")
	e.m.EgressSink().EgressEvent(egress.Event{Kind: egress.EventBlocked, Method: http.MethodConnect, BindingID: b.ID, SandboxName: "repoblock",
		Host: "dynamodb.us-east-1.amazonaws.com", Port: 443, Category: egress.CategoryOperatorBlock, Rule: "dynamodb.us-east-1.amazonaws.com",
		Time: time.Now()})
	got := e.m.EgressRefusals(b.ID, b.SandboxName)
	if len(got) != 1 || got[0].Category != string(egress.CategoryOperatorBlock) ||
		got[0].What != "on the repository policy's block list, "+packs.RepoPolicyPath ||
		got[0].Remedy != "only removing it from the repository policy ("+packs.RepoPolicyPath+") allows it" {
		t.Fatalf("refusals = %+v", got)
	}
	// The user's own list keeps its words.
	if w, r := blockOriginRefusal(packs.BlockFromConfig); w != "" || r != "" {
		t.Fatalf("own list = %q %q", w, r)
	}
}
