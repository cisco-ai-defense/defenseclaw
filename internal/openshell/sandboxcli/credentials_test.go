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

package sandboxcli

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

func TestRunGitHubWriteBindsTheTokenToTheAPI(t *testing.T) {
	ta := newTestApp(t, "")
	ta.daemon.review = sandboxapi.ReviewResponse{Report: &workspace.ReviewReport{}}
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude", GitHubWrite: true}); err == nil || !strings.Contains(err.Error(), "GH_TOKEN") {
		t.Fatalf("--github-write without a token = %v", err)
	}
	ta.env["GITHUB_TOKEN"] = "gh-test-token"
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude", GitHubWrite: true}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	req := createRequest(t, ta.daemon)
	var names []string
	for _, c := range req.Credentials {
		if c.Host != "api.github.com" || c.Value != "gh-test-token" {
			t.Fatalf("credential = %+v", c)
		}
		names = append(names, c.Name)
	}
	if !slices.Equal(names, []string{"GH_TOKEN", "GITHUB_TOKEN"}) {
		t.Fatalf("bound names = %v", names)
	}
	if strings.Contains(ta.output(), "gh-test-token") {
		t.Fatal("the token was printed")
	}
	if !strings.Contains(ta.output(), "GH_TOKEN/GITHUB_TOKEN → api.github.com only") {
		t.Fatalf("banner:\n%s", ta.output())
	}
}

func TestRunModelNoteWhenCredentialBindsTheKey(t *testing.T) {
	ta := newTestApp(t, "")
	ta.env["ANTHROPIC_API_KEY"] = "mock"
	ta.daemon.review = sandboxapi.ReviewResponse{Report: &workspace.ReviewReport{}}
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude", LLM: LLMNone,
		Credentials: []string{"ANTHROPIC_API_KEY=host.openshell.internal:28921"}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ta.output(), "Model     ANTHROPIC_API_KEY comes from --credential") {
		t.Fatalf("banner:\n%s", ta.output())
	}
}
