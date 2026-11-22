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

//go:build unix

package workspace

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0530: a folder named .git in another case (.GIT/hooks/pre-commit)
// failed every pull with git's "invalid path", so an agent could stop the
// user bringing work back. Such folders, and git metadata in general
// (.git/config, .git/hooks, a .git folder below the top that is not a
// repository), are never carried: the pull still brings the rest back,
// the review names what was left out, and an apply with a yes writes none
// of it.
func TestGAP0530GitMetadataIsNeverCarried(t *testing.T) {
	for name, files := range map[string]map[string]string{
		".GIT/hooks/pre-commit":  {".GIT/hooks/pre-commit": "#!/bin/sh\nid\n"},
		".Git/config":            {".Git/config": "[core]\n\tfsmonitor = id\n"},
		".git/hooks/pre-commit":  {".git/hooks/pre-commit": "#!/bin/sh\nid\n"},
		".git/config fsmonitor":  {".git/config": "[core]\n\tfsmonitor = id\n"},
		"nested sub/.git/config": {"sub/.git/config": "[core]\n\tfsmonitor = id\n", "sub/.git/HEAD": "ref: refs/heads/main\n"},
	} {
		t.Run(name, func(t *testing.T) {
			o, sb, _ := copyInActor(t)
			ctx := context.Background()
			agent := sb.local(remoteProject)
			write(t, agent, "README.md", "agent version\n", 0o644)
			for p, body := range files {
				full := filepath.Join(agent, filepath.FromSlash(p))
				if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
					t.Fatal(err)
				}
				old, _ := os.ReadFile(full)
				if err := os.WriteFile(full, append(old, []byte(body)...), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			rv, err := Pull(ctx, PullOptions{Exec: sb, DataDir: o.data, Name: "c1"})
			if err != nil {
				t.Fatalf("the pull failed: %v", err)
			}
			for _, c := range rv.Changed {
				if lp := "/" + strings.ToLower(c.Path); strings.Contains(lp, "/.git/") || strings.HasSuffix(lp, "/.git") {
					t.Errorf("review lists git metadata as a change: %s", c.Path)
				}
			}
			if _, err := Apply(ctx, ApplyOptions{DataDir: o.data, Name: "c1", Mode: ModeApply, AcceptSensitive: true}); err != nil {
				t.Fatalf("apply: %v", err)
			}
			if read(t, o.project, "README.md") != "agent version\n" {
				t.Error("the rest of the work was not brought back")
			}
			for p, body := range files {
				full := filepath.Join(o.project, filepath.FromSlash(p))
				if strings.HasPrefix(p, ".git/") {
					// The project's own git folder: the agent's lines must not
					// reach it.
					b, _ := os.ReadFile(full)
					if strings.Contains(string(b), strings.TrimSpace(body)) {
						t.Errorf("%s was carried into the project's git folder", p)
					}
					continue
				}
				if _, err := os.Lstat(full); err == nil {
					t.Errorf("%s was carried into the folder", p)
				}
			}
		})
	}
}
