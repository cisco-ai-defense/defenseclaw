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
	"slices"
	"testing"

	osw "github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

// RV1 P1-1: a run that shared the root .env with --unmask must not share a
// deploy/prod/.env added later. The run's shared files carry over to push
// as exact paths, never as a base-name pattern.
func TestPushRunUnmaskIsExactPath(t *testing.T) {
	if runtimeUnsupported() {
		t.Skip("copy mode is Linux and macOS only")
	}
	o := newOperator(t)
	o.initRepo()
	write(t, o.project, ".env", "API_KEY=shared-on-purpose-value\n", 0o600)
	a := newActor(t)
	sb := sandboxFS{Client: a.client(), dir: t.TempDir()}
	if _, err := Start(context.Background(), StartOptions{Transport: sb, Project: o.project, Name: "c1", DataDir: o.data, Home: o.home,
		Unmask: []string{".env"}, UnmaskAsked: []string{".env"}}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if rec, err := osw.LoadCopy(o.data, "c1"); err != nil || !slices.Equal(rec.Unmasked, []string{".env"}) {
		t.Fatalf("record unmasked = %v, %v; want [.env]", rec.Unmasked, err)
	}
	write(t, o.project, "deploy/prod/.env", "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n", 0o600)
	write(t, o.project, "notes.md", "n\n", 0o644)
	out, err := Push(context.Background(), pushOpts(o, sb))
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if !slices.Contains(out.Plan.HeldBack, "deploy/prod/.env") {
		t.Fatalf("held back = %v; deploy/prod/.env was not held back", out.Plan.HeldBack)
	}
	if _, err := os.Stat(filepath.Join(sb.local(remoteProject), "deploy", "prod", ".env")); !os.IsNotExist(err) {
		t.Fatalf("deploy/prod/.env reached the agent (stat err %v)", err)
	}
	if got := read(t, sb.local(remoteProject), ".env"); got != "API_KEY=shared-on-purpose-value\n" {
		t.Fatalf("the shared root .env = %q", got)
	}
	if got := read(t, sb.local(remoteProject), "notes.md"); got != "n\n" {
		t.Fatalf("notes.md = %q", got)
	}
}
