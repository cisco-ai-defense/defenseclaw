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

package attest

import (
	"context"
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

type b54CtxScanner struct{ calls int }

func (s *b54CtxScanner) Name() string               { return "skill-scanner" }
func (s *b54CtxScanner) Version() string            { return "test" }
func (s *b54CtxScanner) SupportedTargets() []string { return []string{"skill"} }
func (s *b54CtxScanner) Scan(ctx context.Context, _ string) (*scanner.ScanResult, error) {
	s.calls++
	<-ctx.Done()
	return nil, errors.New("killed")
}

// B5.4: a scan cut by its deadline is not a verdict and is not cached, so
// the gateway's fail mode decides and the next hook scans again.
func TestB54CutScanIsNoVerdict(t *testing.T) {
	sc := &b54CtxScanner{}
	r := &RuntimeScanner{Skill: sc}
	a := RuntimeAsset{Kind: config.AdmissionTypeSkill, Name: "x", Path: "/sandbox/.claude/skills/x",
		Files: []AttachedFile{{Role: RoleSkillFile, Path: "/sandbox/.claude/skills/x/SKILL.md", Content: []byte("---\nname: x\n---\nbody")}}}
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if d, err := r.Scan(ctx, a); !errors.Is(err, context.Canceled) {
			t.Fatalf("scan %d: %+v %v", i, d, err)
		}
	}
	if sc.calls != 2 {
		t.Fatalf("a cut scan was cached: %d calls", sc.calls)
	}
}
