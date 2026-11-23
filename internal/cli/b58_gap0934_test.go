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
	"context"
	"errors"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"github.com/defenseclaw/defenseclaw/internal/substrate/attest"
)

// GAP-0934: the sidecar client waits skills.scan.timeout (not its 20s
// default, cut at 25s), and a scan past its timeout is skill_scan_timeout,
// not skill_scanner_down.
func TestB58SidecarClientUsesTheScanTimeout(t *testing.T) {
	old := substrateScanDir
	substrateScanDir = t.TempDir()
	t.Cleanup(func() { substrateScanDir = old })
	cfg := &config.Config{DataDir: t.TempDir()}
	cfg.Substrate.Skills.Scan.Timeout = "45s"
	s := newRuntimeSkillScanner(cfg)
	if s.remote == nil || s.remote.Timeout != 45*time.Second {
		t.Fatalf("sidecar client timeout: %+v", s.remote)
	}
}

type b58TimeoutScanner struct{}

func (b58TimeoutScanner) Name() string               { return "skill-scanner" }
func (b58TimeoutScanner) Version() string            { return "test" }
func (b58TimeoutScanner) SupportedTargets() []string { return []string{"skill"} }
func (b58TimeoutScanner) Scan(context.Context, string) (*scanner.ScanResult, error) {
	return nil, scanner.ErrScanTimeout
}

func TestB58SidecarTimeoutIsScanTimeout(t *testing.T) {
	rt := attest.NewRuntimeScanner(&config.Config{DataDir: t.TempDir()})
	rt.Skill = b58TimeoutScanner{}
	s := runtimeSkillScanner{rt: rt}
	files := []gateway.SubstrateAttachedFile{{Role: "skill_file", Path: "/sandbox/.claude/skills/x/SKILL.md", Content: []byte("---\nname: x\n---\nbody")}}
	_, _, err := s.ScanSkillFolder(context.Background(), "x", "/sandbox/.claude/skills/x", files)
	if !errors.Is(err, gateway.ErrSubstrateSkillScanTimeout) || errors.Is(err, gateway.ErrSubstrateSkillScannerUnavailable) {
		t.Fatalf("a sidecar timeout: %v", err)
	}
}
