// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/sandbox"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

func TestPolicyFilePoll_BumpsGeneration(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.PolicyDir = filepath.Join(cfg.DataDir, "policies")
	if err := os.MkdirAll(cfg.PolicyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)
	w := New(cfg, nil, nil, store, logger, shell, nil, nil)
	blockPath := filepath.Join(cfg.DataDir, "block_list.yaml")
	if err := os.WriteFile(blockPath, []byte(`- target_type: skill
  target_name: a
  reason: t
`), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	w.pollPolicyFilesOnce(ctx)
	gen1 := version.Current().Generation
	if err := os.WriteFile(blockPath, []byte(`- target_type: skill
  target_name: b
  reason: t
`), 0o600); err != nil {
		t.Fatal(err)
	}
	w.pollPolicyFilesOnce(ctx)
	gen2 := version.Current().Generation
	if gen2 <= gen1 {
		t.Fatalf("generation did not bump: %d -> %d", gen1, gen2)
	}
}

func TestQuarantineStress_ConcurrentMoves(t *testing.T) {
	tmp := t.TempDir()
	qdir := filepath.Join(tmp, "q")
	se := enforce.NewSkillEnforcer(qdir)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			skill := filepath.Join(tmp, fmt.Sprintf("skill-%d", i))
			if err := os.MkdirAll(filepath.Join(skill, "inner"), 0o700); err != nil {
				return
			}
			_, _ = se.Quarantine(skill)
		}(i)
	}
	wg.Wait()
}
