// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enforce"
)

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
