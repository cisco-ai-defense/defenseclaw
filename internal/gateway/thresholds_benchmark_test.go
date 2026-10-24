// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// BenchmarkResolveThresholds is the per-decision cost of resolving levels
// for a configuration a generation build resolved.
func BenchmarkResolveThresholds(b *testing.B) {
	dir := b.TempDir()
	b.Cleanup(func() { packPostures.Delete(dir); pendingPackPostures.Delete(dir) })
	cfg := &config.Config{}
	cfg.Guardrail.RulePackDir = dir
	notePackPosture(dir, "strict")
	buildThresholdTable(cfg, nil)
	publishPackPostures()
	b.ReportAllocs()
	for b.Loop() {
		_ = resolveThresholds(cfg, "codex")
	}
}
