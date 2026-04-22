// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

// TestObservabilityContractDocListsMatchGo ensures docs/OBSERVABILITY-CONTRACT.md
// enumerates every audit action, gateway error code, and gateway subsystem from
// the Go registries (single source of truth: internal/audit/actions.go,
// internal/gatewaylog/error_codes.go).
func TestObservabilityContractDocListsMatchGo(t *testing.T) {
	t.Parallel()
	root := moduleRoot(t)
	docPath := filepath.Join(root, "docs", "OBSERVABILITY-CONTRACT.md")
	b, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("read %s: %v", docPath, err)
	}
	doc := string(b)
	for _, a := range audit.AllActions() {
		s := string(a)
		if !strings.Contains(doc, s) {
			t.Errorf("OBSERVABILITY-CONTRACT.md missing audit action %q (add to Actions section)", s)
		}
	}
	for _, c := range gatewaylog.AllErrorCodes() {
		s := string(c)
		if !strings.Contains(doc, s) {
			t.Errorf("OBSERVABILITY-CONTRACT.md missing error code %q", s)
		}
	}
	for _, sub := range gatewaylog.AllSubsystems() {
		s := string(sub)
		if !strings.Contains(doc, s) {
			t.Errorf("OBSERVABILITY-CONTRACT.md missing subsystem %q", s)
		}
	}
}
