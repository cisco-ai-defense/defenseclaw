// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-1884: a Codex start refused because the registration cannot be
// repaired names the step the user runs when the cause names one (the
// Codex executable changed after a self-update); any other cause keeps the
// bare refusal.
func TestR105GAP1884RefusalNamesTheRepairStep(t *testing.T) {
	changed := errors.New("the Codex executable changed since setup (a Codex update does this); run: defenseclaw setup codex --yes")
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"executable changed", fmt.Errorf("register Codex: %w", fmt.Errorf("selected Codex executable digest does not match protected evidence: /usr/bin/codex (%w)", changed)),
			codexStartRegistrationUnavailable + ": " + changed.Error()},
		{"other cause", errors.New("hooks.json is not writable"), codexStartRegistrationUnavailable},
	} {
		api := &APIServer{scannerCfg: &config.Config{}}
		api.hookRegistrationRepair = func(context.Context, string) error { return tc.err }
		if got := api.codexStartRegistrationRefusal(context.Background(), "codex"); got != tc.want {
			t.Fatalf("%s: refusal = %q, want %q", tc.name, got, tc.want)
		}
	}
}
