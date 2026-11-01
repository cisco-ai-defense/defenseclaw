// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// Only the first enrollment of a deferred row the guardian never protected
// may move the account's own link at its DefenseClaw folder aside
// (GAP-0193); a repair of a protected account and a row that is not
// deferred keep the reparse refusal.
func TestEnterpriseHookDeferredFirstEnrollmentOnlyForANeverProtectedDeferredRow(t *testing.T) {
	enabled := true
	for _, tc := range []struct {
		name      string
		deferred  bool
		protected bool
		want      bool
	}{
		{name: "deferred, never protected", deferred: true, want: true},
		{name: "deferred, protected before", deferred: true, protected: true},
		{name: "not deferred"},
		{name: "not deferred, protected before", protected: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := enterprisehooks.ManifestTarget{Connector: "claudecode", Enabled: &enabled, Deferred: tc.deferred}
			got := enterpriseHookDeferredFirstEnrollment(target, enterpriseHookPreviousProtection{PreviouslyProtected: tc.protected})
			if got != tc.want {
				t.Fatalf("enterpriseHookDeferredFirstEnrollment = %v, want %v", got, tc.want)
			}
		})
	}
}
