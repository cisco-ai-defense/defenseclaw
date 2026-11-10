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

//go:build windows

package cli

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// GAP-1026: the resolver tags a missing runtime selection as drift when no
// integrity finding backs it (the real result for an account that was enrolled
// before the guardian revoked its selection). A standalone hook names it
// pending; Secure Client keeps the class; real drift and a boundary stay as
// they were. Every standalone case is closed.
func TestWindowsStandaloneHookNamesARevokedSelectionPendingNotDrift(t *testing.T) {
	_, _ = stageTrustedNativeHookForTest(t, "closed")
	savedSecureClient := secureClientHost
	previousStandalone := standaloneEnterpriseHookCheck
	t.Cleanup(func() {
		secureClientHost = savedSecureClient
		standaloneEnterpriseHookCheck = previousStandalone
	})
	pending := fmt.Errorf("enterprise hooks: registered SID is absent from the managed runtime generation selector: %w",
		enterprisehooks.ErrWindowsManagedRuntimeGenerationPending)
	for _, tc := range []struct {
		name         string
		err          error
		standalone   bool
		secureClient bool
		want         string
	}{
		{"pending tagged drift, standalone", fmt.Errorf("%w: %w", enterprisehooks.ErrWindowsManagedRuntimeDrift, pending), true, false,
			enterprisehooks.WindowsManagedEnrollmentPendingReason},
		{"pending tagged drift, Secure Client", fmt.Errorf("%w: %w", enterprisehooks.ErrWindowsManagedRuntimeDrift, pending), false, true,
			enterprisehooks.WindowsManagedRuntimeDriftReason},
		{"real drift, standalone", fmt.Errorf("%w: %w", enterprisehooks.ErrWindowsManagedRuntimeDrift, errors.New("bundle ACL drifted")), true, false,
			enterprisehooks.WindowsManagedRuntimeDriftReason},
		{"pending with a boundary finding, standalone", fmt.Errorf("%w: %w", enterprisehooks.ErrWindowsManagedRuntimeBoundary, pending), true, false,
			enterprisehooks.WindowsManagedEnrollmentPendingReason},
		{"boundary without pending, standalone", fmt.Errorf("%w: %w", enterprisehooks.ErrWindowsManagedRuntimeBoundary, errors.New("reparse point")), true, false,
			"enterprise_managed_runtime_state_invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			standalone, err := tc.standalone, tc.err
			standaloneEnterpriseHookCheck = func(string) bool { return standalone }
			secureClientHost = func() bool { return tc.secureClient }
			stubEnterpriseManagedRuntimeResolver(t, func(string, string) (enterprisehooks.WindowsManagedHookRuntime, error) {
				return enterprisehooks.WindowsManagedHookRuntime{
					Connector:    "codex",
					DataDir:      filepath.Join(t.TempDir(), ".defenseclaw"),
					PolicyActive: true,
				}, err
			})
			if prepareEnterpriseManagedHookRuntime("codex") {
				t.Fatal("a runtime failure was treated as a no-op")
			}
			opts := buildHookOptionsForRuntime("codex", "PreToolUse", "", "open", true)
			if opts.ManagedRuntimeFailure != tc.want {
				t.Fatalf("runtime failure %q, want %q", opts.ManagedRuntimeFailure, tc.want)
			}
			if tc.standalone && (opts.FailMode != "closed" || !opts.StrictAvailability) {
				t.Fatalf("standalone refusal is not closed: fail mode %q strict %v", opts.FailMode, opts.StrictAvailability)
			}
		})
	}
}
