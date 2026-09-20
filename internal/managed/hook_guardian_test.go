// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"strings"
	"testing"
	"time"
)

func TestValidateHookGuardianFreshness(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		value   string
		wantErr string
	}{
		{name: "fresh", value: now.Add(-HookGuardianMaxAge).Format(time.RFC3339)},
		{name: "future_within_skew", value: now.Add(HookGuardianFutureSkew).Format(time.RFC3339)},
		{name: "stale", value: now.Add(-HookGuardianMaxAge - time.Second).Format(time.RFC3339), wantErr: "stale"},
		{name: "future", value: now.Add(HookGuardianFutureSkew + time.Second).Format(time.RFC3339), wantErr: "future"},
		{name: "invalid", value: "yesterday", wantErr: "invalid updated_at"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateHookGuardianFreshness(tc.value, now)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateHookGuardianFreshness: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}
