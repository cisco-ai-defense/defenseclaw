// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// TestNormalizeCiscoResponse_RedactionDirective verifies that the
// managed DefenseClawInspect response's is_redaction_enabled flag is
// parsed onto ScanVerdict.RedactionEnabled on BOTH the allow fast-path
// and the block/alert path, and that an absent key (the OSS
// InspectResponse shape) leaves the directive nil.
func TestNormalizeCiscoResponse_RedactionDirective(t *testing.T) {
	tests := []struct {
		name string
		data map[string]interface{}
		want *bool // nil, &true, or &false
	}{
		{
			name: "allow with redact=true",
			data: map[string]interface{}{"is_safe": true, "is_redaction_enabled": true},
			want: boolPtr(true),
		},
		{
			name: "allow with redact=false",
			data: map[string]interface{}{"is_safe": true, "is_redaction_enabled": false},
			want: boolPtr(false),
		},
		{
			name: "allow without directive (OSS)",
			data: map[string]interface{}{"is_safe": true},
			want: nil,
		},
		{
			name: "block with redact=false",
			data: map[string]interface{}{"is_safe": false, "action": "block", "is_redaction_enabled": false},
			want: boolPtr(false),
		},
		{
			name: "block with redact=true",
			data: map[string]interface{}{"is_safe": false, "action": "block", "is_redaction_enabled": true},
			want: boolPtr(true),
		},
		{
			name: "block without directive (OSS)",
			data: map[string]interface{}{"is_safe": false, "action": "block"},
			want: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := normalizeCiscoResponse(tc.data)
			if v == nil {
				t.Fatal("normalizeCiscoResponse returned nil verdict")
			}
			assertBoolPtrEqual(t, "RedactionEnabled", v.RedactionEnabled, tc.want)
		})
	}
}

// TestMergeWithLaneVerdict_PropagatesRedaction verifies the AID lane's
// cloud redaction directive rides through the strictest-wins fold onto
// the tool verdict, while a judge lane (nil directive) leaves it alone.
func TestMergeWithLaneVerdict_PropagatesRedaction(t *testing.T) {
	t.Run("AID directive propagates", func(t *testing.T) {
		local := &ToolInspectVerdict{Action: "allow", Severity: "NONE"}
		no := false
		aid := &ScanVerdict{Action: "block", Severity: "HIGH", RedactionEnabled: &no}
		got := mergeWithAIDVerdict(local, aid)
		assertBoolPtrEqual(t, "RedactionEnabled", got.RedactionEnabled, boolPtr(false))
	})

	t.Run("judge lane leaves existing directive untouched", func(t *testing.T) {
		yes := true
		local := &ToolInspectVerdict{Action: "block", Severity: "HIGH", RedactionEnabled: &yes}
		judge := &ScanVerdict{Action: "alert", Severity: "MEDIUM"} // nil directive
		got := mergeWithJudgeVerdict(local, judge)
		assertBoolPtrEqual(t, "RedactionEnabled", got.RedactionEnabled, boolPtr(true))
	})
}

func assertBoolPtrEqual(t *testing.T, field string, got, want *bool) {
	t.Helper()
	switch {
	case got == nil && want == nil:
		return
	case got == nil || want == nil:
		t.Fatalf("%s: got %v, want %v", field, boolPtrStr(got), boolPtrStr(want))
	case *got != *want:
		t.Fatalf("%s: got %v, want %v", field, *got, *want)
	}
}

func boolPtrStr(b *bool) string {
	if b == nil {
		return "nil"
	}
	if *b {
		return "true"
	}
	return "false"
}
