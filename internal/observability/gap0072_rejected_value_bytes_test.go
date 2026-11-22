// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package observability

import "testing"

// The capture measures the producer's value before canonicalizing it, so the
// measure must end on any value: a self-referencing map or slice from a buggy
// producer, or one nested deeper than a canonical value may be, is reported
// over the capture budget and left out, not walked forever (GAP-0072).
func TestRejectedValueBytesEndsOnCyclesAndDeepValues(t *testing.T) {
	cyclic := map[string]any{"name": "loop"}
	cyclic["self"] = cyclic
	loop := []any{"x"}
	loop = append(loop, nil)
	loop[1] = loop
	deep := any("leaf")
	for range MaxCanonicalValueDepth + 4 {
		deep = map[string]any{"d": deep}
	}
	for name, value := range map[string]any{"cyclic map": cyclic, "cyclic slice": loop, "deep": deep} {
		if got := rejectedValueBytes(value); got <= RejectedRecordMaxCaptureBytes {
			t.Fatalf("%s: rejectedValueBytes = %d, want over the capture budget %d", name, got, RejectedRecordMaxCaptureBytes)
		}
	}
	body, _, omitted := captureRejectedFamilyValues(
		[]familyFieldDescriptor{{key: "loop", fieldClass: FieldClassContent}, {key: "ok", fieldClass: FieldClassMetadata}},
		familyFieldValues{{key: "loop", value: cyclic, present: true}, {key: "ok", value: "fine", present: true}},
	)
	if _, kept := body["loop"]; kept || body["ok"] != "fine" || len(omitted) != 1 || omitted[0] != "loop" {
		t.Fatalf("capture of a cyclic value: body=%v omitted=%v, want loop omitted and ok kept", body, omitted)
	}
	// A shallow value is measured as before.
	shallow := map[string]any{"a": "bc", "list": []any{"d"}}
	if got, want := rejectedValueBytes(shallow), 2+(1+3+4)+(4+3+2+1+3); got != want {
		t.Fatalf("shallow measure = %d, want %d", got, want)
	}
}
