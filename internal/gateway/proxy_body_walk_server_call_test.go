// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
)

// A finished call the provider runs itself is judged with what it was called
// with, not with what it returned: the image of an image_generation_call
// (about 1.6 MB of base64 in result) is no argument of the call, and read as
// one the managed strict tier on a Windows host blocked a benign image reply
// (push 19, TestStreamTailBigLine/benign/responses/image_generation_call/
// managed-strict). A call the agent runs keeps every field.
func TestServerCallArgumentsLeaveOutItsResult(t *testing.T) {
	img := streamTailImage()
	cases := []struct {
		name, item, want string
		keep             bool
	}{
		{"image_generation_call", `{"type":"image_generation_call","id":"ig_1","status":"completed","result":"` + img + `"}`, "image_generation_call", false},
		{"file_search_call", `{"type":"file_search_call","id":"fs_1","queries":["q"],"results":[{"text":"` + img + `"}]}`, "file_search_call", false},
		{"agent call keeps its fields", `{"type":"custom_tool_call","id":"ct_1","name":"tool","result":"` + img + `"}`, "tool", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n, err := parseJSONTree([]byte(tc.item), 0)
			if err != nil {
				t.Fatal(err)
			}
			w := &textWalker{reply: true}
			w.callObject(n, "")
			if len(w.calls) != 1 {
				t.Fatalf("calls = %d, want 1", len(w.calls))
			}
			c := w.calls[0]
			if c.Function.Name != tc.want {
				t.Fatalf("name = %q, want %q", c.Function.Name, tc.want)
			}
			if got := strings.Contains(c.Function.Arguments, img); got != tc.keep {
				t.Fatalf("arguments carry the returned payload = %v, want %v (%d bytes)", got, tc.keep, len(c.Function.Arguments))
			}
			if !strings.Contains(c.Function.Arguments, `"id":`) {
				t.Fatalf("arguments lost the call's own fields: %.200s", c.Function.Arguments)
			}
		})
	}
}
