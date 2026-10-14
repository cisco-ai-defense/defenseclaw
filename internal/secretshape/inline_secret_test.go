// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package secretshape

import (
	"strings"
	"testing"
)

func TestFindInlineSecret(t *testing.T) {
	// Shapes are assembled at run time so no literal here looks like one.
	body := "Q7XK2M9PLW4RT8VN"
	for text, want := range map[string]string{
		"key: AK" + "IA" + body:                          "aws-access-key-id",
		"t=gh" + "p_" + strings.Repeat(body, 2) + "abcd": "github-token",
		"sk-" + "ant-" + strings.Repeat(body, 2):         "anthropic-key",
		"x xo" + "xb-1234567890-abcdef":                  "slack-token",
		"pattern: AKIA[0-9A-Z]{16}":                      "",
		"example AKIA" + strings.Repeat("X", 16):         "",
		"task-" + strings.Repeat(body, 2):                "",
		"plain text":                                     "",
	} {
		got, ok := FindInlineSecret(text)
		if ok != (want != "") || got.Label != want {
			t.Errorf("%q: got %+v %v, want %q", text, got, ok, want)
		}
	}
	text := "first AK" + "IA" + body + " then gh" + "p_" + strings.Repeat(body, 2) + "abcd"
	if got, _ := FindInlineSecret(text); got.Offset != len("first ") {
		t.Fatalf("first secret at %d, want %d", got.Offset, len("first "))
	}
}
