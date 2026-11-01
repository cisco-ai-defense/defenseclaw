// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package rxprefilter

import (
	"regexp"
	"strings"
	"testing"
)

func TestMayMatchNeverSkipsAMatchingText(t *testing.T) {
	filler := strings.Repeat("echo line benign filler for heredoc payload size\n", 200)
	cases := []struct {
		pattern string
		text    string
		match   bool
	}{
		{`(?i)secret_key\s*=`, "ſECRET_KEY =", true},
		{`(?i)secret_key\s*=`, "Key secret_key =", true},
		{`(?i)(?:api[_-]?key|token)\s*[=:]`, "my ToKeN: x", true},
		{`(?i)(?:foo)?bar`, "BAR", true},
		{`(?i)(?:foo)?bar`, "foo", false},
		{`a{0,3}zz`, "zz", true},
		{`(?:x|[0-9])+done`, "7done", true},
		{`[0-9]{3}-[0-9]{4}`, "555-1234", true},
		{`(?i)\bdd\s+if=`, "DD IF=/dev/zero", true},
		{`(?i)(?:^|\n)[^\n]*ssn[^\n]*,`, "id,SSN,name", true},
		{`(?i)\x{212a}elvin`, "kelvin", true},
		{`(?s)begin.*end`, "begin\nend", true},
		{`(?s)begin.*end`, "begin only", false},
		{`(?is)reg\s+add[^\n]{0,9}shell[/\\]open[/\\]command`, "REG ADD x Shell\\Open\\Command", true},
		{`(?is)reg\s+add[^\n]{0,9}shell[/\\]open[/\\]command`, "reg add shell only", false},
		{`(?i)\bos\.(?:sym)?link\s*\(|\bmklink\b`, "MkLink /j a b", true},
	}
	for _, tc := range cases {
		re := regexp.MustCompile(tc.pattern)
		for _, text := range []string{tc.text, filler + tc.text + filler} {
			if got := re.MatchString(text); got != tc.match {
				t.Fatalf("%q on %q: regexp says %v, case wants %v", tc.pattern, tc.text, got, tc.match)
			}
			if tc.match && !MayMatch(re, text) {
				t.Errorf("MayMatch skipped %q on a text it matches (%q)", tc.pattern, tc.text)
			}
			if tc.match && !RequiredLiteralsIn(re, text) {
				t.Errorf("RequiredLiteralsIn(%q) false on a text it matches (%q)", tc.pattern, tc.text)
			}
		}
		if !tc.match && len(filler) >= MinText && MayMatch(re, filler+tc.text+filler) && HasRequiredLiterals(re) &&
			!strings.Contains(tc.pattern, "{0,") {
			t.Logf("%q not skipped on a non-matching text (allowed, only less selective)", tc.pattern)
		}
	}
	if HasRequiredLiterals(regexp.MustCompile(`[0-9]{3}[a-z]{4}`)) {
		t.Fatal("a class-only pattern got required literals")
	}
	if MayMatch(regexp.MustCompile(`(?is)reg\s+add[^\n]{0,9}shell[/\\]open[/\\]command`), filler+"reg add shell only"+filler) {
		t.Fatal("a text missing a required literal of the concatenation was not skipped")
	}
}
