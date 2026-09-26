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

package openshell

import (
	"errors"
	"strings"
	"testing"
)

func TestParseVersionAcceptsReportedShapes(t *testing.T) {
	for in, want := range map[string]string{
		"0.1.1":                 "0.1.1",
		"v0.1.1":                "0.1.1",
		"openshell 0.1.1":       "0.1.1",
		"0.1.1-1":               "0.1.1",
		"openshell 0.1.2-pre.3": "0.1.2",
	} {
		v, err := ParseVersion(in)
		if err != nil {
			t.Fatalf("ParseVersion(%q): %v", in, err)
		}
		if v.String() != want {
			t.Fatalf("ParseVersion(%q) = %s, want %s", in, v, want)
		}
	}
	for _, bad := range []string{"", "openshell", "0.1", "a.b.c", "0.1.-1"} {
		if _, err := ParseVersion(bad); err == nil {
			t.Fatalf("ParseVersion(%q) succeeded", bad)
		}
	}
}

func TestCheckSupportedWindow(t *testing.T) {
	ok := []string{"0.1.1", "0.1.9"}
	for _, s := range ok {
		if err := CheckSupported(mustParse(s)); err != nil {
			t.Fatalf("%s rejected: %v", s, err)
		}
	}
	for _, s := range []string{"0.0.16", "0.1.0", "0.2.0", "1.0.0"} {
		err := CheckSupported(mustParse(s))
		var unsupported *ErrUnsupportedVersion
		if !errors.As(err, &unsupported) {
			t.Fatalf("%s accepted", s)
		}
	}
	if msg := CheckSupported(mustParse("0.0.16")).Error(); !strings.Contains(msg, "cannot upgrade it in place") {
		t.Fatalf("0.0.x message = %q", msg)
	}
}
