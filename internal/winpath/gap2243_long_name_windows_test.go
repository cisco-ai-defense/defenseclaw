// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package winpath

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-2243: LongName spells an 8.3 alias of an existing file by its long
// name, and leaves every other spelling as it is.
func TestGAP2243LongNameExpandsAnAliasOfTheSameFile(t *testing.T) {
	root, hook, other := gap2175Image(t)
	alias := gap2175Short(t, hook)
	if got := LongName(alias); !strings.EqualFold(got, hook) || strings.Contains(got, "~") {
		t.Fatalf("LongName(%s) = %s, want %s", alias, got, hook)
	}
	if got := LongName(gap2175Short(t, other)); !strings.EqualFold(got, other) {
		t.Fatalf("LongName of the other file's alias = %s, want %s", got, other)
	}
	for _, path := range []string{
		hook,
		"",
		filepath.Join(root, "MISSIN~1", "DEFENS~1.EXE"),
		`DEFENS~1.EXE`,
	} {
		if got := LongName(path); got != path {
			t.Errorf("LongName(%q) = %q, want it unchanged", path, got)
		}
	}
	if err := os.Remove(hook); err != nil {
		t.Fatal(err)
	}
	if got := LongName(alias); got != alias {
		t.Errorf("LongName of a removed file's alias = %q, want it unchanged", got)
	}
}
