// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package effectrules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPlainStepUpNeedsRealDirectoryAndReadBudget(t *testing.T) {
	root := t.TempDir()
	plain := filepath.Join(root, "plain")
	outside := filepath.Join(root, "outside", "child")
	for _, dir := range []string{plain, outside} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	for name, operand := range map[string]string{
		"plain":   plain + "/..",
		"link":    filepath.Join(root, "link") + "/..",
		"missing": filepath.Join(root, "missing") + "/..",
	} {
		p := plainStepUpProof{checked: make(map[string]bool)}
		got, ok := p.place(operand)
		if name == "plain" && (!ok || got != root) {
			t.Errorf("plain: got known=%v", ok)
		}
		if name != "plain" && ok {
			t.Errorf("%s: unproved step up became known", name)
		}
		if p.reads > 8 {
			t.Errorf("%s: read budget exceeded", name)
		}
	}
	deep := root
	for i := 0; i < 9; i++ {
		deep = filepath.Join(deep, "d")
		if err := os.MkdirAll(deep, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	p := plainStepUpProof{checked: make(map[string]bool)}
	if _, ok := p.place(deep + "/.."); ok || p.reads != 8 {
		t.Errorf("deep: known=%v reads=%d, want unknown at budget", ok, p.reads)
	}
}
