// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
)

// GAP-0132: the runtime unpacker refuses entries that would leave its folder.
func TestUnpackRefusesEscapingEntries(t *testing.T) {
	for _, name := range []string{"../evil.py", "/abs.py", `python\..\..\x.py`, "a/../../b.py"} {
		var buf bytes.Buffer
		w := zip.NewWriter(&buf)
		f, _ := w.Create(name)
		_, _ = f.Write([]byte("x"))
		_ = w.Close()
		if err := unpack(buf.Bytes(), t.TempDir()); err == nil || !strings.Contains(err.Error(), "relative path") {
			t.Fatalf("unpack(%q) = %v, want refusal", name, err)
		}
	}
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, _ := w.Create("python/Lib/site-packages/ok.py")
	_, _ = f.Write([]byte("ok"))
	_ = w.Close()
	if err := unpack(buf.Bytes(), t.TempDir()); err != nil {
		t.Fatalf("unpack of a plain entry: %v", err)
	}
}
