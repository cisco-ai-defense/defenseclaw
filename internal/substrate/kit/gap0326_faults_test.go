// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The actor kit runs in Linux actor images only (kit.Config refuses other systems); its tests render and
// resolve paths for Linux.
//go:build linux

package kit

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// GAP-0326: the fault file's writer and reader.

func TestGAP0326FaultFileIsNeverCreated(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent")
	for _, p := range []string{missing, "relative-faults"} {
		recordTaskFault(func(k string) string {
			if k == TaskFaultsEnv {
				return p
			}
			return ""
		}, "PostToolUse", time.Now())
		if _, err := os.Stat(p); err == nil {
			os.Remove(p)
			t.Fatalf("recordTaskFault created %q; only the relay's own file may be written", p)
		}
	}
}

func TestGAP0326ReadTaskFaults(t *testing.T) {
	p := filepath.Join(t.TempDir(), "faults")
	body := "garbage\n2026-11-15T06:32:10Z PostToolUse\nnot-a-time Stop\n2026-11-15T06:32:40Z Stop\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	n, first := ReadTaskFaults(p)
	if n != 2 || first.Event != "PostToolUse" || first.At != "2026-11-15T06:32:10Z" {
		t.Fatalf("ReadTaskFaults = %d, %+v; want 2 faults, the first PostToolUse at 06:32:10Z", n, first)
	}
	if n, _ := ReadTaskFaults(filepath.Join(t.TempDir(), "none")); n != 0 {
		t.Fatalf("a missing file has %d faults, want 0", n)
	}
	if w := faultWord("Post\x1b[2JToolUse with spaces"); w != "Post2JToolUsewithspaces" {
		t.Fatalf("faultWord kept unsafe text: %q", w)
	}
}
