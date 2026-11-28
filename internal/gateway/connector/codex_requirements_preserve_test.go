// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"strings"
	"testing"
)

// The in-place editor falls back to the whole-document render for a layout
// it cannot narrow, and its result always decodes to the edited document.
func TestCodexRequirementsPreservingFallsBackForInlineTables(t *testing.T) {
	raw := []byte("# admin\nhooks = { windows_managed_dir = 'C:\\\\x' }\n")
	cfg := map[string]interface{}{"hooks": map[string]interface{}{"windows_managed_dir": `C:\y`}}
	out, err := renderCodexRequirementsPreserving(raw, cfg)
	if err != nil {
		t.Fatal(err)
	}
	check := map[string]interface{}{}
	if err := parseCodexTOML(out, &check); err != nil || !codexValueMatches(check, cfg) {
		t.Fatalf("fallback = %q err=%v", out, err)
	}
	same, err := renderCodexRequirementsPreserving([]byte("# a\nx = 1 # b\n"), map[string]interface{}{"x": int64(1)})
	if err != nil || string(same) != "# a\nx = 1 # b\n" {
		t.Fatalf("unchanged document = %q err=%v", same, err)
	}
	changed, err := renderCodexRequirementsPreserving([]byte("# a\nx = 1 # b\n[t]\n# c\ny = 2\n"),
		map[string]interface{}{"x": int64(3), "t": map[string]interface{}{"y": int64(2), "z": true}})
	if err != nil || !strings.Contains(string(changed), "# a\n") || !strings.Contains(string(changed), "[t]\n") ||
		!strings.Contains(string(changed), "# c\ny = 2\n") || !strings.Contains(string(changed), "x = 3\n") ||
		!strings.Contains(string(changed), "z = true\n") {
		t.Fatalf("narrow edit = %q err=%v", changed, err)
	}
}
