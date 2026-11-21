// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// A row names one way to find its files: rel's under (the path below a
// folder) and feat/substrate's folder (from the folder start, narrowed by
// suffixes) select differently, so no row may set both (push 18b merge,
// S7 review).
func TestCredentialFileShapeRowSetsAtMostOneFolderForm(t *testing.T) {
	for i, row := range credentialFileShapes {
		if row.under != "" && row.folder != "" {
			t.Errorf("row %d (class %s) sets both under %q and folder %q", i, row.class, row.under, row.folder)
		}
	}
}

// Every folder row of the table has its own probe path (the probe walk of the
// secret-read chain tests reaches it), not the suffix-only fallback.
func TestCredentialFileShapeProbePathsCoverFolderRows(t *testing.T) {
	probes := map[string]bool{}
	for _, probe := range CredentialFileShapeProbePaths() {
		probes[probe] = true
	}
	for _, row := range credentialFileShapes {
		if row.folder == "" {
			continue
		}
		want := row.folder + "/probe"
		if len(row.suffixes) != 0 {
			want += row.suffixes[0]
		}
		if !probes[want] {
			t.Errorf("folder row %q: no probe %q", row.folder, want)
		}
	}
}
