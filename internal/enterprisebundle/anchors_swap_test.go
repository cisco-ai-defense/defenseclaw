// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// A-W05 (mgmt-agent-api:GAP-1308): a trust anchor source that another file
// replaces after the trust check passed and before the file is opened is
// refused anchor_insecure, with no anchors and no bytes for the caller to
// install. The trust check is the seam: it renames the swapped file over the
// checked path at the exact check/use instant, so no timing is involved.
func TestReadAnchorsFileRefusesASourceSwappedAfterTheTrustCheck(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, AnchorsName)
	checked := []byte(anchorsJSON("acme", []string{"eng"}, 3, edAnchorKey(t)))
	swapped := []byte(anchorsJSON("other", []string{"eng"}, 0, edAnchorKey(t)))
	if err := os.WriteFile(path, checked, 0o600); err != nil {
		t.Fatal(err)
	}

	// Control: with no swap the checked bytes are returned.
	anchors, raw, err := ReadAnchorsFile(path, func(string) error { return nil })
	if err != nil || anchors == nil || !bytes.Equal(raw, checked) {
		t.Fatalf("unswapped read = %v (anchors %v, %d bytes)", err, anchors != nil, len(raw))
	}

	replacement := filepath.Join(dir, "replacement.json")
	if err := os.WriteFile(replacement, swapped, 0o600); err != nil {
		t.Fatal(err)
	}
	checks := 0
	trust := func(p string) error {
		checks++
		if p != path {
			t.Fatalf("trust checked %q, want %q", p, path)
		}
		// The check passed on the original file; another writer now
		// replaces it before the reader opens the path.
		if err := os.Rename(replacement, path); err != nil {
			t.Fatalf("swap the anchor source: %v", err)
		}
		return nil
	}
	anchors, raw, err = ReadAnchorsFile(path, trust)
	if checks != 1 {
		t.Fatalf("trust ran %d times, want once", checks)
	}
	if CodeOf(err) != CodeAnchorInsecure || anchors != nil || raw != nil {
		t.Fatalf("swapped source = %v (code %q, anchors %v, %d bytes: swapped bytes %v); want anchor_insecure and nothing to install",
			err, CodeOf(err), anchors != nil, len(raw), bytes.Equal(raw, swapped))
	}
}
