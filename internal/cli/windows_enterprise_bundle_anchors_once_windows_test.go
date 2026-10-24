//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// Installing TRUSTANCHORS= reads the source once and writes the bytes it
// decoded and checked: a source that changes after that read does not
// reach the installed file.
func TestWindowsBundleAnchorsInstallReadsTheSourceOnce(t *testing.T) {
	stubWindowsBundleHost(t)
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	checked, err := os.ReadFile(e.anchors)
	if err != nil {
		t.Fatal(err)
	}
	swapped := bytes.Replace(checked, []byte(`"min_version":0`), []byte(`"min_version":1`), 1)
	if bytes.Equal(swapped, checked) {
		t.Fatal("the swapped anchors equal the checked anchors")
	}
	saved := windowsBundleReadAnchors
	t.Cleanup(func() { windowsBundleReadAnchors = saved })
	reads := 0
	windowsBundleReadAnchors = func(path string, trust enterprisebundle.TrustCheck) (*enterprisebundle.Anchors, []byte, error) {
		anchors, raw, err := saved(path, trust)
		if path == e.anchors {
			reads++
			// Another writer replaces the source right after the read.
			writeBundleTestFile(t, e.anchors, swapped)
		}
		return anchors, raw, err
	}
	dst := filepath.Join(t.TempDir(), "trust", enterprisebundle.AnchorsName)
	installed, _, err := installWindowsBundleAnchors(e.anchors, dst)
	if err != nil {
		t.Fatal(err)
	}
	if reads != 1 {
		t.Fatalf("the anchor source was read %d times, want once", reads)
	}
	written, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(installed, checked) || !bytes.Equal(written, checked) {
		t.Fatalf("installed anchors are not the bytes that were checked (returned %d bytes, written %d bytes)", len(installed), len(written))
	}
}
