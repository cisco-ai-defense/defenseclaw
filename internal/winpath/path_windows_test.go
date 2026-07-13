// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package winpath

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestExtendedLocalAndUNCPaths(t *testing.T) {
	local, err := Extended(filepath.Join(t.TempDir(), "nested", "file"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(local, `\\?\`) || strings.HasPrefix(local, `\\?\UNC\`) {
		t.Fatalf("local extended path = %q", local)
	}
	unc, err := Extended(`\\server\share\folder\file`)
	if err != nil {
		t.Fatal(err)
	}
	if unc != `\\?\UNC\server\share\folder\file` {
		t.Fatalf("UNC extended path = %q", unc)
	}
	if repeated, err := Extended(local); err != nil || repeated != local {
		t.Fatalf("idempotent extension = %q, %v", repeated, err)
	}
}

func TestExtendedRejectsEmptyAndNUL(t *testing.T) {
	for _, path := range []string{
		"",
		"bad\x00path",
		`\\.\PhysicalDrive0`,
		`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1`,
		`\\?\UNC\server`,
	} {
		if _, err := Extended(path); err == nil {
			t.Fatalf("Extended(%q) succeeded", path)
		}
	}
}
