// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package sensor

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// TestGAP1592ProcessStartEnvIgnoresAProcFolderAtTheDriveRoot: on Windows the
// path /proc/<pid>/environ names \proc at the drive root, a folder any
// account may make. A file planted there is not the start environment of the
// process and is never read.
func TestGAP1592ProcessStartEnvIgnoresAProcFolderAtTheDriveRoot(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	proc := filepath.VolumeName(wd) + `\proc`
	if _, err := os.Lstat(proc); err == nil {
		t.Fatalf("%s already exists; this test makes and removes it", proc)
	}
	dir := filepath.Join(proc, strconv.Itoa(os.Getpid()))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("make the planted folder %s: %v", dir, err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(proc) })
	if err := os.WriteFile(filepath.Join(dir, "environ"), []byte("DC_GAP1592_PLANTED=1\x00AWS_CONFIG_FILE=C:/planted/config\x00"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"DC_GAP1592_PLANTED", "AWS_CONFIG_FILE"} {
		if value, ok := processStartEnv(os.Getpid(), name); ok {
			t.Fatalf("%s: read %q from the planted %s", name, value, dir)
		}
	}
}
