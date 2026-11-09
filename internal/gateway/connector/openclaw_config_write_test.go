// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"testing"
)

// The digest the gateway reports is that of the slice its own write was handed,
// so a setup that asks for it can tell the file still holds that write (GAP-0973).
func TestOpenClawConfigWriteDigestIsTheBytesTheRegistrationWrote(t *testing.T) {
	configPath, _ := openClawGrantFixture(t, "{\n  gateway: { port: 18789, },\n}\n")
	sum, ok := LastOpenClawConfigWrite()
	if !ok {
		t.Fatal("the registration wrote the file but reported no digest")
	}
	if want := sha256Hex([]byte(mustReadFileString(t, configPath))); sum != want {
		t.Fatalf("digest %s is not that of the written file %s", sum, want)
	}

	// A registration over a file that already says everything writes nothing,
	// and what was reported stays.
	extDir := filepath.Join(filepath.Dir(configPath), "extensions", "defenseclaw")
	if err := patchOpenClawConfig(configPath, extDir, false, false, true); err != nil {
		t.Fatal(err)
	}
	if again, _ := LastOpenClawConfigWrite(); again != sum {
		t.Fatalf("a registration that wrote nothing changed the reported digest: %s", again)
	}
}

// A save made by someone else after the registration leaves the file different
// from the reported digest: it is never read back into it.
func TestOpenClawConfigWriteDigestIgnoresASaveMadeAfterTheWrite(t *testing.T) {
	configPath, _ := openClawGrantFixture(t, "{}\n")
	sum, _ := LastOpenClawConfigWrite()
	saved := mustReadFileString(t, configPath) + "\n"
	if err := os.WriteFile(configPath, []byte(saved), 0o644); err != nil {
		t.Fatal(err)
	}
	if after, _ := LastOpenClawConfigWrite(); after != sum {
		t.Fatalf("an outside save changed the reported digest: %s", after)
	}
	if sha256Hex([]byte(saved)) == sum {
		t.Fatal("test setup: the save must differ from the registration")
	}
}
