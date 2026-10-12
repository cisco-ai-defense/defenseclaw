// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package openshell

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestReadPrerequisites(t *testing.T) {
	old := renderedOwnerOK
	renderedOwnerOK = func(info fs.FileInfo) bool { return info.Mode().Perm()&0o022 == 0 }
	t.Cleanup(func() { renderedOwnerOK = old })
	dir := t.TempDir()
	path := filepath.Join(dir, PrerequisitesFile)

	if record, err := ReadPrerequisites(path); record != nil || err != nil {
		t.Fatalf("a missing record = %+v %v, want nil and no error", record, err)
	}
	doc := `{"version":1,"checked_at":"2026-10-09T10:00:00Z","install":"setup","driver":"vm","ready":false,` +
		`"missing":[{"item":"kvm","detail":"/dev/kvm does not exist","fix":"enable virtualization"}]}`
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	record, err := ReadPrerequisites(path)
	if err != nil || record == nil || record.Ready || record.Install != "setup" || record.Driver != "vm" ||
		len(record.Missing) != 1 || record.Missing[0].Item != "kvm" || record.Missing[0].Fix != "enable virtualization" {
		t.Fatalf("record = %+v %v", record, err)
	}

	// A record from a newer schema, or one anyone can write, is refused.
	if err := os.WriteFile(path, []byte(`{"version":2,"ready":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrerequisites(path); err == nil {
		t.Error("a record of another version is read")
	}
	if err := os.WriteFile(path, []byte(doc), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrerequisites(path); err == nil {
		t.Error("a world-writable record is trusted")
	}
}
