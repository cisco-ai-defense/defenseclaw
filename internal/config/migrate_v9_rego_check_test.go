// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// A program without internal/config/fullconfig stops the v9 migration's Rego
// refresh with an error instead of skipping the module check. Not parallel:
// it removes the registered check for its duration.
func TestV9RegoReadsFailsClosedWhenNotLinked(t *testing.T) {
	registered := v9RegoReads.Load()
	if registered == nil {
		t.Fatal("the config test program must link internal/config/fullconfig (fullconfig_link_test.go)")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "admission.rego"), []byte("package defenseclaw.admission\n\nallow if data.config.ok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	reads := registered.Reads(map[string]any{"admission.rego": mustParseRego(t, registered, dir)}, v9VendorRegoModules)
	if len(reads["admission.rego"]) == 0 {
		t.Fatalf("the registered check found no outside data read in admission.rego: %v", reads)
	}

	v9RegoReads.Store(nil)
	t.Cleanup(func() { v9RegoReads.Store(registered) })
	if _, err := v9RegoReadsCheck(); !errors.Is(err, errV9RegoReadsNotLinked) {
		t.Fatalf("v9RegoReadsCheck without the check = %v, want the not-linked error", err)
	}
}

func mustParseRego(t *testing.T, reads *V9RegoReads, dir string) any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "admission.rego"))
	if err != nil {
		t.Fatal(err)
	}
	module, err := reads.Parse("admission.rego", raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return module
}

func TestV9RegoReadsRegistersOnce(t *testing.T) {
	registered := v9RegoReads.Load()
	if registered == nil {
		t.Fatal("the config test program must link internal/config/fullconfig")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("a second RegisterV9RegoReads did not panic")
		}
		if v9RegoReads.Load() != registered {
			t.Fatal("a second RegisterV9RegoReads replaced the check")
		}
	}()
	RegisterV9RegoReads(*registered)
}
