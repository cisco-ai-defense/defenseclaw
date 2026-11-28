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
	"strings"
	"testing"
)

// A program without internal/config/v8schema fails every v8 schema check
// instead of passing the document unchecked. Not parallel: it removes the
// registered check for its duration.
func TestV8SchemaCheckFailsClosedWhenNotLinked(t *testing.T) {
	registered := v8SchemaCheck.Load()
	if registered == nil {
		t.Fatal("the config test program must link internal/config/fullconfig (fullconfig_link_test.go)")
	}
	v8SchemaCheck.Store(nil)
	t.Cleanup(func() { v8SchemaCheck.Store(registered) })

	for name, raw := range map[string]string{
		"valid":   "config_version: 9\n",
		"invalid": "config_version: 9\nnot_a_setting: true\n",
	} {
		err := ValidateV8SchemaBytes(name+".yaml", []byte(raw))
		if !errors.Is(err, errV8SchemaCheckNotLinked) || !strings.Contains(err.Error(), "initialize embedded v8 schema") {
			t.Fatalf("%s: ValidateV8SchemaBytes without the check = %v, want the not-linked error", name, err)
		}
		if _, err := ParseCompileObservabilityV8(name+".yaml", []byte(raw), ObservabilityV8CompileOptions{DefaultDataDir: t.TempDir()}); !errors.Is(err, errV8SchemaCheckNotLinked) {
			t.Fatalf("%s: ParseCompileObservabilityV8 without the check = %v, want the not-linked error", name, err)
		}
	}
}

func TestV8SchemaCheckRegistersOnce(t *testing.T) {
	registered := v8SchemaCheck.Load()
	if registered == nil {
		t.Fatal("the config test program must link internal/config/fullconfig")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("a second RegisterV8SchemaCheck did not panic")
		}
		if v8SchemaCheck.Load() != registered {
			t.Fatal("a second RegisterV8SchemaCheck replaced the check")
		}
	}()
	RegisterV8SchemaCheck(func(any) (*V8SchemaViolation, bool, error) { return nil, false, nil })
}

// GAP-1862: a program without the v8 schema check cannot tell whether an
// observability destination still uses a credential, so the credential
// reference check reports one instead of "" (which would let the credential
// be removed).
func TestCredentialReferenceFailsClosedWhenTheSchemaCheckIsNotLinked(t *testing.T) {
	registered := v8SchemaCheck.Load()
	if registered == nil {
		t.Fatal("the config test program must link internal/config/fullconfig (fullconfig_link_test.go)")
	}
	raw := []byte("config_version: 9\n")
	if at := InstalledCredentialReference("config.yaml", raw, t.TempDir(), "unused"); at != "" {
		t.Fatalf("linked: InstalledCredentialReference = %q, want none", at)
	}
	v8SchemaCheck.Store(nil)
	t.Cleanup(func() { v8SchemaCheck.Store(registered) })
	for _, at := range []string{
		ObservabilityV8CredentialReference("config.yaml", raw, t.TempDir(), "unused"),
		InstalledCredentialReference("config.yaml", raw, t.TempDir(), "unused"),
	} {
		if !strings.Contains(at, "not linked") {
			t.Fatalf("not linked: credential reference = %q, want the not-linked reference", at)
		}
	}
}
