// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRefusedCaseRootsDoNotWriteOrChangeAnExistingResult(t *testing.T) {
	existing := t.TempDir()
	result := filepath.Join(existing, "terminal-result.json")
	original := []byte("existing result must remain intact\n")
	if err := os.WriteFile(result, original, 0600); err != nil {
		t.Fatal(err)
	}
	v := &verification{Variant: "inherited-console-relay"}
	for _, root := range []string{existing, "relative-terminal-case-refused"} {
		record, err := run(v, "", root, "terminal-basic")
		if err == nil || record["case_root_claimed"] != false {
			t.Fatalf("refused case root %q was claimed: error=%v record=%v", root, err, record)
		}
		raw, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		if err := writeResultIfOwned(root, record["case_root_claimed"] == true, raw); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(result)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatal("refused case root changed an existing result")
	}
}

func TestFreshCaseClaimAndResultCreationAreExclusive(t *testing.T) {
	root := filepath.Join(t.TempDir(), "fresh-terminal-case")
	if err := claimFreshCaseRoot(root); err != nil {
		t.Fatal(err)
	}
	if err := claimFreshCaseRoot(root); err == nil {
		t.Fatal("pre-existing case root was claimed again")
	}
	original := []byte(`{"first":true}`)
	if err := writeResultIfOwned(root, true, original); err != nil {
		t.Fatal(err)
	}
	if err := writeResultIfOwned(root, true, []byte(`{"first":false}`)); err == nil {
		t.Fatal("existing result was overwritten")
	}
	got, err := os.ReadFile(filepath.Join(root, "terminal-result.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, append(original, '\n')) {
		t.Fatal("exclusive result changed after a refused second write")
	}
}
