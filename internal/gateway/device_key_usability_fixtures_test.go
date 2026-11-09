// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The Python CLI decides whether an existing device key is usable with a port of parseIdentity
// (cli/defenseclaw/doctor_recovery.py device_key_bytes_usable). Both sides read this one fixture file;
// cli/tests/test_device_key_usability.py asserts the same verdicts, so the two parsers cannot drift apart.
func TestParseIdentityMatchesTheSharedKeyFileFixtures(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "device_key_usability.json"))
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	var doc struct {
		Cases []struct {
			Name       string `json:"name"`
			FileBase64 string `json:"file_base64"`
			Usable     bool   `json:"usable"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse fixtures: %v", err)
	}
	usable, unusable := 0, 0
	for _, c := range doc.Cases {
		data, err := base64.StdEncoding.DecodeString(c.FileBase64)
		if err != nil {
			t.Fatalf("%s: fixture is not base64: %v", c.Name, err)
		}
		_, parseErr := parseIdentity(data)
		if got := parseErr == nil; got != c.Usable {
			t.Errorf("%s: parseIdentity usable = %v (err %v), fixture says %v", c.Name, got, parseErr, c.Usable)
		}
		if c.Usable {
			usable++
		} else {
			unusable++
		}
	}
	if usable == 0 || unusable == 0 {
		t.Fatalf("fixtures must hold both verdicts: %d usable, %d unusable", usable, unusable)
	}
}
