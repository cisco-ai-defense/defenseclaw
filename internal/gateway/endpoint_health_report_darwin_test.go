// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package gateway

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestAVCVersionReceiptCandidateRule(t *testing.T) {
	for id, want := range map[string]bool{
		"com.cisco.pkg.secureclient.avc":           true,
		"com.cisco.secureclient.agenticvisibility": true,
		"com.cisco.pkg.anyconnect.avc":             true,
		"com.cisco.pkg.secureclient.defenseclaw":   false,
		"com.cisco.secureclient.avc.defenseclaw":   false,
		"com.cisco.pkg.secureclient.gui":           false,
		"com.example.avc":                          false,
	} {
		if got := endpointHealthAVCReceiptCandidate(id); got != want {
			t.Errorf("candidate(%q) = %v, want %v", id, got, want)
		}
	}
}

func TestAVCVersionReadsReceipt(t *testing.T) {
	dir := t.TempDir()
	restore := endpointHealthReceiptDir
	endpointHealthReceiptDir = dir
	defer func() { endpointHealthReceiptDir = restore }()
	if _, err := readAVCVersion(context.Background()); err == nil {
		t.Fatal("an empty receipt directory produced a version")
	}
	receipt, err := base64.StdEncoding.DecodeString(endpointHealthTestBinaryReceipt)
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{
		"com.cisco.pkg.secureclient.gui.plist":         receipt,
		"com.cisco.pkg.secureclient.defenseclaw.plist": receipt,
		"com.cisco.pkg.secureclient.avc.plist":         receipt,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := readAVCVersion(context.Background()); err != nil || got != "5.1.21.4204" {
		t.Fatalf("readAVCVersion = %q, %v", got, err)
	}
	if readOSVersion() == "" {
		t.Fatal("readOSVersion is empty on macOS")
	}
}
