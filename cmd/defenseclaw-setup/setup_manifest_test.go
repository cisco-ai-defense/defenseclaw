// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/xml"
	"os"
	"strings"
	"testing"
)

type setupManifestDocument struct {
	TrustInfo struct {
		Security struct {
			RequestedPrivileges struct {
				ExecutionLevel struct {
					Level    string `xml:"level,attr"`
					UIAccess string `xml:"uiAccess,attr"`
				} `xml:"requestedExecutionLevel"`
			} `xml:"requestedPrivileges"`
		} `xml:"security"`
	} `xml:"trustInfo"`
}

func TestSetupManifestRequiresAsInvoker(t *testing.T) {
	contents, err := os.ReadFile("setup.manifest")
	if err != nil {
		t.Fatal(err)
	}
	var manifest setupManifestDocument
	if err := xml.Unmarshal(contents, &manifest); err != nil {
		t.Fatalf("parse setup manifest: %v", err)
	}
	level := manifest.TrustInfo.Security.RequestedPrivileges.ExecutionLevel
	if level.Level != "asInvoker" || level.UIAccess != "false" {
		t.Fatalf("requestedExecutionLevel = %+v, want asInvoker with uiAccess=false", level)
	}
	lower := strings.ToLower(string(contents))
	for _, forbidden := range []string{"requireadministrator", "highestavailable", "autoelevate"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("setup manifest contains forbidden elevation marker %q", forbidden)
		}
	}
}
