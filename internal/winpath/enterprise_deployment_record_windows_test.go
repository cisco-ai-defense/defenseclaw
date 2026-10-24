// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package winpath

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// InspectEnterpriseDeploymentAt classifies what it finds at a record
// path. A standard user can create either shape a record path can take
// under the default ProgramData ACL, a file or a folder; the file is
// classified like any record, and the folder is an error the caller must
// judge (internal/cli treats a record an administrator did not write as
// absent). A record without a profile or installed field is what every
// Secure Client deployment wrote before uninstall tombstones and the
// standalone profile existed, and must stay installed.
func TestInspectEnterpriseDeploymentAtClassifiesRecordShapes(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, body []byte) string {
		t.Helper()
		path := filepath.Join(dir, name, "deployment.json")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	for _, tc := range []struct {
		name    string
		path    string
		state   EnterpriseDeploymentState
		version string
	}{
		{name: "absent", path: filepath.Join(dir, "absent", "deployment.json"), state: EnterpriseDeploymentAbsent},
		{name: "historical secure client record", path: write("historical", []byte(`{"schema_version":1,"deployment_mode":"managed_enterprise","gateway_service":"DefenseClawGateway"}`)), state: EnterpriseDeploymentInstalled},
		{name: "secure client record", path: write("secure-client", []byte(`{"schema_version":1,"installed":true}`)), state: EnterpriseDeploymentInstalled},
		{name: "record with a byte order mark", path: write("bom", []byte("\xef\xbb\xbf{\"installed\":true,\"product_version\":\"1.2.3\"}")), state: EnterpriseDeploymentInstalled, version: "1.2.3"},
		{name: "tombstone", path: write("tombstone", []byte(`{"installed":false,"product_version":"1.2.3"}`)), state: EnterpriseDeploymentTombstone, version: "1.2.3"},
		{name: "planted empty object", path: write("planted", []byte(`{}`)), state: EnterpriseDeploymentInstalled},
		{name: "damaged record", path: write("damaged", []byte(`{"installed":`)), state: EnterpriseDeploymentUnknown},
		{name: "oversized record", path: write("oversized", bytes.Repeat([]byte(" "), enterpriseMetadataLimit+1)), state: EnterpriseDeploymentUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deployment, err := InspectEnterpriseDeploymentAt("standalone", tc.path)
			if err != nil {
				t.Fatalf("InspectEnterpriseDeploymentAt: %v", err)
			}
			if deployment.State != tc.state || deployment.ProductVersion != tc.version {
				t.Fatalf("deployment %+v, want state %q version %q", deployment, tc.state, tc.version)
			}
			if deployment.Profile != "standalone" || deployment.MetadataPath != tc.path || deployment.Untrusted != "" {
				t.Fatalf("deployment %+v does not describe the inspected record", deployment)
			}
		})
	}

	folder := filepath.Join(dir, "folder", "deployment.json")
	if err := os.MkdirAll(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectEnterpriseDeploymentAt("standalone", folder); err == nil ||
		!strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("a folder at the record path: err = %v, want a not-a-regular-file error", err)
	}
}
