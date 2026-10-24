// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package winpath

import "testing"

func TestEnterpriseRootsForProfiles(t *testing.T) {
	secureClient, err := EnterpriseRootsFor("secure_client", `C:\Program Files\`, `C:\ProgramData`)
	if err != nil {
		t.Fatal(err)
	}
	want := EnterpriseRoots{
		Profile:                  "secure_client",
		InstallRoot:              `C:\Program Files\Cisco\Cisco Secure Client\DefenseClaw`,
		StateRoot:                `C:\ProgramData\Cisco\Cisco Secure Client\DefenseClaw`,
		CertificationInstallBase: `C:\Program Files\Cisco\Cisco Secure Client\DefenseClaw-Cert`,
		CertificationStateBase:   `C:\ProgramData\Cisco\Cisco Secure Client\DefenseClaw-Cert`,
		ManagedIPCDir:            `C:\Program Files\Cisco\Cisco Secure Client\DefenseClaw\ipc`,
		LifecycleDir:             `C:\ProgramData\Cisco\Cisco Secure Client\DefenseClaw-Lifecycle`,
		MetadataPath:             `C:\ProgramData\Cisco\Cisco Secure Client\DefenseClaw\install\deployment.json`,
		PowerShellProfile:        "SecureClient",
	}
	if secureClient != want {
		t.Fatalf("secure client roots:\n got %+v\nwant %+v", secureClient, want)
	}
	standalone, err := EnterpriseRootsFor("standalone", `D:\Program Files`, `D:\ProgramData`)
	if err != nil {
		t.Fatal(err)
	}
	want = EnterpriseRoots{
		Profile:                  "standalone",
		InstallRoot:              `D:\Program Files\Cisco\DefenseClaw`,
		StateRoot:                `D:\ProgramData\Cisco\DefenseClaw`,
		CertificationInstallBase: `D:\Program Files\Cisco\DefenseClaw-Cert`,
		CertificationStateBase:   `D:\ProgramData\Cisco\DefenseClaw-Cert`,
		ManagedIPCDir:            `D:\Program Files\Cisco\DefenseClaw\ipc`,
		LifecycleDir:             `D:\ProgramData\Cisco\DefenseClaw-Lifecycle`,
		MetadataPath:             `D:\ProgramData\Cisco\DefenseClaw\install\deployment.json`,
		PowerShellProfile:        "Standalone",
	}
	if standalone != want {
		t.Fatalf("standalone roots:\n got %+v\nwant %+v", standalone, want)
	}
	for _, bad := range [][3]string{
		{"other", `C:\Program Files`, `C:\ProgramData`},
		{"standalone", `Program Files`, `C:\ProgramData`},
		{"standalone", `C:/Program Files`, `C:\ProgramData`},
		{"standalone", `C:\Program Files`, ``},
	} {
		if _, err := EnterpriseRootsFor(bad[0], bad[1], bad[2]); err == nil {
			t.Fatalf("EnterpriseRootsFor(%q, %q, %q) accepted invalid input", bad[0], bad[1], bad[2])
		}
	}
}

func TestValidateEnterpriseInstallRoot(t *testing.T) {
	roots, err := EnterpriseRootsFor("standalone", `C:\Program Files`, `C:\ProgramData`)
	if err != nil {
		t.Fatal(err)
	}
	for _, accepted := range []string{
		`C:\Program Files\Cisco\DefenseClaw`,
		`c:\program files\cisco\defenseclaw\`,
		`C:\Program Files\Cisco\DefenseClaw-Cert\0a1b2c3d4e`,
	} {
		if err := ValidateEnterpriseInstallRoot(roots, accepted); err != nil {
			t.Fatalf("%s: %v", accepted, err)
		}
	}
	for _, rejected := range []string{
		`C:\Program Files\Cisco\Cisco Secure Client\DefenseClaw`,
		`C:\Program Files\Cisco`,
		`C:\Program Files\Cisco\DefenseClaw-Cert`,
		`C:\Program Files\Cisco\DefenseClaw-Cert\0A1B2C3D4E`,
		`C:\Program Files\Cisco\DefenseClaw-Cert\0a1b2c3d4`,
		`C:\Program Files\Cisco\DefenseClaw-Cert\0a1b2c3d4e\x`,
		`C:\Users\Public\DefenseClaw`,
	} {
		if err := ValidateEnterpriseInstallRoot(roots, rejected); err == nil {
			t.Fatalf("%s was accepted", rejected)
		}
	}
}

func TestClassifyEnterpriseMetadata(t *testing.T) {
	for _, tc := range []struct {
		body    string
		state   EnterpriseDeploymentState
		version string
	}{
		{`{"installed":true,"product_version":"1.2.3"}`, EnterpriseDeploymentInstalled, "1.2.3"},
		{"\ufeff" + `{"installed":false}`, EnterpriseDeploymentTombstone, ""},
		{`{"schema_version":1}`, EnterpriseDeploymentInstalled, ""},
		{`{"installed":"yes"}`, EnterpriseDeploymentUnknown, ""},
		{`not json`, EnterpriseDeploymentUnknown, ""},
	} {
		state, version := classifyEnterpriseMetadata([]byte(tc.body))
		if state != tc.state || version != tc.version {
			t.Fatalf("%q: got (%s, %q), want (%s, %q)", tc.body, state, version, tc.state, tc.version)
		}
	}
}

func TestEnterpriseMetadataTrustMode(t *testing.T) {
	for body, want := range map[string]string{
		`{"installed":true,"trust_mode":"hash_pinned"}`:             "hash_pinned",
		"\ufeff" + `{"installed":false,"trust_mode":"Hash_Pinned"}`: "hash_pinned",
		`{"installed":true,"trust_mode":"authenticode"}`:            "authenticode",
		`{"installed":true}`: "",
		`not json`:           "",
	} {
		if got := enterpriseMetadataTrustMode([]byte(body)); got != want {
			t.Fatalf("%q: trust mode %q, want %q", body, got, want)
		}
	}
}
