// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package setuppayload

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestPayloadBindingCoversIdentityAndEveryFile(t *testing.T) {
	files := map[string]string{
		"defenseclaw.exe":        strings.Repeat("ab", 32),
		"install-enterprise.ps1": strings.Repeat("CD", 32),
	}
	commit := strings.Repeat("0123456789", 4)
	identity := PayloadIdentity{DistributionFlavor: "standalone-unsigned", Version: "1.0.3", SourceCommit: commit}
	// The layout is a build-time contract with build-setup.sh: pin it.
	want := sha256.Sum256([]byte("defenseclaw-setup-payload-binding/v2\n" +
		`flavor="standalone-unsigned"` + "\n" +
		`version="1.0.3"` + "\n" +
		`source_commit="` + commit + `"` + "\n" +
		strings.Repeat("ab", 32) + " defenseclaw.exe\n" +
		strings.Repeat("cd", 32) + " install-enterprise.ps1\n"))
	base := PayloadBinding(identity, files)
	if base != hex.EncodeToString(want[:]) {
		t.Fatalf("PayloadBinding = %s, want %x", base, want)
	}
	for name, other := range map[string]PayloadIdentity{
		"flavor":        {DistributionFlavor: "standalone", Version: identity.Version, SourceCommit: commit},
		"version":       {DistributionFlavor: identity.DistributionFlavor, Version: "9.9.9", SourceCommit: commit},
		"source commit": {DistributionFlavor: identity.DistributionFlavor, Version: identity.Version, SourceCommit: strings.Repeat("f", 40)},
		// A value cannot borrow the next line: quoting keeps the fields apart.
		"field boundary": {DistributionFlavor: identity.DistributionFlavor, Version: "1.0.3\"\nsource_commit=\"" + commit, SourceCommit: ""},
	} {
		if PayloadBinding(other, files) == base {
			t.Errorf("the binding ignores the %s", name)
		}
	}
	changed := map[string]string{"defenseclaw.exe": strings.Repeat("ab", 31) + "ac", "install-enterprise.ps1": files["install-enterprise.ps1"]}
	if PayloadBinding(identity, changed) == base {
		t.Fatal("the binding ignores a file digest")
	}
	extra := map[string]string{"defenseclaw.exe": files["defenseclaw.exe"], "install-enterprise.ps1": files["install-enterprise.ps1"], "x.exe": strings.Repeat("00", 32)}
	if PayloadBinding(identity, extra) == base {
		t.Fatal("the binding ignores an added file")
	}
	renamed := map[string]string{"defenseclaw2.exe": files["defenseclaw.exe"], "install-enterprise.ps1": files["install-enterprise.ps1"]}
	if PayloadBinding(identity, renamed) == base {
		t.Fatal("the binding ignores a file name")
	}
}
