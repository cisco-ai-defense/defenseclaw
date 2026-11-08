// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// windowsHomeCredentialFiles are the credential files the home-prefixed path
// rules name, with the rule the same name matches in a home of the usual shape.
var windowsHomeCredentialFiles = []struct{ rel, rule string }{
	{".netrc", "PATH-NETRC"},
	{".git-credentials", "PATH-GIT-CREDS"},
	{".aws/credentials", "PATH-AWS-CREDS"},
	{".kube/config", "PATH-KUBE"},
	{".docker/config.json", "PATH-DOCKER"},
	{".npmrc", "PATH-NPMRC"},
	{".pypirc", "PATH-PYPIRC"},
}

// windowsWritePathRules are the path rules the trusted dispatch reads for a
// native write of file (a Windows path) by a user whose home is home.
func windowsWritePathRules(t *testing.T, connector, home, file string) map[string]struct{} {
	t.Helper()
	// The path fact the file tool gives: the physical path in the slash
	// spelling the rules read.
	operand := actionfacts.PathFact{Access: actionfacts.PathAccessWrite, Flavor: actionfacts.PathFlavorWindows}
	path := actionfacts.LinkedPathFact(operand, file)
	input := actionfacts.Input{Tool: "Write", ActiveHome: home}
	paths, _ := trustedLegacyPathRuleMatches(
		snapshotRulePackGeneration(connector), input, input.Tool,
		actionfacts.Facts{Paths: []actionfacts.PathFact{path}},
	)
	return paths
}

// A native write of a credential file in the Windows home of the user is
// judged by the rule the same name has in a home of the usual shape, for a
// dotted, hyphenated or mixed-case account name, a home under another folder
// and a drive letter of any case. The same name in the home of another user,
// next to the file and as an example file keeps its verdict.
func TestWindowsWriteOfActiveHomeCredentialFileMatchesTheNameInAnyHome(t *testing.T) {
	const connector = "windows-home-credential-file"
	installDefaultProfileConnector(t, connector)
	homes := []struct{ home, file string }{
		{`C:\Users\alice`, `C:\Users\alice`},
		{`C:\Users\alice.smith`, `C:\Users\alice.smith`},
		{`C:\Users\dc-user`, `C:\Users\dc-user`},
		{`c:\users\alice.smith`, `C:\Users\Alice.Smith`},
		{`C:\Users\alice.smith\`, `C:\Users\alice.smith`},
		{`D:\Profiles\bob`, `D:\Profiles\bob`},
		{`C:/Users/dc-user`, `C:\Users\dc-user`},
	}
	for _, tc := range homes {
		for _, credential := range windowsHomeCredentialFiles {
			rel := strings.ReplaceAll(credential.rel, "/", `\`)
			control := windowsWritePathRules(t, connector, tc.home, `C:\Users\fixture\`+rel)
			if _, ok := control[credential.rule]; !ok {
				t.Fatalf("outside the home, %s does not match %s: %v", credential.rel, credential.rule, control)
			}
			got := windowsWritePathRules(t, connector, tc.home, tc.file+`\`+rel)
			if _, ok := got[credential.rule]; !ok {
				t.Errorf("home %q: write of %s matches %v, want %s", tc.home, credential.rel, got, credential.rule)
			}
		}
		// A name next to a credential file gets the verdict it has in a home
		// of the usual shape: none for an ordinary file, and whatever the
		// unanchored name rule gives for an example file.
		for _, benign := range []string{`\notes.txt`, `\proj\netrc.md`, `\.netrc.example`, `\.npmrc.bak`} {
			control := windowsWritePathRules(t, connector, tc.home, `C:\Users\fixture`+benign)
			got := windowsWritePathRules(t, connector, tc.home, tc.file+benign)
			if len(got) != len(control) {
				t.Errorf("home %q: write of %s matches %v, outside the home %v", tc.home, benign, got, control)
			}
			if strings.HasSuffix(benign, "notes.txt") && len(got) != 0 {
				t.Errorf("home %q: write of %s matches %v, want no rule", tc.home, benign, got)
			}
		}
	}
}

// Only the home as a whole path prefix is the home of the user: a longer
// account name, and a folder that merely holds the home name, get the verdict
// they have without a home.
func TestWindowsWriteOutsideActiveHomeKeepsItsVerdict(t *testing.T) {
	const connector = "windows-home-credential-file-neighbours"
	installDefaultProfileConnector(t, connector)
	for _, file := range []string{
		`C:\Users\alice.smith2\.netrc`,
		`C:\Users\alice.smith2\.aws\credentials`,
		`C:\ProgramData\C-Users-alice.smith\.netrc`,
		`D:\Users\alice.smith\.netrc`,
	} {
		with := windowsWritePathRules(t, connector, `C:\Users\alice.smith`, file)
		without := windowsWritePathRules(t, connector, "", file)
		if len(with) != len(without) {
			t.Errorf("%s: rules %v with a home, %v without", file, with, without)
		}
		for id := range without {
			if _, ok := with[id]; !ok {
				t.Errorf("%s: rule %s lost with a home", file, id)
			}
		}
	}
}
