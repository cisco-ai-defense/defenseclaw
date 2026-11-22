// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestXargsHandedCredentialCopyIsTheCopyGAP0997: an xargs fed fixed names
// runs its program with them, so a copy of a credentials-table file handed
// through xargs (the file as the fixed input of -I{}, or as an operand of the
// program xargs runs) is judged at least as the same copy typed alone, in all
// five tiers (rel-1-0-10:GAP-0997). The rows are credentials-table probe
// paths (credentialStoreProbes) of each rule family, in the shapes of the
// s7-cmrev probe.
func TestXargsHandedCredentialCopyIsTheCopyGAP0997(t *testing.T) {
	env := boundedLaneEnv(t)
	probes := slices.DeleteFunc(credentialStoreProbes(), func(probe string) bool {
		return !slices.Contains(gap0997Probes, probe)
	})
	if len(probes) != len(gap0997Probes) {
		t.Fatalf("credentials table probes %v, want all of %v", probes, gap0997Probes)
	}
	for _, probe := range probes {
		file := filepath.Join(env.home, filepath.FromSlash(probe))
		if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		for _, probe := range probes {
			if strings.ContainsAny(probe, " \t'\"$`\\*?[") {
				continue // the shapes below spell the file as one plain word
			}
			operand := "~/" + probe
			direct, _ := boundedDecideClaudeCode(t, api, env, boundedShellCommand("cp "+operand+" /tmp/n"))
			for _, form := range []string{
				"echo " + operand + " | xargs -I{} cp {} /tmp/n",
				"echo /tmp/n | xargs cp " + operand,
				`printf '%s\n' ` + operand + " | xargs -I{} cp {} /tmp/n",
				"true; echo " + operand + " | xargs -I{} cp {} /tmp/n",
			} {
				action, findings := boundedDecideClaudeCode(t, api, env, boundedShellCommand(form))
				if boundedParse(action) < boundedParse(direct) {
					t.Errorf("%s %s: %q is %s, the copy alone is %s; findings=%v", tier.name, probe, form, action, direct, findings)
				}
			}
		}
		// The same shapes over an ordinary project file stay allowed.
		for _, form := range []string{"echo notes.txt | xargs -I{} cp {} /tmp/n", "echo /tmp/n | xargs cp notes.txt"} {
			if action, findings := boundedDecideClaudeCode(t, api, env, boundedShellCommand(form)); action != "allow" {
				t.Errorf("%s: ordinary %q is %s, want allow; findings=%v", tier.name, form, action, findings)
			}
		}
	}
}

// gap0997Probes are the credentials-table rows the GAP-0997 test copies: an
// SSH key, cloud, database, token and developer-token files.
var gap0997Probes = []string{".ssh/id_probe", ".my.cnf", ".pgpass", ".vault-token", ".netrc", ".npmrc", ".terraform.d/credentials.tfrc.json", "etc/krb5.keytab"}
