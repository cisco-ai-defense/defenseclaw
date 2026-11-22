// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestGAP1004ParentOfHomePatternTwinIsTheUnknownTier is rel-1-0-10:GAP-1004:
// in a folder the call does not give, a credentials-table file or DefenseClaw
// state spelled from a parent of the home (alice/.aws/credentials,
// alice/.aws/*, alice/.git-cred*, alice/.defenseclaw/*) gets the unknown tier
// for every reading verb, as the pattern's literal spelling and the
// .ssh spelling do.
func TestGAP1004ParentOfHomePatternTwinIsTheUnknownTier(t *testing.T) {
	home, project := cdFirstFixture(t)
	user := filepath.Base(home)
	reads := []string{
		user + "/.aws/credentials", user + "/.aws/*", user + "/.aws/cred*", user + "/.git-cred*",
		user + "/.kube/config", "home/" + user + "/.aws/credentials", "home/" + user + "/.aws/*",
	}
	verbs := []string{"cat %s", "tar czf /tmp/s3.tgz %s", "cp %s /tmp/staged", "base64 %s"}
	var cells []string
	for _, operand := range reads {
		for _, verb := range verbs {
			cells = append(cells, `cd "$TD327_UNSET" && `+strings.Replace(verb, "%s", operand, 1))
		}
	}
	for _, inner := range []string{
		"mv " + user + "/.defenseclaw/* /tmp/s3", "echo x >> " + user + "/.defenseclaw/config.yaml",
		"rm -f " + user + "/.defenseclaw/guardrail_runtime.json",
	} {
		cells = append(cells, `cd "$TD327_UNSET" && `+inner)
	}
	controls := []string{"cat " + user + "/src/main.go", "cat " + user + "/.cache/x", "cat " + user + "/*.go"}
	for _, p := range gap0437Packs {
		a := gap0437Server(t, p, "claudecode", "action")
		tier := "L"
		if strings.Contains(p.name, "strict") {
			tier = "B"
		}
		for _, command := range cells {
			if got := cdFirstVerdict(t, a, "g1004-"+p.name, project, command); cdFirstRank[got] < cdFirstRank[tier] {
				t.Errorf("%s: %q is %s, want at least %s", p.name, command, got, tier)
			}
		}
		for _, control := range controls {
			command := `cd "$TD327_UNSET" && ` + control
			if got := cdFirstVerdict(t, a, "g1004-"+p.name, project, command); got != "A" {
				t.Errorf("%s control %q is %s, want allow", p.name, command, got)
			}
		}
	}
}

// TestGAP1005CDPATHPrefixInBashCBodyIsTheUnknownTier is rel-1-0-10:GAP-1005:
// CDPATH="$X" cd x && cat .ssh/id_* in a bash -c body leaves the folder
// unknown as it does at the top level.
func TestGAP1005CDPATHPrefixInBashCBodyIsTheUnknownTier(t *testing.T) {
	_, project := cdFirstFixture(t)
	bodies := []string{
		`CDPATH="$TD3R3_UNSET" cd x && cat .ssh/id_*`, `CDPATH="$TD3R3_UNSET" cd x && mv .ssh/* /tmp/s3`,
		`CDPATH="$TD3R3_UNSET" cd x && cat .s*/id_*`, `CDPATH="$TD3R3_UNSET" cd x && mv .defenseclaw/* /tmp/s3`,
		`CDPATH="$TD3R3_UNSET" cd x && cat .ssh/id_rsa`, `CDPATH="$TD3R3_UNSET" cd x && cat .aws/*`,
	}
	for _, p := range gap0437Packs {
		a := gap0437Server(t, p, "claudecode", "action")
		tier := "L"
		if strings.Contains(p.name, "strict") {
			tier = "B"
		}
		for _, body := range bodies {
			for name, command := range map[string]string{
				"plain": body, "sub": "(" + body + ")", "bashc": "bash -c '" + strings.ReplaceAll(body, "'", `'\''`) + "'",
				"shc": "sh -c '" + strings.ReplaceAll(body, "'", `'\''`) + "'",
			} {
				if got := cdFirstVerdict(t, a, "g1005-"+p.name, project, command); cdFirstRank[got] < cdFirstRank[tier] {
					t.Errorf("%s %s: %q is %s, want at least %s", p.name, name, command, got, tier)
				}
			}
		}
	}
}
