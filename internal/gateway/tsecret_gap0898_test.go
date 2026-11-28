// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// TestGAP0898OtherAccountCredentialSpellingsFiveTiers: a read of another
// account's credentials file whose home is not under a home root (a
// mounted or alternate home the passwd lookup names) keeps the verdict of
// the plain /home/<u> read in all five tiers for every spelling that reaches
// the same file: the absolute path, ~<u>, a variable that holds the path, a
// symlink in the project, and a relative read from the home or a folder
// inside it (rel-1-0-10:GAP-0898, the GAP-0837 forms for homes the
// classifier does not place by shape). A plain file there, and a find -exec
// over a folder that is no home, stay allowed. A find -exec reader over the
// other home is not placed as a read of its files (a documented limit
// candidate, posted to FIXLEAD5).
func TestGAP0898OtherAccountCredentialSpellingsFiveTiers(t *testing.T) {
	if effectHostGOOS == "windows" {
		t.Skip("POSIX account home paths")
	}
	useDefaultEffectsLane(t)
	home := r3KnownHome(t)
	proj := filepath.Join(home, "proj")
	peer := "dcr3" + "peer"
	peerHome := filepath.Join(t.TempDir(), "mnt", "homes", peer)
	aws := filepath.Join(".aws", "credentials")
	key := filepath.Join(".ssh", "id"+"_rsa")
	for _, f := range []string{aws, key, "notes.txt"} {
		p := filepath.Join(peerHome, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	data := filepath.Join(peerHome, "..", "data")
	if err := os.MkdirAll(data, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "credentials"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(proj, "peer-link")
	if err := os.Symlink(filepath.Join(peerHome, aws), link); err != nil {
		t.Fatal(err)
	}
	pinEffectAccounts(t, map[string]string{peer: peerHome})
	cat := "c" + "at"
	shaped := "/home/" + peer + "/"
	type row struct{ id, cwd, command, ctl string }
	rows := []row{
		{"absolute aws", proj, cat + " " + filepath.Join(peerHome, aws), cat + " " + shaped + aws},
		{"absolute key", proj, cat + " " + filepath.Join(peerHome, key), cat + " " + shaped + key},
		{"tilde aws", proj, cat + " ~" + peer + "/" + aws, cat + " " + shaped + aws},
		{"tilde key", proj, cat + " ~" + peer + "/" + key, cat + " " + shaped + key},
		{"variable aws", proj, "P=" + filepath.Join(peerHome, aws) + "; " + cat + ` "$P"`, cat + " " + shaped + aws},
		{"variable key", proj, "P=" + filepath.Join(peerHome, key) + "; " + cat + ` "$P"`, cat + " " + shaped + key},
		{"symlink aws", proj, cat + " peer-link", cat + " " + shaped + aws},
		{"relative from home aws", peerHome, cat + " " + aws, cat + " " + shaped + aws},
		{"relative from folder aws", filepath.Join(peerHome, ".aws"), cat + " credentials", cat + " " + shaped + aws},
		{"relative from folder key", filepath.Join(peerHome, ".ssh"), cat + " id" + "_rsa", cat + " " + shaped + key},
		{"fp: plain file", proj, cat + " " + filepath.Join(peerHome, "notes.txt"), ""},
		{"fp: find exec of a plain folder", proj, "find " + data + " -name credentials -exec " + cat + ` {} \;`, ""},
	}
	probe := os.Getenv("DET111_R3_PROBE") != ""
	for _, tier := range boundedTestTiers {
		for _, route := range r3KnownRoutes() {
			api := gap0589TierAPI(t, route.connector, tier.posture, tier.managed, tier.tier)
			for _, r := range rows {
				where := tier.name + " " + route.connector + " " + r.id
				useEffectsRulesMode(t, "off")
				off, _ := route.decide(api, t.Context(), r.cwd, r.command)
				useDefaultEffectsLane(t)
				got, findings := route.decide(api, t.Context(), r.cwd, r.command)
				g := boundedParse(got.action)
				if r.ctl == "" {
					if probe {
						t.Logf("ROW\t%s\t%s/%s\tctl -", where, got.action, got.severity)
					}
					if g != bounded.Allow {
						t.Errorf("%s: %s, want allow (false-positive guard); findings %v", where, got.action, findings)
					}
					continue
				}
				ctl, _ := route.decide(api, t.Context(), proj, r.ctl)
				c := boundedParse(ctl.action)
				if probe {
					t.Logf("ROW\t%s\t%s/%s\tctl %s/%s\toff %s/%s", where, got.action, got.severity, ctl.action, ctl.severity, off.action, off.severity)
				}
				if c == bounded.Allow && tier.name == "default" {
					t.Fatalf("%s: control allows, the control is void", where)
				}
				if bounded.Stricter(g, boundedParse(off.action)) != g {
					t.Errorf("%s: %s is below its lane-off (1.0.10) verdict %s", where, got.action, off.action)
				}
				// The action of the plain read, and its severity where it alerts
				// (a strict block of a key keeps its own severity, as the
				// GAP-0899 mounted-home rows do).
				if bounded.Stricter(g, c) != g || c == bounded.Alert && r3SeverityRank[got.severity] < r3SeverityRank[ctl.severity] {
					t.Errorf("%s: %s/%s, want at least the plain /home/<u> read %s/%s; findings %v",
						where, got.action, got.severity, ctl.action, ctl.severity, strings.Join(findings, "; "))
				}
			}
		}
	}
}
