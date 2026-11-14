// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// betweenLimitsPatchCall is the typed Codex apply_patch call that adds target
// with the given text lines, each as a line of the file.
func betweenLimitsPatchCall(target string, lines ...string) nativeWriteCall {
	return nativeWriteCall{"codex", "apply_patch", func(string) map[string]any {
		var patch strings.Builder
		patch.WriteString("*** Begin Patch\n*** Add File: " + target + "\n")
		for _, line := range lines {
			patch.WriteString("+" + line + "\n")
		}
		patch.WriteString("*** End Patch\n")
		return map[string]any{"command": patch.String()}
	}}
}

// TestOverLimitPatchFillerLineKeepsContentRuleVerdict pins that a typed
// apply_patch envelope with a filler line of white space on a line of its own
// keeps the verdict of the same envelope without it, at every size: the
// loader-preload, profile.d, Docker and PAM content proofs read the protected
// line below 64 KiB, between 64 KiB and the argument limit, and above it,
// for the file and for a link to it. The same envelope with benign text stays
// allowed.
func TestOverLimitPatchFillerLineKeepsContentRuleVerdict(t *testing.T) {
	home, project := hermesPatchHome(t)
	link := filepath.Join(project, "lnk-preload")
	if err := os.Symlink("/etc/ld.so.preload", link); err != nil {
		t.Fatal(err)
	}
	usedSize, usedLayout, usedTwin := map[int]bool{}, map[[2]int]bool{}, map[[2]int]bool{}
	var subtests []overLimitSubtest
	for ci, c := range []struct {
		name, target, attack, benign, rule string
	}{
		{"ld.so.preload", "/etc/ld.so.preload", "/usr/local/lib/liblogger.so", "# no libraries are preloaded", "persistence.global_ld_preload_install"},
		{"link to ld.so.preload", link, "/usr/local/lib/liblogger.so", "# no libraries are preloaded", "persistence.global_ld_preload_install"},
		{"profile.d", "/etc/profile.d/logger.sh", "export LD_PRELOAD=/usr/local/lib/liblogger.so", "export CLICOLOR=1", "persistence.global_ld_preload_install"},
		{"daemon.json", "/etc/docker/daemon.json", overLimitDockerHTTPRegistry, `{"log-level":"warn"}`, dockerInsecureHTTPRegistryRuleID},
		{"pam.d", "/etc/pam.d/sshd", "auth sufficient pam_permit.so", "auth required pam_unix.so", "tamper.pam_permit_authentication_bypass"},
	} {
		// The owner's test budget: no cross product of target x filler size x
		// layout. Each target is judged at the sizes below 64 KiB (0 and
		// 65536), at one size between 64 KiB and the argument limit (100000,
		// 200000 or 262000 in turn) and at one above it (270000 or 300000 in
		// turn), each in one layout, turning with the target and the size;
		// the benign text and the attack in an ordinary file are judged at
		// the target's two large sizes, one each, swapping from target to
		// target. So every target is judged in every region, every size is
		// judged, every layout is judged in every region, and both twins are
		// judged in both large regions; the check at the end shows it.
		between, above := []int{100000, 200000, 262000}, []int{270000, 300000}
		fillers := []int{0, 65536, between[ci%len(between)], above[ci%len(above)]}
		for si, filler := range fillers {
			layout := fillerLayouts[(ci+si)%len(fillerLayouts)]
			usedSize[filler] = true
			usedLayout[[2]int{fillerRegion(filler), (ci + si) % len(fillerLayouts)}] = true
			lines := func(text string) []string {
				pad := strings.Repeat(" ", filler)
				switch layout {
				case "filler, text":
					return []string{pad, text}
				case "text, filler":
					return []string{text, pad}
				}
				// A JSON document takes no comment line.
				if strings.HasSuffix(c.target, ".json") {
					return []string{"", pad, text}
				}
				return []string{"# c", pad, text}
			}
			benignAt, ordinaryAt := fillers[2], fillers[3]
			if ci%2 == 1 {
				benignAt, ordinaryAt = ordinaryAt, benignAt
			}
			if filler == benignAt {
				usedTwin[[2]int{0, fillerRegion(filler)}] = true
			}
			if filler == ordinaryAt {
				usedTwin[[2]int{1, fillerRegion(filler)}] = true
			}
			calls := map[string]nativeWriteCall{"attack": betweenLimitsPatchCall(c.target, lines(c.attack)...)}
			if filler == benignAt {
				calls["benign"] = betweenLimitsPatchCall(c.target, lines(c.benign)...)
			}
			if filler == ordinaryAt {
				calls["ordinary"] = betweenLimitsPatchCall(filepath.Join(project, "notes.txt"), lines(c.attack)...)
			}
			subtests = append(subtests, overLimitSubtest{name: fmt.Sprintf("%s/filler %d/%s", c.name, filler, layout), calls: calls,
				check: func(t *testing.T, got map[string]string) {
					if overLimitHookAction(t, got["attack"]) != "block" || !strings.Contains(got["attack"], c.rule) {
						t.Fatalf("not blocked by %s: %.600s", c.rule, got["attack"])
					}
					if strings.Contains(got["attack"], overLimitElidedContentTitle) {
						t.Fatalf("padding takes the conservative finding, not the rule verdict: %.600s", got["attack"])
					}
					if benign, ok := got["benign"]; ok && overLimitHookAction(t, benign) == "block" {
						t.Fatalf("benign text of %s blocked: %.600s", c.target, benign)
					}
					if ordinary, ok := got["ordinary"]; ok && overLimitHookAction(t, ordinary) == "block" {
						t.Fatalf("the same text in an ordinary file blocked: %.600s", ordinary)
					}
				}})
		}
	}
	runOverLimitSubtests(t, home, project, subtests)
	for _, size := range []int{0, 65536, 100000, 200000, 262000, 270000, 300000} {
		if !usedSize[size] {
			t.Errorf("filler size %d never judged", size)
		}
	}
	for region := range 3 {
		for layout := range fillerLayouts {
			if !usedLayout[[2]int{region, layout}] {
				t.Errorf("layout %q never judged in size region %d", fillerLayouts[layout], region)
			}
		}
	}
	for twin := range 2 {
		for region := 1; region < 3; region++ {
			if !usedTwin[[2]int{twin, region}] {
				t.Errorf("twin %d never judged in size region %d", twin, region)
			}
		}
	}
}

// fillerLayouts are the places of the filler line in the patched file.
var fillerLayouts = []string{"lead, filler, text", "filler, text", "text, filler"}

// fillerRegion is 0 below 64 KiB, 1 between 64 KiB and the argument limit
// (the sizes of TestOverLimitPatchFillerLineKeepsContentRuleVerdict) and 2
// above it.
func fillerRegion(filler int) int {
	switch {
	case filler < 65536:
		return 0
	case filler <= 262000:
		return 1
	}
	return 2
}

// TestOverLimitPatchTextBetweenLimitsFailsClosedForItsTargetOnly pins that a
// patch file whose text is over 64 KiB with no padding to remove, in an
// envelope within the argument limit, takes the conservative finding when a
// content rule decides on its file, as it does past the argument limit, and
// that no ordinary file, and no other file of the patch, does.
func TestOverLimitPatchTextBetweenLimitsFailsClosedForItsTargetOnly(t *testing.T) {
	home, project := hermesPatchHome(t)
	opaque := strings.Repeat("x", 100000)
	ordinary := filepath.Join(project, "big.txt")
	link := filepath.Join(project, "lnk-preload")
	if err := os.Symlink("/etc/ld.so.preload", link); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name    string
		changes [][2]string
		block   bool
		rule    string
	}{
		{"opaque ld.so.preload", [][2]string{{"/etc/ld.so.preload", opaque}}, true, "persistence.global_ld_preload_install"},
		{"opaque link to ld.so.preload", [][2]string{{link, opaque}}, true, "persistence.global_ld_preload_install"},
		{"opaque daemon.json", [][2]string{{"/etc/docker/daemon.json", opaque}}, true, dockerInsecureHTTPRegistryRuleID},
		{"opaque pam.d", [][2]string{{"/etc/pam.d/sshd", opaque}}, true, "tamper.pam_permit_authentication_bypass"},
		{"opaque ordinary file", [][2]string{{ordinary, opaque}}, false, ""},
		{"opaque ordinary beside benign daemon.json", [][2]string{{ordinary, opaque}, {"/etc/docker/daemon.json", `{"log-level":"warn"}`}}, false, ""},
		{"opaque ordinary beside attack daemon.json", [][2]string{{ordinary, opaque}, {"/etc/docker/daemon.json", overLimitDockerHTTPRegistry}}, true, dockerInsecureHTTPRegistryRuleID},
		{"opaque daemon.json beside ordinary", [][2]string{{"/etc/docker/daemon.json", opaque}, {filepath.Join(project, "a.txt"), "ok"}}, true, dockerInsecureHTTPRegistryRuleID},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := overLimitPatchVerdict(t, home, project, overLimitPatchCall(c.changes, 0, false))
			if (overLimitHookAction(t, got) == "block") != c.block {
				t.Fatalf("block = %t, want %t: %.600s", !c.block, c.block, got)
			}
			if c.block && !strings.Contains(got, c.rule) {
				t.Fatalf("block does not name %s: %.600s", c.rule, got)
			}
			if !c.block && strings.Contains(got, overLimitElidedContentTitle) {
				t.Fatalf("conservative finding on a call that needs none: %.600s", got)
			}
		})
	}
}

// overLimitSubtest is one subtest of the over-limit patch tests: its hook
// calls by role, and the check of their verdicts.
type overLimitSubtest struct {
	name  string
	calls map[string]nativeWriteCall
	check func(t *testing.T, got map[string]string)
}

// runOverLimitSubtests judges the calls of every subtest on every CPU (each
// call builds its own gateway and only reads the fixture, as concurrent
// hooks do; their cost follows their bytes), then runs the subtests in
// order on the verdicts.
func runOverLimitSubtests(t *testing.T, home, project string, subtests []overLimitSubtest) {
	t.Helper()
	type job struct {
		subtest int
		role    string
	}
	var jobs []job
	for i, subtest := range subtests {
		for _, role := range slices.Sorted(maps.Keys(subtest.calls)) {
			jobs = append(jobs, job{i, role})
		}
	}
	verdicts := make([]string, len(jobs))
	forEachOnEveryCPU(len(jobs), func(i int) {
		verdicts[i] = overLimitPatchVerdict(t, home, project, subtests[jobs[i].subtest].calls[jobs[i].role])
	})
	got := make([]map[string]string, len(subtests))
	for i, j := range jobs {
		if got[j.subtest] == nil {
			got[j.subtest] = map[string]string{}
		}
		got[j.subtest][j.role] = verdicts[i]
	}
	for i, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) { subtest.check(t, got[i]) })
	}
}
