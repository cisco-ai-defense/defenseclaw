// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package workspace

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// gap0978NPMRC is an image ~/.npmrc of about n bytes: comment lines, then
// tail as its last line.
func gap0978NPMRC(n int, tail string) string {
	var b strings.Builder
	for b.Len() < n {
		b.WriteString("# image npm setting, kept by the start (filler line for size)\n")
	}
	b.WriteString(tail + "\n")
	return b.String()
}

func gap0978Start(t *testing.T, npmrc string) (RegistryPlan, string, string) {
	t.Helper()
	home := t.TempDir()
	p := filepath.Join(home, NPMRCFile)
	if err := os.WriteFile(p, []byte(npmrc), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := StartRegistryFiles(t.Context(), &shellExec{home: home}, "a", s7Entries())
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return plan, string(got), p
}

// GAP-0978: an image ~/.npmrc over 64 KiB (RVS7-C: 75,620 bytes) was read
// with head -c 65536 and written back as its first 64 KiB plus the added
// lines, so its tail settings were lost. A file under the merge bound is
// merged whole.
func TestGAP0978LargeImageNPMRCMergedWhole(t *testing.T) {
	old := gap0978NPMRC(75_620, "registry=https://npm-mirror.corp.example/")
	plan, got, _ := gap0978Start(t, old)
	if !strings.HasPrefix(got, strings.TrimRight(old, "\n")+"\n") {
		t.Fatalf("the image's ~/.npmrc was not kept whole: %d bytes before, %d after; tail kept: %v",
			len(old), len(got), strings.Contains(got, "registry=https://npm-mirror.corp.example/"))
	}
	if !strings.Contains(got, registryAppendMarker+"\n//npm.corp.example/:_authToken=placeholder-not-a-secret\n") {
		t.Errorf("the placeholder line was not added after the image's lines:\n%s", got[len(old)-200:])
	}
	if hosts := plan.Hosts[RegistryNPM]; len(hosts) != 1 || hosts[0] != "npm.corp.example" {
		t.Errorf("npm hosts %v", hosts)
	}
}

// GAP-0978: the credential check saw only the first 64 KiB, so a token past
// it was merged (and cut). A credential anywhere in the file refuses.
func TestGAP0978CredentialPastTheOldCapRefuses(t *testing.T) {
	old := gap0978NPMRC(70_000, "//npm.other.example/:_authToken=npm_notaplaceholdervalue")
	plan, got, _ := gap0978Start(t, old)
	if got != old {
		t.Fatalf("an image ~/.npmrc with a credential was rewritten: %d bytes before, %d after", len(old), len(got))
	}
	if !strings.Contains(strings.Join(plan.Notes, "\n"), "//npm.other.example/:_authToken, a credential") {
		t.Errorf("no credential note: %q", plan.Notes)
	}
	if len(plan.Hosts[RegistryNPM]) != 0 {
		t.Errorf("npm hosts %v for a refused file", plan.Hosts[RegistryNPM])
	}
}

// GAP-0978: a file over the merge bound is never cut: it is kept byte for
// byte, nothing is added to it, and a Note says why.
func TestGAP0978OversizeNPMRCKeptWithNote(t *testing.T) {
	old := gap0978NPMRC(registryFileCap+4096, "registry=https://npm-mirror.corp.example/")
	plan, got, _ := gap0978Start(t, old)
	if got != old {
		t.Fatalf("an oversize image ~/.npmrc was rewritten: %d bytes before, %d after", len(old), len(got))
	}
	notes := strings.Join(plan.Notes, "\n")
	if !strings.Contains(notes, "~/.npmrc in the agent is larger than") || !strings.Contains(notes, "kept it as it is") {
		t.Errorf("no size note: %q", plan.Notes)
	}
	if len(plan.Hosts[RegistryNPM]) != 0 {
		t.Errorf("npm hosts %v for a kept file", plan.Hosts[RegistryNPM])
	}
	// The pip files are still written: one big file stops only its own merge.
	if _, ok := plan.Write[PyPIRCFile]; !ok {
		t.Errorf("~/.pypirc not written next to an oversize ~/.npmrc")
	}
}

// GAP-0978: a file exactly at the bound is merged whole (the bound is
// inclusive).
func TestGAP0978NPMRCAtTheBoundMerged(t *testing.T) {
	old := gap0978NPMRC(0, "registry=https://npm-mirror.corp.example/")
	old = strings.Repeat("#", registryFileCap-len(old)-1) + "\n" + old
	if len(old) != registryFileCap {
		t.Fatalf("fixture is %d bytes", len(old))
	}
	_, got, _ := gap0978Start(t, old)
	if !strings.HasPrefix(got, old) || !strings.Contains(got, "//npm.corp.example/:_authToken=") {
		t.Fatalf("a file at the bound was not merged whole: %d -> %d bytes", len(old), len(got))
	}
}

// GAP-0978: a merge larger than the start can write in one go is not
// written at all, so no file is ever written in part.
func TestGAP0978MergeOverTheWriteBoundNotWritten(t *testing.T) {
	old := gap0978NPMRC(registryFileCap-200, "registry=https://npm-mirror.corp.example/")
	var in []RegistryEntry
	for i := 0; i < 600; i++ {
		in = append(in, RegistryEntry{Kind: RegistryNPM, Secret: "npm", Host: fmt.Sprintf("npm%03d.corp.example", i)})
	}
	plan := PlanRegistryFiles(RegistryEntries(in), RegistryProbe{Files: map[string]string{NPMRCFile: old}})
	if c, ok := plan.Write[NPMRCFile]; ok {
		t.Fatalf("a %d-byte merge was planned (bound %d)", len(c), registryWriteMax)
	}
	if !strings.Contains(strings.Join(plan.Notes, "\n"), "would be larger than") || len(plan.Hosts[RegistryNPM]) != 0 {
		t.Errorf("notes %q hosts %v", plan.Notes, plan.Hosts[RegistryNPM])
	}
}
