// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// manifestCycle runs one skill publish with SKILL.md text attached and
// returns the rows that carried text.
func manifestCycle(t *testing.T, state *managedInventoryPublishState, at time.Time, published bool,
	skills ...endpointInventoryComponent,
) map[string]endpointInventoryComponent {
	t.Helper()
	cycle := state.beginCycle("scan-"+at.Format(time.RFC3339), at, true)
	rows := cycle.trackSkills(append([]endpointInventoryComponent(nil), skills...), true)
	cycle.attachSkillManifests(rows)
	carried := map[string]endpointInventoryComponent{}
	for _, row := range rows {
		if row.skillManifest != "" {
			carried[row.id] = row
		}
	}
	if published {
		cycle.recordPublished(endpointSkillInventorySource, at.String(), len(rows))
	}
	cycle.commit()
	return carried
}

func manifestSkill(id, manifest string) endpointInventoryComponent {
	row := stateSkill(id, "h-"+manifest)
	row.skillManifestHash = manifest
	return row
}

func TestSkillManifestSentOncePerFileUntilPublished(t *testing.T) {
	state := managedPublishTestState(t)
	files := map[string][]byte{"m1": []byte("---\nname: pdf\n---\nUse it.\n"), "m2": []byte("second")}
	reads := 0
	state.SetSkillManifestReader(func(hash string) ([]byte, bool) {
		reads++
		data, ok := files[hash]
		return data, ok
	})
	at := time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)
	// One file in a folder two agents read goes on one record.
	skills := []endpointInventoryComponent{manifestSkill("a", "m1"), manifestSkill("b", "m1"), manifestSkill("c", "m2")}

	got := manifestCycle(t, state, at, false, skills...)
	if len(got) != 2 || got["a"].skillManifest != string(files["m1"]) || got["c"].skillManifestParts != 1 {
		t.Fatalf("first cycle = %+v", got)
	}
	// Not published: sent again. Published: nothing more, no file read.
	if got = manifestCycle(t, state, at.Add(time.Hour), true, skills...); len(got) != 2 {
		t.Fatalf("after a failed publish = %+v", got)
	}
	reads = 0
	if got = manifestCycle(t, state, at.Add(2*time.Hour), true, skills...); len(got) != 0 || reads != 0 {
		t.Fatalf("after publish = %+v, %d reads", got, reads)
	}
	// A new version is sent; a file changed since the scan is not.
	files["m3"] = []byte("v2")
	skills[2] = manifestSkill("c", "m3")
	skills = append(skills, manifestSkill("d", "gone"))
	if got = manifestCycle(t, state, at.Add(3*time.Hour), true, skills...); len(got) != 1 || got["c"].skillManifest != "v2" {
		t.Fatalf("changed file = %+v", got)
	}
	// Removed rows send no text, and only files a skill still has are kept.
	if got = manifestCycle(t, state, at.Add(4*time.Hour), true, manifestSkill("e", "m3")); len(got) != 0 {
		t.Fatalf("removed rows = %+v", got)
	}
	if len(state.file.SkillManifests) != 1 || state.file.SkillManifests["m3"] != (managedSkillManifest{Sent: 1, Parts: 1}) {
		t.Fatalf("kept progress = %+v", state.file.SkillManifests)
	}
}

func TestSkillManifestNotReadPastTheBudget(t *testing.T) {
	state := managedPublishTestState(t)
	files := map[string][]byte{"b2": []byte(strings.Repeat("y\n", 100<<10))}
	var skills []endpointInventoryComponent
	for i := range 8 {
		hash := fmt.Sprintf("a%d", i)
		files[hash] = []byte(strings.Repeat("x\n", 125<<10))
		skills = append(skills, manifestSkill(hash, hash))
	}
	skills = append(skills, manifestSkill("b", "b2"))
	for i := range skills {
		skills[i].skillManifestSize = int64(len(files[skills[i].skillManifestHash]))
	}
	reads := map[string]int{}
	state.SetSkillManifestReader(func(hash string) ([]byte, bool) {
		reads[hash]++
		data, ok := files[hash]
		return data, ok
	})
	at := time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)
	// Eight 250 KiB files leave 48 KiB of the budget: b2 (200 KiB) is not read.
	got := manifestCycle(t, state, at, true, skills...)
	if len(got) != 8 || reads["b2"] != 0 {
		t.Fatalf("first cycle sent %d, b2 read %d times", len(got), reads["b2"])
	}
	// The next cycle starts with b2.
	got = manifestCycle(t, state, at.Add(time.Hour), true, skills...)
	if len(got) != 1 || got["b"].skillManifest != string(files["b2"]) || reads["b2"] != 1 {
		t.Fatalf("second cycle sent %d, b2 read %d times", len(got), reads["b2"])
	}
}

func TestSkillManifestLargeFilesGoInPartsWithinTheBudget(t *testing.T) {
	state := managedPublishTestState(t)
	big := strings.Repeat(strings.Repeat("é", 1000)+"\n", 140) // two parts
	files := map[string][]byte{"big": []byte(big)}
	skills := []endpointInventoryComponent{manifestSkill("big", "big")}
	for i := range 12 {
		name := fmt.Sprintf("s%02d", i)
		files[name] = []byte(strings.Repeat("x", 200<<10))
		skills = append(skills, manifestSkill(name, name))
	}
	state.SetSkillManifestReader(func(hash string) ([]byte, bool) { data, ok := files[hash]; return data, ok })
	at := time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)
	var bigParts []string
	sent := 0
	for i := range 4 {
		bytes := 0
		for id, row := range manifestCycle(t, state, at.Add(time.Duration(i)*time.Hour), true, skills...) {
			bytes += len(row.skillManifest)
			sent++
			if id == "big" {
				bigParts = append(bigParts, row.skillManifest)
			}
		}
		if bytes > skillManifestCycleBytes {
			t.Fatalf("cycle %d carried %d bytes", i, bytes)
		}
	}
	if len(bigParts) != 2 || strings.Join(bigParts, "") != big || sent != 14 {
		t.Fatalf("big parts %d, rejoined %v, %d sent", len(bigParts), strings.Join(bigParts, "") == big, sent)
	}
	// A part ends at a line and keeps a PEM block whole, so the redaction
	// detectors see each secret in one part; the parts are valid text.
	block := "-----BEGIN CERTIFICATE-----\n" + strings.Repeat("QUJD\n", 200) + "-----END CERTIFICATE-----\n"
	filler := strings.Repeat("y", 99) + "\n"
	pem := strings.Repeat(filler, skillManifestPartBytes/100-5) + block + "\xff" + filler
	parts, ok := splitSkillManifest([]byte(pem))
	if !ok || len(parts) != 2 || !strings.HasPrefix(parts[1], "-----BEGIN") || !strings.HasSuffix(parts[0], "\n") ||
		strings.Join(parts, "") != strings.ToValidUTF8(pem, "\ufffd") || !utf8.ValidString(parts[1]) {
		t.Fatalf("pem parts: ok %v, %d parts", ok, len(parts))
	}
	// A line longer than a part sends only the hash.
	if _, ok := splitSkillManifest([]byte(strings.Repeat("z", skillManifestPartBytes+1))); ok {
		t.Fatal("a line longer than a part was split")
	}
	// Invalid bytes grow when made text; a file over the part bound sends no
	// text and is not retried.
	huge := []byte(strings.Repeat("\xffa\n", maxSkillManifestParts*skillManifestPartBytes/5+1))
	state = managedPublishTestState(t)
	state.SetSkillManifestReader(func(string) ([]byte, bool) { return huge, true })
	for i := range 2 {
		if rows := manifestCycle(t, state, at.Add(time.Duration(i)*time.Hour), true, manifestSkill("huge", "huge")); len(rows) != 0 {
			t.Fatalf("cycle %d sent the text of a file over %d parts", i, maxSkillManifestParts)
		}
	}
}
