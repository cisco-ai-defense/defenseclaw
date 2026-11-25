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
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

const (
	// skillManifestPartBytes is the most SKILL.md text one record carries: the
	// most the redaction detectors scan in one field (a longer one is replaced
	// by a token and the record is rejected). A longer file goes in parts, one
	// part a publish.
	skillManifestPartBytes = redaction.MaxScannedStringBytes
	// skillManifestCycleBytes is the most SKILL.md text one publish carries
	// (its first part always goes), so the skills of a new install reach AI
	// Defense over a few scans instead of in one burst.
	skillManifestCycleBytes = 2 << 20
	// maxSkillManifestParts is the most parts a file goes in (the schema
	// bound of manifest_parts). A file that needs more sends its hash only.
	maxSkillManifestParts = 128
)

// managedSkillManifest tracks local submission, not durable cloud receipt.
type managedSkillManifest struct {
	Sent  int `json:"sent"`
	Parts int `json:"parts"`
}

// SetSkillManifestReader sets how a publish reads a SKILL.md by its hash.
func (state *managedInventoryPublishState) SetSkillManifestReader(read func(hash string) ([]byte, bool)) {
	if state == nil {
		return
	}
	state.mu.Lock()
	state.readSkillManifest = read
	state.receiptEpoch++
	state.mu.Unlock()
}

// attachSkillManifests adds to skills the SKILL.md text AI Defense does not
// have yet: the next part of each file, on one record however many agents or
// homes have that file (the others share its manifest_hash), and at most
// skillManifestCycleBytes a publish. Progress is kept per file and, like the
// skill state, only when the collection publishes.
func (cycle *managedInventoryPublishCycle) attachSkillManifests(components []endpointInventoryComponent) {
	if cycle == nil || cycle.state == nil {
		return
	}
	cycle.state.mu.Lock()
	read, prior := cycle.state.readSkillManifest, cycle.state.file.SkillManifests
	cycle.state.mu.Unlock()
	if read == nil {
		return
	}
	next := map[string]managedSkillManifest{}
	byHash := map[string]int{}
	for i := range components {
		c := &components[i]
		hash := c.skillManifestHash
		if hash == "" || c.skillState == skillStateRemoved {
			continue
		}
		if _, ok := byHash[hash]; !ok {
			byHash[hash] = i
		}
		if progress, ok := prior[hash]; ok {
			next[hash] = progress
		}
	}
	hashes := make([]string, 0, len(byHash))
	for hash := range byHash {
		hashes = append(hashes, hash)
	}
	sort.Strings(hashes)
	cycle.state.mu.Lock()
	cursor := cycle.state.file.ManifestBodyCursor
	cycle.state.mu.Unlock()
	start := sort.SearchStrings(hashes, cursor)
	if start < len(hashes) && hashes[start] == cursor {
		start++
	}
	if start >= len(hashes) {
		start = 0
	}
	// New initial parts get the aggregate budget before already-submitted repairs.
	// Rotate within each class so neither large installs nor broken hashes starve.
	ordered := make([]string, 0, len(hashes))
	for _, repair := range []bool{false, true} {
		for step := 0; step < len(hashes); step++ {
			hash := hashes[(start+step)%len(hashes)]
			progress, known := prior[hash]
			if (known && progress.Sent >= progress.Parts) == repair {
				ordered = append(ordered, hash)
			}
		}
	}
	budget := skillManifestCycleBytes
	for _, hash := range ordered {
		if budget <= 0 {
			break
		}
		c := &components[byHash[hash]]
		progress, known := prior[hash]
		receipt := cycle.receipts[hash]
		if receipt.State == "complete" {
			next[hash] = managedSkillManifest{Sent: receipt.Parts, Parts: receipt.Parts}
			continue
		}
		if receipt.State == "conflict" || receipt.LastScan != "" && receipt.LastScan == cycle.scanID {
			continue
		}
		selected := progress.Sent + 1
		if known && progress.Sent >= progress.Parts {
			selected = cycle.missingManifestPart(hash, progress, receipt)
			if selected == 0 {
				continue
			}
		}
		data, ok := read(hash)
		if !ok {
			continue
		}
		parts, ok := splitSkillManifest(data)
		if !ok || len(parts) > maxSkillManifestParts {
			next[hash] = managedSkillManifest{}
			continue
		}
		if selected > len(parts) || selected < 1 {
			next[hash] = managedSkillManifest{Sent: len(parts), Parts: len(parts)}
			continue
		}
		if receipt.Parts > 0 && receipt.Parts != len(parts) {
			receipt.State = "conflict"
			cycle.receipts[hash] = receipt
			cycle.receiptDirty = true
			continue
		}
		part := parts[selected-1]
		if len(part) > budget && budget < skillManifestCycleBytes {
			continue
		}
		budget -= len(part)
		c.skillManifest, c.skillManifestPart, c.skillManifestParts = part, selected, len(parts)
		if selected > progress.Sent {
			progress.Sent = selected
		}
		progress.Parts = len(parts)
		next[hash] = progress
		cycle.bodyCursor = hash
	}
	cycle.manifests = next
}

// splitSkillManifest cuts the text of data into parts of at most
// skillManifestPartBytes for the redaction detectors, which see one part at a
// time: a part ends at a line and never inside a PEM block, so each secret
// is scanned whole. It reports false for a file a part cannot hold that way
// (a line or a PEM block longer than a part), which sends only its hash.
func splitSkillManifest(data []byte) ([]string, bool) {
	text := strings.ToValidUTF8(string(data), "\ufffd")
	var parts []string
	for len(text) > skillManifestPartBytes {
		n := strings.LastIndexByte(text[:skillManifestPartBytes], '\n') + 1
		if begin := strings.LastIndex(text[:n], "-----BEGIN "); begin >= 0 && !strings.Contains(text[begin:n], "-----END ") {
			n = strings.LastIndexByte(text[:begin], '\n') + 1
		}
		if n == 0 {
			return nil, false
		}
		parts, text = append(parts, text[:n]), text[n:]
	}
	if text != "" {
		parts = append(parts, text)
	}
	return parts, true
}

// hasSkillManifest reports SKILL.md text to send, which publishes the
// collection even when no skill changed.
func hasSkillManifest(components []endpointInventoryComponent) bool {
	for _, component := range components {
		if component.skillManifest != "" {
			return true
		}
	}
	return false
}
