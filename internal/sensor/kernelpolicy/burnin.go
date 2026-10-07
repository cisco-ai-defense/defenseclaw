// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package kernelpolicy

import (
	"errors"
	"os"
	"sort"
	"strconv"
	"time"
)

// maxCounted bounds the paths and binaries kept per control, so a noisy
// user cannot grow the record.
const maxCounted = 8

// Counted is a value and how often it was seen.
type Counted struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

// HitStats summarizes the opens of one control.
type HitStats struct {
	Count    int       `json:"count"`
	First    time.Time `json:"first"`
	Last     time.Time `json:"last"`
	Paths    []Counted `json:"paths,omitempty"`
	Binaries []Counted `json:"binaries,omitempty"`
}

// UIDRecord is one enrolled user's burn-in: evidence that the controls stay
// quiet for the agents of that user, counted by the helper from its own event
// tally and never from Tetragon's counters (they reset on every rename and
// restart).
type UIDRecord struct {
	Connectors       []string `json:"connectors"`
	ConnectorsDigest string   `json:"connectors_digest"`
	// CoveredSeconds is covered agent time since the last would-block hit or
	// reset. Covered time accrues per minute only while the event stream is
	// connected and lossless, the user's policy is enabled and one of the
	// user's roots is alive and anchored. It is never a wall-clock timer.
	CoveredSeconds int64     `json:"covered_seconds"`
	WindowStart    time.Time `json:"window_start"`
	// WouldBlock are opens a monitor-mode control would have denied; a hit
	// restarts the window. Blocked are opens an enforcing control denied.
	WouldBlock  map[string]*HitStats `json:"would_block,omitempty"`
	Blocked     map[string]*HitStats `json:"blocked,omitempty"`
	ResetReason string               `json:"reset_reason,omitempty"`
}

// ETAMinWindow is how long a burn-in window must run before its rate gives
// a calendar estimate; before that the progress reads "measuring".
const ETAMinWindow = 24 * time.Hour

// BurnInETA is the calendar time until a user's burn-in completes at the rate
// so far. Covered time accrues only while an anchored agent of the user runs,
// so the estimate is (needed - covered) / (covered / window age), never the
// covered time still needed. measuring is true while the window is younger
// than ETAMinWindow; ok is false then, before any agent use, without a window
// start and once nothing is left to cover. tetragon verify, tetragon status
// and the gateway's kernel_floor.next_ready_hours all use this one rule.
func BurnInETA(covered, needed time.Duration, windowStart, now time.Time) (eta time.Duration, measuring, ok bool) {
	if needed <= covered || windowStart.IsZero() {
		return 0, false, false
	}
	age := now.Sub(windowStart)
	if age < ETAMinWindow {
		return 0, true, false
	}
	if covered <= 0 {
		return 0, false, false
	}
	return time.Duration(float64(needed-covered) * float64(age) / float64(covered)), false, true
}

// BurnInFile is burnin.json.
type BurnInFile struct {
	Version int `json:"version"`
	// KernelPolicy is the control-set digest the evidence was measured
	// against. A different digest voids all of it.
	KernelPolicy string                `json:"kernel_policy"`
	UIDs         map[string]*UIDRecord `json:"uids,omitempty"`
}

func readBurnIn(dirs Dirs) (BurnInFile, error) {
	var file BurnInFile
	if err := readJSON(dirs.BurnIn(), &file); err != nil && !errors.Is(err, os.ErrNotExist) {
		return BurnInFile{}, err
	}
	if file.UIDs == nil {
		file.UIDs = map[string]*UIDRecord{}
	}
	return file, nil
}

// Burnin is the in-memory burn-in ledger. It is not safe for concurrent use;
// the Controller serializes access.
type Burnin struct {
	file  BurnInFile
	dirty bool
}

// LoadBurnin reads burnin.json; a missing or unreadable file starts empty,
// which only ever delays enforcement.
func LoadBurnin(dirs Dirs) *Burnin {
	file, err := readBurnIn(dirs)
	if err != nil {
		file = BurnInFile{UIDs: map[string]*UIDRecord{}}
	}
	file.Version = stateVersion
	return &Burnin{file: file}
}

// Save writes burnin.json when something changed.
func (b *Burnin) Save(dirs Dirs) error {
	if !b.dirty {
		return nil
	}
	if err := writeJSON(dirs.BurnIn(), b.file); err != nil {
		return err
	}
	b.dirty = false
	return nil
}

// Snapshot returns a deep copy.
func (b *Burnin) Snapshot() BurnInFile {
	out := BurnInFile{Version: b.file.Version, KernelPolicy: b.file.KernelPolicy, UIDs: map[string]*UIDRecord{}}
	for key, rec := range b.file.UIDs {
		copyRec := *rec
		copyRec.Connectors = append([]string(nil), rec.Connectors...)
		copyRec.WouldBlock = cloneStats(rec.WouldBlock)
		copyRec.Blocked = cloneStats(rec.Blocked)
		out.UIDs[key] = &copyRec
	}
	return out
}

func cloneStats(in map[string]*HitStats) map[string]*HitStats {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]*HitStats, len(in))
	for key, stats := range in {
		c := *stats
		c.Paths = append([]Counted(nil), stats.Paths...)
		c.Binaries = append([]Counted(nil), stats.Binaries...)
		out[key] = &c
	}
	return out
}

// Sync applies the reset rules against the current control-set digest and
// enrollment. It returns a reason for every user whose evidence was voided.
//
//   - A different kernel_policy digest voids everyone: the approved controls
//     are not the ones that were measured.
//   - A user whose connector set changed starts over.
//   - A user who left the enrollment is forgotten; one who joined starts a
//     record of their own.
func (b *Burnin) Sync(digest string, e Enrollment, now time.Time) map[int]string {
	resets := map[int]string{}
	if b.file.KernelPolicy != digest {
		if b.file.KernelPolicy != "" {
			for key := range b.file.UIDs {
				if uid, err := strconv.Atoi(key); err == nil {
					resets[uid] = "kernel_policy_changed"
				}
			}
		}
		b.file = BurnInFile{Version: stateVersion, KernelPolicy: digest, UIDs: map[string]*UIDRecord{}}
		b.dirty = true
	}
	enrolled := map[string]bool{}
	for _, uid := range e.UIDs() {
		key := strconv.Itoa(uid)
		enrolled[key] = true
		connectors, sum := e.Connectors(uid), e.ConnectorsDigest(uid)
		rec := b.file.UIDs[key]
		switch {
		case rec == nil:
			b.file.UIDs[key] = &UIDRecord{Connectors: connectors, ConnectorsDigest: sum, WindowStart: now}
			b.dirty = true
		case rec.ConnectorsDigest != sum:
			b.file.UIDs[key] = &UIDRecord{Connectors: connectors, ConnectorsDigest: sum, WindowStart: now,
				ResetReason: "connector_set_changed"}
			resets[uid] = "connector_set_changed"
			b.dirty = true
		}
	}
	for key := range b.file.UIDs {
		if !enrolled[key] {
			delete(b.file.UIDs, key)
			b.dirty = true
		}
	}
	return resets
}

func (b *Burnin) record(uid int) *UIDRecord { return b.file.UIDs[strconv.Itoa(uid)] }

// Accrue adds covered time for uid.
func (b *Burnin) Accrue(uid int, d time.Duration) {
	if rec := b.record(uid); rec != nil {
		rec.CoveredSeconds += int64(d / time.Second)
		b.dirty = true
	}
}

// Covered returns the covered time of uid since its last hit or reset.
func (b *Burnin) Covered(uid int) time.Duration {
	if rec := b.record(uid); rec != nil {
		return time.Duration(rec.CoveredSeconds) * time.Second
	}
	return 0
}

// Ready reports whether uid finished its burn-in. A user with evidence of
// need or more covered time and no hit in the current window is ready; with
// need zero (the administrator skipped burn-in) every enrolled user is.
func (b *Burnin) Ready(uid int, need time.Duration) bool {
	rec := b.record(uid)
	if rec == nil {
		return false
	}
	return need == 0 || time.Duration(rec.CoveredSeconds)*time.Second >= need
}

// Hit records an open of control by uid. A would-block hit restarts the
// user's clean window; a blocked open (an enforcing control doing its job)
// does not.
func (b *Burnin) Hit(uid int, control string, blocked bool, path, binary string, now time.Time) {
	rec := b.record(uid)
	if rec == nil {
		return
	}
	target := &rec.WouldBlock
	if blocked {
		target = &rec.Blocked
	} else {
		rec.CoveredSeconds = 0
		rec.WindowStart = now
	}
	if *target == nil {
		*target = map[string]*HitStats{}
	}
	stats := (*target)[control]
	if stats == nil {
		stats = &HitStats{First: now}
		(*target)[control] = stats
	}
	stats.Count++
	stats.Last = now
	stats.Paths = bump(stats.Paths, path)
	stats.Binaries = bump(stats.Binaries, binary)
	b.dirty = true
}

func bump(list []Counted, value string) []Counted {
	if value == "" {
		return list
	}
	for i := range list {
		if list[i].Value == value {
			list[i].Count++
			sort.SliceStable(list, func(a, c int) bool { return list[a].Count > list[c].Count })
			return list
		}
	}
	if len(list) >= maxCounted {
		// Space-saving: the newcomer replaces the least frequent entry and
		// inherits its count, so a value that really is frequent climbs to the
		// top instead of being evicted every time it appears.
		last := len(list) - 1
		list[last] = Counted{Value: value, Count: list[last].Count + 1}
	} else {
		list = append(list, Counted{Value: value, Count: 1})
	}
	sort.SliceStable(list, func(a, c int) bool { return list[a].Count > list[c].Count })
	return list
}

// Hits returns the would-block hit count of uid across controls.
func (b *Burnin) Hits(uid int) int {
	total := 0
	if rec := b.record(uid); rec != nil {
		for _, stats := range rec.WouldBlock {
			total += stats.Count
		}
	}
	return total
}
