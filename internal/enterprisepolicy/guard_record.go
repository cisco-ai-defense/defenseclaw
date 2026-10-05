// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// A foreign-hook block is decided in the hook process, before any gateway
// contact, and the managed hook's own failure log lives in a directory the
// user cannot write. So the hook appends a small record to a file in the
// user's own data directory, and the guardian's per-user cleanup (running
// with the user's credentials) takes the records and reports them in its
// log, where an administrator sees them next to the removals. The records
// are user-writable and therefore advisory: a user can delete or invent
// them, but cannot hide a block from the hook's own denial.

// BlockRecord is one block the hook recorded.
type BlockRecord struct {
	Time      string `json:"ts"`
	Connector string `json:"connector"`
	Event     string `json:"event,omitempty"`
	Scope     string `json:"scope,omitempty"`
	Path      string `json:"path,omitempty"`
	Digest    string `json:"digest,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// BlockSummary is the records for one connector, file and digest. The
// embedded record is the first block; Events counts every hook event the
// file blocked, in first-seen order, so the summary never attributes all
// blocks to the first event.
type BlockSummary struct {
	BlockRecord
	Count  int          `json:"count"`
	Last   string       `json:"last,omitempty"`
	Events []EventCount `json:"events,omitempty"`
}

// EventCount is how many blocks one hook event had in a summary.
type EventCount struct {
	Event string `json:"event"`
	Count int    `json:"count"`
}

// blockEventLimit bounds the distinct events one summary lists; the
// last slot becomes "other" once more events appear.
const blockEventLimit = 8

func (s *BlockSummary) addEvent(event string) {
	if event == "" {
		event = "-"
	}
	for i := range s.Events {
		if s.Events[i].Event == event {
			s.Events[i].Count++
			return
		}
	}
	if len(s.Events) == blockEventLimit {
		last := &s.Events[blockEventLimit-1]
		last.Event = "other"
		last.Count++
		return
	}
	s.Events = append(s.Events, EventCount{Event: event, Count: 1})
}

const (
	blockRecordFile  = "foreign-hook-blocks.jsonl"
	blockRecordLimit = 256 << 10
	blockFieldLimit  = 512
	// BlockSummaryLimit bounds the summaries one collection returns.
	BlockSummaryLimit = 32
)

// BlockRecordPath is where the hook records blocks for the user whose home
// (from the account database) is accountHome.
func BlockRecordPath(accountHome string) string {
	return filepath.Join(accountHome, ".defenseclaw", blockRecordFile)
}

// RecordForeignHookBlock appends one record for decision (best effort; the
// hook denies regardless). The file is capped: once it holds
// blockRecordLimit bytes further blocks are not recorded until the guardian
// collects it.
func RecordForeignHookBlock(accountHome, connector, event string, decision GuardDecision, now time.Time) error {
	if !decision.Deny || strings.TrimSpace(accountHome) == "" || !filepath.IsAbs(accountHome) {
		return nil
	}
	record := BlockRecord{Time: now.UTC().Format(time.RFC3339), Connector: connector, Event: event}
	for _, finding := range decision.Findings {
		if !finding.Allowed {
			record.Scope, record.Path, record.Digest, record.Reason = finding.Scope, finding.Path, finding.Digest, finding.Reason
			break
		}
	}
	line, err := json.Marshal(record.bounded())
	if err != nil {
		return err
	}
	path := BlockRecordPath(accountHome)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular file", path)
		}
		if info.Size()+int64(len(line))+1 > blockRecordLimit {
			return nil
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	file, err := openGuardAppend(path)
	if err != nil {
		return err
	}
	defer file.Close()
	if info, err := file.Stat(); err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	_, err = file.Write(append(line, '\n'))
	return err
}

// CollectForeignHookBlocks takes the records the user's hooks left and
// summarizes them by connector, file and digest. It runs with the user's
// own credentials. The file is renamed first, so a hook appending
// meanwhile starts a new file instead of losing its record.
func CollectForeignHookBlocks(accountHome string, now time.Time) ([]BlockSummary, int, error) {
	if strings.TrimSpace(accountHome) == "" || !filepath.IsAbs(accountHome) {
		return nil, 0, errors.New("block records need an absolute home directory")
	}
	path := BlockRecordPath(accountHome)
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	if !info.Mode().IsRegular() {
		return nil, 0, fmt.Errorf("%s is not a regular file", path)
	}
	taken := fmt.Sprintf("%s.collect-%d", path, now.UnixNano())
	if err := os.Rename(path, taken); err != nil {
		return nil, 0, err
	}
	defer os.Remove(taken)
	data, _, err := readGuardFileLimit(taken, blockRecordLimit+blockFieldLimit*8)
	if err != nil {
		return nil, 0, err
	}
	summaries := map[string]*BlockSummary{}
	var order []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 4096), blockFieldLimit*16)
	for scanner.Scan() {
		var record BlockRecord
		if json.Unmarshal(scanner.Bytes(), &record) != nil || strings.TrimSpace(record.Connector) == "" {
			continue
		}
		record = record.bounded()
		key := record.Connector + "\x00" + record.Path + "\x00" + record.Digest
		if summary, ok := summaries[key]; ok {
			summary.Count++
			summary.Last = record.Time
			summary.addEvent(record.Event)
			continue
		}
		summary := &BlockSummary{BlockRecord: record, Count: 1, Last: record.Time}
		summary.addEvent(record.Event)
		summaries[key] = summary
		order = append(order, key)
	}
	sort.SliceStable(order, func(i, j int) bool { return summaries[order[i]].Time < summaries[order[j]].Time })
	out := make([]BlockSummary, 0, len(order))
	for _, key := range order {
		if len(out) == BlockSummaryLimit {
			break
		}
		out = append(out, *summaries[key])
	}
	return out, len(order) - len(out), nil
}

func (r BlockRecord) bounded() BlockRecord {
	clip := func(value string) string {
		value = strings.Map(func(c rune) rune {
			if c < 0x20 || c == 0x7f {
				return ' '
			}
			return c
		}, value)
		if len(value) > blockFieldLimit {
			value = value[:blockFieldLimit]
		}
		return value
	}
	return BlockRecord{
		Time: clip(r.Time), Connector: clip(r.Connector), Event: clip(r.Event), Scope: clip(r.Scope),
		Path: clip(r.Path), Digest: clip(r.Digest), Reason: clip(r.Reason),
	}
}

// String renders a summary for the guardian log.
func (s BlockSummary) String() string {
	events := s.Events
	if len(events) == 0 {
		event := s.Event
		if event == "" {
			event = "-"
		}
		events = []EventCount{{Event: event, Count: s.Count}}
	}
	parts := make([]string, 0, len(events))
	for _, e := range events {
		parts = append(parts, fmt.Sprintf("%s %d", e.Event, e.Count))
	}
	when := fmt.Sprintf("between %s and %s", s.Time, s.Last)
	if s.Count == 1 || s.Last == "" || s.Last == s.Time {
		when = "at " + s.Time
	}
	return fmt.Sprintf("blocked %d %s hook call(s) (%s) %s: %s file %s (sha256:%s) %s",
		s.Count, s.Connector, strings.Join(parts, ", "), when, s.Scope, s.Path, s.Digest, s.Reason)
}
