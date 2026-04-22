// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

// Gateway event types surfaced in the TUI (logs + alerts + activity).
const (
	GatewayEventScan        = gatewaylog.EventScan
	GatewayEventScanFinding = gatewaylog.EventScanFinding
	GatewayEventActivity    = gatewaylog.EventActivity
)

// TUI filter taxonomy for OTel (panel filter chips).
const (
	FilterTypeSeverity   = "severity"
	FilterTypeSubsystem  = "subsystem"
	FilterTypeAgentID    = "agent_id"
	FilterTypeEventType  = "event_type"
	FilterTypeSearchText = "search"
)

// ParseGatewayEvent unmarshals one gateway.jsonl line into a typed event.
func ParseGatewayEvent(line string) (*gatewaylog.Event, error) {
	line = strings.TrimSpace(line)
	if line == "" || !strings.HasPrefix(line, "{") {
		return nil, errors.New("tui: empty or non-json gateway line")
	}
	var ev gatewaylog.Event
	if err := json.Unmarshal([]byte(line), &ev); err != nil {
		return nil, err
	}
	return &ev, nil
}

// ScanBlock groups a roll-up scan with its findings (same scan_id).
type ScanBlock struct {
	Summary  gatewaylog.ScanPayload
	Findings []gatewaylog.ScanFindingPayload
	Expanded bool
	TS       time.Time
}

// ActivityMutation is a denormalized view of EventActivity for the Activity panel.
type ActivityMutation struct {
	RawLine     string
	TS          time.Time
	Actor       string
	Action      string
	TargetType  string
	TargetID    string
	Reason      string
	VersionFrom string
	VersionTo   string
	Before      map[string]any
	After       map[string]any
	Diff        []gatewaylog.DiffEntry
}

// LoadGatewayScanBlocks reads gateway.jsonl and returns scan blocks with
// findings attached. Only a tail window is scanned (same cap as LogsPanel).
func LoadGatewayScanBlocks(path string) ([]*ScanBlock, error) {
	scans, _, err := loadGatewayStreams(path)
	return scans, err
}

// LoadGatewayActivity reads gateway.jsonl and returns activity mutations.
func LoadGatewayActivity(path string) ([]ActivityMutation, error) {
	_, acts, err := loadGatewayStreams(path)
	return acts, err
}

func loadGatewayStreams(path string) ([]*ScanBlock, []ActivityMutation, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	const maxBytes = 512 * 1024
	size := info.Size()
	readSize := size
	if readSize > maxBytes {
		readSize = maxBytes
	}
	offset := size - readSize
	buf := make([]byte, readSize)
	n, err := f.ReadAt(buf, offset)
	if err != nil && n == 0 {
		return nil, nil, err
	}
	buf = buf[:n]
	if offset > 0 {
		if idx := strings.IndexByte(string(buf), '\n'); idx >= 0 {
			buf = buf[idx+1:]
		}
	}

	scanByID := make(map[string]*ScanBlock)
	var activities []ActivityMutation

	sc := bufio.NewScanner(strings.NewReader(string(buf)))
	const maxScanToken = 1024 * 1024
	sc.Buffer(make([]byte, 64*1024), maxScanToken)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		ev, err := ParseGatewayEvent(line)
		if err != nil || ev == nil {
			continue
		}
		switch ev.EventType {
		case gatewaylog.EventScan:
			if ev.Scan == nil || ev.Scan.ScanID == "" {
				continue
			}
			id := ev.Scan.ScanID
			b, ok := scanByID[id]
			if !ok {
				b = &ScanBlock{}
				scanByID[id] = b
			}
			b.Summary = *ev.Scan
			if ev.Timestamp.After(b.TS) {
				b.TS = ev.Timestamp
			}
		case gatewaylog.EventScanFinding:
			if ev.ScanFinding == nil || ev.ScanFinding.ScanID == "" {
				continue
			}
			id := ev.ScanFinding.ScanID
			b, ok := scanByID[id]
			if !ok {
				b = &ScanBlock{
					TS: ev.Timestamp,
					Summary: gatewaylog.ScanPayload{
						ScanID:     id,
						Scanner:    ev.ScanFinding.Scanner,
						Target:     ev.ScanFinding.Target,
						Verdict:    "",
						DurationMs: 0,
					},
				}
				scanByID[id] = b
			}
			b.Findings = append(b.Findings, *ev.ScanFinding)
			if ev.Timestamp.After(b.TS) {
				b.TS = ev.Timestamp
			}
		case gatewaylog.EventActivity:
			if ev.Activity == nil {
				continue
			}
			a := *ev.Activity
			activities = append(activities, ActivityMutation{
				RawLine:     line,
				TS:          ev.Timestamp,
				Actor:       a.Actor,
				Action:      a.Action,
				TargetType:  a.TargetType,
				TargetID:    a.TargetID,
				Reason:      a.Reason,
				VersionFrom: a.VersionFrom,
				VersionTo:   a.VersionTo,
				Before:      a.Before,
				After:       a.After,
				Diff:        a.Diff,
			})
		default:
			continue
		}
	}
	if err := sc.Err(); err != nil {
		return nil, nil, fmt.Errorf("tui: scan gateway jsonl: %w", err)
	}

	blocks := make([]*ScanBlock, 0, len(scanByID))
	for _, b := range scanByID {
		blocks = append(blocks, b)
	}
	sort.Slice(blocks, func(i, j int) bool {
		return blocks[i].TS.After(blocks[j].TS)
	})
	return blocks, activities, nil
}
