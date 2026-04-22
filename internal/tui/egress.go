// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
//
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

// EgressEvent is the TUI-facing projection of an EventEgress row.
// Keeping this struct flat (no nested pointer into the gatewaylog
// event) lets the Alerts panel render egress alongside audit rows
// without a second JSON round-trip.
type EgressEvent struct {
	TS           time.Time
	TargetHost   string
	TargetPath   string
	BodyShape    string
	LooksLikeLLM bool
	Branch       string
	Decision     string
	Reason       string
	Source       string
}

// LoadGatewayEgress reads the same tail window of gateway.jsonl that
// LoadGatewayScanBlocks/LoadGatewayActivity scan and returns egress
// rows sorted newest-first. Missing files are reported as a nil
// slice + nil error so the Overview panel can degrade gracefully on
// a brand-new install.
func LoadGatewayEgress(path string) ([]EgressEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
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
		return nil, err
	}
	buf = buf[:n]
	if offset > 0 {
		if idx := strings.IndexByte(string(buf), '\n'); idx >= 0 {
			buf = buf[idx+1:]
		}
	}

	var out []EgressEvent
	sc := bufio.NewScanner(strings.NewReader(string(buf)))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		ev, err := ParseGatewayEvent(line)
		if err != nil || ev == nil {
			continue
		}
		if ev.EventType != gatewaylog.EventEgress || ev.Egress == nil {
			continue
		}
		p := ev.Egress
		out = append(out, EgressEvent{
			TS:           ev.Timestamp,
			TargetHost:   p.TargetHost,
			TargetPath:   p.TargetPath,
			BodyShape:    p.BodyShape,
			LooksLikeLLM: p.LooksLikeLLM,
			Branch:       p.Branch,
			Decision:     p.Decision,
			Reason:       p.Reason,
			Source:       p.Source,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("tui: scan gateway jsonl for egress: %w", err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TS.After(out[j].TS) })
	return out, nil
}

// SyntheticEgressEvent adapts an EgressEvent into the audit.Event
// shape so the Alerts timeline can render it with the same row
// formatter as scan and activity rows.
func SyntheticEgressEvent(e EgressEvent) *audit.Event {
	sev := "INFO"
	// A "shape-detected unknown host allowed through" (branch=shape,
	// decision=allow) is the exact silent-bypass signal operators
	// want to notice. Upgrade to WARNING so the panel's severity
	// chip lights up for it. block decisions are always WARNING —
	// they reflect the SSRF defense firing or policy rejection.
	if e.Decision == "block" {
		sev = "WARNING"
	} else if e.Branch == "shape" && e.LooksLikeLLM {
		sev = "WARNING"
	}
	action := "egress"
	host := e.TargetHost
	if host == "" {
		host = "(unknown)"
	}
	details := fmt.Sprintf(
		"host=%s path=%s branch=%s decision=%s shape=%s looks_like_llm=%t source=%s",
		host, e.TargetPath, e.Branch, e.Decision, e.BodyShape, e.LooksLikeLLM, e.Source,
	)
	if e.Reason != "" {
		details += " reason=" + e.Reason
	}
	return &audit.Event{
		ID:        fmt.Sprintf("gw:egress:%s:%s:%s", host, e.Branch, e.TS.Format(time.RFC3339Nano)),
		Timestamp: e.TS,
		Action:    action,
		Target:    host,
		Details:   details,
		Severity:  sev,
	}
}

// CountRecentSilentBypass returns the number of egress events in the
// last `window` that represent "an LLM call that the guardrail did
// NOT route through regex + judge". Two branches count:
//
//	branch=passthrough + looks_like_llm=true   — unknown host with an
//	                                             LLM-shaped body that
//	                                             was let through because
//	                                             allow_unknown_llm_domains
//	                                             is on (or path shape
//	                                             was ambiguous)
//	branch=shape       + decision=allow        — recognized as LLM by
//	                                             shape + path signal but
//	                                             operator opted into the
//	                                             unknown host
//
// Both are the silent-bypass early-warning signal the Overview panel
// surfaces as a tile. branch=known never counts — those are known
// providers that do go through triage/judge by the proxy. block
// decisions never count either — the proxy rejected them.
func CountRecentSilentBypass(events []EgressEvent, window time.Duration) int {
	if len(events) == 0 || window <= 0 {
		return 0
	}
	cutoff := time.Now().Add(-window)
	n := 0
	for _, e := range events {
		if e.TS.Before(cutoff) {
			continue
		}
		if e.Decision != "allow" {
			continue
		}
		switch {
		case e.Branch == "passthrough" && e.LooksLikeLLM:
			n++
		case e.Branch == "shape":
			n++
		}
	}
	return n
}
