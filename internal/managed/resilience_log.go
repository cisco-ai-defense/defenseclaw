// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"log"
	"sort"
	"strconv"
	"strings"
)

// Resilience markers. Every repair, acceptance, skip, integrity finding,
// missing prerequisite, install recovery and degraded subsystem in the managed
// lifecycle is logged once with exactly one of these leading tokens so DART
// triage can grep a stable vocabulary. The installer module writes the same
// tokens.
const (
	// MarkerRepair: a drifted object was re-stamped to its canonical form.
	MarkerRepair = "defenseclaw_repair"
	// MarkerAccept: drift was tolerated without a repair.
	MarkerAccept = "defenseclaw_accept"
	// MarkerSkip: one user, target or connector was skipped; the rest continued.
	MarkerSkip = "defenseclaw_skip"
	// MarkerBoundary: a code or policy integrity finding. Critical, but not
	// fatal: the component logs it, repairs what it can and keeps running.
	MarkerBoundary = "defenseclaw_boundary"
	// MarkerPrereq: a host prerequisite is missing, with the remedy.
	MarkerPrereq = "defenseclaw_prereq"
	// MarkerRecover: install recovery cleared leftover state.
	MarkerRecover = "defenseclaw_recover"
	// MarkerDegraded: a service is running with a subsystem degraded.
	MarkerDegraded = "defenseclaw_degraded"
)

// ReportResilienceEvent lets an embedding process route resilience events into
// its own structured log. Same contract as ReportTrustDrift: nil by default,
// set once during process startup. When nil the event goes to the standard
// logger.
var ReportResilienceEvent func(marker string, fields map[string]string)

// EmitResilienceEvent logs one resilience event. fields are rendered as
// key="value" pairs in key order after the marker, so the line is stable for
// grepping and diffing.
func EmitResilienceEvent(marker string, fields map[string]string) {
	if sink := ReportResilienceEvent; sink != nil {
		sink(marker, fields)
		return
	}
	log.Print(FormatResilienceEvent(marker, fields))
}

// FormatResilienceEvent renders the line EmitResilienceEvent writes.
func FormatResilienceEvent(marker string, fields map[string]string) string {
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(marker)
	for _, key := range keys {
		b.WriteByte(' ')
		b.WriteString(key)
		b.WriteByte('=')
		b.WriteString(strconv.Quote(fields[key]))
	}
	return b.String()
}
