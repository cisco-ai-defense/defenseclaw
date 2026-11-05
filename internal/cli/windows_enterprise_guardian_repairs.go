// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// windowsGuardianRepairField is one key="value" pair of a resilience event
// line (managed.FormatResilienceEvent quotes every value).
var windowsGuardianRepairField = regexp.MustCompile(`([a-z_]+)=("(?:[^"\\]|\\.)*")`)

// windowsGuardianRepairLimit bounds the repairs one result names.
const windowsGuardianRepairLimit = 5

// windowsGuardianRepairsAfter returns, from the hook guardian's log text, each
// defenseclaw_repair event the guardian logged at or after since (its lines
// carry the local time to the second), as "<path> at <time> (<reason>)":
// one entry per path and reason, the latest kept, oldest first, at most
// windowsGuardianRepairLimit (the most recent).
func windowsGuardianRepairsAfter(text string, since time.Time, loc *time.Location) []string {
	const stamp = "2006/01/02 15:04:05"
	since = since.Truncate(time.Second)
	type repair struct {
		key, line string
	}
	var found []repair
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		if len(line) < len(stamp)+1 || !strings.HasPrefix(line[len(stamp)+1:], "defenseclaw_repair ") {
			continue
		}
		at, err := time.ParseInLocation(stamp, line[:len(stamp)], loc)
		if err != nil || at.Before(since) {
			continue
		}
		fields := map[string]string{}
		for _, match := range windowsGuardianRepairField.FindAllStringSubmatch(line, -1) {
			if value, err := strconv.Unquote(match[2]); err == nil {
				fields[match[1]] = value
			}
		}
		path := strings.TrimSpace(fields["path"])
		if path == "" {
			continue
		}
		key := path + "\x00" + fields["reason"]
		entry := path + " at " + at.UTC().Format(time.RFC3339)
		if reason := strings.TrimSpace(fields["reason"]); reason != "" {
			entry += " (" + reason + ")"
		}
		for i, earlier := range found {
			if earlier.key == key {
				found = append(found[:i], found[i+1:]...)
				break
			}
		}
		found = append(found, repair{key: key, line: entry})
	}
	if len(found) > windowsGuardianRepairLimit {
		found = found[len(found)-windowsGuardianRepairLimit:]
	}
	out := make([]string, 0, len(found))
	for _, repair := range found {
		out = append(out, repair.line)
	}
	return out
}
