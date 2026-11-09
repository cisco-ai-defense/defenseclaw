// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// windowsEnterpriseKeptRecordChanges names the Setup-owned records (the
// deployment record and the application-control attestation) that another
// account could change and that the repair kept aside as
// <name>.rejected-<time>-<hash> and wrote again since since (GAP-0602,
// GAP-0603). The module writes its own warning, which the result does not
// carry; the kept files are listed from the install state folder. A seam for
// tests.
var windowsEnterpriseKeptRecordChanges = func(installStateDir string, since time.Time) []string {
	var changes []string
	for _, record := range []string{"deployment.json", "agent-application-control-attestation.json"} {
		matches, err := filepath.Glob(filepath.Join(installStateDir, record+".rejected-*"))
		if err != nil {
			continue
		}
		for _, kept := range matches {
			// The rename keeps the record's own times; the time the module
			// kept it is in the name (UTC, yyyyMMddTHHmmssfffZ).
			keptAt, ok := windowsEnterpriseKeptRecordTime(kept)
			if !ok || keptAt.Before(since.Add(-time.Minute)) {
				continue
			}
			changes = append(changes, fmt.Sprintf(
				"%s could be changed by another account: kept it as %s (administrators only) and wrote it again%s",
				filepath.Join(installStateDir, record), kept, windowsEnterpriseAttestAgainNote(strings.HasPrefix(record, "agent-"))))
		}
	}
	return changes
}

var windowsEnterpriseKeptRecordTimePattern = regexp.MustCompile(`\.rejected-(\d{8}T\d{6})(\d{3})Z-`)

// windowsEnterpriseKeptRecordTime reads when the module kept a record from
// its name.
func windowsEnterpriseKeptRecordTime(kept string) (time.Time, bool) {
	match := windowsEnterpriseKeptRecordTimePattern.FindStringSubmatch(filepath.Base(kept))
	if match == nil {
		return time.Time{}, false
	}
	at, err := time.Parse("20060102T150405", match[1])
	if err != nil {
		return time.Time{}, false
	}
	millis, _ := strconv.Atoi(match[2])
	return at.Add(time.Duration(millis) * time.Millisecond), true
}

func windowsEnterpriseAttestAgainNote(attestation bool) string {
	if !attestation {
		return ""
	}
	return "; the new attestation says not attested, attest again with enterprise windows repair --attest-agent-application-control"
}
