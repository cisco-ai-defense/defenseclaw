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

	"github.com/defenseclaw/defenseclaw/internal/managed"
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
				"%s could be changed by another account: kept it as %s and wrote it again; the kept copy is given administrator-only access, by this run or by the next /repair if a program holds it open%s",
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

// windowsEnterpriseKeptRecordUntrusted reports whether a kept copy still
// carries the access of an account other than SYSTEM, Administrators and
// TrustedInstaller (an untrusted owner or writer); a seam for tests.
var windowsEnterpriseKeptRecordUntrusted = func(path string) bool {
	result, err := managed.AssessCanonical(path, managed.ObjectInstallFile, managed.CanonicalOptions{Quiet: true})
	return err == nil && result.Outcome == managed.CanonicalBoundary
}

// windowsEnterpriseKeptRecordFiles lists the copies Setup kept aside next to
// the records in installStateDir; a seam for tests.
var windowsEnterpriseKeptRecordFiles = func(installStateDir string) []string {
	var kept []string
	for _, record := range []string{"deployment.json", "agent-application-control-attestation.json"} {
		matches, err := filepath.Glob(filepath.Join(installStateDir, record+".rejected-*"))
		if err == nil {
			kept = append(kept, matches...)
		}
	}
	return kept
}

// addWindowsEnterpriseKeptRecordWarnings names, in status and verify, each
// kept copy of a changed record that still carries another account's access
// (a program held it open when Setup tried to give it administrator-only
// access), with the exact fix. The copy is evidence only and nothing reads
// it, so this is a warning (GAP-0602 review D4).
func addWindowsEnterpriseKeptRecordWarnings(result interface{ AddWarning(code, message string) }, installStateDir string) {
	for _, kept := range windowsEnterpriseKeptRecordFiles(installStateDir) {
		if !windowsEnterpriseKeptRecordUntrusted(kept) {
			continue
		}
		result.AddWarning("kept_record_unprotected", fmt.Sprintf(
			"%s is the copy of a changed record that Setup kept aside, and another account can still change or own it (a program held it open when Setup tried to protect it). It is evidence only and nothing reads it. Fix, from an elevated prompt: icacls \"%s\" /inheritance:r /grant:r \"*S-1-5-18:(F)\" \"*S-1-5-32-544:(F)\" and icacls \"%s\" /setowner *S-1-5-32-544 (after the program that holds it is stopped, or after a restart), or run %s, which does the same",
			kept, kept, kept, windowsEnterpriseSetupCommand("/repair")))
	}
}
