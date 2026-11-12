// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/text/unicode/norm"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// EnrollmentExcludeWarningPrefix starts the status and verify warning for
// enterprise.enrollment.exclude_users entries that match no account; the
// managed lifecycles report it as enrollment_exclude_unmatched.
const EnrollmentExcludeWarningPrefix = "enterprise.enrollment.exclude_users:"

// enrollmentExcludeCheckTTL is how long one pass over the entries is served.
const enrollmentExcludeCheckTTL = 5 * time.Minute

var enrollmentExcludeCache struct {
	sync.Mutex
	key      string
	at       time.Time
	warnings []string
}

// enrollmentExcludeWarnings names, by position, the exclude_users entries of
// a standalone config that the host's account database answers "no such
// account" for (enrollmentExcludeEntryUnknown). Such an entry (a bare name
// that exists nowhere, an AzureAD\ or DOMAIN\ name of no account here)
// excludes nobody, and Setup, status and verify said nothing (GAP-1111). The
// entry text is not repeated: status can be read by any account. A failed
// lookup, a wildcard, a uid or SID the host cannot check and anything past
// the bounded pass say nothing; the warning never changes enrollment.
func enrollmentExcludeWarnings(cfg *config.Config) []string {
	if cfg == nil || !cfg.StandaloneEnterprise() || len(cfg.Enterprise.Enrollment.ExcludeUsers) == 0 {
		return nil
	}
	entries := cfg.Enterprise.Enrollment.ExcludeUsers
	key := strings.Join(entries, "\x00")
	enrollmentExcludeCache.Lock()
	if enrollmentExcludeCache.key == key && time.Since(enrollmentExcludeCache.at) < enrollmentExcludeCheckTTL {
		warnings := enrollmentExcludeCache.warnings
		enrollmentExcludeCache.Unlock()
		return warnings
	}
	enrollmentExcludeCache.Unlock()
	deadline := time.Now().Add(profileGroupCheckBudget)
	var positions []string
	for i, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" || assignmentWildcard(entry) {
			continue
		}
		if i >= profileGroupCheckMax*4 || time.Now().After(deadline) {
			return nil // unchecked entries: say nothing, check again next time
		}
		if enrollmentExcludeEntryUnknown(norm.NFC.String(entry)) {
			positions = append(positions, strconv.Itoa(i+1))
		}
	}
	var warnings []string
	if len(positions) > 0 {
		noun, verb, pronoun := "entry", "matches", "it excludes"
		if len(positions) > 1 {
			noun, verb, pronoun = "entries", "match", "they exclude"
		}
		warnings = []string{fmt.Sprintf("%s %d %s (position %s in the list) %s no account this host knows, so %s nobody; "+
			"check the spelling (on Linux and macOS the exact account name or uid, on Windows DOMAIN\\name, AzureAD\\<name or UPN> or the SID) or remove it",
			EnrollmentExcludeWarningPrefix, len(positions), noun, strings.Join(positions, ", "), verb, pronoun)}
	}
	enrollmentExcludeCache.Lock()
	enrollmentExcludeCache.key, enrollmentExcludeCache.at, enrollmentExcludeCache.warnings = key, time.Now(), warnings
	enrollmentExcludeCache.Unlock()
	return warnings
}
