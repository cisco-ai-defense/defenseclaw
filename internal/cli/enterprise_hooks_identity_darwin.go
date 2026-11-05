//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// A macOS account is identified in the guardian ledger by its uid and its
// GeneratedUID, never by the short name alone: a new account that reuses a
// deleted user's name gets a new GeneratedUID and starts unprotected.
const enterpriseHookDarwinIdentityPrefix = "uid:"

const (
	enterpriseHookGeneratedUIDTimeout = 5 * time.Second
	enterpriseHookGeneratedUIDTTL     = 5 * time.Minute
)

var enterpriseHookGeneratedUIDPattern = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)

// enterpriseHookGeneratedUIDLookup is replaced in tests.
var enterpriseHookGeneratedUIDLookup = func(name string) (string, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), enterpriseHookGeneratedUIDTimeout)
		cmd := exec.CommandContext(ctx, "/usr/bin/dscl", ".", "-read", "/Users/"+name, "GeneratedUID")
		cmd.Env = []string{"LANG=C", "LC_ALL=C"}
		output, err := cmd.Output()
		cancel()
		if err == nil {
			for _, line := range strings.Split(string(output), "\n") {
				if value, ok := strings.CutPrefix(strings.TrimSpace(line), "GeneratedUID:"); ok {
					return strings.TrimSpace(value), nil
				}
			}
			return "", fmt.Errorf("no GeneratedUID for %s", name)
		}
		lastErr = err
	}
	return "", lastErr
}

var enterpriseHookGeneratedUIDs = struct {
	sync.Mutex
	entries map[string]enterpriseHookGeneratedUIDEntry
}{entries: map[string]enterpriseHookGeneratedUIDEntry{}}

type enterpriseHookGeneratedUIDEntry struct {
	uid  int
	guid string
	at   time.Time
}

// enterpriseHookPlatformTargetIdentity returns `uid:<uid>/guid:<GeneratedUID>`
// for a named local account. A directory-service failure fails this target
// for this tick only. The standalone profile keys its targets and per-user
// credentials on the uid itself, so it gets no identity here.
func enterpriseHookPlatformTargetIdentity(name string, uid int) (string, error) {
	if name == "" || uid <= 0 || strings.ContainsAny(name, "/\x00\r\n") || enterpriseHooksStandaloneUnixActive() {
		return "", nil
	}
	enterpriseHookGeneratedUIDs.Lock()
	cached, ok := enterpriseHookGeneratedUIDs.entries[name]
	enterpriseHookGeneratedUIDs.Unlock()
	if ok && cached.uid == uid && time.Since(cached.at) < enterpriseHookGeneratedUIDTTL {
		return enterpriseHookDarwinIdentity(uid, cached.guid), nil
	}
	guid, err := enterpriseHookGeneratedUIDLookup(name)
	if err != nil {
		return "", fmt.Errorf("enterprise hooks: read GeneratedUID for %q: %w", name, err)
	}
	if !enterpriseHookGeneratedUIDPattern.MatchString(guid) {
		return "", fmt.Errorf("enterprise hooks: GeneratedUID for %q is malformed: %q", name, guid)
	}
	guid = strings.ToUpper(guid)
	enterpriseHookGeneratedUIDs.Lock()
	enterpriseHookGeneratedUIDs.entries[name] = enterpriseHookGeneratedUIDEntry{uid: uid, guid: guid, at: time.Now()}
	enterpriseHookGeneratedUIDs.Unlock()
	return enterpriseHookDarwinIdentity(uid, guid), nil
}

func enterpriseHookDarwinIdentity(uid int, guid string) string {
	return enterpriseHookDarwinIdentityPrefix + strconv.Itoa(uid) + "/guid:" + guid
}

// enterpriseHookUnresolvedTargetIdentity finds the ledger identity of a
// target whose account could not be resolved this tick, by its name and
// manifest uid, so its last protected state is kept until it resolves again
// or the enumerator drops it.
func enterpriseHookUnresolvedTargetIdentity(dataDir string, target enterprisehooks.ManifestTarget) string {
	if sid := strings.TrimSpace(target.SID); sid != "" {
		return sid
	}
	name := strings.TrimSpace(target.User)
	if name == "" {
		return ""
	}
	authorization, _, err := loadEnterpriseHookGuardianAuthorization(dataDir)
	if err != nil {
		return ""
	}
	prefix := enterpriseHookDarwinIdentityPrefix
	if target.UID != nil {
		prefix += strconv.Itoa(*target.UID) + "/"
	}
	connectorName := strings.ToLower(strings.TrimSpace(target.Connector))
	for _, row := range authorization.ProtectedTargets {
		if strings.TrimSpace(row.User) == name &&
			strings.ToLower(strings.TrimSpace(row.Connector)) == connectorName &&
			strings.HasPrefix(strings.TrimSpace(row.SID), prefix) {
			return strings.TrimSpace(row.SID)
		}
	}
	return ""
}

// enterpriseHookLegacyLedgerRowMatchesPlatform lets a ledger row written
// before identities were recorded (no SID) match its user once, by name and
// home, so an upgrade does not drop every user's protection. The next
// successful reconcile rewrites the row with the identity.
func enterpriseHookLegacyLedgerRowMatchesPlatform(
	row enterpriseHookReconcileRow,
	userName, userHome, sid string,
) bool {
	if !strings.HasPrefix(sid, enterpriseHookDarwinIdentityPrefix) || userName == "" {
		return false
	}
	if strings.TrimSpace(row.User) != userName {
		return false
	}
	rowHome := strings.TrimSpace(row.UserHome)
	if rowHome == "" && row.Result != nil {
		rowHome = strings.TrimSpace(row.Result.UserHome)
	}
	return rowHome == "" || userHome == "" || filepath.Clean(rowHome) == filepath.Clean(userHome)
}

var enterpriseHookManifestRowSkips = struct {
	sync.Mutex
	logged map[string]struct{}
}{logged: map[string]struct{}{}}

// reportEnterpriseHookManifestSkippedRowsPlatform logs each manifest row
// that was left out, once per streak.
func reportEnterpriseHookManifestSkippedRowsPlatform(path string, skipped []enterprisehooks.ManifestRowSkip) {
	current := map[string]struct{}{}
	enterpriseHookManifestRowSkips.Lock()
	defer enterpriseHookManifestRowSkips.Unlock()
	for _, row := range skipped {
		key := strconv.Itoa(row.Index) + "\x00" + row.Reason
		current[key] = struct{}{}
		if _, logged := enterpriseHookManifestRowSkips.logged[key]; logged {
			continue
		}
		managed.EmitResilienceEvent(managed.MarkerSkip, map[string]string{
			"unit":   "row" + strconv.Itoa(row.Index),
			"path":   filepath.Clean(path),
			"reason": enterpriseHookBoundReason(row.Reason) + "; the other rows continue",
		})
	}
	enterpriseHookManifestRowSkips.logged = current
}

var enterpriseHookWatchDegraded = struct {
	sync.Mutex
	last string
	at   time.Time
}{}

// enterpriseHookWatchFailureToleratedPlatform keeps a failed watch add
// (kqueue descriptor exhaustion on a multi-user host, or an EACCES while a
// per-user euid drop is active) from failing the pass: the periodic tick
// still repairs, so it is logged once as defenseclaw_degraded.
func enterpriseHookWatchFailureToleratedPlatform(err error) bool {
	if enterpriseHooksStandaloneUnixActive() {
		return false
	}
	reason := err.Error()
	if enterprisehooks.OwnerCredentialsDropped() {
		reason += " (during a per-user credential drop; retried next tick)"
	}
	enterpriseHookWatchDegraded.Lock()
	repeat := enterpriseHookWatchDegraded.last == reason && time.Since(enterpriseHookWatchDegraded.at) < time.Hour
	enterpriseHookWatchDegraded.last = reason
	enterpriseHookWatchDegraded.at = time.Now()
	enterpriseHookWatchDegraded.Unlock()
	if !repeat {
		managed.EmitResilienceEvent(managed.MarkerDegraded, map[string]string{
			"component": "hook-guardian",
			"subsystem": "watch",
			"reason":    enterpriseHookBoundReason(reason) + "; the periodic reconcile still repairs",
		})
	}
	return true
}
