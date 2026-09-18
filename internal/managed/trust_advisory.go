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
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// TrustStrictAncestorsEnv restores the pre-AIFW-34262 behaviour: ancestor
// directories of a managed path fail the trust walk when their owner or DACL
// cannot be proven trusted, instead of emitting an advisory and continuing.
//
// The default is advisory because the managed install lives under a directory
// tree that Cisco Secure Client (AVC) owns and re-ACLs on its own schedule
// (`C:\ProgramData\Cisco\Cisco Secure Client` on Windows,
// `/opt/cisco/secureclient` on macOS). AVC is responsible for the permissions
// on that shared parent; a transient third-party grant there must not brick a
// DefenseClaw install, which is exactly what AIFW-34262 hit: the state root
// carried a local-user FullControl ACE, the guardian live-verify failed, the
// rollback failed on the same check, and the quiesce phase had already left all
// four services Disabled.
//
// Set this to 1/true/yes/on for a hardened deployment that wants the ancestor
// verdicts to be fatal again.
const TrustStrictAncestorsEnv = "DEFENSECLAW_MANAGED_TRUST_STRICT_ANCESTORS"

// TrustAdvisoryMarker prefixes every relaxed-ancestor advisory so log scrapers
// and DART triage can grep one stable token.
const TrustAdvisoryMarker = "managed_trust_ancestor_advisory"

// ReportTrustAdvisory lets an embedding process route relaxed-ancestor trust
// advisories into its own structured log or telemetry sink. It mirrors the
// config.ReportConfigLoadError hook: nil by default, set once during process
// startup before any managed trust check runs, never swapped concurrently with
// a check in flight. When nil the advisory goes to the standard logger.
var ReportTrustAdvisory func(path, label, reason string)

// PlatformInstallerOwnedRoots returns the directories whose permissions belong
// to the Cisco Secure Client installer (AVC) rather than to DefenseClaw. AVC
// creates them, shares them with other Cisco software, and re-ACLs them on its
// own schedule, so a trust walk that crosses one of them cannot read foreign
// access there as evidence of compromise (AIFW-34262).
//
// This is deliberately a path allowlist rather than a deployment-mode check.
// The managed deployment mode is pinned by an environment variable on Windows
// but comes from the protected config.yaml on macOS, so a mode gate would be
// dead code on macOS; and a mode gate would also relax ancestors that have
// nothing to do with Cisco (a temp or home directory above a runtime path),
// which is the opposite of what is wanted.
func PlatformInstallerOwnedRoots() []string {
	switch runtime.GOOS {
	case "windows":
		// The canonical per-machine tree is always recognised, not just when
		// the environment is empty: a service started with a stripped or
		// partially redirected environment (%ProgramFiles% set, %ProgramData%
		// not) must still read `C:\ProgramData\Cisco` as installer-owned, or
		// the managed state root itself would be judged foreign.
		roots := make([]string, 0, 4)
		roots = append(roots, `C:\ProgramData\Cisco`)
		for _, envName := range []string{"ProgramData", "ProgramFiles", "ProgramFiles(x86)"} {
			base := os.Getenv(envName)
			if base == "" {
				continue
			}
			root := filepath.Join(base, "Cisco")
			if !containsInstallerOwnedRoot(roots, root) {
				roots = append(roots, root)
			}
		}
		return roots
	case "darwin":
		// /opt/cisco covers the managed install prefix
		// /opt/cisco/secureclient/defenseclaw; the logs root is shared with
		// other Cisco software the same way.
		return []string{"/opt/cisco", "/Library/Logs/Cisco"}
	default:
		return []string{"/opt/cisco"}
	}
}

// PlatformInstallerOwnedPath reports whether path is at or below one of
// PlatformInstallerOwnedRoots. Callers use it to decide whether an ancestor's
// permission verdict should be advisory; it says nothing about the named path a
// caller asked about, which always keeps its verdicts fatal.
func PlatformInstallerOwnedPath(path string) bool {
	if path == "" {
		return false
	}
	clean := filepath.Clean(path)
	for _, root := range PlatformInstallerOwnedRoots() {
		if pathAtOrUnder(clean, filepath.Clean(root)) {
			return true
		}
	}
	return false
}

// containsInstallerOwnedRoot keeps PlatformInstallerOwnedRoots free of
// duplicates when %ProgramData% resolves to the canonical location that is
// always seeded, matching the case-insensitive comparison pathAtOrUnder uses.
func containsInstallerOwnedRoot(roots []string, candidate string) bool {
	for _, root := range roots {
		if runtime.GOOS == "windows" {
			if strings.EqualFold(root, candidate) {
				return true
			}
			continue
		}
		if root == candidate {
			return true
		}
	}
	return false
}

func pathAtOrUnder(path, root string) bool {
	if runtime.GOOS == "windows" {
		path, root = strings.ToLower(path), strings.ToLower(root)
	}
	return path == root || strings.HasPrefix(path, root+string(filepath.Separator))
}

// RelaxAncestorTrustVerdict is the exported form of relaxAncestorTrustVerdict
// for trust walks that live outside this package. The gateway connector keeps
// its own hook API token chain walk with a different owner model (it accepts the
// invoking uid for unmanaged per-user installs), so it cannot call the managed
// validators, but it crosses the same AVC-owned ancestors and needs the same
// verdict downgrade. Pass advisory=false for the named path.
func RelaxAncestorTrustVerdict(advisory bool, path, label string, verdict error) error {
	return relaxAncestorTrustVerdict(advisory, path, label, verdict)
}

// RelaxAncestorTrustJudgement is the exported form of
// relaxAncestorTrustJudgement: it downgrades only errors built with
// NewTrustVerdict, so a helper that returns both permission judgements and
// structural or exec failures keeps the latter fatal.
func RelaxAncestorTrustJudgement(advisory bool, path, label string, err error) error {
	return relaxAncestorTrustJudgement(advisory, path, label, err)
}

// NewTrustVerdict tags an error as a permission judgement, making it eligible
// for the RelaxAncestorTrustJudgement downgrade. Errors built any other way are
// treated as structural and stay fatal.
func NewTrustVerdict(format string, args ...any) error {
	return newTrustVerdict(format, args...)
}

// relaxAncestorTrustVerdict turns a permission verdict about an ancestor
// directory into a warning when advisory is set. It returns verdict unchanged
// for the named leaf and for any other element the caller still wants to fail
// (advisory=false), when strict mode is pinned, and for every structural or API
// failure, because those callers never route through here.
//
// advisory is deliberately a separate decision from the narrower ancestor
// access mask on Windows (see windowsTrustScope): a caller can want stock
// known-folder create-child grants tolerated while still refusing an untrusted
// write ACE on the directory it is about to write into.
//
// This does NOT consult PlatformInstallerOwnedPath — deciding which elements are
// eligible for the downgrade belongs to the walk, which is the only code that
// knows an element's position. Every caller must pass advisory=true only for an
// ancestor inside PlatformInstallerOwnedRoots; passing it for an arbitrary
// ancestor would let a foreign writable directory above the artifact pass
// validation.
func relaxAncestorTrustVerdict(advisory bool, path, label string, verdict error) error {
	if verdict == nil {
		return nil
	}
	if !advisory || trustStrictAncestors() {
		return verdict
	}
	reportTrustAdvisory(path, label, verdict.Error())
	return nil
}

func reportTrustAdvisory(path, label, reason string) {
	if hook := ReportTrustAdvisory; hook != nil {
		hook(path, label, reason)
		return
	}
	log.Printf(
		"%s: %s ancestor %s is not provably trusted, continuing (permissions are owned by the platform installer): %s",
		TrustAdvisoryMarker, label, path, reason,
	)
}

// trustVerdict marks a permission judgement — an owner, mode, or ACL that
// cannot be proven trusted — as opposed to a structural failure (missing path,
// symlink, wrong type) or an OS API failure. Only judgements are downgradable
// for ancestors, so helpers that mix both kinds of failure in one error return
// tag the judgement half with this type.
type trustVerdict struct{ err error }

func (v trustVerdict) Error() string { return v.err.Error() }

func (v trustVerdict) Unwrap() error { return v.err }

func newTrustVerdict(format string, args ...any) error {
	return trustVerdict{err: fmt.Errorf(format, args...)}
}

func isTrustVerdict(err error) bool {
	var verdict trustVerdict
	return errors.As(err, &verdict)
}

// relaxAncestorTrustJudgement is relaxAncestorTrustVerdict for an error that
// may or may not be a permission judgement: structural and API failures pass
// through untouched even for an ancestor.
func relaxAncestorTrustJudgement(advisory bool, path, label string, err error) error {
	if err == nil || !isTrustVerdict(err) {
		return err
	}
	return relaxAncestorTrustVerdict(advisory, path, label, err)
}

func trustStrictAncestors() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(TrustStrictAncestorsEnv))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
