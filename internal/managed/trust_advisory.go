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
