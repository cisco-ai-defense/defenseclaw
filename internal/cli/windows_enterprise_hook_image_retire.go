// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// Retiring the launch folders (GAP-0751 review 1 P1-1). Releases 1.0.9 and
// earlier know only the transition path bin\defenseclaw-hook.exe: their
// Setup compares the hook path in the Codex requirements, the Codex runtime
// state and the Claude managed policy exactly with that path, so a rollback
// with the older Setup /upgrade over configs that name bin\hooks\<d16>
// refuses ("belongs to another protected layout/deployment") and rolls back
// to this release. `enterprise windows hook-image retire`, run by an
// administrator before that rollback, writes bin\hooks\.retired (every writer
// then names the transition set again), has the Codex requirements and the
// guardian rewrite every config, and waits until no DefenseClaw-written file
// names a launch folder: the machine files the older Setup compares and the
// enrolled accounts' own agent configs, which the older guardian owns only
// in the form it renders itself (rel-1-0-10 GAP-0794: it failed a Copilot,
// Hermes and OpenCode account that still named a launch folder, and the
// older Setup /upgrade ended 1603 with every service stopped). The folders stay on disk: sessions that read their
// hook command earlier still start them. This release's next stage removes
// the marker.

// Reason codes of a retire that did not finish.
const (
	// windowsHookImageRetireRefused: nothing changed (the transition images
	// are not the recorded ones, or the install is not a standalone one).
	windowsHookImageRetireRefused = "hook_image_retire_refused"
	// windowsHookImageRetirePending: the marker is written, but some file
	// still names a launch folder; run retire again once the guardian could
	// reach it (for example after the account signs in).
	windowsHookImageRetirePending = "hook_image_retire_pending"
)

// The state bin\hooks\.retired records of the last retire. The marker is a
// progress marker: it is what makes every writer name the transition set,
// so it is written before the writers run and stays while retire is
// pending (removing it would turn the configs of the accounts already
// converted back to the launch folder). Status and verify report a pending
// one as hook_image_retire_pending, not as retired, so it is never read as
// a finished retire (rel-1-0-10 GAP-1158). An older release's Setup does
// not read the marker; this release's Setup stage removes it.
const (
	windowsHookImageRetireStatePending = "pending"
	windowsHookImageRetireStateOK      = "ok"
)

// windowsHookImageRetireWait bounds the wait for the guardian's rewrite.
const (
	windowsHookImageRetireWait = 3 * time.Minute
	windowsHookImageRetirePoll = 5 * time.Second
)

type windowsHookImageNamedFile struct {
	File   string `json:"file"`
	Folder string `json:"folder"`
	// Account marks an enrolled account's own file: only the guardian,
	// in that account's Windows session, rewrites it.
	Account bool `json:"account,omitempty"`
	// Cause is, for a machine file retire left pending on, the writer error
	// that kept it from being rewritten (rel-1-0-10 GAP-0856), and for an
	// unreadable account file why it could not be read.
	Cause string `json:"cause,omitempty"`
	// Unreadable marks an account file retire could not read or vouch for:
	// it may name a launch folder (Folder is "unknown"), so retire does not
	// end ok over it (rel-1-0-10 GAP-0882).
	Unreadable bool `json:"unreadable,omitempty"`
}

// windowsHookImageSignedOutProfile is an enrolled account whose runtime
// selections named a launch folder while it was signed out: the guardian
// cannot rewrite them before it signs in, so retire dropped them
// (enterprisehooks.DeselectWindowsStandaloneSignedOutLaunchSelections).
type windowsHookImageSignedOutProfile struct {
	SID        string   `json:"sid"`
	Account    string   `json:"account,omitempty"`
	Connectors []string `json:"connectors"`
}

// windowsHookImageDeselection is the result of retire's runtime selector
// step: the signed-out accounts whose launch-folder selections it dropped
// and, by selector file (lower case), why one could not be dropped; Error is
// a failure that kept the step from reading any selector.
type windowsHookImageDeselection struct {
	Profiles []windowsHookImageSignedOutProfile
	Errors   map[string]string
	Error    string
}

type windowsHookImageRetireReport struct {
	SchemaVersion int                         `json:"schema_version"`
	OK            bool                        `json:"ok"`
	Reason        string                      `json:"reason"`
	Error         string                      `json:"error"`
	Marker        string                      `json:"marker"`
	Rewritten     []string                    `json:"rewritten"`
	StillNamed    []windowsHookImageNamedFile `json:"still_named"`
	// SkippedProfiles are the enrolled profiles the administrator skipped
	// (--skip-profile) whose own configs still name a launch folder; each
	// is audited and recorded in the marker.
	SkippedProfiles []windowsHookImageSkippedProfile `json:"skipped_profiles"`
	// SignedOutProfiles are the enrolled accounts that were signed out and
	// whose runtime selections retire took off the launch folder; each is
	// pending until it signs in. They do not hold retire back.
	SignedOutProfiles []windowsHookImageSignedOutProfile `json:"signed_out_profiles"`
	Notes             []string                           `json:"notes,omitempty"`
}

// windowsHookImageProfile is an enrolled account of the guardian's manifest.
type windowsHookImageProfile struct {
	Account string
	Home    string
}

// windowsHookImageSkippedProfile is one profile retire skipped: who skipped
// it and when, and its files that still named a launch folder then.
type windowsHookImageSkippedProfile struct {
	SID       string                      `json:"sid"`
	Account   string                      `json:"account,omitempty"`
	Home      string                      `json:"home"`
	SkippedBy string                      `json:"skipped_by"`
	SkippedAt string                      `json:"skipped_at"`
	Files     []windowsHookImageNamedFile `json:"files"`
}

// windowsHookImageRetireMarker is the body of bin\hooks\.retired. Status
// and verify read SkippedProfiles (windowsHookImageSkippedProfileIssues);
// the next stage of this release removes the marker.
type windowsHookImageRetireMarker struct {
	SchemaVersion int    `json:"schema_version"`
	RetiredAt     string `json:"retired_at"`
	// State is how the last retire ended: windowsHookImageRetireStatePending
	// or windowsHookImageRetireStateOK. A marker written before the field
	// existed has none and reads as retired.
	State           string                           `json:"state,omitempty"`
	SkippedProfiles []windowsHookImageSkippedProfile `json:"skipped_profiles,omitempty"`
}

// windowsHookImageRetireSteps are the effects retire uses; the Windows
// command supplies the real ones.
type windowsHookImageRetireSteps struct {
	FS  windowsHookImageFS
	Bin string
	// RecordedSHA256 is the deployment record's digest of an artifact
	// ("hook", "hook_guard"); "" when the record has none.
	RecordedSHA256 func(artifact string) (string, error)
	WriteMarker    func(path string, body []byte) error
	ReconcileCodex func() error
	// DeselectSignedOut drops the launch-folder runtime selections of the
	// enrolled accounts the guardian cannot repair now (signed out); nil
	// skips the step.
	DeselectSignedOut func() windowsHookImageDeselection
	RestartGuardian   func() error
	// GuardianFailures are the guardian's failed rows of its last reconcile,
	// as status words them; nil when unknown.
	GuardianFailures func() []string
	Scan             func() windowsHookImageConfigScan
	// RouteOnlyRouted lists the agents the installed config routes with
	// route-only (managedRouteOnlyConnectors); nil skips the check.
	RouteOnlyRouted func() ([]string, error)
	// SkipProfiles are the SIDs the administrator named with --skip-profile.
	// Profiles lists the enrolled profiles by SID; Actor names who runs
	// retire; Audit writes the audit row of one skip; ReadMarker reads the
	// marker. Only used when SkipProfiles is not empty.
	SkipProfiles []string
	Profiles     func() (map[string]windowsHookImageProfile, error)
	Actor        func() string
	// CallerSystem reports whether retire runs as LocalSystem; nil is
	// not. A skip of a profile whose only holds are files the caller was
	// denied is refused unless it does (rel-1-0-10 GAP-0907).
	CallerSystem func() bool
	Audit        func(windowsHookImageSkippedProfile) error
	// ReadMarker also reads the marker to record how retire ended (State);
	// nil leaves the state as first written (pending).
	ReadMarker func(path string) ([]byte, error)
	Now        func() time.Time
	Sleep      func(time.Duration)
	Wait, Poll time.Duration
}

func retireWindowsHookImages(steps windowsHookImageRetireSteps) windowsHookImageRetireReport {
	report := windowsHookImageRetireReport{
		SchemaVersion:     windowsHookImageReportSchema,
		Rewritten:         []string{},
		StillNamed:        []windowsHookImageNamedFile{},
		SkippedProfiles:   []windowsHookImageSkippedProfile{},
		SignedOutProfiles: []windowsHookImageSignedOutProfile{},
	}
	fail := func(reason, format string, args ...any) windowsHookImageRetireReport {
		report.OK = false
		report.Reason = reason
		report.Error = fmt.Sprintf(format, args...)
		return report
	}
	// A Setup before 1.0.10 has no route-only listener and does not take
	// back the route settings the guardian wrote into each enrolled
	// account, so their agents got 401 or connection refused after the
	// rollback (rel-1-0-10 GAP-0647). Retire is the step before that Setup:
	// it refuses while routing is on, before anything changes.
	if steps.RouteOnlyRouted != nil {
		routed, err := steps.RouteOnlyRouted()
		switch {
		case err != nil:
			report.Notes = append(report.Notes, "route_only_unchecked: the installed config could not be read to check route-only routing ("+err.Error()+
				"); before the older Setup, make sure routing.route_only.connectors is empty and no account reports route_config_drift in enterprise windows verify")
		case len(routed) > 0:
			list := strings.Join(routed, ", ")
			return fail(windowsHookImageRetireRefused, "route-only routing is on for %s, and a Setup before 1.0.10 has no route-only listener and does not take back the route settings "+
				"the guardian wrote for each enrolled account: their agents would get 401 or connection refused. Turn routing off first: remove %s from "+
				"routing.route_only.connectors (or set routing.enabled: false) in the config or the signed bundle and apply it (`%s CONFIG=<config> JSON=1`), "+
				"wait until `enterprise windows verify` reports no route_config_drift (the guardian takes the settings back as each account), then run retire again. "+
				"Nothing was changed", list, list, managed.WindowsSetupCommand("/ensure"))
		}
	}
	bin := strings.TrimRight(strings.TrimSpace(steps.Bin), `\`)
	root := winpath.EnterpriseHookImagesRoot(bin)
	info, err := steps.FS.Lstat(root)
	if errors.Is(err, fs.ErrNotExist) {
		report.OK = true
		report.Notes = append(report.Notes, "no launch folders under "+root+": every config already names the transition image")
		return report
	}
	if err != nil {
		return fail(windowsHookImageRetireRefused, "inspect %s: %v", root, err)
	}
	if !windowsHookImagePlainDir(info) {
		return fail(windowsHookImageRetireRefused, "%s is not a plain folder", root)
	}
	// The transition images are what every config will name: they must be
	// the installed release's, the bytes the guardian keeps.
	for _, item := range []struct{ artifact, name string }{
		{"hook", winpath.EnterpriseHookImageName},
		{"hook_guard", winpath.EnterpriseHookGuardImageName},
	} {
		path := windowsHookImageJoin(bin, item.name)
		want, err := steps.RecordedSHA256(item.artifact)
		if err != nil {
			return fail(windowsHookImageRetireRefused, "read the deployment record's %s digest: %v", item.artifact, err)
		}
		if want == "" {
			if item.artifact == "hook" {
				return fail(windowsHookImageRetireRefused, "the deployment record has no hook digest; run `%s` of this release first. %s", managed.WindowsSetupCommand("/repair", "JSON=1"), managed.WindowsSetupSource)
			}
			continue
		}
		have, err := steps.FS.SHA256(path)
		if err != nil {
			return fail(windowsHookImageRetireRefused, "read %s: %v", path, err)
		}
		if !strings.EqualFold(have, want) {
			return fail(windowsHookImageRetireRefused, "%s has sha256 %s, not the recorded %s; run `%s` of this release first, then retire again. %s", path, have, want, managed.WindowsSetupCommand("/repair", "JSON=1"), managed.WindowsSetupSource)
		}
	}
	before := steps.Scan()
	skip, profiles, err := windowsHookImageRetireSkipSet(steps, before)
	if err != nil {
		return fail(windowsHookImageRetireRefused, "%v. Nothing was changed", err)
	}
	marker := windowsHookImageJoin(root, winpath.EnterpriseHookImagesRetiredMarker)
	report.Marker = marker
	// The marker says pending before any writer runs, and ok only once this
	// retire ends ok: a retire over the marker of an earlier ok retire that
	// is stopped part way must not leave it saying ok (GAP-1158).
	if _, err := steps.FS.Lstat(marker); errors.Is(err, fs.ErrNotExist) {
		body, _ := json.Marshal(windowsHookImageRetireMarker{SchemaVersion: 1, RetiredAt: steps.Now().UTC().Format(time.RFC3339),
			State: windowsHookImageRetireStatePending})
		if err := steps.WriteMarker(marker, append(body, '\n')); err != nil {
			return fail(windowsHookImageRetireRefused, "write %s: %v", marker, err)
		}
	} else if err != nil {
		return fail(windowsHookImageRetireRefused, "inspect %s: %v", marker, err)
	} else if err := windowsHookImageRecordRetireState(steps, marker, windowsHookImageRetireStatePending); err != nil {
		return fail(windowsHookImageRetireRefused, "record in %s that retire is pending: %v. Nothing was changed", marker, err)
	}
	// From here the writers name the transition set: have them write. A
	// writer that failed is named in the report's error and, for each file
	// it left naming a launch folder, in that file's cause (the scan below
	// still decides ok or pending). The Codex requirements go first: the
	// guardian's pass refuses a requirements file that names another managed
	// folder than the one it resolves. Then the selections of signed-out
	// accounts, which only the account's own install publishes, so the
	// guardian's pass after the restart finds them pending, not failed
	// (rel-1-0-10 GAP-0856).
	var writerErrors []string
	var codexErr, guardianErr string
	if err := steps.ReconcileCodex(); err != nil {
		codexErr = err.Error()
		writerErrors = append(writerErrors, "Codex requirements reconcile: "+codexErr)
	}
	var deselection windowsHookImageDeselection
	if steps.DeselectSignedOut != nil {
		deselection = steps.DeselectSignedOut()
		for _, profile := range deselection.Profiles {
			report.SignedOutProfiles = append(report.SignedOutProfiles, profile)
			account := profile.Account
			if account == "" {
				account = profile.SID
			}
			report.Notes = append(report.Notes, fmt.Sprintf("signed_out: %s (%s): its %s runtime selection named a launch folder, "+
				"and the guardian cannot rewrite it while the account is signed out. Retire dropped it: the account has no runtime "+
				"selected until it signs in, and the guardian then installs the transition hook in its session (under an older "+
				"release, that release's guardian does)", account, profile.SID, strings.Join(profile.Connectors, ", ")))
		}
	}
	if err := steps.RestartGuardian(); err != nil {
		guardianErr = err.Error()
		writerErrors = append(writerErrors, "guardian restart: "+guardianErr)
	}
	report.Notes = append(report.Notes, writerErrors...)
	withWriterErrors := func(text string) string {
		if len(writerErrors) == 0 {
			return text
		}
		return text + " (" + strings.Join(writerErrors, "; ") + ")"
	}
	deadline := steps.Now().Add(steps.Wait)
	var after windowsHookImageConfigScan
	for {
		after = steps.Scan()
		if len(after.Incomplete) == 0 && len(windowsHookImageBlockingNamedFiles(after, skip)) == 0 &&
			windowsHookImageBlockingUnverified(after, skip) == 0 {
			break
		}
		if !steps.Now().Before(deadline) {
			break
		}
		steps.Sleep(steps.Poll)
	}
	// Every file decides: the older release's Setup compares the machine
	// files, and its guardian refuses an account's agent config that names a
	// launch folder (a Copilot hook file it did not write, a tampered Hermes
	// command), fails that account and so the older Setup (GAP-0794).
	still := map[string]bool{}
	accountFiles, unreadable := 0, 0
	skipped := map[string][]windowsHookImageNamedFile{}
	for folder, files := range after.Named {
		for _, file := range files {
			key := strings.ToLower(file)
			still[key] = true
			account := after.UserFiles[key]
			named := windowsHookImageNamedFile{File: file, Folder: folder, Account: account}
			if sid := after.FileSIDs[key]; account && skip[sid] {
				skipped[sid] = append(skipped[sid], named)
				continue
			}
			if account {
				accountFiles++
			}
			report.StillNamed = append(report.StillNamed, named)
		}
	}
	// An account file the scan could not read or vouch for may name a
	// launch folder: it holds retire back like one that does, and a skip of
	// its profile covers it (rel-1-0-10 GAP-0882).
	for _, file := range after.Unverified {
		key := strings.ToLower(file.File.Path)
		if still[key] {
			continue
		}
		still[key] = true
		named := windowsHookImageNamedFile{File: file.File.Path, Folder: windowsHookImageUnknownFolder, Account: true, Unreadable: true,
			Cause: windowsHookImageUnverifiedCause(file)}
		if sid := file.File.SID; sid != "" && skip[sid] {
			skipped[sid] = append(skipped[sid], named)
			continue
		}
		unreadable++
		report.StillNamed = append(report.StillNamed, named)
	}
	// Each skip is audited before it is recorded; one the audit store did
	// not take blocks retire like any other account file.
	var auditErrors []string
	if len(skipped) > 0 {
		recorded, failures := windowsHookImageRecordSkips(steps, marker, skipped, profiles)
		report.SkippedProfiles = recorded
		for sid, failure := range failures {
			auditErrors = append(auditErrors, fmt.Sprintf("the skip of %s was not recorded: %s", sid, failure))
			report.StillNamed = append(report.StillNamed, skipped[sid]...)
			for _, named := range skipped[sid] {
				if named.Unreadable {
					unreadable++
				} else {
					accountFiles++
				}
			}
		}
		sort.Strings(auditErrors)
	}
	for sid := range skip {
		if _, ok := skipped[sid]; !ok {
			report.Notes = append(report.Notes, "skip_not_needed: "+sid+" no longer names a launch folder (the guardian rewrote its configs while retire waited); it was not skipped")
		}
	}
	sort.Strings(report.Notes)
	sort.Slice(report.StillNamed, func(i, j int) bool {
		if report.StillNamed[i].File != report.StillNamed[j].File {
			return report.StillNamed[i].File < report.StillNamed[j].File
		}
		return report.StillNamed[i].Folder < report.StillNamed[j].Folder
	})
	rewritten := map[string]bool{}
	for _, files := range before.Named {
		for _, file := range files {
			if !still[strings.ToLower(file)] && !rewritten[strings.ToLower(file)] {
				rewritten[strings.ToLower(file)] = true
				report.Rewritten = append(report.Rewritten, file)
			}
		}
	}
	sort.Strings(report.Rewritten)
	// The marker records how this retire ended, so status never reads a
	// pending one as finished (GAP-1158).
	recordState := func(state string) {
		if err := windowsHookImageRecordRetireState(steps, marker, state); err != nil {
			report.Notes = append(report.Notes, "retire_state_not_recorded: "+marker+" could not record that retire ended "+state+": "+err.Error())
		}
	}
	for _, note := range after.Incomplete {
		report.Notes = append(report.Notes, "scan_incomplete: "+note)
	}
	if len(after.Incomplete) > 0 {
		recordState(windowsHookImageRetireStatePending)
		return fail(windowsHookImageRetirePending, "%s", withWriterErrors("some machine files could not be read, so it is not known whether they still name a launch folder; fix the reason in notes, then run retire again")+". "+windowsHookImageRetirePendingNextStep())
	}
	if len(report.StillNamed) > 0 {
		var guardianFailures []string
		if steps.GuardianFailures != nil {
			guardianFailures = steps.GuardianFailures()
		}
		var machineLines []string
		for i := range report.StillNamed {
			if report.StillNamed[i].Account {
				continue
			}
			report.StillNamed[i].Cause = windowsHookImageBlockCause(report.StillNamed[i].File, codexErr, guardianErr, deselection, guardianFailures, steps.Wait)
			machineLines = append(machineLines, report.StillNamed[i].File+" ("+report.StillNamed[i].Cause+")")
		}
		var parts []string
		if len(machineLines) > 0 {
			parts = append(parts, fmt.Sprintf("%d machine file(s) still name a launch folder after %s: %s", len(machineLines), steps.Wait, strings.Join(machineLines, "; ")))
		}
		if accountFiles > 0 {
			parts = append(parts, fmt.Sprintf("%d agent config(s) of enrolled accounts still name a launch folder after %s (still_named entries with account true). "+
				"The guardian rewrites an account's own configs only in that account's Windows session, and the older release's guardian "+
				"refuses a hook config that names a launch folder, fails that account and stops the older Setup with 1603. "+
				"Have each of those accounts sign in (the guardian rewrites its configs within about a minute), or remove the account with its profile, "+
				"then run retire again", accountFiles, steps.Wait))
		}
		if unreadable > 0 {
			parts = append(parts, fmt.Sprintf("%d agent config(s) of enrolled accounts could not be read or verified (still_named entries with unreadable true; "+
				"each cause says why), so it is not known whether they name a launch folder. An elevated administrator is denied some "+
				"account folders: run retire as LocalSystem, or fix the cause, then run retire again", unreadable))
		}
		if accountFiles > 0 || unreadable > 0 {
			parts[len(parts)-1] += "; an administrator who accepts that a profile stays unconverted can name it with --skip-profile <SID> (audited, and listed by enterprise windows status and verify until it is converted)"
		}
		parts = append(parts, auditErrors...)
		recordState(windowsHookImageRetireStatePending)
		return fail(windowsHookImageRetirePending, "%s", strings.Join(parts, "; ")+". "+windowsHookImageRetirePendingNextStep())
	}
	recordState(windowsHookImageRetireStateOK)
	report.OK = true
	report.Error = strings.Join(writerErrors, "; ")
	return report
}

// windowsHookImageRecordRetireState records state in the marker, keeping
// its skips; a marker that already records it is not written again. A
// marker that does not parse (cut short by a crash, edited) records no state
// and no skips: recording pending replaces it with a fresh pending body
// rather than refusing every later retire; any other state leaves it, and
// status reads it as pending.
func windowsHookImageRecordRetireState(steps windowsHookImageRetireSteps, marker, state string) error {
	if steps.ReadMarker == nil {
		return nil
	}
	current, err := steps.ReadMarker(marker)
	if err != nil {
		return err
	}
	var body windowsHookImageRetireMarker
	if err := json.Unmarshal(current, &body); err != nil {
		if state != windowsHookImageRetireStatePending {
			return err
		}
		body = windowsHookImageRetireMarker{SchemaVersion: 1, RetiredAt: steps.Now().UTC().Format(time.RFC3339)}
	}
	if body.State == state {
		return nil
	}
	body.State = state
	data, _ := json.Marshal(body)
	return steps.WriteMarker(marker, append(data, '\n'))
}

// windowsHookImageRetiredIssues are the status and verify warnings of an
// install whose launch folders are retired (problem is the resolver's
// line): hook_image_retire_pending when the marker records that the last
// retire ended pending (GAP-1158), else hook_image_retired, then the
// skipped profiles (windowsHookImageSkippedProfileIssues). A marker that
// cannot be read gives hook_image_retired alone; one that does not parse
// records no finished retire and reads as pending.
func windowsHookImageRetiredIssues(problem string, marker []byte, markerErr error, bin string,
	read func(windowsHookImageConfigFile) ([]byte, error), callerDenied func(error) bool) []windowsHookImageStatusIssue {
	if markerErr != nil {
		return []windowsHookImageStatusIssue{{Code: "hook_image_retired", Text: problem}}
	}
	var body windowsHookImageRetireMarker
	issue := windowsHookImageStatusIssue{Code: "hook_image_retired", Text: problem}
	why := "the last retire ended pending"
	parseErr := json.Unmarshal(marker, &body)
	if parseErr != nil {
		why = "the retire marker does not parse, so it does not record that the last retire ended ok"
	}
	if parseErr != nil || body.State == windowsHookImageRetireStatePending {
		issue = windowsHookImageStatusIssue{Code: windowsHookImageRetirePending, Text: "hook-image retire has not finished: " + problem +
			", but " + why + ", so some file DefenseClaw wrote may still name a launch folder. Run " +
			"`enterprise windows hook-image retire` again until it ends ok. " + windowsHookImageRetirePendingNextStep()}
	}
	return append([]windowsHookImageStatusIssue{issue}, windowsHookImageSkippedProfileIssues(marker, bin, read, callerDenied)...)
}

// windowsHookImageRetirePendingNextStep is what an administrator does when
// retire ends pending. An older Setup run now fails with 1603 and leaves the
// DefenseClaw services stopped and disabled (rel-1-0-10 GAP-0794, GAP-0856).
func windowsHookImageRetirePendingNextStep() string {
	return "Do NOT run an older release's Setup while retire reports pending: it fails with 1603 and leaves the DefenseClaw services " +
		"stopped and disabled. Fix the cause named for each file, then run retire again until it ends ok. If an older Setup already " +
		"failed, recover with this release's `" + managed.WindowsSetupCommand("/ensure") + "`"
}

// windowsHookImageMachineFileWriter names the step that rewrites a machine
// file retire scans: the runtime selector step ("selector"), the Codex
// requirements reconcile ("codex"), or the guardian ("guardian").
func windowsHookImageMachineFileWriter(path string) string {
	lower := strings.ToLower(strings.ReplaceAll(path, "/", `\`))
	base := lower[strings.LastIndex(lower, `\`)+1:]
	switch {
	case base == ".defenseclaw-managed-runtime-selector.state":
		return "selector"
	case base == "codex-requirements-ownership.json" || strings.Contains(lower, `\openai\codex\`):
		return "codex"
	}
	return "guardian"
}

// windowsHookImageBlockCause is why a machine file still names a launch
// folder: the error of the step that rewrites it, else the guardian's.
func windowsHookImageBlockCause(file, codexErr, guardianErr string, deselection windowsHookImageDeselection,
	guardianFailures []string, wait time.Duration) string {
	switch windowsHookImageMachineFileWriter(file) {
	case "selector":
		if err := deselection.Errors[strings.ToLower(file)]; err != "" {
			return "the runtime selection of a signed-out account could not be dropped: " + err
		}
		if deselection.Error != "" {
			return "the runtime selections of signed-out accounts could not be dropped: " + deselection.Error
		}
	case "codex":
		if codexErr != "" {
			return "Codex requirements reconcile: " + codexErr
		}
	}
	if guardianErr != "" {
		return "guardian restart: " + guardianErr
	}
	if len(guardianFailures) > 0 {
		shown := guardianFailures
		more := ""
		if len(shown) > 3 {
			more = fmt.Sprintf("; and %d more (enterprise windows status)", len(shown)-3)
			shown = shown[:3]
		}
		return fmt.Sprintf("the guardian did not rewrite it within %s: %s%s", wait, strings.Join(shown, "; "), more)
	}
	return fmt.Sprintf("the guardian did not rewrite it within %s and recorded no failed target; read the guardian log "+
		"and enterprise windows status, then run retire again", wait)
}

// windowsHookImageUnverifiedCause is the still_named cause of an account
// file the scan could not read or vouch for.
func windowsHookImageUnverifiedCause(file windowsHookImageUnverifiedFile) string {
	cause := "could not be read or verified, so it may name a launch folder: " + file.Err
	if file.File.Note != "" {
		cause += " (" + file.File.Note + ")"
	}
	return cause
}

// windowsHookImageRetireSkipSet checks the --skip-profile SIDs before
// anything changes: each must be a SID, an enrolled profile of the
// guardian's manifest, and one whose own agent configs name a launch folder
// now (before), or could not be read, so it is what holds retire back. There
// is no blanket skip.
func windowsHookImageRetireSkipSet(steps windowsHookImageRetireSteps, before windowsHookImageConfigScan) (map[string]bool, map[string]windowsHookImageProfile, error) {
	if len(steps.SkipProfiles) == 0 {
		return nil, nil, nil
	}
	if steps.Profiles == nil || steps.Audit == nil || steps.Actor == nil || steps.ReadMarker == nil {
		return nil, nil, errors.New("--skip-profile is not available here")
	}
	profiles, err := steps.Profiles()
	if err != nil {
		return nil, nil, fmt.Errorf("--skip-profile needs the enrolled profiles of the guardian's manifest, which could not be read: %w", err)
	}
	// A profile holds retire back with a file that names a launch folder
	// (named), one it could not read for another reason (unverified), or
	// one the caller's token was denied (denied).
	blocking, named, unverified := map[string]bool{}, map[string]bool{}, map[string]bool{}
	denied := map[string][]string{}
	for key := range windowsHookImageBlockingNamedFiles(before, nil) {
		if sid := before.FileSIDs[key]; sid != "" && before.UserFiles[key] {
			blocking[strings.ToUpper(sid)] = true
			named[strings.ToUpper(sid)] = true
		}
	}
	for _, file := range before.Unverified {
		if sid := strings.ToUpper(strings.TrimSpace(file.File.SID)); sid != "" {
			blocking[sid] = true
			if file.Denied {
				denied[sid] = append(denied[sid], file.File.Path)
			} else {
				unverified[sid] = true
			}
		}
	}
	system := steps.CallerSystem != nil && steps.CallerSystem()
	skip := map[string]bool{}
	for _, raw := range steps.SkipProfiles {
		sid := strings.ToUpper(strings.TrimSpace(raw))
		if !windowsHookImageSIDPattern.MatchString(sid) {
			return nil, nil, fmt.Errorf("--skip-profile %q is not a Windows SID (S-1-5-21-...); name each profile by its SID, as still_named and enterprise windows status show it", raw)
		}
		canonical := ""
		for enrolled := range profiles {
			if strings.EqualFold(enrolled, sid) {
				canonical = enrolled
			}
		}
		if canonical == "" {
			return nil, nil, fmt.Errorf("--skip-profile %s is not an enrolled profile of this computer's guardian manifest", sid)
		}
		if !blocking[sid] {
			return nil, nil, fmt.Errorf("--skip-profile %s does not hold retire back: none of its own agent configs names a launch folder; run retire without it", canonical)
		}
		// An elevated administrator is denied some account folders that
		// LocalSystem reads (the Codex and Copilot ones): such a profile is
		// not known to hold retire back, so skipping it would record a
		// healthy, converted account as unconverted (rel-1-0-10 GAP-0907).
		if !system && !named[sid] && !unverified[sid] && len(denied[sid]) > 0 {
			sort.Strings(denied[sid])
			return nil, nil, fmt.Errorf("--skip-profile %s: retire, run as %s, was denied access to %s, so it is not known whether that profile holds retire back "+
				"(an elevated administrator is denied some account folders). Run retire as LocalSystem, which reads them, and skip the profile only if it "+
				"still holds retire back then", canonical, steps.Actor(), strings.Join(denied[sid], ", "))
		}
		skip[canonical] = true
	}
	return skip, profiles, nil
}

var windowsHookImageSIDPattern = lazyregexp.New(`^S-1-[0-9]+(-[0-9]+)+$`)

// windowsHookImageRetireSkipActivity is the HIGH audit row of one skipped
// profile (GAP-0794 review F4), an operator mutation of the managed hook
// state (config-update). actor is the audit actor of the account that ran
// retire in the form the audit record keeps (configwrite.CurrentOSActor:
// os:sid:<SID>:<DOMAIN/name>). The display form of SkippedBy
// ("DOMAIN\name (SID)") is not an audit actor: the record dropped it, so
// the row named nobody (rel-1-0-10 GAP-0906). after_state carries
// SkippedBy too, so the row alone answers who accepted the profile.
func windowsHookImageRetireSkipActivity(profile windowsHookImageSkippedProfile, actor string) map[string]any {
	return map[string]any{"kind": "activity", "activity": map[string]any{
		"actor":       actor,
		"action":      string(audit.ActionConfigUpdate),
		"target_type": "hook-image-retire-skip",
		"target_id":   profile.SID,
		"severity":    "HIGH",
		"before":      map[string]any{"account": profile.Account, "still_named": profile.Files},
		"after":       map[string]any{"skipped_at": profile.SkippedAt, "skipped_by": profile.SkippedBy, "retired": false},
	}}
}

// windowsHookImageProfileAccount names an enrolled profile for the report,
// the marker and the audit row: the manifest's user, else the SID's account
// (lookup), else "profile folder <name>": a folder name is not an account
// name (a renamed account keeps its folder), so it says what it is. The
// standalone manifest often has no user, and the skip row then had an empty
// account (GAP-0906).
func windowsHookImageProfileAccount(user, home string, lookup func() string) string {
	if user = strings.TrimSpace(user); user != "" {
		return user
	}
	if lookup != nil {
		if name := strings.TrimSpace(lookup()); name != "" {
			return name
		}
	}
	home = strings.TrimRight(strings.TrimSpace(home), `\/`)
	if folder := home[strings.LastIndexAny(home, `\/`)+1:]; folder != "" {
		return "profile folder " + folder
	}
	return ""
}

// windowsHookImageBlockingNamedFiles is the set of files (lower case) of the
// scan that name a launch folder, or may, and do not belong to a skipped
// profile.
func windowsHookImageBlockingNamedFiles(scan windowsHookImageConfigScan, skip map[string]bool) map[string]bool {
	out := map[string]bool{}
	for _, files := range scan.Named {
		for _, file := range files {
			key := strings.ToLower(file)
			if scan.UserFiles[key] && skip[scan.FileSIDs[key]] {
				continue
			}
			out[key] = true
		}
	}
	return out
}

// windowsHookImageBlockingUnverified counts the scan's unverified account
// files that do not belong to a skipped profile: retire waits on them too (a
// file held open can be read again; turev #6).
func windowsHookImageBlockingUnverified(scan windowsHookImageConfigScan, skip map[string]bool) int {
	count := 0
	for _, file := range scan.Unverified {
		if sid := file.File.SID; sid == "" || !skip[sid] {
			count++
		}
	}
	return count
}

// windowsHookImageRecordSkips audits each skipped profile and records the
// audited ones in the marker. It returns the recorded skips and, by SID,
// why a skip was not recorded.
func windowsHookImageRecordSkips(
	steps windowsHookImageRetireSteps,
	marker string,
	skipped map[string][]windowsHookImageNamedFile,
	profiles map[string]windowsHookImageProfile,
) ([]windowsHookImageSkippedProfile, map[string]string) {
	failures := map[string]string{}
	var body windowsHookImageRetireMarker
	current, err := steps.ReadMarker(marker)
	if err == nil {
		err = json.Unmarshal(current, &body)
	}
	if err != nil {
		for sid := range skipped {
			failures[sid] = fmt.Sprintf("read %s: %v", marker, err)
		}
		return []windowsHookImageSkippedProfile{}, failures
	}
	sids := make([]string, 0, len(skipped))
	for sid := range skipped {
		sids = append(sids, sid)
	}
	sort.Strings(sids)
	actor := steps.Actor()
	at := steps.Now().UTC().Format(time.RFC3339)
	recorded := []windowsHookImageSkippedProfile{}
	for _, sid := range sids {
		files := skipped[sid]
		sort.Slice(files, func(i, j int) bool { return files[i].File < files[j].File })
		profile := windowsHookImageSkippedProfile{
			SID: sid, Account: profiles[sid].Account, Home: profiles[sid].Home,
			SkippedBy: actor, SkippedAt: at, Files: files,
		}
		if err := steps.Audit(profile); err != nil {
			failures[sid] = "the audit row could not be written (" + err.Error() + "); start the DefenseClaw gateway service and run retire again"
			continue
		}
		kept := body.SkippedProfiles[:0]
		for _, entry := range body.SkippedProfiles {
			if !strings.EqualFold(entry.SID, sid) {
				kept = append(kept, entry)
			}
		}
		body.SkippedProfiles = append(kept, profile)
		recorded = append(recorded, profile)
	}
	if len(recorded) == 0 {
		return recorded, failures
	}
	data, _ := json.Marshal(body)
	if err := steps.WriteMarker(marker, append(data, '\n')); err != nil {
		for _, profile := range recorded {
			failures[profile.SID] = fmt.Sprintf("audited, but %s could not be written: %v", marker, err)
		}
		return []windowsHookImageSkippedProfile{}, failures
	}
	return recorded, failures
}

// windowsHookImageStatusIssue is one warning status and verify add.
type windowsHookImageStatusIssue struct {
	Code string
	Text string
}

// windowsHookImageSkippedProfileIssues returns, for status and verify, one
// issue per profile the retire marker records as skipped and that is not
// known to be converted: hook_image_profile_not_retired when a recorded file
// still names a launch folder of bin (or can no longer be read to tell), and
// hook_image_profile_unverified when the only files left unread are ones the
// caller was denied (callerDenied; nil when the caller is LocalSystem, which
// reads them): an Administrator's status listed a converted account as not
// retired because it was denied the account's folders (rel-1-0-10
// GAP-0907). A profile whose files no longer name one is converted and is
// not listed. Each file is read as the account's own, below its home.
func windowsHookImageSkippedProfileIssues(marker []byte, bin string, read func(windowsHookImageConfigFile) ([]byte, error), callerDenied func(error) bool) []windowsHookImageStatusIssue {
	var body windowsHookImageRetireMarker
	if err := json.Unmarshal(marker, &body); err != nil {
		return nil
	}
	var issues []windowsHookImageStatusIssue
	for _, profile := range body.SkippedProfiles {
		var still, unknown []string
		for _, named := range profile.Files {
			data, err := read(windowsHookImageConfigFile{Path: named.File, User: true, Home: profile.Home, SID: profile.SID})
			switch {
			case errors.Is(err, fs.ErrNotExist):
				continue
			case err != nil && callerDenied != nil && callerDenied(err):
				unknown = append(unknown, named.File)
			case err != nil:
				still = append(still, named.File+" (could not be read: "+err.Error()+")")
			case len(windowsHookImageFoldersNamedIn(data, bin)) > 0:
				still = append(still, named.File)
			}
		}
		account := profile.Account
		if account == "" {
			account = profile.SID
		}
		switch {
		case len(still) > 0:
			issues = append(issues, windowsHookImageStatusIssue{Code: "hook_image_profile_not_retired", Text: fmt.Sprintf(
				"%s (%s) is not retired: %s skipped it in hook-image retire at %s, and %s still name a launch folder, "+
					"so an older release's guardian fails this account; have it sign in (the guardian rewrites its configs), or remove it with its profile",
				account, profile.SID, profile.SkippedBy, profile.SkippedAt, strings.Join(still, ", "))})
		case len(unknown) > 0:
			issues = append(issues, windowsHookImageStatusIssue{Code: "hook_image_profile_unverified", Text: fmt.Sprintf(
				"%s (%s): %s skipped it in hook-image retire at %s; this account was denied reading %s, so status cannot tell whether it is converted. "+
					"Run enterprise windows status as LocalSystem to check it",
				account, profile.SID, profile.SkippedBy, profile.SkippedAt, strings.Join(unknown, ", "))})
		}
	}
	return issues
}
