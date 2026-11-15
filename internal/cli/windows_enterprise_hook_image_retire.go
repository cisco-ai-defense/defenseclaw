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
	Notes           []string                         `json:"notes,omitempty"`
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
// and verify read SkippedProfiles (windowsHookImageSkippedProfilesNotRetired);
// the next stage of this release removes the marker.
type windowsHookImageRetireMarker struct {
	SchemaVersion   int                              `json:"schema_version"`
	RetiredAt       string                           `json:"retired_at"`
	SkippedProfiles []windowsHookImageSkippedProfile `json:"skipped_profiles,omitempty"`
}

// windowsHookImageRetireSteps are the effects retire uses; the Windows
// command supplies the real ones.
type windowsHookImageRetireSteps struct {
	FS  windowsHookImageFS
	Bin string
	// RecordedSHA256 is the deployment record's digest of an artifact
	// ("hook", "hook_guard"); "" when the record has none.
	RecordedSHA256  func(artifact string) (string, error)
	WriteMarker     func(path string, body []byte) error
	ReconcileCodex  func() error
	RestartGuardian func() error
	Scan            func() windowsHookImageConfigScan
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
	Audit        func(windowsHookImageSkippedProfile) error
	ReadMarker   func(path string) ([]byte, error)
	Now          func() time.Time
	Sleep        func(time.Duration)
	Wait, Poll   time.Duration
}

func retireWindowsHookImages(steps windowsHookImageRetireSteps) windowsHookImageRetireReport {
	report := windowsHookImageRetireReport{
		SchemaVersion:   windowsHookImageReportSchema,
		Rewritten:       []string{},
		StillNamed:      []windowsHookImageNamedFile{},
		SkippedProfiles: []windowsHookImageSkippedProfile{},
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
	if _, err := steps.FS.Lstat(marker); errors.Is(err, fs.ErrNotExist) {
		body, _ := json.Marshal(windowsHookImageRetireMarker{SchemaVersion: 1, RetiredAt: steps.Now().UTC().Format(time.RFC3339)})
		if err := steps.WriteMarker(marker, append(body, '\n')); err != nil {
			return fail(windowsHookImageRetireRefused, "write %s: %v", marker, err)
		}
	} else if err != nil {
		return fail(windowsHookImageRetireRefused, "inspect %s: %v", marker, err)
	}
	// From here the writers name the transition set: have them write. A
	// writer that failed is named in the report's error (and the scan below
	// still decides ok or pending).
	var writerErrors []string
	if err := steps.ReconcileCodex(); err != nil {
		writerErrors = append(writerErrors, "Codex requirements reconcile: "+err.Error())
	}
	if err := steps.RestartGuardian(); err != nil {
		writerErrors = append(writerErrors, "guardian restart: "+err.Error())
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
		if len(after.Incomplete) == 0 && len(windowsHookImageBlockingNamedFiles(after, skip)) == 0 {
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
	accountFiles := 0
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
	// Each skip is audited before it is recorded; one the audit store did
	// not take blocks retire like any other account file.
	var auditErrors []string
	if len(skipped) > 0 {
		recorded, failures := windowsHookImageRecordSkips(steps, marker, skipped, profiles)
		report.SkippedProfiles = recorded
		for sid, failure := range failures {
			auditErrors = append(auditErrors, fmt.Sprintf("the skip of %s was not recorded: %s", sid, failure))
			report.StillNamed = append(report.StillNamed, skipped[sid]...)
			accountFiles += len(skipped[sid])
		}
		sort.Strings(auditErrors)
	}
	for sid := range skip {
		if _, ok := skipped[sid]; !ok {
			report.Notes = append(report.Notes, "skip_not_needed: "+sid+" no longer names a launch folder (the guardian rewrote its configs while retire waited); it was not skipped")
		}
	}
	sort.Strings(report.Notes)
	for _, note := range after.Skipped {
		report.Notes = append(report.Notes, "skipped_unsafe: "+note)
	}
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
	for _, note := range after.Incomplete {
		report.Notes = append(report.Notes, "scan_incomplete: "+note)
	}
	if len(after.Incomplete) > 0 {
		return fail(windowsHookImageRetirePending, "%s", withWriterErrors("some machine files could not be read, so it is not known whether they still name a launch folder; fix the reason in notes, then run retire again"))
	}
	if len(report.StillNamed) > 0 {
		var parts []string
		if machine := len(report.StillNamed) - accountFiles; machine > 0 {
			parts = append(parts, fmt.Sprintf("%d machine file(s) still name a launch folder after %s", machine, steps.Wait))
		}
		if accountFiles > 0 {
			parts = append(parts, fmt.Sprintf("%d agent config(s) of enrolled accounts still name a launch folder after %s (still_named entries with account true). "+
				"The guardian rewrites an account's own configs only in that account's Windows session, and the older release's guardian "+
				"refuses a hook config that names a launch folder, fails that account and stops the older Setup with 1603. "+
				"Have each of those accounts sign in (the guardian rewrites its configs within about a minute), or remove the account with its profile, "+
				"then run retire again", accountFiles, steps.Wait))
		}
		if accountFiles > 0 {
			parts[len(parts)-1] += "; an administrator who accepts that a profile stays unconverted can name it with --skip-profile <SID> (audited, and listed by enterprise windows status and verify until it is converted)"
		}
		parts = append(parts, auditErrors...)
		return fail(windowsHookImageRetirePending, "%s", withWriterErrors(strings.Join(parts, "; ")+"; run the older Setup only after retire ends ok"))
	}
	report.OK = true
	report.Error = strings.Join(writerErrors, "; ")
	return report
}

// windowsHookImageRetireSkipSet checks the --skip-profile SIDs before
// anything changes: each must be a SID, an enrolled profile of the
// guardian's manifest, and one whose own agent configs name a launch folder
// now (before), so it is what holds retire back. There is no blanket skip.
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
	blocking := map[string]bool{}
	for key := range windowsHookImageBlockingNamedFiles(before, nil) {
		if sid := before.FileSIDs[key]; sid != "" && before.UserFiles[key] {
			blocking[strings.ToUpper(sid)] = true
		}
	}
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
		skip[canonical] = true
	}
	return skip, profiles, nil
}

var windowsHookImageSIDPattern = lazyregexp.New(`^S-1-[0-9]+(-[0-9]+)+$`)

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

// windowsHookImageSkippedProfilesNotRetired returns, for status and verify,
// one line per profile the retire marker records as skipped whose recorded
// files still name a launch folder of bin (or can no longer be read to
// tell). A profile whose files no longer name one is converted and is not
// listed. Each file is read as the account's own, below its home.
func windowsHookImageSkippedProfilesNotRetired(marker []byte, bin string, read func(windowsHookImageConfigFile) ([]byte, error)) []string {
	var body windowsHookImageRetireMarker
	if err := json.Unmarshal(marker, &body); err != nil {
		return nil
	}
	var lines []string
	for _, profile := range body.SkippedProfiles {
		var still []string
		for _, named := range profile.Files {
			data, err := read(windowsHookImageConfigFile{Path: named.File, User: true, Home: profile.Home, SID: profile.SID})
			switch {
			case errors.Is(err, fs.ErrNotExist):
				continue
			case err != nil:
				still = append(still, named.File+" (could not be read: "+err.Error()+")")
			case len(windowsHookImageFoldersNamedIn(data, bin)) > 0:
				still = append(still, named.File)
			}
		}
		if len(still) == 0 {
			continue
		}
		account := profile.Account
		if account == "" {
			account = profile.SID
		}
		lines = append(lines, fmt.Sprintf("%s (%s) is not retired: %s skipped it in hook-image retire at %s, and %s still name a launch folder, "+
			"so an older release's guardian fails this account; have it sign in (the guardian rewrites its configs), or remove it with its profile",
			account, profile.SID, profile.SkippedBy, profile.SkippedAt, strings.Join(still, ", ")))
	}
	return lines
}
