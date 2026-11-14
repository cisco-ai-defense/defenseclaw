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
// names a launch folder. The folders stay on disk: sessions that read their
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
}

type windowsHookImageRetireReport struct {
	SchemaVersion int                         `json:"schema_version"`
	OK            bool                        `json:"ok"`
	Reason        string                      `json:"reason"`
	Error         string                      `json:"error"`
	Marker        string                      `json:"marker"`
	Rewritten     []string                    `json:"rewritten"`
	StillNamed    []windowsHookImageNamedFile `json:"still_named"`
	Notes         []string                    `json:"notes,omitempty"`
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
	Now             func() time.Time
	Sleep           func(time.Duration)
	Wait, Poll      time.Duration
}

func retireWindowsHookImages(steps windowsHookImageRetireSteps) windowsHookImageRetireReport {
	report := windowsHookImageRetireReport{
		SchemaVersion: windowsHookImageReportSchema,
		Rewritten:     []string{},
		StillNamed:    []windowsHookImageNamedFile{},
	}
	fail := func(reason, format string, args ...any) windowsHookImageRetireReport {
		report.OK = false
		report.Reason = reason
		report.Error = fmt.Sprintf(format, args...)
		return report
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
	marker := windowsHookImageJoin(root, winpath.EnterpriseHookImagesRetiredMarker)
	report.Marker = marker
	if _, err := steps.FS.Lstat(marker); errors.Is(err, fs.ErrNotExist) {
		body, _ := json.Marshal(struct {
			SchemaVersion int    `json:"schema_version"`
			RetiredAt     string `json:"retired_at"`
		}{1, steps.Now().UTC().Format(time.RFC3339)})
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
		if len(after.Incomplete) == 0 && len(after.NamedBySystem()) == 0 {
			break
		}
		if !steps.Now().Before(deadline) {
			break
		}
		steps.Sleep(steps.Poll)
	}
	// Only the machine files decide: the older release's Setup reads those.
	// An account file that still names a folder is the guardian's to
	// rewrite when it reaches that account; it is reported, not waited for.
	still := map[string]bool{}
	for folder, files := range after.Named {
		for _, file := range files {
			still[strings.ToLower(file)] = true
			if after.UserFiles[strings.ToLower(file)] {
				report.Notes = append(report.Notes, fmt.Sprintf("still_named_by_account_file: %s names %s (the guardian rewrites it at that account's next pass)", file, folder))
				continue
			}
			report.StillNamed = append(report.StillNamed, windowsHookImageNamedFile{File: file, Folder: folder})
		}
	}
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
		return fail(windowsHookImageRetirePending, "%s", withWriterErrors(fmt.Sprintf("%d machine file(s) still name a launch folder after %s; run retire again before the older Setup", len(report.StillNamed), steps.Wait)))
	}
	report.OK = true
	report.Error = strings.Join(writerErrors, "; ")
	return report
}
