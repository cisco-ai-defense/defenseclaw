// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"slices"
	"sort"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// kiroTableForms turns a row into forms, the kiro-cli first, then the
// user's IDE, then the machine's.
func kiroTableForms(row kiroFormsTableRow) []KiroForm {
	var forms []KiroForm
	for _, kind := range []KiroFormKind{KiroFormCLI, KiroFormUserIDE, KiroFormMachineIDE} {
		value, ok := row.Forms[string(kind)]
		if !ok {
			continue
		}
		form := KiroForm{Kind: kind, Version: value}
		if value == kiroFormsTableUnreadable {
			form = KiroForm{Kind: kind, Unread: string(kind) + " is installed, but its version could not be read"}
		}
		forms = append(forms, form)
	}
	return forms
}

// One table for every installed Kiro form (rel-1-0-4 GAP-0895, GAP-0828,
// GAP-0829). Before AssessKiro each consumer judged Kiro on its own: a
// supported IDE hid an unreadable kiro-cli, an unreadable version passed
// action setup as not gated, and an unreadable IDE install was not reported
// at all. Each form is judged independently, unknown is not protected, and
// the managed installer's gates (the version setup and verify use) agree.
func TestKiroFormsTable(t *testing.T) {
	for _, row := range loadKiroFormsTable(t) {
		t.Run(row.Name, func(t *testing.T) {
			assessment := AssessKiro(kiroTableForms(row))
			if len(assessment.Forms) != len(row.Verdicts) {
				t.Fatalf("judged %d forms, want %d", len(assessment.Forms), len(row.Verdicts))
			}
			for _, verdict := range assessment.Forms {
				got := "protected"
				if !verdict.Protected {
					got = verdict.Code
					if verdict.Reason == "" {
						t.Errorf("%s: not protected without a reason", verdict.Form.Kind)
					}
				}
				if want := row.Verdicts[string(verdict.Form.Kind)]; got != want {
					t.Errorf("%s verdict = %s, want %s (%s)", verdict.Form.Kind, got, want, verdict.Reason)
				}
			}
			enrolled := ""
			if assessment.Enrolled != nil {
				enrolled = string(assessment.Enrolled.Form.Kind)
			}
			if enrolled != row.Enroll || assessment.Enroll != kiroTableEnrollVersion(row) {
				t.Fatalf("enrolled %q at %q, want %q at %q", enrolled, assessment.Enroll, row.Enroll, kiroTableEnrollVersion(row))
			}
			if got := admittedWord(assessment.SetupRefusal == ""); got != row.Action {
				t.Errorf("action setup %s (%s), want %s", got, assessment.SetupRefusal, row.Action)
			}
			if got := admittedWord(assessment.EveryModeRefusal == ""); got != row.Observe {
				t.Errorf("observe setup %s (%s), want %s", got, assessment.EveryModeRefusal, row.Observe)
			}
			var unprotected []string
			for _, verdict := range assessment.Unprotected() {
				unprotected = append(unprotected, verdict.Code)
			}
			sort.Strings(unprotected)
			if want := kiroTableUnprotectedCodes(row); !slices.Equal(unprotected, want) {
				t.Errorf("reported %v, want every form that is not protected %v", unprotected, want)
			}

			// The managed install and verify gates see one version: the
			// enrolled form's, else the read version discovery selects (the
			// kiro-cli's, else the IDE's), else none.
			version := assessment.Enroll
			if version == "" {
				for _, form := range kiroTableForms(row) {
					if form.Version != "" {
						version = form.Version
						if form.IDE() {
							version += KiroIDEVersionSuffix
						}
						break
					}
				}
			}
			resolution := resolveHookContract("kiro", version)
			floor := kiroHookFloorRefusal(resolution)
			// Managed Windows Kiro has versioned contracts: there action mode
			// refuses an unread version as unversioned.
			unversioned := version == "" && connector.HookContractNeedsActionOverride(resolution)
			action := floor == "" && kiroActionVersionRefusal(resolution) == "" && !unversioned
			if got := admittedWord(action); got != row.Action {
				t.Errorf("managed action install of %q %s (%s %s), want %s", version, got, floor, kiroActionVersionRefusal(resolution), row.Action)
			}
			if got := admittedWord(floor == ""); got != row.Observe {
				t.Errorf("managed observe install of %q %s (%s), want %s", version, got, floor, row.Observe)
			}
		})
	}
}
