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
	"fmt"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// The one Kiro detection judgment. Kiro has two products behind one
// connector: kiro-cli, and the Kiro IDE (installed for the user or for the
// whole machine). Each installed form is judged on its own, by JudgeKiroForm:
//
//   - a form whose version was read and is at or above its floor
//     (connector.KiroCLIHookFloor for kiro-cli, KiroIDEGlobalHooksFloor for the
//     IDE) is protected;
//   - a form below its floor is not protected (its hooks never run);
//   - a form that is installed but whose version could not be read (the
//     probe failed, timed out, or the file did not name a version) is
//     unknown, and unknown is not protected.
//
// AssessKiro combines the forms. A protected kiro-cli is enrolled; else a
// protected IDE is; else nothing is, and action setup refuses. A protected
// form never hides one that is not protected: every such form is reported.
// The managed installer and verifier (kiroHookFloorRefusal,
// kiroActionVersionRefusal), the standalone floor
// (standaloneNotGatedVersionAdmitted) and both enumerators use it; Python
// setup and doctor mirror it in connector_contracts.assess_kiro, and both are
// held to the same table (testdata/kiro_forms_table.json).

// KiroFormKind names an installed Kiro form.
type KiroFormKind string

const (
	KiroFormCLI        KiroFormKind = "cli"
	KiroFormUserIDE    KiroFormKind = "ide_user"
	KiroFormMachineIDE KiroFormKind = "ide_machine"
)

// KiroIDEMachineDiscoveryKey carries a machine-wide Kiro IDE install from the
// per-user discovery worker, next to KiroIDEDiscoveryKey (the user's own IDE
// install). The version is under Versions; an install whose version could not
// be read is under Reasons (UnixAgentUnversionedReasonPrefix).
const KiroIDEMachineDiscoveryKey = "kiro-ide-machine"

// KiroForm is one installed Kiro form and what its probe read.
type KiroForm struct {
	Kind KiroFormKind
	// Version is the bare version the probe read (an IDE row version may
	// carry KiroIDEVersionSuffix); "" when the probe read none.
	Version string
	// Unread says where the install is and why no version was read.
	Unread string
}

// IDE reports whether the form is a Kiro IDE install.
func (f KiroForm) IDE() bool { return f.Kind == KiroFormUserIDE || f.Kind == KiroFormMachineIDE }

// KiroFormVerdict is JudgeKiroForm's answer for one form.
type KiroFormVerdict struct {
	Form       KiroForm
	Version    string // the version without the IDE marker
	Normalized string
	Protected  bool
	// Code is the unprotected-agent code of a form that is not protected.
	Code string
	// Reason says why the form is not protected.
	Reason string
}

// BelowFloor reports a form whose read version is below its floor.
func (v KiroFormVerdict) BelowFloor() bool {
	return v.Code == UnprotectedCodeKiroCLIBelowHookFloor || v.Code == UnprotectedCodeKiroIDEBelowGlobalHooksFloor
}

// Unknown reports an installed form whose version could not be read.
func (v KiroFormVerdict) Unknown() bool { return !v.Protected && v.Normalized == "" }

// JudgeKiroForm judges one installed Kiro form against its floor.
func JudgeKiroForm(form KiroForm) KiroFormVerdict {
	version := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(form.Version), KiroIDEVersionSuffix))
	verdict := KiroFormVerdict{Form: form, Version: version, Normalized: connector.NormalizeAgentVersion("kiro", version)}
	switch {
	case form.IDE() && verdict.Normalized == "":
		verdict.Code = UnprotectedCodeHookContractUnverified
		verdict.Reason = kiroIDEUnreadReason(form.Unread)
	case form.IDE() && compareStandaloneFloorVersion(verdict.Normalized, KiroIDEGlobalHooksFloor) < 0:
		verdict.Code = UnprotectedCodeKiroIDEBelowGlobalHooksFloor
		verdict.Reason = fmt.Sprintf("Kiro IDE %s is below %s, the first build that reads the global %s file, so its agent sessions run without DefenseClaw hooks",
			version, KiroIDEGlobalHooksFloor, kiroGlobalHooksDisplay())
	case form.IDE():
		verdict.Protected = true
	case verdict.Normalized == "":
		verdict.Code = UnprotectedCodeHookContractUnverified
		verdict.Reason = kiroCLIUnreadReason(form.Unread)
	case compareStandaloneFloorVersion(verdict.Normalized, connector.KiroCLIHookFloor) < 0:
		verdict.Code = UnprotectedCodeKiroCLIBelowHookFloor
		verdict.Reason = connector.KiroCLIBelowHookFloorReason(verdict.Normalized)
	default:
		verdict.Protected = true
	}
	return verdict
}

// KiroAssessment is AssessKiro's answer for one user's installed forms.
type KiroAssessment struct {
	Forms []KiroFormVerdict
	// Enrolled is the protected form a Kiro row covers: the kiro-cli when it
	// is protected, else the first protected IDE; nil when none is.
	Enrolled *KiroFormVerdict
	// Enroll is the version a Kiro row records for Enrolled: the kiro-cli's,
	// or the IDE's marked with KiroIDEVersionSuffix; "" when none is.
	Enroll string
	// SetupRefusal says why action setup refuses: no installed form is
	// protected, or no form is installed. "" when one is protected.
	SetupRefusal string
	// EveryModeRefusal says why observe setup refuses too: no form is
	// protected and one is known to be below its floor, so observe setup
	// would stage hooks that form never runs (GAP-0828). When every form
	// that is not protected is only unknown, action setup alone refuses.
	EveryModeRefusal string
}

// AssessKiro judges each installed form independently and picks the one a
// row covers. Forms that are not installed are left out by the caller.
func AssessKiro(forms []KiroForm) KiroAssessment {
	var assessment KiroAssessment
	for _, form := range forms {
		assessment.Forms = append(assessment.Forms, JudgeKiroForm(form))
	}
	for _, cliFirst := range []bool{true, false} {
		for i := range assessment.Forms {
			verdict := &assessment.Forms[i]
			if verdict.Protected && verdict.Form.IDE() != cliFirst && assessment.Enrolled == nil {
				assessment.Enrolled = verdict
			}
		}
	}
	if assessment.Enrolled != nil {
		assessment.Enroll = assessment.Enrolled.Version
		if assessment.Enrolled.Form.IDE() {
			assessment.Enroll += KiroIDEVersionSuffix
		}
		return assessment
	}
	if len(assessment.Forms) == 0 {
		assessment.SetupRefusal = "no Kiro installation was found, so no Kiro form is known to be protected"
	}
	for _, verdict := range assessment.Forms {
		if assessment.SetupRefusal == "" {
			assessment.SetupRefusal = verdict.Reason
		}
		if verdict.BelowFloor() && assessment.EveryModeRefusal == "" {
			assessment.EveryModeRefusal = verdict.Reason
		}
	}
	return assessment
}

// Unprotected returns every installed form the assessment does not protect,
// with its reason in context: a form next to an enrolled one says that form
// is separately eligible, so the enrolled form never hides it.
func (a KiroAssessment) Unprotected() []KiroFormVerdict {
	var out []KiroFormVerdict
	for _, verdict := range a.Forms {
		if verdict.Protected {
			continue
		}
		verdict.Reason = a.reasonInContext(verdict)
		out = append(out, verdict)
	}
	return out
}

func (a KiroAssessment) reasonInContext(verdict KiroFormVerdict) string {
	reason := verdict.Reason
	enrolled := a.Enrolled
	switch {
	case verdict.Form.IDE():
		if enrolled != nil && !enrolled.Form.IDE() {
			reason += "; kiro-cli " + enrolled.Version + " remains eligible for enrollment"
		} else if enrolled != nil {
			reason += "; Kiro IDE " + enrolled.Version + " is separately eligible for global hooks"
		}
		if verdict.BelowFloor() {
			reason += "; update Kiro IDE"
		}
	case enrolled != nil && verdict.BelowFloor():
		reason += "; Kiro IDE " + enrolled.Version + " is separately eligible for global hooks, but this kiro-cli's non-interactive runs load no hooks"
	case enrolled != nil:
		reason += "; Kiro IDE " + enrolled.Version + " is separately eligible for global hooks"
	}
	return reason
}

// kiroCLIUnreadReason says why a kiro-cli with no readable version is not
// protected.
func kiroCLIUnreadReason(unread string) string {
	unread = strings.TrimSpace(unread)
	if unread == "" {
		unread = "kiro-cli is installed, but its version could not be read"
	}
	return unread + "; without a version DefenseClaw cannot check this kiro-cli against its hook floor, so it is not counted as protected"
}

// kiroIDEUnreadReason says why a Kiro IDE with no readable version is not
// protected. It names no hook contract (hook_contract_unverified).
func kiroIDEUnreadReason(unread string) string {
	unread = strings.TrimSpace(unread)
	if unread == "" {
		unread = "Kiro IDE is installed, but its version could not be read"
	}
	return fmt.Sprintf("%s, so it is not verified against a known hook contract (the global hooks file needs Kiro IDE %s or later) and is not counted as protected",
		unread, KiroIDEGlobalHooksFloor)
}

// kiroGlobalHooksDisplay is the global Kiro hooks folder as users see it.
func kiroGlobalHooksDisplay() string {
	if runtime.GOOS == "windows" {
		return `%USERPROFILE%\.kiro\hooks`
	}
	return "~/.kiro/hooks"
}

// kiroFormFromRowVersion is the form a Kiro row or install version names:
// the IDE when it carries KiroIDEVersionSuffix, else kiro-cli.
func kiroFormFromRowVersion(version string) KiroForm {
	if strings.HasSuffix(strings.TrimSpace(version), KiroIDEVersionSuffix) {
		return KiroForm{Kind: KiroFormUserIDE, Version: version}
	}
	return KiroForm{Kind: KiroFormCLI, Version: version}
}
