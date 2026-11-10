// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// withLocalWriteAnswers adds to the hook client's path answers the answer of
// this gateway's own walk for each file a native file-tool call writes that
// the client did not answer. The per-user hook sends no client evidence at all
// (only the managed hook runs the resolver), so without it the content rules
// of a protected file (the sudoers grant, a PAM entry, the account database)
// judged only the spelling of the call, and a project link to such a file was
// allowed while the direct name was blocked (GAP-0919). The gateway runs as the
// user, so its walk is the client's: the physical file, or, for a directory
// closed to the user, the file the link text leads to. A gateway that cannot
// read the caller's home, or whose action runs elsewhere, adds nothing.
//
// targets are the names the call writes, as written: those of a native
// file-tool call, and, once the shell text is read, those of the apply_patch
// envelope of a shell here-document (actionfacts.NativeCallWriteTargets), so a
// patch header is placed by the same walk as a file-tool name.
func withLocalWriteAnswers(request trustedActionRequest, answers map[string]string, targets []string) map[string]string {
	if request.SkipLocalFilesystemResolution || request.ProtectedHomeHook {
		return answers
	}
	for _, target := range targets {
		// A name that steps up a directory is answered by its raw spelling as
		// well as by the clean one the proofs of older rules read.
		spellings := []string{actionfacts.OperandPath(target, request.Input.CWD)}
		if raw, steps := actionfacts.StepUpSpelling(target, request.Input.CWD); steps && raw != spellings[0] {
			spellings = append(spellings, raw)
		}
		for _, spelling := range spellings {
			if !filepath.IsAbs(spelling) || len(spelling) > hookpaths.MaxWriteTargetPathBytes {
				continue
			}
			if _, answered := request.ResolvedWriteTargets[spelling]; answered {
				continue
			}
			answer := ""
			if physical, ok := request.targetMemo.ResolveWriteTarget(spelling); ok {
				answer = physical
			} else if text, reached := hookpaths.LinkTextWriteTarget(spelling); reached {
				answer = text
			}
			if answer == "" || filepath.Clean(answer) == filepath.Clean(spelling) {
				continue
			}
			if answers == nil {
				answers = map[string]string{}
			}
			answers[spelling] = answer
		}
	}
	return answers
}

// analyzeWithPatchHeaderAnswers reads the call and, when its shell text holds
// the apply_patch envelope of a here-document, places the headers as a
// file-tool name is placed and reads the call again with those answers. The
// proofs formed while the call is read (the sudoers grant) judge a write by the
// physical file the client answers for, so a header that steps up a directory
// after a link must have its answer before they run, not after. The second
// reading happens only when the walk found a file other than the one the name
// spells.
func analyzeWithPatchHeaderAnswers(request *trustedActionRequest) actionfacts.Facts {
	facts := actionfacts.Analyze(request.Input)
	if len(facts.Commands) == 0 {
		return facts
	}
	answered := len(request.Input.ClientResolvedTargets)
	request.Input.ClientResolvedTargets = withLocalWriteAnswers(
		*request, request.Input.ClientResolvedTargets,
		actionfacts.NativeCallWriteTargets(request.Input, facts),
	)
	if len(request.Input.ClientResolvedTargets) == answered {
		return facts
	}
	return actionfacts.Analyze(request.Input)
}

// clientStepUpAnswers maps the lexical placement of each name a native call
// writes that steps up a directory (a file-tool name or the header of an
// apply_patch here-document) to the files the hook client reports for its raw
// spelling, the file the operating system opens. A clean placement is listed
// only when every name that cleans to it has an answer; one without leaves the
// placement to the checks that read it as unknown.
func clientStepUpAnswers(input actionfacts.Input, facts actionfacts.Facts, cwd string, answers map[string]string) map[string][]string {
	var physical map[string][]string
	unanswered := map[string]bool{}
	for _, name := range actionfacts.NativeCallWriteTargets(input, facts) {
		raw, steps := actionfacts.StepUpSpelling(name, cwd)
		if !steps {
			continue
		}
		clean := filepath.Clean(raw)
		if answer := answers[raw]; filepath.IsAbs(answer) {
			if physical == nil {
				physical = map[string][]string{}
			}
			physical[clean] = append(physical[clean], answer)
		} else {
			unanswered[clean] = true
		}
	}
	for clean := range unanswered {
		delete(physical, clean)
	}
	return physical
}
