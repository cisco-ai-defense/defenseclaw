// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// twoFilePatch is one apply_patch call that updates two files, each with its
// own added text.
func twoFilePatch(firstFile, firstLine, secondFile, secondLine string) map[string]any {
	return map[string]any{"command": "*** Begin Patch\n" +
		"*** Update File: " + firstFile + "\n@@\n " + "# base\n+" + firstLine + "\n" +
		"*** Update File: " + secondFile + "\n@@\n " + "# base\n+" + secondLine + "\n" +
		"*** End Patch\n"}
}

// withLinkFor adds the fact the gateway adds for the physical file reached
// through the link the call names as operand.
func withLinkFor(t *testing.T, facts Facts, operand, physical string) Facts {
	t.Helper()
	for _, candidate := range facts.OperandPaths() {
		if candidate.Resolved != operand {
			continue
		}
		linked := candidate
		linked.LinkedFrom = candidate.Resolved
		linked.Value, linked.Normalized, linked.Resolved, linked.Linked = physical, physical, physical, true
		facts.Paths = append(append([]PathFact(nil), facts.Paths...), linked)
		return facts
	}
	t.Fatalf("no operand %s in %+v", operand, facts.Paths)
	return facts
}

// TestContentProofsJudgeEachWriteOfAPatchOnlyAgainstItsOwnLinkTarget pins that
// the file a link reaches belongs to the one operand that names the link: the
// ordinary text a patch adds to another file never takes the identity of the
// protected file, while the protected text added through the link does.
func TestContentProofsJudgeEachWriteOfAPatchOnlyAgainstItsOwnLinkTarget(t *testing.T) {
	linksEtcForTest(t, true)
	const (
		notes = "/work/notes.txt"
		link  = "/work/review-link"
	)
	preload := func(input Input, facts Facts) bool { return ExactGlobalLDPreloadFileWrite(input, facts) }
	pam := func(input Input, facts Facts) bool {
		_, ok := ExactPAMAuthenticationBypass(input, facts)
		return ok
	}
	rows := []struct {
		name, physical, protectedLine, commentLine string
		prove                                      func(Input, Facts) bool
	}{
		{"profile fragment", "/etc/profile.d/bash_completion.sh", "export LD_PRELOAD=/usr/local/lib/libreview.so", "# harmless review comment", preload},
		{"preload file", "/etc/ld.so.preload", "/usr/local/lib/libreview.so", "# harmless review comment", preload},
		{"pam service", "/etc/pam.d/sshd", "auth sufficient pam_permit.so", "# harmless review comment", pam},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			// The protected text goes to the ordinary file and a comment to
			// the link: the link target never receives that text.
			input, facts := nativeProofInput(t, "apply_patch", "", twoFilePatch(notes, row.protectedLine, link, row.commentLine))
			facts = withLinkFor(t, facts, link, row.physical)
			if row.prove(input, facts) {
				t.Error("text added to an ordinary file was judged as text of the protected file another operand reaches")
			}
			// The same call with the operands in the other order.
			input, facts = nativeProofInput(t, "apply_patch", "", twoFilePatch(link, row.commentLine, notes, row.protectedLine))
			facts = withLinkFor(t, facts, link, row.physical)
			if row.prove(input, facts) {
				t.Error("operand order changed the verdict of text added to an ordinary file")
			}
			// The protected text added through the link is still proven,
			// whichever operand comes first, next to ordinary text.
			input, facts = nativeProofInput(t, "apply_patch", "", twoFilePatch(link, row.protectedLine, notes, row.commentLine))
			facts = withLinkFor(t, facts, link, row.physical)
			if !row.prove(input, facts) {
				t.Error("protected text added through a link lost its proof beside another file")
			}
			input, facts = nativeProofInput(t, "apply_patch", "", twoFilePatch(notes, row.commentLine, link, row.protectedLine))
			facts = withLinkFor(t, facts, link, row.physical)
			if !row.prove(input, facts) {
				t.Error("protected text added through a link lost its proof when it is the second file")
			}
			if row.prove(input, Analyze(input)) {
				t.Error("the same call without the link fact is not a protected write and got a proof")
			}
		})
	}
}
