// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// TestExactFileWriteProofsCountOperandsNotLinkedSpellings pins that the file
// the gateway adds for the target of a link (PathFact.Linked) is one more
// spelling of the operand the call names. The exact proofs of a whole-file
// write still hold with it, and still refuse a second operand.
func TestExactFileWriteProofsCountOperandsNotLinkedSpellings(t *testing.T) {
	t.Parallel()
	ldPreload := Input{
		Tool: "Write",
		Args: []byte(`{"file_path":"/etc/profile.d/logger.sh","content":"export LD_PRELOAD=/usr/local/lib/liblogger.so\n"}`),
	}
	docker := dockerRegistryInput(t, "Write", "file_path", dockerDaemonConfigPath,
		`{"insecure-registries":["http://mirror.local"]}`)
	for name, proof := range map[string]struct {
		input Input
		exact func(Input, Facts) bool
	}{
		"global LD_PRELOAD profile": {ldPreload, ExactGlobalLDPreloadFileWrite},
		"docker insecure registry":  {docker, ExactDockerInsecureRegistryWrite},
	} {
		facts := Analyze(proof.input)
		if !proof.exact(proof.input, facts) || len(facts.Paths) != 1 {
			t.Fatalf("%s: no exact proof on the call alone: %+v", name, facts)
		}
		linked := facts.Paths[0]
		linked.Value, linked.Normalized, linked.Resolved = "/private"+linked.Value, "/private"+linked.Normalized, "/private"+linked.Resolved
		linked.Linked = true
		linked.LinkedFrom = facts.Paths[0].Resolved
		withLink := facts
		withLink.Paths = append(append([]PathFact(nil), facts.Paths...), linked)
		if !proof.exact(proof.input, withLink) {
			t.Errorf("%s: the file a link reaches broke the exact proof: %+v", name, withLink.Paths)
		}
		other := linked
		other.Linked = false
		withOperand := facts
		withOperand.Paths = append(append([]PathFact(nil), facts.Paths...), other)
		if proof.exact(proof.input, withOperand) {
			t.Errorf("%s: a second operand kept the exact proof: %+v", name, withOperand.Paths)
		}
	}
}
