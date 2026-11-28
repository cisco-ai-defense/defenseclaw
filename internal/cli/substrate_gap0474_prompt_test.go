// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	api "github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
)

// GAP-0474: the delete question names what goes with each agent (its
// snapshots, with the count, and the checkpoints inside it), and the output
// says how many snapshots were removed.
func TestGAP0474DeletePromptNamesWhatIsPurged(t *testing.T) {
	three, one := 3, 1
	q := substrateDeletePrompt([]api.Actor{{Atespace: "dc-eng", Name: "p-1", Snapshots: &three}})
	for _, want := range []string{"dc-eng/p-1", "3 snapshots", "checkpoints", "not pulled"} {
		if !strings.Contains(q, want) {
			t.Fatalf("prompt %q lacks %q", q, want)
		}
	}
	q = substrateDeletePrompt([]api.Actor{{Atespace: "dc-eng", Name: "a", Snapshots: &one}, {Atespace: "dc-eng", Name: "b"}})
	for _, want := range []string{"Delete 2 agents", "dc-eng/a: the agent, 1 snapshot ", "dc-eng/b: the agent, its snapshots", "checkpoints"} {
		if !strings.Contains(q, want) {
			t.Fatalf("prompt %q lacks %q", q, want)
		}
	}
}
