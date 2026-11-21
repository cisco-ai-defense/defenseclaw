// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// A file that only starts like the AWS credentials file (credentials.bak) is
// an ordinary file in the default and permissive tiers; the strict tier keeps
// a copy protected. The credentials file itself is protected in every tier,
// alone or next to a copy. A template or sample (credentials.sample) is not a
// copy: it is ordinary in every tier (rel-1-0-6:GAP-1009,
// substrate-1:GAP-0210).
func TestAWSCredentialsCopyIsOrdinaryOutsideTheStrictTier(t *testing.T) {
	type call struct {
		name, tool, file, command string
		// block is the verdict in the default and permissive tiers; the
		// strict tier blocks every call that names the file or a copy.
		block bool
		// ordinary: not the file nor a copy, allowed in every tier.
		ordinary bool
	}
	calls := []call{
		{name: "write exact", tool: "Write", file: "/home/alice/.aws/credentials", block: true},
		{name: "write copy", tool: "Write", file: "/home/alice/.aws/credentials.bak"},
		{name: "write template sample", tool: "Write", file: "/home/alice/.aws/credentials.sample", ordinary: true},
		{name: "write template example", tool: "Write", file: "/home/alice/.aws/credentials.example", ordinary: true},
		{name: "write dashed neighbour", tool: "Write", file: "/home/alice/.aws/credentials-old", ordinary: true},
		{name: "redirect to exact", tool: "shell", command: "echo fixture > ~/.aws/credentials", block: true},
		{name: "redirect to copy", tool: "shell", command: "echo fixture > ~/.aws/credentials.bak"},
		{name: "copy the file to a copy", tool: "shell", command: "cp ~/.aws/credentials ~/.aws/credentials.bak", block: true},
		{name: "rename a copy", tool: "shell", command: "mv ~/.aws/credentials.bak ~/.aws/credentials.old"},
	}
	for _, profile := range []string{"default", "permissive", "strict"} {
		connector := "aws-copy-tier-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		for _, tc := range calls {
			t.Run(profile+"/"+tc.name, func(t *testing.T) {
				input := actionfacts.Input{Tool: tc.tool, Command: tc.command, CWD: "/work", ActiveHome: "/home/alice"}
				legacy := tc.command
				if tc.tool == "Write" {
					raw, err := json.Marshal(pathCaseFileCall("Write", tc.file))
					if err != nil {
						t.Fatal(err)
					}
					input.Args, legacy = raw, string(raw)
				}
				findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
					Input: input, LegacyText: legacy, Connector: connector,
					EnforcementCapable: true, StrictPolicy: profile == "strict",
				})
				want := tc.block
				if profile == "strict" {
					want = !tc.ordinary
				}
				if got := buildVerdict(findings, "tool_call").Action == "block"; got != want {
					t.Errorf("block = %v, want %v (%v)", got, want, FindingStrings(findings))
				}
			})
		}
	}
}
