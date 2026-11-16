// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// rel-1-0-10:GAP-0499 behind an exact wrapper (push 18b merge, S7 review): an
// awk program run through env or sudo reaches the awk reading of
// analyzeStructuredArgv and is judged as the bare awk call, in the four
// cells of the strict and the default pack.
func TestAwkCommandChannelsBehindEnvAndSudoAreJudgedAsTheBareAwkCall(t *testing.T) {
	for _, pack := range []string{"default", "strict"} {
		t.Run(pack, func(t *testing.T) {
			f := awkPackFixture(t, pack)
			directs := []string{"touch " + f.keys, "touch keylink", "touch ordinary/new.txt", "wc -l ordinary/a.txt"}
			var commands []string
			for _, direct := range directs {
				for _, channel := range awkChannels {
					bare := awkChannelWrap(channel, direct)
					commands = append(commands, bare, "env "+bare, "sudo "+bare)
				}
			}
			got := awkVerdicts(t, f, commands)
			for _, direct := range directs {
				for _, channel := range awkChannels {
					bare := awkChannelWrap(channel, direct)
					for _, wrapper := range []string{"env ", "sudo "} {
						wrapped := got[wrapper+bare]
						for i, call := range got[bare] {
							if i >= len(wrapped) {
								t.Fatalf("%s%s: %d calls, want %d", wrapper, bare, len(wrapped), len(got[bare]))
							}
							if wrapped[i].verdict != call.verdict {
								t.Errorf("%s%s (%s): %s, want %s (the bare awk call)", wrapper, channel, call.name, wrapped[i].verdict, call.verdict)
							}
						}
					}
				}
			}
		})
	}
}
