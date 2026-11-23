// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

func TestGAP1025FindExecActorAnswersAsLaptop(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	tests := []struct {
		command string
		block   bool
	}{
		{"find ~ -path *ssh* -exec cat {} +", true},
		{"find ~ -path '*ssh*' -exec cat {} +", true},
		{"find ~ -name .ssh -exec cat {} +", true},
		{"find ~/.ssh -exec cat {} +", true},
		{"find ~ -path '*/.ssh/*' -exec cat {} +", true},
		{"find ~ -name 'id_*' -exec cat {} +", true},
		{"find ~ -name '*.txt' -exec cat {} +", false},
		{"find ~ -name *.txt -exec cat {} +", false},
		{"find ~ -path *ssh*", false},
		{"find ~ -name '*ssh*' -exec cat {} \\;", true},
		{"find ~ -name 'auth*' -exec cat {} +", false},
		{"find . -path '*ssh*' -exec cat {} +", true},
		{"find ~ -path '*.txt' -exec cat {} +", false},
		{"find ~ -name '*' -exec cat {} +", true},
		{"find ~ -exec cat {} +", true},
	}
	for _, pack := range []string{"default", "strict"} {
		for _, shape := range gap0545Shapes() {
			t.Run(pack+"/"+shape.name, func(t *testing.T) {
				api, actor, home, _ := gap0545API(t, shape.connector, pack)
				gap0922Layout(t, home)
				for _, tc := range tests {
					body := func(cwd string) []byte { b, _ := json.Marshal(shape.body(tc.command, cwd)); return b }
					la, lr := gap0545Verdict(t, api, context.Background(), shape, body(home))
					ca, cr := gap0545Verdict(t, api, actor, shape, body(sandboxauth.SandboxHome))
					laptopBlock := gap0545Rank(la, lr) == 3
					actorBlock := gap0545Rank(ca, cr) == 3
					if laptopBlock != tc.block || actorBlock != tc.block || gap0545Rank(la, lr) != gap0545Rank(ca, cr) {
						t.Errorf("%q: laptop %s %v, actor %s %v; want block=%t", tc.command, la, lr, ca, cr, tc.block)
					}
				}
			})
		}
	}
}
