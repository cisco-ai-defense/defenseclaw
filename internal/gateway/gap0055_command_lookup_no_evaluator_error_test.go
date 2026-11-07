// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// TestGAP0055CommandLookupNoEvaluatorError is the crash of gas-ux-r1
// GAP-0055 at the gateway: on 1.0.7 to 1.0.9 base 4e4e4e3136 a command that
// reaches unzip with no arguments (command -v unzip && command -v tar,
// command -v unzip, env unzip, a bare unzip) panicked in the hook evaluator:
// the per-user gateway failed closed with "internal evaluator error" and no
// rule id, and the managed hook client panicked before it asked. Each form,
// and every archive program bare, behind a lookup or a launcher, now gets a
// normal allow or block answer for both connectors, managed and per-user.
// The test grades no verdict: archive grading is rel-1-0-6 GAP-0675.
func TestGAP0055CommandLookupNoEvaluatorError(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	commands := []string{
		"command -v unzip && command -v tar",
		"command -v unzip",
		"command -v unzip; command -v tar",
		"command -v unzip || exit 1",
		"command -v unzip >/dev/null 2>&1 && echo yes",
		"command -V unzip",
		"command unzip",
		"env unzip",
		"sudo -n unzip",
		"unzip",
		"exec -a",
		"exec -a x unzip",
		"bash -lc 'command -v unzip && command -v tar'",
	}
	for _, program := range []string{"rsync", "cpio", "bsdcpio", "pax", "tar", "gtar", "bsdtar", "unzip", "7z", "7za", "7zr", "jar", "ditto"} {
		for _, form := range []string{"%s", "command -v %s", "command -v %s && command -v tar", "env %s", "exec -a x %s", "%s --"} {
			if command := fmt.Sprintf(form, program); !slices.Contains(commands, command) {
				commands = append(commands, command)
			}
		}
	}
	if hookAnswerRaceBuild {
		commands = commands[:13]
	}
	f.clientHeaders(t, nil) // the home is searchable while the client reads
	calls := make([]*hookCall, 0, 4*len(commands))
	for _, command := range commands {
		payload := f.payload(t, command)
		var header string
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Errorf("%s: managed hook client panic: %v", command, recovered)
				}
			}()
			header = hookpaths.Resolve(payload)
		}()
		calls = append(calls, everyMode(command, payload, header)...)
	}
	f.answerAll(t, calls)
	for _, call := range calls {
		if call.verdict != "allow" && call.verdict != "block" {
			t.Errorf("%s: no normal verdict: %s", call.name, call.verdict)
		}
		if strings.Contains(call.body, "internal evaluator error") || strings.Contains(call.body, "panics.total") {
			t.Errorf("%s: evaluator error answer: %.300s", call.name, call.body)
		}
		if strings.HasPrefix(call.name, "command -v unzip && command -v tar ") {
			t.Logf("%s: %s", call.name, call.verdict)
		}
	}
}
