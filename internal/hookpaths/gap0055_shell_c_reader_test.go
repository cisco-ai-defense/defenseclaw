// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"
	"testing"
)

// TestGAP0055ShellCommandCallReader is gas-ux-r1 GAP-0055 round 6: one shell
// -c argument reader. The body is the first operand after the options when
// one of them is -c, through the launchers in front of the shell; "--" ends
// the options and is never the body; words after the body are $0 and the
// positional parameters.
func TestGAP0055ShellCommandCallReader(t *testing.T) {
	for line, want := range map[string]string{
		"sh -c BODY":                               "BODY",
		"sh -c -- BODY":                            "BODY",
		"bash -c -- BODY _ a b":                    "BODY",
		"sh -c BODY sh":                            "BODY",
		"/bin/sh -c BODY":                          "BODY",
		"/usr/bin/bash -lc BODY":                   "BODY",
		"bash -l -c BODY":                          "BODY",
		"bash -ec -- BODY":                         "BODY",
		"bash -x -e -c BODY":                       "BODY",
		"bash -c -e BODY":                          "BODY",
		"bash -o pipefail -c BODY":                 "BODY",
		"bash -eo pipefail -c BODY":                "BODY",
		"bash +x -c BODY":                          "BODY",
		"bash --norc --noprofile -c BODY":          "BODY",
		"dash -c BODY":                             "BODY",
		"zsh -c BODY":                              "BODY",
		"ksh -c BODY":                              "BODY",
		"env sh -c BODY":                           "BODY",
		"env -i PATH=/bin sh -c BODY":              "BODY",
		"env -u HOME -C /tmp sh -c BODY":           "BODY",
		"/usr/bin/env bash -c BODY":                "BODY",
		"env -- sh -c BODY":                        "BODY",
		"sudo sh -c BODY":                          "BODY",
		"sudo -u root -E bash -c BODY":             "BODY",
		"sudo -nu root sh -c BODY":                 "BODY",
		"sudo --user=root -- sh -c BODY":           "BODY",
		"nice sh -c BODY":                          "BODY",
		"nice -n 5 sh -c BODY":                     "BODY",
		"timeout 60 sh -c BODY":                    "BODY",
		"timeout -s KILL 5s bash -c BODY":          "BODY",
		"command sh -c BODY":                       "BODY",
		"exec sh -c BODY":                          "BODY",
		"exec -a x sh -c BODY":                     "BODY",
		"nohup sh -c BODY":                         "BODY",
		"busybox sh -c BODY":                       "BODY",
		"stdbuf -oL sh -c BODY":                    "BODY",
		"setsid -f sh -c BODY":                     "BODY",
		"env nice -n 5 sudo -u x bash -lc -- BODY": "BODY",
	} {
		words := strings.Fields(line)
		_, at, ok := shellCommandCall(words)
		if !ok || at >= len(words) || words[at] != want {
			t.Errorf("%s: body %d %t, want %q", line, at, ok, want)
		}
		if index, found := shellCommandBodyIndex(words); found && strings.HasPrefix(line, "sh -c --") && words[index] == "--" {
			t.Errorf("%s: shellCommandBodyIndex reads -- as the body", line)
		}
	}
	for _, line := range []string{"sh script.sh", "sh -- -c BODY", "sh -c", "sh -c --", "bash -z -c BODY", "env -S x sh -c BODY",
		"sudo -l sh -c BODY", "sudo -e sh -c BODY", "command -v sh -c BODY", "python -c BODY", "xargs sh -c BODY", "sh -s BODY"} {
		if _, at, ok := shellCommandCall(strings.Fields(line)); ok {
			t.Errorf("%s: read body %d, want no shell -c call", line, at)
		}
	}
}
