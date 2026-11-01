// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/contracttest"
)

// GAP-2448: with --json, an unknown flag or a malformed value on a Windows
// lifecycle verb, and a stray argument on ensure, print one lifecycle result
// whose only error is invalid_arguments, exit 1639, also when --json follows
// the bad argument. Without --json stdout stays empty and the exit is 1639.
func TestWindowsLifecycleArgumentErrorsPrintTheFailureDocument(t *testing.T) {
	schemas := contracttest.Compile(t)
	saved := secretRawArgs
	t.Cleanup(func() { secretRawArgs = saved })
	cases := map[string][]string{
		"status/unknown flag":    {"--bogus", "--json"},
		"verify/unknown flag":    {"--bogus", "--json"},
		"ensure/unknown flag":    {"--bogus", "--json"},
		"ensure/stray argument":  {"extra", "--json"},
		"repair/malformed value": {"--no-start=maybe", "--json"},
		"uninstall/unknown flag": {"--json", "--bogus"},
	}
	for name, args := range cases {
		action := strings.SplitN(name, "/", 2)[0]
		t.Run(name, func(t *testing.T) {
			run := func(args []string) (string, int) {
				secretRawArgs = func() []string { return append([]string{"enterprise", "windows", action}, args...) }
				cmd := newWindowsEnterpriseLifecycleCommand(action)
				var out bytes.Buffer
				cmd.SetOut(&out)
				cmd.SetErr(io.Discard)
				cmd.SetArgs(args)
				code := runExit(cmd.Execute())
				return out.String(), code
			}
			out, code := run(args)
			doc := schemas.Validate(t, "lifecycle-result.schema.json", []byte(out))
			requireExit(t, doc, code, 1639)
			errs, _ := doc["errors"].([]any)
			if strings.Count(out, `"schema_version"`) != 1 || doc["action"] != action || len(errs) != 1 || errs[0].(map[string]any)["code"] != "invalid_arguments" {
				t.Fatalf("%v: %s", args, out)
			}
			text := make([]string, 0, len(args))
			for _, arg := range args {
				if arg != "--json" {
					text = append(text, arg)
				}
			}
			if out, code := run(text); out != "" || code != 1639 {
				t.Fatalf("%v without --json: exit %d, stdout %q; want exit 1639 and no stdout", text, code, out)
			}
		})
	}
}
