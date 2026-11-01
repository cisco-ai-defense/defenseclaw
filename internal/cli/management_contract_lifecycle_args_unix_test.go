// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/contracttest"
)

// GAP-2448: with --json, every argument error of a Linux or macOS lifecycle
// verb (an unknown flag, a malformed value, a stray argument, a --lock-wait
// out of range) prints one lifecycle result whose only error is
// invalid_arguments, with exit 2, also when --json follows the bad argument
// (the parse stopped before it). Without --json stdout stays empty.
func TestManagementContractUnixLifecycleArgumentErrorsPrintTheFailureDocument(t *testing.T) {
	schemas := contracttest.Compile(t)
	platform := "linux"
	if runtime.GOOS == "darwin" {
		platform = "macos"
	}
	saved := secretRawArgs
	t.Cleanup(func() { secretRawArgs = saved })
	lockWait := map[string]bool{"install": true, "upgrade": true, "repair": true, "ensure": true, "reconcile": true, "rotate-credentials": true, "uninstall": true}
	for _, action := range []string{"install", "upgrade", "repair", "ensure", "reconcile", "rotate-credentials", "status", "verify", "uninstall"} {
		cases := map[string][]string{
			"unknown flag":     {"--bogus", "--json"},
			"stray argument":   {"extra", "--json"},
			"malformed --json": {"--json=maybe"},
		}
		if lockWait[action] {
			cases["malformed --lock-wait"] = []string{"--lock-wait", "soon", "--json"}
			cases["--lock-wait over 15m"] = []string{"--lock-wait", "16m", "--json"}
			cases["negative --lock-wait"] = []string{"--lock-wait=-1s", "--json"}
		}
		for name, args := range cases {
			t.Run(action+"/"+name, func(t *testing.T) {
				run := func(args []string) (string, int) {
					secretRawArgs = func() []string { return append([]string{"enterprise", platform, action}, args...) }
					cmd := newUnixLifecycleCommand(platform, action, "")
					var out bytes.Buffer
					cmd.SetOut(&out)
					cmd.SetErr(io.Discard)
					cmd.SetArgs(args)
					code := runExit(cmd.Execute())
					return out.String(), code
				}
				out, code := run(args)
				if name == "malformed --json" {
					// --json=maybe does not ask for JSON: a text usage error.
					if out != "" || code != 2 {
						t.Fatalf("%v: exit %d, stdout %q; want exit 2 and no stdout", args, code, out)
					}
					return
				}
				if strings.Count(out, `"schema_version"`) != 1 {
					t.Fatalf("%v: want one document, stdout %q", args, out)
				}
				var doc map[string]any
				if action == "rotate-credentials" {
					// Not an action of lifecycle-result.schema.json.
					dec := json.NewDecoder(strings.NewReader(out))
					dec.UseNumber()
					if err := dec.Decode(&doc); err != nil {
						t.Fatal(err)
					}
				} else {
					doc = schemas.Validate(t, "lifecycle-result.schema.json", []byte(out))
				}
				requireExit(t, doc, code, 2)
				errs, _ := doc["errors"].([]any)
				if doc["ok"] != false || doc["action"] != action || len(errs) != 1 || errs[0].(map[string]any)["code"] != "invalid_arguments" {
					t.Fatalf("%v: %s", args, out)
				}
				if msg, _ := errs[0].(map[string]any)["message"].(string); strings.Contains(msg, "Usage:") || msg == "" {
					t.Fatalf("%v: the message carries the usage text or is empty: %q", args, msg)
				}
				text := make([]string, 0, len(args))
				for _, arg := range args {
					if arg != "--json" {
						text = append(text, arg)
					}
				}
				if out, code := run(text); out != "" || code != 2 {
					t.Fatalf("%v without --json: exit %d, stdout %q; want exit 2 and no stdout", text, code, out)
				}
			})
		}
	}
}
