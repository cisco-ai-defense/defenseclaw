// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"errors"
	"strings"
	"testing"
)

// GAP-1360 (verify half): managed Linux and macOS verify run the check
// managed Windows verify runs. An exporter in an account's own Codex or
// Claude Code configuration that carries the managed gateway token is a
// warning naming the account, the file and the remedy, with
// security_complete false; verify still passes (warn, never fail). A
// configuration the check could not read and a check that did not answer
// are warnings too, never a silent pass.
func TestVerifyWarnsAboutAUserNativeOTLPExporterThatCarriesTheGatewayToken(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			writeFreshLedger(t, h)
			clean := h.run(Options{Action: ActionVerify})
			requireOK(t, clean)
			if got := messagesOf(clean.Warnings, codeNativeOTLPProductCredential) + messagesOf(clean.Warnings, codeNativeOTLPConfigUnchecked); got != "" {
				t.Fatalf("clean verify warned: %s", got)
			}
			check := "defenseclaw-gateway enterprise hooks native-otlp-check --manifest " + h.env.Layout.ManifestPath + " --json"
			if !strings.Contains(strings.Join(h.runner.calls, "\n"), "enterprise hooks native-otlp-check --manifest "+h.env.Layout.ManifestPath+" --json") {
				t.Fatalf("verify did not run the native OTLP check: %v", h.runner.calls)
			}
			h.runner.replies = map[string]fakeReply{check: {result: CommandResult{Stdout: []byte(`{"ok":true,"accounts":2,"findings":[` +
				`{"user":"alice","connector":"codex","path":"/home/alice/.codex/config.toml","entries":["otel.exporter"]},` +
				`{"user":"bob","connector":"claudecode","path":"/home/bob/.claude/settings.json","error":"the claudecode user config resolves outside the enrolled home"}]}`)}}}
			v := h.run(Options{Action: ActionVerify})
			requireOK(t, v)
			found := messagesOf(v.Warnings, codeNativeOTLPProductCredential)
			if !strings.Contains(found, "alice's own Codex configuration /home/alice/.codex/config.toml") ||
				!strings.Contains(found, "otel.exporter") || !strings.Contains(found, "the guardian removes it on its next pass") ||
				!strings.Contains(found, " repair`") {
				t.Fatalf("verify did not name the exporter, file and remedy: %q (warnings %+v)", found, v.Warnings)
			}
			if v.SecurityComplete {
				t.Fatal("security_complete stayed true while the gateway token goes to a port the gateway does not serve")
			}
			if unchecked := messagesOf(v.Warnings, codeNativeOTLPConfigUnchecked); !strings.Contains(unchecked, "bob's own Claude Code configuration") ||
				!strings.Contains(unchecked, "outside the enrolled home") {
				t.Fatalf("verify did not report the configuration it could not check: %q", unchecked)
			}
			// A check that does not answer is reported, not passed.
			h.runner.replies = map[string]fakeReply{check: {result: CommandResult{ExitCode: 1}, err: errors.New("unknown command")}}
			v = h.run(Options{Action: ActionVerify})
			requireOK(t, v)
			if unchecked := messagesOf(v.Warnings, codeNativeOTLPConfigUnchecked); !strings.Contains(unchecked, "unknown command") {
				t.Fatalf("a failed check was passed silently: %+v", v.Warnings)
			}
			// Status does not run it.
			h.runner.calls = nil
			h.run(Options{Action: ActionStatus})
			if strings.Contains(strings.Join(h.runner.calls, "\n"), "native-otlp-check") {
				t.Fatal("status ran the per-user native OTLP check")
			}
		})
	}
}
