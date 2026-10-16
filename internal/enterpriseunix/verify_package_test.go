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
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// rpmRecordsRunner answers `rpm -q --qf ... defenseclaw-enterprise` with
// records, one version per line.
type rpmRecordsRunner struct {
	Runner
	records string
}

func (r rpmRecordsRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	if name == "rpm" && len(args) > 0 && args[0] == "-q" {
		return CommandResult{Stdout: []byte(r.records)}, nil
	}
	return r.Runner.Run(ctx, name, args...)
}

// GAP-0782: after a power loss in the middle of an rpm upgrade the package
// database holds both versions, and verify told the administrator to run
// ensure --from-package, which cannot repair the database. It names the
// duplicate records and the package-manager repair.
func TestVerifyNamesDuplicateRPMRecordsOfAnInterruptedUpgrade(t *testing.T) {
	h := packageHost(t, "1.0.0")
	requireOK(t, h.run(Options{Action: ActionInstall, FromPackage: true}))
	writeFreshLedger(t, h)
	bin := h.env.P(h.env.Layout.BinDir)
	newer := h.payload("1.1.0")
	for _, name := range []string{binGateway, binHook, binSensorHelper} {
		if err := h.env.copyFileAtomic(filepath.Join(newer, name), filepath.Join(bin, name), 0o755, rootOwner()); err != nil {
			t.Fatal(err)
		}
	}
	h.env.Runner = rpmRecordsRunner{Runner: h.runner, records: "1.0.0-1\n1.1.0-1\n"}
	r := h.run(Options{Action: ActionVerify})
	requireError(t, r, codeVerify)
	got := messagesOf(r.Errors, codeVerify)
	if !strings.Contains(got, "records 2 versions of defenseclaw-enterprise (1.0.0-1, 1.1.0-1)") ||
		!strings.Contains(got, "dnf remove --duplicates defenseclaw-enterprise") || strings.Contains(got, "--from-package` to apply it") {
		t.Fatalf("verify after an interrupted rpm upgrade: %s", got)
	}
	// One record: the install run did not finish, as before.
	h.env.Runner = rpmRecordsRunner{Runner: h.runner, records: "1.1.0-1\n"}
	if got := messagesOf(h.run(Options{Action: ActionVerify}).Errors, codeVerify); !strings.Contains(got, "--from-package` to apply it") {
		t.Fatalf("verify with one rpm record: %s", got)
	}
}
