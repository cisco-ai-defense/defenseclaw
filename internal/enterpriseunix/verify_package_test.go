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
	"os"
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

func TestStatusWarnsAboutDuplicateRPMRecordsWhenBinaryVersionMatches(t *testing.T) {
	h := packageHost(t, "1.0.0")
	requireOK(t, h.run(Options{Action: ActionInstall, FromPackage: true}))
	writeFreshLedger(t, h)
	h.env.Runner = rpmRecordsRunner{Runner: h.runner, records: "1.0.0-1\n0.9.0-1\n"}
	r := h.run(Options{Action: ActionStatus})
	got := messagesOf(r.Warnings, codeVerify)
	if !strings.Contains(got, "1.0.0-1, 0.9.0-1") || !strings.Contains(got, "dnf reinstall") {
		t.Fatalf("status omitted duplicate rpm records: %s", got)
	}
}

// GAP-0057: an rpm upgrade on a full lifecycle-state filesystem could not
// even create the result file, so its install run never started. dnf said
// Complete, status and verify said only that the run did not finish, and
// last-package-result.json still held the previous version's ok:true. Both
// name the full filesystem and that the kept result is the older run's.
func TestVerifyNamesAFullLifecycleFilesystemAndTheStalePackageResult(t *testing.T) {
	h := packageHost(t, "1.0.0")
	requireOK(t, h.run(Options{Action: ActionInstall, FromPackage: true}))
	writeFreshLedger(t, h)
	lifecycleDir := h.env.P(h.env.Layout.LifecycleDir)
	stale := `{"schema_version":2,"ok":true,"action":"ensure","product_version":"1.0.0","errors":[],"warnings":[]}` + "\n"
	if err := os.WriteFile(filepath.Join(lifecycleDir, lastPackageResultFile), []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := h.env.P(h.env.Layout.BinDir)
	newer := h.payload("1.1.0")
	for _, name := range []string{binGateway, binHook, binSensorHelper} {
		if err := h.env.copyFileAtomic(filepath.Join(newer, name), filepath.Join(bin, name), 0o755, rootOwner()); err != nil {
			t.Fatal(err)
		}
	}
	h.env.DiskSpace = fullFilesystem(lifecycleDir, 64<<10)
	h.env.Runner = rpmRecordsRunner{Runner: h.runner, records: "1.1.0-1\n"}
	verify := h.run(Options{Action: ActionVerify})
	got := messagesOf(verify.Errors, codeVerify)
	for _, want := range []string{
		"the installed package is version 1.1.0 but the deployment applied 1.0.0",
		"the filesystem holding " + h.env.Layout.LifecycleDir + " is full (64 KiB free",
		lastPackageResultFile + " is from the 1.0.0 run",
		"--from-package` to apply it",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("verify on a full lifecycle filesystem lacks %q: %s", want, got)
		}
	}
	status := h.run(Options{Action: ActionStatus})
	if low := messagesOf(status.Warnings, codeDiskSpaceLow); !strings.Contains(low, h.env.Layout.LifecycleDir+" is full") ||
		!strings.Contains(low, "package install or upgrade") {
		t.Fatalf("status does not name the full lifecycle filesystem: %s", low)
	}
	// With space again, a result of this package version is its own.
	h.env.DiskSpace = fullFilesystem(lifecycleDir, 10<<30)
	failed := `{"schema_version":2,"ok":false,"action":"ensure","product_version":"1.1.0","errors":[{"code":"config_rejected","message":"bad key"}]}` + "\n"
	if err := os.WriteFile(filepath.Join(lifecycleDir, lastPackageResultFile), []byte(failed), 0o600); err != nil {
		t.Fatal(err)
	}
	got = messagesOf(h.run(Options{Action: ActionVerify}).Errors, codeVerify)
	if !strings.Contains(got, "did not finish (config_rejected: bad key)") || strings.Contains(got, "is full") || strings.Contains(got, "is from the") {
		t.Fatalf("verify with this package's own failed result: %s", got)
	}
}
