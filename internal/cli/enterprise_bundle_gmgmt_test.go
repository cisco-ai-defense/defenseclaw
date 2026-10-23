// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// The group help names apply on every OS it is registered on, with the
// caller each OS needs.
func TestEnterpriseBundleHelpListsApplyOnEveryOS(t *testing.T) {
	out, code := runBundle(t, "--help")
	if code != 0 {
		t.Fatalf("bundle --help exit %d:\n%s", code, out)
	}
	flat := strings.Join(strings.Fields(out), " ")
	for _, want := range []string{"apply installs a bundle on a managed device", "root on Linux and macOS", "elevated administrator or SYSTEM on Windows"} {
		if !strings.Contains(flat, want) {
			t.Fatalf("bundle --help lacks %q:\n%s", want, out)
		}
	}
}

// An account that may list the installed anchor file but not read it gets
// not_admin from verify with the default anchors, as one that cannot even
// inspect it does.
func TestEnterpriseBundleVerifyAnchorsReadDeniedIsNotAdmin(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a POSIX account that a mode 0000 file denies")
	}
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	signed := filepath.Join(e.dir, "v5.dcbundle")
	if out, code := runBundle(t, e.signArgs("--out", signed, "--key", filepath.Join(e.dir, "key.pem"), "--key-id", "k1")...); code != 0 {
		t.Fatalf("sign exit %d:\n%s", code, out)
	}
	savedAnchors, savedTrust := bundleDefaultAnchors, bundleAnchorTrust
	t.Cleanup(func() { bundleDefaultAnchors, bundleAnchorTrust = savedAnchors, savedTrust })
	bundleDefaultAnchors = func() (string, error) { return e.anchors, nil }
	bundleAnchorTrust = nil
	if err := os.Chmod(e.anchors, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(e.anchors, 0o600) })
	out, code := runBundle(t, "verify", "--bundle", signed, "--platform", "linux", "--json")
	if code != bundleFailureExitCode() || !strings.Contains(out, `"code": "not_admin"`) || strings.Contains(out, "anchor_insecure") {
		t.Fatalf("default anchors denied (exit %d):\n%s", code, out)
	}
	// A named --anchors file the account cannot read stays anchor_insecure:
	// the caller chose that file.
	out, code = runBundle(t, "verify", "--bundle", signed, "--anchors", e.anchors, "--platform", "linux", "--json")
	if code != bundleFailureExitCode() || !strings.Contains(out, "anchor_insecure") {
		t.Fatalf("--anchors denied (exit %d):\n%s", code, out)
	}
}

// bundle apply --json answers an argument error with one invalid_arguments
// document and the invalid-arguments exit code of this OS, also when --json
// follows the flag the parse stopped at.
func TestEnterpriseBundleApplyArgumentErrorPrintsOneDocument(t *testing.T) {
	saved := secretRawArgs
	t.Cleanup(func() { secretRawArgs = saved })
	args := []string{"apply", "--bogus", "--json"}
	secretRawArgs = func() []string { return append([]string{"enterprise", "bundle"}, args...) }
	out, code := runBundle(t, args...)
	var doc bundleApplyResult
	if err := json.Unmarshal([]byte(out), &doc); err != nil || code != enterprisestatus.InvalidArgsExitCode(runtime.GOOS) ||
		doc.OK || doc.Command != "apply" || len(doc.Errors) != 1 || doc.Errors[0].Code != "invalid_arguments" ||
		!strings.Contains(doc.Errors[0].Message, "--bogus") {
		t.Fatalf("exit %d, stdout %q (%v)", code, out, err)
	}
}

// The Windows --defer-restart refusal follows the verify restart
// prediction: required and unknown refuse, not_required applies.
func TestBundleRestartDeferralFollowsThePrediction(t *testing.T) {
	if got := bundleRestartDeferral(&bundleRestartPrediction{GatewayRestart: bundleRestartNotRequired}); got != "" {
		t.Fatalf("not_required: %q", got)
	}
	if got := bundleRestartDeferral(&bundleRestartPrediction{GatewayRestart: bundleRestartRequired, Settings: []string{"gateway.port"}}); !strings.Contains(got, "gateway.port") {
		t.Fatalf("required: %q", got)
	}
	if got := bundleRestartDeferral(&bundleRestartPrediction{GatewayRestart: bundleRestartUnknown}); !strings.Contains(got, "cannot tell") {
		t.Fatalf("unknown: %q", got)
	}
	if got := windowsBundleRestartDeferral(nil, []byte("config_version: 9\n")); !strings.Contains(got, "cannot tell") {
		t.Fatalf("no enforced config: %q", got)
	}
	cmd := newEnterpriseBundleApplyCommand()
	if cmd.Flags().Lookup("defer-restart") == nil {
		t.Fatal("bundle apply has no --defer-restart")
	}
}

func TestWindowsConfirmedBundleReplayIsAConfigChange(t *testing.T) {
	if !windowsBundleConfigChange(&enterprisebundle.Prepared{AlreadyApplied: true}) {
		t.Fatal("a confirmed signed bundle with config drift lost its config apply path")
	}
}
