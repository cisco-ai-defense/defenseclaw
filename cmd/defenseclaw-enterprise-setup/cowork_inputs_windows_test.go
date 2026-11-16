// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"slices"
	"testing"
)

func TestSetupForwardsCoworkReleaseInputsOnlyOnStandaloneMutations(t *testing.T) {
	stage := `C:\ProgramData\DefenseClaw-Enterprise-Setup-0123456789abcdef0123456789abcdef`
	archive := `C:\release\defenseclaw-cowork-amd64.tar.gz`
	signature := archive + ".sig"
	for _, action := range []string{"install", "upgrade", "repair", "ensure"} {
		args := enterpriseLifecycleArguments(stage, enterpriseSetupOptions{Action: action, Standalone: true, CoworkPackage: archive, CoworkSignature: signature})
		for flag, want := range map[string]string{"--cowork-package": archive, "--cowork-signature": signature} {
			i := slices.Index(args, flag)
			if i < 0 || i+1 >= len(args) || args[i+1] != want {
				t.Fatalf("%s: missing %s %q in %#v", action, flag, want, args)
			}
		}
	}
	for _, opts := range []enterpriseSetupOptions{
		{Action: "repair", CoworkPackage: archive, CoworkSignature: signature},
		{Action: "status", Standalone: true, CoworkPackage: archive, CoworkSignature: signature},
	} {
		args := enterpriseLifecycleArguments(stage, opts)
		if slices.Contains(args, "--cowork-package") || slices.Contains(args, "--cowork-signature") {
			t.Fatalf("leaked standalone Cowork input: %#v", args)
		}
	}
}
