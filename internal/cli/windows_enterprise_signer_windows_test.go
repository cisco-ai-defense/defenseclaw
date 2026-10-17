// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"reflect"
	"strings"
	"testing"
)

func TestWindowsEnterpriseAdditionalTrustedSignersForwardAsOneFileArgument(t *testing.T) {
	first := strings.Repeat("ab", 32)
	second := strings.Repeat("CD", 32)
	cmd := newWindowsEnterpriseLifecycleCommand("install")
	if err := cmd.ParseFlags([]string{
		"--additional-trusted-signer-sha256", first,
		"--additional-trusted-signer-sha256", second,
	}); err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	signers, err := cmd.Flags().GetStringSlice("additional-trusted-signer-sha256")
	if err != nil {
		t.Fatalf("read flag: %v", err)
	}
	if !reflect.DeepEqual(signers, []string{first, second}) {
		t.Fatalf("parsed signers = %#v", signers)
	}

	opts := &windowsEnterpriseLifecycleOptions{additionalTrustedSignerSHA256: signers}
	got := windowsEnterprisePowerShellArgs("install", opts)
	want := []string{
		"-Action", "Install",
		// PowerShell -File binds one string per parameter; the installer
		// splits and validates the comma-separated fingerprints.
		"-AdditionalTrustedSignerSha256", first + "," + second,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("windowsEnterprisePowerShellArgs = %#v, want %#v", got, want)
	}
}

func TestWindowsEnterpriseArgsOmitSignerParameterByDefault(t *testing.T) {
	got := windowsEnterprisePowerShellArgs("repair", &windowsEnterpriseLifecycleOptions{})
	for _, argument := range got {
		if argument == "-AdditionalTrustedSignerSha256" {
			t.Fatalf("default lifecycle arguments include the signer parameter: %#v", got)
		}
	}
}
