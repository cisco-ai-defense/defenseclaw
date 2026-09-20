// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const devinPinnedCLIVersion = "3000.4.25"

var devinVersionTokens = regexp.MustCompile(`v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?`)

func verifyDevinExecutableAdmission(executable string) error {
	expected, err := defaultDevinExecutable()
	if err != nil {
		return err
	}
	if err := validateDevinExecutableIdentity(executable, expected); err != nil {
		return err
	}
	if err := rejectReparseAncestors(executable); err != nil {
		return fmt.Errorf("validate Devin CLI path: %w", err)
	}
	info, err := os.Lstat(executable)
	if err != nil {
		return fmt.Errorf("inspect Devin CLI %s: %w", executable, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("Devin CLI target is not a regular non-link executable")
	}
	metadata, err := inspectEmbeddedAuthenticode(executable)
	if err != nil {
		return fmt.Errorf("inspect Devin CLI Authenticode: %w", err)
	}
	if err := validateDevinSigner(metadata); err != nil {
		return err
	}
	if err := verifyEmbeddedAuthenticodeTrust(executable); err != nil {
		return fmt.Errorf("verify Devin CLI Authenticode trust: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, executable, "--version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("probe Devin CLI version: %w", err)
	}
	return validateDevinVersionOutput(output)
}

func validateDevinExecutableIdentity(executable, expected string) error {
	if strings.TrimSpace(executable) != executable || !filepath.IsAbs(executable) ||
		filepath.Clean(executable) != executable || !strings.EqualFold(executable, expected) {
		return errors.New("Devin CLI must be the exact current-user LocalAppData executable")
	}
	return nil
}

func validateDevinSigner(metadata embeddedAuthenticodeMetadata) error {
	if !metadata.Present {
		return errors.New("Devin CLI is not Authenticode signed")
	}
	publisherMatches := metadata.SignerCommonName == "Exafunction, Inc."
	for _, organization := range strings.Split(metadata.SignerOrganizations, "\x00") {
		publisherMatches = publisherMatches || organization == "Exafunction, Inc."
	}
	if !publisherMatches {
		return fmt.Errorf("Devin CLI signer is not Exafunction, Inc. (found %q)", metadata.SignerCommonName)
	}
	return nil
}

func validateDevinVersionOutput(output []byte) error {
	matches := devinVersionTokens.FindAll(output, -1)
	if len(matches) != 1 || strings.TrimPrefix(string(matches[0]), "v") != devinPinnedCLIVersion {
		return fmt.Errorf("Devin CLI version is not pinned %s: %q", devinPinnedCLIVersion, strings.TrimSpace(string(output)))
	}
	return nil
}
