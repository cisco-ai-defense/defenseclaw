// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The Windows form of the Unix port claim (GAP-1569). Standard accounts may
// create files in %ProgramData% but not delete other accounts' files there,
// as with the sticky /var/tmp. A claim holds the SID of the account that
// started a gateway on that port; init on another account skips it
// (bootstrap.py reads the same files). A claim is a hint, never an
// authorization.
var gatewayPortClaimDir = func() string {
	if dir := strings.TrimSpace(os.Getenv("ProgramData")); dir != "" {
		return dir
	}
	return `C:\ProgramData`
}()

const (
	gatewayPortClaimPrefix  = "defenseclaw-api-port-"
	gatewayPortClaimMaxSize = 256
)

// claimGatewayAPIPort records this account's configured API port and drops
// the account's claims on other ports. Best effort.
func claimGatewayAPIPort(cfg *config.Config) {
	if cfg == nil || cfg.StandaloneEnterprise() ||
		managed.IsManagedEnterprise(os.Getenv(managed.DeploymentModeEnv)) {
		return
	}
	port := cfg.Gateway.APIPort
	if port < 1 || port > 65535 {
		return
	}
	own := currentAccountSID()
	if own == "" {
		return
	}
	target := filepath.Join(gatewayPortClaimDir, gatewayPortClaimPrefix+strconv.Itoa(port))
	if matches, err := filepath.Glob(filepath.Join(gatewayPortClaimDir, gatewayPortClaimPrefix+"*")); err == nil {
		for _, match := range matches {
			if !strings.EqualFold(match, target) && strings.EqualFold(gatewayPortClaimSID(match), own) {
				_ = os.Remove(match)
			}
		}
	}
	// O_EXCL keeps an existing claim with its owner.
	if f, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644); err == nil {
		_, _ = f.WriteString(own)
		_ = f.Close()
	}
}

// gatewayPortClaimSID is the account SID a claim names, or "".
func gatewayPortClaimSID(path string) string {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > gatewayPortClaimMaxSize {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func currentAccountSID() string {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return ""
	}
	return user.User.Sid.String()
}
