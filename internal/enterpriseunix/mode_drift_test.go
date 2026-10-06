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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// writeFreshLedger publishes a current guardian authorization ledger, which
// strict verify requires.
func writeFreshLedger(t *testing.T, h *testHost) {
	t.Helper()
	data, _ := json.Marshal(map[string]any{"version": 1, "updated_at": h.env.Now().UTC().Format("2006-01-02T15:04:05Z"), "ok": true})
	h.publishLedger(data)
}

func messagesOf(messages []enterprisestatus.Message, code string) string {
	joined := ""
	for _, m := range messages {
		if m.Code == code {
			joined += m.Message + "\n"
		}
	}
	return joined
}

// A package manager that replaced the binaries while the package's own install
// run failed leaves the record at the previous version. verify names that
// state once instead of calling each binary modified after install
// (GAP-0111).
func TestVerifyNamesAPackageUpgradeThatDidNotFinishApplying(t *testing.T) {
	h := packageHost(t, "1.0.0")
	requireOK(t, h.run(Options{Action: ActionInstall, FromPackage: true}))
	writeFreshLedger(t, h)
	requireOK(t, h.run(Options{Action: ActionVerify}))
	bin := h.env.P(h.env.Layout.BinDir)
	newer := h.payload("1.1.0")
	for _, name := range []string{binGateway, binHook, binSensorHelper} {
		if err := h.env.copyFileAtomic(filepath.Join(newer, name), filepath.Join(bin, name), 0o755, rootOwner()); err != nil {
			t.Fatal(err)
		}
	}
	r := h.run(Options{Action: ActionVerify})
	requireError(t, r, codeVerify)
	got := messagesOf(r.Errors, codeVerify)
	if !strings.Contains(got, "installed package is version 1.1.0 but the deployment applied 1.0.0") ||
		!strings.Contains(got, "--from-package") || strings.Contains(got, "was modified after install") {
		t.Fatalf("verify after a package replaced the binaries: %s", got)
	}
}

// Verify promises every file and permission, but compared only digests: a
// loosened config.yaml (0644) and an installed binary any account could
// replace (0757) went unreported, while repair fixed the first and refused
// the second without saying how to recover.
func TestVerifyReportsInstalledModeDriftAndRepairNamesTheRemedy(t *testing.T) {
	type host struct {
		goos    string
		channel string
		make    func(t *testing.T) (*testHost, Options)
	}
	for _, c := range []host{
		{"linux", ChannelPayload, func(t *testing.T) (*testHost, Options) {
			h := newTestHost(t, "linux")
			return h, Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}
		}},
		{"linux", ChannelPackage, func(t *testing.T) (*testHost, Options) {
			return packageHost(t, "1.0.0"), Options{Action: ActionInstall, FromPackage: true}
		}},
		{"darwin", ChannelPayload, func(t *testing.T) (*testHost, Options) {
			h := newTestHost(t, "darwin")
			return h, Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}
		}},
	} {
		t.Run(c.goos+"-"+c.channel, func(t *testing.T) {
			h, install := c.make(t)
			requireOK(t, h.run(install))
			writeFreshLedger(t, h)
			requireOK(t, h.run(Options{Action: ActionVerify}))
			configPath := h.env.Layout.ConfigPath
			hook := filepath.Join(h.env.Layout.BinDir, binHook)

			if err := os.Chmod(h.env.P(configPath), 0o644); err != nil {
				t.Fatal(err)
			}
			loosened := h.run(Options{Action: ActionVerify})
			requireError(t, loosened, codeVerify)
			if got := messagesOf(loosened.Errors, codeVerify); !strings.Contains(got, configPath+" is 0644") || !strings.Contains(got, " repair`") {
				t.Fatalf("verify does not report the loosened config: %s", got)
			}
			requireOK(t, h.run(Options{Action: ActionRepair}))
			if mode := h.mode(configPath); mode != 0o640 {
				t.Fatalf("repair left config.yaml at %04o", mode)
			}
			requireOK(t, h.run(Options{Action: ActionVerify}))

			if err := os.Chmod(h.env.P(hook), 0o757); err != nil {
				t.Fatal(err)
			}
			writable := h.run(Options{Action: ActionVerify})
			requireError(t, writable, codeVerify)
			if got := messagesOf(writable.Errors, codeVerify); !strings.Contains(got, hook+" is writable by group or other (0757)") || !strings.Contains(got, "`chmod 0755 "+hook+"`") {
				t.Fatalf("verify does not report the replaceable binary: %s", got)
			}
			refused := h.run(Options{Action: ActionRepair})
			requireError(t, refused, codePayload)
			got := messagesOf(refused.Errors, codePayload)
			if !strings.Contains(got, "`chmod 0755 "+hook+"`") {
				t.Fatalf("the repair refusal names no remedy: %s", got)
			}
			if c.channel == ChannelPackage && !strings.Contains(got, "reinstall the DefenseClaw enterprise package") {
				t.Fatalf("the package-channel refusal does not offer a reinstall: %s", got)
			}
			if c.channel == ChannelPayload && !strings.Contains(got, "--payload") {
				t.Fatalf("the payload-channel refusal does not offer --payload: %s", got)
			}
			if err := os.Chmod(h.env.P(hook), 0o755); err != nil {
				t.Fatal(err)
			}
			requireOK(t, h.run(Options{Action: ActionVerify}))
		})
	}
}
