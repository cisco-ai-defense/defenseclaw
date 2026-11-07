// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// On Linux and macOS defenseclaw-gateway is not on the PATH (the packages link
// only the users' sandbox launcher, /usr/bin/defenseclaw or
// /usr/local/bin/defenseclaw), and sudo's secure_path leaves out the install directory. A hint
// that tells an administrator to run the gateway by its bare name ends in
// "command not found" (cowork-1-0-8 GAP-0081).
func TestAdministratorHintsNameTheGatewayByItsFullPath(t *testing.T) {
	for _, tc := range []struct{ goos, gateway string }{
		{"linux", "/opt/defenseclaw/bin/defenseclaw-gateway"},
		{"darwin", "/opt/cisco/defenseclaw/bin/defenseclaw-gateway"},
	} {
		t.Run(tc.goos, func(t *testing.T) {
			h := newTestHost(t, tc.goos)
			if got := h.env.gatewayCommand("status"); got != tc.gateway+" status" {
				t.Fatalf("gatewayCommand = %q", got)
			}
			if got := h.env.bundleApplyCommand(); got != tc.gateway+" enterprise bundle apply --bundle <file>" {
				t.Fatalf("bundleApplyCommand = %q", got)
			}

			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			h.env.HealthGet = func(context.Context) (int, []byte, error) {
				return 200, []byte(`{"api":{"state":"running"},"telemetry":{"details":{"optional_destination_state":"degraded","optional_destination_failure_summary":"archive:failing:no_space"}}}`), nil
			}
			got := messagesOf(h.run(Options{Action: ActionStatus}).Warnings, codeOptionalDestination)
			if !strings.Contains(got, "inspect `"+tc.gateway+" status`") || strings.Contains(got, "`defenseclaw-gateway") {
				t.Fatalf("optional destination warning = %q", got)
			}

			writeBundleAnchors(t, h)
			useConfirmedProductFloor(t, "", errors.New("state unreadable"))
			err := h.env.BundleProductFloorRefusal("1.0.4")
			if err == nil || !strings.Contains(err.Error(), "run `"+tc.gateway+" enterprise bundle apply --bundle <file> --json`") ||
				strings.Contains(err.Error(), "`defenseclaw-gateway") {
				t.Fatalf("floor refusal = %v", err)
			}
		})
	}
}

// A hint written as a Go string must not name the gateway bare. The one
// allowed place is the comment of the tmpfiles override the uninstall writes
// to /etc: it records which command wrote the file.
func TestNoAdministratorHintNamesTheGatewayBare(t *testing.T) {
	bare := regexp.MustCompile("`defenseclaw-gateway [a-z]")
	allowed := map[string]bool{"layout.go": true}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") || allowed[file] {
			continue
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for number, line := range strings.Split(string(raw), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			if bare.MatchString(line) {
				t.Errorf("%s:%d names the gateway by its bare name; use Env.gatewayCommand: %s", file, number+1, trimmed)
			}
		}
	}
}

// The standalone lifecycle never runs on a Secure Client computer: an install
// is refused as a profile conflict, and a status with no standalone record
// does not read the gateway, so none of the lines that name the gateway by its
// layout path (the bundle commands, the optional destination hint) reaches a
// Secure Client computer (review round 4, S1).
func TestStandaloneGatewayHintsDoNotReachASecureClientComputer(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			if err := os.MkdirAll(h.env.P("/opt/cisco/secureclient/defenseclaw"), 0o755); err != nil {
				t.Fatal(err)
			}
			healthReads := 0
			h.env.HealthGet = func(context.Context) (int, []byte, error) {
				healthReads++
				return 200, []byte(`{"api":{"state":"running"},"telemetry":{"details":{"optional_destination_state":"degraded","optional_destination_failure_summary":"archive:failing:no_space"}}}`), nil
			}
			install := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")})
			requireError(t, install, codeProfileConflict)
			status := h.run(Options{Action: ActionStatus})
			if healthReads != 0 {
				t.Fatalf("the gateway health was read %d times on a Secure Client computer", healthReads)
			}
			for _, result := range []*enterprisestatus.Result{install, status} {
				for _, m := range append(append([]enterprisestatus.Message{}, result.Errors...), result.Warnings...) {
					if m.Code == codeOptionalDestination || strings.Contains(m.Message, "bundle apply") || strings.Contains(m.Message, "bundle anchors install") {
						t.Errorf("%s message on a Secure Client computer: %+v", goos, m)
					}
				}
			}
		})
	}
}
