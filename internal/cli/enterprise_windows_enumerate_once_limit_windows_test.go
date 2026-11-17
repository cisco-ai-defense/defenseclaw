// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// GAP-1109: Setup reported only that enumerate --once ran past 900 seconds.
// Past its own limit --once fails first and names the step and the profile
// it was waiting on, on stdout, which Setup's diagnostic starts with.
func TestEnterpriseWindowsEnumerateOnceLimitNamesTheProfile(t *testing.T) {
	const step = `inspecting the profile dcw-orphan07 (S-1-5-21-1004336348-1177238915-682003330-2008), 8 of 46`
	cfg := standaloneWindowsEnrollmentConfig(config.EnterpriseEnrollmentConfig{})
	manifest := filepath.Join(t.TempDir(), "targets.yaml")
	previousConfig := enterpriseWindowsEnumerateConfigLoader
	previousEnumerator := enterpriseWindowsEnumerateProfileEnumerator
	previousLimit := enterpriseWindowsEnumerateOnceLimit
	release := make(chan struct{})
	walked := make(chan struct{})
	t.Cleanup(func() {
		close(release)
		select {
		case <-walked:
		case <-time.After(10 * time.Second):
		}
		enterpriseWindowsEnumerateConfigLoader = previousConfig
		enterpriseWindowsEnumerateProfileEnumerator = previousEnumerator
		enterpriseWindowsEnumerateOnceLimit = previousLimit
	})
	enterpriseWindowsEnumerateConfigLoader = func() (*config.Config, error) { return cfg, nil }
	enterpriseWindowsEnumerateProfileEnumerator = func(_ context.Context, _ *config.Config, opts enterprisehooks.EnumerateOptions) (enterprisehooks.Manifest, error) {
		defer close(walked)
		opts.Progress(step)
		<-release
		return enterprisehooks.Manifest{}, errors.New("released by the test")
	}
	enterpriseWindowsEnumerateOnceLimit = 5 * time.Second
	cmd := &cobra.Command{}
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	err := runEnterpriseWindowsEnumerate(context.Background(), cmd, &enterpriseWindowsEnumerateOptions{manifestPath: manifest, once: true})
	if err == nil || !strings.Contains(err.Error(), "did not finish within 5s") || !strings.Contains(err.Error(), step) {
		t.Fatalf("err = %v, want the --once limit naming %q", err, step)
	}
	if !strings.HasPrefix(stdout.String(), "[hook-enumerator] ERROR ") || !strings.Contains(stdout.String(), step) {
		t.Fatalf("stdout = %q, want the verdict naming the profile first", stdout.String())
	}
}
