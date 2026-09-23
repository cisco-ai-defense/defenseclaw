// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

const ampGatewayFixtureVersion = "0.0.1785875347-gbc402f"

type ampGatewayAuthorityFixture struct {
	opts           connector.SetupOpts
	executablePath string
	pluginPath     string
	receiptPath    string
}

// ampExecutableDriftAfterSetupConnector lets the real Amp Setup complete and
// then replaces the selected executable before the sidecar's fresh lock
// publication. That deterministically exercises the late admission check,
// while retaining Amp's real plugin setup, verification, and teardown paths.
type ampExecutableDriftAfterSetupConnector struct {
	*connector.AMPConnector
	executablePath string
	setupCalls     int
	teardownCalls  int
	drifted        bool
}

func (c *ampExecutableDriftAfterSetupConnector) Setup(ctx context.Context, opts connector.SetupOpts) error {
	c.setupCalls++
	if err := c.AMPConnector.Setup(ctx, opts); err != nil {
		return err
	}
	if err := os.WriteFile(c.executablePath, []byte("MZ drifted Amp image after plugin setup"), 0o700); err != nil {
		return fmt.Errorf("replace Amp executable after setup: %w", err)
	}
	c.drifted = true
	return nil
}

func (c *ampExecutableDriftAfterSetupConnector) Teardown(ctx context.Context, opts connector.SetupOpts) error {
	c.teardownCalls++
	return c.AMPConnector.Teardown(ctx, opts)
}

func prepareAmpGatewayAuthorityFixture(t *testing.T, dataDir string) ampGatewayAuthorityFixture {
	t.Helper()
	if err := safefile.ProtectDirectory(dataDir); err != nil {
		t.Fatalf("protect Amp fixture data directory: %v", err)
	}

	executableRoot := testenv.PrivateTempDir(t)
	executablePath := filepath.Join(executableRoot, "amp.exe")
	executableBody := []byte("MZ native Amp gateway fixture")
	if err := os.WriteFile(executablePath, executableBody, 0o700); err != nil {
		t.Fatalf("write Amp fixture executable: %v", err)
	}
	digest := sha256.Sum256(executableBody)
	now := time.Now().UTC().Truncate(time.Second)
	receipt := map[string]any{
		"schema_version": 1,
		"updated_at":     now.Format(time.RFC3339),
		"selections": map[string]any{
			"amp": map[string]any{
				"connector":          "amp",
				"source":             "setup-selected",
				"executable":         executablePath,
				"raw_version":        ampGatewayFixtureVersion,
				"normalized_version": "0.0.1785875347",
				"sha256":             fmt.Sprintf("%x", digest[:]),
				"selected_at":        now.Format(time.RFC3339),
				"expires_at":         now.Add(15 * time.Minute).Format(time.RFC3339),
			},
		},
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatalf("encode Amp setup authority fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "agent_selection.json"), encoded, 0o600); err != nil {
		t.Fatalf("publish Amp setup authority fixture: %v", err)
	}

	pluginRoot := testenv.PrivateTempDir(t)
	pluginPath := filepath.Join(pluginRoot, "plugins", "defenseclaw.ts")
	previousPluginPath := connector.AMPPluginPathOverride
	connector.AMPPluginPathOverride = pluginPath
	t.Cleanup(func() { connector.AMPPluginPathOverride = previousPluginPath })

	return ampGatewayAuthorityFixture{
		opts: connector.SetupOpts{
			DataDir:         dataDir,
			APIAddr:         "127.0.0.1:18970",
			HookFailMode:    "closed",
			GuardrailMode:   "action",
			AgentVersion:    ampGatewayFixtureVersion,
			AgentExecutable: executablePath,
			HookContractID:  "amp-plugin-v1",
		},
		executablePath: executablePath,
		pluginPath:     pluginPath,
		receiptPath:    filepath.Join(dataDir, "connector_backups", "amp", "config.json"),
	}
}

func readAmpGatewayFixtureFile(t *testing.T, path string) []byte {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture file %s: %v", path, err)
	}
	return body
}

func assertAmpGatewayFixtureFileAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("fixture path %s remains after rollback: %v", path, err)
	}
}

func TestSetupConnectorsIsolated_AmpLatePublicationFailureRestoresPreviouslyActiveRegistration(t *testing.T) {
	s := multiBootSidecar(t)
	s.cfg.DataDir = testenv.PrivateTempDir(t)
	fixture := prepareAmpGatewayAuthorityFixture(t, s.cfg.DataDir)

	prior := connector.NewAMPConnector()
	if err := prior.Setup(context.Background(), fixture.opts); err != nil {
		t.Fatalf("stage prior Amp plugin registration: %v", err)
	}
	priorLock := connector.NewHookContractLockEntry(fixture.opts, prior, "prior-test-build")
	if err := connector.SaveFreshHookContractLockEntry(s.cfg.DataDir, priorLock); err != nil {
		t.Fatalf("seal prior Amp executable authority: %v", err)
	}
	if err := connector.SaveActiveConnectors(s.cfg.DataDir, []string{"amp"}); err != nil {
		t.Fatalf("stage prior Amp active roster: %v", err)
	}
	// Exercise durable lock authority, not the short-lived setup receipt.
	if err := os.Remove(filepath.Join(s.cfg.DataDir, "agent_selection.json")); err != nil {
		t.Fatalf("remove staged Amp setup receipt: %v", err)
	}

	pluginBefore := readAmpGatewayFixtureFile(t, fixture.pluginPath)
	receiptBefore := readAmpGatewayFixtureFile(t, fixture.receiptPath)
	lockPath := filepath.Join(s.cfg.DataDir, "hook_contract_lock.json")
	lockBefore := readAmpGatewayFixtureFile(t, lockPath)

	failed := &ampExecutableDriftAfterSetupConnector{
		AMPConnector:   connector.NewAMPConnector(),
		executablePath: fixture.executablePath,
	}
	got, err := s.setupConnectorsIsolated(
		context.Background(),
		[]connector.Connector{failed},
		"tok", "127.0.0.1:4000", "127.0.0.1:18971", "master",
		guardrail.NewRulePackCache(),
	)
	if err != nil {
		t.Fatalf("isolated Amp late-publication handling: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("succeeded = %v, want Amp skipped after late publication rejection", got)
	}
	if failed.setupCalls != 1 || !failed.drifted || failed.teardownCalls != 1 {
		t.Fatalf(
			"Amp lifecycle setup=%d drifted=%t teardown=%d, want completed Setup, injected drift, and rollback teardown",
			failed.setupCalls, failed.drifted, failed.teardownCalls,
		)
	}
	if pluginAfter := readAmpGatewayFixtureFile(t, fixture.pluginPath); !bytes.Equal(pluginAfter, pluginBefore) {
		t.Fatal("previously-active Amp plugin bytes changed across rejected fresh publication")
	}
	if receiptAfter := readAmpGatewayFixtureFile(t, fixture.receiptPath); !bytes.Equal(receiptAfter, receiptBefore) {
		t.Fatal("previously-active Amp custody receipt bytes changed across rejected fresh publication")
	}
	if lockAfter := readAmpGatewayFixtureFile(t, lockPath); !bytes.Equal(lockAfter, lockBefore) {
		t.Fatal("previously-active Amp hook contract lock bytes changed across rejected fresh publication")
	}
	if active := connector.LoadActiveConnectors(s.cfg.DataDir); len(active) != 1 || active[0] != "amp" {
		t.Fatalf("active connectors = %v, want exact prior Amp roster", active)
	}
}

func TestSetupConnectorsIsolated_AmpLatePublicationFailureRemovesFreshRegistration(t *testing.T) {
	s := multiBootSidecar(t)
	s.cfg.DataDir = testenv.PrivateTempDir(t)
	fixture := prepareAmpGatewayAuthorityFixture(t, s.cfg.DataDir)
	lockPath := filepath.Join(s.cfg.DataDir, "hook_contract_lock.json")

	assertAmpGatewayFixtureFileAbsent(t, fixture.pluginPath)
	assertAmpGatewayFixtureFileAbsent(t, fixture.receiptPath)
	assertAmpGatewayFixtureFileAbsent(t, lockPath)

	failed := &ampExecutableDriftAfterSetupConnector{
		AMPConnector:   connector.NewAMPConnector(),
		executablePath: fixture.executablePath,
	}
	got, err := s.setupConnectorsIsolated(
		context.Background(),
		[]connector.Connector{failed},
		"tok", "127.0.0.1:4000", "127.0.0.1:18971", "master",
		guardrail.NewRulePackCache(),
	)
	if err != nil {
		t.Fatalf("isolated fresh Amp late-publication handling: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("succeeded = %v, want fresh Amp skipped after late publication rejection", got)
	}
	if failed.setupCalls != 1 || !failed.drifted || failed.teardownCalls != 1 {
		t.Fatalf(
			"Amp lifecycle setup=%d drifted=%t teardown=%d, want completed Setup, injected drift, and rollback teardown",
			failed.setupCalls, failed.drifted, failed.teardownCalls,
		)
	}
	assertAmpGatewayFixtureFileAbsent(t, fixture.pluginPath)
	assertAmpGatewayFixtureFileAbsent(t, fixture.receiptPath)
	assertAmpGatewayFixtureFileAbsent(t, lockPath)
	if active := connector.LoadActiveConnectors(s.cfg.DataDir); len(active) != 0 {
		t.Fatalf("active connectors = %v, want fresh failed Amp absent", active)
	}
}
