// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
)

// hookOutageFailModeNow is the gateway-outage mode the config of the per-user
// hook runtime in hookDir gives connectorName's hooks now
// (config.HookOutageFailMode of its policy tier): "open" only when this
// release loads that config, the install is neither managed nor Secure
// Client, and the connector's rule pack is not strict. Every other case is
// "closed".
//
// A per-user hook asks only for a classified gateway outage. Its current
// config decides even when a setup-time record has a different tier.
//
// The policy source is the runtime's own config, config.yaml in the data
// directory above hookDir, whose data_dir is that directory: the folder the
// gateway rendered the hooks into. The hook process's DEFENSECLAW_CONFIG and
// DEFENSECLAW_HOME come from the agent and never choose it, so an agent that
// points them at another default-tier config cannot reopen a strict outage.
// A config kept outside its data directory closes the outage.
func hookOutageFailModeNow(connectorName, hookDir string) string {
	name := strings.ToLower(strings.TrimSpace(connectorName))
	hookDir = strings.TrimSpace(hookDir)
	if name == "" || hookDir == "" || !filepath.IsAbs(hookDir) {
		return "closed"
	}
	dataDir := filepath.Dir(filepath.Clean(hookDir))
	loaded, err := config.LoadFromFile(filepath.Join(dataDir, config.DefaultConfigName))
	if err != nil || loaded == nil || managed.IsManagedEnterprise(loaded.DeploymentMode) || loaded.SecureClientIntegration() {
		return "closed"
	}
	// The machine installation marker is an independent managed signal. A
	// leftover per-user hook cannot reopen a managed host just because its
	// own config still says OSS; an unreadable marker state also closes it.
	if secureClientHost() {
		return "closed"
	}
	if _, present := managedHostWindowsStandalone(); present {
		return "closed"
	}
	if marker := managedHostDescriptorPath(); marker != "" {
		if _, err := os.Lstat(marker); err == nil || !errors.Is(err, os.ErrNotExist) {
			return "closed"
		}
	}
	// An environment that moves the loader's data directory, or a config
	// whose data_dir is elsewhere, is not this runtime's config.
	if !pathidentity.Same(loaded.DataDir, dataDir) {
		return "closed"
	}
	if loaded.EffectiveHookOutageFailModeForConnector(name) == "open" {
		return "open"
	}
	return "closed"
}

func init() {
	var connectorName, hookDir string
	cmd := &cobra.Command{
		Use:    "hook-outage-mode",
		Short:  "Print the gateway-outage mode the config gives a per-user connector's hooks now",
		Hidden: true,
		// A hook runs it while the gateway is down: no daemon bootstrap,
		// no audit store, only a read of config.yaml.
		Annotations: map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"},
		Args:        cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), hookOutageFailModeNow(connectorName, hookDir))
			return err
		},
	}
	cmd.Flags().StringVar(&connectorName, "connector", "", "connector name")
	cmd.Flags().StringVar(&hookDir, "hook-dir", "", "absolute hooks folder of the hook runtime asking")
	_ = cmd.MarkFlagRequired("connector")
	rootCmd.AddCommand(cmd)
}
