// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

var checkAPIPortConfigPath string

// checkAPIPortCmd is the installer's pre-flight for an upgrade: the staged
// gateway reads the API port out of the installed config and refuses, before
// the installer builds anything or stops the old gateway, a port that another
// account's process holds (GAP-0130). It reads only gateway.api_bind and
// gateway.api_port, so it works on a config older than the staged release.
var checkAPIPortCmd = &cobra.Command{
	Use:    "check-api-port",
	Short:  "Installer pre-flight: refuse an API port another account holds",
	Hidden: true,
	Args:   cobra.NoArgs,
	// No config or audit bootstrap: the installed config may predate this binary.
	PersistentPreRunE: func(_ *cobra.Command, _ []string) error { return nil },
	PersistentPostRun: func(_ *cobra.Command, _ []string) {},
	RunE: func(_ *cobra.Command, _ []string) error {
		return checkAPIPort(checkAPIPortConfigPath)
	},
}

func init() {
	checkAPIPortCmd.Flags().StringVar(
		&checkAPIPortConfigPath, "config", "",
		"configuration file (default: DEFENSECLAW_CONFIG or <data-dir>/config.yaml)",
	)
	rootCmd.AddCommand(checkAPIPortCmd)
}

// checkAPIPort returns the reason this account's gateway cannot use the API
// port in the config file at path, and what to do about it. A missing or
// unreadable config has nothing to check: the first run picks its own port.
func checkAPIPort(path string) error {
	if path == "" {
		path = os.Getenv("DEFENSECLAW_CONFIG")
	}
	if path == "" {
		path = filepath.Join(config.DefaultDataPath(), "config.yaml")
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var doc struct {
		Gateway struct {
			APIBind string `yaml:"api_bind"`
			APIPort int    `yaml:"api_port"`
		} `yaml:"gateway"`
	}
	if yaml.Unmarshal(raw, &doc) != nil {
		return nil // the installer's config check reports a malformed file
	}
	c := config.DefaultConfig()
	c.Gateway.APIBind = doc.Gateway.APIBind
	if doc.Gateway.APIPort > 0 {
		c.Gateway.APIPort = doc.Gateway.APIPort
	}
	host := gatewayClientHost(c)
	problem := otherAccountListenerAt(host, c.Gateway.APIPort)
	if problem == "" {
		return nil
	}
	port := "<free port>"
	if free := freeGatewayAPIPort(host, c.Gateway.APIPort); free > 0 {
		port = strconv.Itoa(free)
	}
	return fmt.Errorf(
		"%s, so the upgraded gateway could not start. Move this account's gateway to a free port with: "+
			"defenseclaw setup gateway --api-port %s --non-interactive, then upgrade again",
		problem, port,
	)
}
