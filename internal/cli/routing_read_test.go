// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestRoutingReadRefusesOtherRoutes(t *testing.T) {
	if routingReadCmd.Annotations["defenseclaw.skip-daemon-bootstrap"] != "true" {
		t.Fatal("a standard account runs routing-read without config.yaml")
	}
	for _, c := range []*cobra.Command{budgetStoreServeCmd, budgetStoreIssueCmd, budgetStoreAddCmd, budgetStoreRevokeCmd, budgetStoreListCmd, budgetStoreReportCmd} {
		if !skipsDaemonBootstrap(c) {
			t.Fatalf("budget-store %s runs on a store host without a gateway config", c.Name())
		}
	}
	for _, path := range []string{"/api/v1/routing/test", "/api/v1/usage", "/api/v1/config"} {
		var out bytes.Buffer
		routingReadCmd.SetOut(&out)
		err := routingReadCmd.RunE(routingReadCmd, []string{path})
		if err == nil || !strings.Contains(err.Error(), "PATH must be") {
			t.Fatalf("%s: %v", path, err)
		}
	}
}
