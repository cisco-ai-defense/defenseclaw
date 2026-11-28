// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// teardownRefusingConnector is a connector whose removal cannot finish: its
// own error names the file and the fix.
type teardownRefusingConnector struct {
	connector.Connector
	why string
}

func (c teardownRefusingConnector) Teardown(context.Context, connector.SetupOpts) error {
	return errors.New(c.why)
}
func (c teardownRefusingConnector) VerifyClean(connector.SetupOpts) error { return errors.New(c.why) }

// rel-1-0-10 GAP-1549: a removed connector whose teardown cannot finish (an
// unparsable agent file its record names) kept the gateway down, and the error
// the start returned said only that the teardown was incomplete: the file was
// in gateway.log alone. The error now carries the connector's own words.
func TestRemovedConnectorTeardownFailureNamesTheFileInTheStartError(t *testing.T) {
	testenv.IsolateAccount(t)
	builtins := connector.NewDefaultRegistry()
	original, _ := builtins.Get("kiro")
	const why = "kiro cleanup incomplete: /home/u/.kiro/agents/mine.json, which a backup record of this install names, is not a JSON object; fix or remove the file and run the removal again"
	conn := teardownRefusingConnector{Connector: original, why: why}
	opts := connector.SetupOpts{DataDir: t.TempDir(), APIAddr: "127.0.0.1:18970", APIToken: "test-token"}
	point := multiConnectorSetupRollbackPoint{conn: conn, opts: opts, previousLock: connector.NewHookContractLockEntry(opts, conn, "test-build")}
	removed, failed, causes := teardownRemovedConnectorCandidates([]multiConnectorSetupRollbackPoint{point}, context.Background())
	if len(removed) != 0 || len(failed) != 1 || failed[0] != "kiro" {
		t.Fatalf("removed=%d failed=%v", len(removed), failed)
	}
	msg := connectorTeardownCauses(failed, causes)
	if !strings.Contains(msg, "mine.json") || !strings.Contains(msg, "fix or remove the file") || !strings.HasPrefix(msg, "kiro (") {
		t.Fatalf("the start error does not carry the cause: %q", msg)
	}
	if got := connectorTeardownCauses([]string{"a", "b"}, map[string]string{"b": "why b"}); got != "a; b (why b)" {
		t.Fatalf("causes = %q", got)
	}
}
