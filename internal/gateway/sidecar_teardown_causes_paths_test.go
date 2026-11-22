// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// rel-1-0-10 GAP-1745: the removed-connector teardown paths that returned only
// the connector's name now carry why: the disabled-guardrail pass
// (teardownRemovedConnectorsWhy) and the rollback authority that could not be
// captured (removedConnectorRollbackCandidates).
func TestRemovedConnectorTeardownCausesReachEveryReturnPath(t *testing.T) {
	testenv.IsolateAccount(t)
	builtins := connector.NewDefaultRegistry()
	original, _ := builtins.Get("kiro")
	const why = "kiro cleanup incomplete: /home/u/.kiro/agents/mine.json is not a JSON object; fix or remove the file"
	conn := teardownRefusingConnector{Connector: original, why: why}
	reg := connector.NewRegistry()
	reg.RegisterBuiltin(conn)
	opts := connector.SetupOpts{DataDir: t.TempDir(), APIAddr: "127.0.0.1:18970", APIToken: "test-token"}

	failed, _, causes := teardownRemovedConnectorsWhy(reg, []string{"kiro"}, nil, opts, "", context.Background())
	if len(failed) != 1 {
		t.Fatalf("failed = %v", failed)
	}
	if got := connectorTeardownCauses(failed, causes); !strings.Contains(got, "mine.json") {
		t.Fatalf("the disabled-guardrail error does not carry the cause: %q", got)
	}
	if got := connectorCausesSuffix(nil, nil); got != "" {
		t.Fatalf("no failed connector: %q", got)
	}
	if got := connectorCausesSuffix([]string{"kiro"}, map[string]string{"kiro": "why"}); got != ": kiro (why)" {
		t.Fatalf("suffix = %q", got)
	}
}
