// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// GAP-0858: a removed connector whose teardown removed its hook registration
// but could not delete its scoped hook credential was accepted by
// VerifyClean, its lock cleared and the connector marked removed, while the
// token file still authenticated to its hook route. A teardown that failed
// is now finished only once the credential is gone: until then the removal
// stays pending (failed, lock kept) for the next start to retry. A teardown
// that failed for another reason after revoking the credential, one that
// succeeded and a managed deployment are unchanged.
func TestRemovedConnectorWithAFailedCredentialRevocationStaysPending(t *testing.T) {
	revokeFailed := errors.New("codex teardown: codex revoke removed hook credential: remove hook API token: Access is denied")
	for _, tc := range []struct {
		name        string
		teardownErr error
		keepToken   bool
		managed     bool
		wantPending bool
	}{
		{name: "the credential could not be deleted", teardownErr: revokeFailed, keepToken: true, wantPending: true},
		{name: "another teardown error after the credential went", teardownErr: errors.New("revoke scoped OTLP token: busy")},
		{name: "a teardown that succeeded", keepToken: true},
		{name: "a managed deployment", teardownErr: revokeFailed, keepToken: true, managed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := t.TempDir()
			if tc.keepToken {
				if _, err := connector.EnsureHookAPIToken(dataDir, "codex"); err != nil {
					t.Fatal(err)
				}
			}
			opts := connector.SetupOpts{DataDir: dataDir, ManagedEnterprise: tc.managed}
			for _, path := range []string{"multi-connector removal", "connector switch"} {
				conn := &recordingConnector{stubConnector: stubConnector{name: "codex"}, teardownErr: tc.teardownErr}
				other := &recordingConnector{stubConnector: stubConnector{name: "cursor"}}
				reg := newRecordingRegistry(conn, other)
				var pending bool
				var detail string
				if path == "multi-connector removal" {
					failed, _ := teardownRemovedConnectorsReport(reg, []string{"codex", "cursor"}, []string{"cursor"}, opts, context.Background())
					pending = len(failed) == 1 && failed[0] == "codex"
					detail = strings.Join(failed, ",")
				} else {
					if err := connector.SaveActiveConnector(dataDir, "codex"); err != nil {
						t.Fatal(err)
					}
					err := teardownPreviousConnector(reg, "cursor", opts, context.Background())
					pending = err != nil
					if err != nil {
						detail = err.Error()
					}
				}
				if pending != tc.wantPending {
					t.Fatalf("%s: removal pending = %t (%s), want %t", path, pending, detail, tc.wantPending)
				}
				if tc.wantPending && path == "connector switch" && !strings.Contains(detail, "hook credential") {
					t.Fatalf("%s: the error does not name the credential: %s", path, detail)
				}
			}
		})
	}
}
