// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

func TestPerUserNativeCapableHooksRecordHookOnlyCustody(t *testing.T) {
	installCorrelationHMACForTest()
	for _, connectorName := range []string{"codex", "claudecode"} {
		for _, prior := range []audit.ConnectorExportCustody{"", audit.ConnectorCustodyExternal, audit.ConnectorCustodyDefenseClaw} {
			t.Run(connectorName+"/prior="+string(prior), func(t *testing.T) {
				server, store := newHookCorrelationServer(t, filepath.Join(t.TempDir(), "audit.db"))
				defer store.Close() //nolint:errcheck
				server.scannerCfg = config.DefaultConfig()
				profile := server.hookProfileForConnector(connectorName)
				repo, err := store.CorrelationRepository()
				if err != nil {
					t.Fatal(err)
				}
				if prior != "" {
					if _, err := repo.ResolveConnectorInstance(t.Context(), connectorName, string(profile.Correlation.ProfileVersion), prior); err != nil {
						t.Fatal(err)
					}
				}
				body := []byte(`{"hook_event_name":"SessionStart","session_id":"session-1"}`)
				payload := map[string]interface{}{"hook_event_name": "SessionStart", "session_id": "session-1"}
				request := normalizeAgentHookRequestWithProfile(connectorName, payload, profile)
				if _, _, err := server.correlateHookOccurrence(t.Context(), profile, request, body); err != nil {
					t.Fatal(err)
				}
				instances, err := repo.ListConnectorInstances(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				if len(instances) != 1 || instances[0].ExportCustody != audit.ConnectorCustodyHookOnly {
					t.Fatalf("per-user %s custody = %+v, want hook_only", connectorName, instances)
				}
			})
		}
	}
}

func TestPerUserSandboxNativeCustodyRemainsSeparate(t *testing.T) {
	installCorrelationHMACForTest()
	server, store := newHookCorrelationServer(t, filepath.Join(t.TempDir(), "audit.db"))
	defer store.Close() //nolint:errcheck
	server.scannerCfg = config.DefaultConfig()
	ctx := sandboxauth.WithRequest(t.Context(), sandboxauth.Binding{ID: "sb_0000000000000000000000000000000a", Connector: "claudecode"}, nil)
	ctx = withAuthenticatedHookConnector(ctx, "claudecode")
	profile := server.hookProfileForRequest(ctx, "claudecode")
	body := []byte(`{"hook_event_name":"UserPromptSubmit","session_id":"session-1","prompt":"hello"}`)
	payload := map[string]interface{}{
		"hook_event_name": "UserPromptSubmit", "session_id": "session-1", "prompt": "hello",
	}
	request := normalizeAgentHookRequestWithProfile("claudecode", payload, profile)
	if _, _, err := server.correlateHookOccurrence(ctx, profile, request, body); err != nil {
		t.Fatal(err)
	}
	repo, err := store.CorrelationRepository()
	if err != nil {
		t.Fatal(err)
	}
	instances, err := repo.ListConnectorInstances(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(instances) != 1 || instances[0].ExportCustody != audit.ConnectorCustodyExternal {
		t.Fatalf("per-user sandbox custody = %+v, want external until native delivery", instances)
	}
}

func TestManagedNativeCapableHooksKeepExternalCustodyUntilDelivery(t *testing.T) {
	installCorrelationHMACForTest()
	for _, managedProfile := range []string{managed.ProfileStandalone, managed.ProfileSecureClient} {
		t.Run(managedProfile, func(t *testing.T) {
			server, store := newHookCorrelationServer(t, filepath.Join(t.TempDir(), "audit.db"))
			defer store.Close() //nolint:errcheck
			server.scannerCfg = &config.Config{
				DeploymentMode: managed.DeploymentModeManagedEnterprise,
				Enterprise:     config.EnterpriseConfig{Profile: managedProfile},
			}
			profile := server.hookProfileForConnector("claudecode")
			body := []byte(`{"hook_event_name":"UserPromptSubmit","session_id":"session-1","prompt":"hello"}`)
			payload := map[string]interface{}{
				"hook_event_name": "UserPromptSubmit", "session_id": "session-1", "prompt": "hello",
			}
			request := normalizeAgentHookRequestWithProfile("claudecode", payload, profile)
			if _, _, err := server.correlateHookOccurrence(t.Context(), profile, request, body); err != nil {
				t.Fatal(err)
			}
			repo, err := store.CorrelationRepository()
			if err != nil {
				t.Fatal(err)
			}
			instances, err := repo.ListConnectorInstances(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if len(instances) != 1 || instances[0].ExportCustody != audit.ConnectorCustodyExternal {
				t.Fatalf("managed %s custody = %+v, want external until native delivery", managedProfile, instances)
			}
		})
	}
}
