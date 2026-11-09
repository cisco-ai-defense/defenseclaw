// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

const (
	kubernetesNamedSecretReadRuleID          = "credential.kubernetes_named_secret_content_read"
	protectedKubernetesNamedSecretReadRuleID = "credential.protected_kubernetes_named_secret_content_read"
	pamPermitAuthenticationBypassRuleID      = "tamper.pam_permit_authentication_bypass"
	dockerInsecureHTTPRegistryRuleID         = "tamper.docker_insecure_http_registry"
)

func TestExactAdministrativeSecurityRulePosture(t *testing.T) {
	tests := []struct {
		name    string
		ruleID  string
		input   actionfacts.Input
		actions map[string]string
	}{
		{
			name:   "PAM authentication bypass",
			ruleID: pamPermitAuthenticationBypassRuleID,
			input: exactStructuredInput(t, "Write", map[string]any{
				"file_path": "/etc/pam.d/sshd",
				"content":   "auth sufficient pam_permit.so\n",
			}),
			actions: map[string]string{"default": "block", "permissive": "alert", "strict": "block"},
		},
		{
			name:   "Docker insecure HTTP registry",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "Write", map[string]any{
				"file_path": "/etc/docker/daemon.json",
				"content":   `{"insecure-registries":["http://mirror.local"]}`,
			}),
			actions: map[string]string{"default": "block", "permissive": "alert", "strict": "block"},
		},
		{
			name:   "Docker insecure registry host:port",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "Write", map[string]any{
				"file_path": "/etc/docker/daemon.json",
				"content":   `{"insecure-registries":["198.51.100.7:5000"]}`,
			}),
			actions: map[string]string{"default": "block", "permissive": "alert", "strict": "block"},
		},
		{
			name:   "Docker insecure registry CIDR",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "Write", map[string]any{
				"file_path": "/etc/docker/daemon.json",
				"content":   `{"insecure-registries":["10.0.0.0/8"]}`,
			}),
			actions: map[string]string{"default": "block", "permissive": "alert", "strict": "block"},
		},
		{
			name:   "Docker insecure registry HTTPS URL",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "Write", map[string]any{
				"file_path": "/etc/docker/daemon.json",
				"content":   `{"insecure-registries":["https://mirror.local"]}`,
			}),
			actions: map[string]string{"default": "block", "permissive": "alert", "strict": "block"},
		},
		{
			name:   "Docker insecure registry with other settings",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "Write", map[string]any{
				"file_path": "/etc/docker/daemon.json",
				"content":   `{"log-driver":"json-file","insecure-registries":["198.51.100.7:5000"],"debug":true}`,
			}),
			actions: map[string]string{"default": "block", "permissive": "alert", "strict": "block"},
		},
		{
			name:   "Docker insecure registry listed twice",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "Write", map[string]any{
				"file_path": "/etc/docker/daemon.json",
				"content":   `{"insecure-registries":["198.51.100.7:5000","198.51.100.7:5000"]}`,
			}),
			actions: map[string]string{"default": "block", "permissive": "alert", "strict": "block"},
		},
		{
			name:   "Docker insecure registry upper-case scheme",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "Write", map[string]any{
				"file_path": "/etc/docker/daemon.json",
				"content":   `{"insecure-registries":["HTTP://198.51.100.7:5000"]}`,
			}),
			actions: map[string]string{"default": "block", "permissive": "alert", "strict": "block"},
		},
		{
			name:   "Docker insecure registry zero-padded port",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "Write", map[string]any{
				"file_path": "/etc/docker/daemon.json",
				"content":   `{"insecure-registries":["198.51.100.7:05000"]}`,
			}),
			actions: map[string]string{"default": "block", "permissive": "alert", "strict": "block"},
		},
		{
			name:   "Docker insecure registry through a dot-dot path",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "Write", map[string]any{
				"file_path": "/etc/docker/../docker/daemon.json",
				"content":   `{"insecure-registries":["http://mirror.local"]}`,
			}),
			actions: map[string]string{"default": "block", "permissive": "alert", "strict": "block"},
		},
		{
			name:   "Docker insecure registry in an Edit fragment",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "Edit", map[string]any{
				"file_path":  "/etc/docker/daemon.json",
				"old_string": `"log-driver": "json-file"`,
				"new_string": `"log-driver": "json-file", "insecure-registries": ["http://mirror.local:5000"]`,
			}),
			actions: map[string]string{"default": "block", "permissive": "alert", "strict": "block"},
		},
		{
			name:   "Docker insecure registry in a MultiEdit fragment",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "MultiEdit", map[string]any{
				"file_path": "/etc/docker/daemon.json",
				"edits": []any{map[string]any{
					"old_string": `"debug": true`,
					"new_string": `"debug": true, "insecure-registries": ["198.51.100.7:5000"]`,
				}},
			}),
			actions: map[string]string{"default": "block", "permissive": "alert", "strict": "block"},
		},
		{
			name:   "Docker insecure registry taking over in an Edit of a complete document",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "Edit", map[string]any{
				"file_path":  "/etc/docker/daemon.json",
				"old_string": `{"insecure-registries":["198.51.100.7:5000"],"insecure-registries":[]}`,
				"new_string": `{"insecure-registries":[],"insecure-registries":["198.51.100.7:5000"]}`,
			}),
			actions: map[string]string{"default": "block", "permissive": "alert", "strict": "block"},
		},
		{
			name:   "Docker insecure registry taking over in a two-step MultiEdit",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "MultiEdit", map[string]any{
				"file_path": "/etc/docker/daemon.json",
				"edits": []any{
					map[string]any{
						"old_string": `"insecure-registries":["198.51.100.7:5000"],"insecure-registries":[]`,
						"new_string": `"insecure-registries":[],"insecure-registries":["198.51.100.7:5000"]`,
					},
					map[string]any{"old_string": `"debug":true`, "new_string": `"debug":false`},
				},
			}),
			actions: map[string]string{"default": "block", "permissive": "alert", "strict": "block"},
		},
		{
			name:   "Docker insecure registry taking over in a multi-line patch",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "apply_patch", map[string]any{
				"command": "*** Begin Patch\n*** Update File: /etc/docker/daemon.json\n@@\n" +
					"-  \"insecure-registries\":[\"198.51.100.7:5000\"],\n-  \"insecure-registries\":[],\n-  \"debug\":true\n" +
					"+  \"insecure-registries\":[],\n+  \"insecure-registries\":[\"198.51.100.7:5000\"],\n+  \"debug\":false\n" +
					"*** End Patch\n",
			}),
			actions: map[string]string{"default": "block", "permissive": "alert", "strict": "block"},
		},
		{
			name:   "Docker insecure registry after an object with a repeated key in an Edit",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "Edit", map[string]any{
				"file_path":  "/etc/docker/daemon.json",
				"old_string": `{}`,
				"new_string": `{"debug":true,"debug":false},"insecure-registries":["198.51.100.7:5000"]`,
			}),
			actions: map[string]string{"default": "block", "permissive": "alert", "strict": "block"},
		},
		{
			name:   "Docker insecure registry moving between two keys in a MultiEdit",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "MultiEdit", map[string]any{
				"file_path": "/etc/docker/daemon.json",
				"edits": []any{
					map[string]any{
						"old_string": `"insecure-registries":["198.51.100.7:5000"],`,
						"new_string": `"insecure-registries":[],`,
					},
					map[string]any{
						"old_string": `"insecure-registries":[]}`,
						"new_string": `"insecure-registries":["198.51.100.7:5000"]}`,
					},
				},
			}),
			actions: map[string]string{"default": "block", "permissive": "alert", "strict": "block"},
		},
		{
			name:   "Docker insecure registry moving between two keys in two patch hunks",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "apply_patch", map[string]any{
				"command": "*** Begin Patch\n*** Update File: /etc/docker/daemon.json\n@@\n" +
					"-  \"insecure-registries\":[\"198.51.100.7:5000\"],\n+  \"insecure-registries\":[],\n" +
					"@@\n-  \"insecure-registries\":[]\n+  \"insecure-registries\":[\"198.51.100.7:5000\"]\n" +
					"*** End Patch\n",
			}),
			actions: map[string]string{"default": "block", "permissive": "alert", "strict": "block"},
		},
		{
			name:   "Docker insecure registry moved past a last empty key in a three-step MultiEdit",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "MultiEdit", map[string]any{
				"file_path": "/etc/docker/daemon.json",
				"edits": []any{
					map[string]any{"old_string": `"insecure-registries":["198.51.100.7:5000"],`, "new_string": ``},
					map[string]any{"old_string": `"insecure-registries":[],"debug":true`, "new_string": `"insecure-registries":[],"debug":false`},
					map[string]any{"old_string": `"debug":false`, "new_string": `"debug":false,"insecure-registries":["198.51.100.7:5000"]`},
				},
			}),
			actions: map[string]string{"default": "block", "permissive": "alert", "strict": "block"},
		},
		{
			name:   "Docker insecure registry URL moved past a last empty key in a three-step MultiEdit",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "MultiEdit", map[string]any{
				"file_path": "/etc/docker/daemon.json",
				"edits": []any{
					map[string]any{"old_string": `"insecure-registries":["http://198.51.100.7:5000"],`, "new_string": ``},
					map[string]any{"old_string": `"insecure-registries":[],"debug":true`, "new_string": `"insecure-registries":[],"debug":false`},
					map[string]any{"old_string": `"debug":false`, "new_string": `"debug":false,"insecure-registries":["http://198.51.100.7:5000"]`},
				},
			}),
			actions: map[string]string{"default": "block", "permissive": "alert", "strict": "block"},
		},
		{
			name:   "Docker insecure registry moved past a last empty key in a two-hunk patch",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "apply_patch", map[string]any{
				"command": "*** Begin Patch\n*** Update File: /etc/docker/daemon.json\n@@\n" +
					"-  \"insecure-registries\":[\"198.51.100.7:5000\"],\n" +
					"@@\n   \"insecure-registries\":[],\n-  \"debug\":true\n+  \"debug\":true,\n" +
					"+  \"insecure-registries\":[\"198.51.100.7:5000\"]\n*** End Patch\n",
			}),
			actions: map[string]string{"default": "block", "permissive": "alert", "strict": "block"},
		},
		{
			name:   "Docker insecure registry URL moved past a last empty key in a two-hunk patch",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "apply_patch", map[string]any{
				"command": "*** Begin Patch\n*** Update File: /etc/docker/daemon.json\n@@\n" +
					"-  \"insecure-registries\":[\"http://198.51.100.7:5000\"],\n" +
					"@@\n   \"insecure-registries\":[],\n-  \"debug\":true\n+  \"debug\":true,\n" +
					"+  \"insecure-registries\":[\"http://198.51.100.7:5000\"]\n*** End Patch\n",
			}),
			actions: map[string]string{"default": "block", "permissive": "alert", "strict": "block"},
		},
		{
			name:   "Docker insecure registry long zero-padded port",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "Write", map[string]any{
				"file_path": "/etc/docker/daemon.json",
				"content":   `{"insecure-registries":["198.51.100.7:00000000000000000005000"]}`,
			}),
			actions: map[string]string{"default": "block", "permissive": "alert", "strict": "block"},
		},
		{
			name:   "Docker insecure registry JSON-escaped key in an Edit fragment",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "Edit", map[string]any{
				"file_path":  "/etc/docker/daemon.json",
				"old_string": `"debug": true`,
				"new_string": `"debug": true, "\u0069nsecure-registries": ["198.51.100.7:5000"]`,
			}),
			actions: map[string]string{"default": "block", "permissive": "alert", "strict": "block"},
		},
		{
			name:   "Docker insecure registry JSON-escaped key in a MultiEdit fragment",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "MultiEdit", map[string]any{
				"file_path": "/etc/docker/daemon.json",
				"edits": []any{map[string]any{
					"old_string": `"debug": true`,
					"new_string": `"debug": true, "\u0069nsecure-registries": ["198.51.100.7:5000"]`,
				}},
			}),
			actions: map[string]string{"default": "block", "permissive": "alert", "strict": "block"},
		},
		{
			name:   "Docker insecure registry JSON-escaped key in a patch hunk",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "apply_patch", map[string]any{
				"command": "*** Begin Patch\n*** Update File: /etc/docker/daemon.json\n@@\n+  \"\\u0069nsecure-registries\": [\"198.51.100.7:5000\"]\n*** End Patch\n",
			}),
			actions: map[string]string{"default": "block", "permissive": "alert", "strict": "block"},
		},
		{
			name:   "named Kubernetes Secret content read",
			ruleID: kubernetesNamedSecretReadRuleID,
			input: actionfacts.Input{
				Tool:        "execute_command",
				Command:     "kubectl get secret database-login -n payments -o json",
				DialectHint: actionfacts.DialectPOSIX,
			},
			actions: map[string]string{"default": "alert", "permissive": "alert", "strict": "alert"},
		},
	}

	for _, test := range tests {
		for profile, wantAction := range test.actions {
			t.Run(test.name+"/"+profile, func(t *testing.T) {
				connector := "exact-admin-security-" + profile + "-" + test.ruleID
				installToolCallCorpusProfileConnector(t, connector, profile)
				result := EvaluateDeterministicAction(
					t.Context(), test.input, string(test.input.Args), connector, profile,
				)
				if !slices.Contains(result.RuleIDs, test.ruleID) || result.Action != wantAction {
					t.Fatalf("result=%+v, want %s action %s", result, test.ruleID, wantAction)
				}
			})
		}
	}
}

func TestProtectedKubernetesNamedSecretReadBlocks(t *testing.T) {
	connector := activateUseCaseProfile(t, "kubernetes-production-protection")
	input := actionfacts.Input{
		Tool:        "execute_command",
		Command:     "kubectl get secret database-login -n payments -o json",
		DialectHint: actionfacts.DialectPOSIX,
	}
	result := EvaluateDeterministicAction(
		t.Context(), input, input.Command, connector, "default",
	)
	if !slices.Contains(result.RuleIDs, protectedKubernetesNamedSecretReadRuleID) ||
		result.Action != "block" {
		t.Fatalf("result=%+v, want protected Kubernetes Secret block", result)
	}
}

func TestExactAdministrativeSecurityRuleHardNegatives(t *testing.T) {
	tests := []struct {
		name, ruleID string
		input        actionfacts.Input
	}{
		{
			name:   "PAM documentation",
			ruleID: pamPermitAuthenticationBypassRuleID,
			input: exactStructuredInput(t, "Write", map[string]any{
				"file_path": "/etc/pam.d/README.md",
				"content":   "auth sufficient pam_permit.so\n",
			}),
		},
		{
			name:   "Docker log driver only",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "Write", map[string]any{
				"file_path": "/etc/docker/daemon.json",
				"content":   `{"log-driver":"json-file"}`,
			}),
		},
		{
			name:   "Docker loopback registry",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "Write", map[string]any{
				"file_path": "/etc/docker/daemon.json",
				"content":   `{"insecure-registries":["127.0.0.1:5000"]}`,
			}),
		},
		{
			name:   "Docker log driver and debug settings",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "Write", map[string]any{
				"file_path": "/etc/docker/daemon.json",
				"content":   `{"log-driver":"json-file","debug":true}`,
			}),
		},
		{
			name:   "Docker Edit adding a dns list",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "Edit", map[string]any{
				"file_path":  "/etc/docker/daemon.json",
				"old_string": `"debug": true`,
				"new_string": `"debug": true, "dns": ["8.8.8.8", "198.51.100.7"]`,
			}),
		},
		{
			name:   "Docker Edit adding a loopback registry",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "Edit", map[string]any{
				"file_path":  "/etc/docker/daemon.json",
				"old_string": `"debug": true`,
				"new_string": `"debug": true, "insecure-registries": ["127.0.0.1:5000"]`,
			}),
		},
		{
			name:   "Docker Edit of a complete document whose last insecure-registries key is empty",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "Edit", map[string]any{
				"file_path":  "/etc/docker/daemon.json",
				"old_string": `{"log-driver":"json-file"}`,
				"new_string": `{"log-driver":"json-file","insecure-registries":["198.51.100.7:5000"],"insecure-registries":[]}`,
			}),
		},
		{
			name:   "Docker two-step MultiEdit whose last insecure-registries key is empty",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "MultiEdit", map[string]any{
				"file_path": "/etc/docker/daemon.json",
				"edits": []any{
					map[string]any{
						"old_string": `"debug":true`,
						"new_string": `"insecure-registries":["198.51.100.7:5000"],"insecure-registries":[],"debug":true`,
					},
					map[string]any{"old_string": `"log-driver":"json-file"`, "new_string": `"log-driver":"journald"`},
				},
			}),
		},
		{
			name:   "Docker multi-line patch whose last insecure-registries key is empty",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "apply_patch", map[string]any{
				"command": "*** Begin Patch\n*** Update File: /etc/docker/daemon.json\n@@\n" +
					"+  \"insecure-registries\":[\"198.51.100.7:5000\"],\n+  \"insecure-registries\":[]\n" +
					"*** End Patch\n",
			}),
		},
		{
			name:   "Docker Edit adding a remote list followed by a last null insecure-registries key",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "Edit", map[string]any{
				"file_path":  "/etc/docker/daemon.json",
				"old_string": `"debug":true`,
				"new_string": `"insecure-registries":["198.51.100.7:5000"],"insecure-registries":null,"debug":true`,
			}),
		},
		{
			name:   "Docker patch adding a remote list followed by a last null insecure-registries key",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "apply_patch", map[string]any{
				"command": "*** Begin Patch\n*** Update File: /etc/docker/daemon.json\n@@\n" +
					"+  \"insecure-registries\":[\"198.51.100.7:5000\"],\n+  \"insecure-registries\": null\n" +
					"*** End Patch\n",
			}),
		},
		{
			name:   "Docker Edit adding a builder block with its own insecure-registries key",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "Edit", map[string]any{
				"file_path":  "/etc/docker/daemon.json",
				"old_string": `"debug": true`,
				"new_string": `"debug": true, "builder": {"insecure-registries": ["198.51.100.7:5000"]}`,
			}),
		},
		{
			name:   "Docker MultiEdit that only changes the log driver and a setting",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "MultiEdit", map[string]any{
				"file_path": "/etc/docker/daemon.json",
				"edits": []any{
					map[string]any{"old_string": `"log-driver":"json-file"`, "new_string": `"log-driver":"journald"`},
					map[string]any{"old_string": `"debug":true`, "new_string": `"debug":false`},
				},
			}),
		},
		{
			name:   "Docker dot-dot path to another file",
			ruleID: dockerInsecureHTTPRegistryRuleID,
			input: exactStructuredInput(t, "Write", map[string]any{
				"file_path": "/etc/docker/../daemon.json",
				"content":   `{"insecure-registries":["198.51.100.7:5000"]}`,
			}),
		},
		{
			name:   "Kubernetes Secret name only",
			ruleID: kubernetesNamedSecretReadRuleID,
			input: actionfacts.Input{
				Tool:        "execute_command",
				Command:     "kubectl get secret database-login -o name",
				DialectHint: actionfacts.DialectPOSIX,
			},
		},
	}

	connector := "exact-admin-security-negatives"
	installToolCallCorpusProfileConnector(t, connector, "strict")
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := EvaluateDeterministicAction(
				t.Context(), test.input, string(test.input.Args), connector, "strict",
			)
			if slices.Contains(result.RuleIDs, test.ruleID) {
				t.Fatalf("hard negative matched %s: %+v", test.ruleID, result)
			}
		})
	}
}

func TestExactAdministrativeSecurityContractsAreCodeOwned(t *testing.T) {
	for _, ruleID := range []string{
		kubernetesNamedSecretReadRuleID,
		protectedKubernetesNamedSecretReadRuleID,
		pamPermitAuthenticationBypassRuleID,
		dockerInsecureHTTPRegistryRuleID,
	} {
		contract, ok := exactFallbackContracts[ruleID]
		if !ok || contract.proves == nil || contract.boundedSubgraphProves == nil ||
			!contract.requiresExactDetectionProof || !contract.codeOwnedDetection ||
			contract.detectionOnly {
			t.Fatalf("contract %s=%+v exists=%t", ruleID, contract, ok)
		}
	}
	if !exactFallbackContracts[kubernetesNamedSecretReadRuleID].alertOnly {
		t.Fatal("universal named Secret content read must remain alert-only")
	}
	if exactFallbackContracts[protectedKubernetesNamedSecretReadRuleID].alertOnly {
		t.Fatal("protected named Secret content read must be enforcement-capable")
	}
}

func exactStructuredInput(t *testing.T, tool string, arguments map[string]any) actionfacts.Input {
	t.Helper()
	raw, err := json.Marshal(arguments)
	if err != nil {
		t.Fatal(err)
	}
	return actionfacts.Input{Tool: tool, Args: raw}
}
