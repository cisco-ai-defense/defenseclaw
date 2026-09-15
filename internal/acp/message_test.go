// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestParseMessageRejectsBatchAndMalformedEnvelopes(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
		want error
	}{
		{"batch", `[{"jsonrpc":"2.0","method":"initialize","id":1}]`, ErrBatchUnsupported},
		{"wrong version", `{"jsonrpc":"1.0","method":"initialize","id":1}`, ErrInvalidMessage},
		{"response without id", `{"jsonrpc":"2.0","result":{}}`, ErrInvalidMessage},
		{"request with result", `{"jsonrpc":"2.0","method":"initialize","id":1,"result":{}}`, ErrInvalidMessage},
		{"duplicate method", `{"jsonrpc":"2.0","method":"safe","method":"unsafe"}`, ErrInvalidMessage},
		{"nested duplicate", `{"jsonrpc":"2.0","method":"x","params":{"path":"a","path":"b"}}`, ErrInvalidMessage},
		{"trailing value", `{"jsonrpc":"2.0","method":"x"} {}`, ErrInvalidMessage},
		{"boolean id", `{"jsonrpc":"2.0","method":"x","id":true}`, ErrInvalidMessage},
		{"scalar params", `{"jsonrpc":"2.0","method":"x","params":"bad"}`, ErrInvalidMessage},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseMessage([]byte(test.body))
			if !errors.Is(err, test.want) {
				t.Fatalf("ParseMessage() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestParseMessageAllowsProtocolExtensionMembers(t *testing.T) {
	msg, err := ParseMessage([]byte(`{"jsonrpc":"2.0","id":"x","method":"vendor/extension","params":{},"_meta":{"trace":"1"}}`))
	if err != nil {
		t.Fatalf("extension member rejected: %v", err)
	}
	if msg.Method != "vendor/extension" {
		t.Fatalf("method = %q", msg.Method)
	}
}

func FuzzParseMessageNeverPanics(f *testing.F) {
	for _, seed := range []string{
		`{"jsonrpc":"2.0","method":"initialize","id":1,"params":{}}`,
		`{"jsonrpc":"2.0","method":"session/update","params":{}}`,
		`[]`, "", "{",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		_, _ = ParseMessage(body)
	})
}

func TestParseMessageClassifiesGuardedSurfaces(t *testing.T) {
	for method, want := range map[string]Surface{
		"session/prompt":             SurfacePrompt,
		"session/update":             SurfaceOutput,
		"session/request_permission": SurfacePermission,
		"fs/write_text_file":         SurfaceFilesystem,
		"terminal/create":            SurfaceTerminal,
	} {
		msg, err := ParseMessage([]byte(`{"jsonrpc":"2.0","method":"` + method + `","params":{}}`))
		if err != nil {
			t.Fatal(err)
		}
		if got := Classify(msg, AgentToClient); got != want {
			t.Errorf("Classify(%s) = %s, want %s", method, got, want)
		}
	}
}

func TestParseMessageBoundsFrame(t *testing.T) {
	_, err := ParseMessage([]byte(strings.Repeat("x", MaxFrameBytes+1)))
	if !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("error = %v", err)
	}
}

func TestCatalogHasPinnedSchemaAndUniqueIDs(t *testing.T) {
	catalog := BuiltinCatalog()
	if catalog.SchemaVersion != SchemaVersion || catalog.SchemaSHA256 != SchemaSHA256 {
		t.Fatal("catalog schema pin drifted")
	}
	seen := map[string]bool{}
	for _, agent := range catalog.Agents {
		if seen[agent.ID] {
			t.Fatalf("duplicate agent ID %q", agent.ID)
		}
		seen[agent.ID] = true
		if agent.Command == "" {
			t.Fatalf("agent %q has no command", agent.ID)
		}
		if agent.Kind != "native" && agent.Kind != "bridge" {
			t.Fatalf("agent %q has invalid ACP kind %q", agent.ID, agent.Kind)
		}
		if agent.SourceURL == "" {
			t.Fatalf("agent %q has no provenance URL", agent.ID)
		}
	}
	for _, client := range catalog.Clients {
		if client.SourceURL == "" {
			t.Fatalf("client %q has no provenance URL", client.ID)
		}
	}
}

func TestBuiltinCatalogReturnsAnIndependentCopy(t *testing.T) {
	first := BuiltinCatalog()
	first.Agents[0].Args[0] = "tampered"
	first.Agents[0].Command = "tampered"
	second := BuiltinCatalog()
	if second.Agents[0].Command == "tampered" || second.Agents[0].Args[0] == "tampered" {
		t.Fatal("caller mutation changed the built-in ACP catalog")
	}
}

func TestBuiltinCatalogMatchesCanonicalACPRegistry(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "inventory", "acp_registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	var registry struct {
		Protocol struct {
			Release string `json:"release"`
			SHA256  string `json:"sha256"`
		} `json:"protocol"`
		Agents  []Agent  `json:"agents"`
		Clients []Client `json:"clients"`
	}
	if err := json.Unmarshal(body, &registry); err != nil {
		t.Fatal(err)
	}
	catalog := BuiltinCatalog()
	if registry.Protocol.Release != catalog.SchemaVersion || registry.Protocol.SHA256 != catalog.SchemaSHA256 {
		t.Fatal("canonical ACP protocol pin and compiled catalog differ")
	}
	sort.Slice(registry.Agents, func(i, j int) bool { return registry.Agents[i].ID < registry.Agents[j].ID })
	sort.Slice(catalog.Agents, func(i, j int) bool { return catalog.Agents[i].ID < catalog.Agents[j].ID })
	sort.Slice(registry.Clients, func(i, j int) bool { return registry.Clients[i].ID < registry.Clients[j].ID })
	sort.Slice(catalog.Clients, func(i, j int) bool { return catalog.Clients[i].ID < catalog.Clients[j].ID })
	if !reflect.DeepEqual(registry.Agents, catalog.Agents) || !reflect.DeepEqual(registry.Clients, catalog.Clients) {
		t.Fatal("canonical ACP registry and compiled catalog differ")
	}
}
