// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// scanFixture publishes the gateway copy of a scan the way the enumerator
// does and returns its directory.
func scanFixture(t *testing.T, agents []enterprisehooks.UnprotectedAgent, generation uint64, digest string) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, dir)
	previousValidate, previousStamp := validateManagedGuardianAuthorization, ownStatusConfigStamp
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	ownStatusConfigStamp = func(string) (uint64, string, error) { return 7, "digest-7", nil }
	t.Cleanup(func() { validateManagedGuardianAuthorization, ownStatusConfigStamp = previousValidate, previousStamp })
	data, err := enterprisehooks.MarshalUnprotectedAgentsForConfig(agents, generation, digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, managed.HookGuardianUnprotectedAgentsFile), data, 0o640); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestReadManagedUnprotectedAgentsNeedsACompletedMatchedScan(t *testing.T) {
	v1 := unprotectedAgentFor("alice", 5001, "opencode", enterprisehooks.UnprotectedCodeOpenCodeV1, "V1 copy")

	// A completed scan that found nothing is a record with no agents.
	dir := scanFixture(t, nil, 7, "digest-7")
	if agents, err := readManagedUnprotectedAgents(dir, "/etc/defenseclaw/config.yaml", true); err != nil || len(agents) != 0 {
		t.Fatalf("empty completed scan = %v, %v; want no agents and no error", agents, err)
	}
	// So does one that found agents, whose entries are returned.
	dir = scanFixture(t, []enterprisehooks.UnprotectedAgent{v1}, 7, "digest-7")
	if agents, err := readManagedUnprotectedAgents(dir, "/etc/defenseclaw/config.yaml", true); err != nil || len(agents) != 1 || agents[0].Connector != "opencode" {
		t.Fatalf("scan with a V1 = %v, %v; want the V1 entry", agents, err)
	}
	path := filepath.Join(dir, managed.HookGuardianUnprotectedAgentsFile)

	// A missing copy is an unknown scan, never "no agent found": the gateway
	// copy may be absent or unwritten while the root-only record lists a V1.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if agents, err := readManagedUnprotectedAgents(dir, "/etc/defenseclaw/config.yaml", true); err == nil {
		t.Fatalf("missing copy = %v, nil; want an error", agents)
	}

	for name, mutate := range map[string]func(){
		"an old scan": func() {
			old := time.Now().Add(-2 * enterprisehooks.UnprotectedAgentsMaxAge)
			if err := os.Chtimes(path, old, old); err != nil {
				t.Fatal(err)
			}
		},
		"another install": func() {
			var record map[string]any
			data, _ := os.ReadFile(path)
			if err := json.Unmarshal(data, &record); err != nil {
				t.Fatal(err)
			}
			record["generation"] = "0.0.1-other"
			data, _ = json.Marshal(record)
			if err := os.WriteFile(path, data, 0o640); err != nil {
				t.Fatal(err)
			}
		},
		"another config generation": func() {
			data, _ := enterprisehooks.MarshalUnprotectedAgentsForConfig(nil, 6, "digest-7")
			_ = os.WriteFile(path, data, 0o640)
		},
		"another config digest": func() {
			data, _ := enterprisehooks.MarshalUnprotectedAgentsForConfig(nil, 7, "digest-other")
			_ = os.WriteFile(path, data, 0o640)
		},
		"no config stamp": func() {
			data, _ := enterprisehooks.MarshalUnprotectedAgentsForConfig(nil, 0, "")
			_ = os.WriteFile(path, data, 0o640)
		},
		"a malformed record": func() { _ = os.WriteFile(path, []byte("{"), 0o640) },
		// The enumerator empties a copy it cannot replace or remove.
		"an emptied copy": func() { _ = os.WriteFile(path, nil, 0o640) },
	} {
		dir := scanFixture(t, nil, 7, "digest-7")
		path = filepath.Join(dir, managed.HookGuardianUnprotectedAgentsFile)
		mutate()
		if agents, err := readManagedUnprotectedAgents(dir, "/etc/defenseclaw/config.yaml", true); err == nil {
			t.Fatalf("%s: = %v, nil; want an unknown scan", name, agents)
		}
	}

	// The installed config generation must be known (a Unix record is bound to it).
	dir = scanFixture(t, nil, 7, "digest-7")
	ownStatusConfigStamp = func(string) (uint64, string, error) { return 0, "", errors.New("no generation") }
	if _, err := readManagedUnprotectedAgents(dir, "/etc/defenseclaw/config.yaml", true); err == nil {
		t.Fatal("unknown installed config generation: want an unknown scan")
	}
	// A Windows record carries no config stamp and is not bound to one.
	dir = scanFixture(t, nil, 0, "")
	ownStatusConfigStamp = func(string) (uint64, string, error) { return 0, "", errors.New("no generation") }
	if agents, err := readManagedUnprotectedAgents(dir, "", false); err != nil || len(agents) != 0 {
		t.Fatalf("unbound completed scan = %v, %v; want no agents and no error", agents, err)
	}
}

// The reviewer near variant: the enumerator found an uncovered V1 and its
// gateway copy was never published. The caller own status through the real
// reader says not confirmed, not protected.
func TestOwnStatusWithoutTheGatewayCopyIsNotProtected(t *testing.T) {
	dir := scanFixture(t, nil, 7, "digest-7")
	if err := os.Remove(filepath.Join(dir, managed.HookGuardianUnprotectedAgentsFile)); err != nil {
		t.Fatal(err)
	}
	api := ownStatusUnprotectedFixture(t, nil, nil)
	ownStatusUnprotectedAgents = readManagedUnprotectedAgents
	row := ownStatusConnectorRow(t, api, "5001", "alice", "opencode")
	state := ownRowText(row)
	if row["protected"] != false || strings.HasPrefix(state, "protected") {
		t.Fatalf("OpenCode row without a gateway copy = %#v, want not protected", row)
	}
	// With the completed empty scan published, the same user is protected.
	data, _ := enterprisehooks.MarshalUnprotectedAgentsForConfig(nil, 7, "digest-7")
	if err := os.WriteFile(filepath.Join(dir, managed.HookGuardianUnprotectedAgentsFile), data, 0o640); err != nil {
		t.Fatal(err)
	}
	if row := ownStatusConnectorRow(t, api, "5001", "alice", "opencode"); row["protected"] != true {
		t.Fatalf("OpenCode row with a completed empty scan = %#v, want protected", row)
	}
}
