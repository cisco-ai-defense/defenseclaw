// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

// GAP-2461: a per-user install of 1.0.3 writes its whole [otel] table, with
// its native exporter, on every Setup. After an upgrade kept the operator
// otel.environment, a rollback started 1.0.3 again, which wrote its table over
// that value with the token of its own data; the roll forward brings that
// data to previous/data. The roll forward must take the older render out
// (its token is a product credential) and put the operator entries back.
func TestCodexRollbackPairPutsTheOperatorOtelBack(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		for _, tc := range []struct {
			name string
			// olderTable edits the table the older release wrote before the
			// roll forward; nil keeps it as rendered.
			olderTable func(otel map[string]interface{})
			// foreignBearer replaces the older bearer with one no install holds.
			foreignBearer   bool
			wantEnvironment string
			wantExporter    bool
		}{
			{name: "the older render is taken back", wantEnvironment: "fc-up2461"},
			{name: "a value set while the older release ran stays", olderTable: func(otel map[string]interface{}) { otel["environment"] = "fc-mid" }, wantEnvironment: "fc-mid"},
			{name: "an exporter with a bearer no install holds stays", foreignBearer: true, wantEnvironment: "dev", wantExporter: true},
		} {
			t.Run(goos+"/"+tc.name, func(t *testing.T) {
				dir := t.TempDir()
				configPath := filepath.Join(dir, "config.toml")
				if err := os.WriteFile(configPath, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				prior := CodexConfigPathOverride
				CodexConfigPathOverride = configPath
				t.Cleanup(func() { CodexConfigPathOverride = prior })
				c := NewCodexConnector()
				opts := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:19081", APIToken: "test-hook-token", GOOS: goos}

				earlier := opts
				earlier.sandboxNativeOTLP = true // the 1.0.3 render
				if err := c.Setup(context.Background(), earlier); err != nil {
					t.Fatalf("earlier setup: %v", err)
				}
				gap2461EditOtel(t, configPath, func(otel map[string]interface{}) { otel["environment"] = "fc-up2461" })
				if err := c.Setup(context.Background(), opts); err != nil {
					t.Fatalf("upgrade setup: %v", err)
				}
				if otel := gap2461ReadOtel(t, configPath); otel["environment"] != "fc-up2461" || otel["exporter"] != nil {
					t.Fatalf("upgrade did not keep the operator environment alone: %+v", otel)
				}

				// The older release runs on its own data, which the roll forward
				// moves to previous/data, and writes its whole table again.
				olderToken, err := EnsureOTLPPathToken(rollbackPartnerDataDir(dir), OTLPScopeCodex)
				if err != nil {
					t.Fatal(err)
				}
				bearer := olderToken
				if tc.foreignBearer {
					bearer = strings.Repeat("f", 64)
				}
				older, err := buildCodexOtelBlockWithPathToken(opts, bearer)
				if err != nil {
					t.Fatal(err)
				}
				gap2461EditOtel(t, configPath, func(otel map[string]interface{}) {
					for key := range otel {
						delete(otel, key)
					}
					for key, value := range older {
						otel[key] = value
					}
					if tc.olderTable != nil {
						tc.olderTable(otel)
					}
				})

				if err := c.Setup(context.Background(), opts); err != nil {
					t.Fatalf("roll forward setup: %v", err)
				}
				data, err := os.ReadFile(configPath)
				if err != nil {
					t.Fatal(err)
				}
				if !tc.foreignBearer && strings.Contains(string(data), olderToken) {
					t.Fatal("the bearer of the older release survived the roll forward")
				}
				otel := gap2461ReadOtel(t, configPath)
				if otel["environment"] != tc.wantEnvironment {
					t.Fatalf("otel.environment = %v, want %q (table %+v)", otel["environment"], tc.wantEnvironment, otel)
				}
				if _, has := otel["exporter"]; has != tc.wantExporter {
					t.Fatalf("exporter present = %t, want %t", has, tc.wantExporter)
				}
				if !tc.wantExporter {
					if _, has := otel["log_user_prompt"]; has {
						t.Fatalf("the log_user_prompt of the older render survived: %+v", otel)
					}
				}
				if tc.foreignBearer {
					return
				}

				// The operator removes the table: no later Setup brings it back.
				gap2461EditOtel(t, configPath, nil)
				if err := c.Setup(context.Background(), opts); err != nil {
					t.Fatalf("setup after the operator removed [otel]: %v", err)
				}
				if otel := gap2461ReadOtel(t, configPath); otel != nil {
					t.Fatalf("Setup wrote back a table the operator removed: %+v", otel)
				}
			})
		}
	}
}

// gap2461EditOtel rewrites the [otel] table of the config at path with edit;
// a nil edit removes the table.
func gap2461EditOtel(t *testing.T, path string, edit func(otel map[string]interface{})) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := map[string]interface{}{}
	if err := toml.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if edit == nil {
		delete(cfg, "otel")
	} else {
		otel, _ := cfg["otel"].(map[string]interface{})
		if otel == nil {
			otel = map[string]interface{}{}
		}
		edit(otel)
		cfg["otel"] = otel
	}
	out, err := toml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

func gap2461ReadOtel(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := map[string]interface{}{}
	if err := toml.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	otel, _ := cfg["otel"].(map[string]interface{})
	return otel
}
