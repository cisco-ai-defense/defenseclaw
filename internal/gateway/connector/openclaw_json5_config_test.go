// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/jsonc"
)

// openClawJSON5Variants are the ways OpenClaw lets a user write openclaw.json
// that strict JSON refuses. Each turns a pretty-printed JSON document into one
// spelling; the document keeps a gateway port so the numbers variant has
// something to say.
var openClawJSON5Variants = map[string]func(string) string{
	"plain json": func(s string) string { return s },
	"leading line comment": func(s string) string {
		return "// my OpenClaw settings\n" + s
	},
	"block comments": func(s string) string {
		return "/* my OpenClaw\n   settings */\n" + strings.Replace(s, "\n  \"plugins\"", "\n  /* plugins */ \"plugins\"", 1)
	},
	"trailing commas":  openClawTrailingCommas,
	"hexadecimal port": openClawHexPort,
	"bare keys and single quotes": func(s string) string {
		return openClawSingleQuotes(openClawBareKeys(s))
	},
	"everything together": func(s string) string {
		s = openClawSingleQuotes(openClawBareKeys(openClawHexPort(openClawTrailingCommas(s))))
		return "// user config\n" + s
	},
}

func openClawTrailingCommas(s string) string {
	return regexp.MustCompile(`([^,\s{\[])\n(\s*)([}\]])`).ReplaceAllString(s, "$1,\n$2$3")
}

func openClawHexPort(s string) string {
	return strings.Replace(s, "\"port\": 18789", "\"port\": 0x4965", 1)
}

func openClawBareKeys(s string) string {
	return regexp.MustCompile(`"([A-Za-z_$][A-Za-z0-9_$]*)":`).ReplaceAllString(s, "$1:")
}

func openClawSingleQuotes(s string) string {
	return regexp.MustCompile(`"([^"\\\n]*)"`).ReplaceAllString(s, "\x27$1\x27")
}

const openClawJSON5Base = `{
  "gateway": {
    "port": 18789
  },
  "agents": {
    "defaults": {
      "model": {
        "primary": "first"
      }
    }
  },
  "plugins": {
    "entries": {
      "somebody-else": {
        "enabled": true
      }
    }
  }
}
`

func openClawJSON5Fixture(t *testing.T, dir string) (ocHome, configPath string, opts SetupOpts) {
	t.Helper()
	requireOpenClawExtensionBundle(t)
	ocHome = filepath.Join(dir, "openclaw-home")
	if err := os.MkdirAll(ocHome, 0o755); err != nil {
		t.Fatal(err)
	}
	OpenClawHomeOverride = ocHome
	t.Cleanup(func() { OpenClawHomeOverride = "" })
	return ocHome, filepath.Join(ocHome, "openclaw.json"),
		SetupOpts{DataDir: dir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970"}
}

func readOpenClawJSON5(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	cfg := map[string]interface{}{}
	data := mustReadFileString(t, path)
	if err := jsonc.UnmarshalJSON5([]byte(data), &cfg); err != nil {
		t.Fatalf("openclaw.json is not JSON5 after the change: %v\n%s", err, data)
	}
	return cfg
}

func assertOpenClawJSON5UserKeysKept(t *testing.T, cfg map[string]interface{}) {
	t.Helper()
	if port := cfg["gateway"].(map[string]interface{})["port"]; port != float64(18789) {
		t.Errorf("gateway.port = %v, want 18789", port)
	}
	model := cfg["agents"].(map[string]interface{})["defaults"].(map[string]interface{})["model"].(map[string]interface{})
	if model["primary"] != "first" {
		t.Errorf("agents.defaults.model.primary = %v, want first", model["primary"])
	}
	entries := cfg["plugins"].(map[string]interface{})["entries"].(map[string]interface{})
	if _, ok := entries["somebody-else"]; !ok {
		t.Error("another plugin entry was lost")
	}
}

// GAP-0907: a gateway start (Setup) on an openclaw.json OpenClaw itself reads
// as JSON5 registers the plugin, and leaving OpenClaw mode (Teardown) puts the
// original bytes back, comments and all.
func TestOpenClawSetupAndTeardownReadJSON5AndRestoreTheOriginalBytes(t *testing.T) {
	for name, variant := range openClawJSON5Variants {
		t.Run(name, func(t *testing.T) {
			ocHome, configPath, opts := openClawJSON5Fixture(t, t.TempDir())
			original := variant(openClawJSON5Base)
			if err := os.WriteFile(configPath, []byte(original), 0o644); err != nil {
				t.Fatal(err)
			}

			c := NewOpenClawConnector()
			if err := c.Setup(context.Background(), opts); err != nil {
				t.Fatalf("Setup: %v", err)
			}
			if !openClawConfigRegistersDefenseClaw(configPath) {
				t.Fatalf("Setup did not register the plugin:\n%s", mustReadFileString(t, configPath))
			}
			assertOpenClawJSON5UserKeysKept(t, readOpenClawJSON5(t, configPath))

			if err := c.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			if got := mustReadFileString(t, configPath); got != original {
				t.Fatalf("Teardown did not restore the original bytes.\nwant:\n%s\ngot:\n%s", original, got)
			}
			if _, err := os.Stat(filepath.Join(ocHome, "extensions", "defenseclaw")); !os.IsNotExist(err) {
				t.Fatalf("extension dir still present after Teardown: err=%v", err)
			}
		})
	}
}

// GAP-0907: the user edits an enrolled openclaw.json into JSON5, then the
// gateway restarts (Setup again) and the user later leaves OpenClaw mode.
// Neither step may refuse the file; teardown removes only DefenseClaw entries.
func TestOpenClawRestartAndUninstallReadAJSON5EditMadeWhileEnrolled(t *testing.T) {
	for name, variant := range openClawJSON5Variants {
		t.Run(name, func(t *testing.T) {
			ocHome, configPath, opts := openClawJSON5Fixture(t, t.TempDir())
			if err := os.WriteFile(configPath, []byte(openClawJSON5Base), 0o644); err != nil {
				t.Fatal(err)
			}
			c := NewOpenClawConnector()
			if err := c.Setup(context.Background(), opts); err != nil {
				t.Fatalf("first Setup: %v", err)
			}

			edited := variant(mustReadFileString(t, configPath))
			if err := os.WriteFile(configPath, []byte(edited), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := c.Setup(context.Background(), opts); err != nil {
				t.Fatalf("Setup on the JSON5 file (gateway restart): %v", err)
			}
			if !openClawConfigRegistersDefenseClaw(configPath) {
				t.Fatalf("the restart left the plugin unregistered:\n%s", mustReadFileString(t, configPath))
			}
			assertOpenClawJSON5UserKeysKept(t, readOpenClawJSON5(t, configPath))
			// A restart that has nothing to add leaves the file as the user wrote it.
			if got := mustReadFileString(t, configPath); got != edited {
				t.Fatalf("a restart that changed nothing rewrote the file.\nwant:\n%s\ngot:\n%s", edited, got)
			}

			if err := c.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("Teardown on the JSON5 file: %v", err)
			}
			if openClawConfigRegistersDefenseClaw(configPath) {
				t.Fatalf("Teardown left the plugin registered:\n%s", mustReadFileString(t, configPath))
			}
			assertOpenClawJSON5UserKeysKept(t, readOpenClawJSON5(t, configPath))
			if _, err := os.Stat(filepath.Join(ocHome, "extensions", "defenseclaw")); !os.IsNotExist(err) {
				t.Fatalf("extension dir still present after Teardown: err=%v", err)
			}
		})
	}
}

// GAP-0907: a file that is not JSON5 either is refused with its path, line,
// column and the text at fault, as a typed error the gateway maps to a next
// step that does not blame an open agent, and the file is left as it was.
func TestOpenClawSetupNamesTheLineOfAConfigThatIsNotJSON5(t *testing.T) {
	_, configPath, opts := openClawJSON5Fixture(t, t.TempDir())
	broken := "// my settings\n{\n  gateway: {port: 18789},\n  plugins: {entries: {a: }},\n}\n"
	if err := os.WriteFile(configPath, []byte(broken), 0o644); err != nil {
		t.Fatal(err)
	}

	err := NewOpenClawConnector().Setup(context.Background(), opts)
	if err == nil || !errors.Is(err, ErrOpenClawConfigSyntax) {
		t.Fatalf("Setup = %v, want ErrOpenClawConfigSyntax", err)
	}
	var syntax *jsonc.SyntaxError
	if !errors.As(err, &syntax) || syntax.Line != 4 {
		t.Fatalf("error does not carry the position of the fault (line 4): %v", err)
	}
	for _, want := range []string{configPath, "line 4", "column ", "near ", "fix that spot"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
	if got := mustReadFileString(t, configPath); got != broken {
		t.Fatalf("a refused file was rewritten:\n%s", got)
	}
}

// A document whose top level is not an object is a type problem, not a syntax
// one, and is reported without a line.
func TestOpenClawConfigThatIsAListIsNotASyntaxError(t *testing.T) {
	_, err := parseOpenClawConfig("openclaw.json", []byte("// list\n[1, 2,]"))
	if err == nil || errors.Is(err, ErrOpenClawConfigSyntax) {
		t.Fatalf("got %v, want a plain parse error", err)
	}
	var syntax *json.SyntaxError
	if errors.As(err, &syntax) {
		t.Fatalf("a type mismatch was reported as a syntax error: %v", err)
	}
}

func mustReadFileString(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
