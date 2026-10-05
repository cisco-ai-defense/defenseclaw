// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"bufio"
	"bytes"
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/net/http/httpproxy"
)

// expandCodexDotEnv applies the .env the way Codex does at startup (dotenvy:
// one line at a time, ${VAR} from the process environment, later lines win).
func expandCodexDotEnv(t *testing.T, raw []byte, env map[string]string) {
	t.Helper()
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("unexpected .env line %q", line)
		}
		env[key] = os.Expand(strings.Trim(value, `"`), func(name string) string { return env[name] })
	}
}

// GAP-1550: Setup adds a loopback NO_PROXY block to CODEX_HOME/.env that
// merges with the user's own value, is idempotent, and Teardown restores the
// file byte for byte (or removes it when Setup created it).
func TestCodexDotEnvLoopbackNoProxy(t *testing.T) {
	for _, tc := range []struct {
		name     string
		original *string
	}{
		{name: "user file without trailing newline", original: ptrString("OPENAI_API_KEY=placeholder\nNO_PROXY=corp.example")},
		{name: "no file", original: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			CodexConfigPathOverride = filepath.Join(dir, "config.toml")
			defer func() { CodexConfigPathOverride = "" }()
			envPath := filepath.Join(dir, ".env")
			if tc.original != nil {
				if err := os.WriteFile(envPath, []byte(*tc.original), 0o640); err != nil {
					t.Fatal(err)
				}
			}
			c := NewCodexConnector()
			opts := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:18970"}
			if err := c.Setup(context.Background(), opts); err != nil {
				t.Fatalf("Setup: %v", err)
			}
			first, err := os.ReadFile(envPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Setup(context.Background(), opts); err != nil {
				t.Fatalf("second Setup: %v", err)
			}
			if second, _ := os.ReadFile(envPath); !bytes.Equal(first, second) {
				t.Fatalf("Setup is not idempotent:\n%s\n---\n%s", first, second)
			}
			if tc.original != nil && !bytes.HasPrefix(first, []byte(*tc.original+"\n")) {
				t.Fatalf("user lines changed:\n%s", first)
			}
			if info, _ := os.Stat(envPath); tc.original == nil && info.Mode().Perm() != 0o600 {
				t.Fatalf("new .env mode = %v, want 0600", info.Mode().Perm())
			}

			env := map[string]string{"HTTPS_PROXY": "http://proxy.test:3128"}
			expandCodexDotEnv(t, first, env)
			selector := (&httpproxy.Config{HTTPProxy: "http://proxy.test:3128", HTTPSProxy: "http://proxy.test:3128", NoProxy: env["NO_PROXY"]}).ProxyFunc()
			// GAP-2620: the instance-metadata endpoints bypass the proxy too.
			direct := []string{"http://127.0.0.1:18970/v1/logs", "http://169.254.169.254/latest/api/token", "http://169.254.170.2/v2/credentials", "http://[fd00:ec2::254]/latest/api/token"}
			if tc.original != nil {
				direct = append(direct, "https://corp.example/")
			}
			for _, raw := range direct {
				target, _ := url.Parse(raw)
				if proxy, _ := selector(target); proxy != nil {
					t.Fatalf("%s goes through %s with NO_PROXY=%q", raw, proxy, env["NO_PROXY"])
				}
			}
			target, _ := url.Parse("https://bedrock-runtime.us-east-1.amazonaws.com/")
			if proxy, _ := selector(target); proxy == nil {
				t.Fatalf("other hosts must keep the proxy (NO_PROXY=%q)", env["NO_PROXY"])
			}
			if env["no_proxy"] != env["NO_PROXY"] {
				t.Fatalf("no_proxy = %q, want %q", env["no_proxy"], env["NO_PROXY"])
			}

			if err := c.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			after, err := os.ReadFile(envPath)
			if tc.original == nil {
				if !os.IsNotExist(err) {
					t.Fatalf("Teardown left the .env Setup created: %q (%v)", after, err)
				}
				return
			}
			if string(after) != *tc.original {
				t.Fatalf("Teardown did not restore the user's .env:\n%q\nwant\n%q", after, *tc.original)
			}
		})
	}
}

func ptrString(s string) *string { return &s }
