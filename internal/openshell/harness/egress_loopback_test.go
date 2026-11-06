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

package harness

import (
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/net/http/httpproxy"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// The create environment is shared by every connector and compute driver.
// Provider hosts still have their direct rule, and other destinations still
// use the configured proxy.
func TestSandboxLoopbackProxyExclusions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("OpenShell sandbox artifacts are not rendered on Windows hosts")
	}
	const proxy = "http://proxy.example:18972"
	for _, name := range Names() {
		spec, _ := Get(name)
		profiles := spec.CredentialProfiles("us-east-1")
		ids := []string{""}
		for _, cp := range profiles {
			ids = append(ids, cp.ProfileID)
		}
		for _, id := range ids {
			t.Run(name+"/"+id, func(t *testing.T) {
				env, err := spec.Env(EnvOptions{
					Artifacts: artifactsFor(t, spec), CredentialProfile: id,
					BedrockRegion: "us-east-1", EgressProxyURL: proxy,
				})
				if err != nil {
					t.Fatal(err)
				}
				list := env["NO_PROXY"]
				if list != env["no_proxy"] || list != env[openshell.EnvEgressBypass] {
					t.Fatalf("proxy exclusions differ across environment names")
				}
				SetNoProxy(env, list)
				if env["NO_PROXY"] != list {
					t.Fatalf("setting proxy exclusions a second time changed %q to %q", list, env["NO_PROXY"])
				}
				seen := map[string]bool{}
				for _, host := range strings.Split(list, ",") {
					if seen[host] {
						t.Errorf("duplicate proxy exclusion %q", host)
					}
					seen[host] = true
				}
				for _, host := range []string{"127.0.0.0/8", "127.0.0.1", "::1", "localhost", connector.SandboxIngressHost} {
					if !seen[host] {
						t.Errorf("proxy exclusions lack %q: %q", host, list)
					}
				}
				if seen["outside.example"] {
					t.Errorf("ordinary external destination excluded from the proxy: %q", list)
				}
				selectProxy := (&httpproxy.Config{HTTPSProxy: proxy, NoProxy: list}).ProxyFunc()
				for _, host := range []string{"example.com", "internal.example.com"} {
					selected, err := selectProxy(&url.URL{Scheme: "https", Host: host})
					if err != nil || selected == nil || selected.String() != proxy {
						t.Errorf("%s proxy route = %v, %v", host, selected, err)
					}
				}
				if id != "" {
					cp, err := spec.CredentialProfile(id, "us-east-1")
					if err != nil {
						t.Fatal(err)
					}
					for _, host := range cp.Hosts {
						if !seen[host] {
							t.Errorf("credential host %q lost its direct route", host)
						}
						selected, err := selectProxy(&url.URL{Scheme: "https", Host: host})
						if err != nil || selected != nil {
							t.Errorf("credential host %q proxy route = %v, %v", host, selected, err)
						}
					}
				}
			})
		}
	}
}

func TestSandboxProxyDefaultKeepsLocalServicesDirect(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh is required")
	}
	profile := filepath.Join(t.TempDir(), "sandbox-profile.sh")
	if err := os.WriteFile(profile, shellFile(t, OpenCode, SandboxProfilePath).Data, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", "-c", ". "+profile+"; printf '%s\\n' \"$NO_PROXY\" \"$no_proxy\"")
	cmd.Env = []string{openshell.EnvEgressURL + "=http://proxy.example:18972"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	for _, list := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		seen := map[string]bool{}
		for _, host := range strings.Split(list, ",") {
			seen[host] = true
		}
		for _, host := range []string{"127.0.0.0/8", "127.0.0.1", "::1", "localhost", connector.SandboxIngressHost} {
			if !seen[host] {
				t.Errorf("launcher default lacks %q: %q", host, list)
			}
		}
	}
}
