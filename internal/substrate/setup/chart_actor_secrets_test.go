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

package setup

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// actorSecretsMounts returns, per Deployment, the mount path of its
// actor-secrets volume ("" when it has none) and that volume's Secret.
func actorSecretsMounts(t *testing.T, out []byte) map[string][2]string {
	t.Helper()
	got := map[string][2]string{}
	for _, doc := range strings.Split(string(out), "\n---") {
		var d struct {
			Kind     string `yaml:"kind"`
			Metadata struct {
				Name string `yaml:"name"`
			} `yaml:"metadata"`
			Spec struct {
				Template struct {
					Spec struct {
						Containers []struct {
							VolumeMounts []struct {
								Name      string `yaml:"name"`
								MountPath string `yaml:"mountPath"`
								ReadOnly  bool   `yaml:"readOnly"`
							} `yaml:"volumeMounts"`
						} `yaml:"containers"`
						Volumes []struct {
							Name   string `yaml:"name"`
							Secret struct {
								SecretName string `yaml:"secretName"`
							} `yaml:"secret"`
						} `yaml:"volumes"`
					} `yaml:"spec"`
				} `yaml:"template"`
			} `yaml:"spec"`
		}
		if yaml.Unmarshal([]byte(doc), &d) != nil || d.Kind != "Deployment" {
			continue
		}
		var path, secret string
		for _, c := range d.Spec.Template.Spec.Containers {
			for _, m := range c.VolumeMounts {
				if m.Name == "actor-secrets" {
					if !m.ReadOnly {
						t.Errorf("%s mounts actor-secrets writable", d.Metadata.Name)
					}
					path = m.MountPath
				}
			}
		}
		for _, v := range d.Spec.Template.Spec.Volumes {
			if v.Name == "actor-secrets" {
				secret = v.Secret.SecretName
			}
		}
		got[d.Metadata.Name] = [2]string{path, secret}
	}
	return got
}

// gatewayActorSecretsDir is substrate.extproc.actor_secrets_dir in the
// gateway's config.yaml.
func gatewayActorSecretsDir(t *testing.T, out []byte) string {
	t.Helper()
	for _, o := range decodeObjects(t, out) {
		if o.Kind != "ConfigMap" || o.Metadata["name"] != "defenseclaw-config" {
			continue
		}
		var cfg struct {
			Substrate struct {
				Extproc struct {
					ActorSecretsDir string `yaml:"actor_secrets_dir"`
				} `yaml:"extproc"`
			} `yaml:"substrate"`
		}
		if err := yaml.Unmarshal([]byte(o.Data["config.yaml"].(string)), &cfg); err != nil {
			t.Fatal(err)
		}
		return cfg.Substrate.Extproc.ActorSecretsDir
	}
	t.Fatal("no defenseclaw-config ConfigMap")
	return ""
}

// TestChartActorSecretsReachTheGateway: F3's /llm exact-value DLP needs the
// exposed actor_secrets in the gateway pods. The chart mounts the Secret
// read-only in the gateway and the callout (never the leader or the
// controller), and renders the same directory into both configs; a custom
// actor_secrets_dir moves both mounts; no Secret, no mount and no key.
func TestChartActorSecretsReachTheGateway(t *testing.T) {
	helm := helmBinary(t)
	const dir = "/run/defenseclaw/actor-secrets"
	out := renderChart(t, helm, "actor-secrets")
	m := actorSecretsMounts(t, out)
	for _, dep := range []string{"defenseclaw-gateway", "defenseclaw-callout"} {
		if m[dep] != [2]string{dir, "defenseclaw-actor-secrets-dlp"} {
			t.Errorf("%s: actor-secrets mount %v", dep, m[dep])
		}
	}
	for _, dep := range []string{"defenseclaw-leader", "defenseclaw-controller"} {
		if m[dep] != [2]string{} {
			t.Errorf("%s mounts the actor secrets: %v", dep, m[dep])
		}
	}
	if got := gatewayActorSecretsDir(t, out); got != dir {
		t.Errorf("gateway actor_secrets_dir %q", got)
	}
	if got := calloutConfigFrom(t, out).ActorSecretsDir; got != dir {
		t.Errorf("callout actor_secrets_dir %q", got)
	}

	const custom = "/var/run/dc-exposed"
	out = renderChart(t, helm, "actor-secrets", "--set", "config.substrate.extproc.actor_secrets_dir="+custom)
	m = actorSecretsMounts(t, out)
	if m["defenseclaw-gateway"][0] != custom || m["defenseclaw-callout"][0] != custom {
		t.Errorf("custom dir mounts: %v", m)
	}
	if gatewayActorSecretsDir(t, out) != custom || calloutConfigFrom(t, out).ActorSecretsDir != custom {
		t.Error("custom dir not in both configs")
	}

	out = renderChart(t, helm, "default")
	for dep, v := range actorSecretsMounts(t, out) {
		if v != [2]string{} {
			t.Errorf("default: %s mounts actor secrets: %v", dep, v)
		}
	}
	if got := gatewayActorSecretsDir(t, out); got != "" {
		t.Errorf("default: gateway actor_secrets_dir %q", got)
	}
}
