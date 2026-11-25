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

package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/configwatch"
	"github.com/defenseclaw/defenseclaw/internal/substrate/setup"
)

// substrateConfigMap is the ConfigMap the chart renders config.yaml into
// (templates/configmap.yaml).
const substrateConfigMap = "defenseclaw-config"

// substrateConfigWatcher is the config.yaml source every Substrate
// component follows (GAP-0276): in a cluster the defenseclaw-config
// ConfigMap through the API (each component's Role may get it), else, and
// when that read fails, the file at path.
func substrateConfigWatcher(path string, boot *config.Config) (*configwatch.Watcher, error) {
	if strings.TrimSpace(path) == "" {
		path = config.ConfigPath()
	}
	w, err := configwatch.Start(path, boot)
	if err != nil {
		return nil, err
	}
	ns := strings.TrimSpace(os.Getenv("POD_NAMESPACE"))
	if ns == "" || os.Getenv("KUBERNETES_SERVICE_HOST") == "" {
		return w, nil
	}
	kube, err := setup.NewInClusterKube(setup.InClusterDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[substrate] config.yaml changes are read from the mounted file only (the kubelet updates it on its own schedule): %v\n", err)
		return w, nil
	}
	w.Fetch = substrateConfigMapFetch(kube, ns, substrateConfigMap)
	return w, nil
}

// configMapGetter is the part of setup.Kube the watcher uses.
type configMapGetter interface {
	GetConfigMap(ctx context.Context, namespace, name string) (*setup.ConfigMap, error)
}

func substrateConfigMapFetch(kube configMapGetter, ns, name string) configwatch.Fetch {
	return func(ctx context.Context) ([]byte, bool, error) {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		cm, err := kube.GetConfigMap(ctx, ns, name)
		if err != nil || cm == nil {
			return nil, false, err
		}
		v, ok := cm.Data[configwatch.ConfigMapKey]
		return []byte(v), ok, nil
	}
}

// substrateRoleDeployment is the chart's Deployment of each role
// (templates/gateway.yaml, templates/leader.yaml; defenseclaw-leader is the
// leader's Service, not its Deployment).
var substrateRoleDeployment = map[string]string{"gateway": "defenseclaw-gateway", "leader": "defenseclaw-gateway-leader"}

// substrateRestartAll restarts every pod that reads config.yaml at start,
// the controller included. A change to a key the controller keeps from its
// start (substrateControllerRestartOnly: llm_providers, substrate.identity,
// .services, .api, .extproc) needs it: restarting only the gateway would
// leave the controller rendering the old provider hosts (GAP-0589). The
// controller's own warning names the same command.
const substrateRestartAll = "kubectl rollout restart deploy/defenseclaw-gateway deploy/defenseclaw-gateway-leader deploy/defenseclaw-controller"

// substrateFollower keeps a gateway or leader pod on config.yaml: on a
// change it applies the parts this pod takes live (apply) and names the
// ones that wait for the pod's next start (substrateRestartOnly).
type substrateFollower struct {
	w     *configwatch.Watcher
	role  string
	out   io.Writer
	apply func(*config.Config) error
	// boot is the config the pod started with (the restart-only parts
	// are still its); applied the digest in force.
	boot    *config.Config
	applied string
	// guardrail, for a gateway that reads the ConfigMap through the API,
	// says when an edit reaches its guardrail (substrateGatewayGuardrail).
	guardrail string
}

func newSubstrateFollower(w *configwatch.Watcher, role string, out io.Writer, apply func(*config.Config) error) *substrateFollower {
	boot, d := w.Current()
	f := &substrateFollower{w: w, role: role, out: out, apply: apply, boot: boot, applied: d}
	if role == "gateway" && w.Fetch != nil {
		f.guardrail = substrateGatewayGuardrail(w.Path)
	}
	return f
}

// substrateGatewayGuardrail says when a ConfigMap edit the gateway follower
// has read through the API reaches the gateway's guardrail (hook and /llm
// modes, rules, profiles). The follower applies only the chain egress action
// and the create path's settings; the guardrail reloads from the mounted
// config.yaml (the gateway's config manager), so "in force" at the API read
// was early (substrate-1:GAP-0590). The kubelet updates a directory mount
// (a ..data link beside config.yaml, GAP-0579) about a minute after the
// edit, and never a managed install's subPath mount of the one file.
func substrateGatewayGuardrail(path string) string {
	const what = "the guardrail (hook and /llm modes, rules, profiles) applies "
	if fi, err := os.Lstat(filepath.Join(filepath.Dir(path), "..data")); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return what + "when the kubelet updates the mounted config.yaml, about a minute after the edit"
	}
	return what + "when this pod restarts: config.yaml is mounted as one file (subPath), which the kubelet never updates " +
		"(helm upgrade rolls the pods; after a direct ConfigMap edit run kubectl rollout restart deploy/" + substrateRoleDeployment["gateway"] + ")"
}

// run reads the source every configwatch.DefaultInterval until ctx ends.
func (f *substrateFollower) run(ctx context.Context) {
	t := time.NewTicker(configwatch.DefaultInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		f.step(ctx)
	}
}

// step is one read (tests call it).
func (f *substrateFollower) step(ctx context.Context) {
	ch := f.w.Refresh(ctx)
	if ch.FetchWarning != "" {
		fmt.Fprintf(f.out, "[substrate] %s: %s\n", f.role, ch.FetchWarning)
	}
	if ch.Refused != nil {
		fmt.Fprintf(f.out, "[substrate] %s: config.yaml change not applied: %v\n", f.role, ch.Refused)
	}
	if ch.Config == nil || ch.Digest == f.applied {
		return
	}
	prev := f.applied
	f.applied = ch.Digest
	if err := f.apply(ch.Config); err != nil {
		fmt.Fprintf(f.out, "[substrate] %s: config.yaml %s: not applied live: %v\n", f.role, ch.Digest, err)
		return
	}
	msg := fmt.Sprintf("[substrate] %s: config.yaml %s in force (was %s)", f.role, ch.Digest, prev)
	if f.guardrail != "" {
		msg = fmt.Sprintf("[substrate] %s: config.yaml %s seen (was %s): the chain egress action and the create path's settings apply now; %s",
			f.role, ch.Digest, prev, f.guardrail)
	}
	if pending := substrateRestartOnly(f.boot, ch.Config); len(pending) > 0 {
		msg += "; " + substrateRestartAdvice(f.role, pending, substrateControllerRestartOnly(f.boot, ch.Config))
	}
	fmt.Fprintln(f.out, msg)
}

// substrateHelmOnlyKey is the restart-only key no pod restart applies:
// substrate.extproc renders the callout's ConfigMap, which only helm
// upgrade writes (GAP-0607).
const substrateHelmOnlyKey = "substrate.extproc"

// substrateRestartAdvice says how the restart-only keys in pending apply: a
// rollout restart of the role's Deployment (of every Deployment when the
// controller keeps one of them too, controllerKeys), and helm upgrade only
// for substrate.extproc.
func substrateRestartAdvice(role string, pending, controllerKeys []string) string {
	isHelmOnly := func(k string) bool { return strings.HasPrefix(k, substrateHelmOnlyKey) }
	var restartKeys, helmKeys []string
	for _, k := range pending {
		if isHelmOnly(k) {
			helmKeys = append(helmKeys, k)
		} else {
			restartKeys = append(restartKeys, k)
		}
	}
	var parts []string
	if len(restartKeys) > 0 {
		restart := "kubectl rollout restart deploy/" + substrateRoleDeployment[role]
		for _, k := range controllerKeys {
			if !isHelmOnly(k) {
				restart = substrateRestartAll
				break
			}
		}
		parts = append(parts, "these keys changed and apply when this pod restarts: "+strings.Join(restartKeys, ", ")+
			" (helm upgrade rolls the pods; after a direct ConfigMap edit run "+restart+")")
	}
	if len(helmKeys) > 0 {
		parts = append(parts, "these keys changed and apply only by helm upgrade (a pod restart does not change them): "+strings.Join(helmKeys, ", "))
	}
	return strings.Join(parts, "; ")
}

// substrateRestartOnly names the config keys that differ between boot and
// cur and that a running gateway or leader reads only at start. The rest
// (the egress allow list, profiles and their assignments, launcher
// atespaces, secrets bindings, templates, the chain egress action,
// unattended asks, sandbox classes) is applied live (GAP-0276).
func substrateRestartOnly(boot, cur *config.Config) []string {
	if boot == nil || cur == nil {
		return nil
	}
	b, c := boot.Substrate, cur.Substrate
	var out []string
	for _, k := range []struct {
		key  string
		a, b any
	}{
		{"deployment_mode", boot.DeploymentMode, cur.DeploymentMode},
		{"llm_providers", boot.LLMProviders, cur.LLMProviders},
		{"substrate.api", b.API, c.API},
		{"substrate.identity (sign-in, including kube_sign_in)", b.Identity, c.Identity},
		{"substrate.services", b.Services, c.Services},
		{"substrate.rate_limits", b.RateLimits, c.RateLimits},
		{"substrate.llm", b.LLM, c.LLM},
		{"substrate.workspace_max_bytes", b.WorkspaceMaxBytes, c.WorkspaceMaxBytes},
		{"substrate.secrets (the gateway's injection; the egress bindings apply live)", b.Secrets, c.Secrets},
		{"substrate.extproc (it renders the callout's ConfigMap)", b.Extproc, c.Extproc},
		{"substrate.unattended.ask_timeout (the leader)", b.Unattended.AskTimeout, c.Unattended.AskTimeout},
		{"substrate.bundles", b.Bundles, c.Bundles},
		{"substrate.self_service_secrets.namespace", b.SelfServiceSecrets.EffectiveNamespace(), c.SelfServiceSecrets.EffectiveNamespace()},
		{"substrate.self_service_secrets.provider", b.SelfServiceSecrets.EffectiveProvider(), c.SelfServiceSecrets.EffectiveProvider()},
		// The binding store starts at boot: off to on needs a restart; the
		// other mode changes apply live.
		{"substrate.self_service_secrets.mode (from off)", b.SelfServiceSecrets.EffectiveMode() == config.SelfServiceOff,
			b.SelfServiceSecrets.EffectiveMode() == config.SelfServiceOff && c.SelfServiceSecrets.EffectiveMode() == config.SelfServiceOff},
	} {
		if !reflect.DeepEqual(k.a, k.b) {
			out = append(out, k.key)
		}
	}
	return out
}
