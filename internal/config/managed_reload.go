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

package config

import (
	"errors"
	"fmt"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// ManagedReloadRefusal is why a running process must refuse to apply next
// over old: dropping deployment_mode managed_enterprise (reason
// "managed_downgrade") or changing the enterprise profile
// ("enterprise_profile_change"). The gateway's config reload and the
// Substrate config watch share it (GAP-0294).
func ManagedReloadRefusal(old, next *Config) (string, error) {
	if old == nil || next == nil || !managed.IsManagedEnterprise(old.DeploymentMode) {
		return "", nil
	}
	if !managed.IsManagedEnterprise(next.DeploymentMode) {
		return "managed_downgrade", errors.New("config reload cannot downgrade deployment_mode from managed_enterprise")
	}
	if old.EnterpriseProfile() != next.EnterpriseProfile() {
		return "enterprise_profile_change", fmt.Errorf("config reload cannot change the enterprise profile from %q to %q; reinstall through the lifecycle",
			old.EnterpriseProfile(), next.EnterpriseProfile())
	}
	return "", nil
}

// LiveReloadRefusal is ManagedReloadRefusal plus a deployment_mode change in
// either direction, which a running Substrate component never takes live
// (the gateway marks it restart-required): the whole edit waits for the
// pods to restart with it (GAP-0294).
func LiveReloadRefusal(old, next *Config) (string, error) {
	if reason, err := ManagedReloadRefusal(old, next); err != nil {
		return reason, err
	}
	if old != nil && next != nil && managed.IsManagedEnterprise(old.DeploymentMode) != managed.IsManagedEnterprise(next.DeploymentMode) {
		return "deployment_mode_change", fmt.Errorf("deployment_mode %q to %q is not applied to a running component", old.DeploymentMode, next.DeploymentMode)
	}
	return "", nil
}

// LiveReloadSourceRefusal is LiveReloadRefusal for a source that is not
// loaded yet, from the deployment_mode it would run as (the
// DEFENSECLAW_DEPLOYMENT_MODE pin, else what it declares). A running
// component checks it before the load: a source that switches an OSS
// component to managed_enterprise makes the loader run the managed trust
// check on the mounted path first, and on a ConfigMap mount (symlinks) that
// refusal named the mount instead of the mode change the edit makes
// (GAP-0323). It answers only a change of mode; ManagedReloadRefusal on the
// loaded config still checks a change between two managed profiles.
func LiveReloadSourceRefusal(old *Config, raw []byte) (string, error) {
	if old == nil || len(raw) > V8YAMLMaxSourceBytes {
		return "", nil
	}
	mode := normalizeDeploymentMode(os.Getenv(managed.DeploymentModeEnv))
	if mode == "" {
		var declared struct {
			DeploymentMode string `yaml:"deployment_mode"`
		}
		if decodeSourceYAML(raw, &declared) != nil {
			// The load reports a source that does not decode.
			return "", nil
		}
		mode = normalizeDeploymentMode(declared.DeploymentMode)
	}
	next := &Config{DeploymentMode: mode}
	if managed.IsManagedEnterprise(old.DeploymentMode) == managed.IsManagedEnterprise(next.DeploymentMode) {
		return "", nil
	}
	return LiveReloadRefusal(old, next)
}
