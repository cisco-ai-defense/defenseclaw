// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"encoding/json"
	"fmt"
	"path"
	"reflect"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeproto"
	"github.com/defenseclaw/defenseclaw/internal/sandboxruntime"
)

// UnsupportedPolicy reports only component names, never confidential component
// values or paths. No receipt is emitted when any translation is incomplete.
type UnsupportedPolicy struct {
	Components []sandboxruntime.PolicyComponentName
}

func (e *UnsupportedPolicy) Error() string {
	return fmt.Sprintf("AXIS policy translation is not qualified for components %v", e.Components)
}

func guestGrants(read, write []string) error {
	all := append(slices.Clone(read), write...)
	for i, value := range all {
		if !strings.HasPrefix(value, "/") || value == "/" || path.Clean(value) != value || strings.ContainsRune(value, 0) || len(value) > 4096 {
			return ErrAssets
		}
		for _, reserved := range []string{"/proc", "/dev", "/.defenseclaw"} {
			if value == reserved || strings.HasPrefix(value, reserved+"/") || strings.HasPrefix(reserved, value+"/") {
				return ErrAssets
			}
		}
		for _, previous := range all[:i] {
			if value == previous || strings.HasPrefix(value, previous+"/") || strings.HasPrefix(previous, value+"/") {
				return ErrAssets
			}
		}
	}
	return nil
}

// compilePolicy deliberately has no acknowledgement shortcut. The private
// offline peer is a native mechanism; fixed canaries do not implement the
// complete common policy, host authority, workspace provenance, managed hooks
// or MCP contract. Every such component, including future names, refuses here.
// This must be replaced component by component with reviewed translations,
// rather than copying component digests into an otherwise empty receipt.
func compilePolicy(policy *sandboxruntime.ExecutionPolicy, spec sandboxruntime.Spec, assets *Assets) (bridgeproto.Preparation, sandboxruntime.PolicyReceipt, error) {
	if policy.Digest() == "" || spec.Identity.Validate() != nil {
		return bridgeproto.Preparation{}, sandboxruntime.PolicyReceipt{}, ErrPolicy
	}
	if err := validateWorkspacePreparation(policy, spec, assets); err != nil {
		return bridgeproto.Preparation{}, sandboxruntime.PolicyReceipt{}, err
	}
	unsupported := &UnsupportedPolicy{}
	seen := map[sandboxruntime.PolicyComponentName]bool{}
	for _, component := range policy.Components() {
		if seen[component.Name] {
			return bridgeproto.Preparation{}, sandboxruntime.PolicyReceipt{}, ErrPolicy
		}
		seen[component.Name] = true
		// The native peer has no cgroup resource controller. Even a resource
		// component is refused unless its complete schema is the zero limits.
		if component.Name == sandboxruntime.PolicyResources {
			var limits map[string]int64
			if json.Unmarshal(component.Value, &limits) == nil && len(limits) == 2 &&
				limits["cpu_millicores"] == 0 && limits["memory_bytes"] == 0 {
				if _, cpu := limits["cpu_millicores"]; cpu {
					if _, memory := limits["memory_bytes"]; memory {
						continue
					}
				}
			}
		}
		unsupported.Components = append(unsupported.Components, component.Name)
	}
	if len(unsupported.Components) == 0 {
		// An incomplete/changed resolver inventory cannot become an empty
		// "supported" policy. No current production policy is translatable.
		return bridgeproto.Preparation{}, sandboxruntime.PolicyReceipt{}, ErrPolicy
	}
	return bridgeproto.Preparation{}, sandboxruntime.PolicyReceipt{}, unsupported
}

// validateCompilation is a second boundary after the trusted compiler, before
// native preparation. It does not qualify translations or construct receipts.
func validateCompilation(policy *sandboxruntime.ExecutionPolicy, spec sandboxruntime.Spec, assets *Assets, plan bridgeproto.Preparation, receipt sandboxruntime.PolicyReceipt) error {
	if plan.Validate() != nil || plan.Backend != "bubblewrap" || !plan.Offline || !spec.Offline || plan.Terminal != nil ||
		len(spec.Command) == 0 || spec.Command[0] != "/.defenseclaw/payload" || !reflect.DeepEqual(plan.Argv, spec.Command) ||
		spec.GuestWorkspace != "/work" || plan.Workdir != spec.GuestWorkspace || spec.BindingID != "" || spec.CredentialProfile != "" || spec.CPU != "" || spec.Memory != "" ||
		!reflect.DeepEqual(plan.Filesystem.Read, assets.read) || !reflect.DeepEqual(plan.Filesystem.Write, assets.write) || len(plan.Filesystem.Deny) != 0 {
		return ErrPolicy
	}
	environment := make(map[string]string, len(plan.Environment))
	for _, variable := range plan.Environment {
		want, allowed := map[string]string{"HOME": "/home", "TMPDIR": "/tmp", "TMP": "/tmp", "TEMP": "/tmp", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}[variable.Name]
		if !allowed || variable.Value != want {
			return ErrPolicy
		}
		environment[variable.Name] = variable.Value
	}
	if !reflect.DeepEqual(environment, spec.Env) || environment["HOME"] != "/home" || environment["TMPDIR"] != "/tmp" ||
		!slices.Contains(assets.write, "/home") || !slices.Contains(assets.write, "/tmp") ||
		receipt.Runtime != spec.Identity.Runtime || receipt.Harness != spec.HarnessIdentity || receipt.PolicyDigest != policy.Digest() {
		return ErrPolicy
	}
	components := policy.Components()
	if len(receipt.Components) != len(components) {
		return ErrPolicy
	}
	for i, component := range components {
		if receipt.Components[i] != (sandboxruntime.PolicyComponentBinding{Name: component.Name, Digest: component.Digest}) {
			return ErrPolicy
		}
	}
	return nil
}
