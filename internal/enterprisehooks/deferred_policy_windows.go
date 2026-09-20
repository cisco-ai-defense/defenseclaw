// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

type windowsDeferredPolicyTarget struct {
	manifest ManifestTarget
	sid      string
	dataDir  string
}

func stageWindowsEnterpriseDeferredPoliciesPlatform(
	manifest Manifest,
	pending []ManifestTarget,
	apiAddr string,
) error {
	if len(pending) == 0 {
		return nil
	}
	if err := windowsEnterpriseMutationIdentityCheck(); err != nil {
		return err
	}
	hookExecutable, err := windowsEnterpriseHookExecutable()
	if err != nil {
		return err
	}
	hookExecutable = filepath.Clean(hookExecutable)
	if err := windowsEnterpriseHookTrustCheck(hookExecutable); err != nil {
		return fmt.Errorf(
			"enterprise hooks: deferred machine-policy hook executable is untrusted: %w",
			err,
		)
	}
	apiAddr = strings.TrimSpace(apiAddr)
	if apiAddr == "" {
		return errors.New("enterprise hooks: deferred machine-policy API address is required")
	}
	gatewayServiceName := os.Getenv(connector.WindowsGatewayServiceNameEnv)
	if err := connector.ValidateWindowsManagedGatewayServiceName(gatewayServiceName); err != nil {
		return err
	}

	authorized := make(map[string]ManifestTarget)
	for _, target := range manifest.Targets {
		if !target.IsEnabled() {
			continue
		}
		key := windowsDeferredPolicyManifestKey(target)
		if key == "" {
			return errors.New("enterprise hooks: enabled Windows manifest target has incomplete identity")
		}
		authorized[key] = target
	}
	validated := make([]windowsDeferredPolicyTarget, 0, len(pending))
	seen := make(map[string]struct{}, len(pending))
	for _, target := range pending {
		key := windowsDeferredPolicyManifestKey(target)
		manifestTarget, ok := authorized[key]
		if !ok || !sameWindowsDeferredPolicyTarget(manifestTarget, target) {
			return errors.New("enterprise hooks: pending target is not exactly authorized by the current manifest")
		}
		if _, duplicate := seen[key]; duplicate {
			return errors.New("enterprise hooks: duplicate deferred machine-policy target")
		}
		seen[key] = struct{}{}
		if err := requireWindowsEnterpriseDeferredTargetPendingPlatform(target); err != nil {
			return err
		}
		home, sid, err := validateWindowsEnterpriseHome(target.UserHome, target.SID)
		if err != nil {
			return err
		}
		dataDir, err := resolveWindowsEnterpriseDataDir(home, target.DataDir)
		if err != nil {
			return err
		}
		validated = append(validated, windowsDeferredPolicyTarget{
			manifest: target,
			sid:      sid.String(),
			dataDir:  dataDir,
		})
	}

	registry := newWindowsEnterpriseConnectorRegistry()
	rollbacks := make([]func() error, 0, len(validated))
	rollback := func(cause error) error {
		var rollbackErrs []error
		for index := len(rollbacks) - 1; index >= 0; index-- {
			if rollbacks[index] == nil {
				continue
			}
			if err := rollbacks[index](); err != nil {
				rollbackErrs = append(rollbackErrs, err)
			}
		}
		return errors.Join(append([]error{cause}, rollbackErrs...)...)
	}
	existingClaude := make(map[string]struct{})
	if windowsDeferredPoliciesContainConnector(validated, "claudecode") {
		targets, active, err := ReadWindowsClaudeManagedPolicyTargets()
		if err != nil {
			return err
		}
		if active {
			if err := VerifyWindowsClaudeManagedPolicyIdentity(
				hookExecutable,
				apiAddr,
				gatewayServiceName,
			); err != nil {
				return err
			}
		}
		for _, sid := range targets {
			existingClaude[strings.ToUpper(strings.TrimSpace(sid))] = struct{}{}
		}
	}
	existingCursor := make(map[string]string)
	if windowsDeferredPoliciesContainConnector(validated, "cursor") {
		targets, active, err := ReadWindowsCursorManagedPolicyTargets()
		if err != nil {
			return err
		}
		if active {
			if err := VerifyWindowsCursorManagedPolicyIdentity(
				hookExecutable,
				apiAddr,
				gatewayServiceName,
			); err != nil {
				return err
			}
		}
		for _, target := range targets {
			existingCursor[strings.ToUpper(strings.TrimSpace(target.SID))] =
				filepath.Clean(strings.TrimSpace(target.DataDir))
		}
	}
	for _, target := range validated {
		name := strings.ToLower(strings.TrimSpace(target.manifest.Connector))
		if name == "codex" {
			continue
		}
		sid, err := validateWindowsEnterpriseTargetSID(target.sid)
		if err != nil {
			return rollback(err)
		}
		setup := connector.SetupOpts{
			APIAddr:           apiAddr,
			HookFailMode:      "closed",
			ManagedEnterprise: true,
			HookExecutable:    hookExecutable,
			DataDir:           target.dataDir,
			AgentVersion:      strings.TrimSpace(target.manifest.AgentVersion),
		}
		switch name {
		case "claudecode":
			if _, alreadyStaged := existingClaude[strings.ToUpper(target.sid)]; alreadyStaged {
				continue
			}
			conn, ok := registry.Get(name)
			if !ok {
				return rollback(fmt.Errorf("enterprise hooks: unknown connector %q", name))
			}
			if err := windowsEnterpriseConnectorCertification(name, conn); err != nil {
				return rollback(err)
			}
			provider, ok := conn.(connector.ManagedHookPolicyProvider)
			if !ok {
				return rollback(errors.New("enterprise hooks: Claude connector has no managed-policy provider"))
			}
			body, err := provider.ManagedHookPolicy(setup)
			if err != nil {
				return rollback(err)
			}
			if err := provider.VerifyManagedHookPolicy(body, setup); err != nil {
				return rollback(err)
			}
			_, undo, err := installWindowsClaudeManagedPolicy(body, setup, sid)
			if err != nil {
				return rollback(err)
			}
			rollbacks = append(rollbacks, undo)
			existingClaude[strings.ToUpper(target.sid)] = struct{}{}
		case "cursor":
			if currentDataDir, alreadyStaged := existingCursor[strings.ToUpper(target.sid)]; alreadyStaged {
				if !sameWindowsEnterprisePath(currentDataDir, target.dataDir) {
					return rollback(errors.New("enterprise hooks: existing deferred Cursor target has a different data directory"))
				}
				continue
			}
			undo, err := installWindowsCursorManagedPolicy(setup, sid, target.dataDir)
			if err != nil {
				return rollback(err)
			}
			rollbacks = append(rollbacks, undo)
			existingCursor[strings.ToUpper(target.sid)] = target.dataDir
		default:
			return rollback(fmt.Errorf("enterprise hooks: unsupported deferred connector %q", name))
		}
	}

	if windowsDeferredPoliciesContainConnector(validated, "codex") {
		machineOpts, err := windowsCodexRequirementsOptionsResolver(hookExecutable, apiAddr)
		if err != nil {
			return rollback(err)
		}
		registry, err := connector.ResolveWindowsCodexManagedRuntimeRegistry(machineOpts.HookBinary)
		if err != nil {
			return rollback(err)
		}
		if registry.Active && (registry.GatewayAddr != machineOpts.GatewayAddr ||
			registry.GatewayServiceName != machineOpts.GatewayServiceName) {
			return rollback(errors.New(
				"enterprise hooks: Codex machine policy belongs to another protected gateway deployment",
			))
		}
		if !registry.Active {
			report, err := windowsCodexRequirementsReconciler(machineOpts)
			if err != nil {
				return rollback(fmt.Errorf("enterprise hooks: stage Codex machine requirements: %w", err))
			}
			if !report.OK || !report.SecurityComplete {
				return rollback(errors.New("enterprise hooks: staged Codex machine requirements are not security-complete"))
			}
		}
	}
	return nil
}

func windowsDeferredPolicyManifestKey(target ManifestTarget) string {
	sid := strings.ToUpper(strings.TrimSpace(target.SID))
	connectorName := strings.ToLower(strings.TrimSpace(target.Connector))
	if sid == "" || connectorName == "" {
		return ""
	}
	return connectorName + "\x00" + sid
}

func sameWindowsDeferredPolicyTarget(left, right ManifestTarget) bool {
	return left.IsEnabled() && right.IsEnabled() && left.IsDeferred() && right.IsDeferred() &&
		strings.EqualFold(strings.TrimSpace(left.SID), strings.TrimSpace(right.SID)) &&
		strings.EqualFold(strings.TrimSpace(left.Connector), strings.TrimSpace(right.Connector)) &&
		sameWindowsEnterprisePath(strings.TrimSpace(left.UserHome), strings.TrimSpace(right.UserHome)) &&
		sameWindowsEnterprisePath(strings.TrimSpace(left.DataDir), strings.TrimSpace(right.DataDir)) &&
		strings.TrimSpace(left.AgentVersion) == strings.TrimSpace(right.AgentVersion)
}

func windowsDeferredPoliciesContainConnector(
	targets []windowsDeferredPolicyTarget,
	connectorName string,
) bool {
	for _, target := range targets {
		if strings.EqualFold(strings.TrimSpace(target.manifest.Connector), connectorName) {
			return true
		}
	}
	return false
}
