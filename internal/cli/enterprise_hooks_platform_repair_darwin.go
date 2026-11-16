//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// errEnterpriseHookSelfRepairUnavailable is returned when this process may
// not repair managed objects: it is not the root managed guardian, or the
// path is outside the managed install its LaunchDaemon environment pins.
var errEnterpriseHookSelfRepairUnavailable = errors.New("managed self repair is unavailable to this process for this path")

// enterpriseHookInstallSweepInterval bounds how often a guardian pass sweeps
// the whole managed tree. fsnotify can trigger passes in bursts; the objects
// a pass reads are each repaired right before their own validation anyway.
var (
	enterpriseHookInstallSweepInterval = 30 * time.Second
	enterpriseHookInstallSweepLast     time.Time
)

// repairEnterpriseHookManagedInstallPlatform runs on the guardian's passes: it
// re-stamps the managed machine objects (the same set as the pre-config
// step), the install tree's metadata and the group and other write bits of
// env_config.json, heals the LaunchDaemon plists and the log folder, and
// reports an untrusted /etc/codex.
func repairEnterpriseHookManagedInstallPlatform() {
	layout, ok := managed.PinnedManagedServiceLayout()
	if !ok || !managed.SelfRepairEnabled() {
		return
	}
	now := time.Now()
	if !enterpriseHookInstallSweepLast.IsZero() &&
		now.Sub(enterpriseHookInstallSweepLast) < enterpriseHookInstallSweepInterval {
		return
	}
	enterpriseHookInstallSweepLast = now
	managed.RepairOwnedObjects(guardianManagedObjects(layout))
	repairManagedInstallTree(layout)
	if layout.Within(config.DefaultEnvConfigPath) {
		repairManagedEnvConfig(config.DefaultEnvConfigPath)
	}
	healManagedLaunchdPlatform(managedServiceGuardian, layout)
	connector.ReportCodexSystemRequirementsTrust()
}

// repairEnterpriseHookManagedRuntimePlatform re-stamps the managed data_dir
// before the guardian validates it. Only the runtime folder the LaunchDaemon
// environment pins is touched; any other data_dir is left to the validator.
func repairEnterpriseHookManagedRuntimePlatform(dataDir, _ string) error {
	layout, ok := managed.PinnedManagedServiceLayout()
	if !ok || !managed.SelfRepairEnabled() || !enterpriseHookInsideRuntime(layout, dataDir) {
		return nil
	}
	managed.RepairOwnedObject(managed.OwnedObject{
		Path: dataDir, Kind: managed.ObjectRuntimeDirectory, MoveAsideStructural: true, Recreate: true,
	})
	return nil
}

// repairEnterpriseHookGatewayDataPathsPlatform re-stamps the gateway's
// runtime objects on every guardian pass: the databases and their side
// files, the redaction key, the dotenv, the hooks folder and the
// service-side hook and OTLP tokens. The gateway only repairs them when it
// starts, so drift while it runs is healed here. Nothing is moved aside.
func repairEnterpriseHookGatewayDataPathsPlatform() {
	if cfg == nil || !managed.IsManagedEnterprise(cfg.DeploymentMode) {
		return
	}
	layout, ok := managed.PinnedManagedServiceLayout()
	if !ok || !managed.SelfRepairEnabled() || !enterpriseHookInsideRuntime(layout, cfg.DataDir) {
		return
	}
	managed.RepairOwnedObjects(gatewayRuntimeObjects(cfg, layout, false))
}

// repairEnterpriseHookGuardianLedgerObjectPlatform re-stamps one guardian
// ledger object (the authorization folder, the authorization, activation and
// state records) to root:wheel 0750 or 0640 on a no-follow descriptor.
func repairEnterpriseHookGuardianLedgerObjectPlatform(path string, directory bool) error {
	kind := managed.ObjectAdminFile
	if directory {
		kind = managed.ObjectAuthorizationDirectory
	}
	return repairEnterpriseHookOwnedObject(path, kind)
}

// repairEnterpriseHookManifestACL re-stamps targets.yaml to root:wheel 0640.
func repairEnterpriseHookManifestACL(path string) error {
	return repairEnterpriseHookOwnedObject(path, managed.ObjectAdminFile)
}

func repairEnterpriseHookOwnedObject(path string, kind managed.ObjectKind) error {
	layout, ok := managed.PinnedManagedServiceLayout()
	if !ok || !managed.SelfRepairEnabled() || !layout.Within(path) {
		return errEnterpriseHookSelfRepairUnavailable
	}
	result := managed.RepairOwnedObject(managed.OwnedObject{Path: path, Kind: kind})
	switch result.Outcome {
	case managed.CanonicalOK, managed.CanonicalRepaired:
		return nil
	case managed.CanonicalStructural:
		if result.Err != nil {
			return result.Err
		}
	}
	reason := strings.Join(result.Drift, "; ")
	if result.RepairError != "" {
		reason = result.RepairError
	}
	return fmt.Errorf("%s was not repaired (%s): %s", path, result.Outcome, reason)
}

// repairEnterpriseHookScopedTokenPlatform re-stamps the managed data_dir, the
// hooks folder and one connector's service token before anything reads them,
// so mode or owner drift never fails the token mint.
func repairEnterpriseHookScopedTokenPlatform(dataDir, connectorName string) {
	tokenPath, err := connector.HookAPITokenFilePath(dataDir, connectorName)
	if err != nil {
		return
	}
	repairEnterpriseHookTokenChain(dataDir, tokenPath)
}

func repairEnterpriseOTLPTokenPlatform(dataDir string, scope connector.OTLPPathTokenScope) {
	tokenPath, err := connector.OTLPPathTokenFilePath(dataDir, scope)
	if err != nil {
		return
	}
	repairEnterpriseHookTokenChain(dataDir, tokenPath)
}

func repairEnterpriseHookTokenChain(dataDir, tokenPath string) {
	layout, ok := managed.PinnedManagedServiceLayout()
	if !ok || !managed.SelfRepairEnabled() || !enterpriseHookInsideRuntime(layout, dataDir) {
		return
	}
	managed.RepairOwnedObjects([]managed.OwnedObject{
		{Path: dataDir, Kind: managed.ObjectRuntimeDirectory, MoveAsideStructural: true, Recreate: true},
		{Path: filepath.Dir(tokenPath), Kind: managed.ObjectRuntimeDirectory, Mode: 0o700, MoveAsideStructural: true},
		{Path: tokenPath, Kind: managed.ObjectRuntimeSecretFile, Mode: 0o600, MoveAsideStructural: true},
	})
}

// enterpriseHookTokenOwnerPlatform is the owner a service token is aligned
// to. The Secure Client gateway runs as root, so the token is root:wheel; the
// owner of the data_dir is never copied, because drift there could hand the
// token to a standard user. The standalone gateway runs as its service
// account, which owns the data_dir, so a standalone process
// (managed.StandaloneTrustScope) keeps aligning the token to that owner.
func enterpriseHookTokenOwnerPlatform(st *syscall.Stat_t) (int, int) {
	if managed.StandaloneTrustScope() {
		return int(st.Uid), int(st.Gid)
	}
	return 0, 0
}

func enterpriseHookInsideRuntime(layout managed.ManagedServiceLayout, path string) bool {
	if strings.TrimSpace(path) == "" || layout.RuntimeDir == "" {
		return false
	}
	return managed.ManagedServiceLayout{Home: layout.RuntimeDir}.Within(path)
}
