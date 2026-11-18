// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// reclaimUnguardedConnectorHooks removes, at boot, the DefenseClaw hooks of
// every hook connector this install once set up but no longer guards and no
// other boot step owns (rel-1-0-10:GAP-0275).
//
// The set-difference teardown handles a connector in the last active
// roster, and the orphan reconcile one in the hook contract lock. A
// connector in neither kept its hooks for good: a rollback that rewrote
// them into a form the older release did not own, then a connector switch
// there, left a per-user Windows Kiro hook file on an install that guards
// only OpenClaw, whose hook token the earlier teardown had revoked, so every
// Kiro prompt and tool call failed closed.
//
// A connector qualifies only when this install wrote its hook script (one
// of its HookScriptNames is in the hooks folder), it is not configured, not
// in the active roster and not in the lock, its VerifyClean reports
// DefenseClaw hooks left ("teardown incomplete"; a file it cannot read is
// no proof), and, outside Windows, one of the files it patches names this
// install's own hook command, so the hooks of another DefenseClaw data
// directory on the account stay. Windows commands name the per-account
// launcher, not a data directory.
//
// A rollback's data swap drops the hook script and leaves the entries
// running a script that is not there (rel-1-0-10 GAP-1092). A connector that
// can prove from its decoded entries that one is this install's own
// (connector.InstallHookEntryOwner: the command is exactly one this install's
// Setup writes, never a managed install's, and on Windows, where the command
// names the account's launcher, this data folder also holds the live hook
// script or a backup record of the connector) qualifies with or without the
// script, by that proof alone. When ownership cannot be proven, the entries
// stay and the boot says so. Its own Teardown, in reclaim mode
// (SetupOpts.ReclaimOwnHooksOnly), removes only what this install wrote and
// leaves another install's entries in the shared files, then the hook script goes and its hook token is
// revoked as for a removed connector, so the next boot finds nothing to do.
// A managed install leaves it to the hook guardian. A failure is logged and
// never fails a boot.
func (s *Sidecar) reclaimUnguardedConnectorHooks(ctx context.Context, registry *connector.Registry) {
	cfg := s.currentConfig()
	if cfg == nil || strings.TrimSpace(cfg.DataDir) == "" || managed.IsManagedEnterprise(cfg.DeploymentMode) || !cfg.Guardrail.Enabled {
		return
	}
	if registry == nil {
		registry = connector.NewDefaultRegistry()
	}
	tracked := map[string]bool{}
	for _, name := range cfg.ActiveConnectors() {
		tracked[strings.ToLower(strings.TrimSpace(name))] = true
	}
	for _, name := range connector.LoadActiveConnectors(cfg.DataDir) {
		tracked[strings.ToLower(strings.TrimSpace(name))] = true
	}
	entries, err := connector.LoadProtectedHookContractLockEntries(cfg.DataDir)
	if err != nil {
		// The orphan reconcile reports an unreadable lock; without it no
		// connector here is provably unowned.
		return
	}
	for name := range entries {
		tracked[strings.ToLower(strings.TrimSpace(name))] = true
	}
	names := registry.Names()
	sort.Strings(names)
	opts := connector.SetupOpts{
		DataDir:      cfg.DataDir,
		ProxyAddr:    guardrailListenAddr(cfg.Guardrail.Port, cfg.Guardrail.Host),
		APIAddr:      apiListenAddr(cfg),
		WorkspaceDir: cfg.ConnectorWorkspaceDir(),
	}
	for _, name := range names {
		if tracked[name] {
			continue
		}
		conn, ok := registry.Get(name)
		if !ok {
			continue
		}
		if _, hooked := conn.(connector.HookEndpoint); !hooked {
			continue
		}
		owner, decoded := conn.(connector.InstallHookEntryOwner)
		if !decoded && !installWroteHookScript(conn, opts) {
			continue
		}
		if err := conn.VerifyClean(opts); err == nil || !strings.Contains(err.Error(), "teardown incomplete") {
			continue
		}
		if decoded {
			if owns, err := owner.InstallOwnsHookEntries(opts); err != nil || !owns {
				fmt.Fprintf(os.Stderr, "[guardrail] connector %s is not guarded and DefenseClaw hook entries remain, but this install cannot prove they are its own; left in place\n", name)
				continue
			}
		} else if !connector.PatchedFilesNameOwnHook(opts, conn) {
			continue
		}
		result := "removed"
		reclaim := opts
		reclaim.ReclaimOwnHooksOnly = true
		if err := conn.Teardown(ctx, reclaim); err != nil {
			result = "failed"
			fmt.Fprintf(os.Stderr, "[guardrail] WARNING: connector %s is not guarded but its DefenseClaw hooks could not be removed: %v\n", name, err)
		} else if err := verifyOwnHooksGone(conn, owner, decoded, opts); err != nil {
			result = "incomplete"
			fmt.Fprintf(os.Stderr, "[guardrail] WARNING: connector %s is not guarded and its DefenseClaw hooks are not all gone: %v\n", name, err)
		} else {
			if err := removeTeardownHookFiles(registry, conn, cfg.ActiveConnectors(), opts); err != nil {
				fmt.Fprintf(os.Stderr, "[guardrail] WARNING: connector %s hook script and token were not removed: %v\n", name, err)
			}
			fmt.Fprintf(os.Stderr, "[guardrail] connector %s is not guarded: removed the DefenseClaw hooks an earlier setup left\n", name)
		}
		if s.logger != nil {
			_ = s.logger.LogAction(
				string(audit.ActionSetupHookConnector),
				name,
				fmt.Sprintf("connector=%s action=reclaim-unguarded result=%s", name, result),
			)
		}
	}
}

// verifyOwnHooksGone checks a reclaim: for a connector that proves ownership
// from its decoded entries, that none of this install's is left (another
// install's entries in the shared files stay, so VerifyClean, which reads
// every DefenseClaw entry, would report them); for any other, VerifyClean.
func verifyOwnHooksGone(conn connector.Connector, owner connector.InstallHookEntryOwner, decoded bool, opts connector.SetupOpts) error {
	if !decoded {
		return conn.VerifyClean(opts)
	}
	owns, err := owner.InstallOwnsHookEntries(opts)
	if err != nil {
		return err
	}
	if owns {
		return fmt.Errorf("%s teardown incomplete: hook entries of this install remain", conn.Name())
	}
	return nil
}

// installWroteHookScript reports whether the hooks folder holds one of the
// hook scripts of the connector, that is, this install set the connector up once.
func installWroteHookScript(conn connector.Connector, opts connector.SetupOpts) bool {
	owner, ok := conn.(connector.HookScriptOwner)
	if !ok {
		return false
	}
	for _, script := range owner.HookScriptNames(opts) {
		if info, err := os.Lstat(filepath.Join(opts.DataDir, "hooks", script)); err == nil && info.Mode().IsRegular() {
			return true
		}
	}
	return false
}
