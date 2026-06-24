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

package enterprisehooks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// InstallOptions describes one explicit enterprise hook install/repair target.
//
// The gateway service itself is deliberately sandboxed away from user homes in
// managed enterprise deployments. This helper is for a short-lived privileged
// guardian/MDM step that targets one real interactive user's home directory and
// then exits.
type InstallOptions struct {
	ConnectorName  string
	UserHome       string
	OwnerUID       int
	OwnerGID       int
	DataDir        string
	APIAddr        string
	ProxyAddr      string
	APIToken       string
	MasterKey      string
	HookFailMode   string
	GuardrailMode  string
	HILTEnabled    bool
	AgentVersion   string
	HookContractID string
	WorkspaceDir   string
	Registry       *connector.Registry
}

type InstallResult struct {
	Connector       string   `json:"connector"`
	UserHome        string   `json:"user_home"`
	DataDir         string   `json:"data_dir"`
	HookConfigPaths []string `json:"hook_config_paths,omitempty"`
	HookScripts     []string `json:"hook_scripts,omitempty"`
	BackupFiles     []string `json:"backup_files,omitempty"`
	CreatedDirs     []string `json:"created_dirs,omitempty"`
	AgentVersion    string   `json:"agent_version,omitempty"`
	HookContractID  string   `json:"hook_contract_id,omitempty"`
}

func Install(ctx context.Context, opts InstallOptions) (InstallResult, error) {
	home, err := validateUserHome(opts.UserHome)
	if err != nil {
		return InstallResult{}, err
	}
	uid, gid, err := resolveOwner(home, opts.OwnerUID, opts.OwnerGID)
	if err != nil {
		return InstallResult{}, err
	}
	dataDir := strings.TrimSpace(opts.DataDir)
	if dataDir == "" {
		dataDir = filepath.Join(home, ".defenseclaw")
	}
	dataDir, err = filepath.Abs(dataDir)
	if err != nil {
		return InstallResult{}, fmt.Errorf("enterprise hooks: resolve data dir: %w", err)
	}

	reg := opts.Registry
	if reg == nil {
		reg = connector.NewDefaultRegistry()
	}
	name := strings.ToLower(strings.TrimSpace(opts.ConnectorName))
	if name == "" {
		return InstallResult{}, fmt.Errorf("enterprise hooks: connector is required")
	}
	conn, ok := reg.Get(name)
	if !ok {
		return InstallResult{}, fmt.Errorf("enterprise hooks: unknown connector %q", name)
	}
	if connector.IsProxyConnector(conn.Name()) {
		return InstallResult{}, fmt.Errorf("enterprise hooks: connector %q is proxy/plugin setup-only; per-user hook install is not supported", conn.Name())
	}
	if _, ok := conn.(connector.HookScriptOwner); !ok {
		return InstallResult{}, fmt.Errorf("enterprise hooks: connector %q does not own a hook script", conn.Name())
	}
	if !connector.ConnectorSupportedOnHostOS(conn.Name()) {
		return InstallResult{}, fmt.Errorf("enterprise hooks: connector %q is not supported on this host OS", conn.Name())
	}

	setupOpts := connector.SetupOpts{
		DataDir:        dataDir,
		ProxyAddr:      strings.TrimSpace(opts.ProxyAddr),
		APIAddr:        strings.TrimSpace(opts.APIAddr),
		APIToken:       strings.TrimSpace(opts.APIToken),
		Interactive:    false,
		WorkspaceDir:   strings.TrimSpace(opts.WorkspaceDir),
		HookFailMode:   strings.TrimSpace(opts.HookFailMode),
		HILTEnabled:    opts.HILTEnabled,
		AgentVersion:   strings.TrimSpace(opts.AgentVersion),
		HookContractID: strings.TrimSpace(opts.HookContractID),
	}
	if setupOpts.AgentVersion == "" {
		setupOpts.AgentVersion = connector.LoadCachedAgentVersion(dataDir, conn.Name())
	}
	if setupOpts.HookContractID == "" {
		resolution := connector.ResolveHookContract(conn.Name(), setupOpts.AgentVersion)
		setupOpts.HookContractID = resolution.Contract.ContractID
	}

	var result InstallResult
	err = connector.WithUserHomeDir(home, func() error {
		paths := connector.HookConfigPathsForConnector(conn, setupOpts)
		if err := validateActivationSurfaces(home, paths, uid); err != nil {
			return err
		}
		if err := validateHookContract(opts.GuardrailMode, conn, setupOpts); err != nil {
			return err
		}

		conn.SetCredentials(setupOpts.APIToken, opts.MasterKey)
		if err := conn.Setup(ctx, setupOpts); err != nil {
			return fmt.Errorf("enterprise hooks: connector %s setup failed: %w", conn.Name(), err)
		}
		present, err := connector.OwnedHooksPresent(conn, setupOpts)
		if err != nil {
			_ = conn.Teardown(ctx, setupOpts)
			return fmt.Errorf("enterprise hooks: connector %s hook verification failed: %w", conn.Name(), err)
		}
		if !present {
			_ = conn.Teardown(ctx, setupOpts)
			return fmt.Errorf("enterprise hooks: connector %s hook verification failed: owned hook command not present", conn.Name())
		}
		lockEntry := connector.NewHookContractLockEntry(setupOpts, conn, version.Current().BinaryVersion)
		if err := connector.SaveHookContractLockEntry(dataDir, lockEntry); err != nil {
			_ = conn.Teardown(ctx, setupOpts)
			return fmt.Errorf("enterprise hooks: save hook contract lock: %w", err)
		}

		footprint := connector.AgentPaths{}
		if ap, ok := conn.(connector.AgentPathProvider); ok {
			footprint = ap.AgentPaths(setupOpts)
		}
		result = InstallResult{
			Connector:       conn.Name(),
			UserHome:        home,
			DataDir:         dataDir,
			HookConfigPaths: sortedUnique(paths),
			HookScripts:     sortedUnique(footprint.HookScripts),
			BackupFiles:     sortedUnique(footprint.BackupFiles),
			CreatedDirs:     sortedUnique(footprint.CreatedDirs),
			AgentVersion:    setupOpts.AgentVersion,
			HookContractID:  lockEntry.ContractID,
		}
		return chownInstallFootprint(uid, gid, dataDir, footprint, paths)
	})
	if err != nil {
		return InstallResult{}, err
	}
	return result, nil
}

func validateUserHome(raw string) (string, error) {
	home := strings.TrimSpace(raw)
	if home == "" {
		return "", fmt.Errorf("enterprise hooks: user home is required")
	}
	abs, err := filepath.Abs(home)
	if err != nil {
		return "", fmt.Errorf("enterprise hooks: resolve user home: %w", err)
	}
	clean := filepath.Clean(abs)
	if clean == string(filepath.Separator) {
		return "", fmt.Errorf("enterprise hooks: refusing to target filesystem root as a user home")
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return "", fmt.Errorf("enterprise hooks: inspect user home %s: %w", clean, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("enterprise hooks: refusing symlink user home %s", clean)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("enterprise hooks: user home %s is not a directory", clean)
	}
	return clean, nil
}

func validateActivationSurfaces(home string, paths []string, uid int) error {
	if len(paths) == 0 {
		return fmt.Errorf("enterprise hooks: connector does not expose a hook config path")
	}
	for _, raw := range paths {
		path := filepath.Clean(strings.TrimSpace(raw))
		if path == "" {
			continue
		}
		if !filepath.IsAbs(path) {
			return fmt.Errorf("enterprise hooks: hook config path %q is not absolute", raw)
		}
		if !pathInside(home, path) {
			return fmt.Errorf("enterprise hooks: refusing hook config outside user home: %s", path)
		}
		resolved := path
		info, err := os.Lstat(path)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("enterprise hooks: hook config file missing: %s", path)
			}
			return fmt.Errorf("enterprise hooks: inspect hook config %s: %w", path, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			resolved, err = filepath.EvalSymlinks(path)
			if err != nil {
				return fmt.Errorf("enterprise hooks: resolve hook config symlink %s: %w", path, err)
			}
			resolved = filepath.Clean(resolved)
			if !pathInside(home, resolved) {
				return fmt.Errorf("enterprise hooks: refusing hook config symlink %s -> %s outside user home", path, resolved)
			}
			info, err = os.Stat(resolved)
			if err != nil {
				return fmt.Errorf("enterprise hooks: inspect hook config target %s: %w", resolved, err)
			}
		}
		if info.IsDir() {
			return fmt.Errorf("enterprise hooks: hook config path is a directory: %s", resolved)
		}
		if info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("enterprise hooks: hook config %s is group/other writable", resolved)
		}
		if ok, actual := fileOwnerMatches(resolved, uid); !ok {
			return fmt.Errorf("enterprise hooks: hook config %s owner uid=%d does not match target uid=%d", resolved, actual, uid)
		}
	}
	return nil
}

func validateHookContract(mode string, conn connector.Connector, opts connector.SetupOpts) error {
	if !strings.EqualFold(strings.TrimSpace(mode), "action") || os.Getenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT") == "1" {
		return nil
	}
	resolution := connector.ResolveHookContract(conn.Name(), opts.AgentVersion)
	if connector.HookContractNeedsActionOverride(resolution) {
		return fmt.Errorf("enterprise hooks: connector %s agent version %q is not verified against a known hook contract: %s", conn.Name(), opts.AgentVersion, resolution.Reason)
	}
	if previous := connector.LoadHookContractLockEntry(opts.DataDir, conn.Name()); previous.Connector != "" {
		current := connector.NewHookContractLockEntry(opts, conn, version.Current().BinaryVersion)
		if connector.HookContractLockDrifted(previous, current) {
			return fmt.Errorf("enterprise hooks: connector %s hook contract drift detected: previous version=%q contract=%s current version=%q contract=%s", conn.Name(), previous.RawAgentVersion, previous.ContractID, current.RawAgentVersion, current.ContractID)
		}
	}
	return nil
}

func pathInside(root, path string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func sortedUnique(vals []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, v := range vals {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
