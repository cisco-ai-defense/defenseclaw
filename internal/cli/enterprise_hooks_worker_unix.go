//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// The apply-target worker runs every user-home operation of the standalone
// Unix guardian with the target user's own uid and gid. The root guardian
// keeps token minting, the authorization ledger and file watching; it never
// Lstats, removes, chmods or writes inside a user home itself, so a user
// cannot race a root check-then-act, a Seteuid drop can never leak into
// the guardian's other goroutines, and NFS root_squash homes work.

const (
	// 2: the discover operation also answers app and extension surfaces.
	enterpriseHookWorkerProtocolVersion = 2
	enterpriseHookWorkerRequestLimit    = 1 << 20
	enterpriseHookWorkerResponseLimit   = 8 << 20
	enterpriseHookWorkerStderrLimit     = 64 << 10
	enterpriseHookWorkerParallelism     = 4

	enterpriseHookWorkerOpApply          = "apply"
	enterpriseHookWorkerOpDiscover       = "discover"
	enterpriseHookWorkerOpForeignCleanup = "foreign_cleanup"
	// enterpriseHookWorkerOpAIDiscovery runs the static AI discovery scan
	// of the user's own home (standalone profile).
	enterpriseHookWorkerOpAIDiscovery = "ai_discovery"

	enterpriseHookWorkerModeInstall        = "install"
	enterpriseHookWorkerModeVerify         = "verify"
	enterpriseHookWorkerModeVerifyOrRepair = "verify_or_repair"
	// enterpriseHookWorkerModeRemove tears down DefenseClaw's own per-user
	// registration (standalone uninstall).
	enterpriseHookWorkerModeRemove = "remove"
	// enterpriseHookWorkerModeRemoveLeftover tears down the guardian's
	// per-user registration of a machine-policy connector the user is not
	// enrolled for per user (one an earlier route left, for example
	// ownership: "off" before it kept Claude Code off every route). It
	// changes nothing unless the user's hook contract lock records such a
	// registration.
	enterpriseHookWorkerModeRemoveLeftover = "remove_leftover"
	// enterpriseHookWorkerModePurge removes the user's DefenseClaw per-user
	// state (standalone uninstall --purge). It runs after the request's
	// removals and only when every one of them succeeded: the state holds
	// the backups a failed removal needs when it is retried.
	enterpriseHookWorkerModePurge = "purge"
)

// enterpriseHookWorkerTimeout bounds one worker process.
var enterpriseHookWorkerTimeout = 60 * time.Second

// enterpriseHookWorkerPassthroughEnv are administrator-controlled service
// settings the worker needs; nothing else from root's environment reaches
// a process that runs as the user.
var enterpriseHookWorkerPassthroughEnv = []string{
	"DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT",
	"DEFENSECLAW_CODEX_LOOPBACK_TRUST",
	enterprisehooks.TrustedBinPrefixesEnv,
}

type enterpriseHookWorkerOptions struct {
	ConnectorName                      string `json:"connector"`
	UserHome                           string `json:"user_home"`
	OwnerUID                           int    `json:"owner_uid"`
	OwnerGID                           int    `json:"owner_gid"`
	DataDir                            string `json:"data_dir,omitempty"`
	APIAddr                            string `json:"api_addr,omitempty"`
	ProxyAddr                          string `json:"proxy_addr,omitempty"`
	APIToken                           string `json:"api_token,omitempty"`
	OTLPPathToken                      string `json:"otlp_path_token,omitempty"`
	HookFailMode                       string `json:"hook_fail_mode,omitempty"`
	GuardrailMode                      string `json:"guardrail_mode,omitempty"`
	HILTEnabled                        bool   `json:"hilt_enabled,omitempty"`
	AgentVersion                       string `json:"agent_version,omitempty"`
	HookContractID                     string `json:"hook_contract_id,omitempty"`
	WorkspaceDir                       string `json:"workspace_dir,omitempty"`
	AllowMissingHookConfigRepair       bool   `json:"allow_missing_hook_config_repair,omitempty"`
	RecoveryHookContractLockUpdatedAt  string `json:"recovery_hook_contract_lock_updated_at,omitempty"`
	RecoveryHookContractEntryUpdatedAt string `json:"recovery_hook_contract_entry_updated_at,omitempty"`
	ManagedHookSocket                  string `json:"managed_hook_socket,omitempty"`
	ManagedServiceUID                  int    `json:"managed_service_uid,omitempty"`
	HookCredentialIdentity             string `json:"hook_credential_identity,omitempty"`
	ForeignHookGuardBinary             string `json:"foreign_hook_guard_binary,omitempty"`
}

type enterpriseHookWorkerTarget struct {
	Index               int                         `json:"index"`
	Mode                string                      `json:"mode"`
	PreviouslyProtected bool                        `json:"previously_protected,omitempty"`
	Options             enterpriseHookWorkerOptions `json:"options"`
}

type enterpriseHookWorkerRequest struct {
	Version    int                          `json:"version"`
	Operation  string                       `json:"operation"`
	UID        int                          `json:"uid"`
	GID        int                          `json:"gid"`
	User       string                       `json:"user"`
	Home       string                       `json:"home"`
	Standalone bool                         `json:"standalone"`
	Targets    []enterpriseHookWorkerTarget `json:"targets,omitempty"`
	Connectors []string                     `json:"connectors,omitempty"`
	// ForeignCleanup asks the worker to remove unapproved foreign hooks
	// from the user's own vendor config (foreign_cleanup operation).
	ForeignCleanup []enterpriseHookWorkerForeignCleanup `json:"foreign_cleanup,omitempty"`
	// TightenHome asks the worker to remove group/other write from the
	// user's own home before an apply, so an enrolled user cannot stop
	// repair of their hooks by loosening their home's mode.
	TightenHome bool `json:"tighten_home,omitempty"`
	// StaticDiscovery restricts the discover operation to package metadata
	// and the presence of the agent CLIs, executing nothing: the parent
	// asks for it in a home other users may have written to.
	StaticDiscovery bool `json:"static_discovery,omitempty"`
	// AIDiscovery carries the settings and signature catalog of the
	// ai_discovery operation; the worker cannot read the managed config.
	AIDiscovery *enterpriseHookWorkerAIDiscovery `json:"ai_discovery,omitempty"`
	// CopilotVSCode asks the worker to place or remove DefenseClaw's VS
	// Code Local hook file and Copilot plugin in the user's own home (the
	// foreign_cleanup worker does either; remove-all's apply worker only
	// removes).
	CopilotVSCode *enterpriseHookWorkerCopilotVSCode `json:"copilot_vscode,omitempty"`
}

// enterpriseHookWorkerCopilotVSCode is what the user's home should hold
// for the VS Code Local harness; the parent resolves it from the
// administrator's config.
type enterpriseHookWorkerCopilotVSCode struct {
	HookBinary string `json:"hook_binary"`
	HookFile   bool   `json:"hook_file"`
	Plugin     bool   `json:"plugin"`
}

// enterpriseHookWorkerCopilotVSCodeReport is the worker's account of it
// (user-influenced; only logged).
type enterpriseHookWorkerCopilotVSCodeReport struct {
	Changed []string `json:"changed,omitempty"`
	Removed []string `json:"removed,omitempty"`
	Kept    []string `json:"kept,omitempty"`
	Error   string   `json:"error,omitempty"`
}

type enterpriseHookWorkerAIDiscovery struct {
	Options inventory.UserScanOptions `json:"options"`
	Catalog []inventory.AISignature   `json:"catalog"`
}

// enterpriseHookWorkerForeignCleanup is one connector's foreign-hook
// cleanup; the parent resolves the policy from the administrator's config,
// which the worker cannot read.
type enterpriseHookWorkerForeignCleanup struct {
	Connector     string                                 `json:"connector"`
	HookBinary    string                                 `json:"hook_binary"`
	Policy        enterprisepolicy.PublicConnectorPolicy `json:"policy"`
	OwnedCommands []string                               `json:"owned_commands,omitempty"`
}

// enterpriseHookWorkerCleanupReport summarizes one connector's cleanup.
// It is user-influenced and only logged.
type enterpriseHookWorkerCleanupReport struct {
	Removed   []string `json:"removed,omitempty"`
	Reported  []string `json:"reported,omitempty"`
	BackupDir string   `json:"backup_dir,omitempty"`
	Error     string   `json:"error,omitempty"`
}

type enterpriseHookWorkerTargetResult struct {
	Index    int                            `json:"index"`
	OK       bool                           `json:"ok"`
	Repaired bool                           `json:"repaired,omitempty"`
	Removed  bool                           `json:"removed,omitempty"`
	Pending  bool                           `json:"pending,omitempty"`
	Error    string                         `json:"error,omitempty"`
	Result   *enterprisehooks.InstallResult `json:"result,omitempty"`
}

type enterpriseHookWorkerResponse struct {
	Version  int                                `json:"version"`
	Targets  []enterpriseHookWorkerTargetResult `json:"targets,omitempty"`
	Versions map[string]string                  `json:"versions,omitempty"`
	Reasons  map[string]string                  `json:"reasons,omitempty"`
	// Surfaces are the discovered app and extension installs per connector
	// (user-influenced; the parent validates them).
	Surfaces map[string][]connector.AgentSurface          `json:"surfaces,omitempty"`
	Cleanup  map[string]enterpriseHookWorkerCleanupReport `json:"cleanup,omitempty"`
	// Blocks are the foreign-hook blocks the user's hooks recorded since
	// the last cleanup (user-influenced; only logged).
	Blocks        []enterprisepolicy.BlockSummary `json:"blocks,omitempty"`
	BlocksDropped int                             `json:"blocks_dropped,omitempty"`
	BlocksError   string                          `json:"blocks_error,omitempty"`
	// AIDiscovery is the user's scan report (user-influenced; the guardian
	// validates it before the gateway reads it).
	AIDiscovery *inventory.AIDiscoveryReport `json:"ai_discovery,omitempty"`
	// CopilotVSCode reports the VS Code Local hook file and plugin.
	CopilotVSCode *enterpriseHookWorkerCopilotVSCodeReport `json:"copilot_vscode,omitempty"`
	Error         string                                   `json:"error,omitempty"`
}

// enterpriseHookWorkerAccount is the resolved target the parent spawns
// a worker for.
type enterpriseHookWorkerAccount struct {
	UID  int
	GID  int
	User string
	Home string
}

var enterpriseHooksApplyTargetCmd = &cobra.Command{
	Use:    "apply-target",
	Short:  "Internal: apply or verify hooks for one user with that user's credentials",
	Hidden: true,
	Args:   cobra.NoArgs,
	// The worker runs as the target user, who cannot read the managed
	// config; it receives everything it needs on stdin.
	Annotations: map[string]string{"defenseclaw.skip-daemon-bootstrap": "true"},
	RunE: func(cmd *cobra.Command, _ []string) error {
		// The parent kills the worker's session on timeout, but macOS has
		// no parent-death signal: never outlive the parent's deadline.
		time.AfterFunc(enterpriseHookWorkerTimeout+5*time.Second, func() { os.Exit(5) })
		if code := enterpriseHookWorkerMain(cmd.Context(), cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr()); code != 0 {
			return fmt.Errorf("enterprise hooks apply-target: worker failed (exit %d)", code)
		}
		return nil
	},
}

func init() {
	enterpriseHooksCmd.AddCommand(enterpriseHooksApplyTargetCmd)
}

// enterpriseHookWorkerMain is the worker process body. It returns a process
// exit code; per-target failures are reported in the response, not as a
// non-zero exit.
func enterpriseHookWorkerMain(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer) int {
	if ctx == nil {
		ctx = context.Background()
	}
	respond := func(response enterpriseHookWorkerResponse, code int) int {
		response.Version = enterpriseHookWorkerProtocolVersion
		if err := json.NewEncoder(stdout).Encode(response); err != nil {
			fmt.Fprintf(stderr, "apply-target: write response: %v\n", err)
			return 2
		}
		return code
	}
	data, err := io.ReadAll(io.LimitReader(stdin, enterpriseHookWorkerRequestLimit+1))
	if err != nil || len(data) > enterpriseHookWorkerRequestLimit {
		return respond(enterpriseHookWorkerResponse{Error: "request is unreadable or too large"}, 3)
	}
	var request enterpriseHookWorkerRequest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return respond(enterpriseHookWorkerResponse{Error: "request is not valid JSON: " + err.Error()}, 3)
	}
	if err := validateEnterpriseHookWorkerIdentity(request); err != nil {
		return respond(enterpriseHookWorkerResponse{Error: err.Error()}, 4)
	}
	hardenEnterpriseHookWorkerProcess()
	applyEnterpriseHookWorkerLimits()
	enterprisehooks.SetStandaloneUnix(request.Standalone)
	switch request.Operation {
	case enterpriseHookWorkerOpApply:
		response := runEnterpriseHookWorkerApply(ctx, request)
		if request.CopilotVSCode != nil {
			// remove-all: the VS Code Local file and plugin go with the
			// registrations.
			response.CopilotVSCode = runEnterpriseHookWorkerCopilotVSCode(request)
		}
		return respond(response, 0)
	case enterpriseHookWorkerOpDiscover:
		versions := map[string]string{}
		reasons := map[string]string{}
		surfaces := map[string][]connector.AgentSurface{}
		for _, name := range request.Connectors {
			name = strings.ToLower(strings.TrimSpace(name))
			if name == "" {
				continue
			}
			var version, reason string
			if request.StaticDiscovery {
				version, reason = enterpriseHookWorkerDiscoverStaticVersion(ctx, request.Home, name)
			} else {
				version, reason = enterpriseHookWorkerDiscoverVersion(ctx, request.Home, name, true)
			}
			if version != "" {
				versions[name] = version
			} else if reason != "" {
				reasons[name] = reason
			}
			// Host apps are never run; an engine CLI bundled in one is run
			// only outside a static (untrusted-home) discovery.
			if found := enterpriseHookWorkerDiscoverSurfaces(ctx, request.Home, name, !request.StaticDiscovery); len(found) != 0 {
				surfaces[name] = found
			}
			if name == "kiro" {
				// The Kiro IDE is read, never run, so static discovery reads it too.
				if ide, _ := enterpriseHookWorkerDiscoverKiroIDE(request.Home); ide != "" {
					versions[enterprisehooks.KiroIDEDiscoveryKey] = ide
				}
			}
		}
		return respond(enterpriseHookWorkerResponse{Versions: versions, Reasons: reasons, Surfaces: surfaces}, 0)
	case enterpriseHookWorkerOpForeignCleanup:
		for _, target := range request.Targets {
			if target.Mode != enterpriseHookWorkerModeRemoveLeftover {
				return respond(enterpriseHookWorkerResponse{Error: fmt.Sprintf("the foreign cleanup does not take mode %q", target.Mode)}, 3)
			}
		}
		now := time.Now()
		response := enterpriseHookWorkerResponse{Cleanup: runEnterpriseHookWorkerForeignCleanup(request, now)}
		if request.CopilotVSCode != nil {
			response.CopilotVSCode = runEnterpriseHookWorkerCopilotVSCode(request)
		}
		if len(request.Targets) > 0 {
			response.Targets = runEnterpriseHookWorkerApply(ctx, request).Targets
		}
		blocks, dropped, err := enterprisepolicy.CollectForeignHookBlocks(filepath.Clean(request.Home), now)
		response.Blocks, response.BlocksDropped = blocks, dropped
		if err != nil {
			response.BlocksError = err.Error()
		}
		return respond(response, 0)
	case enterpriseHookWorkerOpAIDiscovery:
		if request.AIDiscovery == nil {
			return respond(enterpriseHookWorkerResponse{Error: "the ai_discovery operation needs its scan settings"}, 3)
		}
		// End with a partial report rather than be killed at the timeout.
		scanCtx, cancel := context.WithTimeout(ctx, enterpriseHookWorkerTimeout*3/4)
		defer cancel()
		report := inventory.ScanUserHome(scanCtx, filepath.Clean(request.Home), request.User, request.UID,
			request.AIDiscovery.Options, request.AIDiscovery.Catalog)
		return respond(enterpriseHookWorkerResponse{AIDiscovery: &report}, 0)
	default:
		return respond(enterpriseHookWorkerResponse{Error: fmt.Sprintf("unknown operation %q", request.Operation)}, 3)
	}
}

// enterpriseHookWorkerDiscoverVersion,
// enterpriseHookWorkerDiscoverStaticVersion,
// enterpriseHookWorkerDiscoverSurfaces and
// enterpriseHookWorkerDiscoverKiroIDE are replaceable in tests.
var (
	enterpriseHookWorkerDiscoverVersion       = enterprisehooks.DiscoverUnixAgentVersion
	enterpriseHookWorkerDiscoverStaticVersion = enterprisehooks.DiscoverUnixAgentVersionStatically
	enterpriseHookWorkerDiscoverSurfaces      = enterprisehooks.DiscoverUnixAgentSurfaces
	enterpriseHookWorkerDiscoverKiroIDE       = enterprisehooks.DiscoverUnixKiroIDEVersion
)

func validateEnterpriseHookWorkerIdentity(request enterpriseHookWorkerRequest) error {
	if request.Version != enterpriseHookWorkerProtocolVersion {
		return fmt.Errorf("unsupported worker protocol version %d", request.Version)
	}
	if request.UID <= 0 || request.GID < 0 {
		return fmt.Errorf("worker refuses uid %d gid %d", request.UID, request.GID)
	}
	if os.Getuid() != request.UID || os.Geteuid() != request.UID ||
		os.Getgid() != request.GID || os.Getegid() != request.GID {
		return fmt.Errorf("worker runs as uid=%d/%d gid=%d/%d, want the target uid=%d gid=%d",
			os.Getuid(), os.Geteuid(), os.Getgid(), os.Getegid(), request.UID, request.GID)
	}
	home := filepath.Clean(strings.TrimSpace(request.Home))
	if !filepath.IsAbs(home) || home == "/" {
		return fmt.Errorf("worker home %q is not an absolute user home", request.Home)
	}
	for _, target := range request.Targets {
		if target.Options.OwnerUID != request.UID || target.Options.OwnerGID != request.GID ||
			filepath.Clean(target.Options.UserHome) != home {
			return fmt.Errorf("worker target %d does not belong to uid %d and home %s", target.Index, request.UID, home)
		}
	}
	return nil
}

// applyEnterpriseHookWorkerLimits drops core dumps (the request carries
// scoped tokens) and bounds files and descriptors the worker can create.
func applyEnterpriseHookWorkerLimits() {
	_ = syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0})
	lowerRlimit(syscall.RLIMIT_FSIZE, 256<<20)
	lowerRlimit(syscall.RLIMIT_NOFILE, 1024)
}

func lowerRlimit(resource int, limit uint64) {
	var current syscall.Rlimit
	if err := syscall.Getrlimit(resource, &current); err != nil {
		return
	}
	if current.Cur > limit || current.Cur == ^uint64(0) {
		current.Cur = limit
	}
	if current.Max > limit || current.Max == ^uint64(0) {
		current.Max = limit
	}
	_ = syscall.Setrlimit(resource, &current)
}

// enterpriseHookWorkerInstaller/Verifier are replaceable in tests.
var (
	enterpriseHookWorkerInstaller = enterprisehooks.Install
	enterpriseHookWorkerVerifier  = enterprisehooks.Verify
	enterpriseHookWorkerRemover   = enterprisehooks.RemoveUserHooks
	enterpriseHookWorkerPurger    = enterprisehooks.PurgeUserState
	// enterpriseHookWorkerStopPerUser stops the account's per-user gateway
	// and watchdog before the purge removes the state they run from.
	enterpriseHookWorkerStopPerUser = stopPerUserGatewayForPurge
)

func runEnterpriseHookWorkerApply(ctx context.Context, request enterpriseHookWorkerRequest) enterpriseHookWorkerResponse {
	registry := connector.NewDefaultRegistry()
	results := make([]enterpriseHookWorkerTargetResult, 0, len(request.Targets))
	if request.TightenHome {
		if err := tightenEnterpriseHookWorkerHome(request.Home, request.UID); err != nil {
			for _, target := range request.Targets {
				results = append(results, enterpriseHookWorkerTargetResult{Index: target.Index, Error: err.Error()})
			}
			return enterpriseHookWorkerResponse{Targets: results}
		}
	}
	removalFailed := false
	for _, target := range request.Targets {
		opts := target.Options.installOptions(registry)
		outcome := enterpriseHookWorkerTargetResult{Index: target.Index}
		var result enterprisehooks.InstallResult
		var err error
		switch target.Mode {
		case enterpriseHookWorkerModeInstall:
			result, err = enterpriseHookWorkerInstaller(ctx, opts)
		case enterpriseHookWorkerModeVerify:
			result, err = enterpriseHookWorkerVerifier(ctx, opts)
		case enterpriseHookWorkerModeVerifyOrRepair:
			if !target.PreviouslyProtected {
				result, err = enterpriseHookWorkerInstaller(ctx, opts)
				break
			}
			result, err = enterpriseHookWorkerVerifier(ctx, opts)
			if err != nil {
				result, err = enterpriseHookWorkerInstaller(ctx, opts)
				outcome.Repaired = err == nil
			}
		case enterpriseHookWorkerModeRemove:
			err = enterpriseHookWorkerRemover(ctx, opts)
		case enterpriseHookWorkerModeRemoveLeftover:
			var leftover bool
			if leftover, err = enterpriseHookWorkerManagedRegistration(opts); err == nil && leftover {
				err = enterpriseHookWorkerRemover(ctx, opts)
				outcome.Removed = err == nil
			}
		case enterpriseHookWorkerModePurge:
			if removalFailed {
				err = errors.New("a DefenseClaw hook registration of this account was not removed")
				break
			}
			if err = enterpriseHookWorkerStopPerUser(opts); err != nil {
				break
			}
			err = enterpriseHookWorkerPurger(ctx, opts)
		default:
			err = fmt.Errorf("unknown worker mode %q", target.Mode)
		}
		if err != nil {
			// Pending only when the home itself went away mid-operation;
			// a missing file inside an available home is a failure.
			outcome.Pending = enterprisehooks.PendingTargetError(err) &&
				enterprisehooks.CheckUnixTargetHome(request.Home, request.UID).State == enterprisehooks.HomePending
			if !outcome.Pending {
				outcome.Error = err.Error()
			}
			removalFailed = removalFailed || target.Mode == enterpriseHookWorkerModeRemove || target.Mode == enterpriseHookWorkerModeRemoveLeftover
		} else {
			outcome.OK = true
			if target.Mode != enterpriseHookWorkerModeRemove && target.Mode != enterpriseHookWorkerModeRemoveLeftover && target.Mode != enterpriseHookWorkerModePurge {
				outcome.Result = &result
			}
		}
		results = append(results, outcome)
	}
	return enterpriseHookWorkerResponse{Targets: results}
}

// enterpriseHookWorkerManagedRegistration reports whether the user's hook
// contract lock records the guardian's registration of the connector: one
// rendered for the standalone hook socket. A personal DefenseClaw install
// in the same home records none and is left alone.
func enterpriseHookWorkerManagedRegistration(opts enterprisehooks.InstallOptions) (bool, error) {
	dataDir := strings.TrimSpace(opts.DataDir)
	if dataDir == "" {
		dataDir = filepath.Join(opts.UserHome, ".defenseclaw")
	}
	entry, err := connector.LoadHookContractLockEntryForMode(dataDir, opts.ConnectorName, true)
	if err != nil {
		return false, err
	}
	posture := entry.RegistrationPosture
	return posture != nil && posture.ManagedEnterprise && strings.TrimSpace(posture.HookSocket) != "", nil
}

// tightenEnterpriseHookWorkerHome removes group/other write from the
// worker user's own home. It runs as that user (an owner may chmod their
// home) through a no-follow directory handle, so a swapped path or a home
// that is not the user's own is refused rather than changed.
func tightenEnterpriseHookWorkerHome(home string, uid int) error {
	fd, err := syscall.Open(home, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("enterprise hooks: open user home %s to remove group/other write: %w", home, err)
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return fmt.Errorf("enterprise hooks: inspect user home %s: %w", home, err)
	}
	if uint32(st.Mode)&syscall.S_IFMT != syscall.S_IFDIR || int(st.Uid) != uid {
		return fmt.Errorf("enterprise hooks: user home %s is not a directory owned by uid %d", home, uid)
	}
	mode := uint32(st.Mode) & 0o7777
	if mode&0o022 == 0 {
		return nil
	}
	if err := syscall.Fchmod(fd, mode&^0o022); err != nil {
		return fmt.Errorf("enterprise hooks: remove group/other write from user home %s: %w", home, err)
	}
	return nil
}

func (o enterpriseHookWorkerOptions) installOptions(registry *connector.Registry) enterprisehooks.InstallOptions {
	return enterprisehooks.InstallOptions{
		ConnectorName:                      o.ConnectorName,
		UserHome:                           o.UserHome,
		OwnerUID:                           o.OwnerUID,
		OwnerGID:                           o.OwnerGID,
		DataDir:                            o.DataDir,
		APIAddr:                            o.APIAddr,
		ProxyAddr:                          o.ProxyAddr,
		APIToken:                           o.APIToken,
		OTLPPathToken:                      o.OTLPPathToken,
		HookFailMode:                       o.HookFailMode,
		GuardrailMode:                      o.GuardrailMode,
		HILTEnabled:                        o.HILTEnabled,
		AgentVersion:                       o.AgentVersion,
		HookContractID:                     o.HookContractID,
		WorkspaceDir:                       o.WorkspaceDir,
		Registry:                           registry,
		AllowMissingHookConfigRepair:       o.AllowMissingHookConfigRepair,
		RecoveryHookContractLockUpdatedAt:  o.RecoveryHookContractLockUpdatedAt,
		RecoveryHookContractEntryUpdatedAt: o.RecoveryHookContractEntryUpdatedAt,
		ManagedHookSocket:                  o.ManagedHookSocket,
		ManagedServiceUID:                  o.ManagedServiceUID,
		HookCredentialIdentity:             o.HookCredentialIdentity,
		ForeignHookGuardBinary:             o.ForeignHookGuardBinary,
	}
}

func enterpriseHookWorkerOptionsFrom(opts enterprisehooks.InstallOptions) enterpriseHookWorkerOptions {
	return enterpriseHookWorkerOptions{
		ConnectorName:                      opts.ConnectorName,
		UserHome:                           opts.UserHome,
		OwnerUID:                           opts.OwnerUID,
		OwnerGID:                           opts.OwnerGID,
		DataDir:                            opts.DataDir,
		APIAddr:                            opts.APIAddr,
		ProxyAddr:                          opts.ProxyAddr,
		APIToken:                           opts.APIToken,
		OTLPPathToken:                      opts.OTLPPathToken,
		HookFailMode:                       opts.HookFailMode,
		GuardrailMode:                      opts.GuardrailMode,
		HILTEnabled:                        opts.HILTEnabled,
		AgentVersion:                       opts.AgentVersion,
		HookContractID:                     opts.HookContractID,
		WorkspaceDir:                       opts.WorkspaceDir,
		AllowMissingHookConfigRepair:       opts.AllowMissingHookConfigRepair,
		RecoveryHookContractLockUpdatedAt:  opts.RecoveryHookContractLockUpdatedAt,
		RecoveryHookContractEntryUpdatedAt: opts.RecoveryHookContractEntryUpdatedAt,
		ManagedHookSocket:                  opts.ManagedHookSocket,
		ManagedServiceUID:                  opts.ManagedServiceUID,
		HookCredentialIdentity:             opts.HookCredentialIdentity,
		ForeignHookGuardBinary:             opts.ForeignHookGuardBinary,
	}
}

// Parent side.

var (
	// enterpriseHookWorkerExecutable resolves the binary the worker runs.
	enterpriseHookWorkerExecutable = defaultEnterpriseHookWorkerExecutable
	// enterpriseHookWorkerArgs are the worker's command-line arguments.
	enterpriseHookWorkerArgs = []string{"enterprise", "hooks", "apply-target"}
	// enterpriseHookWorkerExtraEnv is appended to the worker environment;
	// tests use it to select the helper process.
	enterpriseHookWorkerExtraEnv []string
	// enterpriseHookWorkerLog receives the worker's bounded stderr.
	enterpriseHookWorkerLog io.Writer = os.Stderr
)

func defaultEnterpriseHookWorkerExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve guardian executable: %w", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return "", fmt.Errorf("resolve guardian executable: %w", err)
	}
	if os.Geteuid() == 0 {
		// A root parent hands this binary to every user; it must be
		// administrator-owned so no user can substitute it.
		if err := managed.ValidateTrustedFilePath(exe, "hook guardian worker executable"); err != nil {
			return "", err
		}
	}
	return exe, nil
}

type workerOutputBuffer struct {
	buf      bytes.Buffer
	limit    int
	exceeded bool
}

func (b *workerOutputBuffer) Write(p []byte) (int, error) {
	if b.buf.Len()+len(p) > b.limit {
		b.exceeded = true
		if remaining := b.limit - b.buf.Len(); remaining > 0 {
			b.buf.Write(p[:remaining])
		}
		return len(p), nil
	}
	return b.buf.Write(p)
}

// runEnterpriseHookWorker spawns one worker for account and returns its
// decoded response.
func runEnterpriseHookWorker(
	ctx context.Context,
	account enterpriseHookWorkerAccount,
	request enterpriseHookWorkerRequest,
) (enterpriseHookWorkerResponse, error) {
	if account.UID <= 0 {
		return enterpriseHookWorkerResponse{}, fmt.Errorf("refusing a worker for uid %d", account.UID)
	}
	if os.Geteuid() != 0 && (os.Geteuid() != account.UID || os.Getegid() != account.GID) {
		return enterpriseHookWorkerResponse{}, fmt.Errorf("a non-root guardian can only run a worker for itself (uid %d)", os.Geteuid())
	}
	request.Version = enterpriseHookWorkerProtocolVersion
	request.UID, request.GID = account.UID, account.GID
	request.User, request.Home = account.User, account.Home
	payload, err := json.Marshal(request)
	if err != nil {
		return enterpriseHookWorkerResponse{}, err
	}
	exe, err := enterpriseHookWorkerExecutable()
	if err != nil {
		return enterpriseHookWorkerResponse{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, enterpriseHookWorkerTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, enterpriseHookWorkerArgs...)
	cmd.Dir = "/"
	cmd.Env = enterpriseHookWorkerEnvironment(account)
	cmd.Stdin = bytes.NewReader(payload)
	stdout := &workerOutputBuffer{limit: enterpriseHookWorkerResponseLimit}
	stderr := &workerOutputBuffer{limit: enterpriseHookWorkerStderrLimit}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	var supplementary []int
	if os.Geteuid() == 0 {
		supplementary = enterpriseHookWorkerGroupIDs(account)
	}
	cmd.SysProcAttr = enterpriseHookWorkerSysProcAttr(account, supplementary)
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// The worker leads its own session; kill the whole group so an
		// agent `--version` child cannot outlive the timeout.
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 2 * time.Second
	runErr := cmd.Run()
	forwardEnterpriseHookWorkerStderr(account, stderr)
	if ctx.Err() != nil {
		return enterpriseHookWorkerResponse{}, fmt.Errorf("worker for uid %d timed out: %w", account.UID, ctx.Err())
	}
	if stdout.exceeded {
		return enterpriseHookWorkerResponse{}, fmt.Errorf("worker for uid %d returned an oversized response", account.UID)
	}
	var response enterpriseHookWorkerResponse
	decoder := json.NewDecoder(bytes.NewReader(stdout.buf.Bytes()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		if runErr != nil {
			return enterpriseHookWorkerResponse{}, fmt.Errorf("worker for uid %d failed: %w", account.UID, runErr)
		}
		return enterpriseHookWorkerResponse{}, fmt.Errorf("worker for uid %d returned invalid JSON: %w", account.UID, err)
	}
	if response.Version != enterpriseHookWorkerProtocolVersion {
		return enterpriseHookWorkerResponse{}, fmt.Errorf("worker for uid %d speaks protocol %d", account.UID, response.Version)
	}
	if response.Error != "" {
		return response, fmt.Errorf("worker for uid %d: %s", account.UID, response.Error)
	}
	if runErr != nil {
		return response, fmt.Errorf("worker for uid %d failed: %w", account.UID, runErr)
	}
	return response, nil
}

// enterpriseHookWorkerGroupIDs resolves the account's primary and
// supplementary groups (initgroups through NSS or Directory Services), so
// discovery, install and cleanup run with the user's real rights: an agent
// under an administrator prefix readable only by a group, or a config
// reachable only through one, is otherwise invisible to the worker. When
// the directory cannot answer, the worker runs with the primary group only,
// which can only grant less. Replaceable in tests.
var enterpriseHookWorkerGroupIDs = func(account enterpriseHookWorkerAccount) []int {
	ids, err := enterprisehooks.StandaloneResolver().GroupIDs(unixidentity.Account{Name: account.User, UID: account.UID, GID: account.GID})
	if err != nil {
		if enterpriseHookWorkerLog != nil {
			fmt.Fprintf(enterpriseHookWorkerLog, "[hook-guardian] worker uid=%d: supplementary groups unavailable, using the primary group only: %v\n", account.UID, err)
		}
		return nil
	}
	return ids
}

// enterpriseHookWorkerCredential is the worker's exact identity: the
// target uid and primary gid, then the supplementary groups in order,
// without duplicates, up to the platform's group limit.
func enterpriseHookWorkerCredential(account enterpriseHookWorkerAccount, supplementary []int, limit int) *syscall.Credential {
	groups := []uint32{uint32(account.GID)}
	seen := map[int]bool{account.GID: true}
	for _, gid := range supplementary {
		if len(groups) >= limit {
			break
		}
		if gid < 0 || seen[gid] {
			continue
		}
		seen[gid] = true
		groups = append(groups, uint32(gid))
	}
	return &syscall.Credential{Uid: uint32(account.UID), Gid: uint32(account.GID), Groups: groups}
}

// enterpriseHookWorkerPath lets connector setup find an agent where
// discovery found it (OmniGent locates itself on PATH), after the system
// directories so they always win. The worker runs as the user, so the
// user-owned entries grant nothing the user does not already have; a
// standalone worker leaves out machine directories another account could
// change (enterprisehooks.UnixAgentSearchDirsFor).
func enterpriseHookWorkerPath(home string, uid int) string {
	parts := []string{"/usr/bin", "/bin"}
	seen := map[string]bool{"/usr/bin": true, "/bin": true}
	for _, dir := range enterprisehooks.UnixAgentSearchDirsFor(home, uid) {
		dir = filepath.Clean(dir)
		if seen[dir] || !filepath.IsAbs(dir) || strings.ContainsAny(dir, ":\x00") {
			continue
		}
		seen[dir] = true
		parts = append(parts, dir)
	}
	return strings.Join(parts, ":")
}

func enterpriseHookWorkerEnvironment(account enterpriseHookWorkerAccount) []string {
	env := []string{
		"HOME=" + account.Home,
		"USER=" + account.User,
		"LOGNAME=" + account.User,
		"PATH=" + enterpriseHookWorkerPath(account.Home, account.UID),
		"LANG=C",
		"LC_ALL=C",
	}
	for _, name := range enterpriseHookWorkerPassthroughEnv {
		if value, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+value)
		}
	}
	return append(env, enterpriseHookWorkerExtraEnv...)
}

func forwardEnterpriseHookWorkerStderr(account enterpriseHookWorkerAccount, stderr *workerOutputBuffer) {
	if enterpriseHookWorkerLog == nil || stderr.buf.Len() == 0 {
		return
	}
	scanner := bufio.NewScanner(bytes.NewReader(stderr.buf.Bytes()))
	scanner.Buffer(make([]byte, 0, 4096), enterpriseHookWorkerStderrLimit)
	for scanner.Scan() {
		line := strings.Map(func(r rune) rune {
			if r < 0x20 || r == 0x7f {
				return ' '
			}
			return r
		}, scanner.Text())
		fmt.Fprintf(enterpriseHookWorkerLog, "[hook-guardian] worker uid=%d: %s\n", account.UID, line)
	}
	if stderr.exceeded {
		fmt.Fprintf(enterpriseHookWorkerLog, "[hook-guardian] worker uid=%d: stderr truncated\n", account.UID)
	}
}

// enterpriseHookWorkerJob is one user's batch.
type enterpriseHookWorkerJob struct {
	Account enterpriseHookWorkerAccount
	Request enterpriseHookWorkerRequest
}

type enterpriseHookWorkerOutcome struct {
	Job      enterpriseHookWorkerJob
	Response enterpriseHookWorkerResponse
	Err      error
}

// enterpriseHookWorkerRunner is replaceable in tests.
var enterpriseHookWorkerRunner = runEnterpriseHookWorker

// runEnterpriseHookWorkerPool runs one worker per job with bounded
// parallelism and returns outcomes in job order.
func runEnterpriseHookWorkerPool(ctx context.Context, jobs []enterpriseHookWorkerJob, parallelism int) []enterpriseHookWorkerOutcome {
	return runEnterpriseHookWorkerPoolReporting(ctx, jobs, parallelism, nil)
}

// runEnterpriseHookWorkerPoolReporting is runEnterpriseHookWorkerPool that
// also hands each outcome to done, when set, as soon as its worker ends
// (concurrently with the other workers).
func runEnterpriseHookWorkerPoolReporting(ctx context.Context, jobs []enterpriseHookWorkerJob, parallelism int, done func(enterpriseHookWorkerOutcome)) []enterpriseHookWorkerOutcome {
	if parallelism <= 0 {
		parallelism = enterpriseHookWorkerParallelism
	}
	outcomes := make([]enterpriseHookWorkerOutcome, len(jobs))
	semaphore := make(chan struct{}, parallelism)
	var wg sync.WaitGroup
	for i := range jobs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			response, err := enterpriseHookWorkerRunner(ctx, jobs[i].Account, jobs[i].Request)
			outcomes[i] = enterpriseHookWorkerOutcome{Job: jobs[i], Response: response, Err: err}
			if done != nil {
				done(outcomes[i])
			}
		}(i)
	}
	wg.Wait()
	return outcomes
}

// sortedWorkerJobs returns jobs ordered by uid for deterministic logs.
func sortedWorkerJobs(byUID map[int]*enterpriseHookWorkerJob) []enterpriseHookWorkerJob {
	uids := make([]int, 0, len(byUID))
	for uid := range byUID {
		uids = append(uids, uid)
	}
	sort.Ints(uids)
	jobs := make([]enterpriseHookWorkerJob, 0, len(uids))
	for _, uid := range uids {
		jobs = append(jobs, *byUID[uid])
	}
	return jobs
}

var errEnterpriseHookWorkerNoResult = errors.New("worker returned no result for this target")
