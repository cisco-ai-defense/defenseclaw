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
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/hermespath"
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
	// Remove reports are optional fields of this version. A mixed-version
	// guardian rejects unknown fields or treats an absent report as unverified.
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
	enterpriseHookWorkerModeRemoveLeftover      = "remove_leftover"
	enterpriseHookWorkerModeBlockPersonalClaude = "block_personal_claude"
	// enterpriseHookWorkerModeUnblockPersonalClaude removes the
	// enrollment's Claude Code blocker (standalone uninstall, every
	// account; enterprisehooks.RemovePersonalClaudeHookBlocker).
	enterpriseHookWorkerModeUnblockPersonalClaude     = "unblock_personal_claude"
	enterpriseHookWorkerModeRepairManagedCodexFeature = "repair_managed_codex_feature"
	// enterpriseHookWorkerModeRemoveUserNativeOTLP removes, as the user, a
	// native OTLP exporter in the user's own Codex or Claude Code
	// configuration that carries a DefenseClaw credential (GAP-2376).
	enterpriseHookWorkerModeRemoveUserNativeOTLP = "remove_user_native_otlp"
	// enterpriseHookWorkerModePurge removes the user's DefenseClaw per-user
	// state (standalone uninstall --purge). It runs after the request's
	// removals and only when every one of them succeeded: the state holds
	// the backups a failed removal needs when it is retried.
	enterpriseHookWorkerModePurge = "purge"
)

// enterpriseHookWorkerForeignCleanupModes are the target modes a
// foreign_cleanup worker takes: every mode the guardian's foreign cleanup
// gives an account's job (runEnterpriseHookStandaloneForeignCleanup). A mode
// missing here refuses the whole job, its foreign-hook removals and VS Code
// Local files included (R3-1).
var enterpriseHookWorkerForeignCleanupModes = map[string]bool{
	enterpriseHookWorkerModeRemoveLeftover:        true,
	enterpriseHookWorkerModeBlockPersonalClaude:   true,
	enterpriseHookWorkerModeUnblockPersonalClaude: true,
	enterpriseHookWorkerModeRemoveUserNativeOTLP:  true,
}

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
	ManagedHookBinary                  string `json:"managed_hook_binary,omitempty"`
	// ProductCredentials are the digests of the product credentials a
	// remove_user_native_otlp target knows an exporter by; the credentials
	// themselves never reach a process that runs as the user.
	ProductCredentials []connector.NativeOTLPCredentialDigest `json:"product_credentials,omitempty"`
	// PreviousHome is the recorded home of a re-homed account whose current
	// home a Remove cleans. Receipts copied from it act on this home's copy
	// of the file, never on the other home (rel-1-0-3 GAP-0200).
	PreviousHome string `json:"previous_home,omitempty"`
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
	// RecheckMillis keeps the verify_or_repair targets that verified under
	// check for this long, all at the same time
	// (recheckEnterpriseHookTargetsOverWindow).
	RecheckMillis int `json:"recheck_ms,omitempty"`
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
	// TimeoutSeconds replaces enterpriseHookWorkerTimeout for this worker
	// (remove-all's retry of a worker that timed out).
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
	// CleanupFence tells a foreign_cleanup worker that the guardian passed
	// the cleanup fence pipes (enterprise_hooks_worker_fence_unix.go). The
	// guardian sets it from cleanupFence.
	CleanupFence bool `json:"cleanup_fence,omitempty"`
	// LaunchdHermesHome is HERMES_HOME of the account's launchd user domain
	// as the root guardian read it on macOS: the worker runs in the system
	// bootstrap and cannot read that domain itself (GAP-2374). Unset when
	// the guardian could not read it; the worker then reads its own domain.
	LaunchdHermesHome *string `json:"launchd_hermes_home,omitempty"`
	// cleanupFence is the guardian's side of those pipes; it never leaves
	// the guardian.
	cleanupFence *enterpriseForeignHookFenceSession
}

// enterpriseHookWorkerCopilotVSCode is what the user's home should hold
// for the VS Code Local harness; the parent resolves it from the
// administrator's config.
type enterpriseHookWorkerCopilotVSCode struct {
	HookBinary string `json:"hook_binary"`
	HookFile   bool   `json:"hook_file"`
	Plugin     bool   `json:"plugin"`
	// RemoveDirs are the folders the guardian created in the home for
	// these files (from its record); each still empty afterwards goes.
	RemoveDirs []string `json:"remove_dirs,omitempty"`
}

// enterpriseHookWorkerCopilotVSCodeReport is the worker's account of it
// (user-influenced; only logged).
type enterpriseHookWorkerCopilotVSCodeReport struct {
	Changed []string `json:"changed,omitempty"`
	Removed []string `json:"removed,omitempty"`
	Kept    []string `json:"kept,omitempty"`
	// Created are the folders the write created in the home; the parent
	// records them (only below the home) for the removal.
	Created []string `json:"created,omitempty"`
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
	// AgentConfig is the result's connector.AgentConfigStatus code (a
	// Hermes or Devin config put back or recreated, GAP-0564). It is kept
	// out of the result, which the guardian state stores.
	AgentConfig string `json:"agent_config,omitempty"`
	// Purged is what a purge target found and removed (booleans only, so
	// nothing the account controls reaches the administrator's output).
	Purged *enterpriseHookPurgeDetail `json:"purged,omitempty"`
	// Remove reports are produced as the account, before and after teardown.
	// Presence distinguishes an empty path set from an older worker response.
	CleanedPaths  []string `json:"cleaned_paths,omitempty"`
	PathsReported bool     `json:"paths_reported,omitempty"`
	Remaining     string   `json:"remaining,omitempty"`
	Unverified    string   `json:"unverified,omitempty"`
}

// enterpriseHookPurgeDetail is what uninstall --purge removed for one
// account: its ~/.defenseclaw, its per-user binaries and launcher links in
// ~/.local/bin, and whether it stopped a running per-user gateway first.
// Kept says ~/.defenseclaw holds the account's own per-user install, which
// the purge left as it is (GAP-0727).
type enterpriseHookPurgeDetail struct {
	Data     bool `json:"data,omitempty"`
	Kept     bool `json:"kept,omitempty"`
	Binaries bool `json:"binaries,omitempty"`
	Gateway  bool `json:"gateway,omitempty"`
	UVCache  bool `json:"uv_cache,omitempty"`
	// RemovedConnectorBackups names the folders the OpenHands/OmniGent
	// backups were moved to, comma separated (GAP-2015).
	RemovedConnectorBackups string `json:"removed_connector_backups,omitempty"`
}

type enterpriseHookWorkerResponse struct {
	Version  int                                `json:"version"`
	Targets  []enterpriseHookWorkerTargetResult `json:"targets,omitempty"`
	Versions map[string]string                  `json:"versions,omitempty"`
	Reasons  map[string]string                  `json:"reasons,omitempty"`
	// Surfaces are the discovered app and extension installs per connector
	// (user-influenced; the parent validates them).
	Surfaces        map[string][]connector.AgentSurface          `json:"surfaces,omitempty"`
	PrivateInstalls []enterprisehooks.PrivateAgentInstall        `json:"private_installs,omitempty"`
	Cleanup         map[string]enterpriseHookWorkerCleanupReport `json:"cleanup,omitempty"`
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
		enterpriseHookWorkerSelfDeadline = time.AfterFunc(enterpriseHookWorkerTimeout+5*time.Second, func() { os.Exit(5) })
		if code := enterpriseHookWorkerMain(cmd.Context(), cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr()); code != 0 {
			return fmt.Errorf("enterprise hooks apply-target: worker failed (exit %d)", code)
		}
		return nil
	},
}

// enterpriseHookWorkerSelfDeadline is the worker process's own deadline; a
// request with a longer timeout moves it.
var enterpriseHookWorkerSelfDeadline *time.Timer

// enterpriseHookWorkerRetryTimeout bounds remove-all's single retry of a
// worker that timed out: deleting a large ~/.defenseclaw on cold storage
// (the first purge after a reboot) can outlast enterpriseHookWorkerTimeout.
var enterpriseHookWorkerRetryTimeout = 5 * time.Minute

func init() {
	enterpriseHooksCmd.AddCommand(enterpriseHooksApplyTargetCmd)
}

// workerTimeout is the timeout of one worker for request.
func workerTimeout(request enterpriseHookWorkerRequest) time.Duration {
	if request.TimeoutSeconds > 0 {
		return time.Duration(request.TimeoutSeconds) * time.Second
	}
	return enterpriseHookWorkerTimeout
}

// retryTimedOutWorkers runs once more, with enterpriseHookWorkerRetryTimeout,
// every worker in runs that timed out. A purge stopped with
// per_user_hooks_remaining for two accounts whose workers timed out, and
// named no cause (GAP-0517). A worker that times out again says what
// usually holds it up.
func retryTimedOutWorkers(ctx context.Context, runs []enterpriseHookWorkerOutcome) []enterpriseHookWorkerOutcome {
	var retry []enterpriseHookWorkerJob
	var at []int
	for i, run := range runs {
		if run.Err == nil || !errors.Is(run.Err, context.DeadlineExceeded) || ctx.Err() != nil {
			continue
		}
		job := run.Job
		job.Request.TimeoutSeconds = int(enterpriseHookWorkerRetryTimeout / time.Second)
		retry, at = append(retry, job), append(at, i)
	}
	for n, run := range runEnterpriseHookWorkerPool(ctx, retry, enterpriseHookWorkerParallelism) {
		if run.Err != nil && errors.Is(run.Err, context.DeadlineExceeded) {
			run.Err = fmt.Errorf("%w, also when retried with %s: the home may be on slow or unavailable storage, the account's ~/.defenseclaw may be very large, or a process running as %s may hold its files; rerun once the account is idle",
				run.Err, enterpriseHookWorkerRetryTimeout, run.Job.Account.User)
		}
		runs[at[n]] = run
	}
	return runs
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
	if request.TimeoutSeconds > 0 && enterpriseHookWorkerSelfDeadline != nil {
		enterpriseHookWorkerSelfDeadline.Reset(workerTimeout(request) + 5*time.Second)
	}
	if err := validateEnterpriseHookWorkerIdentity(request); err != nil {
		return respond(enterpriseHookWorkerResponse{Error: err.Error()}, 4)
	}
	if request.LaunchdHermesHome != nil {
		hermespath.UseParentLaunchdHermesHome(request.UID, *request.LaunchdHermesHome)
	}
	hardenEnterpriseHookWorkerProcess()
	applyEnterpriseHookWorkerLimits()
	enterprisehooks.SetStandaloneUnix(request.Standalone)
	switch request.Operation {
	case enterpriseHookWorkerOpApply:
		// remove-all: the VS Code Local file and plugin go with the
		// registrations, first, so a purge target finds the folders
		// DefenseClaw created for them empty and removes them too.
		var vscode *enterpriseHookWorkerCopilotVSCodeReport
		if request.CopilotVSCode != nil {
			vscode = runEnterpriseHookWorkerCopilotVSCode(request)
		}
		response := runEnterpriseHookWorkerApply(ctx, request)
		response.CopilotVSCode = vscode
		return respond(response, 0)
	case enterpriseHookWorkerOpDiscover:
		// The parent can only kill a worker whose request outlives its
		// deadline. Give discovery its own deadline so the private-home
		// walk can return an incomplete result while there is still time
		// to write the response.
		scanCtx, cancel := context.WithTimeout(ctx, workerTimeout(request)*3/4)
		defer cancel()
		return respond(enterpriseHookWorkerDiscoverWithin(scanCtx, request), 0)
	case enterpriseHookWorkerOpForeignCleanup:
		for _, target := range request.Targets {
			if !enterpriseHookWorkerForeignCleanupModes[target.Mode] {
				return respond(enterpriseHookWorkerResponse{Error: fmt.Sprintf("the foreign cleanup does not take mode %q", target.Mode)}, 3)
			}
		}
		var fence enterpriseForeignHookCleanupFence
		if request.CleanupFence {
			pipe, err := openEnterpriseHookWorkerFencePipe()
			if err != nil {
				return respond(enterpriseHookWorkerResponse{Error: err.Error()}, 3)
			}
			fence = pipe
		}
		now := time.Now()
		response := enterpriseHookWorkerResponse{Cleanup: runEnterpriseHookWorkerForeignCleanup(request, now, fence)}
		if request.CopilotVSCode != nil {
			response.CopilotVSCode = runEnterpriseHookWorkerCopilotVSCode(request)
		}
		if len(request.Targets) > 0 {
			response.Targets = runEnterpriseHookWorkerApply(ctx, request).Targets
		} else {
			removeRetiredConnectorsForAccount(ctx, request)
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
		limitEnterpriseHookScanWorkerMemory()
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
	enterpriseHookWorkerDiscoverVersion         = enterprisehooks.DiscoverUnixAgentVersion
	enterpriseHookWorkerDiscoverStaticVersion   = enterprisehooks.DiscoverUnixAgentVersionStatically
	enterpriseHookWorkerDiscoverSurfaces        = enterprisehooks.DiscoverUnixAgentSurfaces
	enterpriseHookWorkerDiscoverKiroIDE         = enterprisehooks.DiscoverUnixKiroIDEForms
	enterpriseHookWorkerDiscoverPrivateInstalls = enterprisehooks.DiscoverUnixPrivateAgentInstalls
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

// enterpriseHookScanWorkerMemoryLimit is the memory ceiling of a per-user
// scan worker. The scan's own bounds keep it far below; a home that defeats
// them ends that user's worker, never the host (GAP-0694: one worker grew to
// 14.7 GB and the kernel's OOM killer took other services down with it).
const enterpriseHookScanWorkerMemoryLimit = 1 << 30

// limitEnterpriseHookScanWorkerMemory caps the scan worker's data segment,
// which on Linux counts the Go heap, so an allocation past the ceiling ends
// the worker with an out-of-memory error. The soft Go limit makes the
// collector work harder before that. The scan runs only ps, which inherits
// the ceiling and stays far below it.
func limitEnterpriseHookScanWorkerMemory() {
	debug.SetMemoryLimit(enterpriseHookScanWorkerMemoryLimit * 3 / 4)
	lowerRlimit(syscall.RLIMIT_DATA, enterpriseHookScanWorkerMemoryLimit)
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
	// purgeBlocked names why a purge in this job must keep the account's
	// state: a Remove before it failed, left a DefenseClaw entry the agent
	// still loads, or could not be checked. The purge deletes the backups and
	// receipts a later cleanup needs to restore those files (GAP-0632).
	purgeBlocked := ""
	recheckWindow := time.Duration(request.RecheckMillis) * time.Millisecond
	var rechecks []enterpriseHookWorkerRecheck
	var recheckedAt []time.Time
	removeRetiredConnectorsForAccount(ctx, request)
	for _, target := range request.Targets {
		opts := target.Options.installOptions(registry)
		outcome := enterpriseHookWorkerTargetResult{Index: target.Index}
		if request.Standalone && connector.IsRemovedConnector(opts.ConnectorName) &&
			(target.Mode == enterpriseHookWorkerModeRemove || target.Mode == enterpriseHookWorkerModeRemoveLeftover) {
			// until 1.1: removeRetiredConnectorsForAccount above already ran
			// this connector's teardown for the account, and the registry no
			// longer resolves it, so its removal is done here and never keeps
			// the purge back (GAP-1915).
			outcome.OK = true
			outcome.PathsReported = target.Mode == enterpriseHookWorkerModeRemove
			results = append(results, outcome)
			continue
		}
		var result enterprisehooks.InstallResult
		var err error
		recheck := false
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
			recheck = err == nil && recheckWindow > 0
			if err != nil {
				result, err = enterpriseHookWorkerInstaller(ctx, opts)
				outcome.Repaired = err == nil
			}
		case enterpriseHookWorkerModeRemove:
			previousHome := strings.TrimSpace(target.Options.PreviousHome)
			if previousHome != "" && (!filepath.IsAbs(previousHome) || filepath.Clean(previousHome) != previousHome) {
				err = fmt.Errorf("enterprise hooks: previous home %q is not a clean absolute path", previousHome)
				break
			}
			restorePreviousHome := connector.BindManagedBackupPreviousHome(previousHome)
			conn, setupOpts, setupErr := enterpriseHookWorkerRemoveSetup(opts)
			if setupErr == nil {
				var reportErr error
				outcome.CleanedPaths, reportErr = enterpriseHookWorkerRemovePaths(opts, conn, setupOpts)
				if reportErr == nil {
					outcome.PathsReported = true
				} else {
					outcome.CleanedPaths = nil
					outcome.Unverified = enterpriseHookWorkerUnverifiedReason(reportErr)
				}
			}
			// An agent config in the home that leads out of it is left
			// alone, link and file, whoever owns that file: the removal
			// fails with the remedy and no teardown runs (rel-1-0-3
			// GAP-0206). The connector writes refuse it as well.
			if err = enterpriseHookWorkerOutsideHomeConfig(opts.UserHome, setupOpts.DataDir, outcome.CleanedPaths); err != nil {
				restorePreviousHome()
				break
			}
			// A report is needed only for a re-homed row. An unreadable
			// receipt must not prevent ordinary teardown.
			if err = enterpriseHookWorkerRemover(ctx, opts); err != nil {
				restorePreviousHome()
				break
			}
			if setupErr != nil {
				outcome.Unverified = enterpriseHookWorkerUnverifiedReason(setupErr)
			}
			if !outcome.PathsReported {
				restorePreviousHome()
				purgeBlocked = firstNonEmpty(purgeBlocked, "the removal of its "+opts.ConnectorName+
					" entries could not be checked ("+outcome.Unverified+"); fix that, then rerun the purge")
				break
			}
			outcome.Remaining = enterpriseHookWorkerRemainingAfterRemove(opts, conn, setupOpts, outcome.CleanedPaths)
			restorePreviousHome()
			if outcome.Remaining != "" {
				purgeBlocked = firstNonEmpty(purgeBlocked, "DefenseClaw entries remain after the removal ("+outcome.Remaining+
					"); remove them from that agent's config, then rerun the purge")
			}
		case enterpriseHookWorkerModeRemoveLeftover:
			var leftover bool
			if leftover, err = enterpriseHookWorkerManagedRegistration(opts); err == nil && leftover {
				err = enterpriseHookWorkerRemover(ctx, opts)
				outcome.Removed = err == nil
			}
		case enterpriseHookWorkerModeBlockPersonalClaude:
			err = blockPersonalClaudeHook(opts)
			result = enterprisehooks.InstallResult{Connector: opts.ConnectorName, UserHome: opts.UserHome}
		case enterpriseHookWorkerModeUnblockPersonalClaude:
			dataDir := strings.TrimSpace(opts.DataDir)
			if dataDir == "" {
				dataDir = filepath.Join(opts.UserHome, ".defenseclaw")
			}
			outcome.Removed, err = enterprisehooks.RemovePersonalClaudeHookBlocker(dataDir)
		case enterpriseHookWorkerModeRepairManagedCodexFeature:
			if !request.Standalone {
				err = errors.New("managed Codex feature repair requires the standalone guardian")
			} else {
				err = repairManagedCodexUserFeature(opts)
			}
			result = enterprisehooks.InstallResult{Connector: opts.ConnectorName, UserHome: opts.UserHome}
		case enterpriseHookWorkerModeRemoveUserNativeOTLP:
			if !request.Standalone {
				err = errors.New("native OTLP exporter removal requires the standalone guardian")
			} else {
				err = removeManagedUserNativeOTLP(opts, target.Options.ProductCredentials)
			}
			result = enterprisehooks.InstallResult{Connector: opts.ConnectorName, UserHome: opts.UserHome}
		case enterpriseHookWorkerModePurge:
			if purgeBlocked != "" {
				err = errors.New("kept the per-user state for its backups: " + purgeBlocked)
				break
			}
			var stopped bool
			if stopped, err = enterpriseHookWorkerStopPerUser(opts); err != nil {
				break
			}
			var summary enterprisehooks.PurgeSummary
			if summary, err = enterpriseHookWorkerPurger(ctx, opts); err == nil {
				outcome.Purged = &enterpriseHookPurgeDetail{Data: summary.Data, Kept: summary.Kept, Binaries: summary.Binaries, Gateway: stopped, UVCache: summary.UVCache, RemovedConnectorBackups: strings.Join(summary.KeptRemovedConnectorBackups, ", ")}
			}
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
			if target.Mode == enterpriseHookWorkerModeRemove || target.Mode == enterpriseHookWorkerModeRemoveLeftover {
				purgeBlocked = firstNonEmpty(purgeBlocked, "a DefenseClaw hook registration of this account was not removed")
			}
		} else {
			outcome.OK = true
			if target.Mode != enterpriseHookWorkerModeRemove && target.Mode != enterpriseHookWorkerModeRemoveLeftover &&
				target.Mode != enterpriseHookWorkerModePurge && target.Mode != enterpriseHookWorkerModeUnblockPersonalClaude {
				outcome.Result = &result
				outcome.AgentConfig = result.AgentConfig
			}
		}
		results = append(results, outcome)
		if recheck {
			rechecks = append(rechecks, enterpriseHookWorkerRecheck{result: len(results) - 1, opts: opts})
			recheckedAt = append(recheckedAt, time.Now())
		}
	}
	recheckEnterpriseHookTargetsOverWindow(ctx, recheckWindow, recheckedAt,
		func(index int) error {
			_, err := enterpriseHookWorkerVerifier(ctx, rechecks[index].opts)
			return err
		},
		func(index int, _ error) {
			outcome := &results[rechecks[index].result]
			result, err := enterpriseHookWorkerInstaller(ctx, rechecks[index].opts)
			if err != nil {
				outcome.OK, outcome.Result, outcome.AgentConfig = false, nil, ""
				outcome.Pending = enterprisehooks.PendingTargetError(err) &&
					enterprisehooks.CheckUnixTargetHome(request.Home, request.UID).State == enterprisehooks.HomePending
				if !outcome.Pending {
					outcome.Error = err.Error()
				}
				return
			}
			outcome.Repaired = true
			outcome.Result = &result
			outcome.AgentConfig = result.AgentConfig
		})
	return enterpriseHookWorkerResponse{Targets: results}
}

// enterpriseHookWorkerRecheck is a verify_or_repair target that verified and
// is checked again over the request's recheck window.
type enterpriseHookWorkerRecheck struct {
	result int
	opts   enterprisehooks.InstallOptions
}

// repairManagedCodexUserFeature runs with the target user's uid. The machine
// requirements already pin hooks=true; this removes only the conflicting user
// key that makes Codex refuse an unrelated project trust write.
func repairManagedCodexUserFeature(opts enterprisehooks.InstallOptions) error {
	if !strings.EqualFold(strings.TrimSpace(opts.ConnectorName), "codex") {
		return errors.New("managed Codex feature repair requires the Codex connector")
	}
	path := filepath.Join(opts.UserHome, ".codex", "config.toml")
	resolved, raw, perm, found, err := readEnterpriseHookWorkerHomeFile(opts.UserHome, path, "Codex user config", "before managed feature repair")
	if err != nil || !found {
		return err
	}
	repaired, err := connector.RemoveCodexManagedHookFeature(raw)
	if err != nil {
		return fmt.Errorf("repair Codex user config %s: %w", path, err)
	}
	if bytes.Equal(raw, repaired) {
		return nil
	}
	if err := configwrite.WriteFileDurable(resolved, repaired, perm); err != nil {
		return fmt.Errorf("publish repaired Codex user config %s: %w", path, err)
	}
	return nil
}

// readEnterpriseHookWorkerHomeFile reads path, a file of the enrolled home,
// as the user: a regular file of at most 4 MiB that resolves inside the home.
// found is false when it does not exist. remedy ends the refusal of a file
// that resolves outside the home.
func readEnterpriseHookWorkerHomeFile(home, path, label, remedy string) (resolved string, raw []byte, perm os.FileMode, found bool, err error) {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return "", nil, 0, false, nil
	} else if err != nil {
		return "", nil, 0, false, fmt.Errorf("inspect %s %s: %w", label, path, err)
	}
	resolved, err = filepath.EvalSymlinks(path)
	if err != nil {
		return "", nil, 0, false, fmt.Errorf("resolve %s %s: %w", label, path, err)
	}
	resolvedHome, err := filepath.EvalSymlinks(home)
	if err != nil {
		return "", nil, 0, false, fmt.Errorf("resolve enrolled home %s for %s: %w", home, label, err)
	}
	if !enterpriseHookWorkerPathWithin(resolvedHome, resolved) {
		return "", nil, 0, false, fmt.Errorf("the %s %s resolves outside the enrolled home; move it into the home %s", label, path, remedy)
	}
	file, err := os.OpenFile(resolved, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", nil, 0, false, fmt.Errorf("open %s %s: %w", label, path, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", nil, 0, false, fmt.Errorf("stat %s %s: %w", label, path, err)
	}
	if !info.Mode().IsRegular() || info.Size() > 4<<20 {
		return "", nil, 0, false, fmt.Errorf("the %s %s is not a regular file of at most 4 MiB", label, path)
	}
	raw, err = io.ReadAll(io.LimitReader(file, 4<<20+1))
	if err != nil {
		return "", nil, 0, false, fmt.Errorf("read bounded %s %s: %w", label, path, err)
	}
	if len(raw) > 4<<20 {
		return "", nil, 0, false, fmt.Errorf("the %s %s exceeded the 4 MiB read limit", label, path)
	}
	return resolved, raw, info.Mode().Perm(), true, nil
}

// removeManagedUserNativeOTLP runs with the target user's uid. Under the
// managed Unix profile DefenseClaw writes no native OTLP exporter into an
// account's own Codex or Claude Code configuration (Setup removes one; only
// an OpenShell sandbox image carries its own). An exporter an earlier
// install or a copied configuration left there that carries a DefenseClaw
// credential sends it, with the agent's prompt telemetry, to whoever holds
// its port (GAP-2376, as GAP-0836 on Windows). This removes exactly those
// entries, known by the scoped credential in the account's data dir, the
// values the setup backup recorded, or the digest of a product credential
// in credentials; every other entry, an exporter with its own bearer
// included, stays as the user wrote it.
func removeManagedUserNativeOTLP(opts enterprisehooks.InstallOptions, credentials []connector.NativeOTLPCredentialDigest) error {
	name := strings.ToLower(strings.TrimSpace(opts.ConnectorName))
	backupName := connector.UserNativeOTLPBackupName(name)
	if backupName == "" {
		return fmt.Errorf("connector %q has no native OTLP exporter", opts.ConnectorName)
	}
	dataDir := strings.TrimSpace(opts.DataDir)
	if dataDir == "" {
		dataDir = filepath.Join(opts.UserHome, ".defenseclaw")
	}
	path := connector.UserNativeOTLPConfigPathFor(name, opts.UserHome)
	label := name + " user config"
	resolved, raw, perm, found, err := readEnterpriseHookWorkerHomeFile(opts.UserHome, path, label, "and the next repair checks it")
	if err != nil || !found {
		return err
	}
	_, backup, _, _, err := readEnterpriseHookWorkerHomeFile(opts.UserHome, filepath.Join(dataDir, backupName), name+" setup backup", "and the next repair checks it")
	if err != nil {
		return err
	}
	out, removed, err := connector.UserNativeOTLPWithout(name, raw, backup, connector.SetupOpts{DataDir: dataDir, ManagedEnterprise: true}, credentials)
	if err != nil {
		return fmt.Errorf("inspect %s %s for a native OTLP exporter: %w", label, path, err)
	}
	if len(removed) == 0 {
		return nil
	}
	if err := configwrite.WriteFileDurable(resolved, out, perm); err != nil {
		return fmt.Errorf("remove the native OTLP exporter from %s %s: %w", label, path, err)
	}
	fmt.Fprintf(os.Stderr, "[enterprise-hooks] %s: removed a native OTLP exporter that carried a DefenseClaw credential to a port the managed gateway does not serve (%s)\n",
		name, strings.Join(removed, ", "))
	return nil
}

// blockPersonalClaudeHook replaces only an existing DefenseClaw-owned
// personal script, as the target user. A managed policy may cover the agent
// while an old personal registration still invokes this script. Its direct
// invocation must deny instead of allowing on a dead personal gateway port.
func blockPersonalClaudeHook(opts enterprisehooks.InstallOptions) error {
	if opts.ConnectorName != "claudecode" {
		return errors.New("personal hook blocking is only for Claude Code")
	}
	dataDir := strings.TrimSpace(opts.DataDir)
	if dataDir == "" {
		dataDir = filepath.Join(opts.UserHome, ".defenseclaw")
	}
	path := filepath.Join(dataDir, "hooks", "claude-code-hook.sh")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("personal Claude Code hook %s is not a regular file", path)
	}
	if info.Size() > 1<<20 {
		return fmt.Errorf("personal Claude Code hook %s is too large", path)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Contains(body[:min(len(body), 160)], []byte("# defenseclaw-managed-hook v")) {
		return fmt.Errorf("personal Claude Code hook %s is not DefenseClaw-owned", path)
	}
	if string(body) == enterprisehooks.PersonalClaudeHookBlocker {
		return nil
	}
	return configwrite.WriteFileDurable(path, []byte(enterprisehooks.PersonalClaudeHookBlocker), 0o700)
}

// enterpriseHookWorkerRemoveSetup resolves the same SetupOpts as
// RemoveUserHooks. Its error never replaces the remover's own error.
func enterpriseHookWorkerRemoveSetup(opts enterprisehooks.InstallOptions) (connector.Connector, connector.SetupOpts, error) {
	dataDir := strings.TrimSpace(opts.DataDir)
	if dataDir == "" {
		dataDir = filepath.Join(opts.UserHome, ".defenseclaw")
	}
	var err error
	dataDir, err = filepath.Abs(dataDir)
	if err != nil {
		return nil, connector.SetupOpts{}, fmt.Errorf("resolve data dir: %w", err)
	}
	registry := opts.Registry
	if registry == nil {
		registry = connector.NewDefaultRegistry()
	}
	name := strings.ToLower(strings.TrimSpace(opts.ConnectorName))
	conn, ok := registry.Get(name)
	if !ok {
		return nil, connector.SetupOpts{}, fmt.Errorf("unknown connector %q", name)
	}
	setupOpts := connector.SetupOpts{
		DataDir: dataDir, Interactive: false, ManagedEnterprise: true,
		WorkspaceDir: strings.TrimSpace(opts.WorkspaceDir), AgentVersion: strings.TrimSpace(opts.AgentVersion),
		HookContractID: strings.TrimSpace(opts.HookContractID),
	}
	return conn, setupOpts, nil
}

// enterpriseHookWorkerRemovePaths runs as the account whose receipts and
// config it reads. A failed collection is unverified, never a clean report.
func enterpriseHookWorkerRemovePaths(opts enterprisehooks.InstallOptions, conn connector.Connector, setupOpts connector.SetupOpts) ([]string, error) {
	var paths []string
	err := connector.WithUserHomeDir(opts.UserHome, func() error {
		paths = append(paths, connector.CleanupConfigPathsForConnector(conn, setupOpts)...)
		receipts, readErr := connector.ManagedFileBackupTargetsForConnector(setupOpts.DataDir, conn.Name())
		if readErr != nil {
			return readErr
		}
		paths = append(paths, receipts...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	paths = uniqueEnterpriseHookWorkerPaths(paths)
	if err := validateEnterpriseHookWorkerRemoveReport(enterpriseHookWorkerTargetResult{PathsReported: true, CleanedPaths: paths}); err != nil {
		return nil, err
	}
	return paths, nil
}

// enterpriseHookWorkerOutsideHomeConfig refuses a removal while one of the
// agent config paths in the home leads out of it through a symlink (the
// config, or a folder on the way) to a file that still holds DefenseClaw's
// entries, or that cannot be checked as the account. A teardown would have
// restored or deleted that file: the worker runs as the user, but a file
// outside the home is not DefenseClaw's to change, whoever owns it
// (rel-1-0-3 GAP-0206). Once the account removes those entries, the
// teardown leaves that file as it is and the removal goes on. A dangling
// link changes nothing outside; the check after the teardown reports it.
func enterpriseHookWorkerOutsideHomeConfig(home, dataDir string, paths []string) error {
	const maxConfigBytes = 4 << 20
	customDataDir := ""
	if filepath.Clean(dataDir) != filepath.Join(home, ".defenseclaw") {
		customDataDir = filepath.Clean(dataDir)
	}
	for _, path := range paths {
		target, outside, err := connector.AgentConfigOutsideHome(home, path)
		if err != nil {
			return fmt.Errorf("%s: the agent config link cannot be followed (%v); DefenseClaw left it alone: replace the link with the file it names, then rerun", path, err)
		}
		if !outside {
			continue
		}
		refuse := func(detail string) error {
			return &connector.AgentConfigOutsideHomeError{Path: path, Target: target, Detail: detail}
		}
		info, err := os.Stat(target)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() {
			return refuse("which cannot be checked as the account")
		}
		file, err := os.Open(target)
		if err != nil {
			return refuse("which cannot be read as the account")
		}
		data, readErr := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
		_ = file.Close()
		if readErr != nil || len(data) > maxConfigBytes {
			return refuse("which could not be checked within the read limit")
		}
		if line, marker := enterpriseHookWorkerConfigReferenceLine(data, customDataDir); line != 0 {
			return refuse(fmt.Sprintf("and that file still holds DefenseClaw's %s (line %d)", marker, line))
		}
	}
	return nil
}

// enterpriseHookWorkerRemainingAfterRemove names the first DefenseClaw entry
// the agent still loads after a teardown: one VerifyClean reports, or a
// reference in a config path the worker resolved. Empty means checked clean.
func enterpriseHookWorkerRemainingAfterRemove(opts enterprisehooks.InstallOptions, conn connector.Connector, setupOpts connector.SetupOpts, paths []string) string {
	verifyErr := connector.WithUserHomeDir(opts.UserHome, func() error {
		return conn.VerifyClean(setupOpts)
	})
	if verifyErr != nil {
		path := opts.UserHome
		for _, candidate := range paths {
			if enterpriseHookWorkerPathWithin(opts.UserHome, candidate) {
				path = candidate
				break
			}
		}
		return boundedString(strings.Join(strings.Fields(path+": "+verifyErr.Error()), " "), 1000)
	}
	// Some connectors validate only references to this data dir. A copied
	// config can still name the former home's hook path.
	return enterpriseHookWorkerRemainingConfigReference(opts.UserHome, setupOpts.DataDir, paths)
}

func enterpriseHookWorkerUnverifiedReason(err error) string {
	value := strings.ToValidUTF8(err.Error(), "\ufffd")
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value)
	value = strings.TrimSpace(value)
	if len(value) > enterpriseHookWorkerRemainingMax {
		if path := enterpriseHookUnverifiedReceiptPath(value); path != "" {
			value = strings.Replace(value, path, shortEnterpriseHookReportPath(path), 1)
		}
	}
	if len(value) <= enterpriseHookWorkerRemainingMax {
		return value
	}
	value = value[:enterpriseHookWorkerRemainingMax]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

func uniqueEnterpriseHookWorkerPaths(paths []string) []string {
	seen := make(map[string]bool, len(paths))
	unique := make([]string, 0, len(paths))
	for _, path := range paths {
		if !seen[path] {
			seen[path] = true
			unique = append(unique, path)
		}
	}
	return unique
}

// enterpriseHookWorkerRemainingConfigReference is a conservative final check
// of the config paths the worker resolved. It runs as the user and reads at
// most 4 MiB from each regular file. An unreadable or nonregular config is
// unverified rather than assumed clean.
func enterpriseHookWorkerRemainingConfigReference(home, dataDir string, paths []string) string {
	const maxConfigBytes = 4 << 20
	customDataDir := ""
	if filepath.Clean(dataDir) != filepath.Join(home, ".defenseclaw") {
		customDataDir = filepath.Clean(dataDir)
	}
	for _, path := range paths {
		if !enterpriseHookWorkerPathWithin(home, path) {
			continue
		}
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return path + ": cannot inspect agent config"
		}
		target := path
		if info.Mode()&os.ModeSymlink != 0 {
			// A dotfile manager links the agent config to a file elsewhere
			// (~/.codex/config.toml -> ~/dotfiles/codex.toml). The worker
			// runs as the user and reads that file, also one outside the
			// home, which the removal never changes (GAP-0642, rel-1-0-3
			// GAP-0206).
			resolved, problem := enterpriseHookWorkerConfigLinkTarget(path)
			if problem != "" {
				return path + ": " + problem
			}
			target = resolved
			if info, err = os.Lstat(target); err != nil {
				return path + ": cannot inspect the file the agent config links to"
			}
		}
		if !info.Mode().IsRegular() {
			return path + ": agent config is not a regular file"
		}
		file, err := os.Open(target)
		if err != nil {
			return path + ": cannot read agent config"
		}
		data, readErr := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
		_ = file.Close()
		if readErr != nil || len(data) > maxConfigBytes {
			return path + ": agent config could not be checked within the read limit"
		}
		if line, marker := enterpriseHookWorkerConfigReferenceLine(data, customDataDir); line != 0 {
			return fmt.Sprintf("%s:%d: DefenseClaw %s remains in agent config", path, line, marker)
		}
	}
	return ""
}

// enterpriseHookWorkerConfigLinkTarget resolves a symlinked agent config,
// or says why it cannot.
func enterpriseHookWorkerConfigLinkTarget(path string) (string, string) {
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", "agent config is a symlink that cannot be resolved; remove DefenseClaw's entries from the file it names, or replace the link with that file"
	}
	return target, ""
}

// enterpriseHookWorkerConfigReferenceLine matches only connector-owned
// markers and data-dir paths. Agent comments, including the Codex bootstrap
// header, are inert. It does no I/O and is safe to exercise for every agent.
func enterpriseHookWorkerConfigReferenceLine(data []byte, customDataDir string) (int, string) {
	markers := []string{
		"defenseclaw-managed-hook", "x-defenseclaw-source", "x-defenseclaw-client",
		"x-defenseclaw-token", "defenseclaw-hook", "defenseclaw-gateway",
		"defenseclaw.js", "defenseclaw.ts", "defenseclaw.json",
		"defenseclaw.listener-proof.v1",
	}
	for index, raw := range bytes.Split(data, []byte{'\n'}) {
		line := strings.TrimSpace(string(raw))
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		lower := strings.ToLower(line)
		for start := 0; start < len(lower); {
			found := strings.Index(lower[start:], ".defenseclaw")
			if found < 0 {
				break
			}
			begin := start + found
			end := begin + len(".defenseclaw")
			if begin > 0 && !strings.ContainsRune("/\\\"'= \t([{,", rune(lower[begin-1])) {
				start = end
				continue
			}
			if end == len(lower) || strings.ContainsRune("/\\\"'", rune(lower[end])) {
				return index + 1, "data-dir path"
			}
			start = end
		}
		if customDataDir != "" && strings.Contains(line, filepath.Clean(customDataDir)+string(filepath.Separator)) {
			return index + 1, "data-dir path"
		}
		for _, marker := range markers {
			if strings.Contains(lower, marker) {
				return index + 1, "connector marker"
			}
		}
	}
	return 0, ""
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
		ManagedHookBinary:                  o.ManagedHookBinary,
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
		ManagedHookBinary:                  opts.ManagedHookBinary,
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
	request.CleanupFence = request.cleanupFence != nil
	if enterpriseHookWorkerReadsLaunchd() {
		request.LaunchdHermesHome = enterpriseHookWorkerLaunchdHermesHome(account)
	}
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
	ctx, cancel := context.WithTimeout(ctx, workerTimeout(request))
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
	if enterpriseHookWorkersStuck.has(account.UID) {
		return enterpriseHookWorkerResponse{}, fmt.Errorf("worker for uid %d timed out: %w: its previous worker was killed but has not exited yet (a file system call in the account's home may be stuck)", account.UID, context.DeadlineExceeded)
	}
	stopFence, err := attachEnterpriseHookWorkerFence(ctx, cmd, request)
	if err != nil {
		return enterpriseHookWorkerResponse{}, err
	}
	abandoned, runErr := runEnterpriseHookWorkerProcess(ctx, cmd, account.UID)
	stopFence()
	if abandoned {
		return enterpriseHookWorkerResponse{}, fmt.Errorf("worker for uid %d timed out: %w: it was killed but did not exit (a file system call in the account's home may be stuck)", account.UID, ctx.Err())
	}
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

// enterpriseHookWorkerWait waits for a started worker. Tests replace it to
// stand for a worker the kernel cannot reap.
var enterpriseHookWorkerWait = (*exec.Cmd).Wait

// enterpriseHookWorkerAbandonGrace is how long a worker whose context ended
// may take to exit after it is killed (and its output pipes are closed,
// cmd.WaitDelay) before the caller stops waiting for it.
var enterpriseHookWorkerAbandonGrace = 3 * time.Second

// enterpriseHookWorkersStuck holds the uids whose last worker was killed but
// has not exited. A worker blocked in an uninterruptible file system call
// (a stalled FUSE or NFS mount in the home) cannot be reaped, and waiting
// for it held the enumerator's cycle for good (GAP-1468, GAP-1470). The
// caller stops waiting, the account is reported not inspected, and no new
// worker starts for it until the stuck one exits.
var enterpriseHookWorkersStuck = stuckEnterpriseHookWorkers{uids: map[int]bool{}}

type stuckEnterpriseHookWorkers struct {
	mu   sync.Mutex
	uids map[int]bool
}

func (s *stuckEnterpriseHookWorkers) has(uid int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.uids[uid]
}

func (s *stuckEnterpriseHookWorkers) set(uid int, stuck bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if stuck {
		s.uids[uid] = true
	} else {
		delete(s.uids, uid)
	}
}

// runEnterpriseHookWorkerProcess runs cmd and waits for it. Once ctx ends
// (cmd.Cancel kills the worker's group) it waits at most
// enterpriseHookWorkerAbandonGrace more; abandoned is true when the worker
// still has not exited, and uid stays stuck until it does.
func runEnterpriseHookWorkerProcess(ctx context.Context, cmd *exec.Cmd, uid int) (abandoned bool, err error) {
	if err := cmd.Start(); err != nil {
		return false, err
	}
	done := make(chan error, 1)
	var settled sync.Mutex
	gaveUp := false
	go func() {
		err := enterpriseHookWorkerWait(cmd)
		settled.Lock()
		if gaveUp {
			enterpriseHookWorkersStuck.set(uid, false)
		}
		settled.Unlock()
		done <- err
	}()
	select {
	case err := <-done:
		return false, err
	case <-ctx.Done():
	}
	grace := time.NewTimer(enterpriseHookWorkerAbandonGrace)
	defer grace.Stop()
	select {
	case err := <-done:
		return false, err
	case <-grace.C:
	}
	settled.Lock()
	defer settled.Unlock()
	select {
	case err := <-done:
		return false, err
	default:
	}
	gaveUp = true
	enterpriseHookWorkersStuck.set(uid, true)
	return true, nil
// enterpriseHookWorkerReadsLaunchd says whether this guardian reads each
// account's launchd user domain for its worker: a root guardian on macOS.
// Replaceable in tests.
var enterpriseHookWorkerReadsLaunchd = func() bool {
	return runtime.GOOS == "darwin" && os.Geteuid() == 0
}

// enterpriseHookWorkerLaunchdHermesHome reads HERMES_HOME of the account's
// launchd user domain for its worker (GAP-2374). When the domain cannot be
// read the worker reads its own, as before. Replaceable in tests.
var enterpriseHookWorkerLaunchdHermesHome = func(account enterpriseHookWorkerAccount) *string {
	value, err := hermespath.ReadLaunchdHermesHome(account.UID)
	if err != nil {
		if enterpriseHookWorkerLog != nil {
			fmt.Fprintf(enterpriseHookWorkerLog, "[hook-guardian] worker uid=%d: launchd environment unavailable: %v\n", account.UID, err)
		}
		return nil
	}
	return &value
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
// discovery found it, after the system directories so they always win. The worker runs as the user, so the
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
			response, err := enterpriseHookWorkerRunner(ctx, jobs[i].Account, jobs[i].Request)
			// The slot is free before done runs: a removal record that waits
			// for its account's lock never holds off another account's worker.
			<-semaphore
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

// enterpriseHookWorkerScanGrace is how long a discover worker waits, after
// its scan deadline, for a scan that observes the deadline to return.
var enterpriseHookWorkerScanGrace = 2 * time.Second

// enterpriseHookWorkerDiscovery is what one discover worker has found so far.
type enterpriseHookWorkerDiscovery struct {
	mu          sync.Mutex
	versions    map[string]string
	reasons     map[string]string
	surfaces    map[string][]connector.AgentSurface
	unlisted    []enterprisehooks.PrivateAgentInstall
	installs    []enterprisehooks.PrivateAgentInstall
	finished    map[string]bool
	privateDone bool
}

// enterpriseHookWorkerDiscoverWithin answers by ctx's deadline even when
// discovery cannot. A file system call that never returns (macOS holding an
// open() of a home folder for a privacy or file-provider decision, a hung
// network mount) never observes a context, so a worker that waited for it
// timed out and the parent discarded every version it had found: a supported
// installed Hermes stayed unenrolled after a reinstall (GAP-1413). The worker
// now answers with the versions already found, and names each connector it
// could not finish, and the private-install scan when it did not return, as
// incomplete, so the account is reported NOT COVERED with the reason and the
// next cycle tries again. The worker exits after it answers, which ends the
// blocked call's goroutine.
func enterpriseHookWorkerDiscoverWithin(ctx context.Context, request enterpriseHookWorkerRequest) enterpriseHookWorkerResponse {
	found := &enterpriseHookWorkerDiscovery{
		versions: map[string]string{},
		reasons:  map[string]string{},
		surfaces: map[string][]connector.AgentSurface{},
		finished: map[string]bool{},
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		enterpriseHookWorkerDiscover(ctx, request, found)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		grace := time.NewTimer(enterpriseHookWorkerScanGrace)
		select {
		case <-done:
		case <-grace.C:
		}
		grace.Stop()
	}
	return found.response(request.Connectors)
}

func enterpriseHookWorkerDiscover(ctx context.Context, request enterpriseHookWorkerRequest, found *enterpriseHookWorkerDiscovery) {
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
		// Host apps are never run; an engine CLI bundled in one is run
		// only outside a static (untrusted-home) discovery.
		surfaces, complete := enterpriseHookWorkerDiscoverSurfaces(ctx, request.Home, name, !request.StaticDiscovery)
		var kiroIDE []enterprisehooks.KiroForm
		if name == "kiro" {
			// The Kiro IDE is read, never run, so static discovery reads it too.
			kiroIDE = enterpriseHookWorkerDiscoverKiroIDE(request.Home)
		}
		found.mu.Lock()
		if version != "" {
			found.versions[name] = version
		} else if reason != "" {
			found.reasons[name] = reason
		}
		if len(surfaces) != 0 {
			found.surfaces[name] = surfaces
		}
		if !complete {
			found.unlisted = append(found.unlisted, enterprisehooks.PrivateAgentInstall{Connector: name, Incomplete: true, Skipped: enterprisehooks.PrivateInstallSkippedExtensions})
		}
		if name == "kiro" {
			enterprisehooks.PutUnixKiroIDEForms(kiroIDE, found.versions, found.reasons)
		}
		found.finished[name] = true
		found.mu.Unlock()
	}
	installs := enterpriseHookWorkerDiscoverPrivateInstalls(ctx, request.Home, request.Connectors)
	found.mu.Lock()
	found.installs, found.privateDone = installs, true
	found.mu.Unlock()
}

// response is the worker's answer from what was found so far.
func (found *enterpriseHookWorkerDiscovery) response(connectors []string) enterpriseHookWorkerResponse {
	found.mu.Lock()
	defer found.mu.Unlock()
	response := enterpriseHookWorkerResponse{
		Versions: make(map[string]string, len(found.versions)),
		Reasons:  make(map[string]string, len(found.reasons)),
		Surfaces: make(map[string][]connector.AgentSurface, len(found.surfaces)),
	}
	for name, version := range found.versions {
		response.Versions[name] = version
	}
	for name, reason := range found.reasons {
		response.Reasons[name] = reason
	}
	for name, surfaces := range found.surfaces {
		response.Surfaces[name] = append([]connector.AgentSurface(nil), surfaces...)
	}
	installs := append([]enterprisehooks.PrivateAgentInstall(nil), found.installs...)
	incomplete := func(name string) {
		installs = append(installs, enterprisehooks.PrivateAgentInstall{Connector: name, Incomplete: true, Skipped: enterprisehooks.PrivateInstallSkippedTimedOut})
	}
	if !found.privateDone {
		for _, name := range enterprisehooks.UnixPrivateInstallConnectors(connectors) {
			incomplete(name)
		}
	}
	for _, name := range connectors {
		if name = strings.ToLower(strings.TrimSpace(name)); name != "" && !found.finished[name] {
			incomplete(name)
		}
	}
	response.PrivateInstalls = append(installs, found.unlisted...)
	return response
}
