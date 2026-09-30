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

package openshell

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// Client is the narrow surface DefenseClaw drives the OpenShell gateway
// through. Sandbox, draft, policy and setting calls are scoped to the
// client's workspace; provider profiles are platform-scoped, matching
// `openshell profile import --global`.
//
// Every call applies ClientOptions.RPCTimeout when the context has no
// deadline. Errors wrap the SDK's *StatusError, so the Is* predicates in
// this package classify them.
type Client interface {
	// Workspace is the OpenShell workspace the client is bound to.
	Workspace() string

	// Health reports gateway liveness and its release.
	Health(ctx context.Context) (*GatewayHealth, error)
	// GatewayInfo reports the gateway's compute drivers and extensions.
	GatewayInfo(ctx context.Context) (*GatewayInfo, error)

	CreateSandbox(ctx context.Context, name string, spec *SandboxSpec, opts CreateSandboxOptions) (*Sandbox, error)
	GetSandbox(ctx context.Context, name string) (*Sandbox, error)
	// ListSandboxes returns the sandboxes carrying every label in
	// selector (all sandboxes when selector is empty).
	ListSandboxes(ctx context.Context, selector map[string]string) ([]*Sandbox, error)
	// DeleteSandbox deletes a sandbox; a missing sandbox is not an error
	// (Outcome reports DeletionAlreadyAbsent).
	DeleteSandbox(ctx context.Context, name string) (*DeletionResult, error)
	StopSandbox(ctx context.Context, name string) (*Sandbox, error)
	StartSandbox(ctx context.Context, name string) (*Sandbox, error)
	// WaitReady waits for phase Ready and for the gateway to accept the
	// sandbox configuration. A rejected configuration returns a
	// *ConfigurationRejectedError.
	WaitReady(ctx context.Context, name string) (*Sandbox, error)
	WaitStopped(ctx context.Context, name string) (*Sandbox, error)
	// WaitDeleted waits until the sandbox no longer exists.
	WaitDeleted(ctx context.Context, name string) error

	// Exec runs argv in a sandbox. The sandbox stops the command at its
	// timeout; see ExecOptions for what is and is not retried.
	Exec(ctx context.Context, sandbox string, argv []string, opts ExecOptions) (*ExecResult, error)

	ListProfiles(ctx context.Context) ([]*ProviderProfile, error)
	GetProfile(ctx context.Context, id string) (*ProviderProfile, error)
	LintProfiles(ctx context.Context, items []ProfileImportItem) (*LintResult, error)
	// ImportProfiles imports each item in its own request, because a
	// multi-profile import can fail as a whole on one bad file.
	ImportProfiles(ctx context.Context, items []ProfileImportItem) (*ImportResult, error)
	UpdateProfile(ctx context.Context, id string, expectedResourceVersion uint64, item ProfileImportItem) (*UpdateResult, error)
	DeleteProfile(ctx context.Context, id string) (*DeletionResult, error)

	CreateProvider(ctx context.Context, provider *Provider) (*Provider, error)
	GetProvider(ctx context.Context, name string) (*Provider, error)
	ListProviders(ctx context.Context) ([]*Provider, error)
	UpdateProvider(ctx context.Context, provider *Provider) (*Provider, error)
	// EnsureProvider creates the provider or replaces an existing one of
	// the same name.
	EnsureProvider(ctx context.Context, provider *Provider) (*Provider, error)
	DeleteProvider(ctx context.Context, name string) (*DeletionResult, error)
	AttachProvider(ctx context.Context, sandbox, provider string) (*AttachProviderResult, error)
	DetachProvider(ctx context.Context, sandbox, provider string) (*DetachProviderResult, error)

	// GetDraft returns the sandbox's proposed policy chunks, optionally
	// filtered by status ("pending", "approved", "rejected").
	GetDraft(ctx context.Context, sandbox, status string) (*DraftPolicy, error)
	ApproveDraftChunk(ctx context.Context, sandbox, chunkID, reviewToken string) (*ApproveResult, error)
	// ApproveDraftChunks approves several reviewed chunks in one policy
	// revision, so the sandbox reloads (and drops connections) once.
	// Security-flagged chunks are never included.
	ApproveDraftChunks(ctx context.Context, sandbox string, approvals []DraftChunkApproval) (*ApproveAllResult, error)
	RejectDraftChunk(ctx context.Context, sandbox, chunkID, reason string) error

	// SandboxConfig returns the sandbox's effective policy and settings.
	SandboxConfig(ctx context.Context, sandbox string) (*SandboxConfig, error)
	// SetPolicy replaces the sandbox policy. OpenShell only lets
	// network_policies differ from the create-time policy.
	SetPolicy(ctx context.Context, sandbox string, policy *SandboxPolicy, opts PolicyUpdateOptions) (*ConfigUpdateResult, error)
	// MergePolicy applies incremental merge operations in one revision.
	MergePolicy(ctx context.Context, sandbox string, ops []PolicyMergeOperation, opts PolicyUpdateOptions) (*ConfigUpdateResult, error)
	// PolicyStatus returns one policy revision (0 = latest) and the active
	// version.
	PolicyStatus(ctx context.Context, sandbox string, version uint32) (*PolicyStatusResult, error)
	// GlobalPolicy returns the active gateway-global policy revision, or
	// nil when sandbox-level policy control is in effect.
	GlobalPolicy(ctx context.Context) (*PolicyRevision, error)

	// GatewaySettings returns the gateway-global settings.
	GatewaySettings(ctx context.Context) (*GatewayConfig, error)
	// UpdateSetting upserts or deletes one setting key.
	UpdateSetting(ctx context.Context, update SettingUpdate) (*ConfigUpdateResult, error)

	Close() error
}

// Client defaults.
const (
	DefaultRPCTimeout   = 30 * time.Second
	DefaultPollInterval = 500 * time.Millisecond
	// DefaultReadyTimeout bounds WaitReady/WaitStopped/WaitDeleted when the
	// context has no deadline. The first sandbox on a host pulls a
	// multi-gigabyte base image, and on the MicroVM (vm) driver the first
	// start of each image also prepares its MicroVM disk (about a minute).
	DefaultReadyTimeout = 15 * time.Minute
)

// ClientOptions tune a Client.
type ClientOptions struct {
	// Workspace defaults to DefaultWorkspace.
	Workspace string
	// RPCTimeout bounds each unary call whose context has no deadline.
	RPCTimeout time.Duration
	// PollInterval paces WaitReady, WaitStopped and WaitDeleted.
	PollInterval time.Duration
	// ReadyTimeout bounds waits whose context has no deadline.
	ReadyTimeout time.Duration
	// ExecGrace is how long Exec waits past a command's timeout for the
	// sandbox to report its end (default DefaultExecGrace).
	ExecGrace time.Duration
}

func (o ClientOptions) withDefaults() ClientOptions {
	if o.Workspace == "" {
		o.Workspace = DefaultWorkspace
	}
	if o.RPCTimeout <= 0 {
		o.RPCTimeout = DefaultRPCTimeout
	}
	if o.PollInterval <= 0 {
		o.PollInterval = DefaultPollInterval
	}
	if o.ReadyTimeout <= 0 {
		o.ReadyTimeout = DefaultReadyTimeout
	}
	if o.ExecGrace <= 0 {
		o.ExecGrace = DefaultExecGrace
	}
	return o
}

// CreateSandboxOptions carries sandbox metadata.
type CreateSandboxOptions struct {
	Labels      map[string]string
	Annotations map[string]string
}

// PolicyUpdateOptions carries optimistic concurrency and provenance for a
// sandbox policy revision. Annotations must not contain secrets; OpenShell
// stores them with the revision.
type PolicyUpdateOptions struct {
	ExpectedResourceVersion uint64
	Annotations             map[string]string
}

// SettingUpdate mutates one setting key at sandbox or gateway-global
// scope. Exactly one of Sandbox and Global selects the scope, and exactly
// one of Value and Delete the operation. OpenShell only deletes
// gateway-global keys.
type SettingUpdate struct {
	Sandbox string
	Global  bool
	Key     string
	Value   *SettingValue
	Delete  bool
}

// GatewayHealth is the gateway's health answer.
type GatewayHealth struct {
	Healthy bool
	// Version is the parsed release; zero when RawVersion is unparseable.
	Version    Version
	RawVersion string
}

// CheckVersion reports whether the gateway release is inside the
// supported window.
func (h *GatewayHealth) CheckVersion() error {
	if h.Version == (Version{}) {
		return fmt.Errorf("openshell: gateway reported an unrecognized version %q", h.RawVersion)
	}
	return CheckSupported(h.Version)
}

// ConfigurationRejectedError reports a sandbox whose configuration the
// gateway refused (ConfigurationInvalid). The manager re-renders once and
// then reports it.
type ConfigurationRejectedError struct {
	Sandbox string
	Message string
}

func (e *ConfigurationRejectedError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("openshell: sandbox %q configuration was rejected", e.Sandbox)
	}
	return fmt.Sprintf("openshell: sandbox %q configuration was rejected: %s", e.Sandbox, e.Message)
}

// ErrInvalidName reports a sandbox, provider or label name the client
// refuses to send.
var ErrInvalidName = errors.New("openshell: invalid name")

var (
	sandboxNamePattern  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	providerNamePattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$`)
	labelKeyPattern     = regexp.MustCompile(`^([a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?/)?[A-Za-z0-9]([A-Za-z0-9._-]{0,61}[A-Za-z0-9])?$`)
	labelValuePattern   = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9._-]{0,61}[A-Za-z0-9])?)?$`)
)

// ValidSandboxName reports whether name is a DNS-label sandbox name
// (lowercase letters, digits and '-', at most 63 characters). DefenseClaw
// only creates and addresses sandboxes named this way, which also keeps
// names safe as CLI positionals.
func ValidSandboxName(name string) bool { return sandboxNamePattern.MatchString(name) }

// MaxSandboxNameLen is the longest sandbox name OpenShell 0.1.1 creates: its
// gateway refuses longer ones ("name exceeds maximum length (22 > 19)").
// Sandboxes are still addressed by any ValidSandboxName.
const MaxSandboxNameLen = 19

// ValidNewSandboxName reports whether OpenShell creates a sandbox of this
// name: a ValidSandboxName of at most MaxSandboxNameLen characters.
func ValidNewSandboxName(name string) bool {
	return len(name) <= MaxSandboxNameLen && ValidSandboxName(name)
}

func checkSandboxName(name string) error {
	if !ValidSandboxName(name) {
		return fmt.Errorf("%w: sandbox %q", ErrInvalidName, name)
	}
	return nil
}

func checkProviderName(name string) error {
	if !providerNamePattern.MatchString(name) {
		return fmt.Errorf("%w: provider %q", ErrInvalidName, name)
	}
	return nil
}

// LabelSelector renders labels as an OpenShell equality selector
// ("k1=v1,k2=v2", keys sorted). Keys and values follow Kubernetes label
// syntax, which rules out selector metacharacters.
func LabelSelector(labels map[string]string) (string, error) {
	keys := make([]string, 0, len(labels))
	for k, v := range labels {
		if !labelKeyPattern.MatchString(k) {
			return "", fmt.Errorf("%w: label key %q", ErrInvalidName, k)
		}
		if !labelValuePattern.MatchString(v) {
			return "", fmt.Errorf("%w: label %q value %q", ErrInvalidName, k, v)
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + labels[k]
	}
	return strings.Join(parts, ","), nil
}

// Dial connects to a discovered local mTLS gateway with the CLI's TLS
// files and no per-call credentials (the SDK's gateway helper refuses
// mtls). The file checks run again, so a key loosened after discovery is
// refused. Registrations without client certificates are refused with
// ErrUnauthenticatedGateway: no client, and so no provider credential,
// ever reaches such a gateway.
func Dial(reg *Registration, opts ClientOptions) (Client, error) {
	if reg == nil {
		return nil, errors.New("openshell: nil registration")
	}
	if reg.Remote {
		return nil, fmt.Errorf("%w: %s", ErrRemoteGateway, reg.Endpoint)
	}
	cfg := v1.Config{Address: reg.Endpoint, Auth: v1.NoAuth()}
	switch reg.AuthMode {
	case AuthModeMTLS:
		if _, err := CheckTLSFiles(reg.TLS); err != nil {
			return nil, err
		}
		cfg.TLS = &v1.TLSConfig{CAFile: reg.TLS.CA, CertFile: reg.TLS.Cert, KeyFile: reg.TLS.Key}
	case AuthModePlaintext, AuthModeNone:
		return nil, unauthenticatedError(reg)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedAuthMode, reg.AuthMode)
	}
	sdk, err := v1.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("openshell: connect to %s: %w", reg.Endpoint, err)
	}
	return NewClient(sdk, opts), nil
}

// NewClient wraps an SDK client, typically the SDK's in-memory fake in
// tests (see package openshelltest).
func NewClient(sdk v1.ClientInterface, opts ClientOptions) Client {
	return &client{sdk: sdk, opts: opts.withDefaults(), sleep: sleepContext}
}

type client struct {
	sdk   v1.ClientInterface
	opts  ClientOptions
	sleep func(context.Context, time.Duration) error
}

func (c *client) Workspace() string { return c.opts.Workspace }

func (c *client) Close() error { return c.sdk.Close() }

// rpc applies the default per-call timeout to deadline-free contexts.
func (c *client) rpc(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, c.opts.RPCTimeout)
}

func (c *client) wait(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, c.opts.ReadyTimeout)
}

func wrap(op string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("openshell: %s: %w", op, err)
}

func (c *client) Health(ctx context.Context) (*GatewayHealth, error) {
	ctx, cancel := c.rpc(ctx)
	defer cancel()
	res, err := c.sdk.Health().Check(ctx)
	if err != nil {
		return nil, wrap("health", err)
	}
	h := &GatewayHealth{Healthy: res.Healthy, RawVersion: res.Version}
	if v, err := ParseVersion(res.Version); err == nil {
		h.Version = v
	}
	return h, nil
}

func (c *client) GatewayInfo(ctx context.Context) (*GatewayInfo, error) {
	ctx, cancel := c.rpc(ctx)
	defer cancel()
	info, err := c.sdk.Health().GetGatewayInfo(ctx)
	return info, wrap("gateway info", err)
}

func (c *client) CreateSandbox(ctx context.Context, name string, spec *SandboxSpec, opts CreateSandboxOptions) (*Sandbox, error) {
	if err := checkSandboxName(name); err != nil {
		return nil, err
	}
	if _, err := LabelSelector(opts.Labels); err != nil {
		return nil, err
	}
	ctx, cancel := c.rpc(ctx)
	defer cancel()
	var create []v1.CreateOptions
	if len(opts.Annotations) > 0 {
		create = append(create, v1.CreateOptions{Annotations: opts.Annotations})
	}
	sb, err := c.sdk.Sandboxes().Create(ctx, c.opts.Workspace, name, spec, opts.Labels, create...)
	return sb, wrap(fmt.Sprintf("create sandbox %q", name), err)
}

func (c *client) GetSandbox(ctx context.Context, name string) (*Sandbox, error) {
	if err := checkSandboxName(name); err != nil {
		return nil, err
	}
	ctx, cancel := c.rpc(ctx)
	defer cancel()
	sb, err := c.sdk.Sandboxes().Get(ctx, c.opts.Workspace, name)
	return sb, wrap(fmt.Sprintf("get sandbox %q", name), err)
}

func (c *client) ListSandboxes(ctx context.Context, selector map[string]string) ([]*Sandbox, error) {
	sel, err := LabelSelector(selector)
	if err != nil {
		return nil, err
	}
	ctx, cancel := c.rpc(ctx)
	defer cancel()
	all, err := c.sdk.Sandboxes().ListAll(ctx, c.opts.Workspace, v1.ListOptions{LabelSelector: sel})
	if err != nil {
		return nil, wrap("list sandboxes", err)
	}
	// Filter again locally: the selector is an optimization, and a server
	// (or fake) that ignores it must not widen the result.
	out := all[:0]
	for _, sb := range all {
		if sb != nil && hasLabels(sb.Labels, selector) {
			out = append(out, sb)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func hasLabels(have, want map[string]string) bool {
	for k, v := range want {
		if got, ok := have[k]; !ok || got != v {
			return false
		}
	}
	return true
}

func (c *client) DeleteSandbox(ctx context.Context, name string) (*DeletionResult, error) {
	if err := checkSandboxName(name); err != nil {
		return nil, err
	}
	ctx, cancel := c.rpc(ctx)
	defer cancel()
	res, err := c.sdk.Sandboxes().Delete(ctx, c.opts.Workspace, name, v1.DeleteOptions{AllowMissing: true})
	return res, wrap(fmt.Sprintf("delete sandbox %q", name), err)
}

func (c *client) StopSandbox(ctx context.Context, name string) (*Sandbox, error) {
	if err := checkSandboxName(name); err != nil {
		return nil, err
	}
	ctx, cancel := c.rpc(ctx)
	defer cancel()
	sb, err := c.sdk.Sandboxes().Stop(ctx, c.opts.Workspace, name)
	return sb, wrap(fmt.Sprintf("stop sandbox %q", name), err)
}

func (c *client) StartSandbox(ctx context.Context, name string) (*Sandbox, error) {
	if err := checkSandboxName(name); err != nil {
		return nil, err
	}
	ctx, cancel := c.rpc(ctx)
	defer cancel()
	sb, err := c.sdk.Sandboxes().Start(ctx, c.opts.Workspace, name)
	return sb, wrap(fmt.Sprintf("start sandbox %q", name), err)
}

// configState is the gateway's verdict on a sandbox configuration.
type configState int

const (
	configPending configState = iota
	configAccepted
	configRejected
)

// ConditionConfigurationReady is the sandbox condition OpenShell 0.1.x
// sets once the supervisor has loaded the effective configuration.
const ConditionConfigurationReady = "ConfigurationReady"

func configurationState(sb *Sandbox) (configState, string) {
	if adm := sb.Status.ConfigurationAdmission; adm != nil {
		switch adm.State {
		case types.ConfigurationAdmissionAccepted:
			return configAccepted, ""
		case types.ConfigurationAdmissionRejected:
			return configRejected, adm.Error
		default:
			return configPending, ""
		}
	}
	for _, cond := range sb.Status.Conditions {
		if cond.Type != ConditionConfigurationReady {
			continue
		}
		if strings.EqualFold(cond.Status, "True") {
			return configAccepted, ""
		}
		reason := strings.ToLower(cond.Reason)
		if strings.Contains(reason, "reject") || strings.Contains(reason, "invalid") {
			return configRejected, strings.TrimSpace(cond.Reason + " " + cond.Message)
		}
		return configPending, ""
	}
	// No admission reporting at all: the phase is the only signal.
	return configAccepted, ""
}

// maxWaitBackoff caps the pause between polls that failed transiently.
const maxWaitBackoff = 5 * time.Second

// transientWaitError reports a poll failure a wait rides out: the gateway
// is unreachable (restarting after a configuration change, doctor --fix
// or systemd's Restart=on-failure) or one poll timed out, while the wait
// itself still has time.
func transientWaitError(ctx context.Context, err error) bool {
	return gatewayDidNotAnswer(ctx, err)
}

// gatewayDidNotAnswer reports a call that failed because the gateway did
// not answer it: the gateway is unreachable or the call timed out, while
// ctx itself still has time.
func gatewayDidNotAnswer(ctx context.Context, err error) bool {
	return ctx.Err() == nil && (IsUnavailable(err) || IsDeadlineExceeded(err))
}

// retryWait runs poll until it succeeds, fails for good, or ctx ends,
// backing off after transient failures. Ending on ctx keeps the last
// failure in the message.
func (c *client) retryWait(ctx context.Context, poll func(context.Context) error) error {
	delay := c.opts.PollInterval
	for {
		err := poll(ctx)
		if err == nil || !transientWaitError(ctx, err) {
			return err
		}
		if serr := c.sleep(ctx, delay); serr != nil {
			return fmt.Errorf("%w (last poll: %v)", serr, err)
		}
		delay = min(delay*2, maxWaitBackoff)
	}
}

// getForWait is one wait poll, bounded like a unary call so that a hung
// call is retried instead of using up the wait.
func (c *client) getForWait(ctx context.Context, name string) (*Sandbox, error) {
	ctx, cancel := context.WithTimeout(ctx, c.opts.RPCTimeout)
	defer cancel()
	return c.sdk.Sandboxes().Get(ctx, c.opts.Workspace, name)
}

func (c *client) WaitReady(ctx context.Context, name string) (*Sandbox, error) {
	if err := checkSandboxName(name); err != nil {
		return nil, err
	}
	ctx, cancel := c.wait(ctx)
	defer cancel()
	var sb *Sandbox
	err := c.retryWait(ctx, func(ctx context.Context) (err error) {
		sb, err = c.sdk.Sandboxes().WaitReady(ctx, c.opts.Workspace, name, v1.WaitOptions{PollInterval: c.opts.PollInterval})
		return err
	})
	if err != nil {
		return nil, wrap(fmt.Sprintf("wait for sandbox %q", name), c.withFailureReason(ctx, name, err))
	}
	for {
		state, msg := configurationState(sb)
		switch state {
		case configAccepted:
			return sb, nil
		case configRejected:
			return sb, &ConfigurationRejectedError{Sandbox: name, Message: msg}
		}
		if err := c.sleep(ctx, c.opts.PollInterval); err != nil {
			return nil, wrap(fmt.Sprintf("wait for sandbox %q configuration", name), err)
		}
		err := c.retryWait(ctx, func(ctx context.Context) (err error) {
			sb, err = c.getForWait(ctx, name)
			return err
		})
		if err != nil {
			return nil, wrap(fmt.Sprintf("wait for sandbox %q configuration", name), err)
		}
		switch sb.Status.Phase {
		case PhaseError, PhaseDeleting, PhaseStopped, PhaseStopping:
			return sb, fmt.Errorf("openshell: sandbox %q entered phase %s while its configuration was pending", name, sb.Status.Phase)
		}
	}
}

// withFailureReason adds to a wait that ended with the sandbox in the
// error phase what OpenShell says went wrong: the SDK's error names only
// the phase ("sandbox x is in error state").
func (c *client) withFailureReason(ctx context.Context, name string, err error) error {
	if ctx.Err() != nil {
		return err
	}
	sb, gerr := c.getForWait(ctx, name)
	if gerr != nil || sb == nil || sb.Status.Phase != PhaseError {
		return err
	}
	if reason := failureReason(sb); reason != "" {
		return fmt.Errorf("%w; OpenShell says: %s", err, reason)
	}
	return err
}

// failureReason is what a sandbox's conditions that do not hold say
// ("reason: message" each, "; " between), on one line and without control
// characters, or "" when none says anything.
func failureReason(sb *Sandbox) string {
	var parts []string
	for _, cond := range sb.Status.Conditions {
		if strings.EqualFold(cond.Status, "True") {
			continue
		}
		var said []string
		for _, s := range []string{cond.Reason, cond.Message} {
			if s = strings.Join(strings.Fields(s), " "); s != "" {
				said = append(said, strings.Map(func(r rune) rune {
					if unicode.IsControl(r) {
						return unicode.ReplacementChar
					}
					return r
				}, s))
			}
		}
		if text := strings.Join(said, ": "); text != "" && !slices.Contains(parts, text) {
			parts = append(parts, text)
		}
	}
	return strings.Join(parts, "; ")
}

func (c *client) WaitStopped(ctx context.Context, name string) (*Sandbox, error) {
	if err := checkSandboxName(name); err != nil {
		return nil, err
	}
	ctx, cancel := c.wait(ctx)
	defer cancel()
	var sb *Sandbox
	err := c.retryWait(ctx, func(ctx context.Context) (err error) {
		sb, err = c.sdk.Sandboxes().WaitStopped(ctx, c.opts.Workspace, name, v1.WaitOptions{PollInterval: c.opts.PollInterval})
		return err
	})
	return sb, wrap(fmt.Sprintf("wait for sandbox %q to stop", name), err)
}

func (c *client) WaitDeleted(ctx context.Context, name string) error {
	if err := checkSandboxName(name); err != nil {
		return err
	}
	ctx, cancel := c.wait(ctx)
	defer cancel()
	for {
		gone := false
		err := c.retryWait(ctx, func(ctx context.Context) error {
			_, err := c.getForWait(ctx, name)
			if IsNotFound(err) {
				gone = true
				return nil
			}
			return err
		})
		if err != nil {
			return wrap(fmt.Sprintf("wait for sandbox %q deletion", name), err)
		}
		if gone {
			return nil
		}
		if err := c.sleep(ctx, c.opts.PollInterval); err != nil {
			return wrap(fmt.Sprintf("wait for sandbox %q deletion", name), err)
		}
	}
}

func (c *client) ListProfiles(ctx context.Context) ([]*ProviderProfile, error) {
	ctx, cancel := c.rpc(ctx)
	defer cancel()
	profiles, err := c.sdk.Providers().Profiles().ListAll(ctx, "")
	return profiles, wrap("list provider profiles", err)
}

func (c *client) GetProfile(ctx context.Context, id string) (*ProviderProfile, error) {
	if id == "" {
		return nil, fmt.Errorf("%w: empty profile id", ErrInvalidName)
	}
	ctx, cancel := c.rpc(ctx)
	defer cancel()
	p, err := c.sdk.Providers().Profiles().Get(ctx, "", id)
	return p, wrap(fmt.Sprintf("get provider profile %q", id), err)
}

func (c *client) LintProfiles(ctx context.Context, items []ProfileImportItem) (*LintResult, error) {
	ctx, cancel := c.rpc(ctx)
	defer cancel()
	res, err := c.sdk.Providers().Profiles().Lint(ctx, "", items)
	return res, wrap("lint provider profiles", err)
}

func (c *client) ImportProfiles(ctx context.Context, items []ProfileImportItem) (*ImportResult, error) {
	out := &ImportResult{Imported: len(items) > 0}
	for _, item := range items {
		res, err := c.importOne(ctx, item)
		if err != nil {
			return out, wrap(fmt.Sprintf("import provider profile %q", profileLabel(item)), err)
		}
		out.Diagnostics = append(out.Diagnostics, res.Diagnostics...)
		out.Profiles = append(out.Profiles, res.Profiles...)
		out.Imported = out.Imported && res.Imported
	}
	return out, nil
}

func (c *client) importOne(ctx context.Context, item ProfileImportItem) (*ImportResult, error) {
	ctx, cancel := c.rpc(ctx)
	defer cancel()
	return c.sdk.Providers().Profiles().Import(ctx, "", []ProfileImportItem{item})
}

func profileLabel(item ProfileImportItem) string {
	if item.Profile.ID != "" {
		return item.Profile.ID
	}
	return item.Source
}

func (c *client) UpdateProfile(ctx context.Context, id string, expectedResourceVersion uint64, item ProfileImportItem) (*UpdateResult, error) {
	if id == "" {
		return nil, fmt.Errorf("%w: empty profile id", ErrInvalidName)
	}
	ctx, cancel := c.rpc(ctx)
	defer cancel()
	res, err := c.sdk.Providers().Profiles().Update(ctx, "", id, expectedResourceVersion, item)
	return res, wrap(fmt.Sprintf("update provider profile %q", id), err)
}

func (c *client) DeleteProfile(ctx context.Context, id string) (*DeletionResult, error) {
	if id == "" {
		return nil, fmt.Errorf("%w: empty profile id", ErrInvalidName)
	}
	ctx, cancel := c.rpc(ctx)
	defer cancel()
	res, err := c.sdk.Providers().Profiles().Delete(ctx, "", id, v1.DeleteOptions{AllowMissing: true})
	return res, wrap(fmt.Sprintf("delete provider profile %q", id), err)
}

func (c *client) CreateProvider(ctx context.Context, provider *Provider) (*Provider, error) {
	if provider == nil {
		return nil, errors.New("openshell: nil provider")
	}
	if err := checkProviderName(provider.Name); err != nil {
		return nil, err
	}
	ctx, cancel := c.rpc(ctx)
	defer cancel()
	p, err := c.sdk.Providers().Create(ctx, c.opts.Workspace, provider)
	return p, wrap(fmt.Sprintf("create provider %q", provider.Name), err)
}

func (c *client) GetProvider(ctx context.Context, name string) (*Provider, error) {
	if err := checkProviderName(name); err != nil {
		return nil, err
	}
	ctx, cancel := c.rpc(ctx)
	defer cancel()
	p, err := c.sdk.Providers().Get(ctx, c.opts.Workspace, name)
	return p, wrap(fmt.Sprintf("get provider %q", name), err)
}

func (c *client) ListProviders(ctx context.Context) ([]*Provider, error) {
	ctx, cancel := c.rpc(ctx)
	defer cancel()
	ps, err := c.sdk.Providers().ListAll(ctx, c.opts.Workspace)
	if err != nil {
		return nil, wrap("list providers", err)
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].Name < ps[j].Name })
	return ps, nil
}

func (c *client) UpdateProvider(ctx context.Context, provider *Provider) (*Provider, error) {
	if provider == nil {
		return nil, errors.New("openshell: nil provider")
	}
	if err := checkProviderName(provider.Name); err != nil {
		return nil, err
	}
	ctx, cancel := c.rpc(ctx)
	defer cancel()
	p, err := c.sdk.Providers().Update(ctx, c.opts.Workspace, provider)
	return p, wrap(fmt.Sprintf("update provider %q", provider.Name), err)
}

func (c *client) EnsureProvider(ctx context.Context, provider *Provider) (*Provider, error) {
	if provider == nil {
		return nil, errors.New("openshell: nil provider")
	}
	if err := checkProviderName(provider.Name); err != nil {
		return nil, err
	}
	ctx, cancel := c.rpc(ctx)
	defer cancel()
	p, err := c.sdk.Providers().Ensure(ctx, c.opts.Workspace, provider)
	return p, wrap(fmt.Sprintf("ensure provider %q", provider.Name), err)
}

func (c *client) DeleteProvider(ctx context.Context, name string) (*DeletionResult, error) {
	if err := checkProviderName(name); err != nil {
		return nil, err
	}
	ctx, cancel := c.rpc(ctx)
	defer cancel()
	res, err := c.sdk.Providers().Delete(ctx, c.opts.Workspace, name, v1.DeleteOptions{AllowMissing: true})
	return res, wrap(fmt.Sprintf("delete provider %q", name), err)
}

func (c *client) AttachProvider(ctx context.Context, sandbox, provider string) (*AttachProviderResult, error) {
	if err := checkSandboxName(sandbox); err != nil {
		return nil, err
	}
	if err := checkProviderName(provider); err != nil {
		return nil, err
	}
	ctx, cancel := c.rpc(ctx)
	defer cancel()
	res, err := c.sdk.Sandboxes().AttachProvider(ctx, c.opts.Workspace, sandbox, provider, 0)
	return res, wrap(fmt.Sprintf("attach provider %q to %q", provider, sandbox), err)
}

func (c *client) DetachProvider(ctx context.Context, sandbox, provider string) (*DetachProviderResult, error) {
	if err := checkSandboxName(sandbox); err != nil {
		return nil, err
	}
	if err := checkProviderName(provider); err != nil {
		return nil, err
	}
	ctx, cancel := c.rpc(ctx)
	defer cancel()
	res, err := c.sdk.Sandboxes().DetachProvider(ctx, c.opts.Workspace, sandbox, provider, 0)
	return res, wrap(fmt.Sprintf("detach provider %q from %q", provider, sandbox), err)
}

func (c *client) GetDraft(ctx context.Context, sandbox, status string) (*DraftPolicy, error) {
	if err := checkSandboxName(sandbox); err != nil {
		return nil, err
	}
	ctx, cancel := c.rpc(ctx)
	defer cancel()
	var opts []v1.GetDraftOption
	if status != "" {
		opts = append(opts, v1.WithStatusFilter(status))
	}
	d, err := c.sdk.Policy().GetDraft(ctx, c.opts.Workspace, sandbox, opts...)
	return d, wrap(fmt.Sprintf("get draft policy of %q", sandbox), err)
}

func (c *client) ApproveDraftChunk(ctx context.Context, sandbox, chunkID, reviewToken string) (*ApproveResult, error) {
	if err := checkSandboxName(sandbox); err != nil {
		return nil, err
	}
	if chunkID == "" {
		return nil, fmt.Errorf("%w: empty draft chunk id", ErrInvalidName)
	}
	ctx, cancel := c.rpc(ctx)
	defer cancel()
	res, err := c.sdk.Policy().ApproveDraftChunk(ctx, c.opts.Workspace, sandbox, chunkID, reviewToken)
	return res, wrap(fmt.Sprintf("approve draft chunk %q of %q", chunkID, sandbox), err)
}

func (c *client) ApproveDraftChunks(ctx context.Context, sandbox string, approvals []DraftChunkApproval) (*ApproveAllResult, error) {
	if err := checkSandboxName(sandbox); err != nil {
		return nil, err
	}
	if len(approvals) == 0 {
		return &ApproveAllResult{}, nil
	}
	for _, a := range approvals {
		if a.ChunkID == "" {
			return nil, fmt.Errorf("%w: empty draft chunk id", ErrInvalidName)
		}
	}
	ctx, cancel := c.rpc(ctx)
	defer cancel()
	res, err := c.sdk.Policy().ApproveAllDraftChunks(ctx, c.opts.Workspace, sandbox, v1.WithDraftApprovals(approvals...))
	return res, wrap(fmt.Sprintf("approve %d draft chunks of %q", len(approvals), sandbox), err)
}

func (c *client) RejectDraftChunk(ctx context.Context, sandbox, chunkID, reason string) error {
	if err := checkSandboxName(sandbox); err != nil {
		return err
	}
	if chunkID == "" {
		return fmt.Errorf("%w: empty draft chunk id", ErrInvalidName)
	}
	ctx, cancel := c.rpc(ctx)
	defer cancel()
	return wrap(fmt.Sprintf("reject draft chunk %q of %q", chunkID, sandbox),
		c.sdk.Policy().RejectDraftChunk(ctx, c.opts.Workspace, sandbox, chunkID, reason))
}

func (c *client) SandboxConfig(ctx context.Context, sandbox string) (*SandboxConfig, error) {
	if err := checkSandboxName(sandbox); err != nil {
		return nil, err
	}
	ctx, cancel := c.rpc(ctx)
	defer cancel()
	cfg, err := c.sdk.Config().GetSandbox(ctx, c.opts.Workspace, sandbox)
	return cfg, wrap(fmt.Sprintf("get config of %q", sandbox), err)
}

func (c *client) SetPolicy(ctx context.Context, sandbox string, policy *SandboxPolicy, opts PolicyUpdateOptions) (*ConfigUpdateResult, error) {
	if err := checkSandboxName(sandbox); err != nil {
		return nil, err
	}
	if policy == nil {
		return nil, errors.New("openshell: nil policy")
	}
	return c.updateConfig(ctx, fmt.Sprintf("set policy of %q", sandbox), &v1.ConfigUpdate{
		Name:                    sandbox,
		Policy:                  policy,
		ExpectedResourceVersion: opts.ExpectedResourceVersion,
		Annotations:             opts.Annotations,
	})
}

func (c *client) MergePolicy(ctx context.Context, sandbox string, ops []PolicyMergeOperation, opts PolicyUpdateOptions) (*ConfigUpdateResult, error) {
	if err := checkSandboxName(sandbox); err != nil {
		return nil, err
	}
	if len(ops) == 0 {
		return nil, errors.New("openshell: no policy merge operations")
	}
	for i, op := range ops {
		if n := countMergeFields(op); n != 1 {
			return nil, fmt.Errorf("openshell: merge operation %d sets %d operations, want exactly one", i, n)
		}
	}
	return c.updateConfig(ctx, fmt.Sprintf("merge policy of %q", sandbox), &v1.ConfigUpdate{
		Name:                    sandbox,
		MergeOperations:         ops,
		ExpectedResourceVersion: opts.ExpectedResourceVersion,
		Annotations:             opts.Annotations,
	})
}

func countMergeFields(op PolicyMergeOperation) int {
	n := 0
	for _, set := range []bool{op.AddRule != nil, op.RemoveEndpoint != nil, op.RemoveRule != nil,
		op.AddDenyRules != nil, op.AddAllowRules != nil, op.RemoveBinary != nil} {
		if set {
			n++
		}
	}
	return n
}

func (c *client) updateConfig(ctx context.Context, op string, update *v1.ConfigUpdate) (*ConfigUpdateResult, error) {
	ctx, cancel := c.rpc(ctx)
	defer cancel()
	res, err := c.sdk.Config().Update(ctx, c.opts.Workspace, update)
	return res, wrap(op, err)
}

func (c *client) PolicyStatus(ctx context.Context, sandbox string, version uint32) (*PolicyStatusResult, error) {
	if err := checkSandboxName(sandbox); err != nil {
		return nil, err
	}
	ctx, cancel := c.rpc(ctx)
	defer cancel()
	var opts []v1.GetStatusOption
	if version > 0 {
		opts = append(opts, v1.WithVersion(version))
	}
	res, err := c.sdk.Policy().GetStatus(ctx, c.opts.Workspace, sandbox, opts...)
	return res, wrap(fmt.Sprintf("get policy status of %q", sandbox), err)
}

func (c *client) GlobalPolicy(ctx context.Context) (*PolicyRevision, error) {
	ctx, cancel := c.rpc(ctx)
	defer cancel()
	res, err := c.sdk.Policy().GetStatus(ctx, "", "", v1.WithStatusGlobal(true))
	if IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, wrap("get global policy", err)
	}
	switch res.Revision.Status {
	case v1.PolicyLoadStatusLoaded, v1.PolicyLoadStatusPending:
		rev := res.Revision
		return &rev, nil
	default:
		return nil, nil
	}
}

func (c *client) GatewaySettings(ctx context.Context) (*GatewayConfig, error) {
	ctx, cancel := c.rpc(ctx)
	defer cancel()
	cfg, err := c.sdk.Config().GetGateway(ctx)
	return cfg, wrap("get gateway settings", err)
}

func (c *client) UpdateSetting(ctx context.Context, u SettingUpdate) (*ConfigUpdateResult, error) {
	if u.Key == "" {
		return nil, errors.New("openshell: setting key is required")
	}
	if (u.Sandbox == "") == !u.Global {
		return nil, errors.New("openshell: a setting update needs exactly one of a sandbox or global scope")
	}
	if (u.Value == nil) == !u.Delete {
		return nil, errors.New("openshell: a setting update needs exactly one of a value or delete")
	}
	if u.Delete && !u.Global {
		return nil, errors.New("openshell: OpenShell only deletes gateway-global settings")
	}
	if u.Sandbox != "" {
		if err := checkSandboxName(u.Sandbox); err != nil {
			return nil, err
		}
	}
	scope := "global"
	if u.Sandbox != "" {
		scope = fmt.Sprintf("sandbox %q", u.Sandbox)
	}
	return c.updateConfig(ctx, fmt.Sprintf("update setting %q (%s)", u.Key, scope), &v1.ConfigUpdate{
		Name:          u.Sandbox,
		Global:        u.Global,
		SettingKey:    u.Key,
		SettingValue:  u.Value,
		DeleteSetting: u.Delete,
	})
}

func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
