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

// Package openshelltest provides an in-memory OpenShell gateway for tests
// of code that drives openshell.Client.
//
// Fake builds on the SDK's own fake (github.com/NVIDIA/OpenShell/sdk/go/
// openshell/v1/fake) for sandbox, provider and workspace storage and adds
// what that fake leaves unimplemented and DefenseClaw needs: scripted exec,
// sandbox configuration (policy replace and merge operations, settings,
// global policy), the draft-policy inbox, provider profiles, configuration
// admission, and per-method error injection.
//
//	f := openshelltest.New()
//	c := f.Client(openshell.ClientOptions{})
//	f.HandleExec(func(ctx context.Context, call openshelltest.ExecCall) openshelltest.ExecResponse {
//		return openshelltest.ExecResponse{Stdout: []byte("ok\n")}
//	})
package openshelltest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/fake"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// Method names accepted by FailNext and Intercept.
const (
	MethodCreateSandbox     = "Sandboxes.Create"
	MethodGetSandbox        = "Sandboxes.Get"
	MethodListSandboxes     = "Sandboxes.List"
	MethodDeleteSandbox     = "Sandboxes.Delete"
	MethodStopSandbox       = "Sandboxes.Stop"
	MethodStartSandbox      = "Sandboxes.Start"
	MethodWaitReady         = "Sandboxes.WaitReady"
	MethodWaitStopped       = "Sandboxes.WaitStopped"
	MethodAttachProvider    = "Sandboxes.AttachProvider"
	MethodDetachProvider    = "Sandboxes.DetachProvider"
	MethodExec              = "Exec.Stream"
	MethodHealth            = "Health.Check"
	MethodGatewayInfo       = "Health.GetGatewayInfo"
	MethodCreateProvider    = "Providers.Create"
	MethodGetProvider       = "Providers.Get"
	MethodListProviders     = "Providers.List"
	MethodUpdateProvider    = "Providers.Update"
	MethodDeleteProvider    = "Providers.Delete"
	MethodListProfiles      = "Profiles.List"
	MethodGetProfile        = "Profiles.Get"
	MethodLintProfiles      = "Profiles.Lint"
	MethodImportProfiles    = "Profiles.Import"
	MethodUpdateProfile     = "Profiles.Update"
	MethodDeleteProfile     = "Profiles.Delete"
	MethodGetSandboxConfig  = "Config.GetSandbox"
	MethodGetGatewayConfig  = "Config.GetGateway"
	MethodUpdateConfig      = "Config.Update"
	MethodGetDraft          = "Policy.GetDraft"
	MethodApproveDraftChunk = "Policy.ApproveDraftChunk"
	MethodApproveAllChunks  = "Policy.ApproveAllDraftChunks"
	MethodRejectDraftChunk  = "Policy.RejectDraftChunk"
	MethodPolicyStatus      = "Policy.GetStatus"
	MethodListPolicies      = "Policy.List"
)

// Fake is an in-memory OpenShell gateway implementing v1.ClientInterface.
// It is safe for concurrent use.
type Fake struct {
	sdk *fake.Client

	mu        sync.Mutex
	intercept func(method string) error
	failures  map[string][]error
	calls     map[string]int
	closed    bool

	health      types.HealthResult
	gatewayInfo types.GatewayInfo

	sandboxes *sandboxClient
	providers *providerClient
	exec      *execClient
	cfg       *configClient
	policy    *policyClient

	execHandler ExecHandler
	execCalls   []ExecCall

	// per "workspace/name" sandbox state
	states map[string]*sandboxState

	globalSettings    map[string]types.SettingValue
	globalSettingsRev uint64
	globalRevisions   []types.SandboxPolicyRevision

	profiles map[string]*types.ProviderProfile // keyed by id (platform scope)

	now func() time.Time
}

// sandboxState is the configuration the SDK fake does not model.
type sandboxState struct {
	policy          *types.SandboxPolicy
	createPolicy    *types.SandboxPolicy
	policyVersion   uint32
	revisions       []types.SandboxPolicyRevision
	settings        map[string]types.SettingValue
	settingsRev     uint64
	configRev       uint64
	admission       types.ConfigurationAdmissionState
	admissionError  string
	chunks          []types.PolicyChunk
	draftVersion    uint64
	history         []types.DraftHistoryEntry
	nextChunkNumber int
}

// Option configures a Fake.
type Option func(*Fake)

// WithHealth sets the health answer (default healthy, version
// openshell.SupportedMin).
func WithHealth(healthy bool, version string) Option {
	return func(f *Fake) { f.health = types.HealthResult{Healthy: healthy, Version: version} }
}

// WithGatewayInfo sets the gateway info answer.
func WithGatewayInfo(info types.GatewayInfo) Option {
	return func(f *Fake) { f.gatewayInfo = info }
}

// New returns an empty, healthy fake gateway with the docker driver.
func New(opts ...Option) *Fake {
	f := &Fake{
		sdk:            fake.NewClient(),
		failures:       map[string][]error{},
		calls:          map[string]int{},
		health:         types.HealthResult{Healthy: true, Version: openshell.SupportedMin},
		states:         map[string]*sandboxState{},
		globalSettings: map[string]types.SettingValue{},
		profiles:       map[string]*types.ProviderProfile{},
		now:            time.Now,
		gatewayInfo: types.GatewayInfo{
			Status:         types.ServiceStatusHealthy,
			Version:        openshell.SupportedMin,
			ComputeDrivers: []types.ComputeDriverInfo{{Name: "docker", DriverName: "docker", DriverVersion: openshell.SupportedMin}},
		},
	}
	f.sandboxes = &sandboxClient{f: f, inner: f.sdk.Sandboxes()}
	f.providers = &providerClient{f: f, inner: f.sdk.Providers(), profiles: &profileClient{f: f}}
	f.exec = &execClient{f: f}
	f.cfg = &configClient{f: f}
	f.policy = &policyClient{f: f}
	for _, o := range opts {
		o(f)
	}
	return f
}

// Client wraps the fake in the production openshell.Client.
func (f *Fake) Client(opts openshell.ClientOptions) openshell.Client {
	if opts.PollInterval == 0 {
		opts.PollInterval = time.Millisecond
	}
	return openshell.NewClient(f, opts)
}

// SDK returns the underlying SDK fake, for seeding fixtures directly
// (AddSandbox, AddProvider, AddWorkspace). Writes through it bypass error
// injection.
func (f *Fake) SDK() *fake.Client { return f.sdk }

// Sandboxes returns the sandbox sub-client.
func (f *Fake) Sandboxes() v1.SandboxInterface { return f.sandboxes }

// SandboxTemplates returns the SDK fake's template sub-client.
func (f *Fake) SandboxTemplates() v1.SandboxTemplateInterface { return f.sdk.SandboxTemplates() }

// CreateSandboxFromTemplate delegates to the SDK fake.
func (f *Fake) CreateSandboxFromTemplate(ctx context.Context, workspace, name, templateName string, spec *types.SandboxSpec, labels map[string]string, opts ...types.CreateOptions) (*types.Sandbox, error) {
	return f.sdk.CreateSandboxFromTemplate(ctx, workspace, name, templateName, spec, labels, opts...)
}

// Services returns the SDK fake's service sub-client.
func (f *Fake) Services() v1.ServiceInterface { return f.sdk.Services() }

// Files returns the SDK fake's file sub-client (unimplemented upstream too).
func (f *Fake) Files() v1.FileInterface { return f.sdk.Files() }

// SSH returns the SDK fake's SSH sub-client.
func (f *Fake) SSH() v1.SSHInterface { return f.sdk.SSH() }

// TCP returns the SDK fake's TCP sub-client.
func (f *Fake) TCP() v1.TCPInterface { return f.sdk.TCP() }

// Workspaces returns the SDK fake's workspace sub-client.
func (f *Fake) Workspaces() v1.WorkspaceInterface { return f.sdk.Workspaces() }

// Close closes the fake; later calls fail with Unavailable.
func (f *Fake) Close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	return f.sdk.Close()
}

// Providers returns the provider sub-client (with profile support).
func (f *Fake) Providers() v1.ProviderInterface { return f.providers }

// Exec returns the scripted exec sub-client.
func (f *Fake) Exec() v1.ExecInterface { return f.exec }

// Health returns the health sub-client.
func (f *Fake) Health() v1.HealthInterface { return healthClient{f: f} }

// Config returns the configuration sub-client.
func (f *Fake) Config() v1.ConfigInterface { return f.cfg }

// Policy returns the draft and revision sub-client.
func (f *Fake) Policy() v1.PolicyInterface { return f.policy }

var _ v1.ClientInterface = (*Fake)(nil)

// Intercept installs a hook that runs before every operation; a non-nil
// return fails the operation with that error.
func (f *Fake) Intercept(hook func(method string) error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.intercept = hook
}

// FailNext makes the next call of method return err. Calls queue in
// order.
func (f *Fake) FailNext(method string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failures[method] = append(f.failures[method], err)
}

// Calls reports how many times method was invoked.
func (f *Fake) Calls(method string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[method]
}

// SetHealth changes the health answer.
func (f *Fake) SetHealth(healthy bool, version string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.health = types.HealthResult{Healthy: healthy, Version: version}
}

// enter records a call and returns an injected failure, if any.
func (f *Fake) enter(method string) error {
	f.mu.Lock()
	f.calls[method]++
	if f.closed {
		f.mu.Unlock()
		return statusErr(types.ErrorUnavailable, "client is closed")
	}
	hook := f.intercept
	var err error
	if q := f.failures[method]; len(q) > 0 {
		err, f.failures[method] = q[0], q[1:]
	}
	f.mu.Unlock()
	if err != nil {
		return err
	}
	if hook != nil {
		return hook(method)
	}
	return nil
}

func key(workspace, name string) string { return workspace + "/" + name }

// state returns the configuration state of a sandbox; the caller holds mu.
func (f *Fake) state(workspace, name string) *sandboxState {
	st := f.states[key(workspace, name)]
	if st == nil {
		st = &sandboxState{settings: map[string]types.SettingValue{}, admission: types.ConfigurationAdmissionAccepted}
		f.states[key(workspace, name)] = st
	}
	return st
}

// SetAdmission makes the next WaitReady of a sandbox report the given
// configuration admission (e.g. types.ConfigurationAdmissionRejected).
func (f *Fake) SetAdmission(workspace, name string, state types.ConfigurationAdmissionState, message string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.state(workspace, name)
	st.admission, st.admissionError = state, message
}

// SetPhase forces a sandbox phase, as the gateway would on a driver event.
func (f *Fake) SetPhase(workspace, name string, phase types.SandboxPhase) error {
	sb, err := f.sdk.Sandboxes().Get(context.Background(), workspace, name)
	if err != nil {
		return err
	}
	sb.Status.Phase = phase
	sb.ResourceVersion++
	f.sdk.AddSandbox(workspace, sb)
	return nil
}

// SandboxPolicy returns a copy of a sandbox's current policy.
func (f *Fake) SandboxPolicy(workspace, name string) (*types.SandboxPolicy, uint32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.states[key(workspace, name)]
	if st == nil {
		return nil, 0
	}
	return clonePolicy(st.policy), st.policyVersion
}

// SandboxSettings returns a copy of a sandbox's own settings.
func (f *Fake) SandboxSettings(workspace, name string) map[string]types.SettingValue {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]types.SettingValue{}
	if st := f.states[key(workspace, name)]; st != nil {
		for k, v := range st.settings {
			out[k] = v
		}
	}
	return out
}

// SetGlobalPolicy installs (or, with nil, clears) a gateway-global policy.
func (f *Fake) SetGlobalPolicy(policy *types.SandboxPolicy) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.globalRevisions {
		if f.globalRevisions[i].Status == types.PolicyLoadStatusLoaded {
			f.globalRevisions[i].Status = types.PolicyLoadStatusSuperseded
		}
	}
	if policy == nil {
		return
	}
	version := uint32(len(f.globalRevisions) + 1)
	f.globalRevisions = append(f.globalRevisions, types.SandboxPolicyRevision{
		Version: version, PolicyHash: policyHash(policy), Status: types.PolicyLoadStatusLoaded,
		CreatedAt: f.now(), LoadedAt: f.now(), Policy: clonePolicy(policy),
	})
}

// AddDraftChunk queues a proposed rule in a sandbox's draft inbox and
// returns its id. Empty ID and Status default to a generated id and
// "pending".
func (f *Fake) AddDraftChunk(workspace, sandbox string, chunk types.PolicyChunk) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.state(workspace, sandbox)
	st.nextChunkNumber++
	if chunk.ID == "" {
		chunk.ID = fmt.Sprintf("chunk-%d", st.nextChunkNumber)
	}
	if chunk.Status == "" {
		chunk.Status = "pending"
	}
	if chunk.CreatedAt.IsZero() {
		chunk.CreatedAt = f.now()
	}
	chunk.ProposedRule = cloneRule(chunk.ProposedRule)
	st.chunks = append(st.chunks, chunk)
	st.draftVersion++
	return chunk.ID
}

// DraftChunk returns a copy of one draft chunk.
func (f *Fake) DraftChunk(workspace, sandbox, id string) (types.PolicyChunk, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.states[key(workspace, sandbox)]
	if st == nil {
		return types.PolicyChunk{}, false
	}
	for _, c := range st.chunks {
		if c.ID == id {
			c.ProposedRule = cloneRule(c.ProposedRule)
			return c, true
		}
	}
	return types.PolicyChunk{}, false
}

func statusErr(code types.ErrorCode, format string, args ...any) error {
	return &types.StatusError{Code: code, Message: fmt.Sprintf(format, args...)}
}

// clonePolicy deep-copies through JSON; every SandboxPolicy field is plain
// exported data.
func clonePolicy(p *types.SandboxPolicy) *types.SandboxPolicy {
	if p == nil {
		return nil
	}
	data, err := json.Marshal(p)
	if err != nil {
		panic(fmt.Sprintf("openshelltest: clone policy: %v", err))
	}
	var out types.SandboxPolicy
	if err := json.Unmarshal(data, &out); err != nil {
		panic(fmt.Sprintf("openshelltest: clone policy: %v", err))
	}
	return &out
}

func cloneRule(r *types.NetworkPolicyRule) *types.NetworkPolicyRule {
	if r == nil {
		return nil
	}
	data, _ := json.Marshal(r)
	var out types.NetworkPolicyRule
	_ = json.Unmarshal(data, &out)
	return &out
}

func policyHash(p *types.SandboxPolicy) string {
	data, _ := json.Marshal(p)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
