// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
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

package gateway

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor"
	"github.com/defenseclaw/defenseclaw/internal/sensor/acquire"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
)

// aiRuntimeResponse is the wire shape of GET /api/v1/ai-usage/runtime.
//
// Coverage travels with the findings rather than in a separate call, because
// a caller that reads findings without reading coverage cannot tell a quiet
// host from a blind sensor -- and that is the one confusion this subsystem
// exists to prevent.
type aiRuntimeResponse struct {
	Enabled                 bool               `json:"enabled"`
	ScannedAt               string             `json:"scanned_at,omitempty"`
	Findings                []aiRuntimeFinding `json:"findings"`
	Planes                  []aiRuntimePlane   `json:"planes"`
	ProcessesObserved       int                `json:"processes_observed"`
	ProcessesSkipped        int                `json:"processes_skipped"`
	ConnectionsObserved     int                `json:"connections_observed"`
	ConnectionsUnattributed int                `json:"connections_unattributed"`
	HostPlaneObservations   int64              `json:"host_plane_observations"`
	HostPlaneGated          int64              `json:"host_plane_gated"`
	// HostPlaneContainerEvents counts the host-plane events of container
	// processes, which never join a host agent session.
	HostPlaneContainerEvents int64 `json:"host_plane_container_events,omitempty"`
	// HostPlaneHookUnexpected counts processes under a verified DefenseClaw
	// hook that are not its own tools.
	HostPlaneHookUnexpected int64    `json:"host_plane_hook_unexpected,omitempty"`
	Degraded                bool     `json:"degraded"`
	DegradedReasons         []string `json:"degraded_reasons,omitempty"`
}

type aiRuntimeFinding struct {
	FindingID string              `json:"finding_id"`
	PID       int                 `json:"pid"`
	Process   string              `json:"process"`
	Cmdline   string              `json:"cmdline,omitempty"`
	User      string              `json:"user,omitempty"`
	AgentName string              `json:"agent_name,omitempty"`
	Score     int                 `json:"score"`
	Severity  string              `json:"severity"`
	Signals   []aiRuntimeSignal   `json:"signals"`
	Providers []aiRuntimeProvider `json:"providers,omitempty"`
	// Correlation is always present, including when the inventory had nothing
	// to say and why. Omitting it on "unobserved" would let a reader mistake
	// blindness for agreement.
	Correlation aiRuntimeCorrelation `json:"correlation"`
	FirstSeen   string               `json:"first_seen,omitempty"`
	LastSeen    string               `json:"last_seen,omitempty"`

	// The fields below describe a host-plane session's agent root.

	Exe string `json:"exe,omitempty"`
	// UserID is the root's kernel uid; LoginID its audit login uid, given
	// only when the uid is root's.
	UserID  string `json:"user_id,omitempty"`
	LoginID string `json:"login_id,omitempty"`
	// Connector and AgentIdentityID name the CLI connector install the root
	// is, where the gateway derives agent identities; IdentityVerified is
	// true for a root the sensor helper enrolled for that uid.
	Connector        string `json:"connector,omitempty"`
	AgentIdentityID  string `json:"agent_identity_id,omitempty"`
	IdentityVerified bool   `json:"identity_verified,omitempty"`
	// NotEnforcedReason says why no kernel control applies to this root:
	// ide_hosted, heuristic_root, not_enrolled, or the helper's reason for
	// an observe-only user.
	NotEnforcedReason string              `json:"not_enforced_reason,omitempty"`
	Activities        []aiRuntimeActivity `json:"activities,omitempty"`
}

// aiRuntimeActivity is one tactic of a host-plane session.
type aiRuntimeActivity struct {
	Tactic      string `json:"tactic"`
	EventSource string `json:"event_source,omitempty"`
	UserID      string `json:"user_id,omitempty"`
	LoginID     string `json:"login_id,omitempty"`
	// KernelOutcome is what a DefenseClaw kernel control did: observed,
	// would_block or blocked.
	KernelOutcome string `json:"kernel_outcome,omitempty"`
	KernelControl string `json:"kernel_control,omitempty"`
	// HookSeen is set on managed hosts: whether a hook decision covered the
	// tool call the activity came from. HookJoin says how it was matched
	// (exact or temporal), with the decision's session and tool call.
	HookSeen         *bool  `json:"hook_seen,omitempty"`
	HookJoin         string `json:"hook_join,omitempty"`
	SessionID        string `json:"session_id,omitempty"`
	ToolInvocationID string `json:"tool_invocation_id,omitempty"`
}

type aiRuntimeSignal struct {
	ID     string `json:"id"`
	Title  string `json:"title,omitempty"`
	Detail string `json:"detail,omitempty"`
	Weight int    `json:"weight"`
}

type aiRuntimeProvider struct {
	Hostname          string  `json:"hostname"`
	Address           string  `json:"address,omitempty"`
	Port              int     `json:"port,omitempty"`
	Category          string  `json:"category,omitempty"`
	Confidence        float64 `json:"confidence,omitempty"`
	AttributionSource string  `json:"attribution_source,omitempty"`
}

type aiRuntimeCorrelation struct {
	Verdict          string   `json:"verdict"`
	Reason           string   `json:"reason"`
	MatchedSignalIDs []string `json:"matched_signal_ids,omitempty"`
	Categories       []string `json:"categories,omitempty"`
}

type aiRuntimePlane struct {
	Plane     string `json:"plane"`
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Running   bool   `json:"running"`
	Mechanism string `json:"mechanism,omitempty"`
	Reason    string `json:"reason,omitempty"`
	// Backend is Plane C's process backend on the managed Linux sensor
	// helper; absent everywhere else.
	Backend *aiRuntimeBackend `json:"backend,omitempty"`
}

// aiRuntimeBackend is the wire shape of Plane C's backend, in the runtime
// API and in /health ai_runtime.details.planes.c.backend. The CLI, the
// doctor row and the TUI read these keys.
type aiRuntimeBackend struct {
	// Kind is tetragon or native.
	Kind    string `json:"kind"`
	Version string `json:"version,omitempty"`
	// Mode is the effective enterprise.tetragon mode the helper runs.
	Mode   string `json:"mode,omitempty"`
	Socket string `json:"socket,omitempty"`
	// EventsLost is what the backend reported losing; LossKnown is false
	// when Tetragon's own counters could not be read, and readers show the
	// loss as unknown then.
	EventsLost int64 `json:"events_lost"`
	LossKnown  bool  `json:"loss_known"`
	// FallbackReason is why the native backend runs although Tetragon is
	// wanted: a reason code, a colon and the detail.
	FallbackReason string                  `json:"fallback_reason,omitempty"`
	Policies       []aiRuntimeKernelPolicy `json:"policies,omitempty"`
	// KernelFloor summarizes the kernel controls' scope per user, when the
	// helper's reconciler runs (observe or enforce).
	KernelFloor *aiRuntimeKernelFloor `json:"kernel_floor,omitempty"`
}

type aiRuntimeKernelPolicy struct {
	Name  string `json:"name"`
	Mode  string `json:"mode,omitempty"`
	State string `json:"state,omitempty"`
	Error string `json:"error,omitempty"`
}

type aiRuntimeKernelFloor struct {
	Mode          string `json:"mode"`
	EnrolledUsers int    `json:"enrolled_users"`
	EnforcedUsers int    `json:"enforced_users"`
	BurnInUsers   int    `json:"burn_in_users"`
	PausedUntil   string `json:"paused_until,omitempty"`
}

// handleAIRuntime serves the most recent runtime-plane snapshot.
func (a *APIServer) handleAIRuntime(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	service, release := a.leaseAIRuntime()
	defer release()
	if service == nil {
		a.writeJSON(w, http.StatusOK, aiRuntimeResponse{
			Enabled: false, Findings: []aiRuntimeFinding{}, Planes: []aiRuntimePlane{},
		})
		return
	}
	a.writeJSON(w, http.StatusOK, renderAIRuntimeSnapshot(service.Snapshot()))
}

// handleAIRuntimeScan triggers an immediate poll and returns its result.
func (a *APIServer) handleAIRuntimeScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	service, release := a.leaseAIRuntime()
	defer release()
	if service == nil {
		// 503 rather than 404: the route exists, the subsystem is switched
		// off. The CLI turns this into an actionable "enable it first".
		http.Error(w, "ai_discovery.runtime is disabled in config", http.StatusServiceUnavailable)
		return
	}
	a.writeJSON(w, http.StatusOK, renderAIRuntimeSnapshot(service.Poll(r.Context())))
}

func renderAIRuntimeSnapshot(snapshot sensor.Snapshot) aiRuntimeResponse {
	response := aiRuntimeResponse{
		Enabled:                  true,
		Findings:                 make([]aiRuntimeFinding, 0, len(snapshot.Findings)),
		Planes:                   make([]aiRuntimePlane, 0, len(snapshot.Planes)),
		ProcessesObserved:        snapshot.ProcessesObserved,
		ProcessesSkipped:         snapshot.ProcessesSkipped,
		ConnectionsObserved:      snapshot.ConnectionsObserved,
		ConnectionsUnattributed:  snapshot.ConnectionsUnattributed,
		HostPlaneObservations:    snapshot.HostPlaneObservations,
		HostPlaneGated:           snapshot.HostPlaneGated,
		HostPlaneContainerEvents: snapshot.HostPlaneContainerEvents,
		HostPlaneHookUnexpected:  snapshot.HostPlaneHookUnexpected,
		Degraded:                 snapshot.Degraded,
	}
	if !snapshot.ScannedAt.IsZero() {
		response.ScannedAt = snapshot.ScannedAt.UTC().Format(time.RFC3339)
	}
	if snapshot.Degraded {
		response.DegradedReasons = sensor.SortedDegradedReasons(snapshot)
	}
	for _, plane := range snapshot.Planes {
		response.Planes = append(response.Planes, aiRuntimePlane{
			Plane: string(plane.Plane), Name: plane.Plane.Name(),
			Available: plane.Available, Running: plane.Running,
			Mechanism: plane.Mechanism, Reason: plane.Reason,
			Backend: renderAIRuntimeBackend(plane.Backend, snapshot.Kernel),
		})
	}
	for _, finding := range snapshot.Findings {
		identity := runtimeFindingIdentity(finding, snapshot.Kernel)
		rendered := aiRuntimeFinding{
			FindingID: finding.FindingID, PID: finding.PID, Process: finding.Process,
			Cmdline: finding.Cmdline, User: finding.User, AgentName: finding.AgentName,
			Score: finding.Score, Severity: string(finding.Severity),
			Signals: make([]aiRuntimeSignal, 0, len(finding.Signals)),
			Correlation: aiRuntimeCorrelation{
				Verdict:          string(finding.Correlation.Verdict),
				Reason:           finding.Correlation.Reason,
				MatchedSignalIDs: finding.Correlation.MatchedSignalIDs,
				Categories:       finding.Correlation.Categories,
			},
			Exe: finding.Exe, UserID: identity.UserID, LoginID: identity.LoginID,
			Connector: identity.Connector, AgentIdentityID: identity.AgentIdentityID,
			IdentityVerified:  identity.Verified,
			NotEnforcedReason: runtimeNotEnforcedReason(finding, snapshot.Kernel),
		}
		for _, signal := range finding.Signals {
			rendered.Signals = append(rendered.Signals, aiRuntimeSignal{
				ID: signal.ID, Title: signal.Title, Detail: signal.Detail, Weight: signal.Weight,
			})
		}
		for _, provider := range finding.Providers {
			rendered.Providers = append(rendered.Providers, aiRuntimeProvider{
				Hostname: provider.Hostname, Address: provider.Address, Port: provider.Port,
				Category: provider.Category, Confidence: provider.Confidence,
				AttributionSource: provider.AttributionSource,
			})
		}
		for _, activity := range finding.Activities {
			rendered.Activities = append(rendered.Activities, renderAIRuntimeActivity(finding, activity))
		}
		if !finding.FirstSeen.IsZero() {
			rendered.FirstSeen = finding.FirstSeen.UTC().Format(time.RFC3339)
		}
		if !finding.LastSeen.IsZero() {
			rendered.LastSeen = finding.LastSeen.UTC().Format(time.RFC3339)
		}
		response.Findings = append(response.Findings, rendered)
	}
	return response
}

func renderAIRuntimeActivity(finding sensor.Finding, activity sensor.RuntimeActivity) aiRuntimeActivity {
	identity := runtimeActivityIdentity(finding, activity)
	rendered := aiRuntimeActivity{
		Tactic: string(activity.Tactic), EventSource: string(activity.Source),
		UserID: identity.UserID, LoginID: identity.LoginID,
		KernelOutcome: string(activity.Outcome), KernelControl: activity.Control,
	}
	if activity.Hook != nil {
		seen := activity.Hook.Seen
		rendered.HookSeen = &seen
		if seen {
			rendered.HookJoin = activity.Hook.Confidence
			rendered.SessionID = activity.Hook.SessionID
			rendered.ToolInvocationID = activity.Hook.ToolInvocationID
		}
	}
	return rendered
}

// renderAIRuntimeBackend is Plane C's backend as the runtime API and /health
// publish it, with the kernel floor when the helper's reconciler runs. nil
// when the plane reports no backend: every gateway but a managed Linux one
// whose helper knows about Tetragon.
func renderAIRuntimeBackend(backend *plane.Backend, kernel *sensor.KernelState) *aiRuntimeBackend {
	if backend == nil {
		return nil
	}
	rendered := &aiRuntimeBackend{
		Kind: backend.Kind, Version: backend.Version, Mode: backend.Mode, Socket: backend.Socket,
		EventsLost: backend.EventsLost, LossKnown: backend.LossKnown, FallbackReason: backend.FallbackReason,
	}
	for _, policy := range backend.Policies {
		rendered.Policies = append(rendered.Policies, aiRuntimeKernelPolicy{
			Name: policy.Name, Mode: policy.Mode, State: policy.State, Error: policy.Error,
		})
	}
	rendered.KernelFloor = renderKernelFloor(kernel)
	return rendered
}

// renderKernelFloor counts the enrolled users by enforcing scope.
func renderKernelFloor(kernel *sensor.KernelState) *aiRuntimeKernelFloor {
	if kernel == nil || !kernel.Status.Available {
		return nil
	}
	switch kernel.Status.Mode {
	case "observe", "enforce":
	default:
		return nil
	}
	floor := &aiRuntimeKernelFloor{
		Mode: kernel.Status.Mode, EnrolledUsers: len(kernel.Status.Users),
		PausedUntil: kernelPauseUntil(kernel.Status.Pause),
	}
	for _, user := range kernel.Status.Users {
		switch user.Mode {
		case "enforce":
			floor.EnforcedUsers++
		case "burnin":
			floor.BurnInUsers++
		}
	}
	return floor
}

// kernelPauseUntil renders a break-glass pause's end: a UTC time, "reboot"
// for --until-reboot, or "" when there is no pause.
func kernelPauseUntil(pause *acquire.KernelPause) string {
	switch {
	case pause == nil:
		return ""
	case pause.UntilUnixNano > 0:
		return time.Unix(0, pause.UntilUnixNano).UTC().Format(time.RFC3339)
	case pause.UntilReboot:
		return "reboot"
	}
	return "resumed"
}

// runtimeIdentity is the user and agent identity a runtime record carries
// (spec 12.1).
type runtimeIdentity struct {
	// UserID is the kernel uid of the process, never replaced by the login
	// uid; LoginID is the audit login uid, set only when the uid is 0.
	UserID    string
	LoginID   string
	UserName  string
	Connector string
	// AgentIdentityID is the agt-... id the hook path derives for this
	// connector and uid, where the gateway derives one.
	AgentIdentityID string
	// Verified is true only for a root the sensor helper enrolled: the uid
	// from the kernel, the connector from an install enrolled for it.
	Verified bool
}

// runtimeFindingIdentity is the identity of a host-plane finding's agent
// root. Heuristic and IDE-hosted roots carry no connector, so no agent
// identity: the instance and session come only from a hook join.
func runtimeFindingIdentity(finding sensor.Finding, kernel *sensor.KernelState) runtimeIdentity {
	identity := uidIdentity(finding.UID, finding.AUID)
	identity.UserName, identity.Connector = finding.User, finding.Connector
	if identity.Connector != "" && identity.UserID != "" {
		identity.AgentIdentityID = inventoryAgentIdentityID(identity.Connector, identity.UserID)
		identity.Verified = identity.AgentIdentityID != "" && kernelEnrolled(kernel, *finding.UID, identity.Connector)
	}
	return identity
}

// runtimeActivityIdentity is the identity of the process that performed one
// tactic: its own uid when the backend reported it, else its root's.
func runtimeActivityIdentity(finding sensor.Finding, activity sensor.RuntimeActivity) runtimeIdentity {
	if activity.UID != nil {
		identity := uidIdentity(activity.UID, activity.AUID)
		identity.UserName = firstNonEmpty(activity.User, finding.User)
		return identity
	}
	identity := uidIdentity(finding.UID, finding.AUID)
	identity.UserName = finding.User
	return identity
}

func uidIdentity(uid, auid *int) runtimeIdentity {
	if uid == nil {
		return runtimeIdentity{}
	}
	identity := runtimeIdentity{UserID: strconv.Itoa(*uid)}
	if *uid == 0 && auid != nil {
		identity.LoginID = strconv.Itoa(*auid)
	}
	return identity
}

// kernelEnrolled reports a uid the helper enrolled with connector.
func kernelEnrolled(kernel *sensor.KernelState, uid int, connector string) bool {
	user := kernelUser(kernel, uid)
	if user == nil {
		return false
	}
	for _, enrolled := range user.Connectors {
		if strings.EqualFold(enrolled, connector) {
			return true
		}
	}
	return false
}

func kernelUser(kernel *sensor.KernelState, uid int) *acquire.KernelUserStatus {
	if kernel == nil {
		return nil
	}
	for index := range kernel.Status.Users {
		if kernel.Status.Users[index].UID == uid {
			return &kernel.Status.Users[index]
		}
	}
	return nil
}

// runtimeNotEnforcedReason is why no kernel control applies to a finding's
// root: the gateway's own observe-only classes first, then, while the
// helper's reconciler runs, a uid it did not enroll or one it keeps
// observe-only. "" when the root can be in scope (or the gateway cannot tell).
func runtimeNotEnforcedReason(finding sensor.Finding, kernel *sensor.KernelState) string {
	if finding.NotEnforcedReason != "" {
		return finding.NotEnforcedReason
	}
	if finding.Connector == "" || finding.UID == nil || kernel == nil || !kernel.Status.Available {
		return ""
	}
	user := kernelUser(kernel, *finding.UID)
	switch {
	case user == nil:
		return "not_enrolled"
	case user.Mode == "observe_only":
		return firstNonEmpty(user.Reason, "observe_only")
	case len(user.Connectors) > 0 && !kernelEnrolled(kernel, *finding.UID, finding.Connector):
		return "not_enrolled"
	}
	return ""
}

// kernelOrphanGrace is how long the sensor helper must stay unreachable
// before the policies it last reported loaded count as orphaned. The helper
// restarts on every manifest change; a restart is seconds, not this.
const kernelOrphanGrace = time.Minute

// kernelPolicyHealth is the /health policy.kernel object: what the managed
// Linux sensor helper's kernel-policy reconciler applied. nil when it does
// not apply: no helper that reports kernel policy, or a helper in consume or
// off with nothing of DefenseClaw's left loaded.
func kernelPolicyHealth(state *sensor.KernelState, now time.Time) map[string]interface{} {
	if state == nil || state.FetchedAt.IsZero() {
		return nil
	}
	status := state.Status
	orphaned := kernelOrphans(state, now)
	if !status.Available && len(orphaned) == 0 {
		return nil
	}
	section := map[string]interface{}{
		"available":        status.Available,
		"mode":             status.Mode,
		"kernel_policy":    status.KernelPolicy,
		"applied":          status.Applied,
		"helper_reachable": state.Reachable,
		"fetched_at":       state.FetchedAt.UTC().Format(time.RFC3339),
	}
	if !status.Available && status.Reason != "" {
		section["reason"] = status.Reason
	}
	if counts := kernelModeCounts(status.Users); len(counts) > 0 {
		section["mode_by_uid_count"] = counts
	}
	if until := kernelPauseUntil(status.Pause); until != "" {
		section["paused_until"] = until
	}
	if len(status.Overrides) > 0 {
		section["overrides"] = append([]string(nil), status.Overrides...)
	}
	if len(orphaned) > 0 {
		section["orphaned"] = orphaned
	}
	if len(status.Warnings) > 0 {
		section["warnings"] = append([]string(nil), status.Warnings...)
	}
	if status.UpdatedUnixNano > 0 {
		section["updated_at"] = time.Unix(0, status.UpdatedUnixNano).UTC().Format(time.RFC3339)
	}
	return section
}

// kernelModeCounts counts enrolled uids by the helper's mode for them.
func kernelModeCounts(users []acquire.KernelUserStatus) map[string]int {
	counts := make(map[string]int, len(users))
	for _, user := range users {
		mode := user.Mode
		if mode == "" {
			mode = "unknown"
		}
		counts[mode]++
	}
	return counts
}

// kernelOrphans are DefenseClaw policies loaded with nothing to reconcile
// them (spec 7.8): names the helper itself reports orphaned; recorded names
// still loaded while the helper runs in consume or off, after its retire
// step; and, once the helper has been unreachable past the grace, the
// recorded names it last reported -- gRPC-loaded policies outlive it.
func kernelOrphans(state *sensor.KernelState, now time.Time) []string {
	names := map[string]bool{}
	for _, warning := range state.Status.Warnings {
		if name, ok := strings.CutPrefix(warning, "kernel_policy_orphaned:"); ok && strings.TrimSpace(name) != "" {
			names[strings.TrimSpace(name)] = true
		}
	}
	reconciling := state.Status.Mode == "observe" || state.Status.Mode == "enforce"
	switch {
	case state.Reachable && !reconciling:
		for _, policy := range state.Status.Policies {
			if policy.Recorded {
				names[policy.Name] = true
			}
		}
	case !state.Reachable && !state.UnreachableSince.IsZero() && now.Sub(state.UnreachableSince) >= kernelOrphanGrace:
		for _, policy := range state.Status.Policies {
			if policy.Recorded && policy.State != "unloading" {
				names[policy.Name] = true
			}
		}
	}
	if len(names) == 0 {
		return nil
	}
	out := make([]string, 0, len(names))
	for name := range names {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// policyHealthBody is the /health "policy" object: the live generation's
// PolicyHealth, with the sensor helper's kernel-policy state as "kernel"
// when it reports one (doctor reads policy.kernel and compares its
// kernel_policy with policy.components.kernel_policy).
func (a *APIServer) policyHealthBody(policy PolicyHealth) interface{} {
	service, release := a.leaseAIRuntime()
	var kernel *sensor.KernelState
	if service != nil {
		kernel = service.Snapshot().Kernel
	}
	release()
	section := kernelPolicyHealth(kernel, time.Now())
	if section == nil {
		return policy
	}
	raw, err := json.Marshal(policy)
	if err != nil {
		return policy
	}
	var body map[string]interface{}
	if err := json.Unmarshal(raw, &body); err != nil {
		return policy
	}
	body["kernel"] = section
	return body
}
