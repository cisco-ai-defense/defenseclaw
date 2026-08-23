// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"fmt"
)

// ErrWindowsManagedRuntimeGenerationConflict reports that the protected
// selector entry changed after a target-owned generation was prepared. The
// caller must reconcile again instead of overwriting the newer generation.
var ErrWindowsManagedRuntimeGenerationConflict = errors.New(
	"enterprise hooks: Windows managed runtime generation changed concurrently",
)

// WindowsManagedRuntimeGenerationDesired is the complete authenticated input
// used to render one immutable per-target hook runtime generation. ScopedToken
// is deliberately excluded from JSON if this orchestration object is ever
// included in a protected transaction report; the token exists only in the
// target-owned immutable bundle.
type WindowsManagedRuntimeGenerationDesired struct {
	Connector                  string `json:"connector"`
	TargetSID                  string `json:"target_sid"`
	DataDir                    string `json:"data_dir"`
	HookExecutable             string `json:"hook_executable"`
	GatewayAddr                string `json:"gateway_addr"`
	GatewayServiceName         string `json:"gateway_service_name"`
	ScopedToken                string `json:"-"`
	HookContractID             string `json:"hook_contract_id"`
	HookContractLockUpdatedAt  string `json:"hook_contract_lock_updated_at"`
	HookContractEntryUpdatedAt string `json:"hook_contract_entry_updated_at"`
}

func (d WindowsManagedRuntimeGenerationDesired) String() string {
	return fmt.Sprintf(
		"WindowsManagedRuntimeGenerationDesired{Connector:%q TargetSID:%q DataDir:%q HookExecutable:%q GatewayAddr:%q GatewayServiceName:%q HookContractID:%q}",
		d.Connector,
		d.TargetSID,
		d.DataDir,
		d.HookExecutable,
		d.GatewayAddr,
		d.GatewayServiceName,
		d.HookContractID,
	)
}

func (d WindowsManagedRuntimeGenerationDesired) GoString() string { return d.String() }

// WindowsManagedRuntimeGenerationResolveOptions binds selector resolution to
// a SID and machine-policy identity that the caller has already authenticated.
// MachinePolicyRegistered must be true: the selector augments the existing
// machine policy and can never enroll a user by itself.
type WindowsManagedRuntimeGenerationResolveOptions struct {
	Connector               string
	TargetSID               string
	DataDir                 string
	HookExecutable          string
	MachinePolicyRegistered bool
}

// WindowsManagedRuntimeGenerationRemovalOptions authorizes removal only after
// the primary machine-policy enrollment has been revoked. The expected fields
// prevent one deployment from deleting a different deployment's selector
// entry for the same SID.
type WindowsManagedRuntimeGenerationRemovalOptions struct {
	Connector                string
	TargetSID                string
	DataDir                  string
	HookExecutable           string
	PrimaryEnrollmentRemoved bool
}

// WindowsManagedRuntimeSelectorSnapshotOptions binds a secretless selector
// target snapshot to the exact primary-policy identity being serviced.
type WindowsManagedRuntimeSelectorSnapshotOptions struct {
	Connector      string
	TargetSID      string
	DataDir        string
	HookExecutable string
}

// WindowsManagedRuntimeSelectorTargetCAS is the compact protected-journal
// identity of one selector target. All identity fields are required when
// Exists is true; absence is represented explicitly rather than by a magic
// digest.
type WindowsManagedRuntimeSelectorTargetCAS struct {
	Exists       bool   `json:"exists"`
	GenerationID string `json:"generation_id,omitempty"`
	BundleSHA256 string `json:"bundle_sha256,omitempty"`
	TargetSHA256 string `json:"target_sha256,omitempty"`
}

// WindowsManagedRuntimeSelectorTargetSnapshot contains the canonical
// secretless selector entry for one SID. It never contains bundle bytes or a
// scoped token, so it is safe to persist in the authenticated lifecycle
// journal.
type WindowsManagedRuntimeSelectorTargetSnapshot struct {
	SchemaVersion int                                    `json:"schema_version"`
	Connector     string                                 `json:"connector"`
	TargetSID     string                                 `json:"target_sid"`
	Existed       bool                                   `json:"existed"`
	Target        []byte                                 `json:"target,omitempty"`
	TargetSHA256  string                                 `json:"target_sha256,omitempty"`
	CAS           WindowsManagedRuntimeSelectorTargetCAS `json:"cas"`
}

// WindowsManagedRuntimeSelectorRestoreOptions supplies the exact target CAS
// expected after a failed servicing mutation. Restore refuses a concurrent
// same-SID generation and preserves all peer-SID selector entries.
type WindowsManagedRuntimeSelectorRestoreOptions struct {
	Snapshot        WindowsManagedRuntimeSelectorTargetSnapshot `json:"snapshot"`
	ExpectedCurrent WindowsManagedRuntimeSelectorTargetCAS      `json:"expected_current"`
}

// WindowsManagedRuntimeSelectorCAS identifies one complete connector selector
// without exposing target bundle secrets.
type WindowsManagedRuntimeSelectorCAS struct {
	Exists bool   `json:"exists"`
	SHA256 string `json:"sha256,omitempty"`
}

// WindowsManagedRuntimeSelectorSnapshot is the canonical secretless complete
// selector used by servicing journals that replace an entire connector target
// set.
type WindowsManagedRuntimeSelectorSnapshot struct {
	SchemaVersion  int                              `json:"schema_version"`
	Connector      string                           `json:"connector"`
	Existed        bool                             `json:"existed"`
	Selector       []byte                           `json:"selector,omitempty"`
	SelectorSHA256 string                           `json:"selector_sha256,omitempty"`
	CAS            WindowsManagedRuntimeSelectorCAS `json:"cas"`
}

// WindowsManagedRuntimeSelectorFullRestoreOptions prevents lifecycle rollback
// from overwriting a selector changed outside the recorded transaction.
type WindowsManagedRuntimeSelectorFullRestoreOptions struct {
	Snapshot        WindowsManagedRuntimeSelectorSnapshot `json:"snapshot"`
	ExpectedCurrent WindowsManagedRuntimeSelectorCAS      `json:"expected_current"`
}

// WindowsManagedRuntimeGenerationGCOptions authorizes bounded cleanup of
// strict, unselected immutable bundles for one authenticated target. Preserve
// IDs come from the protected lifecycle journal and are always unioned with
// the currently selected generation.
type WindowsManagedRuntimeGenerationGCOptions struct {
	Connector                      string
	TargetSID                      string
	DataDir                        string
	HookExecutable                 string
	ProtectedPreserveGenerationIDs []string
}

// WindowsManagedRuntimeGenerationPublication is an opaque prepared immutable
// bundle. Its secret-bearing bytes stay private so ordinary formatting and
// JSON reporting cannot disclose the scoped token.
type WindowsManagedRuntimeGenerationPublication struct {
	desired        WindowsManagedRuntimeGenerationDesired
	generationID   string
	bundleSHA256   string
	bundlePath     string
	bundleBytes    []byte
	previousTarget *windowsManagedRuntimeSelectorTarget
	reused         bool
}

func (p WindowsManagedRuntimeGenerationPublication) GenerationID() string {
	return p.generationID
}

func (p WindowsManagedRuntimeGenerationPublication) BundleSHA256() string {
	return p.bundleSHA256
}

func (p WindowsManagedRuntimeGenerationPublication) BundlePath() string {
	return p.bundlePath
}

func (p WindowsManagedRuntimeGenerationPublication) Reused() bool {
	return p.reused
}

// SelectorTargetCAS returns the exact secretless selector target identity that
// can be persisted before Commit for crash-safe lifecycle restoration.
func (p WindowsManagedRuntimeGenerationPublication) SelectorTargetCAS() WindowsManagedRuntimeSelectorTargetCAS {
	return windowsManagedRuntimeGenerationPublicationTargetCASPlatform(p)
}

func (p WindowsManagedRuntimeGenerationPublication) String() string {
	return fmt.Sprintf(
		"WindowsManagedRuntimeGenerationPublication{Connector:%q TargetSID:%q GenerationID:%q BundleSHA256:%q Reused:%t}",
		p.desired.Connector,
		p.desired.TargetSID,
		p.generationID,
		p.bundleSHA256,
		p.reused,
	)
}

func (p WindowsManagedRuntimeGenerationPublication) GoString() string { return p.String() }

// WindowsManagedRuntimeSelectorCommit is a target-granular CAS receipt. It
// contains no token material and can restore only the exact selector entry
// changed by its transaction while preserving concurrent peer-SID updates.
type WindowsManagedRuntimeSelectorCommit struct {
	connector       string
	targetSID       string
	previousTarget  *windowsManagedRuntimeSelectorTarget
	publishedTarget *windowsManagedRuntimeSelectorTarget
	changed         bool
}

func (c WindowsManagedRuntimeSelectorCommit) Changed() bool {
	return c.changed
}

// Rollback restores the exact target entry preimage only if this commit still
// owns the target entry. A concurrent same-SID update fails closed.
func (c WindowsManagedRuntimeSelectorCommit) Rollback() error {
	return rollbackWindowsManagedRuntimeSelectorCommitPlatform(c)
}

// Finalize retires the previous immutable bundle only after the surrounding
// whole-manifest lifecycle transaction has committed and no rollback can
// select it again. It must not run merely because one connector row succeeded;
// removal callers must invoke it before reporting the outer uninstall success.
func (c WindowsManagedRuntimeSelectorCommit) Finalize() error {
	return finalizeWindowsManagedRuntimeSelectorCommitPlatform(c)
}

// WindowsManagedRuntimeGenerationResolved is a complete immutable runtime
// snapshot selected while the SID remained registered in the primary machine
// policy. The token is intentionally private; callers must opt in to reading it
// through ScopedToken instead of exposing it through JSON or default logging.
type WindowsManagedRuntimeGenerationResolved struct {
	Connector                  string `json:"connector"`
	TargetSID                  string `json:"target_sid"`
	DataDir                    string `json:"data_dir"`
	HookExecutable             string `json:"hook_executable"`
	GatewayAddr                string `json:"gateway_addr"`
	GatewayServiceName         string `json:"gateway_service_name"`
	GenerationID               string `json:"generation_id"`
	BundleSHA256               string `json:"bundle_sha256"`
	HookContractID             string `json:"hook_contract_id"`
	HookContractLockUpdatedAt  string `json:"hook_contract_lock_updated_at"`
	HookContractEntryUpdatedAt string `json:"hook_contract_entry_updated_at"`
	scopedToken                string
}

func (r WindowsManagedRuntimeGenerationResolved) ScopedToken() string {
	return r.scopedToken
}

func (r WindowsManagedRuntimeGenerationResolved) String() string {
	return fmt.Sprintf(
		"WindowsManagedRuntimeGenerationResolved{Connector:%q TargetSID:%q DataDir:%q HookExecutable:%q GatewayAddr:%q GatewayServiceName:%q GenerationID:%q BundleSHA256:%q HookContractID:%q}",
		r.Connector,
		r.TargetSID,
		r.DataDir,
		r.HookExecutable,
		r.GatewayAddr,
		r.GatewayServiceName,
		r.GenerationID,
		r.BundleSHA256,
		r.HookContractID,
	)
}

func (r WindowsManagedRuntimeGenerationResolved) GoString() string { return r.String() }

// PrepareWindowsManagedRuntimeGeneration publishes a complete immutable
// target-owned bundle without replacing any existing generation name. It must
// run under the authenticated target identity.
func PrepareWindowsManagedRuntimeGeneration(
	desired WindowsManagedRuntimeGenerationDesired,
) (WindowsManagedRuntimeGenerationPublication, error) {
	return prepareWindowsManagedRuntimeGenerationPlatform(desired)
}

// CommitWindowsManagedRuntimeGeneration atomically selects a prepared bundle
// under a connector-specific machine-protected transaction lock. It compares
// the same-SID selector preimage captured by Prepare before making a change.
func CommitWindowsManagedRuntimeGeneration(
	publication WindowsManagedRuntimeGenerationPublication,
) (WindowsManagedRuntimeSelectorCommit, error) {
	return commitWindowsManagedRuntimeGenerationPlatform(publication)
}

// DiscardWindowsManagedRuntimeGenerationPublication removes an unselected new
// bundle after a failed selector commit. Reused selected generations are never
// removed by this helper.
func DiscardWindowsManagedRuntimeGenerationPublication(
	publication WindowsManagedRuntimeGenerationPublication,
) error {
	return discardWindowsManagedRuntimeGenerationPublicationPlatform(publication)
}

// ResolveWindowsManagedRuntimeGeneration returns a complete old-or-new
// snapshot. Resolution reads the protected selector, validates its immutable
// target bundle, then requires the selector bytes to remain unchanged.
func ResolveWindowsManagedRuntimeGeneration(
	opts WindowsManagedRuntimeGenerationResolveOptions,
) (WindowsManagedRuntimeGenerationResolved, error) {
	return resolveWindowsManagedRuntimeGenerationPlatform(opts)
}

// VerifyWindowsManagedRuntimeGeneration performs privileged read-only
// verification without impersonating the target and without returning token
// material. The expected token is compared only inside the verifier.
func VerifyWindowsManagedRuntimeGeneration(
	desired WindowsManagedRuntimeGenerationDesired,
) error {
	return verifyWindowsManagedRuntimeGenerationPlatform(desired)
}

// RemoveWindowsManagedRuntimeGenerationEnrollment removes one selector entry
// only after primary machine-policy revocation has made it inactive.
func RemoveWindowsManagedRuntimeGenerationEnrollment(
	opts WindowsManagedRuntimeGenerationRemovalOptions,
) (WindowsManagedRuntimeSelectorCommit, error) {
	return removeWindowsManagedRuntimeGenerationEnrollmentPlatform(opts)
}

// CaptureWindowsManagedRuntimeSelectorTarget snapshots only one secretless
// target entry under the selector lock, never the peer enrollment set.
func CaptureWindowsManagedRuntimeSelectorTarget(
	opts WindowsManagedRuntimeSelectorSnapshotOptions,
) (WindowsManagedRuntimeSelectorTargetSnapshot, error) {
	return captureWindowsManagedRuntimeSelectorTargetPlatform(opts)
}

// RestoreWindowsManagedRuntimeSelectorTargetCAS restores a captured target
// only when the current target still matches the protected expected CAS.
func RestoreWindowsManagedRuntimeSelectorTargetCAS(
	opts WindowsManagedRuntimeSelectorRestoreOptions,
) error {
	return restoreWindowsManagedRuntimeSelectorTargetCASPlatform(opts)
}

// CaptureWindowsManagedRuntimeSelector snapshots the complete connector
// selector as canonical secretless bytes under its cross-process lock.
func CaptureWindowsManagedRuntimeSelector(
	connectorName string,
) (WindowsManagedRuntimeSelectorSnapshot, error) {
	return captureWindowsManagedRuntimeSelectorPlatform(connectorName)
}

// RestoreWindowsManagedRuntimeSelectorCAS restores a complete connector
// selector only when the current full-selector CAS matches the protected
// lifecycle journal.
func RestoreWindowsManagedRuntimeSelectorCAS(
	opts WindowsManagedRuntimeSelectorFullRestoreOptions,
) error {
	return restoreWindowsManagedRuntimeSelectorCASPlatform(opts)
}

// GarbageCollectWindowsManagedRuntimeGenerations deletes only strict,
// target-owned, unselected bundles while preserving protected journal pins.
func GarbageCollectWindowsManagedRuntimeGenerations(
	opts WindowsManagedRuntimeGenerationGCOptions,
) (int, error) {
	return garbageCollectWindowsManagedRuntimeGenerationsPlatform(opts)
}
