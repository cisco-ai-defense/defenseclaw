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

//go:build !windows

package enterpriseunix

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// Signed policy bundle apply on Linux and macOS (management plane spec P1
// section 7). An ensure with Options.Bundle receives the bundle (receipt),
// copies it into the store staging directory, verifies the staged copy
// (never the path MDM dropped it at), promotes it to its immutable version
// directory and renders its config.yaml against that directory. The
// existing ensure transaction then installs the rendered config like a
// --config file: snapshot, apply or hot apply, verify. Before the
// deployment commits, the gateway must report the effective policy the
// installed config computes to, the written config_generation and no reload
// error; otherwise the transaction rolls back to the snapshot, whose config
// points at the untouched last good version directory. Once the deployment
// committed, bundle-state.json makes the bundle current in one atomic
// replace. The current policy keeps enforcing until then, and a failed or
// interrupted apply leaves (or puts back) the last good one.
//
// Bundle mode is on once the MDM installed the trust anchors. Then every
// changing run applies the config of the current bundle (an in-place edit of
// config.yaml is reverted) and a --config that differs from it is refused
// with bundle_required. The committed config (committed-config.yaml) is
// therefore always the config of the current bundle.

const (
	codeBundleRequired      = string(enterprisebundle.CodeBundleRequired)
	codeBundleNotConfirmed  = string(enterprisebundle.CodeNotConfirmed)
	codeBundleInbox         = "bundle_inbox_refused"
	codeBundleConfirmedLate = enterprisebundle.WarnConfirmedAfterInterrupt
	codeBundleNotCurrent    = "bundle_not_current"
	// codeBundleConfirmedWithErrors names a bundle this run committed and
	// confirmed although a later step of the run failed.
	codeBundleConfirmedWithErrors = "bundle_confirmed_with_errors"

	// bundleConfigFileName is the rendered config of the bundle a run
	// applies, root-only in the lifecycle directory; the transaction reads it
	// as its --config.
	bundleConfigFileName = "bundle-config.yaml"
	bundleInboxDirName   = "inbox"
	bundleFileSuffix     = ".dcbundle"
	// maxInboxFiles bounds how many inbox files one run looks at.
	maxInboxFiles = 16
	// bundleApplyCommand is how an administrator applies a bundle.
	bundleApplyCommand = "defenseclaw-gateway enterprise bundle apply --bundle <file>"
)

// bundleRun is the bundle one run applies.
type bundleRun struct {
	store   *enterprisebundle.Store
	receipt *enterprisebundle.Receipt
	// verifiedProductFloor came from this run's verified signed manifest. A
	// replacement bundle can recover a damaged confirmed bundle without
	// relying on the damaged bundle's unreadable minimum.
	verifiedProductFloor string
	// configSHA is the SHA-256 of the rendered config.yaml.
	configSHA string
	// confirmPending is set when the deployment committed the bundle config
	// but the gateway stopped reporting its policy before the receipt was
	// confirmed: the receipt stays applied for the next run to settle, and
	// the run exits with the retry code (GAP-0032).
	confirmPending bool
	// committed is set once the transaction of this run committed the
	// deployment of the bundle config, after the gateway reported its policy.
	committed bool
	// settled is set once finishBundle ran for this run: a receipt it left
	// applied is settled by the next changing run, not again by this one.
	settled bool
}

// bundleAnchorsPath is <etc>/trust/bundle-anchors.json (rooted).
func (e *Env) bundleAnchorsPath() string {
	return e.P(filepath.Join(e.Layout.ConfigDir, "trust", enterprisebundle.AnchorsName))
}

// bundleInboxDir is <etc>/bundles/inbox (rooted), where MDM drops bundles
// for the apply trigger.
func (e *Env) bundleInboxDir() string {
	return e.P(filepath.Join(e.Layout.ConfigDir, enterprisebundle.BundlesDirName, bundleInboxDirName))
}

func (e *Env) bundleConfigPath() string {
	return filepath.Join(e.P(e.Layout.LifecycleDir), bundleConfigFileName)
}

// bundleVersionDir is the installed path of a version directory, as the
// rendered config.yaml names it.
func (e *Env) bundleVersionDir(name string) string {
	return filepath.Join(e.Layout.ConfigDir, enterprisebundle.BundlesDirName, name)
}

// bundleMode reports whether trust anchors are installed. Any entry at
// the anchor path turns it on: a link or a file another account could write
// is refused later (anchor_insecure), never read as bundle mode off.
func (e *Env) bundleMode() bool {
	_, err := os.Lstat(e.bundleAnchorsPath())
	return err == nil
}

// fault runs the bundle test fault seam at phase; nil in production.
func (e *Env) fault(phase string) error {
	if e.bundleFault == nil {
		return nil
	}
	return e.bundleFault(phase)
}

// currentBundleConfig renders config.yaml of the current bundle against
// its version directory; nil when no bundle is current.
func (e *Env) currentBundleConfig(store *enterprisebundle.Store) ([]byte, *enterprisebundle.Ref, error) {
	st, err := store.LoadState()
	if err != nil || st.Current == nil {
		return nil, nil, err
	}
	b, err := store.ReadVersion(st.Current)
	if err != nil {
		return nil, st.Current, err
	}
	raw, err := enterprisebundle.RenderConfig(b, e.bundleVersionDir(st.Current.Dir))
	return raw, st.Current, err
}

// currentBundleGenerationOptions attributes a write of the current bundle's
// rendered config. The state pins the stored manifest, so its signed
// principal remains available even after the confirmed receipt was pruned.
func currentBundleGenerationOptions(store *enterprisebundle.Store, ref *enterprisebundle.Ref) (configwrite.Options, error) {
	b, err := store.ReadVersion(ref)
	if err != nil {
		return configwrite.Options{}, err
	}
	m, err := enterprisebundle.DecodeManifest(b.Manifest)
	if err != nil {
		return configwrite.Options{}, err
	}
	if m.BundleID != ref.BundleID || m.Version != ref.Version || ref.SignerKeyID == "" {
		return configwrite.Options{}, fmt.Errorf("confirmed policy bundle %s version %d has incomplete identity", ref.BundleID, ref.Version)
	}
	opt, ok := enterprisebundle.GenerationOptions(&enterprisebundle.Receipt{
		BundleID: ref.BundleID, Version: ref.Version, Principal: m.CreatedBy,
		SignerKeyID: ref.SignerKeyID, ChangeSummary: m.ChangeSummary,
	})
	if !ok {
		return configwrite.Options{}, fmt.Errorf("confirmed policy bundle %s version %d has no principal", ref.BundleID, ref.Version)
	}
	opt.GenerationFloor = ref.ConfigGeneration
	return opt, nil
}

// configWriteOptions is how the transaction records the config it installs
// in config.generation.json: as the lifecycle, or for a bundle as its
// principal with the bundle change summary and the bundle fields.
func (l *lifecycle) configWriteOptions() configwrite.Options {
	if l.bundle != nil {
		if opt, ok := enterprisebundle.GenerationOptions(l.bundle.receipt); ok {
			return opt
		}
	}
	if l.currentBundleGeneration != nil {
		return *l.currentBundleGeneration
	}
	return configwrite.Options{Actor: configwrite.ActorLifecycle, Reason: "enterprise " + l.opts.Action}
}

// useBundleConfig makes raw the config this run applies, as a root-only
// --config file in the lifecycle directory.
func (l *lifecycle) useBundleConfig(raw []byte) error {
	path := l.env.bundleConfigPath()
	if err := l.env.writeFileAtomic(path, raw, 0o600, rootOwner()); err != nil {
		return err
	}
	l.opts.ConfigFile = path
	return nil
}

// useCurrentBundleConfig makes a transaction in bundle mode apply the config
// of the current bundle. It is false, with an error in the result, when that
// config cannot be read.
func (l *lifecycle) useCurrentBundleConfig() bool {
	env := l.env
	l.currentBundleGeneration = nil
	if !env.bundleMode() {
		return true
	}
	store := env.bundleStore()
	raw, ref, err := env.currentBundleConfig(store)
	if err == nil && raw != nil {
		var opt configwrite.Options
		opt, err = currentBundleGenerationOptions(store, ref)
		if err == nil {
			err = l.useBundleConfig(raw)
		}
		if err == nil {
			l.currentBundleGeneration = &opt
		}
	}
	if err != nil {
		l.result.AddError(codeBundleStateUnreadable, "cannot read the current policy bundle, so no config is applied: "+err.Error())
		return false
	}
	return true
}

// prepareBundleMode runs before a changing action. It picks the inbox bundle
// for --inbox and for the apply trigger, refuses a bundle apply on a host
// that is not installed, and in bundle mode refuses a --config that is not
// the current bundle config (bundle_required) or makes the run apply the
// current bundle config. done is set when the run ends here.
func (l *lifecycle) prepareBundleMode(ctx context.Context, record *Deployment) (code int, done bool) {
	env, r := l.env, l.result
	switch l.opts.Action {
	case ActionInstall, ActionUpgrade, ActionRepair, ActionEnsure:
	default:
		return 0, false
	}
	stop := func() (int, bool) {
		if record != nil {
			l.describe(ctx, record, false)
		}
		return 0, true
	}
	trigger := l.opts.Action == ActionEnsure && l.opts.Reason == "path" && l.opts.Bundle == "" && l.opts.ConfigFile == "" && env.bundleMode()
	if l.opts.BundleInbox || trigger {
		path, err := l.takeInboxBundle()
		if err != nil {
			r.AddError(codeBundleInbox, err.Error())
			return stop()
		}
		if path == "" && l.opts.BundleInbox {
			r.Noop, r.NoopReason = true, "inbox_empty"
			return stop()
		}
		l.opts.Bundle = path
	}
	if l.opts.Bundle != "" {
		if record == nil {
			r.AddError(codeNotInstalled, "DefenseClaw enterprise is not installed; install it before you apply a policy bundle")
			return 0, true
		}
		return 0, false
	}
	if !env.bundleMode() {
		return 0, false
	}
	current, _, err := env.currentBundleConfig(env.bundleStore())
	if err != nil {
		// The run still repairs the host (services, hooks, permissions)
		// with the config the last deployment committed, the config of the
		// bundle that was current then; an in-place edit of config.yaml is
		// reverted as in every bundle-mode run. Only bytes that match the
		// deployment record qualify. A new signed bundle replaces the
		// damaged one.
		committed := env.committedDeploymentConfig(record)
		if l.opts.ConfigFile != "" || committed == nil {
			r.AddError(codeBundleStateUnreadable, "cannot read the current policy bundle, so no config is applied: "+err.Error())
			return stop()
		}
		r.AddWarning(codeBundleStateUnreadable, "cannot read the current policy bundle, so the config the last deployment committed is kept; deliver a new signed bundle to replace it: "+err.Error())
		if err := l.useBundleConfig(committed); err != nil {
			r.AddError(codeState, err.Error())
			return stop()
		}
		return 0, false
	}
	if l.opts.ConfigFile != "" {
		given, err := readBounded(l.opts.ConfigFile, maxInputBytes)
		if err != nil || current == nil || !bytes.Equal(given, current) {
			r.AddError(codeBundleRequired, fmt.Sprintf(
				"this device takes its policy from signed bundles (a trust anchor file is installed at %s), so --config is not applied; deliver a signed bundle with `%s`",
				filepath.Join(env.Layout.ConfigDir, "trust", enterprisebundle.AnchorsName), bundleApplyCommand))
			return stop()
		}
	}
	if current != nil && !l.useCurrentBundleConfig() {
		return stop()
	}
	return 0, false
}

// committedDeploymentConfig is the config the deployment record says was
// applied: committed-config.yaml, else the installed config.yaml, when its
// SHA-256 is the record's; nil when neither matches.
func (e *Env) committedDeploymentConfig(record *Deployment) []byte {
	if record == nil || record.ConfigSHA256 == "" {
		return nil
	}
	for _, path := range []string{e.committedConfigPath(), e.P(e.Layout.ConfigPath)} {
		if raw, err := readBounded(path, maxInputBytes); err == nil && sha256Bytes(raw) == record.ConfigSHA256 {
			return raw
		}
	}
	return nil
}

// takeInboxBundle returns the inbox bundle with the highest manifest version
// ("" for none) and marks every inbox bundle processed: the run removes them
// once it ends, as the receipts record it, unless it deferred the bundle
// (restart_deferred), which a later run retries. A file that is not
// administrator-controlled stops the run and stays.
func (l *lifecycle) takeInboxBundle() (string, error) {
	env := l.env
	dir := env.bundleInboxDir()
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("cannot read the bundle inbox: %w", err)
	}
	type candidate struct {
		path     string
		bundleID string
		version  uint64
	}
	var found []candidate
	for _, entry := range entries {
		name := entry.Name()
		// MDM copies under a temporary dot name and renames into place.
		if strings.HasPrefix(name, ".") || !strings.HasSuffix(name, bundleFileSuffix) {
			continue
		}
		if len(found) == maxInboxFiles {
			break
		}
		path := filepath.Join(dir, name)
		if err := env.Trust(path, TrustAdminFile); err != nil {
			return "", fmt.Errorf("the bundle inbox file %s is not administrator-controlled, so it is not applied: %v", name, err)
		}
		id, version := peekBundleManifest(path)
		found = append(found, candidate{path: path, bundleID: id, version: version})
	}
	if len(found) == 0 {
		return "", nil
	}
	sort.SliceStable(found, func(i, j int) bool {
		if found[i].version != found[j].version {
			return found[i].version > found[j].version
		}
		return found[i].path > found[j].path
	})
	for i, c := range found {
		l.inboxProcessed = append(l.inboxProcessed, c.path)
		if i > 0 {
			l.inboxSuperseded = append(l.inboxSuperseded, supersededInbox{bundleID: c.bundleID, version: c.version})
		}
	}
	l.inboxTopVersion = found[0].version
	return found[0].path, nil
}

// supersededInbox is an inbox bundle a run did not apply because the inbox
// held a higher version.
type supersededInbox struct {
	bundleID string
	version  uint64
}

// recordSupersededInbox gives each inbox bundle this run did not take a
// receipt that ends as failed(superseded), so every delivery is accounted
// for in bundle status and the receipt events. It runs once the outcome of
// the bundle the run took is known, and not when that bundle was deferred.
func (l *lifecycle) recordSupersededInbox(store *enterprisebundle.Store) {
	for _, s := range l.inboxSuperseded {
		receipt, err := store.Receive(s.bundleID, s.version, "")
		if err == nil {
			err = store.Fail(receipt, enterprisebundle.CodeSuperseded,
				fmt.Sprintf("the bundle inbox also held version %d; a run takes only the highest inbox version", l.inboxTopVersion))
		}
		if err != nil {
			l.result.AddWarning(codeBundleStateUnreadable, "cannot write the receipt of a superseded inbox bundle: "+err.Error())
		}
	}
	l.inboxSuperseded = nil
}

// removeProcessedInbox removes the inbox files this run processed.
func (l *lifecycle) removeProcessedInbox() {
	for _, path := range l.inboxProcessed {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			l.result.AddWarning(codeBundleInbox, "could not remove the processed bundle inbox file "+filepath.Base(path)+": "+err.Error())
		}
	}
	l.inboxProcessed = nil
}

// peekBundleManifest is the bundle id and version the unverified manifest of
// the bundle at path claims ("" and 0 when it cannot be read); they only
// order the inbox and name the receipt of a superseded bundle.
func peekBundleManifest(path string) (string, uint64) {
	b, err := readBundleInput(path)
	if err != nil {
		return "", 0
	}
	m, err := enterprisebundle.DecodeManifest(b.Manifest)
	if err != nil {
		return "", 0
	}
	return m.BundleID, m.Version
}

// readBundleInput reads a .dcbundle file (no link followed, at most the
// compressed limit) or a bundle directory.
func readBundleInput(path string) (*enterprisebundle.Bundle, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, &enterprisebundle.Error{Code: enterprisebundle.CodeArchiveInvalid, Detail: "the bundle path does not exist"}
	}
	if info.IsDir() {
		return enterprisebundle.ReadDir(path)
	}
	raw, err := safefile.ReadRegularFileBounded(path, enterprisebundle.MaxCompressedBytes+1)
	if err != nil || len(raw) > enterprisebundle.MaxCompressedBytes {
		return nil, &enterprisebundle.Error{Code: enterprisebundle.CodeArchiveInvalid, Detail: "not a regular bundle file of at most 4 MiB"}
	}
	return enterprisebundle.ReadArchive(bytes.NewReader(raw))
}

// applyBundle is ensure with a bundle: receive, stage, verify, promote, then
// the ensure transaction with the rendered config, confirm, and the swap.
func (l *lifecycle) applyBundle(ctx context.Context, record *Deployment) int {
	env, r := l.env, l.result
	store := env.bundleStore()
	if record != nil {
		store = env.bundleStoreForGroup(record.ServiceGID)
	}
	deferred := false
	defer func() {
		if deferred {
			// Retried later: the inbox keeps the deferred bundle and the
			// lower versions, and no receipt says another one was taken.
			l.inboxProcessed, l.inboxSuperseded = nil, nil
			return
		}
		l.recordSupersededInbox(store)
		l.removeProcessedInbox()
	}()
	b, readErr := readBundleInput(l.opts.Bundle)
	id, version, manifestSHA := "", uint64(0), ""
	if readErr == nil {
		if m, err := enterprisebundle.DecodeManifest(b.Manifest); err == nil {
			id, version, manifestSHA = m.BundleID, m.Version, sha256Bytes(b.Manifest)
		}
	}
	repeat := false
	defer func() { l.scopeLateConfirmWarning(id, version, manifestSHA, repeat) }()
	receipt, err := store.Receive(id, version, l.opts.DeliveryID)
	if err != nil {
		r.AddError(codeBundleStateUnreadable, "cannot write the policy bundle receipt, so the bundle is not applied: "+err.Error())
		l.describe(ctx, record, false)
		return 0
	}
	run := &bundleRun{store: store, receipt: receipt}
	refuse := func(err error) int {
		code := enterprisebundle.CodeOf(err)
		if code == "" {
			code = enterprisebundle.CodeApplyFailed
		}
		l.failBundle(ctx, run, record, code, err.Error())
		l.describe(ctx, record, false)
		l.describeBundle()
		return 0
	}
	if err := env.fault(enterprisebundle.StateReceived); err != nil {
		return refuse(err)
	}
	if readErr != nil {
		return refuse(readErr)
	}
	if err := env.ensureDir(store.BundlesDir, 0o755, rootOwner()); err != nil {
		return refuse(fmt.Errorf("prepare the policy bundle store: %w", err))
	}
	staging, err := store.Stage(receipt, b)
	if err != nil {
		return refuse(enterprisebundle.StageError(err))
	}
	// Everything below reads the staged copy only.
	staged, err := enterprisebundle.ReadDir(staging)
	if err != nil {
		return refuse(err)
	}
	if env.BundleDigester == nil {
		return refuse(&enterprisebundle.Error{Code: enterprisebundle.CodeConfigInvalid, Detail: "this build cannot compute the effective policy digest of a bundle"})
	}
	anchors, err := enterprisebundle.LoadAnchors(env.bundleAnchorsPath(), func(path string) error { return env.Trust(path, TrustAdminFile) })
	if err != nil {
		return refuse(err)
	}
	st, err := store.LoadState()
	if err != nil {
		return refuse(&enterprisebundle.Error{Code: enterprisebundle.CodeStateInvalid, Detail: err.Error()})
	}
	res, err := enterprisebundle.Verify(ctx, enterprisebundle.VerifyInput{
		Bundle: staged, Anchors: anchors, Platform: env.GOOS, Now: env.Now().UTC(), Confirmed: st.Confirmed(),
		ProductVersion: env.ProductVersion, SecretValue: env.SecretValue, RequireSecretPresence: true,
		DeviceLayout: func() *enterprisebundle.DeviceLayout {
			layout := enterprisebundle.DeviceLayoutFromManaged(env.Layout)
			return &layout
		}(),
		Stage:    func(*enterprisebundle.Bundle) (string, error) { return staging, nil },
		Digester: env.BundleDigester,
	})
	for _, w := range res.Warnings {
		r.AddWarning(w.Code, w.Message)
	}
	if err != nil {
		return refuse(err)
	}
	if res.AlreadyApplied {
		// The repeat installs the current bundle config again over an
		// installed config that may have drifted: with --defer-restart a
		// restart that change needs is deferred before any transaction.
		if env.DeferRestart {
			if reason := env.repeatRestartDeferral(store); reason != "" {
				deferred = true
				refuse(&enterprisebundle.Error{Code: enterprisebundle.CodeRestartDeferred, Detail: reason})
				return enterprisestatus.BusyExitCode(env.GOOS)
			}
		}
		// A retry of the bundle that is current: its confirmed receipt stays
		// the one status reports, and ensure re-applies its config (a no-op
		// on a healthy host).
		repeat = true
		receipt.Principal, receipt.ChangeSummary, receipt.SignerKeyID = res.Manifest.CreatedBy, res.Manifest.ChangeSummary, res.Signature.KeyID
		if err := store.Discard(receipt); err != nil {
			r.AddWarning(codeBundleStateUnreadable, "could not remove the receipt of the repeated delivery: "+err.Error())
		}
		if !l.useCurrentBundleConfig() {
			l.describe(ctx, record, false)
			return 0
		}
		code := l.ensureInstalled(ctx, record, l.apply)
		if r.Noop {
			r.NoopReason = "already_applied"
		}
		// The old receipt proves only that the bundle was enforced when it
		// was first confirmed. A repeated delivery may repair config.yaml
		// and restart the gateway without its policy ever converging. Do not
		// report that cached confirmation as this delivery's outcome.
		if code == 0 && len(r.Errors) == 0 {
			generation, generationErr := configwrite.ReadGenerationState(env.P(env.Layout.ConfigPath))
			gateway, hasGateway := gatewayUnitOf(env.Services.Units())
			var health bundleHealth
			if hasGateway {
				if body, healthErr := l.gatewayHealth(ctx, gateway, record.ServiceUID); healthErr == nil {
					health = parseBundleHealth(body)
				}
			}
			if generationErr != nil || r.Policy == nil || !r.Policy.Applied ||
				r.Policy.EffectiveDigest != res.EffectivePolicyDigest ||
				r.Policy.GatewayReportedDigest != res.EffectivePolicyDigest ||
				generation.BundleID != id || generation.BundleVersion != version ||
				health.digest != res.EffectivePolicyDigest || health.configGeneration != generation.Generation ||
				health.bundleID != id || health.bundleVersion != version || health.reloadError != "" || health.configState == "error" ||
				enterprisebundle.ConfirmPolicyDigests(res.ExpectedDigest, r.Policy.EffectiveDigest, health.digest, res.DigestVerified) != nil {
				r.Noop, r.NoopReason = false, ""
				// ensureInstalled describes the historical confirmed receipt.
				// This repeated delivery has not earned that result block.
				r.Bundle = nil
				r.AddError(codeBundleNotConfirmed, fmt.Sprintf(
					"the repeated policy bundle is installed, but the gateway has not confirmed its effective policy; check `defenseclaw-gateway enterprise bundle status`, then resubmit the same signed bundle with `%s`", bundleApplyCommand))
				return code
			}
		}
		l.describeCurrentBundle()
		return code
	}
	m := res.Manifest
	run.verifiedProductFloor = m.MinProductVersion
	if err := store.Advance(receipt, enterprisebundle.StateVerified, func(rc *enterprisebundle.Receipt) {
		rc.TenantID, rc.DeviceGroup, rc.Principal = m.TenantID, m.Target.DeviceGroup, m.CreatedBy
		rc.ChangeSummary, rc.RollbackOf = m.ChangeSummary, m.RollbackOf
		rc.SignerKeyID, rc.ManifestSHA256, rc.ExpectedDigest = res.Signature.KeyID, sha256Bytes(staged.Manifest), res.ExpectedDigest
		rc.SetDigestComparison(res.DigestVerified, res.DigestUnverifiable, res.DigestLayoutUnverifiable)
	}); err != nil {
		return refuse(err)
	}
	if err := env.fault(enterprisebundle.StateVerified); err != nil {
		return refuse(err)
	}
	versionName := enterprisebundle.VersionDirNameForReceipt(receipt.Version, receipt.BundleID, receipt.ReceiptID)
	rendered, err := enterprisebundle.RenderConfig(staged, env.bundleVersionDir(versionName))
	if err != nil {
		return refuse(err)
	}
	current, err := readBounded(env.P(env.Layout.ConfigPath), maxInputBytes)
	if err != nil {
		return refuse(&enterprisebundle.Error{Code: enterprisebundle.CodeStateInvalid, Detail: "cannot read the enforced config: " + err.Error()})
	}
	deviceLayout := enterprisebundle.DeviceLayoutFromManaged(env.Layout)
	if err := enterprisebundle.RefuseDeviceKeyMove(current, rendered, env.GOOS, &deviceLayout); err != nil {
		return refuse(err)
	}
	loss, err := enterprisebundle.DisabledByBundle(current, rendered)
	if err != nil {
		return refuse(&enterprisebundle.Error{Code: enterprisebundle.CodeStateInvalid, Detail: err.Error()})
	}
	receipt.DisabledByBundle = loss
	if len(loss) > 0 {
		receipt.WarningCodes = append(receipt.WarningCodes, "capability_disabled")
		r.AddWarning("capability_disabled", "the bundle disables: "+strings.Join(loss, ", "))
		if env.RefuseCapabilityLoss {
			return refuse(&enterprisebundle.Error{Code: enterprisebundle.CodeCapabilityLoss, Detail: "the bundle disables: " + strings.Join(loss, ", ")})
		}
	}
	if env.DeferRestart {
		// The classifier bundle verify reports as restart_prediction.
		if reason := env.restartDeferral(current, rendered); reason != "" {
			deferred = true
			refuse(&enterprisebundle.Error{Code: enterprisebundle.CodeRestartDeferred, Detail: reason})
			return enterprisestatus.BusyExitCode(env.GOOS)
		}
	}
	if _, err := store.Promote(receipt); err != nil {
		return refuse(err)
	}
	if err := env.fault(enterprisebundle.StateStaged); err != nil {
		return refuse(err)
	}
	if err := l.useBundleConfig(rendered); err != nil {
		return refuse(err)
	}
	run.configSHA = sha256Bytes(rendered)
	l.bundle = run
	code := l.ensureInstalled(ctx, record, l.applyBundleTransaction)
	// ensure ended before the transaction (a refusal) or found nothing to
	// change.
	l.finishBundle(ctx)
	l.describeBundle()
	if run.confirmPending && code == 0 {
		code = enterprisestatus.BusyExitCode(env.GOOS)
		l.scheduleBundleSettle(ctx, receipt)
	}
	return code
}

// restartDeferral is the restart_deferred detail of a change from the
// installed config to rendered, as bundle verify predicts the restart; ""
// when the change applies without one.
func (e *Env) restartDeferral(installed, rendered []byte) string {
	restart, err := configwrite.ManagedConfigRestartRequired(installed, rendered, configwrite.ManagedDefaultsFor(e.Layout))
	return enterprisebundle.RestartDeferralReason(restart, err != nil || len(installed) == 0)
}

// repeatRestartDeferral is restartDeferral for a repeated delivery of the
// current bundle: from the installed config to the current bundle config.
// "" when the current bundle cannot be read; the repeat then refuses
// without a transaction (useCurrentBundleConfig).
func (e *Env) repeatRestartDeferral(store *enterprisebundle.Store) string {
	rendered, _, err := e.currentBundleConfig(store)
	if err != nil || rendered == nil {
		return ""
	}
	installed, err := readBounded(e.P(e.Layout.ConfigPath), maxInputBytes)
	if err != nil {
		installed = nil
	}
	return e.restartDeferral(installed, rendered)
}

// scheduleBundleSettle makes the apply trigger settle a bundle this run left
// applied but not confirmed (the gateway stopped reporting its policy). On
// macOS the apply LaunchDaemon watches config.yaml and runs once this run
// releases the lock (GAP-0042). On Linux the transaction stops the apply path
// unit while it writes config.yaml, so that write never starts the apply
// service: a deferred start does, once the gateway had time to come back,
// bounded as every apply retry is (#1321).
func (l *lifecycle) scheduleBundleSettle(ctx context.Context, receipt *enterprisebundle.Receipt) {
	if l.env.GOOS != "linux" || receipt == nil {
		return
	}
	// scheduleApplyRetry reports the deferred run (or its limit) as an
	// input_changed warning; nothing scheduled leaves the resubmit, which
	// not_confirmed already asks for.
	_ = l.scheduleApplyRetry(ctx, fmt.Sprintf("policy bundle %s version %d is applied but the gateway has not confirmed it", receipt.BundleID, receipt.Version))
}

// lateConfirmMessage is the bundle_confirmed_after_interrupt warning.
func lateConfirmMessage(id string, version uint64) string {
	return fmt.Sprintf("policy bundle %s version %d, applied by a run that ended before the bundle was confirmed, is confirmed now", id, version)
}

// scopeLateConfirmWarning keeps bundle_confirmed_after_interrupt in the
// result of a bundle apply for the submitted bundle only: the agent reads it
// to tell a late confirm of the bundle it resubmitted from a first confirm.
// It is reported when this run's settle confirmed the submitted bundle, or
// when the submitted bundle is the current one and an earlier run confirmed
// it late (its receipt records the code). On macOS the apply LaunchDaemon
// watches config.yaml, so the path-triggered ensure that the bundle's own
// config write queued settles the receipt as soon as the not_confirmed apply
// ends, and the agent's resubmit is a repeat (already_applied) that reported
// no warning (GAP-0042). A late confirm of another bundle that this run's
// settle confirmed stays in that bundle's receipt.
func (l *lifecycle) scopeLateConfirmWarning(id string, version uint64, manifestSHA string, repeat bool) {
	r := l.result
	late := manifestSHA != "" && l.confirmedLate[manifestSHA]
	if !late && repeat && r.Bundle != nil && r.Bundle.BundleID == id && r.Bundle.Version == version {
		late = slices.Contains(r.Bundle.WarningCodes, codeBundleConfirmedLate)
	}
	r.Warnings = slices.DeleteFunc(r.Warnings, func(w enterprisestatus.Message) bool { return w.Code == codeBundleConfirmedLate })
	if late {
		r.AddWarning(codeBundleConfirmedLate, lateConfirmMessage(id, version))
	}
}

// applyBundleTransaction is the ensure transaction of a bundle, then the
// swap, before any follow-up transaction reads the current bundle.
func (l *lifecycle) applyBundleTransaction(ctx context.Context, record *Deployment) int {
	code := l.apply(ctx, record)
	l.finishBundle(ctx)
	return code
}

// confirmBundleInTransaction runs in the transaction once the services run
// and verify passed, before the deployment commits: the gateway must report
// the policy of the installed config. Then the receipt is applied.
func (l *lifecycle) confirmBundleInTransaction(ctx context.Context, configSHA string) error {
	env := l.env
	if err := env.fault("transaction"); err != nil {
		return err
	}
	digest, generation, err := l.awaitBundlePolicy(ctx, l.serviceUID, true, l.bundle.receipt)
	if err != nil {
		return err
	}
	if err := l.markBundleApplied(digest, generation, configSHA, !l.gatewayKeptRunning); err != nil {
		return err
	}
	return env.fault(enterprisebundle.StateApplied)
}

func (l *lifecycle) markBundleApplied(digest string, generation uint64, configSHA string, restart bool) error {
	at := l.env.Now().UTC().Format("2006-01-02T15:04:05.000Z07:00")
	sessions := l.env.UnprotectedSessions(context.Background())
	return l.bundle.store.Advance(l.bundle.receipt, enterprisebundle.StateApplied, func(rc *enterprisebundle.Receipt) {
		rc.EffectivePolicyDigest, rc.ConfigGeneration, rc.ConfigSHA256 = digest, generation, configSHA
		rc.AppliedAt, rc.Restart, rc.RestartRequired = at, restart, restart
		rc.SessionsRestartRequired = sessions.Count
	})
}

// finishBundle settles the receipt once the ensure of a bundle ended: an
// applied bundle whose deployment committed becomes current (one atomic
// bundle-state.json replace); a bundle ensure had nothing to install for
// (its config is already the installed one) is confirmed against the running
// gateway; anything else fails the receipt.
func (l *lifecycle) finishBundle(ctx context.Context) {
	env, r, run := l.env, l.result, l.bundle
	if run == nil || run.settled || enterprisebundle.Finished(run.receipt.State) {
		return
	}
	run.settled = true
	rc := run.receipt
	record, _ := env.loadDeployment()
	// A step that fails after this run committed the bundle deployment (the
	// per-user sandbox report, the guardian report) does not undo the
	// commit: the bundle config is the deployment, and the gateway reported
	// its policy before the commit (GAP-0271). Failing the receipt then left
	// a receipt that said failed over a policy that was in force.
	committed := record != nil && record.ConfigSHA256 == run.configSHA && (len(r.Errors) == 0 || run.committed)
	checked := false
	if committed && rc.State == enterprisebundle.StateStaged {
		// Recorded without a reload: the gateway reports the generation it
		// last loaded, so only its digest and reload state are compared.
		err := l.recordBundleGeneration(ctx, record)
		var digest string
		var generation uint64
		if err == nil {
			digest, generation, err = l.awaitBundlePolicy(ctx, record.ServiceUID, false, rc)
		}
		if err == nil {
			err = l.markBundleApplied(digest, generation, record.ConfigSHA256, false)
		}
		if err != nil {
			l.failBundle(ctx, run, record, bundleConfirmationCode(err), err.Error())
			return
		}
		checked = true
	}
	if committed && rc.State == enterprisebundle.StateApplied {
		if len(r.Errors) > 0 {
			// committedBundleEnforced asked the gateway again after the
			// commit, so bundleStillEnforced does not ask a second time.
			if !l.committedBundleEnforced(ctx, record, rc) {
				return
			}
			checked = true
		}
		if env.fault("committed") != nil {
			// The test seam ends the run here, as a crash between the commit
			// and the swap would: settle finishes it on the next run.
			return
		}
		if !checked && !l.bundleStillEnforced(ctx, record, rc) {
			return
		}
		rc.SessionsRestartRequired = env.UnprotectedSessions(ctx).Count
		if _, err := run.store.Confirm(rc); err != nil {
			r.AddWarning(codeBundleNotCurrent, "the bundle is applied but could not be recorded as the current bundle; the next lifecycle run confirms it: "+err.Error())
		}
		return
	}
	code := enterprisebundle.CodeApplyFailed
	if hasMessageCode(r.Errors, string(enterprisebundle.CodeDigestMismatch)) {
		code = enterprisebundle.CodeDigestMismatch
	} else if hasMessageCode(r.Errors, codeBundleNotConfirmed) {
		code = enterprisebundle.CodeNotConfirmed
	}
	var codes []string
	for _, e := range r.Errors {
		if !slices.Contains(codes, e.Code) {
			codes = append(codes, e.Code)
		}
	}
	message := "the ensure run did not install the bundle config"
	if len(codes) > 0 {
		// Only codes: lifecycle messages can quote config values, and the
		// receipt is reported off the device.
		message = "the ensure transaction failed (" + strings.Join(codes, ", ") + ")"
	}
	for _, failure := range r.Errors {
		if strings.Contains(failure.Message, "config.state=error") {
			message = "the gateway reported config.state=error while loading the bundle config"
			break
		}
	}
	l.failBundle(ctx, run, record, code, message)
}

// bundleStillEnforced asks the gateway again, just before the receipt of a
// committed bundle is confirmed, whether it reports the bundle's policy.
// The transaction checked it before the commit, but a gateway that crashed
// or was killed after that check returned confirmed with policy.applied
// false (GAP-0032): confirmed means the running gateway enforces the digest.
// It waits as long as the transaction's check does, so a gateway its service
// manager starts again on the committed config still confirms the bundle.
// Otherwise the receipt stays applied (neither confirmed nor failed), the
// result fails with not_confirmed and the run exits with the retry code: the
// next lifecycle run (the agent's resubmit of the same bundle, an MDM or
// path-triggered ensure) confirms it once the gateway reports its policy, or
// keeps it pending until live evidence disproves the apply.
func (l *lifecycle) bundleStillEnforced(ctx context.Context, record *Deployment, rc *enterprisebundle.Receipt) bool {
	r := l.result
	digest, _, err := l.awaitBundlePolicy(ctx, record.ServiceUID, false, rc)
	if err == nil && digest != rc.EffectivePolicyDigest {
		err = fmt.Errorf("the gateway reports effective policy %s, not %s of the applied receipt", shortDigest(digest), shortDigest(rc.EffectivePolicyDigest))
	}
	if err == nil {
		// The result's policy block was read after the commit, possibly
		// while the gateway was down; it reports what was just confirmed.
		if p := r.Policy; p != nil && p.EffectiveDigest == digest {
			p.GatewayReportedDigest, p.LastReloadError, p.Applied = digest, "", true
		}
		return true
	}
	l.bundle.confirmPending = true
	r.AddError(codeBundleNotConfirmed, fmt.Sprintf(
		"policy bundle %s version %d is installed, but the gateway stopped reporting its policy before the bundle was confirmed (%v); the receipt stays applied and the last good bundle stays current: resubmit the same bundle, and the next lifecycle run confirms it once the gateway reports its policy or keeps it pending until live evidence disproves the apply",
		displayID(rc), rc.Version, err))
	return false
}

// committedBundleEnforced reports whether the gateway still enforces the
// policy of the bundle this run committed, when a step after the commit
// failed. Then the bundle is confirmed as after a clean run, and a warning
// says the errors of the run did not change the policy. Otherwise the
// receipt stays applied, never failed while its config is the deployment:
// the next changing run confirms it or keeps it pending until the gateway
// proves another policy is enforced
// (settleUnconfirmedBundle).
func (l *lifecycle) committedBundleEnforced(ctx context.Context, record *Deployment, rc *enterprisebundle.Receipt) bool {
	r := l.result
	digest, _, err := l.awaitBundlePolicy(ctx, record.ServiceUID, true, rc)
	if err == nil && digest != rc.EffectivePolicyDigest {
		err = fmt.Errorf("the installed config computes to %s, not %s, which the gateway reported before the commit", shortDigest(digest), shortDigest(rc.EffectivePolicyDigest))
	}
	if err != nil {
		r.AddError(string(bundleConfirmationCode(err)), fmt.Sprintf(
			"policy bundle %s version %d is installed, but after a later step of this run failed the gateway did not report its policy again: %v; the next lifecycle run confirms it or keeps it pending until the gateway proves another policy is enforced",
			displayID(rc), rc.Version, err))
		return false
	}
	r.AddWarning(codeBundleConfirmedWithErrors, fmt.Sprintf(
		"policy bundle %s version %d is in force and confirmed: the gateway enforces its policy; the errors of this run come from steps after the policy change committed",
		displayID(rc), rc.Version))
	return true
}

// failBundle ends the receipt of run as failed(code), records whether the
// transaction rolled back and what the gateway enforces now, and reports the
// code in the result.
func (l *lifecycle) failBundle(ctx context.Context, run *bundleRun, record *Deployment, code enterprisebundle.Code, message string) {
	r := l.result
	rc := run.receipt
	rc.RolledBack = hasMessageCode(r.Warnings, codeRolledBack)
	if record != nil {
		rc.EnforcingDigest, _ = l.gatewayPolicyNow(ctx, record.ServiceUID)
	}
	if err := run.store.Fail(rc, code, message); err != nil {
		r.AddWarning(codeBundleStateUnreadable, "could not record the failed policy bundle receipt: "+err.Error())
	}
	if !hasMessageCode(r.Errors, string(code)) {
		r.AddError(string(code), fmt.Sprintf("policy bundle %s version %d was not applied: %s; the last good policy keeps enforcing", displayID(rc), rc.Version, message))
	}
}

func displayID(rc *enterprisebundle.Receipt) string {
	if rc.BundleID != "" {
		return rc.BundleID
	}
	return rc.ReceiptID
}

func bundleConfirmationCode(err error) enterprisebundle.Code {
	if enterprisebundle.CodeOf(err) == enterprisebundle.CodeDigestMismatch {
		return enterprisebundle.CodeDigestMismatch
	}
	return enterprisebundle.CodeNotConfirmed
}

// bundleHealth is the /health policy block a bundle confirm reads.
type bundleHealth struct {
	digest, reloadError      string
	configState, configError string
	configGeneration         uint64
	bundleID                 string
	bundleVersion            uint64
}

func parseBundleHealth(body []byte) bundleHealth {
	var health struct {
		Config struct {
			State     string `json:"state"`
			LastError string `json:"last_error"`
		} `json:"config"`
		Policy *struct {
			EffectiveDigest  string `json:"effective_digest"`
			ConfigGeneration uint64 `json:"config_generation"`
			LastReloadError  string `json:"last_reload_error"`
			BundleID         string `json:"bundle_id"`
			BundleVersion    uint64 `json:"bundle_version"`
		} `json:"policy"`
	}
	if json.Unmarshal(body, &health) != nil || health.Policy == nil {
		return bundleHealth{}
	}
	return bundleHealth{digest: health.Policy.EffectiveDigest, reloadError: health.Policy.LastReloadError,
		configState: health.Config.State, configError: health.Config.LastError, configGeneration: health.Policy.ConfigGeneration,
		bundleID: health.Policy.BundleID, bundleVersion: health.Policy.BundleVersion}
}

// gatewayPolicyNow is what the running gateway reports once ("" when it
// does not answer).
func (l *lifecycle) gatewayPolicyNow(ctx context.Context, serviceUID int) (digest, reloadError string) {
	gateway, ok := gatewayUnitOf(l.env.Services.Units())
	if !ok {
		return "", ""
	}
	body, err := l.gatewayHealth(ctx, gateway, serviceUID)
	if err != nil {
		return "", ""
	}
	h := parseBundleHealth(body)
	return h.digest, h.reloadError
}

// confirmRecoveredBundle checks the activated state after an interrupted
// transaction was rolled back. A successful file restore alone is not enough:
// the running gateway may still hold the unconfirmed policy.
func (l *lifecycle) confirmRecoveredBundle(ctx context.Context) error {
	env := l.env
	if !env.bundleMode() {
		return nil
	}
	store := env.bundleStore()
	raw, current, err := env.currentBundleConfig(store)
	if err != nil || current == nil {
		return err
	}
	configPath := env.P(env.Layout.ConfigPath)
	installed, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read restored config: %w", err)
	}
	if !bytes.Equal(installed, raw) {
		return fmt.Errorf("restored config does not match confirmed bundle %s version %d", current.BundleID, current.Version)
	}
	record, err := env.loadDeployment()
	if err != nil || record == nil || record.ConfigSHA256 != sha256Bytes(installed) {
		return fmt.Errorf("restored config does not match the committed deployment: %v", err)
	}
	state, err := configwrite.ReadGenerationState(configPath)
	if err != nil || state.ConfigSHA256 != sha256Bytes(installed) || state.BundleID != current.BundleID || state.BundleVersion != current.Version {
		return fmt.Errorf("restored config generation does not name confirmed bundle %s version %d: %v", current.BundleID, current.Version, err)
	}
	// The state keeps the digest of the build that confirmed this bundle.
	// After an upgrade the restored bytes can produce a new effective digest.
	// Recompute it from the pinned, hashed bundle with this build before
	// comparing the gateway. The earlier raw check proves the installed bytes.
	digest, _, err := enterprisebundle.VerifiedCurrentDigest(ctx, store, current, env.GOOS,
		enterprisebundle.DeviceLayoutFromManaged(env.Layout), env.BundleDigester)
	if err != nil {
		return fmt.Errorf("compute restored bundle policy: %w", err)
	}
	gateway, ok := gatewayUnitOf(env.Services.Units())
	if !ok {
		return errors.New("no gateway unit to check after rollback")
	}
	check := func() error {
		body, err := l.gatewayHealth(ctx, gateway, record.ServiceUID)
		if err != nil {
			return err
		}
		health := parseBundleHealth(body)
		if health.digest != digest || health.configGeneration != state.Generation ||
			health.bundleID != current.BundleID || health.bundleVersion != current.Version || health.reloadError != "" || health.configState == "error" {
			return fmt.Errorf("gateway policy %s at config generation %d for bundle %s version %d does not match confirmed bundle %s version %d policy %s at generation %d (reload error: %s)",
				health.digest, health.configGeneration, health.bundleID, health.bundleVersion,
				current.BundleID, current.Version, digest, state.Generation, health.reloadError)
		}
		return nil
	}
	if err := check(); err == nil {
		return nil
	}
	if l.keepThroughRollback[gateway.Name] {
		// The gateway kept running through the rollback of a hot change:
		// give it the hot-apply wait to reload the restored config before
		// it is restarted (GAP-0238).
		deadline := env.Now().Add(min(hotApplyTimeout, env.ReadyTimeout))
		for env.Now().Before(deadline) {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(env.PollInterval):
			}
			if err := check(); err == nil {
				return nil
			}
		}
	}
	// A hot applied gateway can retain the new policy after the files were
	// restored. Restart it once to load the confirmed generation.
	if err := restartUnit(ctx, env.Services, gateway); err != nil {
		return fmt.Errorf("restart gateway for confirmed bundle: %w", err)
	}
	if err := l.waitGatewayReady(ctx, gateway); err != nil {
		return fmt.Errorf("wait for gateway after bundle rollback: %w", err)
	}
	return check()
}

// recordBundleGeneration records the installed config, which is already
// the config of the bundle, as a generation of the bundle principal, unless
// config.generation.json names it.
func (l *lifecycle) recordBundleGeneration(ctx context.Context, record *Deployment) error {
	env, rc := l.env, l.bundle.receipt
	configPath := env.P(env.Layout.ConfigPath)
	if state, err := configwrite.ReadGenerationState(configPath); err == nil &&
		state.BundleID == rc.BundleID && state.BundleVersion == rc.Version && state.ConfigSHA256 == record.ConfigSHA256 {
		return nil
	}
	if _, err := configwrite.Locked(ctx, configPath, l.configWriteOptions(), func() (bool, error) { return true, nil }); err != nil {
		return err
	}
	return env.fixMetadata(env.P(configwrite.GenerationPath(env.Layout.ConfigPath)), 0o640, fileOwner{UID: 0, GID: record.ServiceGID})
}

// awaitBundlePolicy waits (the hot apply wait at most) for the gateway to
// report the effective policy the installed config computes to and no
// reload error, and with requireGeneration the recorded config_generation.
// It returns that digest and generation.
func (l *lifecycle) awaitBundlePolicy(ctx context.Context, serviceUID int, requireGeneration bool, rc *enterprisebundle.Receipt) (string, uint64, error) {
	env := l.env
	want, ok := l.bundlePolicyWant(ctx, rc)
	if !ok {
		return "", 0, errors.New("the installed gateway cannot compute the effective policy digest of the bundle config, so the gateway cannot confirm it")
	}
	state, err := configwrite.ReadGenerationState(env.P(env.Layout.ConfigPath))
	if err != nil {
		return "", 0, fmt.Errorf("read the config generation: %w", err)
	}
	gateway, ok := gatewayUnitOf(env.Services.Units())
	if !ok {
		return "", 0, errors.New("no gateway unit to confirm the bundle")
	}
	deadline := env.Now().Add(min(hotApplyTimeout, env.ReadyTimeout))
	var last bundleHealth
	for {
		if body, err := l.gatewayHealth(ctx, gateway, serviceUID); err == nil {
			last = parseBundleHealth(body)
			if last.digest == want && last.reloadError == "" && last.configState != "error" && (!requireGeneration || last.configGeneration == 0 || last.configGeneration == state.Generation) {
				if err := enterprisebundle.ConfirmPolicyDigests(rc.ExpectedDigest, want, last.digest, rc.DigestComparable); err != nil {
					return "", 0, err
				}
				return want, state.Generation, nil
			}
		}
		if !env.Now().Before(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return "", 0, ctx.Err()
		case <-time.After(env.PollInterval):
		}
	}
	switch {
	case last.configState == "error":
		return "", 0, fmt.Errorf("the gateway reports config.state=error for the bundle config: %s", last.configError)
	case last.reloadError != "":
		return "", 0, fmt.Errorf("the gateway refused the bundle policy and keeps enforcing its previous policy: %s", last.reloadError)
	case last.digest == "":
		return "", 0, errors.New("the gateway did not report its effective policy, so it did not confirm the bundle")
	case last.digest != want:
		if err := enterprisebundle.ConfirmPolicyDigests(rc.ExpectedDigest, want, last.digest, rc.DigestComparable); err != nil {
			return "", 0, err
		}
		return "", 0, fmt.Errorf("the gateway reports effective policy %s, not %s of the bundle config", shortDigest(last.digest), shortDigest(want))
	}
	return "", 0, fmt.Errorf("the gateway reports config generation %d, not %d", last.configGeneration, state.Generation)
}

// settleUnconfirmedBundle finishes an applied receipt only from proof about
// its committed config and the gateway's live policy. Missing evidence keeps
// it pending; a gateway that demonstrably enforces another policy fails it.
func (l *lifecycle) settleUnconfirmedBundle(ctx context.Context, store *enterprisebundle.Store, record *Deployment, rc *enterprisebundle.Receipt) bool {
	r := l.result
	pending := func(reason string) bool {
		r.AddWarning(enterprisebundle.WarnBundlePending, fmt.Sprintf("policy bundle %s version %d remains applied and pending: %s; retry ensure after the evidence is available", rc.BundleID, rc.Version, reason))
		return true
	}
	committed := record != nil && rc.ConfigSHA256 != "" && record.ConfigSHA256 == rc.ConfigSHA256
	if !committed {
		rc.RolledBack = true
		if record != nil {
			rc.EnforcingDigest, _ = l.gatewayPolicyNow(ctx, record.ServiceUID)
		}
		if err := store.Fail(rc, enterprisebundle.CodeInterrupted, "the run that applied this bundle ended before its transaction committed; the transaction was rolled back and the last good policy kept enforcing"); err != nil {
			r.AddWarning(codeBundleStateUnreadable, "could not settle the policy bundle store: "+err.Error())
			return true
		}
		r.AddWarning(codeBundleInterrupted, fmt.Sprintf("policy bundle %s version %d was rolled back after an interrupted apply; the last good policy enforces", rc.BundleID, rc.Version))
		return false
	}
	configPath := l.env.P(l.env.Layout.ConfigPath)
	installedSHA, err := sha256File(configPath)
	if err != nil || installedSHA != rc.ConfigSHA256 {
		return pending("the installed config cannot be matched to the receipt")
	}
	generation, err := configwrite.ReadGenerationState(configPath)
	if err != nil || generation.Generation == 0 || generation.Generation != rc.ConfigGeneration ||
		generation.ConfigSHA256 != rc.ConfigSHA256 || generation.BundleID != rc.BundleID ||
		generation.BundleVersion != rc.Version || generation.SignerKeyID != rc.SignerKeyID || generation.Actor != rc.Principal {
		return pending("the committed signed bundle generation cannot be verified")
	}
	digest, comparable, err := enterprisebundle.VerifiedReceiptDigest(ctx, store, rc, l.env.GOOS,
		enterprisebundle.DeviceLayoutFromManaged(l.env.Layout), l.env.ProductVersion,
		l.env.bundleVersionDir(rc.Dir), l.env.BundleDigester)
	if err != nil {
		return pending("this build cannot verify the stored signed bundle's current policy digest")
	}
	gateway, ok := gatewayUnitOf(l.env.Services.Units())
	if !ok {
		return pending("the gateway service is unavailable")
	}
	body, err := l.gatewayHealth(ctx, gateway, record.ServiceUID)
	if err != nil {
		return pending("the gateway policy is unavailable")
	}
	health := parseBundleHealth(body)
	if digest != rc.EffectivePolicyDigest && health.digest == rc.EffectivePolicyDigest &&
		health.configGeneration == generation.Generation && health.bundleID == rc.BundleID &&
		health.bundleVersion == rc.Version {
		return pending("the gateway still reports this bundle's historical policy digest; retry after the gateway upgrade")
	}
	rejected := health.reloadError != "" || health.configState == "error"
	if !rejected {
		if len(health.digest) != 71 || !strings.HasPrefix(health.digest, "sha256:") || strings.ToLower(health.digest) != health.digest {
			return pending("the gateway has not reported a valid policy digest")
		}
		if _, err := hex.DecodeString(health.digest[len("sha256:"):]); err != nil {
			return pending("the gateway has not reported a valid policy digest")
		}
		if health.configGeneration == 0 || health.bundleID == "" || health.bundleVersion == 0 || health.configState == "" {
			return pending("the gateway has not reported enough bundle attribution to confirm or disprove the apply")
		}
	}
	digestErr := enterprisebundle.ConfirmPolicyDigests(rc.ExpectedDigest, digest, health.digest, comparable)
	if digestErr == nil && health.digest == digest && health.configGeneration == generation.Generation &&
		health.bundleID == rc.BundleID && health.bundleVersion == rc.Version && health.reloadError == "" && health.configState != "error" {
		rc.SessionsRestartRequired = l.env.UnprotectedSessions(ctx).Count
		// The receipt records the late confirm: a resubmit of the same bundle
		// that finds it current (another run settled it first) reports it.
		if !slices.Contains(rc.WarningCodes, codeBundleConfirmedLate) {
			rc.WarningCodes = append(rc.WarningCodes, codeBundleConfirmedLate)
		}
		if _, err := store.Confirm(rc); err != nil {
			r.AddWarning(codeBundleNotCurrent, "could not record the applied policy bundle as current: "+err.Error())
			return true
		}
		if l.confirmedLate == nil {
			l.confirmedLate = map[string]bool{}
		}
		l.confirmedLate[rc.ManifestSHA256] = true
		r.AddWarning(codeBundleConfirmedLate, lateConfirmMessage(rc.BundleID, rc.Version))
		return false
	}
	st, _ := store.LoadState()
	rc.RolledBack = st.Current != nil
	rc.EnforcingDigest = health.digest
	if err := store.Fail(rc, bundleConfirmationCode(digestErr), "after an interrupted apply the gateway did not report the policy of this bundle"); err != nil {
		r.AddWarning(codeBundleStateUnreadable, "could not settle the policy bundle store: "+err.Error())
		return true
	}
	next := "there is no last good bundle to return to, and the gateway keeps enforcing the policy it last built"
	if st.Current != nil {
		next = fmt.Sprintf("a changing run applies the last good bundle %s version %d again", st.Current.BundleID, st.Current.Version)
	}
	r.AddWarning(codeBundleUnconfirmed, fmt.Sprintf("policy bundle %s version %d was applied but the gateway did not confirm it (failed: not_confirmed); %s", rc.BundleID, rc.Version, next))
	return false
}
