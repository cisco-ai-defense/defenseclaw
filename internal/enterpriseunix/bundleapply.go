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
	codeBundleConfirmedLate = "bundle_confirmed_after_interrupt"
	codeBundleNotCurrent    = "bundle_not_current"

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
	// configSHA is the SHA-256 of the rendered config.yaml.
	configSHA string
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

// bundleMode reports whether the MDM installed trust anchors. Any entry at
// the anchor path turns it on: a link or a file another account could write
// is refused later (anchor_insecure), never read as bundle mode off.
func (e *Env) bundleMode() bool {
	_, err := os.Lstat(e.bundleAnchorsPath())
	return err == nil
}

// bundleSecretPresent reports whether the enterprise secret store holds the
// credential name (the value is never read).
func (e *Env) bundleSecretPresent(name string) (bool, error) {
	names, _, err := e.listSecrets()
	if err != nil {
		return false, err
	}
	return slices.Contains(names, name), nil
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

// configWriteOptions is how the transaction records the config it installs
// in config.generation.json: as the lifecycle, or for a bundle as its
// principal with the bundle change summary and the bundle fields.
func (l *lifecycle) configWriteOptions() configwrite.Options {
	if l.bundle != nil {
		if opt, ok := enterprisebundle.GenerationOptions(l.bundle.receipt); ok {
			return opt
		}
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
	if !env.bundleMode() {
		return true
	}
	raw, _, err := env.currentBundleConfig(env.bundleStore())
	if err == nil && raw != nil {
		err = l.useBundleConfig(raw)
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
		r.AddError(codeBundleStateUnreadable, "cannot read the current policy bundle, so no config is applied: "+err.Error())
		return stop()
	}
	if l.opts.ConfigFile != "" {
		given, err := readBounded(l.opts.ConfigFile, maxInputBytes)
		if err != nil || current == nil || !bytes.Equal(given, current) {
			r.AddError(codeBundleRequired, fmt.Sprintf(
				"this device takes its policy from signed bundles (the MDM installed %s), so --config is not applied; deliver a signed bundle with `%s`",
				filepath.Join(env.Layout.ConfigDir, "trust", enterprisebundle.AnchorsName), bundleApplyCommand))
			return stop()
		}
		return 0, false
	}
	if current != nil {
		if err := l.useBundleConfig(current); err != nil {
			r.AddError(codeState, err.Error())
			return stop()
		}
	}
	return 0, false
}

// takeInboxBundle returns the inbox bundle with the highest manifest version
// ("" for none) and marks every inbox bundle processed: the run removes them
// once it ends, whatever the outcome, as the receipt records it. A file that
// is not administrator-controlled stops the run and stays.
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
		path    string
		version uint64
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
		found = append(found, candidate{path: path, version: peekBundleVersion(path)})
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
	for _, c := range found {
		l.inboxProcessed = append(l.inboxProcessed, c.path)
	}
	return found[0].path, nil
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

// peekBundleVersion is the version the unverified manifest of the bundle at
// path claims (0 when it cannot be read); it only orders the inbox.
func peekBundleVersion(path string) uint64 {
	b, err := readBundleInput(path)
	if err != nil {
		return 0
	}
	m, err := enterprisebundle.DecodeManifest(b.Manifest)
	if err != nil {
		return 0
	}
	return m.Version
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
	defer l.removeProcessedInbox()
	store := env.bundleStore()
	if record != nil {
		store = env.bundleStoreForGroup(record.ServiceGID)
	}
	b, readErr := readBundleInput(l.opts.Bundle)
	id, version := "", uint64(0)
	if readErr == nil {
		if m, err := enterprisebundle.DecodeManifest(b.Manifest); err == nil {
			id, version = m.BundleID, m.Version
		}
	}
	receipt, err := store.Receive(id, version)
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
	if err := env.ensureDir(store.BundlesDir, 0o750, fileOwner{UID: 0, GID: record.ServiceGID}); err != nil {
		return refuse(fmt.Errorf("prepare the policy bundle store: %w", err))
	}
	staging, err := store.Stage(receipt, b)
	if err != nil {
		return refuse(&enterprisebundle.Error{Code: enterprisebundle.CodeArchiveInvalid, Detail: "cannot stage the bundle: " + err.Error()})
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
		ProductVersion: env.ProductVersion, HostPlatform: env.GOOS, SecretPresent: env.bundleSecretPresent,
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
		// A retry of the bundle that is current: its confirmed receipt stays
		// the one status reports, and ensure re-applies its config (a no-op
		// on a healthy host).
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
		l.describeBundle()
		return code
	}
	m := res.Manifest
	if err := store.Advance(receipt, enterprisebundle.StateVerified, func(rc *enterprisebundle.Receipt) {
		rc.TenantID, rc.DeviceGroup, rc.Principal = m.TenantID, m.Target.DeviceGroup, m.CreatedBy
		rc.ChangeSummary = m.ChangeSummary
		rc.SignerKeyID, rc.ManifestSHA256, rc.ExpectedDigest = res.Signature.KeyID, sha256Bytes(staged.Manifest), res.ExpectedDigest
	}); err != nil {
		return refuse(err)
	}
	if err := env.fault(enterprisebundle.StateVerified); err != nil {
		return refuse(err)
	}
	if _, err := store.Promote(receipt); err != nil {
		return refuse(err)
	}
	rendered, err := enterprisebundle.RenderConfig(staged, env.bundleVersionDir(receipt.Dir))
	if err != nil {
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
	return code
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
	digest, generation, err := l.awaitBundlePolicy(ctx, l.serviceUID, true)
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
	return l.bundle.store.Advance(l.bundle.receipt, enterprisebundle.StateApplied, func(rc *enterprisebundle.Receipt) {
		rc.EffectivePolicyDigest, rc.ConfigGeneration, rc.ConfigSHA256 = digest, generation, configSHA
		rc.AppliedAt, rc.Restart = at, restart
	})
}

// finishBundle settles the receipt once the ensure of a bundle ended: an
// applied bundle whose deployment committed becomes current (one atomic
// bundle-state.json replace); a bundle ensure had nothing to install for
// (its config is already the installed one) is confirmed against the running
// gateway; anything else fails the receipt.
func (l *lifecycle) finishBundle(ctx context.Context) {
	env, r, run := l.env, l.result, l.bundle
	if run == nil || enterprisebundle.Finished(run.receipt.State) {
		return
	}
	rc := run.receipt
	record, _ := env.loadDeployment()
	committed := record != nil && len(r.Errors) == 0 && record.ConfigSHA256 == run.configSHA
	if committed && rc.State == enterprisebundle.StateStaged {
		// Recorded without a reload: the gateway reports the generation it
		// last loaded, so only its digest and reload state are compared.
		err := l.recordBundleGeneration(ctx, record)
		var digest string
		var generation uint64
		if err == nil {
			digest, generation, err = l.awaitBundlePolicy(ctx, record.ServiceUID, false)
		}
		if err == nil {
			err = l.markBundleApplied(digest, generation, record.ConfigSHA256, false)
		}
		if err != nil {
			l.failBundle(ctx, run, record, enterprisebundle.CodeNotConfirmed, err.Error())
			return
		}
	}
	if committed && rc.State == enterprisebundle.StateApplied {
		if env.fault("committed") != nil {
			// The test seam ends the run here, as a crash between the commit
			// and the swap would: settle finishes it on the next run.
			return
		}
		if _, err := run.store.Confirm(rc); err != nil {
			r.AddWarning(codeBundleNotCurrent, "the bundle is applied but could not be recorded as the current bundle; the next lifecycle run confirms it: "+err.Error())
		}
		return
	}
	code := enterprisebundle.CodeApplyFailed
	if hasMessageCode(r.Errors, codeBundleNotConfirmed) {
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
	l.failBundle(ctx, run, record, code, message)
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

// bundleHealth is the /health policy block a bundle confirm reads.
type bundleHealth struct {
	digest, reloadError string
	configGeneration    uint64
}

func parseBundleHealth(body []byte) bundleHealth {
	var health struct {
		Policy *struct {
			EffectiveDigest  string `json:"effective_digest"`
			ConfigGeneration uint64 `json:"config_generation"`
			LastReloadError  string `json:"last_reload_error"`
		} `json:"policy"`
	}
	if json.Unmarshal(body, &health) != nil || health.Policy == nil {
		return bundleHealth{}
	}
	return bundleHealth{digest: health.Policy.EffectiveDigest, reloadError: health.Policy.LastReloadError, configGeneration: health.Policy.ConfigGeneration}
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
func (l *lifecycle) awaitBundlePolicy(ctx context.Context, serviceUID int, requireGeneration bool) (string, uint64, error) {
	env := l.env
	want, _, ok := l.computePolicy(ctx)
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
			if last.digest == want && last.reloadError == "" && (!requireGeneration || last.configGeneration == 0 || last.configGeneration == state.Generation) {
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
	case last.reloadError != "":
		return "", 0, fmt.Errorf("the gateway refused the bundle policy and keeps enforcing its previous policy: %s", last.reloadError)
	case last.digest == "":
		return "", 0, errors.New("the gateway did not report its effective policy, so it did not confirm the bundle")
	case last.digest != want:
		return "", 0, fmt.Errorf("the gateway reports effective policy %s, not %s of the bundle config", shortDigest(last.digest), shortDigest(want))
	}
	return "", 0, fmt.Errorf("the gateway reports config generation %d, not %d", last.configGeneration, state.Generation)
}

// settleUnconfirmedBundle finishes a bundle a previous run applied but did
// not make current. When its transaction did not commit (recoverInterrupted
// put the snapshot back), the receipt fails as interrupted. When the
// deployment committed it, the gateway is asked again: reporting its policy
// confirms it now; otherwise the receipt fails as not confirmed and this run
// applies the current (last good) bundle again.
func (l *lifecycle) settleUnconfirmedBundle(ctx context.Context, store *enterprisebundle.Store, record *Deployment, rc *enterprisebundle.Receipt) {
	r := l.result
	committed := record != nil && rc.ConfigSHA256 != "" && record.ConfigSHA256 == rc.ConfigSHA256
	if !committed {
		rc.RolledBack = true
		if record != nil {
			rc.EnforcingDigest, _ = l.gatewayPolicyNow(ctx, record.ServiceUID)
		}
		if err := store.Fail(rc, enterprisebundle.CodeInterrupted, "the run that applied this bundle ended before its transaction committed; the transaction was rolled back and the last good policy kept enforcing"); err != nil {
			r.AddWarning(codeBundleStateUnreadable, "could not settle the policy bundle store: "+err.Error())
			return
		}
		r.AddWarning(codeBundleInterrupted, fmt.Sprintf("policy bundle %s version %d was rolled back after an interrupted apply; the last good policy enforces", rc.BundleID, rc.Version))
		return
	}
	digest, _, err := l.awaitBundlePolicy(ctx, record.ServiceUID, false)
	if err == nil && digest == rc.EffectivePolicyDigest {
		if _, err := store.Confirm(rc); err != nil {
			r.AddWarning(codeBundleNotCurrent, "could not record the applied policy bundle as current: "+err.Error())
			return
		}
		r.AddWarning(codeBundleConfirmedLate, fmt.Sprintf("policy bundle %s version %d, applied by a run that ended before it recorded the bundle, is confirmed now", rc.BundleID, rc.Version))
		return
	}
	st, _ := store.LoadState()
	rc.RolledBack = st.Current != nil
	rc.EnforcingDigest, _ = l.gatewayPolicyNow(ctx, record.ServiceUID)
	if err := store.Fail(rc, enterprisebundle.CodeNotConfirmed, "after an interrupted apply the gateway did not report the policy of this bundle"); err != nil {
		r.AddWarning(codeBundleStateUnreadable, "could not settle the policy bundle store: "+err.Error())
		return
	}
	next := "there is no last good bundle to return to, and the gateway keeps enforcing the policy it last built"
	if st.Current != nil {
		next = fmt.Sprintf("a changing run applies the last good bundle %s version %d again", st.Current.BundleID, st.Current.Version)
	}
	r.AddWarning(codeBundleUnconfirmed, fmt.Sprintf("policy bundle %s version %d was applied but the gateway did not confirm it (failed: not_confirmed); %s", rc.BundleID, rc.Version, next))
}
