// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

const (
	windowsManagedRuntimeGenerationSchema                = 1
	windowsManagedRuntimeSelectorFile                    = ".defenseclaw-managed-runtime-selector.state"
	windowsManagedRuntimeSelectorLockFile                = ".defenseclaw-managed-runtime-selector.lock"
	windowsManagedRuntimeSelectorMaxBytes          int64 = 1 << 20
	windowsManagedRuntimeBundleMaxBytes            int64 = 128 << 10
	windowsManagedRuntimeSelectorMaxTargets              = 128
	windowsManagedRuntimeSelectorReadAttempts            = 3
	windowsManagedRuntimeGenerationAttempts              = 128
	windowsManagedRuntimeGenerationGCMaxCandidates       = 256
)

var (
	windowsManagedRuntimeGenerationEntropy         io.Reader = rand.Reader
	windowsManagedRuntimeSelectorPathResolver                = defaultWindowsManagedRuntimeSelectorPath
	windowsManagedRuntimeSelectorWriter                      = writeWindowsManagedFile
	windowsManagedRuntimeSelectorLockTimeout                 = 10 * time.Second
	windowsManagedRuntimeSelectorLockRetry                   = 50 * time.Millisecond
	windowsManagedRuntimeSelectorMutationAuthorize           = requireWindowsEnterpriseAdministrator
	windowsManagedRuntimeSelectorVerifyAuthorize             = requireWindowsEnterpriseAdministrator
)

type windowsManagedRuntimeSelector struct {
	SchemaVersion int                                   `json:"schema_version"`
	Connector     string                                `json:"connector"`
	Targets       []windowsManagedRuntimeSelectorTarget `json:"targets"`
}

type windowsManagedRuntimeSelectorTarget struct {
	Connector          string `json:"connector"`
	SID                string `json:"sid"`
	DataDir            string `json:"data_dir"`
	HookExecutable     string `json:"hook_executable"`
	GatewayAddr        string `json:"gateway_addr"`
	GatewayServiceName string `json:"gateway_service_name"`
	GenerationID       string `json:"generation_id"`
	BundleSHA256       string `json:"bundle_sha256"`
}

type windowsManagedRuntimeBundle struct {
	SchemaVersion              int    `json:"schema_version"`
	GenerationID               string `json:"generation_id"`
	Connector                  string `json:"connector"`
	TargetSID                  string `json:"target_sid"`
	DataDir                    string `json:"data_dir"`
	HookExecutable             string `json:"hook_executable"`
	GatewayAddr                string `json:"gateway_addr"`
	GatewayServiceName         string `json:"gateway_service_name"`
	FailMode                   string `json:"fail_mode"`
	ScopedToken                string `json:"scoped_token"`
	HookContractID             string `json:"hook_contract_id"`
	HookContractLockUpdatedAt  string `json:"hook_contract_lock_updated_at"`
	HookContractEntryUpdatedAt string `json:"hook_contract_entry_updated_at"`
}

func prepareWindowsManagedRuntimeGenerationPlatform(
	desired WindowsManagedRuntimeGenerationDesired,
) (WindowsManagedRuntimeGenerationPublication, error) {
	var result WindowsManagedRuntimeGenerationPublication
	desired, target, err := validateWindowsManagedRuntimeGenerationDesired(desired)
	if err != nil {
		return result, err
	}
	if err := requireWindowsManagedRuntimeEffectiveTarget(target); err != nil {
		return result, err
	}
	if err := validateWindowsManagedRuntimeGenerationRoots(desired.DataDir, target); err != nil {
		return result, err
	}

	selector, _, exists, err := readWindowsManagedRuntimeSelector(desired.Connector, true)
	if err != nil {
		return result, err
	}
	var previous *windowsManagedRuntimeSelectorTarget
	if exists {
		if current, ok := windowsManagedRuntimeSelectorTargetForSID(selector, desired.TargetSID); ok {
			copy := current
			previous = &copy
			if windowsManagedRuntimeSelectorTargetMatchesDesired(current, desired) {
				bundle, data, path, loadErr := loadWindowsManagedRuntimeBundle(current, target)
				if loadErr == nil && windowsManagedRuntimeBundleMatchesDesired(bundle, desired) {
					return WindowsManagedRuntimeGenerationPublication{
						desired:        desired,
						generationID:   current.GenerationID,
						bundleSHA256:   current.BundleSHA256,
						bundlePath:     path,
						bundleBytes:    data,
						previousTarget: previous,
						reused:         true,
					}, nil
				}
			}
		}
	}

	for attempt := 0; attempt < windowsManagedRuntimeGenerationAttempts; attempt++ {
		generationID, err := newWindowsManagedRuntimeGenerationID()
		if err != nil {
			return result, err
		}
		bundle := windowsManagedRuntimeBundleFromDesired(desired, generationID)
		data, err := marshalWindowsManagedRuntimeBundle(bundle)
		if err != nil {
			return result, err
		}
		path, err := windowsManagedRuntimeBundlePath(
			desired.DataDir,
			desired.Connector,
			generationID,
		)
		if err != nil {
			return result, err
		}
		if err := connector.PublishManagedTargetRuntimeFileNoReplace(path, data); err != nil {
			if errors.Is(err, os.ErrExist) {
				continue
			}
			return result, fmt.Errorf(
				"enterprise hooks: publish immutable managed runtime generation: %w",
				err,
			)
		}
		digest := windowsManagedRuntimeSHA256(data)
		entry := windowsManagedRuntimeSelectorTargetFromDesired(
			desired,
			generationID,
			digest,
		)
		loaded, loadedData, loadedPath, err := loadWindowsManagedRuntimeBundle(entry, target)
		if err != nil {
			verifyErr := fmt.Errorf(
				"enterprise hooks: verify immutable managed runtime generation: %w",
				err,
			)
			return result, errors.Join(
				verifyErr,
				deleteWindowsManagedRuntimeBundle(entry, target, data),
			)
		}
		if !bytes.Equal(loadedData, data) || loadedPath != path ||
			!windowsManagedRuntimeBundleMatchesDesired(loaded, desired) {
			return result, errors.Join(
				errors.New("enterprise hooks: immutable managed runtime generation changed during publication"),
				deleteWindowsManagedRuntimeBundle(entry, target, data),
			)
		}
		return WindowsManagedRuntimeGenerationPublication{
			desired:        desired,
			generationID:   generationID,
			bundleSHA256:   digest,
			bundlePath:     path,
			bundleBytes:    append([]byte(nil), data...),
			previousTarget: previous,
		}, nil
	}
	return result, errors.New(
		"enterprise hooks: exhausted immutable managed runtime generation collisions",
	)
}

func commitWindowsManagedRuntimeGenerationPlatform(
	publication WindowsManagedRuntimeGenerationPublication,
) (WindowsManagedRuntimeSelectorCommit, error) {
	var receipt WindowsManagedRuntimeSelectorCommit
	desired, target, err := validateWindowsManagedRuntimeGenerationPublication(publication)
	if err != nil {
		return receipt, err
	}
	if err := windowsManagedRuntimeSelectorMutationAuthorize(); err != nil {
		return receipt, err
	}
	entry := windowsManagedRuntimeSelectorTargetFromDesired(
		desired,
		publication.generationID,
		publication.bundleSHA256,
	)
	if _, data, path, err := loadWindowsManagedRuntimeBundle(entry, target); err != nil {
		return receipt, fmt.Errorf(
			"enterprise hooks: validate managed runtime generation before selection: %w",
			err,
		)
	} else if !bytes.Equal(data, publication.bundleBytes) || path != publication.bundlePath {
		return receipt, errors.New(
			"enterprise hooks: prepared managed runtime generation no longer matches its publication receipt",
		)
	}

	err = withWindowsManagedRuntimeSelectorTransaction(desired.Connector, func() error {
		selector, _, exists, err := readWindowsManagedRuntimeSelector(desired.Connector, true)
		if err != nil {
			return err
		}
		if !exists {
			selector = windowsManagedRuntimeSelector{
				SchemaVersion: windowsManagedRuntimeGenerationSchema,
				Connector:     desired.Connector,
				Targets:       []windowsManagedRuntimeSelectorTarget{},
			}
		}
		current, currentExists := windowsManagedRuntimeSelectorTargetForSID(
			selector,
			desired.TargetSID,
		)
		if !windowsManagedRuntimeOptionalSelectorTargetsEqual(
			current,
			currentExists,
			publication.previousTarget,
		) {
			return ErrWindowsManagedRuntimeGenerationConflict
		}
		previous := publication.previousTarget
		if currentExists && reflect.DeepEqual(current, entry) {
			receipt = WindowsManagedRuntimeSelectorCommit{
				connector:       desired.Connector,
				targetSID:       desired.TargetSID,
				previousTarget:  cloneWindowsManagedRuntimeSelectorTarget(previous),
				publishedTarget: cloneWindowsManagedRuntimeSelectorTarget(&entry),
			}
			return nil
		}
		selector = setWindowsManagedRuntimeSelectorTarget(selector, &entry)
		if err := publishWindowsManagedRuntimeSelector(selector); err != nil {
			return err
		}
		receipt = WindowsManagedRuntimeSelectorCommit{
			connector:       desired.Connector,
			targetSID:       desired.TargetSID,
			previousTarget:  cloneWindowsManagedRuntimeSelectorTarget(previous),
			publishedTarget: cloneWindowsManagedRuntimeSelectorTarget(&entry),
			changed:         true,
		}
		return nil
	})
	return receipt, err
}

func windowsManagedRuntimeGenerationPublicationTargetCASPlatform(
	publication WindowsManagedRuntimeGenerationPublication,
) WindowsManagedRuntimeSelectorTargetCAS {
	desired, _, err := validateWindowsManagedRuntimeGenerationPublication(publication)
	if err != nil {
		return WindowsManagedRuntimeSelectorTargetCAS{}
	}
	entry := windowsManagedRuntimeSelectorTargetFromDesired(
		desired,
		publication.generationID,
		publication.bundleSHA256,
	)
	return windowsManagedRuntimeSelectorTargetCAS(&entry)
}

func resolveWindowsManagedRuntimeGenerationPlatform(
	opts WindowsManagedRuntimeGenerationResolveOptions,
) (WindowsManagedRuntimeGenerationResolved, error) {
	var result WindowsManagedRuntimeGenerationResolved
	opts, target, err := validateWindowsManagedRuntimeGenerationResolveOptions(opts)
	if err != nil {
		return result, err
	}
	if !opts.MachinePolicyRegistered {
		return result, fmt.Errorf(
			"%s: connector %s SID %s is not enrolled by the primary machine policy",
			WindowsManagedSIDUnregisteredReason,
			opts.Connector,
			opts.TargetSID,
		)
	}
	if err := requireWindowsManagedRuntimeProcessTarget(target); err != nil {
		return result, err
	}
	if err := windowsEnterpriseHookTrustCheck(opts.HookExecutable); err != nil {
		return result, fmt.Errorf(
			"enterprise hooks: managed runtime generation hook trust check failed: %w",
			err,
		)
	}

	for attempt := 0; attempt < windowsManagedRuntimeSelectorReadAttempts; attempt++ {
		selector, first, exists, err := readWindowsManagedRuntimeSelector(opts.Connector, false)
		if err != nil {
			return result, err
		}
		if !exists {
			return result, errors.New(
				"enterprise hooks: managed runtime generation selector is absent",
			)
		}
		entry, ok := windowsManagedRuntimeSelectorTargetForSID(selector, opts.TargetSID)
		if !ok {
			return result, errors.New(
				"enterprise hooks: registered SID is absent from the managed runtime generation selector",
			)
		}
		if err := validateWindowsManagedRuntimeSelectorTargetAgainstResolve(entry, opts); err != nil {
			return result, err
		}
		if err := validateWindowsManagedRuntimeGenerationRoots(opts.DataDir, target); err != nil {
			return result, err
		}
		bundle, _, _, err := loadWindowsManagedRuntimeBundle(entry, target)
		if err != nil {
			return result, err
		}
		if err := validateWindowsManagedRuntimeBundleAgainstSelector(bundle, entry); err != nil {
			return result, err
		}
		_, second, secondExists, err := readWindowsManagedRuntimeSelector(opts.Connector, false)
		if err != nil {
			return result, err
		}
		if !secondExists || !bytes.Equal(first, second) {
			continue
		}
		return WindowsManagedRuntimeGenerationResolved{
			Connector:                  bundle.Connector,
			TargetSID:                  bundle.TargetSID,
			DataDir:                    bundle.DataDir,
			HookExecutable:             bundle.HookExecutable,
			GatewayAddr:                bundle.GatewayAddr,
			GatewayServiceName:         bundle.GatewayServiceName,
			GenerationID:               bundle.GenerationID,
			BundleSHA256:               entry.BundleSHA256,
			HookContractID:             bundle.HookContractID,
			HookContractLockUpdatedAt:  bundle.HookContractLockUpdatedAt,
			HookContractEntryUpdatedAt: bundle.HookContractEntryUpdatedAt,
			scopedToken:                bundle.ScopedToken,
		}, nil
	}
	return result, ErrWindowsManagedRuntimeGenerationConflict
}

func verifyWindowsManagedRuntimeGenerationPlatform(
	desired WindowsManagedRuntimeGenerationDesired,
) error {
	desired, target, err := validateWindowsManagedRuntimeGenerationDesired(desired)
	if err != nil {
		return err
	}
	if err := windowsManagedRuntimeSelectorVerifyAuthorize(); err != nil {
		return err
	}
	if err := windowsEnterpriseHookTrustCheck(desired.HookExecutable); err != nil {
		return fmt.Errorf(
			"enterprise hooks: managed runtime generation hook trust check failed: %w",
			err,
		)
	}
	for attempt := 0; attempt < windowsManagedRuntimeSelectorReadAttempts; attempt++ {
		selector, first, _, err := readWindowsManagedRuntimeSelector(desired.Connector, false)
		if err != nil {
			return err
		}
		entry, ok := windowsManagedRuntimeSelectorTargetForSID(selector, desired.TargetSID)
		if !ok || !windowsManagedRuntimeSelectorTargetMatchesDesired(entry, desired) {
			return errors.New(
				"enterprise hooks: managed runtime generation selector does not match the verified target",
			)
		}
		if err := validateWindowsManagedRuntimeGenerationRoots(desired.DataDir, target); err != nil {
			return err
		}
		bundle, _, _, err := loadWindowsManagedRuntimeBundle(entry, target)
		if err != nil {
			return err
		}
		if !windowsManagedRuntimeBundleMatchesDesired(bundle, desired) {
			return errors.New(
				"enterprise hooks: immutable managed runtime generation does not match the verified connector contract",
			)
		}
		_, second, _, err := readWindowsManagedRuntimeSelector(desired.Connector, false)
		if err != nil {
			return err
		}
		if bytes.Equal(first, second) {
			return nil
		}
	}
	return ErrWindowsManagedRuntimeGenerationConflict
}

func removeWindowsManagedRuntimeGenerationEnrollmentPlatform(
	opts WindowsManagedRuntimeGenerationRemovalOptions,
) (WindowsManagedRuntimeSelectorCommit, error) {
	var receipt WindowsManagedRuntimeSelectorCommit
	opts, _, err := validateWindowsManagedRuntimeGenerationRemovalOptions(opts)
	if err != nil {
		return receipt, err
	}
	if !opts.PrimaryEnrollmentRemoved {
		return receipt, errors.New(
			"enterprise hooks: primary machine-policy enrollment must be removed before runtime selector revocation",
		)
	}
	if err := windowsManagedRuntimeSelectorMutationAuthorize(); err != nil {
		return receipt, err
	}
	err = withWindowsManagedRuntimeSelectorTransaction(opts.Connector, func() error {
		selector, _, exists, err := readWindowsManagedRuntimeSelector(opts.Connector, true)
		if err != nil {
			return err
		}
		if !exists {
			return nil
		}
		current, ok := windowsManagedRuntimeSelectorTargetForSID(selector, opts.TargetSID)
		if !ok {
			return nil
		}
		if err := validateWindowsManagedRuntimeSelectorTargetAgainstRemoval(current, opts); err != nil {
			return err
		}
		selector = setWindowsManagedRuntimeSelectorTarget(selector, nilForSID(opts.TargetSID))
		if err := publishOrRemoveWindowsManagedRuntimeSelector(selector); err != nil {
			return err
		}
		receipt = WindowsManagedRuntimeSelectorCommit{
			connector:      opts.Connector,
			targetSID:      opts.TargetSID,
			previousTarget: cloneWindowsManagedRuntimeSelectorTarget(&current),
			changed:        true,
		}
		return nil
	})
	return receipt, err
}

func rollbackWindowsManagedRuntimeSelectorCommitPlatform(
	receipt WindowsManagedRuntimeSelectorCommit,
) error {
	if !receipt.changed {
		return nil
	}
	connectorName, err := canonicalWindowsManagedRuntimeConnector(receipt.connector)
	if err != nil || connectorName != receipt.connector {
		return errors.New("enterprise hooks: invalid managed runtime selector rollback receipt")
	}
	if _, err := validateWindowsEnterpriseTargetSID(receipt.targetSID); err != nil {
		return errors.New("enterprise hooks: invalid managed runtime selector rollback SID")
	}
	if err := windowsManagedRuntimeSelectorMutationAuthorize(); err != nil {
		return err
	}
	return withWindowsManagedRuntimeSelectorTransaction(receipt.connector, func() error {
		selector, _, exists, err := readWindowsManagedRuntimeSelector(receipt.connector, true)
		if err != nil {
			return err
		}
		if !exists {
			selector = windowsManagedRuntimeSelector{
				SchemaVersion: windowsManagedRuntimeGenerationSchema,
				Connector:     receipt.connector,
				Targets:       []windowsManagedRuntimeSelectorTarget{},
			}
		}
		current, currentExists := windowsManagedRuntimeSelectorTargetForSID(
			selector,
			receipt.targetSID,
		)
		if !windowsManagedRuntimeOptionalSelectorTargetsEqual(
			current,
			currentExists,
			receipt.publishedTarget,
		) {
			return ErrWindowsManagedRuntimeGenerationConflict
		}
		// A first-time selection has receipt.previousTarget == nil.
		// setWindowsManagedRuntimeSelectorTarget returns the selector
		// unchanged when target == nil, so passing nil would republish
		// the selector that still contains receipt.publishedTarget and
		// silently un-revoke the rollback. Match the sentinel used by
		// restoreWindowsManagedRuntimeSelectorTargetCASPlatform for
		// the absent-preimage case: nilForSID clears the entry so the
		// caller's "revoked" status matches the persisted state.
		restored := receipt.previousTarget
		if restored == nil {
			restored = nilForSID(receipt.targetSID)
		}
		selector = setWindowsManagedRuntimeSelectorTarget(selector, restored)
		return publishOrRemoveWindowsManagedRuntimeSelector(selector)
	})
}

func finalizeWindowsManagedRuntimeSelectorCommitPlatform(
	receipt WindowsManagedRuntimeSelectorCommit,
) error {
	if !receipt.changed || receipt.previousTarget == nil {
		return nil
	}
	connectorName, err := canonicalWindowsManagedRuntimeConnector(receipt.connector)
	if err != nil || connectorName != receipt.connector {
		return errors.New("enterprise hooks: invalid managed runtime selector finalization receipt")
	}
	target, err := validateWindowsEnterpriseTargetSID(receipt.targetSID)
	if err != nil || target.String() != receipt.targetSID {
		return errors.New("enterprise hooks: invalid managed runtime selector finalization SID")
	}
	if err := validateWindowsManagedRuntimeSelectorTarget(*receipt.previousTarget, receipt.connector); err != nil {
		return errors.New("enterprise hooks: invalid managed runtime selector finalization preimage")
	}
	if receipt.publishedTarget != nil &&
		receipt.publishedTarget.GenerationID == receipt.previousTarget.GenerationID {
		return nil
	}
	if err := windowsManagedRuntimeSelectorMutationAuthorize(); err != nil {
		return err
	}
	return withWindowsManagedRuntimeSelectorTransaction(receipt.connector, func() error {
		selector, _, exists, err := readWindowsManagedRuntimeSelector(receipt.connector, true)
		if err != nil {
			return err
		}
		var current windowsManagedRuntimeSelectorTarget
		currentExists := false
		if exists {
			current, currentExists = windowsManagedRuntimeSelectorTargetForSID(
				selector,
				receipt.targetSID,
			)
		}
		if !windowsManagedRuntimeOptionalSelectorTargetsEqual(
			current,
			currentExists,
			receipt.publishedTarget,
		) {
			return ErrWindowsManagedRuntimeGenerationConflict
		}
		return retireWindowsManagedRuntimeSelectorTargetBundle(
			*receipt.previousTarget,
			target,
		)
	})
}

func captureWindowsManagedRuntimeSelectorTargetPlatform(
	opts WindowsManagedRuntimeSelectorSnapshotOptions,
) (WindowsManagedRuntimeSelectorTargetSnapshot, error) {
	var snapshot WindowsManagedRuntimeSelectorTargetSnapshot
	opts, _, err := validateWindowsManagedRuntimeSelectorSnapshotOptions(opts)
	if err != nil {
		return snapshot, err
	}
	if err := windowsManagedRuntimeSelectorMutationAuthorize(); err != nil {
		return snapshot, err
	}
	snapshot = WindowsManagedRuntimeSelectorTargetSnapshot{
		SchemaVersion: windowsManagedRuntimeGenerationSchema,
		Connector:     opts.Connector,
		TargetSID:     opts.TargetSID,
		CAS:           WindowsManagedRuntimeSelectorTargetCAS{},
	}
	err = withWindowsManagedRuntimeSelectorTransaction(opts.Connector, func() error {
		selector, _, exists, err := readWindowsManagedRuntimeSelector(opts.Connector, true)
		if err != nil {
			return err
		}
		if !exists {
			return nil
		}
		entry, ok := windowsManagedRuntimeSelectorTargetForSID(selector, opts.TargetSID)
		if !ok {
			return nil
		}
		if err := validateWindowsManagedRuntimeSelectorTargetAgainstSnapshot(entry, opts); err != nil {
			return err
		}
		data, err := marshalWindowsManagedRuntimeSelectorTarget(entry)
		if err != nil {
			return err
		}
		snapshot.Existed = true
		snapshot.Target = data
		snapshot.TargetSHA256 = windowsManagedRuntimeSHA256(data)
		snapshot.CAS = windowsManagedRuntimeSelectorTargetCAS(&entry)
		return nil
	})
	return snapshot, err
}

func restoreWindowsManagedRuntimeSelectorTargetCASPlatform(
	opts WindowsManagedRuntimeSelectorRestoreOptions,
) error {
	snapshot, restoredTarget, targetSID, err := validateWindowsManagedRuntimeSelectorSnapshot(
		opts.Snapshot,
	)
	if err != nil {
		return err
	}
	if err := validateWindowsManagedRuntimeSelectorTargetCAS(opts.ExpectedCurrent); err != nil {
		return fmt.Errorf("enterprise hooks: invalid expected managed runtime selector CAS: %w", err)
	}
	if err := windowsManagedRuntimeSelectorMutationAuthorize(); err != nil {
		return err
	}
	return withWindowsManagedRuntimeSelectorTransaction(snapshot.Connector, func() error {
		selector, _, exists, err := readWindowsManagedRuntimeSelector(snapshot.Connector, true)
		if err != nil {
			return err
		}
		if !exists {
			selector = windowsManagedRuntimeSelector{
				SchemaVersion: windowsManagedRuntimeGenerationSchema,
				Connector:     snapshot.Connector,
				Targets:       []windowsManagedRuntimeSelectorTarget{},
			}
		}
		current, currentExists := windowsManagedRuntimeSelectorTargetForSID(
			selector,
			snapshot.TargetSID,
		)
		if !reflect.DeepEqual(
			windowsManagedRuntimeSelectorTargetCAS(optionalWindowsManagedRuntimeSelectorTarget(current, currentExists)),
			opts.ExpectedCurrent,
		) {
			return ErrWindowsManagedRuntimeGenerationConflict
		}
		if restoredTarget != nil {
			if _, _, _, err := loadWindowsManagedRuntimeBundle(*restoredTarget, targetSID); err != nil {
				return fmt.Errorf(
					"enterprise hooks: refusing selector restore with invalid preimage bundle: %w",
					err,
				)
			}
			selector = setWindowsManagedRuntimeSelectorTarget(selector, restoredTarget)
		} else {
			selector = setWindowsManagedRuntimeSelectorTarget(
				selector,
				nilForSID(snapshot.TargetSID),
			)
		}
		return publishOrRemoveWindowsManagedRuntimeSelector(selector)
	})
}

func captureWindowsManagedRuntimeSelectorPlatform(
	connectorName string,
) (WindowsManagedRuntimeSelectorSnapshot, error) {
	var snapshot WindowsManagedRuntimeSelectorSnapshot
	name, err := canonicalWindowsManagedRuntimeConnector(connectorName)
	if err != nil || name != connectorName {
		return snapshot, errors.New("enterprise hooks: managed runtime selector snapshot connector is not canonical")
	}
	if err := windowsManagedRuntimeSelectorMutationAuthorize(); err != nil {
		return snapshot, err
	}
	snapshot = WindowsManagedRuntimeSelectorSnapshot{
		SchemaVersion: windowsManagedRuntimeGenerationSchema,
		Connector:     connectorName,
		CAS:           WindowsManagedRuntimeSelectorCAS{},
	}
	err = withWindowsManagedRuntimeSelectorTransaction(connectorName, func() error {
		_, data, exists, err := readWindowsManagedRuntimeSelector(connectorName, true)
		if err != nil {
			return err
		}
		if !exists {
			return nil
		}
		snapshot.Existed = true
		snapshot.Selector = append([]byte(nil), data...)
		snapshot.SelectorSHA256 = windowsManagedRuntimeSHA256(data)
		snapshot.CAS = WindowsManagedRuntimeSelectorCAS{
			Exists: true,
			SHA256: snapshot.SelectorSHA256,
		}
		return nil
	})
	return snapshot, err
}

func readWindowsManagedRuntimeSelectorCASPlatform(
	connectorName string,
) (WindowsManagedRuntimeSelectorCAS, error) {
	var cas WindowsManagedRuntimeSelectorCAS
	name, err := canonicalWindowsManagedRuntimeConnector(connectorName)
	if err != nil || name != connectorName {
		return cas, errors.New(
			"enterprise hooks: managed runtime selector read connector is not canonical",
		)
	}
	if err := windowsManagedRuntimeSelectorVerifyAuthorize(); err != nil {
		return cas, err
	}
	_, data, exists, err := readWindowsManagedRuntimeSelector(connectorName, true)
	if err != nil {
		return cas, err
	}
	cas.Exists = exists
	if exists {
		cas.SHA256 = windowsManagedRuntimeSHA256(data)
	}
	return cas, nil
}

func restoreWindowsManagedRuntimeSelectorCASPlatform(
	opts WindowsManagedRuntimeSelectorFullRestoreOptions,
) error {
	snapshot, restored, err := validateWindowsManagedRuntimeSelectorSnapshotFull(opts.Snapshot)
	if err != nil {
		return err
	}
	if err := validateWindowsManagedRuntimeSelectorCAS(opts.ExpectedCurrent); err != nil {
		return fmt.Errorf("enterprise hooks: invalid expected full selector CAS: %w", err)
	}
	if err := windowsManagedRuntimeSelectorMutationAuthorize(); err != nil {
		return err
	}
	return withWindowsManagedRuntimeSelectorTransaction(snapshot.Connector, func() error {
		_, currentData, currentExists, err := readWindowsManagedRuntimeSelector(
			snapshot.Connector,
			true,
		)
		if err != nil {
			return err
		}
		currentCAS := WindowsManagedRuntimeSelectorCAS{Exists: currentExists}
		if currentExists {
			currentCAS.SHA256 = windowsManagedRuntimeSHA256(currentData)
		}
		if !reflect.DeepEqual(currentCAS, opts.ExpectedCurrent) {
			return ErrWindowsManagedRuntimeGenerationConflict
		}
		if restored == nil {
			path, err := windowsManagedRuntimeSelectorPath(snapshot.Connector)
			if err != nil {
				return err
			}
			if currentExists {
				if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
					return fmt.Errorf("enterprise hooks: remove selector during exact lifecycle restore: %w", err)
				}
			}
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				return errors.New(
					"enterprise hooks: selector survived absent lifecycle restore",
				)
			}
			return nil
		}
		for _, entry := range restored.Targets {
			target, err := validateWindowsEnterpriseTargetSID(entry.SID)
			if err != nil {
				return err
			}
			if _, _, _, err := loadWindowsManagedRuntimeBundle(entry, target); err != nil {
				return fmt.Errorf(
					"enterprise hooks: refusing full selector restore with invalid %s bundle: %w",
					entry.SID,
					err,
				)
			}
		}
		return publishWindowsManagedRuntimeSelector(*restored)
	})
}

func discardWindowsManagedRuntimeGenerationPublicationPlatform(
	publication WindowsManagedRuntimeGenerationPublication,
) error {
	if publication.reused {
		return nil
	}
	desired, target, err := validateWindowsManagedRuntimeGenerationPublication(publication)
	if err != nil {
		return err
	}
	if err := windowsManagedRuntimeSelectorMutationAuthorize(); err != nil {
		return err
	}
	return withWindowsManagedRuntimeSelectorTransaction(desired.Connector, func() error {
		selector, _, exists, err := readWindowsManagedRuntimeSelector(desired.Connector, true)
		if err != nil {
			return err
		}
		if exists {
			if selected, ok := windowsManagedRuntimeSelectorTargetForSID(selector, desired.TargetSID); ok &&
				selected.GenerationID == publication.generationID {
				return ErrWindowsManagedRuntimeGenerationConflict
			}
		}
		entry := windowsManagedRuntimeSelectorTargetFromDesired(
			desired,
			publication.generationID,
			publication.bundleSHA256,
		)
		return deleteWindowsManagedRuntimeBundle(entry, target, publication.bundleBytes)
	})
}

func garbageCollectWindowsManagedRuntimeGenerationsPlatform(
	opts WindowsManagedRuntimeGenerationGCOptions,
) (int, error) {
	removed := 0
	snapshotOpts := WindowsManagedRuntimeSelectorSnapshotOptions{
		Connector:      opts.Connector,
		TargetSID:      opts.TargetSID,
		DataDir:        opts.DataDir,
		HookExecutable: opts.HookExecutable,
	}
	validated, target, err := validateWindowsManagedRuntimeSelectorSnapshotOptions(snapshotOpts)
	if err != nil {
		return 0, err
	}
	if validated.DataDir == "" {
		return 0, errors.New("enterprise hooks: managed runtime generation GC requires an exact data directory")
	}
	preserve := make(map[string]struct{}, len(opts.ProtectedPreserveGenerationIDs)+1)
	for _, generationID := range opts.ProtectedPreserveGenerationIDs {
		if !validWindowsManagedRuntimeGenerationID(generationID) {
			return 0, errors.New("enterprise hooks: protected managed runtime GC pin is invalid")
		}
		preserve[generationID] = struct{}{}
	}
	if err := windowsManagedRuntimeSelectorMutationAuthorize(); err != nil {
		return 0, err
	}
	if _, err := os.Lstat(validated.DataDir); errors.Is(err, os.ErrNotExist) {
		return 0, nil
	} else if err != nil {
		return 0, err
	}
	// GC is also used to retire a committed lifecycle journal before Guardian
	// has published the first immutable generation. Authenticate the existing
	// target-owned data root independently so that an absent hooks child can be
	// distinguished from an untrusted data root without weakening the strict
	// two-root validator used by publication and verification.
	if err := validateWindowsUserPathElement(
		validated.DataDir,
		target,
		true,
		true,
		true,
	); err != nil {
		return 0, fmt.Errorf(
			"enterprise hooks: managed runtime generation directory is untrusted: %w",
			err,
		)
	}
	err = withWindowsManagedRuntimeSelectorTransaction(validated.Connector, func() error {
		selector, _, exists, err := readWindowsManagedRuntimeSelector(validated.Connector, true)
		if err != nil {
			return err
		}
		selected := false
		if exists {
			if current, ok := windowsManagedRuntimeSelectorTargetForSID(selector, validated.TargetSID); ok {
				if err := validateWindowsManagedRuntimeSelectorTargetAgainstSnapshot(current, validated); err != nil {
					return err
				}
				selected = true
				preserve[current.GenerationID] = struct{}{}
			}
		}

		// Re-authenticate DataDir while holding the selector transaction before
		// using selector absence to authorize the empty pre-activation case.
		if err := validateWindowsUserPathElement(
			validated.DataDir,
			target,
			true,
			true,
			true,
		); err != nil {
			return fmt.Errorf(
				"enterprise hooks: managed runtime generation directory is untrusted: %w",
				err,
			)
		}

		hookDir := filepath.Join(validated.DataDir, "hooks")
		if _, err := os.Lstat(hookDir); errors.Is(err, os.ErrNotExist) {
			if selected {
				return fmt.Errorf(
					"enterprise hooks: selected managed runtime generation directory is absent: %w",
					os.ErrNotExist,
				)
			}
			return nil
		} else if err != nil {
			return err
		}
		if err := validateWindowsManagedRuntimeGenerationRoots(validated.DataDir, target); err != nil {
			return err
		}

		entries, err := os.ReadDir(hookDir)
		if err != nil {
			return err
		}
		candidates := 0
		for _, directoryEntry := range entries {
			connectorName, generationID, ok := parseWindowsManagedRuntimeBundleLeaf(
				directoryEntry.Name(),
			)
			if !ok || connectorName != validated.Connector {
				continue
			}
			candidates++
			if candidates > windowsManagedRuntimeGenerationGCMaxCandidates {
				return errors.New("enterprise hooks: managed runtime generation GC candidate limit exceeded")
			}
			if _, keep := preserve[generationID]; keep {
				continue
			}
			entry, data, err := loadUnselectedWindowsManagedRuntimeBundle(
				validated,
				target,
				generationID,
			)
			if err != nil {
				return err
			}
			if err := deleteWindowsManagedRuntimeBundle(entry, target, data); err != nil {
				return err
			}
			removed++
		}
		return nil
	})
	return removed, err
}

func loadUnselectedWindowsManagedRuntimeBundle(
	opts WindowsManagedRuntimeSelectorSnapshotOptions,
	target *windows.SID,
	generationID string,
) (windowsManagedRuntimeSelectorTarget, []byte, error) {
	var entry windowsManagedRuntimeSelectorTarget
	path, err := windowsManagedRuntimeBundlePath(opts.DataDir, opts.Connector, generationID)
	if err != nil {
		return entry, nil, err
	}
	data, err := loadWindowsManagedRuntimeBundleAtPath(path, target)
	if err != nil {
		return entry, nil, err
	}
	bundle, err := decodeWindowsManagedRuntimeBundle(data)
	if err != nil {
		return entry, nil, err
	}
	if bundle.GenerationID != generationID || bundle.Connector != opts.Connector ||
		bundle.TargetSID != opts.TargetSID || bundle.DataDir != opts.DataDir ||
		!sameWindowsEnterprisePath(bundle.DataDir, opts.DataDir) ||
		bundle.HookExecutable != opts.HookExecutable ||
		!sameWindowsEnterprisePath(bundle.HookExecutable, opts.HookExecutable) {
		return entry, nil, errors.New(
			"enterprise hooks: refusing to collect a managed runtime bundle with a foreign identity",
		)
	}
	desired := WindowsManagedRuntimeGenerationDesired{
		Connector:                  bundle.Connector,
		TargetSID:                  bundle.TargetSID,
		DataDir:                    bundle.DataDir,
		HookExecutable:             bundle.HookExecutable,
		GatewayAddr:                bundle.GatewayAddr,
		GatewayServiceName:         bundle.GatewayServiceName,
		ScopedToken:                bundle.ScopedToken,
		HookContractID:             bundle.HookContractID,
		HookContractLockUpdatedAt:  bundle.HookContractLockUpdatedAt,
		HookContractEntryUpdatedAt: bundle.HookContractEntryUpdatedAt,
	}
	if _, _, err := validateWindowsManagedRuntimeGenerationDesired(desired); err != nil {
		return entry, nil, errors.New(
			"enterprise hooks: refusing to collect an invalid managed runtime bundle",
		)
	}
	entry = windowsManagedRuntimeSelectorTargetFromDesired(
		desired,
		generationID,
		windowsManagedRuntimeSHA256(data),
	)
	if err := validateWindowsManagedRuntimeBundleAgainstSelector(bundle, entry); err != nil {
		return entry, nil, err
	}
	return entry, data, nil
}

func validateWindowsManagedRuntimeGenerationDesired(
	desired WindowsManagedRuntimeGenerationDesired,
) (WindowsManagedRuntimeGenerationDesired, *windows.SID, error) {
	connectorName, err := canonicalWindowsManagedRuntimeConnector(desired.Connector)
	if err != nil || connectorName != desired.Connector {
		return desired, nil, errors.New(
			"enterprise hooks: managed runtime generation connector is not canonical",
		)
	}
	target, err := validateWindowsEnterpriseTargetSID(desired.TargetSID)
	if err != nil || target.String() != desired.TargetSID {
		return desired, nil, errors.New(
			"enterprise hooks: managed runtime generation target SID is not canonical",
		)
	}
	if err := validateWindowsManagedRuntimeGenerationPath(desired.DataDir, ".defenseclaw"); err != nil {
		return desired, nil, fmt.Errorf("enterprise hooks: invalid managed runtime data directory: %w", err)
	}
	if err := validateWindowsManagedRuntimeGenerationPath(desired.HookExecutable, ""); err != nil {
		return desired, nil, fmt.Errorf("enterprise hooks: invalid managed hook executable: %w", err)
	}
	if !strings.EqualFold(filepath.Ext(desired.HookExecutable), ".exe") {
		return desired, nil, errors.New("enterprise hooks: managed hook executable is not an .exe file")
	}
	gatewayAddr, err := connector.NormalizeWindowsManagedGatewayAddr(desired.GatewayAddr)
	if err != nil || gatewayAddr != desired.GatewayAddr {
		return desired, nil, errors.New("enterprise hooks: managed runtime gateway address is not canonical")
	}
	if err := connector.ValidateWindowsManagedGatewayServiceName(desired.GatewayServiceName); err != nil {
		return desired, nil, err
	}
	if desired.ScopedToken == "" || desired.ScopedToken != strings.TrimSpace(desired.ScopedToken) ||
		len(desired.ScopedToken) > int(windowsEnterpriseTokenMaxBytes) ||
		strings.ContainsAny(desired.ScopedToken, "\x00\r\n") {
		return desired, nil, errors.New("enterprise hooks: managed runtime scoped token is invalid")
	}
	if !validWindowsManagedRuntimeText(desired.HookContractID, 256) ||
		!windowsManagedRuntimeKnownContract(desired.Connector, desired.HookContractID) {
		return desired, nil, errors.New("enterprise hooks: managed runtime hook contract is invalid")
	}
	lockTime, err := time.Parse(time.RFC3339Nano, desired.HookContractLockUpdatedAt)
	if err != nil {
		return desired, nil, errors.New("enterprise hooks: managed runtime hook contract lock timestamp is invalid")
	}
	entryTime, err := time.Parse(time.RFC3339Nano, desired.HookContractEntryUpdatedAt)
	if err != nil || entryTime.After(lockTime) {
		return desired, nil, errors.New("enterprise hooks: managed runtime hook contract entry timestamp is invalid")
	}
	return desired, target, nil
}

func validateWindowsManagedRuntimeGenerationResolveOptions(
	opts WindowsManagedRuntimeGenerationResolveOptions,
) (WindowsManagedRuntimeGenerationResolveOptions, *windows.SID, error) {
	desired := WindowsManagedRuntimeGenerationDesired{
		Connector:      opts.Connector,
		TargetSID:      opts.TargetSID,
		DataDir:        opts.DataDir,
		HookExecutable: opts.HookExecutable,
	}
	name, err := canonicalWindowsManagedRuntimeConnector(desired.Connector)
	if err != nil || name != desired.Connector {
		return opts, nil, errors.New("enterprise hooks: managed runtime connector is not canonical")
	}
	target, err := validateWindowsEnterpriseTargetSID(desired.TargetSID)
	if err != nil || target.String() != desired.TargetSID {
		return opts, nil, errors.New("enterprise hooks: managed runtime target SID is not canonical")
	}
	if err := validateWindowsManagedRuntimeGenerationPath(desired.DataDir, ".defenseclaw"); err != nil {
		return opts, nil, err
	}
	if err := validateWindowsManagedRuntimeGenerationPath(desired.HookExecutable, ""); err != nil ||
		!strings.EqualFold(filepath.Ext(desired.HookExecutable), ".exe") {
		return opts, nil, errors.New("enterprise hooks: managed runtime hook executable is invalid")
	}
	return opts, target, nil
}

func validateWindowsManagedRuntimeGenerationRemovalOptions(
	opts WindowsManagedRuntimeGenerationRemovalOptions,
) (WindowsManagedRuntimeGenerationRemovalOptions, *windows.SID, error) {
	name, err := canonicalWindowsManagedRuntimeConnector(opts.Connector)
	if err != nil || name != opts.Connector {
		return opts, nil, errors.New("enterprise hooks: managed runtime removal connector is not canonical")
	}
	target, err := validateWindowsEnterpriseTargetSID(opts.TargetSID)
	if err != nil || target.String() != opts.TargetSID {
		return opts, nil, errors.New("enterprise hooks: managed runtime removal SID is not canonical")
	}
	if opts.DataDir != "" {
		if err := validateWindowsManagedRuntimeGenerationPath(opts.DataDir, ".defenseclaw"); err != nil {
			return opts, nil, errors.New("enterprise hooks: managed runtime removal data directory is invalid")
		}
	}
	if err := validateWindowsManagedRuntimeGenerationPath(opts.HookExecutable, ""); err != nil ||
		!strings.EqualFold(filepath.Ext(opts.HookExecutable), ".exe") {
		return opts, nil, errors.New("enterprise hooks: managed runtime removal hook executable is invalid")
	}
	return opts, target, nil
}

func validateWindowsManagedRuntimeSelectorSnapshotOptions(
	opts WindowsManagedRuntimeSelectorSnapshotOptions,
) (WindowsManagedRuntimeSelectorSnapshotOptions, *windows.SID, error) {
	removal := WindowsManagedRuntimeGenerationRemovalOptions{
		Connector:      opts.Connector,
		TargetSID:      opts.TargetSID,
		DataDir:        opts.DataDir,
		HookExecutable: opts.HookExecutable,
	}
	_, target, err := validateWindowsManagedRuntimeGenerationRemovalOptions(removal)
	return opts, target, err
}

func validateWindowsManagedRuntimeSelectorTargetAgainstSnapshot(
	entry windowsManagedRuntimeSelectorTarget,
	opts WindowsManagedRuntimeSelectorSnapshotOptions,
) error {
	removal := WindowsManagedRuntimeGenerationRemovalOptions{
		Connector:      opts.Connector,
		TargetSID:      opts.TargetSID,
		DataDir:        opts.DataDir,
		HookExecutable: opts.HookExecutable,
	}
	return validateWindowsManagedRuntimeSelectorTargetAgainstRemoval(entry, removal)
}

func marshalWindowsManagedRuntimeSelectorTarget(
	entry windowsManagedRuntimeSelectorTarget,
) ([]byte, error) {
	data, err := json.Marshal(entry)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func decodeWindowsManagedRuntimeSelectorTarget(
	data []byte,
	connectorName,
	targetSID string,
) (windowsManagedRuntimeSelectorTarget, error) {
	var entry windowsManagedRuntimeSelectorTarget
	if int64(len(data)) > windowsManagedRuntimeSelectorMaxBytes {
		return entry, errors.New("enterprise hooks: selector target snapshot exceeds size limit")
	}
	if err := decodeWindowsManagedRuntimeExactJSON(data, &entry); err != nil {
		return entry, err
	}
	if err := validateWindowsManagedRuntimeSelectorTarget(entry, connectorName); err != nil ||
		entry.SID != targetSID {
		return entry, errors.New("enterprise hooks: selector target snapshot identity is invalid")
	}
	canonical, err := marshalWindowsManagedRuntimeSelectorTarget(entry)
	if err != nil || !bytes.Equal(canonical, data) {
		return entry, errors.New("enterprise hooks: selector target snapshot is noncanonical")
	}
	return entry, nil
}

func windowsManagedRuntimeSelectorTargetCAS(
	entry *windowsManagedRuntimeSelectorTarget,
) WindowsManagedRuntimeSelectorTargetCAS {
	if entry == nil {
		return WindowsManagedRuntimeSelectorTargetCAS{}
	}
	data, err := marshalWindowsManagedRuntimeSelectorTarget(*entry)
	if err != nil {
		return WindowsManagedRuntimeSelectorTargetCAS{}
	}
	return WindowsManagedRuntimeSelectorTargetCAS{
		Exists:       true,
		GenerationID: entry.GenerationID,
		BundleSHA256: entry.BundleSHA256,
		TargetSHA256: windowsManagedRuntimeSHA256(data),
	}
}

func optionalWindowsManagedRuntimeSelectorTarget(
	entry windowsManagedRuntimeSelectorTarget,
	exists bool,
) *windowsManagedRuntimeSelectorTarget {
	if !exists {
		return nil
	}
	return &entry
}

func validateWindowsManagedRuntimeSelectorTargetCAS(
	cas WindowsManagedRuntimeSelectorTargetCAS,
) error {
	if !cas.Exists {
		if cas.GenerationID != "" || cas.BundleSHA256 != "" || cas.TargetSHA256 != "" {
			return errors.New("absent selector target CAS contains an identity")
		}
		return nil
	}
	if !validWindowsManagedRuntimeGenerationID(cas.GenerationID) ||
		!validWindowsManagedRuntimeSHA256(cas.BundleSHA256) ||
		!validWindowsManagedRuntimeSHA256(cas.TargetSHA256) {
		return errors.New("selector target CAS identity is invalid")
	}
	return nil
}

func validateWindowsManagedRuntimeSelectorSnapshot(
	snapshot WindowsManagedRuntimeSelectorTargetSnapshot,
) (WindowsManagedRuntimeSelectorTargetSnapshot, *windowsManagedRuntimeSelectorTarget, *windows.SID, error) {
	if snapshot.SchemaVersion != windowsManagedRuntimeGenerationSchema {
		return snapshot, nil, nil, errors.New("enterprise hooks: selector target snapshot schema is unsupported")
	}
	name, err := canonicalWindowsManagedRuntimeConnector(snapshot.Connector)
	if err != nil || name != snapshot.Connector {
		return snapshot, nil, nil, errors.New("enterprise hooks: selector target snapshot connector is invalid")
	}
	targetSID, err := validateWindowsEnterpriseTargetSID(snapshot.TargetSID)
	if err != nil || targetSID.String() != snapshot.TargetSID {
		return snapshot, nil, nil, errors.New("enterprise hooks: selector target snapshot SID is invalid")
	}
	if err := validateWindowsManagedRuntimeSelectorTargetCAS(snapshot.CAS); err != nil {
		return snapshot, nil, nil, err
	}
	if !snapshot.Existed {
		if len(snapshot.Target) != 0 || snapshot.TargetSHA256 != "" || snapshot.CAS.Exists {
			return snapshot, nil, nil, errors.New("enterprise hooks: absent selector target snapshot contains state")
		}
		return snapshot, nil, targetSID, nil
	}
	entry, err := decodeWindowsManagedRuntimeSelectorTarget(
		snapshot.Target,
		snapshot.Connector,
		snapshot.TargetSID,
	)
	if err != nil {
		return snapshot, nil, nil, err
	}
	digest := windowsManagedRuntimeSHA256(snapshot.Target)
	if snapshot.TargetSHA256 != digest ||
		!reflect.DeepEqual(snapshot.CAS, windowsManagedRuntimeSelectorTargetCAS(&entry)) {
		return snapshot, nil, nil, errors.New("enterprise hooks: selector target snapshot digest does not match its state")
	}
	return snapshot, &entry, targetSID, nil
}

func validateWindowsManagedRuntimeSelectorCAS(cas WindowsManagedRuntimeSelectorCAS) error {
	if !cas.Exists {
		if cas.SHA256 != "" {
			return errors.New("absent full selector CAS contains a digest")
		}
		return nil
	}
	if !validWindowsManagedRuntimeSHA256(cas.SHA256) {
		return errors.New("full selector CAS digest is invalid")
	}
	return nil
}

func validateWindowsManagedRuntimeSelectorSnapshotFull(
	snapshot WindowsManagedRuntimeSelectorSnapshot,
) (WindowsManagedRuntimeSelectorSnapshot, *windowsManagedRuntimeSelector, error) {
	if snapshot.SchemaVersion != windowsManagedRuntimeGenerationSchema {
		return snapshot, nil, errors.New("enterprise hooks: full selector snapshot schema is unsupported")
	}
	name, err := canonicalWindowsManagedRuntimeConnector(snapshot.Connector)
	if err != nil || name != snapshot.Connector {
		return snapshot, nil, errors.New("enterprise hooks: full selector snapshot connector is invalid")
	}
	if err := validateWindowsManagedRuntimeSelectorCAS(snapshot.CAS); err != nil {
		return snapshot, nil, err
	}
	if !snapshot.Existed {
		if len(snapshot.Selector) != 0 || snapshot.SelectorSHA256 != "" || snapshot.CAS.Exists {
			return snapshot, nil, errors.New("enterprise hooks: absent full selector snapshot contains state")
		}
		return snapshot, nil, nil
	}
	selector, err := decodeWindowsManagedRuntimeSelector(snapshot.Selector, snapshot.Connector)
	if err != nil {
		return snapshot, nil, err
	}
	digest := windowsManagedRuntimeSHA256(snapshot.Selector)
	if snapshot.SelectorSHA256 != digest ||
		!reflect.DeepEqual(snapshot.CAS, WindowsManagedRuntimeSelectorCAS{Exists: true, SHA256: digest}) {
		return snapshot, nil, errors.New("enterprise hooks: full selector snapshot digest does not match its state")
	}
	return snapshot, &selector, nil
}

func validateWindowsManagedRuntimeGenerationPublication(
	publication WindowsManagedRuntimeGenerationPublication,
) (WindowsManagedRuntimeGenerationDesired, *windows.SID, error) {
	desired, target, err := validateWindowsManagedRuntimeGenerationDesired(publication.desired)
	if err != nil {
		return desired, nil, err
	}
	if !validWindowsManagedRuntimeGenerationID(publication.generationID) ||
		!validWindowsManagedRuntimeSHA256(publication.bundleSHA256) ||
		windowsManagedRuntimeSHA256(publication.bundleBytes) != publication.bundleSHA256 {
		return desired, nil, errors.New("enterprise hooks: invalid managed runtime generation publication receipt")
	}
	expectedPath, err := windowsManagedRuntimeBundlePath(
		desired.DataDir,
		desired.Connector,
		publication.generationID,
	)
	if err != nil || publication.bundlePath != expectedPath {
		return desired, nil, errors.New("enterprise hooks: managed runtime generation publication path is invalid")
	}
	return desired, target, nil
}

func canonicalWindowsManagedRuntimeConnector(raw string) (string, error) {
	if raw != strings.TrimSpace(raw) || raw != strings.ToLower(raw) {
		return "", errors.New("connector is not canonical")
	}
	switch raw {
	case "claudecode", "codex", "cursor":
		return raw, nil
	default:
		return "", fmt.Errorf("unsupported managed connector %q", raw)
	}
}

func validateWindowsManagedRuntimeGenerationPath(path, requiredLeaf string) error {
	if path == "" || path != strings.TrimSpace(path) || !filepath.IsAbs(path) ||
		filepath.Clean(path) != path {
		return errors.New("path is not absolute and canonical")
	}
	if requiredLeaf != "" && !strings.EqualFold(filepath.Base(path), requiredLeaf) {
		return fmt.Errorf("path leaf is not %s", requiredLeaf)
	}
	return nil
}

func validWindowsManagedRuntimeText(value string, maximum int) bool {
	return value != "" && value == strings.TrimSpace(value) && len(value) <= maximum &&
		!strings.ContainsAny(value, "\x00\r\n")
}

func windowsManagedRuntimeKnownContract(connectorName, contractID string) bool {
	for _, contract := range connector.KnownHookContracts(connectorName) {
		if contract.ContractID == contractID {
			return true
		}
	}
	return false
}

func requireWindowsManagedRuntimeEffectiveTarget(target *windows.SID) error {
	if target == nil {
		return errors.New("enterprise hooks: managed runtime target SID is unavailable")
	}
	user, err := windows.GetCurrentThreadEffectiveToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return fmt.Errorf("enterprise hooks: resolve effective managed runtime SID: %w", err)
	}
	if !user.User.Sid.Equals(target) {
		return fmt.Errorf(
			"enterprise hooks: effective managed runtime SID %s does not match target SID %s",
			user.User.Sid,
			target,
		)
	}
	return nil
}

func requireWindowsManagedRuntimeProcessTarget(target *windows.SID) error {
	if target == nil {
		return errors.New("enterprise hooks: managed runtime target SID is unavailable")
	}
	// GetCurrentThreadEffectiveToken resolves the process token for an ordinary
	// native hook process and the pinned target token for Guardian verification
	// performed inside the authenticated impersonation boundary.
	user, err := windows.GetCurrentThreadEffectiveToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return fmt.Errorf("enterprise hooks: resolve managed hook effective SID: %w", err)
	}
	if !user.User.Sid.Equals(target) {
		return fmt.Errorf(
			"enterprise hooks: managed hook effective SID %s does not match enrolled SID %s",
			user.User.Sid,
			target,
		)
	}
	return nil
}

func validateWindowsManagedRuntimeGenerationRoots(dataDir string, target *windows.SID) error {
	hookDir := filepath.Join(dataDir, "hooks")
	for _, path := range []string{dataDir, hookDir} {
		if err := validateWindowsUserPathElement(path, target, true, true, true); err != nil {
			return fmt.Errorf(
				"enterprise hooks: managed runtime generation directory is untrusted: %w",
				err,
			)
		}
	}
	return nil
}

func newWindowsManagedRuntimeGenerationID() (string, error) {
	var value [16]byte
	if _, err := io.ReadFull(windowsManagedRuntimeGenerationEntropy, value[:]); err != nil {
		return "", fmt.Errorf("enterprise hooks: generate managed runtime generation ID: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}

func validWindowsManagedRuntimeGenerationID(value string) bool {
	if len(value) != 32 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 16
}

func windowsManagedRuntimeSHA256(data []byte) string {
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func validWindowsManagedRuntimeSHA256(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 ||
		!strings.HasPrefix(value, "sha256:") || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size
}

func windowsManagedRuntimeBundleLeaf(connectorName, generationID string) (string, error) {
	name, err := canonicalWindowsManagedRuntimeConnector(connectorName)
	if err != nil || name != connectorName || !validWindowsManagedRuntimeGenerationID(generationID) {
		return "", errors.New("enterprise hooks: invalid managed runtime bundle identity")
	}
	return ".managed-runtime-" + name + "-" + generationID + ".json", nil
}

func parseWindowsManagedRuntimeBundleLeaf(leaf string) (string, string, bool) {
	if filepath.Base(leaf) != leaf || !strings.HasPrefix(leaf, ".managed-runtime-") ||
		!strings.HasSuffix(leaf, ".json") {
		return "", "", false
	}
	identity := strings.TrimSuffix(strings.TrimPrefix(leaf, ".managed-runtime-"), ".json")
	for _, connectorName := range []string{"claudecode", "codex", "cursor"} {
		prefix := connectorName + "-"
		if !strings.HasPrefix(identity, prefix) {
			continue
		}
		generationID := strings.TrimPrefix(identity, prefix)
		expected, err := windowsManagedRuntimeBundleLeaf(connectorName, generationID)
		if err == nil && expected == leaf {
			return connectorName, generationID, true
		}
	}
	return "", "", false
}

func windowsManagedRuntimeBundlePath(dataDir, connectorName, generationID string) (string, error) {
	if err := validateWindowsManagedRuntimeGenerationPath(dataDir, ".defenseclaw"); err != nil {
		return "", err
	}
	leaf, err := windowsManagedRuntimeBundleLeaf(connectorName, generationID)
	if err != nil {
		return "", err
	}
	return filepath.Join(dataDir, "hooks", leaf), nil
}

func windowsManagedRuntimeBundleFromDesired(
	desired WindowsManagedRuntimeGenerationDesired,
	generationID string,
) windowsManagedRuntimeBundle {
	return windowsManagedRuntimeBundle{
		SchemaVersion:              windowsManagedRuntimeGenerationSchema,
		GenerationID:               generationID,
		Connector:                  desired.Connector,
		TargetSID:                  desired.TargetSID,
		DataDir:                    desired.DataDir,
		HookExecutable:             desired.HookExecutable,
		GatewayAddr:                desired.GatewayAddr,
		GatewayServiceName:         desired.GatewayServiceName,
		FailMode:                   "closed",
		ScopedToken:                desired.ScopedToken,
		HookContractID:             desired.HookContractID,
		HookContractLockUpdatedAt:  desired.HookContractLockUpdatedAt,
		HookContractEntryUpdatedAt: desired.HookContractEntryUpdatedAt,
	}
}

func windowsManagedRuntimeSelectorTargetFromDesired(
	desired WindowsManagedRuntimeGenerationDesired,
	generationID, bundleSHA256 string,
) windowsManagedRuntimeSelectorTarget {
	return windowsManagedRuntimeSelectorTarget{
		Connector:          desired.Connector,
		SID:                desired.TargetSID,
		DataDir:            desired.DataDir,
		HookExecutable:     desired.HookExecutable,
		GatewayAddr:        desired.GatewayAddr,
		GatewayServiceName: desired.GatewayServiceName,
		GenerationID:       generationID,
		BundleSHA256:       bundleSHA256,
	}
}

func marshalWindowsManagedRuntimeBundle(bundle windowsManagedRuntimeBundle) ([]byte, error) {
	data, err := json.Marshal(bundle)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func decodeWindowsManagedRuntimeBundle(data []byte) (windowsManagedRuntimeBundle, error) {
	var bundle windowsManagedRuntimeBundle
	if int64(len(data)) > windowsManagedRuntimeBundleMaxBytes {
		return bundle, errors.New("enterprise hooks: managed runtime bundle exceeds size limit")
	}
	if err := decodeWindowsManagedRuntimeExactJSON(data, &bundle); err != nil {
		return bundle, fmt.Errorf("enterprise hooks: decode managed runtime bundle: %w", err)
	}
	canonical, err := marshalWindowsManagedRuntimeBundle(bundle)
	if err != nil || !bytes.Equal(data, canonical) {
		return bundle, errors.New("enterprise hooks: managed runtime bundle JSON is noncanonical")
	}
	return bundle, nil
}

func validateWindowsManagedRuntimeBundleAgainstSelector(
	bundle windowsManagedRuntimeBundle,
	entry windowsManagedRuntimeSelectorTarget,
) error {
	if bundle.SchemaVersion != windowsManagedRuntimeGenerationSchema ||
		bundle.GenerationID != entry.GenerationID ||
		bundle.Connector != entry.Connector || bundle.TargetSID != entry.SID ||
		!sameWindowsEnterprisePath(bundle.DataDir, entry.DataDir) || bundle.DataDir != entry.DataDir ||
		!sameWindowsEnterprisePath(bundle.HookExecutable, entry.HookExecutable) || bundle.HookExecutable != entry.HookExecutable ||
		bundle.GatewayAddr != entry.GatewayAddr ||
		bundle.GatewayServiceName != entry.GatewayServiceName ||
		bundle.FailMode != "closed" {
		return errors.New("enterprise hooks: managed runtime bundle does not match its protected selector")
	}
	desired := WindowsManagedRuntimeGenerationDesired{
		Connector:                  bundle.Connector,
		TargetSID:                  bundle.TargetSID,
		DataDir:                    bundle.DataDir,
		HookExecutable:             bundle.HookExecutable,
		GatewayAddr:                bundle.GatewayAddr,
		GatewayServiceName:         bundle.GatewayServiceName,
		ScopedToken:                bundle.ScopedToken,
		HookContractID:             bundle.HookContractID,
		HookContractLockUpdatedAt:  bundle.HookContractLockUpdatedAt,
		HookContractEntryUpdatedAt: bundle.HookContractEntryUpdatedAt,
	}
	if _, _, err := validateWindowsManagedRuntimeGenerationDesired(desired); err != nil {
		return errors.New("enterprise hooks: managed runtime bundle contains invalid authenticated fields")
	}
	return nil
}

func windowsManagedRuntimeBundleMatchesDesired(
	bundle windowsManagedRuntimeBundle,
	desired WindowsManagedRuntimeGenerationDesired,
) bool {
	return bundle.Connector == desired.Connector &&
		bundle.TargetSID == desired.TargetSID && bundle.DataDir == desired.DataDir &&
		bundle.HookExecutable == desired.HookExecutable &&
		bundle.GatewayAddr == desired.GatewayAddr &&
		bundle.GatewayServiceName == desired.GatewayServiceName &&
		bundle.FailMode == "closed" &&
		subtle.ConstantTimeCompare([]byte(bundle.ScopedToken), []byte(desired.ScopedToken)) == 1 &&
		bundle.HookContractID == desired.HookContractID &&
		// The lock timestamp is audit metadata for the shared, multi-connector
		// hook_contract_lock.json. A later authenticated update to a different
		// connector advances it without changing this connector's contract.
		// HookContractEntryUpdatedAt is the stable connector-scoped identity.
		bundle.HookContractEntryUpdatedAt == desired.HookContractEntryUpdatedAt
}

func loadWindowsManagedRuntimeBundle(
	entry windowsManagedRuntimeSelectorTarget,
	target *windows.SID,
) (windowsManagedRuntimeBundle, []byte, string, error) {
	var bundle windowsManagedRuntimeBundle
	if err := validateWindowsManagedRuntimeSelectorTarget(entry, ""); err != nil {
		return bundle, nil, "", err
	}
	path, err := windowsManagedRuntimeBundlePath(entry.DataDir, entry.Connector, entry.GenerationID)
	if err != nil {
		return bundle, nil, "", err
	}
	data, err := loadWindowsManagedRuntimeBundleAtPath(path, target)
	if err != nil {
		return bundle, nil, path, err
	}
	if windowsManagedRuntimeSHA256(data) != entry.BundleSHA256 {
		return bundle, nil, path, errors.New("enterprise hooks: managed runtime bundle digest does not match protected selector")
	}
	bundle, err = decodeWindowsManagedRuntimeBundle(data)
	if err != nil {
		return bundle, nil, path, err
	}
	if err := validateWindowsManagedRuntimeBundleAgainstSelector(bundle, entry); err != nil {
		return bundle, nil, path, err
	}
	return bundle, data, path, nil
}

func loadWindowsManagedRuntimeBundleAtPath(
	path string,
	target *windows.SID,
) ([]byte, error) {
	if target == nil {
		return nil, errors.New("enterprise hooks: managed runtime bundle target SID is unavailable")
	}
	if err := validateWindowsUserPathElement(path, target, false, false, true); err != nil {
		return nil, fmt.Errorf("enterprise hooks: managed runtime bundle trust check failed: %w", err)
	}
	data, err := connector.ReadManagedHookRuntimeFile(
		path,
		"immutable managed runtime generation",
		windowsManagedRuntimeBundleMaxBytes,
	)
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: read immutable managed runtime generation: %w", err)
	}
	if err := validateWindowsUserPathElement(path, target, false, false, true); err != nil {
		return nil, fmt.Errorf("enterprise hooks: managed runtime bundle changed protection during read: %w", err)
	}
	return data, nil
}

func defaultWindowsManagedRuntimeSelectorPath(connectorName string) (string, error) {
	name, err := canonicalWindowsManagedRuntimeConnector(connectorName)
	if err != nil {
		return "", err
	}
	var directory string
	switch name {
	case "claudecode":
		policyPath, err := windowsClaudeManagedPolicyPath()
		if err != nil {
			return "", err
		}
		directory = filepath.Dir(policyPath)
	case "cursor":
		cursorPaths, err := windowsCursorManagedPaths()
		if err != nil {
			return "", err
		}
		directory = cursorPaths.Root
	case "codex":
		requirementsPath, err := windowsCodexMachineRequirementsPath()
		if err != nil {
			return "", err
		}
		directory = filepath.Dir(requirementsPath)
	default:
		return "", fmt.Errorf("enterprise hooks: unsupported managed runtime selector connector %q", name)
	}
	return filepath.Join(directory, windowsManagedRuntimeSelectorFile), nil
}

func windowsManagedRuntimeSelectorPath(connectorName string) (string, error) {
	name, err := canonicalWindowsManagedRuntimeConnector(connectorName)
	if err != nil || name != connectorName {
		return "", errors.New("enterprise hooks: managed runtime selector connector is not canonical")
	}
	path, err := windowsManagedRuntimeSelectorPathResolver(name)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		filepath.Base(path) != windowsManagedRuntimeSelectorFile {
		return "", fmt.Errorf("enterprise hooks: refusing noncanonical managed runtime selector path: %s", path)
	}
	return path, nil
}

func readWindowsManagedRuntimeSelector(
	connectorName string,
	allowMissing bool,
) (windowsManagedRuntimeSelector, []byte, bool, error) {
	var selector windowsManagedRuntimeSelector
	path, err := windowsManagedRuntimeSelectorPath(connectorName)
	if err != nil {
		return selector, nil, false, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if allowMissing {
			return selector, nil, false, nil
		}
		return selector, nil, false, fmt.Errorf(
			"enterprise hooks: managed runtime selector is absent: %w",
			os.ErrNotExist,
		)
	}
	if err != nil {
		return selector, nil, false, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() < 0 || info.Size() > windowsManagedRuntimeSelectorMaxBytes {
		return selector, nil, false, errors.New(
			"enterprise hooks: managed runtime selector is not a bounded regular file",
		)
	}
	if err := validateWindowsManagedRuntimeMachineFileProtection(path, true); err != nil {
		return selector, nil, false, err
	}
	data, err := connector.ReadManagedHookRuntimeFile(
		path,
		"machine-protected managed runtime selector",
		windowsManagedRuntimeSelectorMaxBytes,
	)
	if err != nil {
		return selector, nil, false, err
	}
	if err := validateWindowsManagedRuntimeMachineFileProtection(path, true); err != nil {
		return selector, nil, false, err
	}
	selector, err = decodeWindowsManagedRuntimeSelector(data, connectorName)
	if err != nil {
		return selector, nil, false, err
	}
	return selector, data, true, nil
}

func marshalWindowsManagedRuntimeSelector(
	selector windowsManagedRuntimeSelector,
) ([]byte, error) {
	data, err := json.Marshal(selector)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func decodeWindowsManagedRuntimeSelector(
	data []byte,
	expectedConnector string,
) (windowsManagedRuntimeSelector, error) {
	var selector windowsManagedRuntimeSelector
	if int64(len(data)) > windowsManagedRuntimeSelectorMaxBytes {
		return selector, errors.New("enterprise hooks: managed runtime selector exceeds size limit")
	}
	if err := decodeWindowsManagedRuntimeExactJSON(data, &selector); err != nil {
		return selector, fmt.Errorf("enterprise hooks: decode managed runtime selector: %w", err)
	}
	if err := validateWindowsManagedRuntimeSelector(selector, expectedConnector); err != nil {
		return selector, err
	}
	canonical, err := marshalWindowsManagedRuntimeSelector(selector)
	if err != nil || !bytes.Equal(data, canonical) {
		return selector, errors.New("enterprise hooks: managed runtime selector JSON is noncanonical")
	}
	return selector, nil
}

func decodeWindowsManagedRuntimeExactJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func validateWindowsManagedRuntimeSelector(
	selector windowsManagedRuntimeSelector,
	expectedConnector string,
) error {
	name, err := canonicalWindowsManagedRuntimeConnector(selector.Connector)
	if err != nil || name != selector.Connector || selector.Connector != expectedConnector {
		return errors.New("enterprise hooks: managed runtime selector connector is invalid")
	}
	if selector.SchemaVersion != windowsManagedRuntimeGenerationSchema {
		return errors.New("enterprise hooks: managed runtime selector schema version is unsupported")
	}
	if selector.Targets == nil || len(selector.Targets) > windowsManagedRuntimeSelectorMaxTargets {
		return errors.New("enterprise hooks: managed runtime selector target set is invalid")
	}
	previous := ""
	for index, target := range selector.Targets {
		if err := validateWindowsManagedRuntimeSelectorTarget(target, selector.Connector); err != nil {
			return fmt.Errorf("enterprise hooks: invalid managed runtime selector target %d: %w", index, err)
		}
		if index > 0 && target.SID <= previous {
			return errors.New("enterprise hooks: managed runtime selector targets are not strictly sorted")
		}
		previous = target.SID
	}
	return nil
}

func validateWindowsManagedRuntimeSelectorTarget(
	entry windowsManagedRuntimeSelectorTarget,
	expectedConnector string,
) error {
	name, err := canonicalWindowsManagedRuntimeConnector(entry.Connector)
	if err != nil || name != entry.Connector ||
		(expectedConnector != "" && entry.Connector != expectedConnector) {
		return errors.New("selector target connector is invalid")
	}
	sid, err := validateWindowsEnterpriseTargetSID(entry.SID)
	if err != nil || sid.String() != entry.SID {
		return errors.New("selector target SID is invalid")
	}
	if err := validateWindowsManagedRuntimeGenerationPath(entry.DataDir, ".defenseclaw"); err != nil {
		return errors.New("selector target data directory is invalid")
	}
	if err := validateWindowsManagedRuntimeGenerationPath(entry.HookExecutable, ""); err != nil ||
		!strings.EqualFold(filepath.Ext(entry.HookExecutable), ".exe") {
		return errors.New("selector target hook executable is invalid")
	}
	if normalized, err := connector.NormalizeWindowsManagedGatewayAddr(entry.GatewayAddr); err != nil ||
		normalized != entry.GatewayAddr {
		return errors.New("selector target gateway address is invalid")
	}
	if err := connector.ValidateWindowsManagedGatewayServiceName(entry.GatewayServiceName); err != nil {
		return err
	}
	if !validWindowsManagedRuntimeGenerationID(entry.GenerationID) ||
		!validWindowsManagedRuntimeSHA256(entry.BundleSHA256) {
		return errors.New("selector target generation binding is invalid")
	}
	return nil
}

func validateWindowsManagedRuntimeSelectorTargetAgainstResolve(
	entry windowsManagedRuntimeSelectorTarget,
	opts WindowsManagedRuntimeGenerationResolveOptions,
) error {
	if entry.Connector != opts.Connector || entry.SID != opts.TargetSID ||
		entry.HookExecutable != opts.HookExecutable ||
		!sameWindowsEnterprisePath(entry.HookExecutable, opts.HookExecutable) {
		return errors.New(
			"enterprise hooks: managed runtime selector does not match authenticated primary machine policy",
		)
	}
	if opts.DataDir != "" && (entry.DataDir != opts.DataDir ||
		!sameWindowsEnterprisePath(entry.DataDir, opts.DataDir)) {
		return errors.New(
			"enterprise hooks: managed runtime selector does not match the authenticated primary data directory",
		)
	}
	return nil
}

func validateWindowsManagedRuntimeSelectorTargetAgainstRemoval(
	entry windowsManagedRuntimeSelectorTarget,
	opts WindowsManagedRuntimeGenerationRemovalOptions,
) error {
	if entry.Connector != opts.Connector || entry.SID != opts.TargetSID ||
		entry.HookExecutable != opts.HookExecutable ||
		!sameWindowsEnterprisePath(entry.HookExecutable, opts.HookExecutable) {
		return errors.New(
			"enterprise hooks: refusing to remove a managed runtime selector entry owned by another deployment",
		)
	}
	if opts.DataDir != "" && (entry.DataDir != opts.DataDir ||
		!sameWindowsEnterprisePath(entry.DataDir, opts.DataDir)) {
		return errors.New(
			"enterprise hooks: refusing to remove a managed runtime selector entry with a different data directory",
		)
	}
	return nil
}

func windowsManagedRuntimeSelectorTargetMatchesDesired(
	entry windowsManagedRuntimeSelectorTarget,
	desired WindowsManagedRuntimeGenerationDesired,
) bool {
	return entry.Connector == desired.Connector && entry.SID == desired.TargetSID &&
		entry.DataDir == desired.DataDir && entry.HookExecutable == desired.HookExecutable &&
		entry.GatewayAddr == desired.GatewayAddr &&
		entry.GatewayServiceName == desired.GatewayServiceName
}

func windowsManagedRuntimeSelectorTargetForSID(
	selector windowsManagedRuntimeSelector,
	sid string,
) (windowsManagedRuntimeSelectorTarget, bool) {
	index := sort.Search(len(selector.Targets), func(index int) bool {
		return selector.Targets[index].SID >= sid
	})
	if index >= len(selector.Targets) || selector.Targets[index].SID != sid {
		return windowsManagedRuntimeSelectorTarget{}, false
	}
	return selector.Targets[index], true
}

func setWindowsManagedRuntimeSelectorTarget(
	selector windowsManagedRuntimeSelector,
	target *windowsManagedRuntimeSelectorTarget,
) windowsManagedRuntimeSelector {
	if target == nil {
		return selector
	}
	result := selector
	result.Targets = make([]windowsManagedRuntimeSelectorTarget, 0, len(selector.Targets)+1)
	removed := target.GenerationID == ""
	for _, current := range selector.Targets {
		if current.SID != target.SID {
			result.Targets = append(result.Targets, current)
		}
	}
	if !removed {
		result.Targets = append(result.Targets, *target)
	}
	sort.Slice(result.Targets, func(left, right int) bool {
		return result.Targets[left].SID < result.Targets[right].SID
	})
	return result
}

func nilForSID(sid string) *windowsManagedRuntimeSelectorTarget {
	return &windowsManagedRuntimeSelectorTarget{SID: sid}
}

func windowsManagedRuntimeOptionalSelectorTargetsEqual(
	current windowsManagedRuntimeSelectorTarget,
	currentExists bool,
	expected *windowsManagedRuntimeSelectorTarget,
) bool {
	if expected == nil {
		return !currentExists
	}
	return currentExists && reflect.DeepEqual(current, *expected)
}

func cloneWindowsManagedRuntimeSelectorTarget(
	target *windowsManagedRuntimeSelectorTarget,
) *windowsManagedRuntimeSelectorTarget {
	if target == nil {
		return nil
	}
	copy := *target
	return &copy
}

func publishWindowsManagedRuntimeSelector(selector windowsManagedRuntimeSelector) error {
	if err := validateWindowsManagedRuntimeSelector(selector, selector.Connector); err != nil {
		return err
	}
	data, err := marshalWindowsManagedRuntimeSelector(selector)
	if err != nil {
		return err
	}
	if int64(len(data)) > windowsManagedRuntimeSelectorMaxBytes {
		return errors.New("enterprise hooks: managed runtime selector exceeds size limit")
	}
	path, err := windowsManagedRuntimeSelectorPath(selector.Connector)
	if err != nil {
		return err
	}
	if err := windowsManagedRuntimeSelectorWriter(path, data, true); err != nil {
		return fmt.Errorf("enterprise hooks: publish managed runtime selector: %w", err)
	}
	if err := setWindowsManagedPolicyProtection(path, false, true); err != nil {
		return fmt.Errorf("enterprise hooks: harden managed runtime selector: %w", err)
	}
	if err := validateWindowsManagedRuntimeMachineFileProtection(path, true); err != nil {
		return err
	}
	_, persisted, exists, err := readWindowsManagedRuntimeSelector(selector.Connector, false)
	if err != nil || !exists {
		return fmt.Errorf("enterprise hooks: verify managed runtime selector publication: %w", err)
	}
	if !bytes.Equal(persisted, data) {
		return errors.New("enterprise hooks: persisted managed runtime selector bytes differ from publication")
	}
	return nil
}

func publishOrRemoveWindowsManagedRuntimeSelector(
	selector windowsManagedRuntimeSelector,
) error {
	if len(selector.Targets) != 0 {
		return publishWindowsManagedRuntimeSelector(selector)
	}
	path, err := windowsManagedRuntimeSelectorPath(selector.Connector)
	if err != nil {
		return err
	}
	if _, _, exists, err := readWindowsManagedRuntimeSelector(selector.Connector, true); err != nil {
		return err
	} else if !exists {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("enterprise hooks: remove empty managed runtime selector: %w", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errors.New("enterprise hooks: empty managed runtime selector survived removal")
	}
	return nil
}

func withWindowsManagedRuntimeSelectorTransaction(
	connectorName string,
	fn func() error,
) error {
	path, err := windowsManagedRuntimeSelectorPath(connectorName)
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	if err := ensureWindowsManagedPolicyDirectory(directory); err != nil {
		return fmt.Errorf("enterprise hooks: prepare managed runtime selector directory: %w", err)
	}
	if err := rejectWindowsReparseChain(directory); err != nil {
		return err
	}
	if err := windowsManagedPolicyDirTrustCheck(directory); err != nil {
		return fmt.Errorf("enterprise hooks: managed runtime selector directory is untrusted: %w", err)
	}
	lockPath := filepath.Join(directory, windowsManagedRuntimeSelectorLockFile)
	if info, statErr := os.Lstat(lockPath); statErr == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("enterprise hooks: managed runtime selector lock is not a regular file")
		}
		if err := validateWindowsManagedRuntimeMachineFileProtection(lockPath, false); err != nil {
			return fmt.Errorf("enterprise hooks: managed runtime selector lock is untrusted: %w", err)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}

	deadline := time.Now().Add(windowsManagedRuntimeSelectorLockTimeout)
	for {
		lock, lockErr := openWindowsClaudeManagedPolicyLockFile(lockPath)
		if lockErr == nil {
			defer windows.CloseHandle(lock)
			if err := setWindowsManagedPolicyProtection(lockPath, false, false); err != nil {
				return fmt.Errorf("enterprise hooks: harden managed runtime selector lock: %w", err)
			}
			if err := validateWindowsManagedRuntimeMachineFileProtection(lockPath, false); err != nil {
				return fmt.Errorf("enterprise hooks: verify managed runtime selector lock: %w", err)
			}
			return fn()
		}
		if !errors.Is(lockErr, windows.ERROR_SHARING_VIOLATION) &&
			!errors.Is(lockErr, windows.ERROR_LOCK_VIOLATION) {
			return fmt.Errorf("enterprise hooks: acquire managed runtime selector lock: %w", lockErr)
		}
		if !time.Now().Before(deadline) {
			return errors.New("enterprise hooks: timed out waiting for managed runtime selector lock")
		}
		delay := windowsManagedRuntimeSelectorLockRetry
		if remaining := time.Until(deadline); remaining < delay {
			delay = remaining
		}
		if delay > 0 {
			time.Sleep(delay)
		}
	}
}

func validateWindowsManagedRuntimeMachineFileProtection(
	path string,
	userReadable bool,
) error {
	if err := rejectWindowsReparseChain(path); err != nil {
		return err
	}
	if err := windowsManagedPolicyFileTrustCheck(path); err != nil {
		return err
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		return err
	}
	descriptor, err := windows.GetNamedSecurityInfo(
		extended,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || descriptor == nil {
		return fmt.Errorf("enterprise hooks: inspect managed runtime machine file protection: %w", err)
	}
	owner, err := windowsManagedPolicyOwnerSID()
	if err != nil || owner == nil {
		return errors.New("enterprise hooks: managed runtime machine file owner SID is unavailable")
	}
	actualOwner, _, err := descriptor.Owner()
	if err != nil || actualOwner == nil || !actualOwner.Equals(owner) {
		return errors.New("enterprise hooks: managed runtime machine file owner is noncanonical")
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("enterprise hooks: managed runtime machine file DACL is not protected")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return errors.New("enterprise hooks: managed runtime machine file DACL is unavailable")
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		return err
	}
	type expectedACE struct {
		sid   *windows.SID
		masks map[windows.ACCESS_MASK]struct{}
	}
	maskSet := func(generic windows.ACCESS_MASK) map[windows.ACCESS_MASK]struct{} {
		return map[windows.ACCESS_MASK]struct{}{
			generic:                                {},
			mapWindowsUserPathGenericMask(generic): {},
		}
	}
	expected := []expectedACE{
		{sid: owner, masks: maskSet(windows.GENERIC_ALL)},
		{sid: system, masks: maskSet(windows.GENERIC_ALL)},
	}
	if userReadable {
		expected = append(expected, expectedACE{
			sid:   users,
			masks: maskSet(windows.GENERIC_READ),
		})
	}
	if int(dacl.AceCount) != len(expected) {
		return errors.New("enterprise hooks: managed runtime machine file DACL has a noncanonical ACE count")
	}
	seen := make([]bool, len(expected))
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return err
		}
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			ace.Header.AceFlags != 0 {
			return errors.New("enterprise hooks: managed runtime machine file contains a noncanonical ACE")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		matched := -1
		for candidate, expectedACE := range expected {
			if seen[candidate] || !sid.Equals(expectedACE.sid) {
				continue
			}
			if _, ok := expectedACE.masks[ace.Mask]; ok {
				matched = candidate
				break
			}
		}
		if matched < 0 {
			return errors.New("enterprise hooks: managed runtime machine file contains an unexpected ACE")
		}
		seen[matched] = true
	}
	return nil
}

func retireWindowsManagedRuntimeSelectorTargetBundle(
	entry windowsManagedRuntimeSelectorTarget,
	target *windows.SID,
) error {
	path, err := windowsManagedRuntimeBundlePath(entry.DataDir, entry.Connector, entry.GenerationID)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	_, data, _, err := loadWindowsManagedRuntimeBundle(entry, target)
	if err != nil {
		return err
	}
	return deleteWindowsManagedRuntimeBundle(entry, target, data)
}

func deleteWindowsManagedRuntimeBundle(
	entry windowsManagedRuntimeSelectorTarget,
	target *windows.SID,
	expected []byte,
) error {
	if err := validateWindowsManagedRuntimeGenerationRoots(entry.DataDir, target); err != nil {
		return err
	}
	path, err := windowsManagedRuntimeBundlePath(entry.DataDir, entry.Connector, entry.GenerationID)
	if err != nil {
		return err
	}
	if err := validateWindowsUserPathElement(path, target, false, false, true); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		return err
	}
	pathPtr, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ|windows.DELETE|windows.READ_CONTROL|
			windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("enterprise hooks: open unselected managed runtime generation for deletion: %w", err)
	}
	handleOwned := true
	defer func() {
		if handleOwned {
			_ = windows.CloseHandle(handle)
		}
	}()
	var identity windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &identity); err != nil {
		return err
	}
	if identity.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
		identity.NumberOfLinks != 1 {
		return errors.New("enterprise hooks: unselected managed runtime generation is redirected or linked")
	}
	descriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || descriptor == nil {
		return fmt.Errorf("enterprise hooks: inspect unselected managed runtime generation protection: %w", err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.Equals(target) {
		return errors.New("enterprise hooks: unselected managed runtime generation owner changed")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return errors.New("enterprise hooks: unselected managed runtime generation DACL is unavailable")
	}
	if err := validateWindowsUserPathProtectionACL(path, descriptor, dacl, target, false); err != nil {
		return err
	}
	file := os.NewFile(uintptr(handle), filepath.Base(path))
	if file == nil {
		return errors.New("enterprise hooks: wrap unselected managed runtime generation handle")
	}
	handleOwned = false
	data, err := io.ReadAll(io.LimitReader(file, windowsManagedRuntimeBundleMaxBytes+1))
	if err != nil {
		_ = file.Close()
		return err
	}
	if int64(len(data)) > windowsManagedRuntimeBundleMaxBytes ||
		!bytes.Equal(data, expected) || windowsManagedRuntimeSHA256(data) != entry.BundleSHA256 {
		_ = file.Close()
		return errors.New("enterprise hooks: unselected managed runtime generation changed before deletion")
	}
	flags := uint32(
		windows.FILE_DISPOSITION_DELETE |
			windows.FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE,
	)
	deleteErr := windows.SetFileInformationByHandle(
		windows.Handle(file.Fd()),
		windows.FileDispositionInfoEx,
		(*byte)(unsafe.Pointer(&flags)),
		uint32(unsafe.Sizeof(flags)),
	)
	if deleteErr != nil {
		deleteFile := byte(1)
		if fallbackErr := windows.SetFileInformationByHandle(
			windows.Handle(file.Fd()),
			windows.FileDispositionInfo,
			&deleteFile,
			1,
		); fallbackErr != nil {
			_ = file.Close()
			return fmt.Errorf(
				"enterprise hooks: delete unselected managed runtime generation by handle: %w",
				fallbackErr,
			)
		}
	}
	closeErr := file.Close()
	if closeErr != nil {
		return closeErr
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errors.New("enterprise hooks: unselected managed runtime generation survived deletion")
	}
	return nil
}
