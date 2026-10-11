// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import "errors"

type windowsManagedRuntimeSelectorTarget struct{}

var errWindowsManagedRuntimeGenerationUnsupported = errors.New(
	"enterprise hooks: managed runtime generations require Windows",
)

func prepareWindowsManagedRuntimeGenerationPlatform(
	WindowsManagedRuntimeGenerationDesired,
) (WindowsManagedRuntimeGenerationPublication, error) {
	return WindowsManagedRuntimeGenerationPublication{}, errWindowsManagedRuntimeGenerationUnsupported
}

func windowsManagedRuntimeGenerationPublicationTargetCASPlatform(
	WindowsManagedRuntimeGenerationPublication,
) WindowsManagedRuntimeSelectorTargetCAS {
	return WindowsManagedRuntimeSelectorTargetCAS{}
}

func commitWindowsManagedRuntimeGenerationPlatform(
	WindowsManagedRuntimeGenerationPublication,
) (WindowsManagedRuntimeSelectorCommit, error) {
	return WindowsManagedRuntimeSelectorCommit{}, errWindowsManagedRuntimeGenerationUnsupported
}

func discardWindowsManagedRuntimeGenerationPublicationPlatform(
	WindowsManagedRuntimeGenerationPublication,
) error {
	return errWindowsManagedRuntimeGenerationUnsupported
}

func resolveWindowsManagedRuntimeGenerationPlatform(
	WindowsManagedRuntimeGenerationResolveOptions,
) (WindowsManagedRuntimeGenerationResolved, error) {
	return WindowsManagedRuntimeGenerationResolved{}, errWindowsManagedRuntimeGenerationUnsupported
}

func verifyWindowsManagedRuntimeGenerationPlatform(
	WindowsManagedRuntimeGenerationDesired,
) error {
	return errWindowsManagedRuntimeGenerationUnsupported
}

func removeWindowsManagedRuntimeGenerationEnrollmentPlatform(
	WindowsManagedRuntimeGenerationRemovalOptions,
) (WindowsManagedRuntimeSelectorCommit, error) {
	return WindowsManagedRuntimeSelectorCommit{}, errWindowsManagedRuntimeGenerationUnsupported
}

func rollbackWindowsManagedRuntimeSelectorCommitPlatform(
	WindowsManagedRuntimeSelectorCommit,
) error {
	return errWindowsManagedRuntimeGenerationUnsupported
}

func finalizeWindowsManagedRuntimeSelectorCommitPlatform(
	WindowsManagedRuntimeSelectorCommit,
) error {
	return errWindowsManagedRuntimeGenerationUnsupported
}

func captureWindowsManagedRuntimeSelectorTargetPlatform(
	WindowsManagedRuntimeSelectorSnapshotOptions,
) (WindowsManagedRuntimeSelectorTargetSnapshot, error) {
	return WindowsManagedRuntimeSelectorTargetSnapshot{}, errWindowsManagedRuntimeGenerationUnsupported
}

func restoreWindowsManagedRuntimeSelectorTargetCASPlatform(
	WindowsManagedRuntimeSelectorRestoreOptions,
) error {
	return errWindowsManagedRuntimeGenerationUnsupported
}

func captureWindowsManagedRuntimeSelectorPlatform(
	string,
) (WindowsManagedRuntimeSelectorSnapshot, error) {
	return WindowsManagedRuntimeSelectorSnapshot{}, errWindowsManagedRuntimeGenerationUnsupported
}

func readWindowsManagedRuntimeSelectorCASPlatform(
	string,
) (WindowsManagedRuntimeSelectorCAS, error) {
	return WindowsManagedRuntimeSelectorCAS{}, errWindowsManagedRuntimeGenerationUnsupported
}

func restoreWindowsManagedRuntimeSelectorCASPlatform(
	WindowsManagedRuntimeSelectorFullRestoreOptions,
) error {
	return errWindowsManagedRuntimeGenerationUnsupported
}

func garbageCollectWindowsManagedRuntimeGenerationsPlatform(
	WindowsManagedRuntimeGenerationGCOptions,
) (int, error) {
	return 0, errWindowsManagedRuntimeGenerationUnsupported
}
