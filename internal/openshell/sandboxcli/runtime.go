// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxcli

import (
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxruntime"
)

// CheckRunRuntime selects the requested route before host/nested/info launch
// shortcuts. Selection does not qualify an adapter or enable its configuration.
// The native AXIS route remains unavailable until its complete launch contract
// has been implemented and independently qualified.
func CheckRunRuntime(requested, configured string) (string, error) {
	selected, err := sandboxruntime.Select(sandboxruntime.ID(requested), sandboxruntime.ID(configured))
	if err != nil {
		return "", &ExitError{Code: 2, Err: err}
	}
	if selected == sandboxruntime.Axis {
		return "", &ExitError{Code: 3, Err: sandboxapi.Errorf(sandboxapi.CodeUnavailable,
			"AXIS sandbox execution is not available: native policy enforcement and harness integration are still being qualified")}
	}
	return string(selected), nil
}

// A legacy response without a runtime belongs to OpenShell. An explicit owner
// must never reach its CLI or POSIX workspace transport by display name.
func isOpenShellSandbox(sb *sandboxapi.Sandbox) bool {
	return sb.Runtime == "" || sb.Runtime == string(sandboxruntime.OpenShell)
}

func requireOpenShellOperation(sb *sandboxapi.Sandbox, operation string) error {
	if isOpenShellSandbox(sb) {
		return nil
	}
	return sandboxapi.Errorf(sandboxapi.CodeUnavailable, "%s is not available for sandbox runtime %q", operation, sb.Runtime)
}

// Stop and Delete are dispatched by the server to the immutable session owner.
// Unknown owners still refuse before any legacy client preflight.
func requireLifecycleRuntime(sb *sandboxapi.Sandbox, operation string) error {
	if isOpenShellSandbox(sb) || sb.Runtime == string(sandboxruntime.Axis) {
		return nil
	}
	return requireOpenShellOperation(sb, operation)
}
