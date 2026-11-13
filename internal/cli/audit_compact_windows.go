// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"github.com/spf13/cobra"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// auditCompactAsStoreOwner: on managed Windows an elevated administrator
// compacts the stopped gateway service's store itself, checked as the
// service's runtime file (audit.CompactOptions.ServiceOwned); on a per-user
// install the user owns the store.
func auditCompactAsStoreOwner(*cobra.Command, string) (bool, error) { return false, nil }

// auditCompactServiceLive reports a managed gateway service whose process
// runs or is starting (every state but stopped and stop-pending). A per-user
// install has no service. Tests replace it.
var auditCompactServiceLive = func() (bool, error) {
	if !auditCompactManaged() {
		return false, nil
	}
	manager, err := mgr.Connect()
	if err != nil {
		return false, err
	}
	defer manager.Disconnect() //nolint:errcheck -- read-only SCM handle.
	service, err := manager.OpenService(managed.StandaloneWindowsGatewaySvc)
	if err != nil {
		return false, err
	}
	defer service.Close() //nolint:errcheck -- read-only service handle.
	state, err := scmGatewayService{service}.state()
	if err != nil {
		return false, err
	}
	return windowsServiceProcessLive(state), nil
}
