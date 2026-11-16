// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package sandboxcli

import (
	"context"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// accountDockerNamespace is the docker sandbox namespace setup gives the
// account's own gateway, "" to leave it (GAP-0579). Every per-user docker
// gateway without one shares OpenShell's default namespace with the other
// accounts' gateways on this computer, and each one's start removes the
// supervisors of the others' running sandboxes. The gateway lists only its
// namespace's sandboxes, so one that keeps sandboxes in the default
// namespace (its gateway lists them, or the docker driver keeps their
// folders) stays there, which setup says and the doctor repeats until they
// are gone.
func (a *App) accountDockerNamespace(ctx context.Context, state *openshell.GatewayConfigState) string {
	if state == nil || !state.SharesDefaultDockerNamespace() {
		return ""
	}
	home, err := a.Home()
	if err != nil || home == "" {
		return ""
	}
	listed, known := a.gatewaySandboxes(ctx)
	if (known && len(listed) > 0) || openshell.DockerNamespaceInUse(openshell.UserStateHome(a.Getenv, home), openshell.DefaultDockerNamespace) {
		a.note("your OpenShell gateway keeps its sandboxes in OpenShell's default Docker sandbox namespace, which the gateways of the other accounts on this computer share " +
			"(when one of them starts, your running sandboxes stop); setup gives it a namespace of its own once no sandbox is left on it (`" + CommandName + " doctor` says how)")
		return ""
	}
	return openshell.AccountDockerNamespace(a.Geteuid())
}
