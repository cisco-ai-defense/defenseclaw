// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package winenterprise detects an administrator-managed DefenseClaw
// enterprise deployment on Windows, so the per-user gateway and installer can
// refuse to run beside it.
//
// Both products serve hooks on the same local port. A per-user gateway that
// holds that port makes every user's managed hooks fail closed, because the
// managed hook client accepts only the enterprise SCM service as the listener.
package winenterprise

import (
	"errors"
	"fmt"
)

// GatewayServiceName is the SCM service the production enterprise lifecycle
// registers for the managed gateway. Only an administrator can create it.
const GatewayServiceName = "DefenseClawGateway"

// ErrEnterpriseDeploymentPresent reports that a per-user operation was
// refused because an enterprise deployment is installed.
var ErrEnterpriseDeploymentPresent = errors.New(
	"an administrator-managed DefenseClaw enterprise deployment is installed on this computer",
)

// Deployment describes a detected enterprise deployment.
type Deployment struct {
	// ServiceName is the SCM service that identified the deployment.
	ServiceName string
}

// Test seams. Production code uses the platform implementations.
var (
	detectDeployment      = platformDetectDeployment
	currentProcessService = platformCurrentProcessIsService
)

// Detect reports whether an enterprise deployment is installed. It never
// changes machine state and works from a standard-user token.
func Detect() (Deployment, bool, error) {
	return detectDeployment()
}

// RefusePerUser returns an error when an enterprise deployment is installed
// and the caller is not itself a Windows service. operation completes the
// sentence "the per-user DefenseClaw cannot ...", for example "start its
// gateway". Detection failures do not refuse: this guard prevents an
// accidental port conflict and is not an authorization boundary.
func RefusePerUser(operation string) error {
	if service, err := currentProcessService(); err == nil && service {
		return nil
	}
	deployment, present, err := detectDeployment()
	if err != nil || !present {
		return nil
	}
	return fmt.Errorf(
		"%w (Windows service %s); the per-user DefenseClaw cannot %s beside it. "+
			"The enterprise service already protects every user's agents on this computer, "+
			"and a per-user gateway would take the port its managed hooks use. "+
			"Uninstall the per-user DefenseClaw, or contact your administrator",
		ErrEnterpriseDeploymentPresent,
		deployment.ServiceName,
		operation,
	)
}
