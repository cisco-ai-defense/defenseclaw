// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package winpath

// EnterpriseService is one Windows service a standalone deployment
// registers, by name and by its status kind.
type EnterpriseService struct {
	Name string
	Kind string
}

// EnterpriseStandaloneServices is every service a standalone deployment
// registers. The lifecycle status and the refusals of Setup and of the CLI
// read the same roster.
var EnterpriseStandaloneServices = []EnterpriseService{
	{Name: EnterpriseGatewayServiceName, Kind: "gateway"},
	{Name: "DefenseClawHookGuardian", Kind: "guardian"},
	{Name: "DefenseClawHookEnumerator", Kind: "enumerator"},
	{Name: "DefenseClawSensorHelper", Kind: "sensor_helper"},
}
