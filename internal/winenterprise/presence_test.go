// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package winenterprise

import (
	"errors"
	"strings"
	"testing"
)

func withSeams(t *testing.T, detect func() (Deployment, bool, error), service func() (bool, error)) {
	t.Helper()
	previousDetect, previousService := detectDeployment, currentProcessService
	detectDeployment, currentProcessService = detect, service
	t.Cleanup(func() {
		detectDeployment, currentProcessService = previousDetect, previousService
	})
}

func TestRefusePerUserBesideEnterpriseDeployment(t *testing.T) {
	withSeams(t,
		func() (Deployment, bool, error) { return Deployment{ServiceName: GatewayServiceName}, true, nil },
		func() (bool, error) { return false, nil },
	)
	err := RefusePerUser("start its gateway")
	if !errors.Is(err, ErrEnterpriseDeploymentPresent) {
		t.Fatalf("RefusePerUser error = %v, want ErrEnterpriseDeploymentPresent", err)
	}
	for _, want := range []string{GatewayServiceName, "cannot start its gateway beside it", "Uninstall the per-user DefenseClaw"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal %q does not contain %q", err, want)
		}
	}
}

func TestRefusePerUserAllowsWhenNoEnterpriseDeployment(t *testing.T) {
	withSeams(t,
		func() (Deployment, bool, error) { return Deployment{}, false, nil },
		func() (bool, error) { return false, nil },
	)
	if err := RefusePerUser("start its gateway"); err != nil {
		t.Fatalf("RefusePerUser without a deployment = %v", err)
	}
}

func TestRefusePerUserDoesNotBlockTheEnterpriseServiceItself(t *testing.T) {
	detected := false
	withSeams(t,
		func() (Deployment, bool, error) {
			detected = true
			return Deployment{ServiceName: GatewayServiceName}, true, nil
		},
		func() (bool, error) { return true, nil },
	)
	if err := RefusePerUser("start its gateway"); err != nil {
		t.Fatalf("RefusePerUser for a service account = %v", err)
	}
	if detected {
		t.Fatal("service-account caller still queried the SCM")
	}
}

func TestRefusePerUserDetectionFailureDoesNotBlock(t *testing.T) {
	withSeams(t,
		func() (Deployment, bool, error) { return Deployment{}, false, errors.New("scm unavailable") },
		func() (bool, error) { return false, errors.New("token unavailable") },
	)
	if err := RefusePerUser("start its gateway"); err != nil {
		t.Fatalf("RefusePerUser with detection failure = %v", err)
	}
}
