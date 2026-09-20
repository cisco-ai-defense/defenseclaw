// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
)

func TestRuntimeRequiresAdapterForEnabledOptionalDestinationAndAllocatesNoneWhenDisabled(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	enabledPlan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90,
		func(source *config.ObservabilityV8Source) {
			source.Destinations = []config.ObservabilityV8DestinationSource{{
				Name: "future-console", Kind: config.ObservabilityV8DestinationConsole,
			}}
		},
	)
	_, err := New(t.Context(), runtimegraph.ConfigFromPlan(enabledPlan, false), dependencies.options())
	var graphErr *runtimegraph.Error
	if !errors.As(err, &graphErr) || graphErr.Code() != runtimegraph.ErrorInitialization ||
		graphErr.ComponentName() != DestinationDispatchComponentName {
		t.Fatalf("enabled optional destination error=%v", err)
	}

	disabled := false
	disabledPlan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90,
		func(source *config.ObservabilityV8Source) {
			source.Destinations = []config.ObservabilityV8DestinationSource{{
				Name: "future-console", Kind: config.ObservabilityV8DestinationConsole,
				Enabled: &disabled,
			}}
		},
	)
	runtime := newRuntimeForTest(t, dependencies, disabledPlan, false)
	destination, ok := runtime.Active().Plan().Destination("future-console")
	if !ok || destination.Enabled {
		t.Fatalf("disabled destination was not preserved: %#v", destination)
	}
}
