// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// GAP-0455: a prometheus destination with listen ":9466" passed the config
// load, then the runtime refused it with a bare runtime_unavailable and
// every gateway pod crash-looped. The load now refuses a listener that is
// not loopback, naming the destination field and the reason.
func TestGAP0455PrometheusListenMustBeLoopbackAtLoad(t *testing.T) {
	compile := func(listen string) error {
		_, err := CompileObservabilityV8(&ObservabilityV8Source{Destinations: []ObservabilityV8DestinationSource{
			{Name: "prom", Kind: ObservabilityV8DestinationPrometheus, Listen: listen, Path: "/metrics"},
		}})
		return err
	}
	for _, listen := range []string{":9466", "0.0.0.0:9466", "[::]:9466", "10.0.0.5:9466", "metrics.example.com:9466"} {
		err := compile(listen)
		if err == nil {
			t.Fatalf("listen %q was accepted at load; the runtime refuses it", listen)
		}
		for _, want := range []string{"destinations[0].listen", "loopback", "no authentication"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("listen %q: error %q lacks %q", listen, err, want)
			}
		}
	}
	for _, listen := range []string{"127.0.0.1:9466", "[::1]:9466", "localhost:9466", "127.0.0.2:9466"} {
		if err := compile(listen); err != nil {
			t.Fatalf("loopback listen %q refused: %v", listen, err)
		}
	}
}
