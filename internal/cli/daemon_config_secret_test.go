// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
)

// A missing destination secret used to send start to the default port of the
// fallback configuration, which then blamed whoever held that port.
func TestMissingObservabilitySecretErrorNamesTheVariable(t *testing.T) {
	loadErr := fmt.Errorf("compile: %w", &config.V8SecretReferenceError{
		Destination: "galileo",
		Path:        `observability.destinations[1].headers["Galileo-API-Key"]`,
		Reference:   "GALILEO_API_KEY",
	})
	err := missingObservabilitySecretError("start", loadErr)
	if err == nil {
		t.Fatal("expected a refusal for a missing destination secret")
	}
	for _, want := range []string{
		`destination "galileo" needs GALILEO_API_KEY`,
		"defenseclaw keys set GALILEO_API_KEY",
		"defenseclaw-gateway start",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "--api-port") {
		t.Errorf("error %q still points at the port", err)
	}
	for _, other := range []error{nil, errors.New("config file is missing")} {
		if got := missingObservabilitySecretError("start", other); got != nil {
			t.Errorf("missingObservabilitySecretError(%v) = %v, want nil", other, got)
		}
	}
}

func TestShutdownConfigLoadsListenerWhenDestinationSecretIsUnset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	const source = `config_version: 9
gateway:
  api_bind: 127.0.0.1
  api_port: 18987
observability:
  destinations:
    - name: archive
      kind: splunk_hec
      endpoint: https://collector.example.test/services/collector/event
      token_env: DC_SHUTDOWN_TEST_UNSET
`
	t.Setenv("DC_SHUTDOWN_TEST_UNSET", "")
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadShutdownConfigWithoutDestinations(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Gateway.APIPort != 18987 || got.Gateway.APIBind != "127.0.0.1" {
		t.Fatalf("shutdown listener = %s:%d", got.Gateway.APIBind, got.Gateway.APIPort)
	}
}

func TestRunStopUsesConfiguredTokenAndOverridePortWithUnsetDestinationSecret(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows shutdown requires the verified gateway PID to own the listener")
	}
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	marker := filepath.Join(t.TempDir(), "stop-probe-running")
	t.Setenv(cliRestartProbeEnv, marker)
	d := daemon.New(config.DefaultDataPath())
	pid, err := d.Start([]string{"-test.run=^TestCLIRestartProcessProbe$"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Stop(3 * time.Second) })
	waitForCLIProbe(t, d, marker)
	requests := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Header.Get("Authorization")
		w.WriteHeader(http.StatusAccepted)
		go func() {
			process, findErr := os.FindProcess(pid)
			if findErr == nil {
				_ = process.Kill()
				_ = process.Release()
			}
		}()
	}))
	defer server.Close()
	_, portText, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	var port int
	if _, err := fmt.Sscanf(portText, "%d", &port); err != nil {
		t.Fatal(err)
	}
	oldHost, oldPort := sidecarHost, sidecarPort
	sidecarHost, sidecarPort = "127.0.0.1", port
	t.Cleanup(func() { sidecarHost, sidecarPort = oldHost, oldPort })
	const source = `config_version: 9
gateway:
  api_bind: 127.0.0.1
  api_port: 18987
observability:
  destinations:
    - name: archive
      kind: splunk_hec
      endpoint: https://collector.example.test/services/collector/event
      token_env: DC_SHUTDOWN_TEST_UNSET
`
	t.Setenv("DC_SHUTDOWN_TEST_UNSET", "")
	// stop loads the .env token into the process environment; every test
	// after this one inherited it (GAP-0079).
	unsetEnvironmentForDotenvTest(t, "DEFENSECLAW_GATEWAY_TOKEN")
	if err := os.WriteFile(config.ConfigPath(), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".env"), []byte("DEFENSECLAW_GATEWAY_TOKEN=disposable-stop-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runStop(stopCmd, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case authorization := <-requests:
		if authorization != "Bearer disposable-stop-token" {
			t.Fatal("stop used the wrong gateway token")
		}
	default:
		t.Fatal("stop never requested shutdown on the overridden port")
	}
}

func TestRunStopWithMalformedConfigSignalsVerifiedGateway(t *testing.T) {
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	marker := filepath.Join(t.TempDir(), "stop-probe-running")
	t.Setenv(cliRestartProbeEnv, marker)
	d := daemon.New(config.DefaultDataPath())
	if _, err := d.Start([]string{"-test.run=^TestCLIRestartProcessProbe$"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Stop(3 * time.Second) })
	waitForCLIProbe(t, d, marker)
	if err := os.WriteFile(config.ConfigPath(), []byte("config_version: 9\nguardrail: [unclosed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runStop(stopCmd, nil); err != nil {
		t.Fatal(err)
	}
	if running, _ := d.IsRunning(); running {
		t.Fatal("verified gateway survived stop")
	}
}
