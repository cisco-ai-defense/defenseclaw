// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/trace"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinationtest"
)

const (
	destinationTestComplianceTimeout = 5 * time.Second
	traceCanaryDefaultTimeout        = 15 * time.Second
	traceCanaryMinimumTimeout        = 100 * time.Millisecond
	traceCanaryMaximumTimeout        = 60 * time.Second
	traceCanaryMaxResponseBytes      = 1024
)

var (
	observabilityV8ConfigPath string
	observabilityV8DataDir    string
	observabilityV8CanaryWait = traceCanaryDefaultTimeout
)

var observabilityV8Cmd = &cobra.Command{
	Use:    "observability-v8",
	Short:  "Internal observability-v8 operations",
	Hidden: true,
	PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
		return nil
	},
	PersistentPostRun: func(_ *cobra.Command, _ []string) {},
}

var observabilityV8RecordDestinationTestCmd = &cobra.Command{
	Use:    "record-destination-test-activity",
	Short:  "Persist one content-free local destination-test activity",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		if err := recordDestinationTestActivity(
			cmd.Context(), cmd.InOrStdin(), observabilityV8ConfigPath, observabilityV8DataDir,
		); err != nil {
			return err
		}
		encoder := json.NewEncoder(cmd.OutOrStdout())
		encoder.SetEscapeHTML(false)
		return encoder.Encode(map[string]bool{"recorded": true})
	},
}

var observabilityV8EmitTraceCanaryCmd = &cobra.Command{
	Use:    "emit-trace-canary DESTINATION",
	Short:  "Emit one generation-owned trace canary through the running gateway",
	Hidden: true,
	Args:   cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runTraceCanaryCommand(
			cmd.Context(), cmd.OutOrStdout(), args[0], observabilityV8ConfigPath,
			observabilityV8DataDir, observabilityV8CanaryWait,
		)
	},
}

func init() {
	observabilityV8Cmd.PersistentFlags().StringVar(
		&observabilityV8ConfigPath,
		"config",
		"",
		"configuration file (default: DEFENSECLAW_CONFIG or <data-dir>/config.yaml)",
	)
	observabilityV8Cmd.PersistentFlags().StringVar(
		&observabilityV8DataDir,
		"data-dir",
		"",
		"default data directory when data_dir is omitted from the source",
	)
	observabilityV8EmitTraceCanaryCmd.Flags().DurationVar(
		&observabilityV8CanaryWait,
		"timeout",
		traceCanaryDefaultTimeout,
		"bounded wait for the runtime canary acknowledgement",
	)
	observabilityV8Cmd.AddCommand(
		observabilityV8RecordDestinationTestCmd,
		observabilityV8EmitTraceCanaryCmd,
	)
	rootCmd.AddCommand(observabilityV8Cmd)
}

type observabilityV8GatewayAccess struct {
	host  string
	port  int
	token string
}

var (
	errObservabilityV8GatewayAccessConfig = errors.New("observability-v8 gateway access configuration is invalid")
	errObservabilityV8GatewayAccessAuth   = errors.New("observability-v8 gateway authentication is unavailable")
)

type traceCanaryHelperResult struct {
	Destination  string `json:"destination,omitempty"`
	TraceID      string `json:"trace_id,omitempty"`
	Generation   uint64 `json:"generation,omitempty"`
	Acknowledged bool   `json:"acknowledged"`
	FailureClass string `json:"failure_class,omitempty"`
}

type traceCanaryHelperError struct {
	class string
}

func (failure *traceCanaryHelperError) Error() string {
	if failure == nil || failure.class == "" {
		return "telemetry trace canary failed safely"
	}
	return "telemetry trace canary failed: " + failure.class
}

func traceCanaryFailure(destination, class string) (traceCanaryHelperResult, error) {
	return traceCanaryHelperResult{
		Destination: destination, FailureClass: class,
	}, &traceCanaryHelperError{class: class}
}

func recordDestinationTestActivity(
	ctx context.Context,
	input io.Reader,
	configPath string,
	dataDir string,
) error {
	if ctx == nil || input == nil {
		return errors.New("destination-test compliance recorder is unavailable")
	}
	activity, err := decodeDestinationTestActivity(input)
	if err != nil {
		return err
	}
	loaded, err := loadConfigV8File(configPath, dataDir)
	if err != nil {
		return errors.New("destination-test compliance configuration is invalid")
	}
	access, err := destinationTestAccess(loaded)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(activity)
	if err != nil {
		return errors.New("destination-test compliance activity is invalid")
	}
	address := net.JoinHostPort(access.host, strconv.Itoa(access.port))
	requestURL := (&url.URL{Scheme: "http", Host: address, Path: destinationtest.EndpointPath}).String()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, bytes.NewReader(payload))
	if err != nil {
		return errors.New("destination-test compliance recorder is unavailable")
	}
	request.Header.Set("Authorization", "Bearer "+access.token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-DefenseClaw-Client", "python-cli")

	dialer := &net.Dialer{Timeout: destinationTestComplianceTimeout}
	client := &http.Client{
		Timeout: destinationTestComplianceTimeout,
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         dialer.DialContext,
			DisableCompression:  true,
			ForceAttemptHTTP2:   false,
			MaxIdleConns:        1,
			MaxIdleConnsPerHost: 1,
			IdleConnTimeout:     time.Second,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("destination-test compliance recorder is unavailable")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
	if response.StatusCode != http.StatusNoContent {
		return errors.New("destination-test compliance recorder rejected the activity")
	}
	return nil
}

func decodeDestinationTestActivity(input io.Reader) (destinationtest.Activity, error) {
	raw, err := io.ReadAll(io.LimitReader(input, destinationtest.MaxEncodedBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > destinationtest.MaxEncodedBytes {
		return destinationtest.Activity{}, errors.New("destination-test compliance activity is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var activity destinationtest.Activity
	if err := decoder.Decode(&activity); err != nil {
		return destinationtest.Activity{}, errors.New("destination-test compliance activity is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return destinationtest.Activity{}, errors.New("destination-test compliance activity is invalid")
	}
	if err := activity.Validate(); err != nil {
		return destinationtest.Activity{}, errors.New("destination-test compliance activity is invalid")
	}
	return activity, nil
}

func runTraceCanaryCommand(
	ctx context.Context,
	output io.Writer,
	destination string,
	configPath string,
	dataDir string,
	timeout time.Duration,
) error {
	result, canaryErr := requestTraceCanary(ctx, destination, configPath, dataDir, timeout)
	if output == nil {
		return &traceCanaryHelperError{class: "output_unavailable"}
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		return &traceCanaryHelperError{class: "output_unavailable"}
	}
	return canaryErr
}

func requestTraceCanary(
	ctx context.Context,
	destination string,
	configPath string,
	dataDir string,
	timeout time.Duration,
) (traceCanaryHelperResult, error) {
	if ctx == nil || !observability.IsStableToken(destination) ||
		timeout < traceCanaryMinimumTimeout || timeout > traceCanaryMaximumTimeout {
		return traceCanaryFailure("", "invalid_request")
	}
	loaded, err := loadConfigV8File(configPath, dataDir)
	if err != nil {
		return traceCanaryFailure(destination, "configuration_unavailable")
	}
	access, err := observabilityV8GatewayAccessForConfig(loaded)
	if err != nil {
		if errors.Is(err, errObservabilityV8GatewayAccessAuth) {
			return traceCanaryFailure(destination, "authentication_unavailable")
		}
		return traceCanaryFailure(destination, "configuration_unavailable")
	}
	payload, err := json.Marshal(struct {
		Destination string `json:"destination"`
	}{Destination: destination})
	if err != nil {
		return traceCanaryFailure(destination, "invalid_request")
	}
	address := net.JoinHostPort(access.host, strconv.Itoa(access.port))
	requestURL := (&url.URL{Scheme: "http", Host: address, Path: "/api/v1/telemetry/canary"}).String()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, bytes.NewReader(payload))
	if err != nil {
		return traceCanaryFailure(destination, "invalid_request")
	}
	request.Header.Set("Authorization", "Bearer "+access.token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-DefenseClaw-Client", "python-cli")

	dialer := &net.Dialer{Timeout: timeout}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           dialer.DialContext,
			DisableCompression:    true,
			DisableKeepAlives:     true,
			ForceAttemptHTTP2:     false,
			MaxIdleConns:          1,
			MaxIdleConnsPerHost:   1,
			ResponseHeaderTimeout: timeout,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return traceCanaryFailure(destination, "gateway_unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, traceCanaryMaxResponseBytes))
		return traceCanaryFailure(destination, "gateway_rejected")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, traceCanaryMaxResponseBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > traceCanaryMaxResponseBytes {
		return traceCanaryFailure(destination, "invalid_response")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var result traceCanaryHelperResult
	if err := decoder.Decode(&result); err != nil {
		return traceCanaryFailure(destination, "invalid_response")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return traceCanaryFailure(destination, "invalid_response")
	}
	parsedTraceID, traceErr := trace.TraceIDFromHex(result.TraceID)
	if traceErr != nil || !parsedTraceID.IsValid() || result.Destination != destination ||
		result.Generation == 0 || !result.Acknowledged || result.FailureClass != "" {
		return traceCanaryFailure(destination, "invalid_response")
	}
	return result, nil
}

func observabilityV8GatewayAccessForConfig(loaded *loadedConfigV8File) (observabilityV8GatewayAccess, error) {
	if loaded == nil || loaded.document == nil || loaded.gatewayAPIPort < 1 || loaded.gatewayAPIPort > 65535 {
		return observabilityV8GatewayAccess{}, errObservabilityV8GatewayAccessConfig
	}
	gateway := config.GatewayConfig{}
	dialHost := "127.0.0.1"
	if source, ok := loaded.document.Plain["gateway"].(map[string]any); ok {
		if value, present := source["api_bind"]; present {
			text, typed := value.(string)
			if !typed {
				return observabilityV8GatewayAccess{}, errObservabilityV8GatewayAccessConfig
			}
			var valid bool
			dialHost, valid = observabilityV8LoopbackDialHost(text)
			if !valid {
				return observabilityV8GatewayAccess{}, errObservabilityV8GatewayAccessConfig
			}
		}
		if value, present := source["token"]; present {
			text, typed := value.(string)
			if !typed {
				return observabilityV8GatewayAccess{}, errObservabilityV8GatewayAccessConfig
			}
			gateway.Token = text
		}
		if value, present := source["token_env"]; present {
			text, typed := value.(string)
			if !typed {
				return observabilityV8GatewayAccess{}, errObservabilityV8GatewayAccessConfig
			}
			gateway.TokenEnv = text
		}
	}
	token := strings.TrimSpace(gateway.ResolvedToken())
	if token == "" {
		return observabilityV8GatewayAccess{}, errObservabilityV8GatewayAccessAuth
	}
	return observabilityV8GatewayAccess{host: dialHost, port: loaded.gatewayAPIPort, token: token}, nil
}

// observabilityV8LoopbackDialHost converts the supported API bind forms into
// one literal loopback dial target. Wildcard listeners remain reachable only
// through their matching loopback family; hostnames other than localhost and
// every non-loopback address fail closed before a bearer is attached.
//
// This is same-user credential-custody hygiene, not a privilege boundary. The
// helper and its caller run with the same OS identity and trust the same
// owner-controlled config and dotenv files.
func observabilityV8LoopbackDialHost(bind string) (string, bool) {
	value := strings.TrimSpace(bind)
	if value != bind {
		return "", false
	}
	switch value {
	case "", "localhost", "0.0.0.0":
		return "127.0.0.1", true
	case "::", "[::]":
		return "::1", true
	}
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		value = strings.TrimSuffix(strings.TrimPrefix(value, "["), "]")
	}
	address := net.ParseIP(value)
	if address == nil || !address.IsLoopback() {
		return "", false
	}
	return address.String(), true
}

func destinationTestAccess(loaded *loadedConfigV8File) (observabilityV8GatewayAccess, error) {
	access, err := observabilityV8GatewayAccessForConfig(loaded)
	if errors.Is(err, errObservabilityV8GatewayAccessAuth) {
		return observabilityV8GatewayAccess{}, errors.New(
			"destination-test compliance authentication is unavailable; set DEFENSECLAW_GATEWAY_TOKEN or run defenseclaw setup gateway",
		)
	}
	if err != nil {
		return observabilityV8GatewayAccess{}, errors.New("destination-test compliance configuration is invalid")
	}
	return access, nil
}
