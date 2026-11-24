// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/hookcli"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

var (
	configValidatePath    string
	configValidateDataDir string
	configValidateJSON    bool
)

// configValidateCmd checks a candidate config.yaml with the compiler and the
// runtime loader the gateway runs at start, so an administrator learns before
// applying it whether a guardrail profile, a sandbox floor or any other
// setting would be refused. It is read-only: it starts nothing, opens no
// database and contacts no destination (GAP-0252).
var configValidateCmd = &cobra.Command{
	Use:   "validate [config.yaml]",
	Short: "Check a config.yaml the way the gateway loads it, without changing anything",
	Long: "Compiles the file with the strict compiler and the runtime loader the gateway runs at start: the schema, " +
		"guardrail profiles and assignments, every profile's sandbox floor combined with openshell.admin, " +
		"the rule packs and the observability destinations. Exits 0 when the gateway could load it. " +
		"A refusal names the setting and the profile. It changes nothing.",
	Args:         cobra.MaximumNArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		path := strings.TrimSpace(configValidatePath)
		if len(args) == 1 {
			path = strings.TrimSpace(args[0])
		}
		dataDir := strings.TrimSpace(configValidateDataDir)
		if layout, ok := configValidateManagedHostLayout(); ok {
			// The installed config of a standalone managed computer is the
			// layout's, not the per-user ~/.defenseclaw one root has none of
			// (GAP-0602); a data_dir left out resolves there as ensure does.
			if path == "" && os.Getenv(managed.ConfigPathEnv) == "" {
				path = layout.ConfigPath
			}
			if dataDir == "" {
				dataDir = layout.DataDir
			}
		}
		loaded, err := checkConfigV8Candidate(path, dataDir)
		var derivationErr error
		if err == nil {
			// The gateway derives every profile's policy and sandbox floor
			// (pack digests included) at load and on every reload.
			_, derivationErr = loaded.runtime.DeriveGuardrailProfiles()
		}
		var packErr error
		if err == nil && derivationErr == nil {
			// The required sandbox packs, as ensure loads them (GAP-0546).
			packErr = configValidateRequiredSandboxPacks(loaded.runtime)
		}
		out := cmd.OutOrStdout()
		if err != nil || derivationErr != nil || packErr != nil {
			failure := configV8ValidationFailure(err)
			if derivationErr != nil {
				failure.Path = "$.guardrail.profiles"
				failure.Reason = configV8DiagnosticReason("config_semantic_invalid",
					configV8SettingRule(derivationErr.Error()), "", "")
				failure.ConfigVersion = loaded.runtime.ConfigVersion
			}
			if packErr != nil {
				failure.Path = "$.openshell.admin.required_pack"
				failure.Reason = configV8DiagnosticReason("config_semantic_invalid",
					configV8SettingRule(packErr.Error()), "", "")
				failure.ConfigVersion = loaded.runtime.ConfigVersion
			}
			refusal := err
			if derivationErr != nil {
				refusal = derivationErr
			}
			if packErr != nil {
				refusal = packErr
			}
			plain, worded := configValidatePlainRefusal(refusal, failure, configValidateShownPath(path), path)
			var readError *configV8ReadError
			if errors.As(err, &readError) {
				// A file that could not be read was not refused for its
				// content: every host says so in plain words (GAP-0605).
				plain, worded = readError.sentence(configValidateShownPath(path)), true
			}
			if worded {
				failure.Message = plain
			}
			if configValidateJSON {
				_ = json.NewEncoder(out).Encode(failure)
			}
			if worded {
				return errors.New(plain)
			}
			return fmt.Errorf("%s is not valid at %s: %s", configValidateShownPath(path), failure.Path, failure.Reason)
		}
		warnings := append(gateway.ConfigHILTWarnings(loaded.runtime), loaded.runtime.SandboxDefaultProfileWarnings()...)
		warnings = append(warnings, configV8InstalledAdvisories(loaded)...)
		warnings = append(warnings, configValidateManagedStandaloneWarnings(loaded)...)
		warnings = append(warnings, configValidateUserEntryWarnings(cmd.Context(), loaded.runtime.Guardrail.ProfileAssignments)...)
		warnings = append(warnings, configValidateRoutingGroupWarnings(cmd.Context(), loaded.runtime)...)
		warnings = append(warnings, loaded.runtime.RoutingAdminIssuerWarnings()...)
		if configValidateJSON {
			valid := true
			encoder := json.NewEncoder(out)
			encoder.SetEscapeHTML(false)
			return encoder.Encode(configV8WireResponse{
				WireVersion: configV8WireVersion, Kind: "validation", ConfigVersion: loaded.runtime.ConfigVersion,
				Source: loaded.source, DataDir: loaded.compiled.DataDir, GatewayAPIPort: loaded.gatewayAPIPort,
				PlanDigest: loaded.compiled.Plan.Digest(), NetworkValidation: "offline_syntax_and_literal_policy_only",
				Valid: &valid, Warnings: warnings,
			})
		}
		fmt.Fprintf(out, "%s: valid (config_version %d)\n", loaded.source, loaded.runtime.ConfigVersion)
		for _, warning := range warnings {
			fmt.Fprintf(out, "warning: %s\n", warning)
		}
		return nil
	},
}

// configValidateUserEntryWarnings names the guardrail.profile_assignments
// users entries that select nobody on this computer, as status and verify
// name them once the gateway runs the file (GAP-0197). A seam for tests.
var configValidateUserEntryWarnings = func(ctx context.Context, assignments []config.ProfileAssignment) []string {
	if ctx == nil {
		ctx = context.Background()
	}
	var warnings []string
	for _, warning := range gateway.ProfileUserEntryWarnings(ctx, assignments) {
		warnings = append(warnings, warning+" (profile_assignment_unmatched)")
	}
	return warnings
}

// configValidateRoutingGroupWarnings names the routing.admin rules and
// group budgets whose group this computer knows by no spelling the matcher
// selects, so a deny there never acts (rel-1-0-10:GAP-1124). A seam for
// tests.
var configValidateRoutingGroupWarnings = func(ctx context.Context, loadedCfg *config.Config) []string {
	spoolDir := ""
	if loadedCfg != nil && loadedCfg.DataDir != "" {
		spoolDir = enterprisehooks.IdentitySpoolDir(managed.HookGuardianAuthorizationDir(loadedCfg.DataDir))
	}
	return gateway.RoutingAdminGroupWarnings(ctx, loadedCfg, spoolDir)
}

// configValidateLayout is this computer's standalone layout. A seam for
// tests.
var configValidateLayout = func() (managed.StandaloneLayout, error) {
	return enterprisebundle.Layout(runtime.GOOS)
}

// configValidateManagedHostLayout is this computer's standalone managed
// layout when its administrator-owned runtime descriptor is present.
func configValidateManagedHostLayout() (managed.StandaloneLayout, bool) {
	layout, err := configValidateLayout()
	if err != nil {
		return managed.StandaloneLayout{}, false
	}
	// A Windows standalone computer is named by its protected registration
	// marker, as every other managed-host check there reads it; without it
	// validate with no file read the per-user config the administrator has
	// none of (GAP-1625, the Windows half of GAP-0602).
	if _, present := hookcli.ManagedHostWindowsStandalone(); present {
		return layout, true
	}
	if layout.DescriptorPath == "" {
		return managed.StandaloneLayout{}, false
	}
	if _, err := os.Stat(layout.DescriptorPath); err != nil {
		return managed.StandaloneLayout{}, false
	}
	return layout, true
}

// configValidateManagedStandaloneLayout applies the rules ensure, Setup and
// bundle apply refuse a managed standalone config on, so validate does not
// call a file valid that the lifecycle then refuses (GAP-0601). On a
// standalone managed computer the file is decoded as its installed config and
// gets that OS's rules: the listener, data_dir, rule pack folders and jsonl
// paths. Elsewhere it gets the listener rule of the OS it can be for (see
// configValidateOffHostGOOS). Other configs, Secure Client's included, keep
// their own rules.
func configValidateManagedStandaloneLayout(loaded *loadedConfigV8File) error {
	cfg := loaded.runtime
	if !managed.IsManagedEnterprise(cfg.DeploymentMode) || !cfg.StandaloneEnterprise() {
		return nil
	}
	var err error
	if layout, ok := configValidateManagedHostLayout(); ok {
		var installed *config.Config
		if installed, err = config.LoadRuntimeV8InspectionCandidateFromBytes(layout.ConfigPath, loaded.raw); err == nil {
			err = config.ValidateManagedStandaloneConfig(loaded.raw, installed, loaded.compiled.Plan, layout)
		}
	} else {
		err = config.ValidateManagedStandaloneListener(cfg, configValidateOffHostGOOS(loaded))
	}
	if err != nil {
		return &config.V8SemanticError{
			Path:    "$",
			Summary: "the managed standalone lifecycle refuses this file: " + err.Error(),
			Action:  "set the value the managed layout requires, or leave the key out",
		}
	}
	return nil
}

// configValidateOffHostGOOS is the OS a managed standalone file checked off a
// managed computer can be for: "linux" when its explicit data_dir is a POSIX
// path, which Windows refuses (Linux and macOS share the listener rule), and
// "" when it could be for any OS.
func configValidateOffHostGOOS(loaded *loadedConfigV8File) string {
	if loaded.document == nil {
		return ""
	}
	if dataDir, ok := loaded.document.Plain["data_dir"].(string); ok && strings.HasPrefix(strings.TrimSpace(dataDir), "/") {
		return "linux"
	}
	return ""
}

// configValidateManagedStandaloneWarnings names the gateway.api_port of a
// managed standalone file checked off a managed computer that Linux and
// macOS refuse and Windows accepts, when the file could be for any OS.
func configValidateManagedStandaloneWarnings(loaded *loadedConfigV8File) []string {
	cfg := loaded.runtime
	if !managed.IsManagedEnterprise(cfg.DeploymentMode) || !cfg.StandaloneEnterprise() {
		return nil
	}
	if _, ok := configValidateManagedHostLayout(); ok || configValidateOffHostGOOS(loaded) != "" {
		return nil
	}
	if port := cfg.Gateway.APIPort; port != 0 && port != config.DefaultGatewayAPIPort {
		return []string{fmt.Sprintf("managed_api_port: gateway.api_port %d is refused by Linux and macOS ensure, which require %d; Windows accepts it when chosen before the first install",
			port, config.DefaultGatewayAPIPort)}
	}
	return nil
}

// configValidateDestinationWarnings names two push destination settings that
// validate accepts offline but that deliver nothing (GAP-0272):
//   - a Kubernetes Service host (NAME.NAMESPACE.svc[.cluster.local]) resolves
//     to a cluster address, private on most clusters: without
//     network_safety.allow_private_networks the gateway starts the
//     destination deferred and refuses that address on every delivery;
//   - an otlp destination on port 4318 (OTLP/HTTP) with protocol grpc, the
//     default.
func configValidateDestinationWarnings(loaded *loadedConfigV8File) []string {
	if loaded == nil || loaded.compiled == nil || loaded.compiled.Plan == nil {
		return nil
	}
	var warnings []string
	for _, shown := range loaded.compiled.Plan.Destinations() {
		destination, ok := loaded.compiled.Plan.RuntimeDestination(shown.Name)
		if !ok || !destination.Enabled {
			continue
		}
		switch destination.Kind {
		case config.ObservabilityV8DestinationOTLP, config.ObservabilityV8DestinationSplunkHEC,
			config.ObservabilityV8DestinationHTTPJSONL:
		default:
			continue
		}
		host, port := configValidateEndpointHostPort(destination.Transport.Endpoint)
		safety := destination.Transport.NetworkSafety
		// Only allow_private_networks admits a private ClusterIP; allow_cgnat
		// alone does not (GAP-0287). Every endpoint counts: the main one and
		// each signal override.
		if safety == nil || !safety.AllowPrivateNetworks {
			hosts := []string{host}
			for _, signal := range configValidateOverrideSignals(destination.Transport.SignalOverrides) {
				if endpoint := destination.Transport.SignalOverrides[signal].Endpoint; endpoint != "" {
					overrideHost, _ := configValidateEndpointHostPort(endpoint)
					hosts = append(hosts, overrideHost)
				}
			}
			seen := map[string]bool{}
			for _, candidate := range hosts {
				if seen[candidate] || !configValidateKubernetesServiceHost(candidate) {
					continue
				}
				seen[candidate] = true
				warnings = append(warnings, fmt.Sprintf(
					"private_service_endpoint: observability destination %q: %s is a Kubernetes Service name, which resolves to a cluster address; "+
						"set network_safety.allow_private_networks: true on it, or the gateway runs without it and refuses that address on every delivery",
					destination.Name, candidate))
			}
		}
		if destination.Kind == config.ObservabilityV8DestinationOTLP && port == "4318" &&
			(destination.Transport.Protocol == "grpc" || destination.Transport.Protocol == "grpc/protobuf") {
			warnings = append(warnings, fmt.Sprintf(
				"otlp_protocol_port: observability destination %q: protocol is grpc (the default) on port 4318, the OTLP/HTTP port; "+
					"set protocol: http/protobuf, or use the gRPC port 4317", destination.Name))
		}
	}
	return warnings
}

// configValidateOverrideSignals returns the override signals in a stable order.
func configValidateOverrideSignals(overrides map[observability.Signal]config.ObservabilityV8SignalOverrideSource) []observability.Signal {
	signals := make([]observability.Signal, 0, len(overrides))
	for signal := range overrides {
		signals = append(signals, signal)
	}
	sort.Slice(signals, func(i, j int) bool { return signals[i] < signals[j] })
	return signals
}

// configValidateKubernetesServiceHost reports a Service DNS name of the
// default cluster domain: NAME.NAMESPACE.svc or NAME.NAMESPACE.svc.cluster.local.
func configValidateKubernetesServiceHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	return strings.HasSuffix(host, ".svc") || strings.HasSuffix(host, ".svc.cluster.local")
}

// configValidateEndpointHostPort splits a URL or a gRPC host:port authority.
func configValidateEndpointHostPort(endpoint string) (string, string) {
	if strings.Contains(endpoint, "://") {
		parsed, err := url.Parse(endpoint)
		if err != nil {
			return "", ""
		}
		return parsed.Hostname(), parsed.Port()
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return endpoint, ""
	}
	return host, port
}

func configValidateShownPath(path string) string {
	if path == "" {
		return config.ConfigPath()
	}
	return path
}

func init() {
	configValidateCmd.Flags().StringVar(&configValidatePath, "config", "", "config.yaml (default: the installed config)")
	configValidateCmd.Flags().StringVar(&configValidateDataDir, "data-dir", "", "default data directory when data_dir is omitted from the source")
	configValidateCmd.Flags().BoolVar(&configValidateJSON, "json", false, "print the result as JSON")
	configCmd.AddCommand(configValidateCmd)
}
