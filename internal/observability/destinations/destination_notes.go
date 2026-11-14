// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package destinations

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/netguard"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/otlp"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/push"
)

// The operator lines of this file name the administrator's destination, the
// cause and the fix. A failed preparation reaches the gateway only as a
// content-free code, so the gateway stopped with only "observability v8
// bootstrap failed: runtime_unavailable" and a destination that started
// deferred said nothing at all (GAP-0890, GAP-0272). Secure Client keeps the
// origin/main refusal without these lines (GAP-1018).

// destinationNotePrefix starts every line; the CLI's start messages read the
// refusal lines (internal/cli gatewayLogExitReason).
const destinationNotePrefix = "defenseclaw: observability destination "

// LastPreparationFailure returns the cause of the newest failed destination
// preparation, as `destination "NAME": CAUSE` with no path or endpoint, or ""
// when none failed (and always under Secure Client).
func (factory *Factory) LastPreparationFailure() string {
	if factory == nil {
		return ""
	}
	factory.noteMu.Lock()
	defer factory.noteMu.Unlock()
	return factory.lastFailure
}

// noteFailure writes the refusal line of one failed preparation and keeps its
// path-free cause for LastPreparationFailure.
func (factory *Factory) noteFailure(
	ctx context.Context,
	destination config.ObservabilityV8EffectiveDestination,
	err error,
) {
	if factory == nil || factory.secureClient || err == nil ||
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		(ctx != nil && ctx.Err() != nil) {
		return
	}
	problem, summary := describePreparationFailure(err)
	factory.noteMu.Lock()
	factory.lastFailure = fmt.Sprintf("destination %q: %s", destination.Name, summary)
	factory.noteMu.Unlock()
	factory.writeNote(fmt.Sprintf("%s%q: %s or remove the destination", destinationNotePrefix, destination.Name, problem))
}

// noteDeferred writes why one endpoint host of a destination started without
// a usable address (otlp.Factory.Deferrals, or a push activation warning):
// the gateway runs, and every delivery
// re-resolves the host and refuses an address its network_safety does not
// allow, so the destination delivers nothing until the answer or the config
// changes.
func (factory *Factory) noteDeferred(destination config.ObservabilityV8EffectiveDestination, host string, cause error) {
	if factory == nil || factory.secureClient || cause == nil {
		return
	}
	if host == "" {
		host = "(unparsed)"
	}
	switch {
	case errors.Is(cause, netguard.ErrV8AddressProhibited):
		factory.writeNote(fmt.Sprintf("%s%q: endpoint host %s resolves to an address %s; the gateway runs without this destination and refuses that address on every delivery",
			destinationNotePrefix, destination.Name, host, prohibitedAddressFix(netguard.V8ProhibitedOption(cause))))
	case errors.Is(cause, netguard.ErrV8ResolutionFailed):
		factory.writeNote(fmt.Sprintf("%s%q: endpoint host %s does not resolve; the gateway runs without this destination and resolves the host again on every delivery",
			destinationNotePrefix, destination.Name, host))
	}
}

// prohibitedAddressFix names the network_safety option that allows the
// address, the same options config validate names for a literal address.
func prohibitedAddressFix(option string) string {
	switch option {
	case "allow_private_networks":
		return "in a loopback or private range (an in-cluster Kubernetes Service is one), which needs network_safety.allow_private_networks: true on the destination"
	case "allow_cgnat":
		return "in the CGNAT range 100.64.0.0/10, which needs network_safety.allow_cgnat: true on the destination"
	default:
		return "no destination may reach (metadata, link-local, multicast or reserved)"
	}
}

// destinationWarnings forwards the push adapter warnings of one destination
// and writes the deferred-start line the activation warnings stand for.
func (factory *Factory) destinationWarnings(destination config.ObservabilityV8EffectiveDestination) push.WarningObserver {
	return push.WarningObserverFunc(func(warning push.Warning) {
		switch warning.Code {
		case push.WarningActivationAddressProhibited:
			factory.noteDeferred(destination, endpointHost(destination.Transport.Endpoint),
				&netguard.V8AddressProhibitedError{Option: warning.Option})
		case push.WarningActivationDNSDegraded:
			factory.noteDeferred(destination, endpointHost(destination.Transport.Endpoint), netguard.ErrV8ResolutionFailed)
		}
		emitFactoryWarning(factory.warnings, warning)
	})
}

// writeNote writes line once per process: a reload or the trace and metric
// pipelines of the same destination do not repeat it.
func (factory *Factory) writeNote(line string) {
	if nilInterface(factory.stderr) {
		return
	}
	factory.noteMu.Lock()
	if factory.noted == nil {
		factory.noted = make(map[string]struct{})
	}
	_, seen := factory.noted[line]
	factory.noted[line] = struct{}{}
	factory.noteMu.Unlock()
	if !seen {
		_, _ = fmt.Fprintln(factory.stderr, line)
	}
}

// adapterPrepareError is ErrorAdapterPrepare with the cause of an exporter
// error (otlp or push), so PrepareDestination can name it.
func adapterPrepareError(cause error) error {
	problem, summary := describePreparationFailure(cause)
	return &Error{code: ErrorAdapterPrepare, problem: problem, summary: summary}
}

// describePreparationFailure returns the operator problem (it may name the
// administrator's path) and the same cause without one. Each ends with its
// fix.
func describePreparationFailure(err error) (problem, summary string) {
	var prepared *Error
	if errors.As(err, &prepared) && prepared.problem != "" {
		return prepared.problem, prepared.summary
	}
	reason := preparationFailureReason(err)
	return reason, reason
}

func preparationFailureReason(err error) string {
	var otlpErr *otlp.Error
	if errors.As(err, &otlpErr) {
		switch otlpErr.Code() {
		case otlp.ErrorUnsafeEndpoint:
			return "its endpoint is not allowed (inline credentials, a scheme other than http or https, or a prohibited address); fix the endpoint"
		case otlp.ErrorTLS:
			return "its TLS settings cannot be loaded (tls.ca_cert is not a PEM CA bundle); fix tls"
		case otlp.ErrorInvalidConfig:
			return "its OTLP settings do not fit the exporter (protocol, endpoint form, tls.insecure, headers or batch limits); fix them"
		default:
			return "its OTLP exporter could not start; check its endpoint and protocol"
		}
	}
	switch {
	case errors.Is(err, push.ErrUnsafeEndpoint):
		return "its endpoint is not allowed (inline credentials, a redirect or a prohibited address); fix the endpoint"
	case errors.Is(err, push.ErrInvalidConfig):
		return "its settings do not fit the exporter (endpoint, method, headers or tls); fix them"
	case IsError(err, ErrorSecretUnavailable):
		return "a secret it names (an env or credential reference of its token or headers) is not set, or the gateway cannot read it; set it"
	case IsError(err, ErrorCALoadFailed):
		return "its tls.ca_cert file cannot be read by the gateway or is empty; fix the file"
	case IsError(err, ErrorInvalidDestination):
		return "its settings are not valid for this gateway; run defenseclaw-gateway config validate and fix them"
	case IsError(err, ErrorUnsupportedKind):
		return "its kind or signals are not supported for this destination; fix them"
	case IsError(err, ErrorUnsupportedPolicy):
		return "its policy is not supported for this destination; fix it"
	default:
		return "its exporter could not be prepared; check its settings"
	}
}

// endpointHost is the host of an OTLP, Splunk HEC or HTTP JSONL endpoint (a
// URL, or a gRPC host:port authority), never its path, query or port.
func endpointHost(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if strings.Contains(endpoint, "://") {
		if parsed, err := url.Parse(endpoint); err == nil && parsed.Hostname() != "" {
			return parsed.Hostname()
		}
		return "(unparsed)"
	}
	if host, _, err := net.SplitHostPort(endpoint); err == nil && host != "" {
		return host
	}
	return "(unparsed)"
}

// noteOTLPDeferrals writes one line per deferred endpoint of an otlp
// destination, naming the host that was refused (an override's, not the
// main endpoint's, when it is the override that failed; GAP-0287).
func (factory *Factory) noteOTLPDeferrals(destination config.ObservabilityV8EffectiveDestination, prepared *otlp.Factory) {
	for _, deferral := range prepared.Deferrals() {
		factory.noteDeferred(destination, deferral.Host, deferral.Cause)
	}
}
