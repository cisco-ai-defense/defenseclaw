// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"net/netip"
)

// curlHTTPProxyChainRoute is the exact two-hop --preproxy SOCKS plus
// --proxy HTTP(S) route. Each peer is a distinct physical observer.
type curlHTTPProxyChainRoute struct {
	Preproxy            NetworkFact
	MainProxy           NetworkFact
	PreproxyCanonical   string
	PreproxyValue       string
	DownstreamPlaintext bool
}

func staticCurlHTTPProxyChainRoute(
	command CommandFact,
) (curlHTTPProxyChainRoute, curlArgvParse, bool) {
	empty := func() (curlHTTPProxyChainRoute, curlArgvParse, bool) {
		return curlHTTPProxyChainRoute{}, curlArgvParse{}, false
	}
	if command.Effect != EffectExecute || !command.ArgvComplete ||
		command.ParentCommandID != 0 || len(command.Wrappers) != 0 ||
		len(command.Redirects) != 0 || command.Program != "curl" ||
		len(command.Argv) == 0 || !staticCurlArgvIdentity(command) ||
		!staticCurlProgramIdentity(command) ||
		len(command.Arguments) != len(command.Argv) {
		return empty()
	}
	for index := range command.Argv {
		if !staticCommandArgumentAt(command, index) {
			return empty()
		}
	}
	parsed := parseCurlArgv(command.Argv)
	if !parsed.Complete || parsed.ConfigOpaque || parsed.Preview ||
		parsed.EmptyTransferGroup || !parsed.hasValidOptionValues() ||
		len(parsed.Targets) == 0 || !curlRequestModeValid(parsed) ||
		!curlRangeOptionsValid(parsed) ||
		!staticCurlFeatureDependentPositiveOptionsValid(parsed) {
		return empty()
	}
	group := parsed.Targets[0].Group
	if !staticCurlNetrcSetupValid(command, parsed, group) ||
		!staticCurlGETPostDataValid(command, parsed, group) {
		return empty()
	}
	if _, valid := staticCurlHTTPRequestComponentProjection(
		command, parsed, group,
	); !valid || !curlStaticFormSequenceValid(command, parsed, group) {
		return empty()
	}
	lastProxy := -1
	lastPreproxy := -1
	lastNoProxy := -1
	lastProxyUser := -1
	fail := false
	failWithBody := false
	for index, option := range parsed.Options {
		if option.Group != group || option.Canonical == "--next" ||
			option.Role == curlOptionConfig {
			return empty()
		}
		if !curlProxyOptionPreservesDestination(command, option) {
			return empty()
		}
		if option.Role == curlOptionNetworkOverride {
			switch {
			case curlMainProxyOption(option.Canonical):
				lastProxy = index
			case option.Canonical == "--preproxy":
				lastPreproxy = index
			case option.Canonical == "--noproxy":
				lastNoProxy = index
			default:
				return empty()
			}
		}
		if option.Canonical == "--proxy-user" && option.ValuePresent {
			lastProxyUser = index
		}
		if option.Canonical == "--fail" {
			fail = option.Name != "--no-fail"
		}
		if option.Canonical == "--fail-with-body" {
			failWithBody = option.Name != "--no-fail-with-body"
		}
	}
	if lastProxy < 0 || lastPreproxy < 0 || fail && failWithBody {
		return empty()
	}
	proxyOption := parsed.Options[lastProxy]
	preproxyOption := parsed.Options[lastPreproxy]
	if !staticCurlOptionValue(command, proxyOption) ||
		!staticCurlOptionValue(command, preproxyOption) {
		return empty()
	}
	if proxyOption.Value == "" ||
		curlProxyDecodedControlUserinfoDisables(
			command.ID, proxyOption.Canonical, proxyOption.Value,
		) || curlProxyDecodedControlUserinfoDisables(
		command.ID, "--proxy", preproxyOption.Value,
	) {
		return empty()
	}
	if lastNoProxy >= 0 &&
		!staticCurlOptionValue(command, parsed.Options[lastNoProxy]) {
		return empty()
	}
	if lastProxyUser >= 0 {
		proxyUser := parsed.Options[lastProxyUser]
		if !staticCurlOptionValue(command, proxyUser) {
			return empty()
		}
		if _, _, valid := curlDecodedProxyCredentials(proxyUser.Value); !valid {
			return empty()
		}
	}
	if !curlExplicitSOCKSProxyURL(preproxyOption.Value) {
		return empty()
	}
	mainProxy, _, _, mainOK := staticCurlHTTPProxyFact(
		command.ID, proxyOption.Canonical, proxyOption.Value,
	)
	if !mainOK || mainProxy.Scheme != "http" && mainProxy.Scheme != "https" {
		return empty()
	}
	preproxy, preproxySOCKS, preproxyOK := staticCurlFTPProxyFact(
		command.ID, "--proxy", preproxyOption.Value,
	)
	if !preproxyOK || !preproxySOCKS || preproxy.Scheme != "tcp" {
		return empty()
	}
	if !curlSOCKS4UserWithinBounds(
		"--proxy", preproxyOption.Value, "", false,
	) {
		return empty()
	}
	if curlProxyUsesSOCKS4("--proxy", preproxyOption.Value) &&
		!curlProxyUsesSOCKS4A("--proxy", preproxyOption.Value) {
		address, err := netip.ParseAddr(mainProxy.Host)
		if err != nil || address.Is6() {
			return empty()
		}
	}
	if !curlProxyPeerMatchesIPVersion(preproxy, parsed, group) ||
		!curlProxyPeerMatchesIPVersion(mainProxy, parsed, group) {
		return empty()
	}
	hasHTTPTarget := false
	proxyContact := false
	for _, target := range parsed.Targets {
		if target.Group != group ||
			!staticCommandArgumentAt(command, target.ArgvIndex) ||
			!validLiteralRequestTarget(target.Value) ||
			curlHasUnmodeledGlob(target.Value) ||
			curlTargetHasInvalidUserinfo(target.Value) {
			return empty()
		}
		targetFact, ok := webTargetFact(command.ID, target.Value, NetworkDownload)
		if !ok || targetFact.Scheme != "http" && targetFact.Scheme != "https" {
			return empty()
		}
		hasHTTPTarget = true
		if curlTargetUsesExplicitProxy(parsed, target) {
			proxyContact = true
		}
	}
	if !hasHTTPTarget || !proxyContact {
		return empty()
	}
	return curlHTTPProxyChainRoute{
		Preproxy:            preproxy,
		MainProxy:           mainProxy,
		PreproxyCanonical:   "--proxy",
		PreproxyValue:       preproxyOption.Value,
		DownstreamPlaintext: mainProxy.Scheme == "http",
	}, parsed, true
}

func staticCurlHTTPProxyChainDestination(
	command CommandFact,
) (NetworkFact, curlArgvParse, bool) {
	chain, parsed, ok := staticCurlHTTPProxyChainRoute(command)
	if !ok {
		return NetworkFact{}, curlArgvParse{}, false
	}
	return chain.MainProxy, parsed, true
}

func staticCurlPreproxyDestinationHostnameComponents(
	command CommandFact,
) []TransmittedRequestComponent {
	chain, parsed, ok := staticCurlHTTPProxyChainRoute(command)
	if !ok || len(parsed.Targets) == 0 ||
		!staticCurlHostnameFirstWireSetupValid(
			command, parsed, parsed.Targets[0].Group,
		) {
		return nil
	}
	component := func(value string) TransmittedRequestComponent {
		return TransmittedRequestComponent{
			Value: value, Scheme: chain.Preproxy.Scheme,
			Host: chain.Preproxy.Host, Port: chain.Preproxy.Port,
		}
	}
	var components []TransmittedRequestComponent
	appendComponent := func(value string) {
		if value == "" {
			return
		}
		candidate := component(value)
		for _, existing := range components {
			if existing == candidate {
				return
			}
		}
		components = append(components, candidate)
	}
	if curlProxyResolvesTargetHostname(chain.PreproxyCanonical, chain.PreproxyValue) {
		appendComponent(chain.MainProxy.Host)
	}
	if !chain.DownstreamPlaintext {
		return components
	}
	group := parsed.Targets[0].Group
	for _, target := range parsed.Targets {
		if target.Group != group || !curlTargetUsesExplicitProxy(parsed, target) {
			continue
		}
		targetFact, valid := webTargetFact(
			command.ID, target.Value, NetworkDownload,
		)
		if !valid || targetFact.Scheme != "http" && targetFact.Scheme != "https" {
			continue
		}
		hostname, hostnameValid := staticHTTPDestinationHostnameComponent(
			target.Value, targetFact,
		)
		if !hostnameValid {
			continue
		}
		if targetFact.Scheme == "http" && !curlOriginHostHeaderOverridden(
			command, parsed, target.Group,
		) {
			appendComponent(hostname.Value)
		}
		if targetFact.Scheme == "https" {
			sni, sniValid := staticHTTPSDestinationSNIComponent(
				target.Value, targetFact,
			)
			if sniValid {
				appendComponent(sni.Value)
			}
		}
	}
	return components
}

func staticCurlPreproxyPlaintextHTTPRequestComponents(
	command CommandFact,
) []TransmittedRequestComponent {
	chain, parsed, ok := staticCurlHTTPProxyChainRoute(command)
	if !ok || !chain.DownstreamPlaintext || len(parsed.Targets) == 0 ||
		!staticCurlHostnameFirstWireSetupValid(
			command, parsed, parsed.Targets[0].Group,
		) {
		return nil
	}
	group := parsed.Targets[0].Group
	var proxiedHTTP []NetworkFact
	for _, target := range parsed.Targets {
		if target.Group != group || !curlTargetUsesExplicitProxy(parsed, target) {
			continue
		}
		targetFact, valid := webTargetFact(
			command.ID, target.Value, NetworkDownload,
		)
		if valid && targetFact.Scheme == "http" {
			proxiedHTTP = append(proxiedHTTP, targetFact)
		}
	}
	if len(proxiedHTTP) == 0 {
		return nil
	}
	origin := StaticCurlTransmittedMetadata(command)
	component := func(value string) TransmittedRequestComponent {
		return TransmittedRequestComponent{
			Value: value, Scheme: chain.Preproxy.Scheme,
			Host: chain.Preproxy.Host, Port: chain.Preproxy.Port,
		}
	}
	var components []TransmittedRequestComponent
	appendComponent := func(value string) {
		if value == "" {
			return
		}
		candidate := component(value)
		for _, existing := range components {
			if existing == candidate {
				return
			}
		}
		components = append(components, candidate)
	}
	for _, value := range origin.Headers {
		appendComponent(value)
	}
	for _, value := range origin.HTTPOriginCredentials {
		appendComponent(value)
	}
	for _, value := range origin.HTTPBearerTokens {
		appendComponent(value)
	}
	appendTargetBound := func(candidates []TransmittedRequestComponent) {
		for _, candidate := range candidates {
			for _, target := range proxiedHTTP {
				if candidate.Scheme == target.Scheme &&
					candidate.Host == target.Host && candidate.Port == target.Port {
					appendComponent(candidate.Value)
					break
				}
			}
		}
	}
	appendTargetBound(origin.HTTPRequestComponents)
	appendTargetBound(origin.HTTPOriginCredentialComponents)
	return components
}

func curlHTTPProxyChainNetworks(command CommandFact) []NetworkFact {
	chain, _, ok := staticCurlHTTPProxyChainRoute(command)
	if !ok {
		return nil
	}
	return []NetworkFact{chain.Preproxy, chain.MainProxy}
}
