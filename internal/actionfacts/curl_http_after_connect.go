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

// staticCurlHTTPAfterCONNECTRequestComponents rebinds already-proved origin
// HTTP path, query, ordinary headers, and origin authentication onto the
// explicit HTTP(S) proxy that observes those bytes after CONNECT. HTTPS
// origin request bytes stay excluded: they are encrypted inside the tunnel.
func staticCurlHTTPAfterCONNECTRequestComponents(
	command CommandFact,
) []TransmittedRequestComponent {
	proxy, parsed, ok := staticCurlProxyDestination(command)
	if !ok || proxy.Scheme != "http" && proxy.Scheme != "https" ||
		len(parsed.Targets) == 0 {
		return nil
	}
	group := parsed.Targets[0].Group
	if !curlProxyTunnelEnabled(parsed, group) ||
		!staticCurlHostnameFirstWireSetupValid(command, parsed, group) {
		return nil
	}

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
			Value: value, Scheme: proxy.Scheme,
			Host: proxy.Host, Port: proxy.Port,
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

func appendUniqueTransmittedRequestComponents(
	dst []TransmittedRequestComponent,
	src []TransmittedRequestComponent,
) []TransmittedRequestComponent {
	for _, candidate := range src {
		found := false
		for _, existing := range dst {
			if existing == candidate {
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, candidate)
		}
	}
	return dst
}
