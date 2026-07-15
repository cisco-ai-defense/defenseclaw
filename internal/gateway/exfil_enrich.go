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

package gateway

import (
	"net/url"
	"regexp"
	"strings"
)

const artifactEvidencePrefix = "artifact:"

var (
	archiveArtifactRe    = regexp.MustCompile(`(?i)(?:\bzip\b\s+(?:-[a-zA-Z]+\s+)*-r\b\s+(\S+)\s+\.|\btar\b\s+(?:-[a-zA-Z]+\s+)*-(?:czf|cz|c[jJ]f)\b\s+(\S+)\s+\.|\bgit\s+bundle\s+create\b\s+(\S+))`)
	curlUploadArtifactRe = regexp.MustCompile(`(?i)\bcurl\b[^;&|]*(?:--upload-file|-T)\s+(\S+)`)
	curlDataAtRe         = regexp.MustCompile(`(?i)\bcurl\b[^;&|]*--data\s+@(\S+)`)
	wgetPostArtifactRe   = regexp.MustCompile(`(?i)\bwget\b[^;&|]*--post-file=(\S+)`)

	curlSegmentRe         = regexp.MustCompile(`(?i)\bcurl\b[^;&|]*`)
	curlUploadIndicatorRe = regexp.MustCompile(`(?i)(?:--upload-file|-T)\s+\S+`)
	wgetSegmentRe         = regexp.MustCompile(`(?i)\bwget\b[^;&|]*`)
	wgetPostIndicatorRe   = regexp.MustCompile(`(?i)--post-file=\S+`)
	urlInTextRe           = regexp.MustCompile(`(?i)https?://[^\s'"]+`)
	nonDestCurlFlagURLRe  = regexp.MustCompile(`(?i)(?:--referer|-e|--proxy)\s+https?://\S+`)
	scpDestRe             = regexp.MustCompile(`(?i)\bscp\b.*\s((?:[^\s:@/]+@)?[^\s:/]+):`)
	s3URIRe               = regexp.MustCompile(`(?i)\bs3://([^/\s]+)`)
)

var scpFlagsWithArg = map[string]bool{
	"-i": true, "-P": true, "-F": true, "-l": true, "-S": true, "-c": true, "-o": true,
}

var rsyncFlagsWithArg = map[string]bool{
	"-e": true, "--rsh": true, "--password-file": true, "--exclude-from": true, "--include-from": true,
}

// allowedExfilEndpointHosts lists known artifact-store hosts. Matching
// uses exact host or registrable suffix (host == allowed or
// host.HasSuffix("."+allowed)) to avoid substring spoofing.
var allowedExfilEndpointHosts = []string{
	"s3.amazonaws.com",
	"storage.googleapis.com",
	"blob.core.windows.net",
	"github.com",
	"api.github.com",
	"gitlab.com",
	"registry.npmjs.org",
	"registry.yarnpkg.com",
}

// enrichExfilFinding attaches correlator-friendly artifact evidence and
// external endpoints to archive/upload command findings.
func enrichExfilFinding(f RuleFinding, text string) RuleFinding {
	switch f.RuleID {
	case "CMD-WORKSPACE-ARCHIVE", "CMD-ARCHIVE-EXFIL", "CMD-ENCODE-EXFIL":
		if art := extractArchiveArtifact(text); art != "" {
			f.Evidence = artifactEvidencePrefix + art
		}
		if f.RuleID == "CMD-ARCHIVE-EXFIL" || f.RuleID == "CMD-ENCODE-EXFIL" {
			f = applyUploadEnrichment(f, text)
		}
	case "CMD-CURL-UPLOAD", "CMD-WGET-POST":
		f = applyUploadEnrichment(f, text)
	}
	return f
}

func applyUploadEnrichment(f RuleFinding, text string) RuleFinding {
	if !strings.HasPrefix(f.Evidence, artifactEvidencePrefix) {
		if art := extractUploadArtifact(text); art != "" {
			f.Evidence = artifactEvidencePrefix + art
		}
	}
	if ep := extractExternalEndpoint(text); ep != "" {
		f.ExternalEndpoint = ep
		if isAllowlistedExfilEndpoint(ep) &&
			(f.RuleID == "CMD-ARCHIVE-EXFIL" || f.RuleID == "CMD-ENCODE-EXFIL") {
			f.Severity = "MEDIUM"
		}
	}
	return f
}

func extractArchiveArtifact(text string) string {
	m := archiveArtifactRe.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	for i := 1; i < len(m); i++ {
		if m[i] != "" {
			return normalizeArtifactName(m[i])
		}
	}
	return ""
}

func extractUploadArtifact(text string) string {
	for _, re := range []*regexp.Regexp{
		curlUploadArtifactRe, curlDataAtRe, wgetPostArtifactRe,
	} {
		if m := re.FindStringSubmatch(text); len(m) > 1 && m[1] != "" {
			return normalizeArtifactName(m[1])
		}
	}
	if art := extractSCPArtifact(text); art != "" {
		return art
	}
	if art := extractRsyncArtifact(text); art != "" {
		return art
	}
	return ""
}

func normalizeArtifactName(name string) string {
	name = strings.Trim(name, `"'`)
	name = strings.TrimPrefix(name, "./")
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		name = name[idx+1:]
	}
	return name
}

func extractExternalEndpoint(text string) string {
	if m := s3URIRe.FindStringSubmatch(text); len(m) > 1 {
		return "s3://" + strings.ToLower(m[1])
	}
	if host := extractHTTPHost(text); host != "" {
		return host
	}
	if host := extractSCPHost(text); host != "" {
		return host
	}
	return ""
}

func extractHTTPHost(text string) string {
	if host := extractCurlUploadHost(text); host != "" {
		return host
	}
	return extractWgetPostHost(text)
}

func extractCurlUploadHost(text string) string {
	seg := curlSegmentRe.FindString(text)
	if seg == "" || !curlUploadIndicatorRe.MatchString(seg) {
		return ""
	}
	return hostFromLastURL(scrubNonDestinationFlagURLs(seg))
}

func extractWgetPostHost(text string) string {
	seg := wgetSegmentRe.FindString(text)
	if seg == "" || !wgetPostIndicatorRe.MatchString(seg) {
		return ""
	}
	return hostFromLastURL(seg)
}

func scrubNonDestinationFlagURLs(seg string) string {
	return nonDestCurlFlagURLRe.ReplaceAllString(seg, " ")
}

func hostFromLastURL(seg string) string {
	urls := urlInTextRe.FindAllString(seg, -1)
	if len(urls) == 0 {
		return ""
	}
	raw := urls[len(urls)-1]
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	host := u.Hostname()
	if host == "" {
		return ""
	}
	return strings.ToLower(host)
}

func extractSCPHost(text string) string {
	m := scpDestRe.FindStringSubmatch(text)
	if len(m) < 2 {
		return ""
	}
	target := m[1]
	if at := strings.LastIndex(target, "@"); at >= 0 {
		target = target[at+1:]
	}
	return strings.ToLower(target)
}

func extractSCPArtifact(text string) string {
	lower := strings.ToLower(text)
	idx := strings.Index(lower, "scp")
	if idx < 0 {
		return ""
	}
	args := strings.Fields(text[idx+3:])
	i := 0
	for i < len(args) {
		arg := args[i]
		if !strings.HasPrefix(arg, "-") {
			break
		}
		if strings.HasPrefix(arg, "-o") {
			if strings.Contains(arg, "=") {
				i++
				continue
			}
			if i+1 < len(args) {
				i += 2
				continue
			}
			i++
			continue
		}
		if scpFlagsWithArg[arg] {
			if i+1 < len(args) {
				i += 2
				continue
			}
			i++
			continue
		}
		if len(arg) > 2 && arg[0] == '-' && arg[1] != '-' {
			needsArg := false
			for _, c := range arg[1:] {
				if c == 'i' || c == 'P' || c == 'F' || c == 'l' {
					needsArg = true
					break
				}
			}
			if needsArg && i+1 < len(args) {
				i += 2
				continue
			}
		}
		i++
	}
	if i >= len(args) {
		return ""
	}
	candidate := args[i]
	if strings.Contains(candidate, ":") || strings.Contains(candidate, "@") {
		return ""
	}
	return normalizeArtifactName(candidate)
}

func extractRsyncArtifact(text string) string {
	lower := strings.ToLower(text)
	idx := strings.Index(lower, "rsync")
	if idx < 0 {
		return ""
	}
	args := strings.Fields(text[idx+5:])
	i := 0
	for i < len(args) {
		arg := args[i]
		if !strings.HasPrefix(arg, "-") {
			break
		}
		if rsyncFlagsWithArg[arg] {
			if i+1 < len(args) {
				i += 2
				continue
			}
			i++
			continue
		}
		if strings.HasPrefix(arg, "--") && strings.Contains(arg, "=") {
			i++
			continue
		}
		i++
	}
	if i >= len(args) {
		return ""
	}
	candidate := args[i]
	if strings.Contains(candidate, ":") || strings.Contains(candidate, "@") {
		return ""
	}
	return normalizeArtifactName(candidate)
}

func isAllowlistedExfilEndpoint(endpoint string) bool {
	ep := strings.ToLower(strings.TrimSpace(endpoint))
	if ep == "" {
		return false
	}
	if strings.HasPrefix(ep, "s3://") {
		return true
	}
	return hostMatchesAllowlist(ep)
}

func hostMatchesAllowlist(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	for _, allowed := range allowedExfilEndpointHosts {
		if host == allowed || strings.HasSuffix(host, "."+allowed) {
			return true
		}
	}
	return false
}
