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

	curlSegmentRe = regexp.MustCompile(`(?i)\bcurl\b[^;&|#]*`)
	wgetSegmentRe = regexp.MustCompile(`(?i)\bwget\b[^;&|#]*`)
	s3URIRe       = regexp.MustCompile(`(?i)\bs3://([^/\s]+)`)
)

var scpFlagsWithArg = map[string]bool{
	"-i": true, "-P": true, "-F": true, "-l": true, "-S": true, "-c": true, "-o": true, "-J": true,
}

var rsyncFlagsWithArg = map[string]bool{
	"-e": true, "--rsh": true, "--password-file": true,
	"--exclude-from": true, "--include-from": true,
	"--exclude": true, "--include": true, "--filter": true,
	"--max-size": true, "--min-size": true, "--chmod": true,
	"--compare-dest": true, "--copy-dest": true, "--link-dest": true,
	"-f": true,
}

var curlLongFlagsWithArg = map[string]bool{
	"upload-file": true, "data": true, "data-binary": true, "data-raw": true,
	"referer": true, "proxy": true, "proxy-user": true, "proxy-header": true,
	"header": true, "user": true, "cookie": true, "cookie-jar": true,
	"cert": true, "key": true, "cacert": true, "capath": true, "crlfile": true,
	"dns-servers": true, "interface": true, "local-port": true, "output": true,
	"range": true, "rate": true, "resolve": true, "ssl-reqd": true,
	"tlsuser": true, "tlspassword": true, "tlsauthtype": true,
	"write-out": true, "xattr": true,
}

var curlShortFlagsWithArg = map[byte]bool{
	'T': true, 'd': true, 'H': true, 'e': true, 'x': true, 'u': true, 'b': true,
	'c': true, 'E': true, 'F': true, 'o': true, 'z': true, 'Z': true,
}

var wgetLongFlagsWithArg = map[string]bool{
	"post-file": true, "body-file": true, "header": true, "referer": true,
	"proxy": true, "proxy-user": true, "output-document": true, "directory-prefix": true,
	"user": true, "password": true, "certificate": true, "private-key": true,
	"ca-certificate": true, "ca-directory": true,
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

// allowedExfilS3Buckets lists CI artifact buckets that may downgrade
// chained exfil findings when used as explicit upload destinations.
var allowedExfilS3Buckets = []string{
	"my-ci-bucket",
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
	if ep := primaryUploadEndpoint(text); ep != "" {
		f.ExternalEndpoint = ep
		if allUploadDestinationsAllowlisted(text) &&
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
	return primaryUploadEndpoint(text)
}

func primaryUploadEndpoint(text string) string {
	endpoints := extractAllUploadEndpoints(text)
	for _, ep := range endpoints {
		if !isAllowlistedExfilEndpoint(ep) {
			return ep
		}
	}
	if len(endpoints) > 0 {
		return endpoints[0]
	}
	return ""
}

func extractAllUploadEndpoints(text string) []string {
	var out []string
	if m := s3URIRe.FindStringSubmatch(text); len(m) > 1 {
		out = append(out, "s3://"+strings.ToLower(m[1]))
	}
	for _, host := range extractCurlUploadHosts(text) {
		out = append(out, host)
	}
	for _, host := range extractWgetPostHosts(text) {
		out = append(out, host)
	}
	if host := extractSCPHost(text); host != "" {
		out = append(out, host)
	}
	return out
}

func allUploadDestinationsAllowlisted(text string) bool {
	endpoints := extractAllUploadEndpoints(text)
	if len(endpoints) == 0 {
		return false
	}
	for _, ep := range endpoints {
		if !isAllowlistedExfilEndpoint(ep) {
			return false
		}
	}
	return true
}

func extractHTTPHost(text string) string {
	if host := extractCurlUploadHosts(text); len(host) > 0 {
		return host[0]
	}
	return extractWgetPostHost(text)
}

func extractCurlUploadHosts(text string) []string {
	segments := curlSegmentRe.FindAllString(text, -1)
	if len(segments) == 0 {
		return nil
	}
	var hosts []string
	seen := map[string]bool{}
	for _, seg := range segments {
		if !isCurlUploadSegment(seg) {
			continue
		}
		args := tokenizeShellArgs(strings.TrimSpace(seg[4:])) // skip "curl"
		for _, host := range curlDestinationHosts(args) {
			if !seen[host] {
				seen[host] = true
				hosts = append(hosts, host)
			}
		}
	}
	return hosts
}

func isCurlUploadSegment(seg string) bool {
	lower := strings.ToLower(seg)
	return strings.Contains(lower, "-t ") || strings.Contains(lower, "--upload-file") ||
		strings.Contains(lower, "--data @") || strings.Contains(lower, "--data-binary @")
}

func curlDestinationHosts(args []string) []string {
	var hosts []string
	seen := map[string]bool{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "-") {
			if host := hostFromURLToken(arg); host != "" && !seen[host] {
				seen[host] = true
				hosts = append(hosts, host)
			}
			continue
		}
		if strings.HasPrefix(arg, "--") {
			name, _, hasValue := splitLongFlag(arg)
			if curlLongFlagsWithArg[name] {
				if !hasValue && i+1 < len(args) {
					i++
				}
				continue
			}
			if hasValue {
				continue
			}
			continue
		}
		if len(arg) > 1 {
			consumed := 0
			for j := 1; j < len(arg); j++ {
				if curlShortFlagsWithArg[arg[j]] {
					consumed = 1
				}
			}
			if consumed > 0 && i+consumed < len(args) {
				i += consumed
			}
		}
	}
	return hosts
}

func extractWgetPostHost(text string) string {
	hosts := extractWgetPostHosts(text)
	if len(hosts) == 0 {
		return ""
	}
	return hosts[0]
}

func extractWgetPostHosts(text string) []string {
	var hosts []string
	seen := map[string]bool{}
	for _, seg := range wgetSegmentRe.FindAllString(text, -1) {
		if !strings.Contains(strings.ToLower(seg), "--post-file") {
			continue
		}
		args := tokenizeShellArgs(strings.TrimSpace(seg[4:])) // skip "wget"
		for i := 0; i < len(args); i++ {
			arg := args[i]
			if !strings.HasPrefix(arg, "-") {
				if host := hostFromURLToken(arg); host != "" && !seen[host] {
					seen[host] = true
					hosts = append(hosts, host)
				}
				continue
			}
			if strings.HasPrefix(arg, "--") {
				name, _, hasValue := splitLongFlag(arg)
				if wgetLongFlagsWithArg[name] {
					if !hasValue && i+1 < len(args) {
						i++
					}
				}
				continue
			}
		}
	}
	return hosts
}

func splitLongFlag(arg string) (name string, value string, hasValue bool) {
	arg = strings.TrimPrefix(arg, "--")
	if idx := strings.Index(arg, "="); idx >= 0 {
		return strings.ToLower(arg[:idx]), arg[idx+1:], true
	}
	return strings.ToLower(arg), "", false
}

func hostFromURLToken(token string) string {
	if !strings.HasPrefix(strings.ToLower(token), "http://") &&
		!strings.HasPrefix(strings.ToLower(token), "https://") {
		return ""
	}
	u, err := url.Parse(token)
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
	dest := extractSCPDestination(text)
	if dest == "" {
		return ""
	}
	target := dest
	if at := strings.LastIndex(target, "@"); at >= 0 {
		target = target[at+1:]
	}
	if colon := strings.Index(target, ":"); colon >= 0 {
		target = target[:colon]
	}
	return strings.ToLower(target)
}

func extractSCPDestination(text string) string {
	args := scpArgs(text)
	if len(args) == 0 {
		return ""
	}
	start := skipSCPFlags(args)
	for j := len(args) - 1; j >= start; j-- {
		if isRemoteTarget(args[j]) {
			return args[j]
		}
	}
	return ""
}

func scpArgs(text string) []string {
	lower := strings.ToLower(text)
	idx := strings.Index(lower, "scp")
	if idx < 0 {
		return nil
	}
	rest := text[idx+3:]
	if comment := strings.Index(rest, "#"); comment >= 0 {
		rest = rest[:comment]
	}
	return tokenizeShellArgs(rest)
}

func skipSCPFlags(args []string) int {
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
				if c == 'i' || c == 'P' || c == 'F' || c == 'l' || c == 'J' {
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
	return i
}

func extractSCPArtifact(text string) string {
	args := scpArgs(text)
	if len(args) == 0 {
		return ""
	}
	start := skipSCPFlags(args)
	for i := start; i < len(args); i++ {
		candidate := args[i]
		if isRemoteTarget(candidate) {
			continue
		}
		if strings.Contains(candidate, "@") {
			continue
		}
		return normalizeArtifactName(candidate)
	}
	return ""
}

func extractRsyncArtifact(text string) string {
	args := rsyncArgs(text)
	if len(args) == 0 {
		return ""
	}
	start := skipRsyncFlags(args)
	for i := start; i < len(args); i++ {
		candidate := args[i]
		if isRemoteTarget(candidate) {
			continue
		}
		if strings.Contains(candidate, "@") {
			continue
		}
		return normalizeArtifactName(candidate)
	}
	return ""
}

func rsyncArgs(text string) []string {
	lower := strings.ToLower(text)
	idx := strings.Index(lower, "rsync")
	if idx < 0 {
		return nil
	}
	rest := text[idx+5:]
	if comment := strings.Index(rest, "#"); comment >= 0 {
		rest = rest[:comment]
	}
	return tokenizeShellArgs(rest)
}

func skipRsyncFlags(args []string) int {
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
		if strings.HasPrefix(arg, "--") {
			name, _, hasValue := splitLongFlag(arg)
			if rsyncFlagsWithArg["--"+name] {
				if !hasValue && i+1 < len(args) {
					i += 2
					continue
				}
			}
			i++
			continue
		}
		i++
	}
	return i
}

func isRemoteTarget(token string) bool {
	colon := strings.Index(token, ":")
	if colon <= 0 {
		return false
	}
	prefix := token[:colon]
	if prefix == "" {
		return false
	}
	// host:path or user@host:path; reject Windows drive letters (C:)
	if len(prefix) == 1 && prefix[0] >= 'A' && prefix[0] <= 'Z' {
		return false
	}
	if len(prefix) == 1 && prefix[0] >= 'a' && prefix[0] <= 'z' && !strings.Contains(token, "@") {
		return false
	}
	return true
}

func tokenizeShellArgs(s string) []string {
	var tokens []string
	var buf strings.Builder
	var quote byte
	escaped := false
	flush := func() {
		if buf.Len() > 0 {
			tokens = append(tokens, buf.String())
			buf.Reset()
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if escaped {
				buf.WriteByte(c)
				escaped = false
				continue
			}
			if c == '\\' && quote == '"' {
				escaped = true
				continue
			}
			if c == quote {
				quote = 0
			} else {
				buf.WriteByte(c)
			}
			continue
		}
		if c == '\'' || c == '"' {
			flush()
			quote = c
			continue
		}
		if c == ' ' || c == '\t' {
			flush()
			continue
		}
		buf.WriteByte(c)
	}
	flush()
	return tokens
}

func isAllowlistedExfilEndpoint(endpoint string) bool {
	ep := strings.ToLower(strings.TrimSpace(endpoint))
	if ep == "" {
		return false
	}
	if strings.HasPrefix(ep, "s3://") {
		bucket := strings.TrimPrefix(ep, "s3://")
		if slash := strings.Index(bucket, "/"); slash >= 0 {
			bucket = bucket[:slash]
		}
		return isAllowlistedS3Bucket(bucket)
	}
	if strings.HasSuffix(ep, ".s3.amazonaws.com") {
		bucket := strings.TrimSuffix(ep, ".s3.amazonaws.com")
		return isAllowlistedS3Bucket(bucket)
	}
	return hostMatchesAllowlist(ep)
}

func isAllowlistedS3Bucket(bucket string) bool {
	bucket = strings.ToLower(strings.TrimSpace(bucket))
	for _, allowed := range allowedExfilS3Buckets {
		if bucket == allowed {
			return true
		}
	}
	return false
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
