// Copyright 2026 Cisco Systems, Inc. and its affiliates
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
	archiveArtifactRe = regexp.MustCompile(`(?i)(?:\bzip\b\s+(?:-[a-zA-Z]+\s+)*-r\b\s+(\S+)\s+\.|\btar\b\s+(?:-[a-zA-Z]+\s+)*-(?:czf|cz|c[jJ]f)\b\s+(\S+)\s+\.|\bgit\s+bundle\s+create\b\s+(\S+))`)
	curlUploadArtifactRe = regexp.MustCompile(`(?i)\bcurl\b[^;&|]*(?:--upload-file|-T)\s+(\S+)`)
	curlDataAtRe         = regexp.MustCompile(`(?i)\bcurl\b[^;&|]*--data\s+@(\S+)`)
	wgetPostArtifactRe   = regexp.MustCompile(`(?i)\bwget\b[^;&|]*--post-file=(\S+)`)
	scpArtifactRe        = regexp.MustCompile(`(?i)\bscp\b\s+(\S+)`)
	rsyncArtifactRe      = regexp.MustCompile(`(?i)\brsync\b[^;&|]*\s(\S+)\s+\S+.*:`)

	urlHostRe = regexp.MustCompile(`(?i)https?://([^/\s:;|&]+)`)
	scpHostRe = regexp.MustCompile(`(?i)\bscp\b\s+\S+\s+([^@:\s]+@)?([^:\s/]+)`)
	s3URIRe   = regexp.MustCompile(`(?i)\bs3://([^/\s]+)`)
)

// allowedExfilEndpointSubstrings lists known artifact-store hosts and
// schemes. Uploads targeting these are downgraded from HIGH to MEDIUM
// on chained archive+upload findings to reduce CI/deploy FPs.
var allowedExfilEndpointSubstrings = []string{
	"s3.amazonaws.com",
	"amazonaws.com/",
	"storage.googleapis.com",
	"blob.core.windows.net",
	"github.com",
	"api.github.com",
	"gitlab.com",
	"registry.npmjs.org",
	"registry.yarnpkg.com",
	"artifactory",
	"sonatype",
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
	if art := extractUploadArtifact(text); art != "" {
		f.Evidence = artifactEvidencePrefix + art
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
		curlUploadArtifactRe, curlDataAtRe, wgetPostArtifactRe, scpArtifactRe, rsyncArtifactRe,
	} {
		if m := re.FindStringSubmatch(text); len(m) > 1 && m[1] != "" {
			return normalizeArtifactName(m[1])
		}
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
	if m := urlHostRe.FindStringSubmatch(text); len(m) > 1 {
		return strings.ToLower(m[1])
	}
	if m := scpHostRe.FindStringSubmatch(text); len(m) > 2 && m[2] != "" {
		return strings.ToLower(m[2])
	}
	return ""
}

func isAllowlistedExfilEndpoint(endpoint string) bool {
	ep := strings.ToLower(strings.TrimSpace(endpoint))
	if ep == "" {
		return false
	}
	if strings.HasPrefix(ep, "s3://") {
		return true
	}
	for _, allowed := range allowedExfilEndpointSubstrings {
		if strings.Contains(ep, allowed) {
			return true
		}
	}
	// Parse host from URL-shaped endpoints.
	if strings.Contains(ep, "://") {
		if u, err := url.Parse(ep); err == nil && u.Host != "" {
			ep = strings.ToLower(u.Host)
			for _, allowed := range allowedExfilEndpointSubstrings {
				if strings.Contains(ep, allowed) {
					return true
				}
			}
		}
	}
	return false
}
