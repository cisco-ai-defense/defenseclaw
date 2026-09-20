// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bytes"
	"net/netip"
	"path"
	"strings"
)

const (
	adcsCertificatePrincipalDigestDomain = "defenseclaw/actionfacts/adcs-certificate-impersonation/principal/v1"
	adcsCertificatePFXDigestDomain       = "defenseclaw/actionfacts/adcs-certificate-impersonation/pfx/v1"
	adcsCertificateResultMaxBytes        = 256 * 1024
	adcsCertificateResultLineMaxBytes    = 16 * 1024
)

const (
	adcsCertificateRequestedLine = "[*] Successfully requested certificate"
	adcsCertificateSavingPrefix  = "[*] Saving certificate and private key to '"
	adcsCertificateWrotePrefix   = "[*] Wrote certificate and private key to '"
)

// ADCSCertificateImpersonationRequestFact is the value-free projection of one
// exact Certipy certificate request whose authenticating and requested
// principals are provably different. Credential material and raw identities
// are deliberately discarded.
type ADCSCertificateImpersonationRequestFact struct {
	CommandID                     int64
	SourcePrincipalIdentityDigest string
	TargetPrincipalIdentityDigest string
}

// ADCSCertificateImpersonationAuthFact is the value-free projection of one
// exact Certipy PFX authentication invocation. TargetPrincipalIdentityDigest
// is empty when the optional username was not supplied.
type ADCSCertificateImpersonationAuthFact struct {
	CommandID                     int64
	PFXArtifactIdentityDigest     string
	TargetPrincipalIdentityDigest string
}

// ExactADCSCertificateImpersonationRequest recognizes one direct,
// unconditional Certipy request using the closed argument grammar observed in
// the pinned Cochise trajectories. Result evidence and request/auth chaining
// intentionally remain the responsibility of the gateway lifecycle.
func ExactADCSCertificateImpersonationRequest(
	facts Facts,
) (ADCSCertificateImpersonationRequestFact, bool) {
	command, ok := exactADCSCertificateCommand(facts)
	if !ok || len(command.Argv) < 12 || strings.ToLower(command.Argv[1]) != "req" {
		return ADCSCertificateImpersonationRequestFact{}, false
	}

	values, ok := exactADCSOptions(command.Argv[2:], map[string]struct{}{
		"-u": {}, "-p": {}, "-ca": {}, "-template": {}, "-upn": {},
		"-target": {}, "-dc-ip": {},
	})
	if !ok || len(values) < 5 || len(values) > 7 {
		return ADCSCertificateImpersonationRequestFact{}, false
	}
	for _, required := range []string{"-u", "-p", "-ca", "-template", "-upn"} {
		if values[required] == "" {
			return ADCSCertificateImpersonationRequestFact{}, false
		}
	}
	if !exactADCSCredential(values["-p"]) ||
		!exactADCSName(values["-ca"]) || !exactADCSName(values["-template"]) ||
		(values["-target"] != "" && !exactADCSTarget(values["-target"])) ||
		(values["-dc-ip"] != "" && !exactADCSIPAddress(values["-dc-ip"])) {
		return ADCSCertificateImpersonationRequestFact{}, false
	}

	source, sourceOK := canonicalADCSCertificatePrincipal(values["-u"], "")
	target, targetOK := canonicalADCSCertificatePrincipal(values["-upn"], "")
	if !sourceOK || !targetOK || !provablyDifferentADCSPrincipals(source, target) {
		return ADCSCertificateImpersonationRequestFact{}, false
	}

	return ADCSCertificateImpersonationRequestFact{
		CommandID:                     command.ID,
		SourcePrincipalIdentityDigest: framedPrivateDigest(adcsCertificatePrincipalDigestDomain, source),
		TargetPrincipalIdentityDigest: framedPrivateDigest(adcsCertificatePrincipalDigestDomain, target),
	}, true
}

// ExactADCSCertificateImpersonationAuth recognizes one direct, unconditional
// Certipy authentication using one static PFX and the closed argument grammar
// observed in the pinned Cochise trajectories.
func ExactADCSCertificateImpersonationAuth(
	facts Facts,
) (ADCSCertificateImpersonationAuthFact, bool) {
	command, ok := exactADCSCertificateCommand(facts)
	if !ok || len(command.Argv) < 6 || strings.ToLower(command.Argv[1]) != "auth" {
		return ADCSCertificateImpersonationAuthFact{}, false
	}

	values, ok := exactADCSOptions(command.Argv[2:], map[string]struct{}{
		"-pfx": {}, "-dc-ip": {}, "-username": {}, "-domain": {},
	})
	if !ok || len(values) < 2 || len(values) > 4 ||
		values["-pfx"] == "" || values["-dc-ip"] == "" ||
		!exactADCSIPAddress(values["-dc-ip"]) {
		return ADCSCertificateImpersonationAuthFact{}, false
	}

	pfxDigest := ADCSCertificatePFXArtifactIdentityDigest(values["-pfx"])
	if pfxDigest == "" {
		return ADCSCertificateImpersonationAuthFact{}, false
	}
	fact := ADCSCertificateImpersonationAuthFact{
		CommandID: command.ID, PFXArtifactIdentityDigest: pfxDigest,
	}
	username, domain := values["-username"], values["-domain"]
	if username == "" {
		if domain != "" {
			return ADCSCertificateImpersonationAuthFact{}, false
		}
		return fact, true
	}
	canonical, ok := canonicalADCSCertificatePrincipal(username, domain)
	if !ok {
		return ADCSCertificateImpersonationAuthFact{}, false
	}
	fact.TargetPrincipalIdentityDigest = framedPrivateDigest(
		adcsCertificatePrincipalDigestDomain, canonical,
	)
	return fact, true
}

// ADCSCertificatePrincipalIdentityDigest returns the private identity used to
// join request, authentication, and result principals. It returns an empty
// string for dynamic, malformed, or oversized identities.
func ADCSCertificatePrincipalIdentityDigest(principal, explicitDomain string) string {
	canonical, ok := canonicalADCSCertificatePrincipal(principal, explicitDomain)
	if !ok {
		return ""
	}
	return framedPrivateDigest(adcsCertificatePrincipalDigestDomain, canonical)
}

// ADCSCertificatePFXArtifactIdentityDigest returns the private identity used
// to join a Certipy result artifact to a later authentication. The path is
// bounded, POSIX-normalized, and rejected if it is dynamic or traverses a
// parent directory.
func ADCSCertificatePFXArtifactIdentityDigest(artifact string) string {
	if artifact == "" || len(artifact) > maxScalarBytes ||
		validateScalar(artifact, maxScalarBytes) != "" ||
		strings.TrimSpace(artifact) != artifact ||
		unresolvedCredentialLineageScalar(artifact) ||
		strings.ContainsAny(artifact, "\\:'\"") || strings.HasPrefix(artifact, "~") {
		return ""
	}
	cleaned := path.Clean(artifact)
	if cleaned == "." || cleaned == "/" || cleaned == ".." ||
		strings.HasPrefix(cleaned, "../") ||
		!strings.HasSuffix(strings.ToLower(cleaned), ".pfx") {
		return ""
	}
	return framedPrivateDigest(adcsCertificatePFXDigestDomain, cleaned)
}

// ExactADCSCertificatePFXResult returns the value-free identity of a PFX only
// when one bounded result proves successful enrollment and agrees on the exact
// artifact in both Certipy save messages. The raw result and path are never
// retained by this classifier.
func ExactADCSCertificatePFXResult(result []byte) string {
	if len(result) == 0 || len(result) > adcsCertificateResultMaxBytes ||
		bytes.IndexByte(result, 0) >= 0 {
		return ""
	}
	requested, saving, wrote := false, false, false
	artifactDigest := ""
	for _, rawLine := range bytes.Split(result, []byte{'\n'}) {
		lineBytes := bytes.TrimSpace(rawLine)
		if len(lineBytes) == 0 {
			continue
		}
		if len(lineBytes) > adcsCertificateResultLineMaxBytes {
			return ""
		}
		line := string(lineBytes)
		switch {
		case line == adcsCertificateRequestedLine:
			requested = true
		case strings.HasPrefix(line, adcsCertificateSavingPrefix):
			digest := exactADCSCertificateResultArtifact(line, adcsCertificateSavingPrefix)
			if digest == "" || (artifactDigest != "" && artifactDigest != digest) {
				return ""
			}
			artifactDigest, saving = digest, true
		case strings.HasPrefix(line, adcsCertificateWrotePrefix):
			digest := exactADCSCertificateResultArtifact(line, adcsCertificateWrotePrefix)
			if digest == "" || (artifactDigest != "" && artifactDigest != digest) {
				return ""
			}
			artifactDigest, wrote = digest, true
		}
	}
	if !requested || !saving || !wrote {
		return ""
	}
	return artifactDigest
}

func exactADCSCertificateResultArtifact(line, prefix string) string {
	if !strings.HasPrefix(line, prefix) || len(line) <= len(prefix)+1 ||
		!strings.HasSuffix(line, "'") {
		return ""
	}
	return ADCSCertificatePFXArtifactIdentityDigest(
		strings.TrimSuffix(strings.TrimPrefix(line, prefix), "'"),
	)
}

func exactADCSCertificateCommand(facts Facts) (CommandFact, bool) {
	if !adcsCertificateParseEligible(facts.Parse) || len(facts.Commands) != 1 {
		return CommandFact{}, false
	}
	command := facts.Commands[0]
	if command.ID == 0 || !exactUnconditionalTopLevelCommand(command) ||
		!command.ArgvComplete || len(command.Argv) < 2 {
		return CommandFact{}, false
	}
	program := strings.ToLower(command.Program)
	if program != "certipy" && program != "certipy-ad" {
		return CommandFact{}, false
	}
	return command, true
}

func adcsCertificateParseEligible(parse ParseResult) bool {
	if parse.Status == StatusComplete {
		return len(parse.Issues) == 0
	}
	return parse.Status == StatusPartial && len(parse.Issues) == 1 &&
		parse.Issues[0] == IssueUnknownOperandGrammar
}

func exactADCSOptions(
	argv []string,
	allowed map[string]struct{},
) (map[string]string, bool) {
	if len(argv) == 0 || len(argv)%2 != 0 {
		return nil, false
	}
	values := make(map[string]string, len(argv)/2)
	for index := 0; index < len(argv); index += 2 {
		option := strings.ToLower(argv[index])
		if _, known := allowed[option]; !known {
			return nil, false
		}
		if _, duplicate := values[option]; duplicate {
			return nil, false
		}
		value := argv[index+1]
		if value == "" || strings.HasPrefix(value, "-") ||
			len(value) > maxScalarBytes || validateScalar(value, maxScalarBytes) != "" {
			return nil, false
		}
		values[option] = value
	}
	return values, true
}

func canonicalADCSCertificatePrincipal(value, explicitDomain string) (string, bool) {
	if !exactADCSPrincipalScalar(value) ||
		(explicitDomain != "" && !validKerberosTicketDomain(explicitDomain)) {
		return "", false
	}
	value = strings.ToLower(value)
	explicitDomain = strings.ToLower(strings.TrimSuffix(explicitDomain, "."))
	if strings.Count(value, "@") > 1 || strings.Contains(value, "\\") {
		return "", false
	}
	if strings.Contains(value, "@") {
		parts := strings.SplitN(value, "@", 2)
		if !exactADCSLocalPrincipal(parts[0]) ||
			!validKerberosTicketDomain(parts[1]) ||
			(explicitDomain != "" && parts[1] != explicitDomain) {
			return "", false
		}
		return parts[0] + "@" + parts[1], true
	}
	if !exactADCSLocalPrincipal(value) {
		return "", false
	}
	if explicitDomain != "" {
		return value + "@" + explicitDomain, true
	}
	return value, true
}

func exactADCSPrincipalScalar(value string) bool {
	return value != "" && len(value) <= 253 &&
		validateScalar(value, 253) == "" &&
		!unresolvedCredentialLineageScalar(value) &&
		!strings.ContainsAny(value, "/:;|&='\" ")
}

func exactADCSLocalPrincipal(value string) bool {
	if value == "" || len(value) > 128 || !asciiAlphaNumeric(value[0]) {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if character == '$' && index != len(value)-1 {
			return false
		}
		if !asciiAlphaNumeric(character) &&
			!strings.ContainsRune("._-$", rune(character)) {
			return false
		}
	}
	return true
}

func provablyDifferentADCSPrincipals(source, target string) bool {
	if source == target {
		return false
	}
	sourceLocal := strings.SplitN(source, "@", 2)[0]
	targetLocal := strings.SplitN(target, "@", 2)[0]
	// If one side lacks a domain and local names match, the two spellings may
	// still designate the same account. Abstain instead of claiming impersonation.
	return sourceLocal != targetLocal ||
		(strings.Contains(source, "@") && strings.Contains(target, "@"))
}

func exactADCSCredential(value string) bool {
	return value != "" && len(value) <= maxScalarBytes &&
		validateScalar(value, maxScalarBytes) == "" &&
		!unresolvedCredentialLineageScalar(value)
}

func exactADCSName(value string) bool {
	if value == "" || len(value) > 253 ||
		validateScalar(value, 253) != "" || unresolvedCredentialLineageScalar(value) {
		return false
	}
	for index := range len(value) {
		if !asciiAlphaNumeric(value[index]) &&
			!strings.ContainsRune("._-", rune(value[index])) {
			return false
		}
	}
	return true
}

func exactADCSTarget(value string) bool {
	if exactADCSIPAddress(value) {
		return true
	}
	return validKerberosTicketDomain(value) &&
		!strings.EqualFold(strings.TrimSuffix(value, "."), "localhost")
}

func exactADCSIPAddress(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && !address.IsUnspecified() && !address.IsMulticast()
}
