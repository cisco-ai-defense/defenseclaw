// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"net/netip"
	"strings"
)

// ExactSourceArchiveUploads returns a defensive copy of exact bounded proofs.
func ExactSourceArchiveUploads(facts Facts) []SourceArchiveUploadFact {
	return append([]SourceArchiveUploadFact(nil), facts.SourceArchiveUploads...)
}

func projectSourceArchiveUploads(facts Facts) []SourceArchiveUploadFact {
	if !facts.Authoritative() {
		return nil
	}
	result := make([]SourceArchiveUploadFact, 0, 1)
	for _, source := range facts.Commands {
		if !exactGitHEADArchiveCommand(source) || source.PipelineID == 0 {
			continue
		}
		for _, encoder := range facts.Commands {
			if encoder.PipelineID != source.PipelineID || !exactBase64StdinEncoder(encoder) ||
				!hasExactCommandFlow(facts, source.ID, encoder.ID) {
				continue
			}
			for _, upload := range facts.Commands {
				if upload.PipelineID != source.PipelineID ||
					!hasExactCommandFlow(facts, encoder.ID, upload.ID) ||
					!staticCurlStdinUploadWithMetadata(upload) ||
					!hasSourceArchiveExternalUpload(facts, upload.ID) {
					continue
				}
				result = append(result, SourceArchiveUploadFact{
					SourceCommandID: source.ID,
					UploadCommandID: upload.ID,
					Base64Encoded:   true,
				})
			}
		}
	}
	return result
}

func exactGitHEADArchiveCommand(command CommandFact) bool {
	return command.Dialect == DialectPOSIX && command.Effect == EffectExecute &&
		!command.ControlFlowUncertain && command.ArgvComplete &&
		command.ParentCommandID == 0 && len(command.Wrappers) == 0 &&
		command.Program == "git" && command.Executable == command.Argv[0] &&
		len(command.Argv) == 3 && command.Argv[0] == "git" &&
		command.Argv[1] == "archive" && command.Argv[2] == "HEAD" &&
		allStaticCommandArguments(command)
}

func exactBase64StdinEncoder(command CommandFact) bool {
	return command.Dialect == DialectPOSIX && command.Effect == EffectExecute &&
		!command.ControlFlowUncertain && command.ArgvComplete &&
		command.ParentCommandID == 0 && len(command.Wrappers) == 0 &&
		command.Program == "base64" && command.Executable == command.Argv[0] &&
		len(command.Argv) == 1 && command.Argv[0] == "base64" &&
		allStaticCommandArguments(command)
}

func allStaticCommandArguments(command CommandFact) bool {
	if len(command.Arguments) != len(command.Argv) {
		return false
	}
	for index, argument := range command.Arguments {
		if argument.Expands || argument.Quote == QuoteMixed ||
			argument.Value != command.Argv[index] {
			return false
		}
	}
	return true
}

func hasExactCommandFlow(facts Facts, from, to int64) bool {
	for _, flow := range facts.DataFlows {
		if flow.FromCommandID == from && flow.ToCommandID == to &&
			flow.From == DataStdout && flow.To == DataStdin {
			return true
		}
	}
	return false
}

func staticCurlStdinUploadWithMetadata(command CommandFact) bool {
	if command.Dialect != DialectPOSIX || command.Effect != EffectExecute ||
		command.ControlFlowUncertain || !command.ArgvComplete ||
		command.ParentCommandID != 0 || len(command.Wrappers) != 0 ||
		command.Program != "curl" || command.Executable != command.Argv[0] ||
		!exactCaseSensitivePOSIXProgram(&command, "curl") ||
		!allStaticCommandArguments(command) {
		return false
	}
	parsed := parseCurlArgv(command.Argv)
	if !parsed.Complete || parsed.ConfigOpaque || parsed.Preview ||
		parsed.EmptyTransferGroup || !parsed.hasValidOptionValues() ||
		len(parsed.Targets) != 1 || !curlRequestModeValid(parsed) ||
		!curlRangeOptionsValid(parsed) ||
		!staticCurlFeatureDependentPositiveOptionsValid(command, parsed) {
		return false
	}
	target := parsed.Targets[0]
	bodyCount := 0
	for _, option := range parsed.Options {
		if option.Group != target.Group {
			return false
		}
		switch option.Canonical {
		case "--silent", "--show-error", "--fail", "--fail-with-body":
			if option.ValuePresent {
				return false
			}
		case "--request":
			if !option.ValuePresent || !staticCurlOptionValue(command, option) ||
				(option.Value != "POST" && option.Value != "PUT") {
				return false
			}
		case "--header":
			if !option.ValuePresent || !staticCurlOptionValue(command, option) ||
				!safeSourceArchiveContentType(option.Value) {
				return false
			}
		case "--data-binary":
			if !option.ValuePresent || !staticCurlOptionValue(command, option) ||
				option.Value != "@-" {
				return false
			}
			bodyCount++
		default:
			return false
		}
	}
	if bodyCount != 1 || !staticCommandArgumentAt(command, target.ArgvIndex) ||
		!webMetadataTargetSchemeSupported(target.Value) ||
		!validLiteralRequestTarget(target.Value) ||
		curlTargetHasInvalidUserinfo(target.Value) || curlHasUnmodeledGlob(target.Value) {
		return false
	}
	return true
}

func hasSourceArchiveExternalUpload(facts Facts, commandID int64) bool {
	for _, network := range facts.Network {
		if network.CommandID != commandID || network.Action != NetworkUpload ||
			(network.Scheme != "http" && network.Scheme != "https") {
			continue
		}
		if network.Scope == NetworkScopePublic {
			return true
		}
		if network.Scope != NetworkScopeUnknown ||
			network.TargetKind != NetworkTargetSingleHost {
			continue
		}
		// Hostname destinations remain scope-unknown because ActionFacts never
		// performs DNS. The normalized fact still distinguishes reserved local
		// names and canonical numeric addresses from a literal external host.
		host := strings.TrimSuffix(
			strings.ToLower(strings.TrimSpace(network.NormalizedHost)), ".",
		)
		if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") {
			continue
		}
		if address, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil && address.Unmap().IsLoopback() {
			continue
		}
		return true
	}
	return false
}

func safeSourceArchiveContentType(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "content-type: text/plain" ||
		value == "content-type: application/octet-stream"
}
