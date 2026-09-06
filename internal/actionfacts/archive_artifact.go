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
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

const archiveArtifactIdentityDomain = "defenseclaw.archive-artifact.v1"

// ArtifactRole is whether a command produces or consumes a named artifact.
type ArtifactRole string

const (
	ArtifactProduce ArtifactRole = "produce"
	ArtifactConsume ArtifactRole = "consume"
)

// ArtifactKind is a closed set of statically identified artifact classes.
type ArtifactKind string

const (
	ArtifactKindArchive ArtifactKind = "archive"
)

// ArtifactFact is one statically named archive artifact. Identity is the
// SHA-256 of the normalized path after the same derivation used for PathFact.
// ActionFacts never opens the file or hashes its bytes.
type ArtifactFact struct {
	CommandID  int64
	Role       ArtifactRole
	Kind       ArtifactKind
	Value      string
	Normalized string
	Absolute   bool
	Resolved   string
	Identity   string
}

// ArchiveArtifactLineage is one exact produce-then-consume join on the same
// normalized artifact identity. Detection-only when either side is unproved.
type ArchiveArtifactLineage struct {
	Identity      string
	ProducedBy    int64
	ConsumedBy    int64
	Normalized    string
	Authoritative bool
}

func (o *parseOutput) appendArtifact(fact ArtifactFact) bool {
	if fact.CommandID == 0 || fact.Value == "" || fact.Value == "-" ||
		fact.Role == "" || fact.Kind == "" {
		return true
	}
	if len(o.artifacts) >= maxArtifactFacts {
		o.markLimit(IssueFactLimit)
		return false
	}
	o.artifacts = append(o.artifacts, fact)
	return true
}

func appendArchiveArtifact(out *parseOutput, commandID int64, role ArtifactRole, value string) {
	if out == nil || !staticArchiveArtifactPath(value) {
		return
	}
	out.appendArtifact(ArtifactFact{
		CommandID: commandID,
		Role:      role,
		Kind:      ArtifactKindArchive,
		Value:     value,
	})
}

func staticArchiveArtifactPath(value string) bool {
	if value == "" || value == "-" || value == "." || value == ".." {
		return false
	}
	if strings.ContainsAny(value, "*?[]") || strings.Contains(value, "$") {
		return false
	}
	return true
}

func classifyArchiveArtifactProducers(out *parseOutput, command *CommandFact) {
	if out == nil || command == nil {
		return
	}
	switch strings.ToLower(command.Program) {
	case "tar", "tar.exe":
		classifyTarArchiveProducer(out, command)
	case "zip", "zip.exe":
		classifyZipArchiveProducer(out, command)
	case "compress-archive":
		classifyCompressArchiveProducer(out, command)
	}
}

func classifyTarArchiveProducer(out *parseOutput, command *CommandFact) {
	if len(command.Argv) < 3 {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	file, created, complete := tarCreateArchiveFile(command.Argv)
	if !complete {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	if !created {
		return
	}
	if !staticArchiveArtifactPath(file) {
		out.markPartial(IssueUnsupportedConstruct)
		return
	}
	addOperation(command, OperationWrite)
	appendCommandPath(out, command, PathAccessWrite, file)
	appendArchiveArtifact(out, command.ID, ArtifactProduce, file)
}

func tarCreateArchiveFile(argv []string) (file string, created, complete bool) {
	if len(argv) < 2 {
		return "", false, false
	}
	if !strings.HasPrefix(argv[1], "-") {
		return traditionalTarCreateArchiveFile(argv)
	}
	parsed := parseOwnedPOSIXOptions(
		argv,
		exactOptionSet("-f", "--file"),
		exactOptionSet(
			"-c", "--create", "-t", "--list", "-x", "--extract",
			"-r", "--append", "-u", "--update", "-d", "--diff", "--compare",
			"-z", "--gzip", "-j", "--bzip2", "-J", "--xz", "-a", "--auto-compress",
			"-v", "--verbose", "-p", "--preserve-permissions",
			"-P", "--absolute-names", "--exclude-vcs",
		),
		exactOptionSet("--help", "--version"),
	)
	if parsed.preview {
		return "", false, true
	}
	if !parsed.complete {
		return "", false, false
	}
	created = archiveOptionSeen(parsed, "-c", "--create")
	if !created {
		return "", false, true
	}
	file, ok := parsed.values["-f"]
	if !ok {
		file, ok = parsed.values["--file"]
	}
	if !ok || file == "" {
		return "", false, false
	}
	return file, true, true
}

func traditionalTarCreateArchiveFile(argv []string) (file string, created, complete bool) {
	cluster := argv[1]
	if cluster == "" || strings.HasPrefix(cluster, "-") {
		return "", false, false
	}
	fileIndex := -1
	for i := 0; i < len(cluster); i++ {
		switch cluster[i] {
		case 'c':
			created = true
		case 't', 'x', 'u', 'r', 'd':
			created = false
		case 'f':
			if fileIndex >= 0 {
				return "", false, false
			}
			fileIndex = 2
		case 'z', 'j', 'J', 'a', 'v', 'p', 'P', 'h', 'k', 'm', 'o', 's', 'w',
			'B', 'C', 'H', 'L', 'S', 'W', 'X', 'Z':
		default:
			return "", false, false
		}
	}
	if !created {
		return "", false, true
	}
	if fileIndex < 0 || fileIndex >= len(argv) || argv[fileIndex] == "" {
		return "", false, false
	}
	return argv[fileIndex], true, true
}

func classifyZipArchiveProducer(out *parseOutput, command *CommandFact) {
	parsed := parseOwnedPOSIXOptions(
		command.Argv,
		exactOptionSet(
			"-b", "-n", "-t", "-tt", "-x", "-i", "-P",
			"--output-file",
		),
		exactOptionSet(
			"-r", "-q", "-1", "-2", "-3", "-4", "-5", "-6", "-7", "-8", "-9",
			"-X", "-j", "-y", "-m", "-u", "-F", "-FF", "-A", "-T", "-UN",
		),
		exactOptionSet("-h", "-hh", "--help"),
	)
	if parsed.preview && len(parsed.positionals) == 0 {
		command.Effect = EffectPreview
		return
	}
	if !parsed.complete || len(parsed.positionals) == 0 {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	file := parsed.positionals[0]
	if !staticArchiveArtifactPath(file) {
		out.markPartial(IssueUnsupportedConstruct)
		return
	}
	addOperation(command, OperationWrite)
	appendCommandPath(out, command, PathAccessWrite, file)
	appendArchiveArtifact(out, command.ID, ArtifactProduce, file)
}

func classifyCompressArchiveProducer(out *parseOutput, command *CommandFact) {
	if !requireCommandDialect(out, command, DialectPowerShell) {
		return
	}
	destination := powerShellNamedValue(command.Argv, "-DestinationPath", "-destinationpath")
	if destination == "" && len(command.Argv) >= 3 &&
		!strings.HasPrefix(command.Argv[len(command.Argv)-1], "-") {
		destination = command.Argv[len(command.Argv)-1]
	}
	if !staticArchiveArtifactPath(destination) {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	addOperation(command, OperationWrite)
	appendCommandPath(out, command, PathAccessWrite, destination)
	appendArchiveArtifact(out, command.ID, ArtifactProduce, destination)
}

func classifyGitBundleProducer(out *parseOutput, command *CommandFact, index int) {
	if index+2 >= len(command.Argv) {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	if !strings.EqualFold(command.Argv[index+1], "create") {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	file := command.Argv[index+2]
	if strings.HasPrefix(file, "-") || !staticArchiveArtifactPath(file) {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	if !gitBundleCreateHasRevisionInput(command.Argv, index+2) {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	addOperation(command, OperationWrite)
	appendCommandPath(out, command, PathAccessWrite, file)
	appendArchiveArtifact(out, command.ID, ArtifactProduce, file)
}

func gitBundleCreateHasRevisionInput(argv []string, fileIndex int) bool {
	if fileIndex < 0 || fileIndex >= len(argv)-1 {
		return false
	}
	for _, arg := range argv[fileIndex+1:] {
		if gitBundleRevisionListArg(arg) {
			return true
		}
	}
	return false
}

func gitBundleRevisionListArg(arg string) bool {
	if arg == "" || gitBundleCreateOnlyOption(arg) {
		return false
	}
	switch {
	case arg == "--stdin", arg == "--all", arg == "--not":
		return true
	case strings.HasPrefix(arg, "--branches"),
		strings.HasPrefix(arg, "--tags"),
		strings.HasPrefix(arg, "--remotes"):
		return true
	case strings.HasPrefix(arg, "^") && arg != "^":
		return true
	case !strings.HasPrefix(arg, "-"):
		return true
	default:
		return false
	}
}

func gitBundleCreateOnlyOption(arg string) bool {
	switch arg {
	case "-q", "--quiet", "--progress", "--all-progress", "--all-progress-implied":
		return true
	default:
		return strings.HasPrefix(arg, "--version")
	}
}

func classifyArchiveArtifactConsumers(out *parseOutput, command *CommandFact) {
	if out == nil || command == nil {
		return
	}
	program := strings.ToLower(command.Program)
	switch program {
	case "curl", "curl.exe":
		for _, source := range StaticCurlUploadFileSources(*command) {
			appendArchiveArtifact(out, command.ID, ArtifactConsume, source.Path)
		}
	case "scp", "scp.exe":
		if !artifactCommandHasOperation(*command, OperationUpload) {
			return
		}
		for _, source := range scpLocalUploadSourceOperands(*command) {
			appendArchiveArtifact(out, command.ID, ArtifactConsume, source)
		}
	}
}

func artifactCommandHasOperation(command CommandFact, want OperationKind) bool {
	for _, operation := range command.Operations {
		if operation == want {
			return true
		}
	}
	return false
}

func archiveOptionSeen(parsed ownedPOSIXOptionParse, options ...string) bool {
	for _, option := range options {
		if _, ok := parsed.seen[option]; ok {
			return true
		}
	}
	return false
}

func powerShellNamedValue(argv []string, names ...string) string {
	wanted := make(map[string]struct{}, len(names))
	for _, name := range names {
		wanted[strings.ToLower(name)] = struct{}{}
	}
	for i := 1; i < len(argv); i++ {
		key, value, joined := strings.Cut(argv[i], ":")
		if _, ok := wanted[strings.ToLower(key)]; !ok {
			continue
		}
		if joined {
			return value
		}
		if i+1 < len(argv) && !strings.HasPrefix(argv[i+1], "-") {
			return argv[i+1]
		}
	}
	return ""
}

func normalizeArtifactFactsForCommands(
	facts []ArtifactFact,
	cwd string,
	activeHome string,
	commands []CommandFact,
) {
	if len(facts) == 0 {
		return
	}
	paths := make([]PathFact, len(facts))
	for i, fact := range facts {
		paths[i] = PathFact{
			CommandID: fact.CommandID,
			Access:    PathAccessWrite,
			Value:     fact.Value,
		}
		if fact.Role == ArtifactConsume {
			paths[i].Access = PathAccessRead
		}
	}
	normalizePathFactsForCommands(paths, cwd, activeHome, commands)
	for i := range facts {
		facts[i].Normalized = paths[i].Normalized
		facts[i].Absolute = paths[i].Absolute
		facts[i].Resolved = paths[i].Resolved
		facts[i].Identity = archiveArtifactIdentity(paths[i])
	}
}

func archiveArtifactIdentity(path PathFact) string {
	canonical := strings.TrimSpace(path.Resolved)
	if canonical == "" {
		canonical = strings.TrimSpace(path.Normalized)
	}
	if canonical == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(
		archiveArtifactIdentityDomain + "\x00" +
			string(path.Flavor) + "\x00" + canonical,
	))
	return hex.EncodeToString(sum[:])
}

// StaticArchiveArtifactLineage returns exact same-artifact produce/consume
// joins. Authoritative is true only when the enclosing facts are complete and
// both sides have a non-empty identity.
func StaticArchiveArtifactLineage(facts Facts) []ArchiveArtifactLineage {
	return joinArchiveArtifactFacts(facts.Artifacts, facts.Authoritative())
}

// JoinArchiveArtifactLineage correlates a producer action with a later consumer
// action on the same normalized identity. Command IDs are remapped so split
// tool calls that both start at 1 still join. This is an identity-bound join,
// not a seventh content-free tool-chain.
func JoinArchiveArtifactLineage(produced Facts, consumed Facts) []ArchiveArtifactLineage {
	offset := int64(0)
	for _, command := range produced.Commands {
		if command.ID > offset {
			offset = command.ID
		}
	}
	for _, fact := range produced.Artifacts {
		if fact.CommandID > offset {
			offset = fact.CommandID
		}
	}
	joined := make([]ArtifactFact, 0, len(produced.Artifacts)+len(consumed.Artifacts))
	joined = append(joined, produced.Artifacts...)
	for _, fact := range consumed.Artifacts {
		fact.CommandID += offset
		joined = append(joined, fact)
	}
	return joinArchiveArtifactFacts(
		joined,
		produced.Authoritative() && consumed.Authoritative(),
	)
}

func precedingArchiveProducer(
	producers []ArtifactFact,
	consumer ArtifactFact,
) (ArtifactFact, bool) {
	var best ArtifactFact
	found := false
	for _, producer := range producers {
		if producer.Identity != consumer.Identity ||
			producer.CommandID >= consumer.CommandID {
			continue
		}
		if !found || producer.CommandID > best.CommandID {
			best = producer
			found = true
		}
	}
	return best, found
}

func joinArchiveArtifactFacts(
	facts []ArtifactFact,
	authoritative bool,
) []ArchiveArtifactLineage {
	var producers []ArtifactFact
	var lineages []ArchiveArtifactLineage
	seen := make(map[string]struct{})
	for _, fact := range facts {
		if fact.Kind != ArtifactKindArchive || fact.Identity == "" {
			continue
		}
		if fact.Role == ArtifactProduce {
			producers = append(producers, fact)
		}
	}
	for _, fact := range facts {
		if fact.Kind != ArtifactKindArchive || fact.Role != ArtifactConsume ||
			fact.Identity == "" {
			continue
		}
		producer, ok := precedingArchiveProducer(producers, fact)
		if !ok {
			continue
		}
		key := fact.Identity + "\x00" +
			strings.TrimSpace(producer.Normalized)
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		lineages = append(lineages, ArchiveArtifactLineage{
			Identity:   fact.Identity,
			ProducedBy: producer.CommandID,
			ConsumedBy: fact.CommandID,
			Normalized: firstNonEmptyArtifactPath(producer, fact),
			Authoritative: authoritative &&
				producer.Identity != "" && fact.Identity != "",
		})
	}
	return lineages
}

// HasAuthoritativeArchiveLineage is the typed CEL-compatible owner predicate
// for same-command archive-then-upload.
func (f Facts) HasAuthoritativeArchiveLineage() bool {
	for _, lineage := range StaticArchiveArtifactLineage(f) {
		if lineage.Authoritative {
			return true
		}
	}
	return false
}

func firstNonEmptyArtifactPath(values ...ArtifactFact) string {
	for _, fact := range values {
		if fact.Resolved != "" {
			return fact.Resolved
		}
		if fact.Normalized != "" {
			return fact.Normalized
		}
	}
	return ""
}
