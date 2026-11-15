// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"strings"
)

// CredentialSenderReason names why a call hands credential material to a
// sender whose destination is not read in full (GAP-0595). Such a call is
// the unknown tier of the one bound rule: an alert in the default and
// permissive packs, a block in strict (bounded.Unknown).
type CredentialSenderReason string

const (
	// CredentialSenderNone: the call proves no credential material reaching
	// a sender.
	CredentialSenderNone CredentialSenderReason = ""
	// CredentialSenderInlineCode: interpreter code that asks for a network
	// capability and names a credentials file (python3 -c, node -e, ...).
	CredentialSenderInlineCode CredentialSenderReason = "credential_file_in_inline_sender"
	// CredentialSenderEnvPipe: a credential-named environment variable's
	// value is piped into a program that uploads its standard input.
	CredentialSenderEnvPipe CredentialSenderReason = "credential_env_piped_to_sender"
)

// CredentialSenderUnreadDestination reports credential material reaching a
// sender the projection could not read as an exact upload: interpreter code
// that names a credentials file and a network capability, or a
// credential-named environment variable piped into an upload sender. It
// reads only what the call itself shows; the file is a credentials file by
// the same closed vocabulary the exact upload rule uses.
func CredentialSenderUnreadDestination(facts Facts) CredentialSenderReason {
	if inlineCodeNamesCredentialFile(facts) {
		return CredentialSenderInlineCode
	}
	if credentialEnvPipedToSender(facts) {
		return CredentialSenderEnvPipe
	}
	return CredentialSenderNone
}

func inlineCodeNamesCredentialFile(facts Facts) bool {
	for _, command := range facts.Commands {
		row, argv, ok := inlineProgramRow(command)
		if !ok {
			continue
		}
		source := inlineCodeOperands(row, argv[1:])
		if source == "" || !inlineSourceNetwork(row, source) {
			continue
		}
		for _, literal := range quotedLiterals(source) {
			if credentialFileLiteral(literal, facts.CWD, facts.ActiveHome) {
				return true
			}
		}
	}
	return false
}

// credentialFileLiteral reports a string literal that names a credentials
// file: an absolute path, a ~/ path under the active home, or a path
// relative to the working directory.
func credentialFileLiteral(literal, cwd, home string) bool {
	value := strings.TrimSpace(literal)
	if value == "" || len(value) > 4096 || strings.ContainsAny(value, "\x00\n") {
		return false
	}
	switch {
	case strings.HasPrefix(value, "~/") && strings.HasPrefix(home, "/"):
		value = path.Join(home, value[2:])
	case strings.HasPrefix(value, "/"):
	case !strings.Contains(value, "://") && !strings.ContainsAny(value, " \t"):
		// A relative name: the hook path often has no working directory, so
		// the name is judged by its shape alone, rooted at /.
		root := "/"
		if strings.HasPrefix(cwd, "/") {
			root = cwd
		}
		value = path.Join(root, value)
	default:
		return false
	}
	canonical := strings.ToLower(path.Clean(value))
	if _, ok := MatchCredentialFileShape(canonical); ok {
		return true
	}
	return credentialFileUploadClass(value) == CredentialFileUploadStrong
}

// quotedLiterals returns the single- and double-quoted string literals of
// interpreter source (a backslash escapes the next byte), bounded.
func quotedLiterals(source string) []string {
	const maxLiterals = 256
	var out []string
	for i := 0; i < len(source) && len(out) < maxLiterals; i++ {
		quote := source[i]
		if quote != '\'' && quote != '"' && quote != '`' {
			continue
		}
		var b strings.Builder
		j := i + 1
		for ; j < len(source); j++ {
			if source[j] == '\\' && j+1 < len(source) {
				j++
				b.WriteByte(source[j])
				continue
			}
			if source[j] == quote {
				break
			}
			b.WriteByte(source[j])
		}
		out = append(out, b.String())
		i = j
	}
	return out
}

// credentialEnvPipedToSender reports a pipeline whose first stage emits a
// credential-named environment variable (an expansion of the call, or the
// operand of printenv or env) and whose next stage is a projected upload that
// reads its standard input.
func credentialEnvPipedToSender(facts Facts) bool {
	senders := map[int64]bool{}
	for _, command := range facts.Commands {
		if command.Effect != EffectExecute || !hasFactOperation(command, OperationUpload) {
			continue
		}
		for _, flow := range facts.DataFlows {
			if flow.FromCommandID == command.ID && flow.From == DataStdin && flow.To == DataNetwork {
				senders[command.ID] = true
			}
		}
	}
	if len(senders) == 0 {
		return false
	}
	byID := map[int64]CommandFact{}
	for _, command := range facts.Commands {
		byID[command.ID] = command
	}
	var expanded []string
	for _, source := range facts.sendSources {
		expanded = append(expanded, envReferenceNames(source.text)...)
		for _, word := range source.argv {
			expanded = append(expanded, envReferenceNames(word)...)
		}
	}
	for _, flow := range facts.DataFlows {
		if flow.From != DataStdout || flow.To != DataStdin || !senders[flow.ToCommandID] {
			continue
		}
		producer, ok := byID[flow.FromCommandID]
		if !ok {
			continue
		}
		switch senderProgramName(producer.Program) {
		case "echo", "printf":
			for _, argument := range producer.Arguments {
				if argument.Expands && anyCredentialEnvName(expanded) {
					return true
				}
			}
		case "printenv", "env":
			for _, word := range commandArgs(producer) {
				if credentialEnvName(word) {
					return true
				}
			}
		}
	}
	return false
}

func anyCredentialEnvName(names []string) bool {
	for _, name := range names {
		if credentialEnvName(name) {
			return true
		}
	}
	return false
}

// envReferenceNames returns the names of the $NAME and ${NAME...} references
// in a shell text.
func envReferenceNames(text string) []string {
	var names []string
	for i := 0; i+1 < len(text) && len(names) < 64; i++ {
		if text[i] != '$' {
			continue
		}
		j := i + 1
		if text[j] == '{' {
			j++
		}
		start := j
		for j < len(text) && (text[j] == '_' || text[j] >= 'A' && text[j] <= 'Z' ||
			text[j] >= 'a' && text[j] <= 'z' || text[j] >= '0' && text[j] <= '9' && j > start) {
			j++
		}
		if j > start {
			names = append(names, text[start:j])
		}
		i = j - 1
	}
	return names
}

// credentialEnvName reports an environment variable name that holds a
// credential: a TOKEN, SECRET, PASSWORD, PASSWD, CREDENTIAL(S) or APIKEY
// word of the name, or a KEY word after API, ACCESS, PRIVATE, SIGNING or
// AUTH (GITHUB_TOKEN, AWS_SECRET_ACCESS_KEY, DB_PASSWORD, OPENAI_API_KEY).
func credentialEnvName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	words := strings.Split(strings.ToUpper(name), "_")
	for i, word := range words {
		switch word {
		case "TOKEN", "TOKENS", "SECRET", "SECRETS", "PASSWORD", "PASSWD", "CREDENTIAL", "CREDENTIALS", "APIKEY":
			return true
		case "KEY":
			if i > 0 {
				switch words[i-1] {
				case "API", "ACCESS", "PRIVATE", "SIGNING", "AUTH":
					return true
				}
			}
		}
	}
	return false
}
