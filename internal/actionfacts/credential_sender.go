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
	// CredentialSenderFile: a credentials file handed to a sender the upload
	// rule does not prove: an operand, a redirect or a pipe into a program
	// that writes to the network (ssh or nc stdin, a wrapped scp, a program
	// whose network role is not proven).
	CredentialSenderFile CredentialSenderReason = "credential_file_to_unproven_sender"
	// CredentialSenderDirectory: a directory or a glob that may hold a
	// credentials file (scp -r of ~/.aws, rsync of the home, a name glob)
	// uploaded by any sender.
	CredentialSenderDirectory CredentialSenderReason = "credential_directory_to_sender"
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
	return credentialHandedToSender(facts)
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

// credentialHandedToSender reads the senders of the shared sender reader for
// credential material the exact upload rule does not judge: a credentials
// file in the operands, the redirect or the pipeline of a sender that is not
// an exact projected upload, and a directory or glob that may hold one in the
// operands of any sender (GAP-0719, GAP-0720).
func credentialHandedToSender(facts Facts) CredentialSenderReason {
	reading := ReadSenders(facts)
	if !reading.Sends() {
		return credentialToRemoteOperand(facts)
	}
	byID := map[int64]CommandFact{}
	for _, command := range facts.Commands {
		byID[command.ID] = command
	}
	reason := CredentialSenderNone
	for _, sender := range reading.Senders {
		// an exact projected upload of a complete call is judged by the
		// credential-file upload rule
		exact := !(sender.Origin == SenderProjected && facts.Authoritative())
		for _, operand := range sender.Operands {
			if exact && credentialPathOperand(operand, facts.CWD, facts.ActiveHome) {
				return CredentialSenderFile
			}
			if credentialMayHold(operand, facts.CWD, facts.ActiveHome) {
				reason = CredentialSenderDirectory
			}
		}
		if exact && sender.CommandID != 0 {
			command := byID[sender.CommandID]
			for _, redirect := range command.Redirects {
				if redirect.FD == 0 && redirect.Access == PathAccessRead &&
					credentialPathOperand(redirect.Target, facts.CWD, facts.ActiveHome) {
					return CredentialSenderFile
				}
			}
			if credentialProducerFeeds(facts, sender.CommandID, 4) {
				return CredentialSenderFile
			}
		}
	}
	return reason
}

// credentialToRemoteOperand reads a command no network program of the
// classifiers (rclone, docker cp, a copy tool): a credentials file operand
// beside an operand that names a remote place (host:path, a URL).
func credentialToRemoteOperand(facts Facts) CredentialSenderReason {
	for _, command := range facts.Commands {
		if command.Kind == CommandKindShellRedirect || command.Effect == EffectPreview ||
			len(networkFactsOf(facts, command.ID)) > 0 {
			continue
		}
		credential, remote := false, false
		for _, word := range commandWords(command) {
			switch {
			case credentialPathOperand(word, facts.CWD, facts.ActiveHome):
				credential = true
			case unprovenRemoteOperand(word) || namedRemoteOperand(word):
				remote = true
			}
		}
		if credential && remote {
			return CredentialSenderFile
		}
	}
	return CredentialSenderNone
}

// namedRemoteOperand is name:path of a configured remote (rclone remote:bucket,
// docker cp ctr:/path): a name of two letters or more before the colon.
func namedRemoteOperand(word string) bool {
	m := senderRemoteOperand.FindStringSubmatch(word)
	return m != nil && len(m[1]) >= 2 && len(word) > len(m[0])
}

// credentialProducerFeeds reports a command, up to hops pipe stages before
// the sender, that reads a credentials file.
func credentialProducerFeeds(facts Facts, id int64, hops int) bool {
	if hops <= 0 {
		return false
	}
	for _, flow := range facts.DataFlows {
		if flow.ToCommandID != id || flow.From != DataStdout || flow.To != DataStdin {
			continue
		}
		for _, candidate := range facts.Paths {
			if candidate.CommandID == flow.FromCommandID && candidate.Access == PathAccessRead &&
				credentialPathOperand(firstNonEmpty(candidate.Resolved, candidate.Value), facts.CWD, facts.ActiveHome) {
				return true
			}
		}
		if credentialProducerFeeds(facts, flow.FromCommandID, hops-1) {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// credentialPathOperand is a word that names a credentials file: an absolute
// path, a ~/ path under the active home, a Windows path, or a path relative
// to the working directory (judged by its shape when the hook has none).
func credentialPathOperand(word, cwd, home string) bool {
	canonical, ok := senderOperandPath(word, cwd, home)
	if !ok {
		return false
	}
	if _, match := MatchCredentialFileShape(canonical); match {
		return true
	}
	return credentialFileUploadClass(canonical) == CredentialFileUploadStrong
}

// senderOperandPath is the lower-case, forward-slash, absolute path a local
// operand word names, or false for a word that is an option, a URL or a
// remote operand.
func senderOperandPath(word, cwd, home string) (string, bool) {
	value := strings.TrimSpace(word)
	if value == "" || len(value) > 4096 || strings.ContainsAny(value, "\x00\n") ||
		strings.HasPrefix(value, "-") || senderURLOperand.MatchString(value) || unprovenRemoteOperand(value) {
		return "", false
	}
	value = strings.ReplaceAll(value, `\`, "/")
	if len(value) > 2 && value[1] == ':' && (value[0] >= 'a' && value[0] <= 'z' || value[0] >= 'A' && value[0] <= 'Z') {
		value = value[2:] // a Windows drive
	}
	switch {
	case strings.HasPrefix(value, "~/") && strings.HasPrefix(home, "/"):
		value = path.Join(home, value[2:])
	case strings.HasPrefix(value, "/"):
	default:
		root := "/"
		if strings.HasPrefix(cwd, "/") {
			root = cwd
		}
		value = path.Join(root, value)
	}
	return strings.ToLower(path.Clean(value)), true
}

// credentialDirectoryNames are the folder names the credentials-file table
// names: the parent of each trailing relative path (.aws, .kube,
// .config/gcloud) and each row's dir (.ssh, .azure).
var credentialDirectoryNames = func() []string {
	seen := map[string]bool{}
	var names []string
	add := func(name string) {
		if name != "" && name != "." && !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	for _, row := range credentialFileShapes {
		if row.relative != "" {
			add(path.Dir(row.relative))
		}
		add(row.dir)
	}
	return names
}()

// credentialMayHold reports a directory or a glob operand that may hold a
// credentials file: a credentials folder or anything below one, the active
// home or one of its parents, or a glob whose name pattern a credentials
// file name matches (or that sits in a credentials folder).
func credentialMayHold(word, cwd, home string) bool {
	canonical, ok := senderOperandPath(word, cwd, home)
	if !ok {
		return false
	}
	inCredentialDirectory := func(dir string) bool {
		for _, name := range credentialDirectoryNames {
			if dir == name || strings.HasSuffix(dir, "/"+name) || strings.Contains(dir, "/"+name+"/") ||
				strings.HasPrefix(dir, name+"/") {
				return true
			}
		}
		return false
	}
	if strings.ContainsAny(canonical, "*?[") {
		dir, base := path.Dir(canonical), path.Base(canonical)
		if inCredentialDirectory(dir) {
			return true
		}
		for _, row := range credentialFileShapes {
			name := row.base
			switch {
			case row.relative != "":
				name = path.Base(row.relative)
			case row.basePrefix != "":
				name = row.basePrefix + "x"
				if len(row.suffixes) > 0 {
					name += row.suffixes[0]
				}
			}
			if name == "" || strings.HasPrefix(name, ".") && !strings.HasPrefix(base, ".") {
				continue // a shell glob does not match a dot file unless its pattern starts with a dot
			}
			if matched, _ := path.Match(base, name); matched {
				return true
			}
		}
		return false
	}
	if _, file := MatchCredentialFileShape(canonical); file {
		return false // a file: the exact rules judge it
	}
	if inCredentialDirectory(canonical) {
		return true
	}
	if home = strings.ToLower(path.Clean(home)); strings.HasPrefix(home, "/") {
		return canonical == home || canonical == "/" || strings.HasPrefix(home, canonical+"/")
	}
	return canonical == "/"
}
