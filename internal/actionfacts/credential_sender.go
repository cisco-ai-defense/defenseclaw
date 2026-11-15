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
		command := byID[sender.CommandID]
		// The destination is where the connection goes: a route option
		// (--resolve, --connect-to, a proxy) can send a local-looking URL to
		// any address (GAP-0795).
		override := sender.CommandID != 0 && senderRouteOverridden(command)
		if sender.Origin == SenderProjected && !override && !senderToExternal(sender) {
			continue // the data stays on this host or its private network
		}
		// A relative operand is rooted at the working directory the call has
		// there: the one the hook reports, moved by every cd before the
		// sender (GAP-0773, GAP-0797). A cd whose target is not read leaves
		// no working directory: the operand is judged by its shape alone.
		scoped := facts
		moved := false
		if cwd, changed := cwdBefore(facts, sender.CommandID); changed {
			scoped.CWD, moved = cwd, true
		}
		// A projected upload or remote copy (curl, scp, rsync, wget: the
		// exact credential-file upload rule judges its files) keeps that
		// rule's reach; the file check here is for the senders it does not
		// read: a network role, an unproven role, a part the projection did
		// not read.
		exact := sender.Origin != SenderProjected && sender.Origin != SenderRemoteCopy
		operands := sender.Operands
		if !exact && sender.CommandID != 0 && (override || moved || !judgedByUploadRule(facts, command)) {
			// A projected upload the exact rule cannot judge (a partial or
			// uncertain parse, another dialect, a route option, a working
			// directory the rule does not know) is read here by the files its
			// upload options name (GAP-0768).
			exact = true
			if files, known := uploadOptionFiles(byID[sender.CommandID]); known {
				// the option tables name what is sent; the other words
				// (--key, --cert, a TLS file) are not data
				operands = files
			}
		}
		if sender.Program == "scp" && remoteOperandCount(sender.Operands) >= 2 {
			exact = true // scp -3: the file goes through the local host to a second remote
		}
		unreadDirectory := moved && scoped.CWD == ""
		for _, operand := range operands {
			if exact && (credentialPathOperand(operand, scoped.CWD, facts.ActiveHome) ||
				unreadDirectory && relativeCredentialLeaf(operand)) {
				return CredentialSenderFile
			}
			if credentialMayHold(operand, scoped.CWD, facts.ActiveHome) {
				reason = CredentialSenderDirectory
			}
		}
		// what is fed to the sender is what it sends: a file or text on its
		// standard input, the output of the commands piped or substituted
		// into it (GAP-0775). A sender the exact rule judges keeps that
		// rule for the files its options name; the fed data it does not read.
		if sender.CommandID != 0 && (exact || override || senderToExternal(sender)) {
			for _, redirect := range command.Redirects {
				if redirect.FD == 0 && redirect.Access == PathAccessRead &&
					credentialPathOperand(redirect.Target, scoped.CWD, facts.ActiveHome) {
					return CredentialSenderFile
				}
			}
			switch credentialProducerFeeds(scoped, sender.CommandID, 4) {
			case CredentialSenderFile:
				return CredentialSenderFile
			case CredentialSenderDirectory:
				reason = CredentialSenderDirectory
			}
		}
		for _, word := range batchTransferWords(sender.FedText) {
			if credentialPathOperand(word, scoped.CWD, facts.ActiveHome) {
				return CredentialSenderFile
			}
			if credentialMayHold(word, scoped.CWD, facts.ActiveHome) {
				reason = CredentialSenderDirectory
			}
		}
	}
	return reason
}

// judgedByUploadRule reports a command the exact credential-file upload rule
// reads (projectCredentialFileUploads): a complete parse, a POSIX command that
// runs, with no uncertain control flow.
func judgedByUploadRule(facts Facts, command CommandFact) bool {
	return facts.Authoritative() && command.Dialect == DialectPOSIX &&
		command.Effect == EffectExecute && !command.ControlFlowUncertain
}

// cwdBefore is the working directory the call has at the command with the
// given id: the hook's, moved by every cd, pushd or popd before it. changed
// is false when no command moved it. A move whose target is not a static
// word (or runs under uncertain control flow) leaves cwd empty: the
// directory is not read.
func cwdBefore(facts Facts, id int64) (cwd string, changed bool) {
	cwd = facts.CWD
	for _, command := range facts.Commands {
		if id != 0 && command.ID >= id {
			continue
		}
		switch senderProgramName(command.Program) {
		case "cd", "chdir", "pushd", "popd":
		default:
			continue
		}
		changed = true
		target := ""
		// the target is read from the arguments (an expansion is an empty
		// word); cd on the left of && changes the directory of what follows
		// it, any other control flow leaves the directory unknown
		unconditional := !command.ControlFlowUncertain ||
			command.ControlFlowOperator == ControlFlowOperatorNone || command.ControlFlowOperator == ControlFlowOperatorAnd
		if unconditional && senderProgramName(command.Program) != "popd" && len(command.Arguments) > 1 {
			for _, argument := range command.Arguments[1:] {
				if argument.Value == "--" || argument.Value == "-L" || argument.Value == "-P" {
					continue
				}
				target = argument.Value
				if argument.Expands {
					target = ""
				}
			}
		}
		switch {
		case target == "" || strings.ContainsAny(target, "$`*?[") || target == "-":
			cwd = ""
		case strings.HasPrefix(target, "~/") && strings.HasPrefix(facts.ActiveHome, "/"):
			cwd = path.Join(facts.ActiveHome, target[2:])
		case target == "~" && strings.HasPrefix(facts.ActiveHome, "/"):
			cwd = facts.ActiveHome
		case strings.HasPrefix(target, "/"):
			cwd = path.Clean(target)
		case strings.HasPrefix(cwd, "/"):
			cwd = path.Join(cwd, target)
		default:
			cwd = ""
		}
	}
	return cwd, changed
}

// relativeCredentialLeaf reports a relative file name that is the last part
// of a credentials file in some credentials folder (credentials of .aws, id_rsa
// of .ssh, .env). Used when a cd whose target is not read leaves the folder
// unknown: such a name is the unknown tier, as any other input the call does
// not let us read.
func relativeCredentialLeaf(word string) bool {
	if word == "" || strings.HasPrefix(word, "/") || strings.HasPrefix(word, "~") || strings.HasPrefix(word, "-") ||
		strings.ContainsAny(word, "$`*?[\x00") || len(word) > 256 {
		return false
	}
	word = strings.ToLower(path.Clean(word))
	if strings.HasPrefix(word, "../") || word == ".." {
		return false
	}
	candidates := []string{"/" + word}
	for _, dir := range credentialDirectoryNames {
		candidates = append(candidates, "/"+dir+"/"+word)
	}
	for _, candidate := range candidates {
		if _, ok := MatchCredentialFileShape(candidate); ok {
			return true
		}
	}
	return false
}

// senderRouteOverridden reports a curl or wget whose options send the
// connection somewhere other than the URL names: --resolve, --connect-to, a
// proxy, a socks proxy, a unix socket (curl's network-override options), or
// a wget run with a proxy or an -e setting. Its URL is not its destination.
func senderRouteOverridden(command CommandFact) bool {
	switch {
	case isCurlProgram(command.Program):
		for _, option := range parseCurlArgv(command.Argv).Options {
			if option.Role == curlOptionNetworkOverride && option.Canonical != "--noproxy" && option.Canonical != "--interface" {
				return true
			}
		}
	case isWgetProgram(command.Program):
		parsed := parseWgetArgv(command.Argv)
		return parsed.ConfigIndirect || (parsed.ProxySet && parsed.Proxy)
	}
	return false
}

// batchTransferWords are the local words of a file-transfer batch fed to a
// sender (sftp, ftp): the words after the put, mput, send, reput or append
// verb of a line. Any other fed text is that program's script or data, not a
// list of local files to send (GAP-0796).
func batchTransferWords(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "put", "mput", "send", "reput", "append", "lput", "lmput":
			out = append(out, fields[1:]...)
		}
	}
	return out
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
		// the values the program's option tables own (ssh -i, scp -o) are
		// not operands: an identity file authenticates, it is not sent
		for _, word := range senderOperandWords(senderProgramName(command.Program), commandWords(command)) {
			switch {
			case credentialPathOperand(word, facts.CWD, facts.ActiveHome):
				credential = true
			case unprovenRemoteOperand(word):
				remote = true
			}
		}
		if credential && remote {
			return CredentialSenderFile
		}
	}
	return CredentialSenderNone
}

// credentialProducerFeeds reads the commands up to hops stages before the
// sender, through a pipe or a command substitution: a credentials file they
// read (or name) is CredentialSenderFile, a folder that may hold one
// CredentialSenderDirectory.
func credentialProducerFeeds(facts Facts, id int64, hops int) CredentialSenderReason {
	if hops <= 0 {
		return CredentialSenderNone
	}
	reason := CredentialSenderNone
	byID := map[int64]CommandFact{}
	for _, command := range facts.Commands {
		byID[command.ID] = command
	}
	for _, flow := range facts.DataFlows {
		if flow.ToCommandID != id || flow.From != DataStdout || (flow.To != DataStdin && flow.To != DataProcess) {
			continue
		}
		var words []string
		for _, candidate := range facts.Paths {
			if candidate.CommandID == flow.FromCommandID && candidate.Access == PathAccessRead {
				words = append(words, firstNonEmpty(candidate.Resolved, candidate.Value))
			}
		}
		switch senderProgramName(byID[flow.FromCommandID].Program) {
		case "echo", "printf":
			// these print their words: not a read of the files they name
		default:
			words = append(words, commandWords(byID[flow.FromCommandID])...)
		}
		for _, word := range words {
			if credentialPathOperand(word, facts.CWD, facts.ActiveHome) {
				return CredentialSenderFile
			}
			if credentialMayHold(word, facts.CWD, facts.ActiveHome) {
				reason = CredentialSenderDirectory
			}
		}
		if inner := credentialProducerFeeds(facts, flow.FromCommandID, hops-1); inner == CredentialSenderFile {
			return CredentialSenderFile
		} else if inner != CredentialSenderNone {
			reason = inner
		}
	}
	return reason
}

// senderToExternal reports a projected sender whose destination is not proven
// loopback, private or link-local.
func senderToExternal(sender SenderFact) bool {
	if len(sender.Network) == 0 {
		return true
	}
	for _, network := range sender.Network {
		host := strings.ToLower(firstNonEmpty(network.NormalizedHost, network.Host))
		switch {
		case network.Scope == NetworkScopeLoopback || network.Scope == NetworkScopeLinkLocal || network.Scope == NetworkScopePrivate:
		case host == "localhost" || strings.HasSuffix(host, ".localhost"):
		default:
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
	if value == "" || len(value) > 4096 || strings.ContainsAny(value, "\x00\n$`{}") ||
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
	unrooted := !strings.HasPrefix(cwd, "/") && !strings.HasPrefix(word, "/") && !strings.HasPrefix(word, "~") &&
		!strings.ContainsAny(word, "*?[") && !strings.Contains(word, ":")
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
		// A name glob counts when it names something: a literal prefix of
		// three bytes or more (.env*, cred*, id_*), or a key-file suffix
		// (*.key, *.pem, *.p12, *.pfx). A bare * or *.json matches every file.
		literal := base
		if i := strings.IndexAny(base, "*?["); i >= 0 {
			literal = base[:i]
		}
		switch path.Ext(base) {
		case ".key", ".pem", ".p12", ".pfx":
			if strings.HasPrefix(base, "*") {
				literal = "   "
			}
		}
		if len(literal) < 3 {
			return false
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
		return true // a credentials folder by its name, rooted or not
	}
	if unrooted {
		return false // a relative folder with no working directory is not rooted: it is not the root or the home
	}
	if home = strings.ToLower(path.Clean(home)); strings.HasPrefix(home, "/") {
		return canonical == home || canonical == "/" || strings.HasPrefix(home, canonical+"/")
	}
	return canonical == "/"
}

func remoteOperandCount(operands []string) int {
	count := 0
	for _, operand := range operands {
		if _, remote := remoteOperandHost(operand); remote {
			count++
		}
	}
	return count
}
