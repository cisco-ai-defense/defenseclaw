// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const maliciousPersistenceDownloadExecuteClass = "download_execute"

var (
	persistencePowerShellDownloadString = regexp.MustCompile(`(?is)\bpowershell(?:\.exe)?\b.{0,500}\b(?:iex|invoke-expression)\b.{0,500}\b(?:new-object\s+)?net\.webclient\b.{0,160}\.downloadstring\s*\(\s*(?:["'](https?://[^\s"'()]{1,1000})["']|[\\]{1,2}["'](https?://[^\s"'()]{1,1000})[\\]{1,2}["'])\s*\)`)
	persistencePOSIXDownloadPipe        = regexp.MustCompile(`(?is)^\s*(?:/(?:usr/)?bin/(?:sh|bash)\s+-c\s+["'])?(?:while\s+true\s*;\s*do\s+)?(?:/(?:usr/)?bin/)?(?:curl|wget)\b(?:\s+-[A-Za-z][A-Za-z0-9-]*(?:=[^\s|;"']+)?)*\s+["']?(https?://[^\s|;"']{1,1000})["']?\s*\|\s*(?:/(?:usr/)?bin/)?(?:sh|bash)\b(?:\s+-[A-Za-z0-9-]+)*(?:\s*;\s*sleep\s+[0-9]{1,8}\s*;\s*done)?["']?\s*$`)
	persistenceCronEntry                = regexp.MustCompile(`^\s*(?:@(?:reboot|hourly|daily|weekly|monthly)|(?:\S+\s+){4}\S+)\s+(.+)$`)
	persistenceSystemdExecStart         = regexp.MustCompile(`(?m)^\s*ExecStart\s*=\s*(\S[^\r\n]*)$`)
	persistencePAMExec                  = regexp.MustCompile(`(?i)^\s*(?:auth|account|password|session)\s+(?:required|requisite|sufficient|optional)\s+pam_exec\.so(?:\s+(?:debug|expose_authtok|seteuid|quiet|log=\S+))*\s+(.+?)\s*$`)
	persistenceLiteralShellCommand      = regexp.MustCompile(`^/bin/(?:sh|bash)[ \t]+-c[ \t]+(['"])([^'"\\\r\n]{1,1000})(['"])$`)
	persistencePowerShellSourceText     = regexp.MustCompile(`(?is)\b(?:write-output|write-host|set-content|add-content|out-file)\b.{0,400}\b(?:invoke-webrequest|downloadstring)\b`)
	persistenceWindowsPath              = regexp.MustCompile(`(?i)^[A-Z]:\\[A-Za-z0-9_.()\\ -]{1,500}$`)
	persistenceIWR                      = regexp.MustCompile(`(?i)\bInvoke-WebRequest\b`)
	persistenceOutFile                  = regexp.MustCompile(`(?i)\s-OutFile\b`)
)

// ExactMaliciousPersistencePayload reports one value-free closed proof.
func ExactMaliciousPersistencePayload(facts Facts) bool {
	return len(facts.MaliciousPersistencePayloads) == 1 &&
		facts.MaliciousPersistencePayloads[0].Class == maliciousPersistenceDownloadExecuteClass
}

func projectMaliciousPersistencePayloads(input Input) []MaliciousPersistencePayloadFact {
	if input.Tool != "persist" || input.Command != "" || len(input.Argv) != 0 {
		return nil
	}
	object, ok := exactStagedPayloadObject(input.Args)
	if !ok || len(object) != 2 {
		return nil
	}
	method, methodOK := object["method"].(string)
	payload, payloadOK := object["payload"].(string)
	if !methodOK || !payloadOK || payload == "" || len(payload) > stagedPayloadMaxScriptBytes ||
		strings.TrimSpace(payload) != payload {
		return nil
	}
	if exactPersistencePOSIXDownloadExecute(method, payload) ||
		exactPersistenceBashTCPReverseShell(method, payload) ||
		exactPAMPersistenceReverseShell(method, payload) ||
		exactPersistencePowerShellDownloadExecute(method, payload) {
		return []MaliciousPersistencePayloadFact{{Class: maliciousPersistenceDownloadExecuteClass}}
	}
	return nil
}

// exactPersistenceBashTCPReverseShell proves that a closed persist invocation
// installs one literal interactive Bash /dev/tcp reverse shell. Cron and
// systemd payload extraction remain owned by their existing closed grammars;
// the executable command is then checked by the same parser-backed proof used
// for staged payloads and Kubernetes CronJobs.
func exactPersistenceBashTCPReverseShell(method, payload string) bool {
	if payload == "" || len(payload) > stagedPayloadMaxScriptBytes ||
		strings.TrimSpace(payload) != payload {
		return false
	}

	var command string
	var ok bool
	switch method {
	case "cron":
		command, ok = exactPersistenceCronCommand(payload)
	case "systemd":
		command, ok = exactPersistenceSystemdCommand(payload)
	default:
		return false
	}
	if !ok || command == "" || strings.TrimSpace(command) != command {
		return false
	}
	if exactPersistenceLiteralBashTCPReverseShell(command) {
		return true
	}

	// Accept one exact literal shell boundary needed by common cron/systemd
	// forms. The existing matcher rejects nested quotes, escapes, newlines,
	// mismatched delimiters, environment wrappers, and additional commands.
	wrapped := persistenceLiteralShellCommand.FindStringSubmatch(command)
	return len(wrapped) == 4 && wrapped[1] == wrapped[3] &&
		exactPersistenceLiteralBashTCPReverseShell(wrapped[2])
}

func exactPersistenceLiteralBashTCPReverseShell(command string) bool {
	if !exactAuthoritativePOSIXReverseShellCommand(command) {
		return false
	}
	const suffix = " 0>&1"
	var endpoint string
	for _, prefix := range []string{
		"bash -i >& /dev/tcp/",
		"/bin/bash -i >& /dev/tcp/",
	} {
		if strings.HasPrefix(command, prefix) && strings.HasSuffix(command, suffix) {
			endpoint = strings.TrimSuffix(strings.TrimPrefix(command, prefix), suffix)
			break
		}
	}
	host, port, ok := strings.Cut(endpoint, "/")
	if !ok || host == "" || port == "" || strings.Contains(port, "/") {
		return false
	}
	normalized, scope, kind, _ := deriveNetworkTarget(host)
	if normalized == "" || kind != NetworkTargetSingleHost ||
		scope == NetworkScopeLoopback || scope == NetworkScopeLinkLocal {
		return false
	}
	lowerHost := strings.ToLower(strings.TrimSuffix(normalized, "."))
	return lowerHost != "localhost" && !strings.HasSuffix(lowerHost, ".localhost") &&
		!strings.HasSuffix(lowerHost, ".local")
}

func exactPAMPersistenceReverseShell(method, payload string) bool {
	if method != "pam_module" || strings.ContainsAny(payload, "\r\n") {
		return false
	}
	pam := persistencePAMExec.FindStringSubmatch(payload)
	if len(pam) != 2 {
		return false
	}
	wrapped := persistenceLiteralShellCommand.FindStringSubmatch(pam[1])
	if len(wrapped) != 4 || wrapped[1] != wrapped[3] {
		return false
	}
	command := strings.Fields(wrapped[2])
	if len(command) != 5 || !exactPersistenceNetcatProgram(command[0]) {
		return false
	}

	var host, port, shell string
	if command[1] == "-e" {
		shell, host, port = command[2], command[3], command[4]
	} else if command[3] == "-e" {
		host, port, shell = command[1], command[2], command[4]
	} else {
		return false
	}
	if shell != "/bin/sh" && shell != "/bin/bash" {
		return false
	}
	parsedPort, err := strconv.Atoi(port)
	if err != nil || parsedPort < 1 || parsedPort > 65535 {
		return false
	}
	if strings.ContainsAny(host, "$`{}[]*?;|&<>()\\\"'") {
		return false
	}
	normalized, scope, kind, _ := deriveNetworkTarget(host)
	if normalized == "" || kind != NetworkTargetSingleHost ||
		scope == NetworkScopeLoopback || scope == NetworkScopeLinkLocal {
		return false
	}
	lowerHost := strings.ToLower(strings.TrimSuffix(normalized, "."))
	if lowerHost == "localhost" || strings.HasSuffix(lowerHost, ".localhost") ||
		strings.HasSuffix(lowerHost, ".local") {
		return false
	}
	if address, err := netip.ParseAddr(normalized); err == nil && address.IsUnspecified() {
		return false
	}
	return true
}

func exactPersistenceNetcatProgram(program string) bool {
	switch program {
	case "nc", "netcat", "/bin/nc", "/usr/bin/nc", "/bin/netcat", "/usr/bin/netcat":
		return true
	default:
		return false
	}
}

func exactPersistencePOSIXDownloadExecute(method, payload string) bool {
	var command string
	switch method {
	case "cron":
		if strings.ContainsAny(payload, "\r\n") {
			return false
		}
		match := persistenceCronEntry.FindStringSubmatch(payload)
		if len(match) != 2 {
			return false
		}
		command = match[1]
	case "systemd":
		matches := persistenceSystemdExecStart.FindAllStringSubmatch(payload, -1)
		if len(matches) != 1 {
			return false
		}
		command = matches[0][1]
	case "pam_module":
		if strings.ContainsAny(payload, "\r\n") {
			return false
		}
		match := persistencePAMExec.FindStringSubmatch(payload)
		if len(match) != 2 {
			return false
		}
		command = match[1]
	default:
		return false
	}
	match := persistencePOSIXDownloadPipe.FindStringSubmatch(command)
	return len(match) == 2 && literalExternalHTTPURL(match[1])
}

func exactPersistencePowerShellDownloadExecute(method, payload string) bool {
	switch method {
	case "registry_run", "scheduled_task", "wmi_subscription":
	default:
		return false
	}
	if persistencePowerShellSourceText.MatchString(payload) {
		return false
	}
	if match := persistencePowerShellDownloadString.FindStringSubmatch(payload); len(match) == 3 {
		for _, target := range match[1:] {
			if target != "" && literalExternalHTTPURL(target) {
				return true
			}
		}
	}
	return method == "scheduled_task" && exactPersistencePowerShellIWRStage(payload)
}

func exactPersistencePowerShellIWRStage(payload string) bool {
	powerShell := regexp.MustCompile(`(?i)\bpowershell(?:\.exe)?\b`).FindStringIndex(payload)
	iwr := persistenceIWR.FindStringIndex(payload)
	if powerShell == nil || iwr == nil || powerShell[0] > iwr[0] {
		return false
	}
	remainder := strings.TrimSpace(payload[iwr[1]:])
	if strings.HasPrefix(strings.ToLower(remainder), "-uri") {
		remainder = strings.TrimSpace(remainder[len("-uri"):])
	}
	target, remainder, ok := persistenceLiteralToken(remainder)
	if !ok || !literalExternalHTTPURL(target) {
		return false
	}
	outFile := persistenceOutFile.FindStringIndex(remainder)
	if outFile == nil || outFile[0] > 500 {
		return false
	}
	stagedPath, suffix, ok := persistenceLiteralToken(strings.TrimSpace(remainder[outFile[1]:]))
	if !ok || !persistenceWindowsPath.MatchString(stagedPath) {
		return false
	}
	quotedPath := regexp.QuoteMeta(stagedPath)
	boundary := `(?:["']|\s|$)`
	for _, expression := range []string{
		`(?is)^\s*;\s*["']?\s*Start-Process\s+powershell(?:\.exe)?\b.{0,300}?(?:\s|["'])-File\s+["']?` + quotedPath + boundary,
		`(?is)^\s*;\s*["']?\s*Start-Process\s+["']?` + quotedPath + boundary,
		`(?is)^\s*;\s*["']?\s*powershell(?:\.exe)?\b.{0,300}?\s-File\s+["']?` + quotedPath + boundary,
		`(?is)^\s*;\s*["']?\s*(?:&\s*)?["']?` + quotedPath + boundary,
	} {
		if regexp.MustCompile(expression).MatchString(suffix) {
			return true
		}
	}
	return false
}

func persistenceLiteralToken(value string) (string, string, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", "", false
	}
	if value[0] == '\'' || value[0] == '"' {
		quote := value[0]
		end := strings.IndexByte(value[1:], quote)
		if end < 0 {
			return "", "", false
		}
		end++
		if end == 1 {
			return "", "", false
		}
		return value[1:end], value[end+1:], true
	}
	end := strings.IndexAny(value, " \t\r\n;")
	if end < 0 {
		return value, "", true
	}
	if end == 0 {
		return "", "", false
	}
	return value[:end], value[end:], true
}

func literalExternalHTTPURL(value string) bool {
	if !validLiteralRequestTarget(value) || strings.ContainsAny(value, "$`{}") {
		return false
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") ||
		parsed.Host == "" || parsed.User != nil {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") ||
		strings.HasSuffix(host, ".local") {
		return false
	}
	_, scope, kind, _ := deriveNetworkTarget(host)
	if kind != NetworkTargetSingleHost || scope == NetworkScopeLoopback ||
		scope == NetworkScopeLinkLocal {
		return false
	}
	return true
}
