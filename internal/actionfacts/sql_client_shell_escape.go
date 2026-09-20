// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "strings"

// ExactSQLClientShellEscapes returns validated value-free copies of exact SQL
// client shell escapes. Any malformed private fact makes the projection fail
// closed rather than exposing a partially trusted set.
func ExactSQLClientShellEscapes(facts Facts) []SQLClientShellEscapeFact {
	if !facts.Authoritative() {
		return nil
	}
	result := make([]SQLClientShellEscapeFact, 0, len(facts.SQLClientShellEscapes))
	for _, fact := range facts.SQLClientShellEscapes {
		if !validSQLClientShellEscapeFact(facts, fact) {
			return nil
		}
		result = append(result, fact)
	}
	return result
}

func validSQLClientShellEscapeFact(facts Facts, fact SQLClientShellEscapeFact) bool {
	if fact.CommandID <= 0 || !fact.Exact || !validSQLClientShellEscapeClient(fact.Client) {
		return false
	}
	for _, command := range facts.Commands {
		if command.ID != fact.CommandID {
			continue
		}
		client, ok := exactSQLClientShellEscape(command)
		return ok && client == fact.Client && exactUnconditionalTopLevelCommand(command)
	}
	return false
}

func validSQLClientShellEscapeClient(client SQLClientShellEscapeClient) bool {
	switch client {
	case SQLClientShellEscapeSQLite, SQLClientShellEscapeMySQL:
		return true
	default:
		return false
	}
}

func projectSQLClientShellEscapes(facts Facts) []SQLClientShellEscapeFact {
	if !facts.Authoritative() || len(facts.Commands) != 1 {
		return nil
	}
	command := facts.Commands[0]
	if !exactUnconditionalTopLevelCommand(command) || !command.ArgvComplete ||
		(command.Dialect != DialectPOSIX && command.Dialect != DialectArgv) ||
		!staticArguments(command.Arguments) {
		return nil
	}
	client, ok := exactSQLClientShellEscape(command)
	if !ok {
		return nil
	}
	return []SQLClientShellEscapeFact{{
		CommandID: command.ID,
		Client:    client,
		Exact:     true,
	}}
}

func exactSQLClientShellEscape(command CommandFact) (SQLClientShellEscapeClient, bool) {
	switch command.Program {
	case "sqlite3":
		if !exactCaseSensitivePOSIXProgram(&command, "sqlite3") ||
			!exactSQLiteShellEscapeArgv(command.Argv) {
			return "", false
		}
		return SQLClientShellEscapeSQLite, true
	case "mysql", "mariadb":
		if !exactCaseSensitivePOSIXProgram(&command, command.Program) ||
			!exactMySQLShellEscapeArgv(command.Argv) {
			return "", false
		}
		return SQLClientShellEscapeMySQL, true
	default:
		return "", false
	}
}

func exactSQLiteShellEscapeArgv(argv []string) bool {
	if len(argv) != 2 && len(argv) != 3 {
		return false
	}
	metaIndex := 1
	if len(argv) == 3 {
		database := argv[1]
		if database == "" || strings.HasPrefix(database, "-") {
			return false
		}
		metaIndex = 2
	}
	return exactReviewedSQLClientShell(argv[metaIndex], ".shell")
}

func exactMySQLShellEscapeArgv(argv []string) bool {
	query := ""
	databaseSeen := false
	seen := make(map[string]struct{})
	for index := 1; index < len(argv); index++ {
		argument := argv[index]
		key, value, consumesNext, flag, ok := exactMySQLShellEscapeOption(argument)
		if ok {
			if _, duplicate := seen[key]; duplicate {
				return false
			}
			seen[key] = struct{}{}
			if consumesNext {
				if index+1 >= len(argv) || argv[index+1] == "" {
					return false
				}
				index++
				value = argv[index]
			}
			if !flag && key != "query" &&
				(!exactSQLScalar(value, maxCommandBytes) || unresolvedSQLMutationValue(value)) {
				return false
			}
			if key == "query" {
				query = value
			}
			if key == "database" {
				if databaseSeen {
					return false
				}
				databaseSeen = true
			}
			continue
		}
		if strings.HasPrefix(argument, "-") || databaseSeen ||
			!exactSQLIdentity(argument) {
			return false
		}
		databaseSeen = true
	}
	return exactReviewedSQLClientShell(query, `\!`)
}

func exactMySQLShellEscapeOption(argument string) (key, value string, consumesNext, flag, ok bool) {
	if strings.HasPrefix(argument, "-p") && len(argument) > len("-p") {
		value := strings.TrimPrefix(argument, "-p")
		if exactSQLScalar(value, maxCommandBytes) && !unresolvedSQLMutationValue(value) {
			return "password", value, false, false, true
		}
		return "", "", false, false, false
	}
	type option struct {
		name string
		key  string
		flag bool
	}
	options := []option{
		{"-e", "query", false}, {"--execute", "query", false},
		{"-D", "database", false}, {"--database", "database", false},
		{"-h", "host", false}, {"--host", "host", false},
		{"-P", "port", false}, {"--port", "port", false},
		{"-u", "user", false}, {"--user", "user", false},
		{"--password", "password", false},
		{"--protocol", "protocol", false}, {"--socket", "socket", false},
		{"--ssl-mode", "ssl_mode", false},
		{"-B", "batch", true}, {"--batch", "batch", true},
		{"-N", "skip_column_names", true}, {"--skip-column-names", "skip_column_names", true},
	}
	for _, candidate := range options {
		if argument == candidate.name {
			return candidate.key, "true", !candidate.flag, candidate.flag, true
		}
		if strings.HasPrefix(candidate.name, "--") && !candidate.flag &&
			strings.HasPrefix(argument, candidate.name+"=") {
			value = strings.TrimPrefix(argument, candidate.name+"=")
			if value == "" {
				return "", "", false, false, false
			}
			return candidate.key, value, false, false, true
		}
	}
	return "", "", false, false, false
}

func exactReviewedSQLClientShell(value, prefix string) bool {
	switch value {
	case prefix + " /bin/sh", prefix + " /bin/bash":
		return true
	default:
		return false
	}
}
