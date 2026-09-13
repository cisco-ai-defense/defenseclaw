// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net/url"
	"sort"
	"strings"
)

const (
	sqlMutationConnectionDigestDomain = "defenseclaw/actionfacts/sql-mutation-connection/v1"
	sqlMutationDatabaseDigestDomain   = "defenseclaw/actionfacts/sql-mutation-database/v1"
	sqlMutationObjectDigestDomain     = "defenseclaw/actionfacts/sql-mutation-object/v1"
)

type exactSQLMutationInput struct {
	engine             string
	query              string
	source             SQLMutationQuerySource
	connectionIdentity string
	databaseIdentity   string
}

// ExactSQLMutations returns validated value-free copies of all exact mutation
// facts for one action. It never returns SQL, connection data, credentials, or
// raw database/object identities.
func ExactSQLMutations(facts Facts) []SQLMutationFact {
	result := make([]SQLMutationFact, 0, len(facts.SQLMutations))
	for _, fact := range facts.SQLMutations {
		if !validSQLMutationFact(fact) {
			return nil
		}
		result = append(result, fact)
	}
	return result
}

func validSQLMutationFact(fact SQLMutationFact) bool {
	if !fact.Exact || !validSQLMutationDigest(fact.ConnectionIdentityDigest) ||
		!validSQLMutationDigest(fact.DatabaseIdentityDigest) ||
		!validSQLMutationDigest(fact.ObjectIdentityDigest) {
		return false
	}
	switch fact.Engine {
	case "postgresql", "mysql", "sqlserver":
	default:
		return false
	}
	switch fact.QuerySource {
	case SQLMutationQueryArgv, SQLMutationQueryLiteralStdin, SQLMutationQueryStructured:
	default:
		return false
	}
	switch fact.Operation {
	case SQLMutationDeleteUnbounded, SQLMutationTruncate:
		return fact.Scope == SQLMutationScopeTable
	case SQLMutationDropSchema:
		return fact.Scope == SQLMutationScopeSchema
	case SQLMutationDropDatabase:
		return fact.Scope == SQLMutationScopeDatabase
	default:
		return false
	}
}

func validSQLMutationDigest(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func projectSQLMutations(input Input, facts Facts) []SQLMutationFact {
	inputs := exactSQLMutationInputs(input, facts)
	mutations := make([]SQLMutationFact, 0, len(inputs))
	for _, candidate := range inputs {
		operation, scope, object, ok := exactSQLMutation(candidate.engine, candidate.query)
		if !ok {
			continue
		}
		connectionDigest := sqlMutationDigest(
			sqlMutationConnectionDigestDomain,
			candidate.engine,
			candidate.connectionIdentity,
		)
		databaseIdentity := candidate.databaseIdentity
		if operation == SQLMutationDropDatabase {
			databaseIdentity = object
		}
		if databaseIdentity == "" {
			databaseIdentity = "implicit"
		}
		fact := SQLMutationFact{
			Engine:                   candidate.engine,
			Operation:                operation,
			Scope:                    scope,
			QuerySource:              candidate.source,
			ConnectionIdentityDigest: connectionDigest,
			DatabaseIdentityDigest: sqlMutationDigest(
				sqlMutationDatabaseDigestDomain,
				candidate.engine,
				databaseIdentity,
			),
			ObjectIdentityDigest: sqlMutationDigest(
				sqlMutationObjectDigestDomain,
				candidate.engine,
				object,
			),
			Exact: true,
		}
		if validSQLMutationFact(fact) {
			mutations = append(mutations, fact)
		}
	}
	return mutations
}

func exactSQLMutationInputs(input Input, facts Facts) []exactSQLMutationInput {
	if connection, database, query, ok := exactSQLQueryInput(input); ok {
		engine, derivedDatabase, ok := exactStructuredSQLMutationTarget(connection, database)
		if !ok {
			return nil
		}
		return []exactSQLMutationInput{{
			engine:             engine,
			query:              query,
			source:             SQLMutationQueryStructured,
			connectionIdentity: connection,
			databaseIdentity:   derivedDatabase,
		}}
	}
	if input.Tool == "sql_query" || !facts.Authoritative() || len(facts.Commands) != 1 {
		return nil
	}
	candidate, ok := exactSQLMutationCommand(facts.Commands[0])
	if !ok {
		return nil
	}
	return []exactSQLMutationInput{candidate}
}

func exactStructuredSQLMutationTarget(connection, database string) (string, string, bool) {
	lower := strings.ToLower(connection)
	engine := ""
	expectedScheme := ""
	for prefix, candidate := range map[string]string{
		"postgres://": "postgresql", "postgresql://": "postgresql",
		"mysql://": "mysql", "mariadb://": "mysql",
		"sqlserver://": "sqlserver", "mssql://": "sqlserver",
	} {
		if strings.HasPrefix(lower, prefix) {
			engine = candidate
			expectedScheme = strings.TrimSuffix(prefix, "://")
			break
		}
	}
	if engine == "" {
		return "", "", false
	}
	parsed, err := url.Parse(connection)
	if err != nil || parsed == nil || parsed.Opaque != "" || parsed.Fragment != "" ||
		strings.ToLower(parsed.Scheme) != expectedScheme || parsed.Hostname() == "" {
		return "", "", false
	}
	pathDatabase, err := url.PathUnescape(strings.TrimPrefix(parsed.EscapedPath(), "/"))
	if err != nil || strings.Contains(pathDatabase, "/") ||
		(pathDatabase != "" && (!exactSQLIdentity(pathDatabase) || unresolvedSQLConnectionIdentity(pathDatabase))) {
		return "", "", false
	}
	if database == "" {
		database = pathDatabase
	} else if !exactSQLIdentity(database) ||
		(pathDatabase != "" && !strings.EqualFold(database, pathDatabase)) {
		return "", "", false
	}
	return engine, strings.ToLower(database), true
}

func exactSQLMutationCommand(command CommandFact) (exactSQLMutationInput, bool) {
	if command.Kind != CommandKindProcess || command.Effect != EffectExecute ||
		command.ControlFlowUncertain || !command.ArgvComplete || len(command.Wrappers) != 0 ||
		len(command.Argv) < 1 {
		return exactSQLMutationInput{}, false
	}
	engine, ok := sqlMutationEngine(command.Program)
	if !ok {
		return exactSQLMutationInput{}, false
	}
	parsed, ok := parseExactSQLCLI(command.Argv, engine)
	if !ok {
		return exactSQLMutationInput{}, false
	}
	query, source := parsed.query, SQLMutationQueryArgv
	if command.LiteralStdinComplete && !command.LiteralStdinAmbiguous {
		if query != "" {
			return exactSQLMutationInput{}, false
		}
		query, source = command.LiteralStdin, SQLMutationQueryLiteralStdin
	}
	if query == "" {
		return exactSQLMutationInput{}, false
	}
	return exactSQLMutationInput{
		engine:             engine,
		query:              query,
		source:             source,
		connectionIdentity: parsed.connectionIdentity(engine),
		databaseIdentity:   strings.ToLower(parsed.database),
	}, true
}

func sqlMutationEngine(program string) (string, bool) {
	switch strings.ToLower(program) {
	case "psql":
		return "postgresql", true
	case "mysql", "mariadb":
		return "mysql", true
	case "sqlcmd":
		return "sqlserver", true
	default:
		return "", false
	}
}

type exactSQLCLI struct {
	query    string
	database string
	options  map[string]string
}

func (parsed exactSQLCLI) connectionIdentity(engine string) string {
	keys := make([]string, 0, len(parsed.options))
	for key := range parsed.options {
		if key != "query" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	parts := []string{engine}
	for _, key := range keys {
		parts = append(parts, key, parsed.options[key])
	}
	if parsed.database != "" {
		parts = append(parts, "database", strings.ToLower(parsed.database))
	} else {
		parts = append(parts, "database", "implicit")
	}
	return strings.Join(parts, "\x00")
}

func parseExactSQLCLI(argv []string, engine string) (exactSQLCLI, bool) {
	parsed := exactSQLCLI{options: make(map[string]string)}
	for index := 1; index < len(argv); index++ {
		argument := argv[index]
		key, value, consumesNext, flag, ok := exactSQLCLIOption(engine, argument)
		if ok {
			if _, duplicate := parsed.options[key]; duplicate {
				return exactSQLCLI{}, false
			}
			if consumesNext {
				if index+1 >= len(argv) || argv[index+1] == "" {
					return exactSQLCLI{}, false
				}
				index++
				value = argv[index]
			}
			if !flag && (!exactSQLScalar(value, maxCommandBytes) || unresolvedSQLMutationValue(value)) {
				return exactSQLCLI{}, false
			}
			parsed.options[key] = value
			if key == "query" {
				parsed.query = value
			}
			if key == "database" {
				parsed.database = value
			}
			continue
		}
		if strings.HasPrefix(argument, "-") || engine == "sqlserver" ||
			!exactSQLIdentity(argument) || parsed.database != "" {
			return exactSQLCLI{}, false
		}
		parsed.database = argument
	}
	if optionDatabase, ok := parsed.options["database"]; ok && parsed.database != optionDatabase {
		return exactSQLCLI{}, false
	}
	return parsed, true
}

func exactSQLCLIOption(engine, argument string) (key, value string, consumesNext, flag, ok bool) {
	type option struct {
		name string
		key  string
		flag bool
	}
	var options []option
	switch engine {
	case "postgresql":
		options = []option{{"-c", "query", false}, {"--command", "query", false}, {"-d", "database", false}, {"--dbname", "database", false}, {"-h", "host", false}, {"--host", "host", false}, {"-p", "port", false}, {"--port", "port", false}, {"-U", "user", false}, {"--username", "user", false}, {"-X", "no_psqlrc", true}, {"--no-psqlrc", "no_psqlrc", true}, {"-w", "no_password", true}, {"--no-password", "no_password", true}}
	case "mysql":
		options = []option{{"-e", "query", false}, {"--execute", "query", false}, {"-D", "database", false}, {"--database", "database", false}, {"-h", "host", false}, {"--host", "host", false}, {"-P", "port", false}, {"--port", "port", false}, {"-u", "user", false}, {"--user", "user", false}, {"--ssl-mode", "ssl_mode", false}, {"-B", "batch", true}, {"--batch", "batch", true}, {"-N", "skip_column_names", true}, {"--skip-column-names", "skip_column_names", true}}
	case "sqlserver":
		options = []option{{"-q", "query", false}, {"-Q", "query", false}, {"-S", "server", false}, {"-d", "database", false}, {"-U", "user", false}, {"-E", "trusted_connection", true}, {"-C", "trust_server_certificate", true}}
	default:
		return "", "", false, false, false
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

func exactSQLMutation(engine, query string) (SQLMutationOperation, SQLMutationScope, string, bool) {
	if query == "" || len(query) > maxCommandBytes || unresolvedSQLMutationValue(query) ||
		strings.ContainsAny(query, "'\"`[]#") || strings.Contains(query, "--") ||
		strings.Contains(query, "/*") || strings.Contains(query, "*/") {
		return "", "", "", false
	}
	statements := make([][]string, 0, 3)
	for _, raw := range strings.Split(query, ";") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if !exactSQLSyntaxCharacters(raw) {
			return "", "", "", false
		}
		statements = append(statements, strings.Fields(strings.ToUpper(raw)))
	}
	if len(statements) == 0 {
		return "", "", "", false
	}
	if isExactSQLBegin(statements[0]) {
		if len(statements) < 3 || len(statements[2]) != 1 {
			return "", "", "", false
		}
		// The transaction body must remain inside the same exact single-mutation
		// grammar even when it is rolled back. This rejects nested, incomplete,
		// and otherwise ambiguous transaction structure before considering a
		// statement after the transaction boundary.
		if _, _, _, ok := exactSQLMutationTokens(engine, statements[1]); !ok {
			return "", "", "", false
		}
		switch statements[2][0] {
		case "COMMIT":
			if len(statements) != 3 {
				return "", "", "", false
			}
			statements = statements[1:2]
		case "ROLLBACK":
			if len(statements) == 3 {
				return "", "", "", false
			}
			if len(statements) != 4 {
				return "", "", "", false
			}
			statements = statements[3:4]
		default:
			return "", "", "", false
		}
	} else if len(statements) != 1 {
		return "", "", "", false
	}
	return exactSQLMutationTokens(engine, statements[0])
}

func exactSQLMutationTokens(engine string, tokens []string) (SQLMutationOperation, SQLMutationScope, string, bool) {
	explainAnalyze := false
	if len(tokens) >= 2 && tokens[0] == "EXPLAIN" {
		// PostgreSQL EXPLAIN ANALYZE executes the wrapped statement. Keep this
		// production exact: no options, aliases, or other engines are inferred,
		// and the remainder must satisfy the existing destructive grammar.
		if engine != "postgresql" || tokens[1] != "ANALYZE" {
			return "", "", "", false
		}
		explainAnalyze = true
		tokens = tokens[2:]
	}
	var operation SQLMutationOperation
	var scope SQLMutationScope
	var object string
	switch {
	case len(tokens) == 3 && tokens[0] == "DELETE" && tokens[1] == "FROM":
		operation, scope, object = SQLMutationDeleteUnbounded, SQLMutationScopeTable, tokens[2]
	case len(tokens) == 2 && tokens[0] == "TRUNCATE":
		operation, scope, object = SQLMutationTruncate, SQLMutationScopeTable, tokens[1]
	case len(tokens) == 3 && tokens[0] == "TRUNCATE" && tokens[1] == "TABLE":
		operation, scope, object = SQLMutationTruncate, SQLMutationScopeTable, tokens[2]
	case len(tokens) >= 3 && tokens[0] == "DROP" && tokens[1] == "SCHEMA":
		operation, scope = SQLMutationDropSchema, SQLMutationScopeSchema
		object = exactSQLDropObject(tokens[2:])
	case len(tokens) >= 3 && tokens[0] == "DROP" && tokens[1] == "DATABASE":
		operation, scope = SQLMutationDropDatabase, SQLMutationScopeDatabase
		object = exactSQLDropObject(tokens[2:])
	default:
		return "", "", "", false
	}
	object = strings.ToLower(object)
	if !exactSQLQualifiedIdentity(object) {
		return "", "", "", false
	}
	// Of the closed destructive operations above, PostgreSQL EXPLAIN accepts
	// DELETE but not TRUNCATE, DROP SCHEMA, or DROP DATABASE. Do not authorize
	// enforcement for a wrapper that the database would reject.
	if explainAnalyze && operation != SQLMutationDeleteUnbounded {
		return "", "", "", false
	}
	return operation, scope, object, true
}

func isExactSQLBegin(tokens []string) bool {
	return len(tokens) == 1 && tokens[0] == "BEGIN" ||
		len(tokens) == 2 && tokens[0] == "START" && tokens[1] == "TRANSACTION"
}

func exactSQLDropObject(tokens []string) string {
	if len(tokens) >= 2 && tokens[0] == "IF" && tokens[1] == "EXISTS" {
		tokens = tokens[2:]
	}
	if len(tokens) == 2 && (tokens[1] == "CASCADE" || tokens[1] == "RESTRICT") {
		tokens = tokens[:1]
	}
	if len(tokens) != 1 {
		return ""
	}
	return tokens[0]
}

func exactSQLSyntaxCharacters(value string) bool {
	for _, character := range value {
		if character == ';' || character == '.' || character == '_' || character == '-' ||
			character == ' ' || character == '\t' || character == '\r' || character == '\n' ||
			character >= '0' && character <= '9' ||
			character >= 'A' && character <= 'Z' ||
			character >= 'a' && character <= 'z' {
			continue
		}
		return false
	}
	return true
}

func exactSQLQualifiedIdentity(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return false
	}
	for _, part := range parts {
		if !exactSQLIdentity(part) {
			return false
		}
	}
	return true
}

func exactSQLIdentity(value string) bool {
	if value == "" || len(value) > 128 || value[0] >= '0' && value[0] <= '9' {
		return false
	}
	for _, character := range value {
		if character != '_' && character != '-' &&
			(character < '0' || character > '9') &&
			(character < 'A' || character > 'Z') &&
			(character < 'a' || character > 'z') {
			return false
		}
	}
	return true
}

func unresolvedSQLMutationValue(value string) bool {
	lower := strings.ToLower(value)
	return strings.ContainsAny(value, "$`\\") || strings.Contains(value, "{{") ||
		strings.Contains(value, "}}") || strings.Contains(value, "#{") ||
		strings.Contains(value, "<%") || strings.Contains(value, "%>") ||
		strings.Contains(lower, "<database") || strings.Contains(lower, "<table") ||
		strings.Contains(lower, "your_database") || strings.Contains(lower, "your_table")
}

func sqlMutationDigest(domain string, values ...string) string {
	hash := sha256.New()
	var length [4]byte
	for _, value := range append([]string{domain}, values...) {
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(value))
	}
	return hex.EncodeToString(hash.Sum(nil))
}
