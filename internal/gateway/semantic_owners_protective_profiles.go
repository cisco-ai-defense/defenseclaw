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

package gateway

import (
	"strings"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

const (
	semanticCloudBulkDataDeleteExpression       = `f.commands.exists(c, c.argv_complete && ((c.program == 'aws' && (('s3' in c.argv && 'rm' in c.argv && '--recursive' in c.argv) || ('s3api' in c.argv && 'delete-objects' in c.argv))) || (c.program == 'gcloud' && 'storage' in c.argv && 'rm' in c.argv && (('--recursive' in c.argv) || ('-r' in c.argv))) || (c.program == 'az' && 'storage' in c.argv && 'delete-batch' in c.argv)))`
	semanticCloudResourceDeleteExpression       = `f.commands.exists(c, c.argv_complete && ((c.program == 'aws' && ('delete' in c.argv || 'delete-bucket' in c.argv || 'delete-db-instance' in c.argv || 'delete-table' in c.argv || 'delete-stack' in c.argv || 'terminate-instances' in c.argv || 'delete-cluster' in c.argv)) || (c.program == 'gcloud' && 'delete' in c.argv) || (c.program == 'az' && 'delete' in c.argv)))`
	semanticSQLUnboundedDeleteExpression        = `f.commands.exists(c, c.argv_complete && c.program in ['psql', 'mysql', 'mariadb', 'sqlcmd', 'snowsql'] && (('-c' in c.argv) || ('-e' in c.argv) || ('-q' in c.argv) || ('-Q' in c.argv) || ('--command' in c.argv) || ('--execute' in c.argv) || ('--query' in c.argv) || c.argv.exists(a, a.startsWith('--command=') || a.startsWith('--execute=') || a.startsWith('--query='))))`
	semanticSQLSchemaDestroyExpression          = semanticSQLUnboundedDeleteExpression
	semanticKubernetesNamespaceDeleteExpression = `f.commands.exists(c, c.argv_complete && c.program in ['kubectl', 'oc'] && 'delete' in c.argv && (('namespace' in c.argv) || ('namespaces' in c.argv) || ('ns' in c.argv)))`
	semanticKubernetesBulkDeleteExpression      = `f.commands.exists(c, c.argv_complete && c.program in ['kubectl', 'oc'] && 'delete' in c.argv && '--all' in c.argv)`
	semanticIaCFullDestroyExpression            = `f.commands.exists(c, c.argv_complete && c.program in ['terraform', 'tofu', 'pulumi'] && (('destroy' in c.argv) || ('-destroy' in c.argv)))`
)

var semanticProtectiveProfileOwners = map[string]semanticOwner{
	"impact.cloud_bulk_data_delete": {
		prerequisite:     cloudBulkDataDeletePrerequisite,
		suppressFallback: authoritativeSemanticSafeNegative,
	},
	"impact.cloud_resource_delete": {
		prerequisite:     cloudResourceDeletePrerequisite,
		suppressFallback: authoritativeSemanticSafeNegative,
	},
	"impact.sql_unbounded_delete": {
		prerequisite:     sqlUnboundedDeletePrerequisite,
		suppressFallback: authoritativeSemanticSafeNegative,
	},
	"impact.sql_schema_destroy": {
		prerequisite:     sqlSchemaDestroyPrerequisite,
		suppressFallback: authoritativeSemanticSafeNegative,
	},
	"impact.kubernetes_namespace_delete": {
		prerequisite:     kubernetesNamespaceDeletePrerequisite,
		suppressFallback: authoritativeSemanticSafeNegative,
	},
	"impact.kubernetes_bulk_delete": {
		prerequisite:     kubernetesBulkDeletePrerequisite,
		suppressFallback: authoritativeSemanticSafeNegative,
	},
	"impact.iac_full_destroy": {
		prerequisite:     infrastructureAsCodeFullDestroyPrerequisite,
		suppressFallback: authoritativeSemanticSafeNegative,
	},
}

func cloudBulkDataDeletePrerequisite(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		if !reconImpactExecutingOwned(command) {
			continue
		}
		argv := lowerArgv(command.Argv)
		switch strings.ToLower(command.Program) {
		case "aws":
			if containsArgvSequence(argv, "s3api", "delete-objects") ||
				(containsArgvSequence(argv, "s3", "rm") &&
					hasAnyArgFold(argv, "--recursive") &&
					hasArgPrefixFold(argv, "s3://")) {
				return true
			}
		case "gcloud":
			if containsArgvSequence(argv, "storage", "rm") &&
				hasAnyArgFold(argv, "--recursive", "-r") &&
				hasArgPrefixFold(argv, "gs://") {
				return true
			}
		case "az":
			if containsArgvSequence(argv, "storage", "blob", "delete-batch") {
				return true
			}
		}
	}
	return false
}

func cloudResourceDeletePrerequisite(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		if !reconImpactExecutingOwned(command) {
			continue
		}
		argv := lowerArgv(command.Argv)
		var operations [][]string
		switch strings.ToLower(command.Program) {
		case "aws":
			operations = [][]string{
				{"s3api", "delete-bucket"},
				{"rds", "delete-db-instance"},
				{"dynamodb", "delete-table"},
				{"cloudformation", "delete-stack"},
				{"ec2", "terminate-instances"},
				{"eks", "delete-cluster"},
			}
		case "gcloud":
			operations = [][]string{
				{"projects", "delete"},
				{"sql", "instances", "delete"},
				{"compute", "instances", "delete"},
				{"container", "clusters", "delete"},
				{"spanner", "instances", "delete"},
			}
		case "az":
			operations = [][]string{
				{"group", "delete"},
				{"storage", "account", "delete"},
				{"storage", "container", "delete"},
				{"sql", "server", "delete"},
				{"sql", "db", "delete"},
				{"postgres", "flexible-server", "delete"},
				{"mysql", "flexible-server", "delete"},
				{"vm", "delete"},
				{"aks", "delete"},
			}
		default:
			continue
		}
		for _, operation := range operations {
			if containsArgvSequence(argv, operation...) {
				return true
			}
		}
	}
	return false
}

func hasAnyArgFold(argv []string, values ...string) bool {
	for _, argument := range argv {
		for _, value := range values {
			if strings.EqualFold(argument, value) {
				return true
			}
		}
	}
	return false
}

func hasArgPrefixFold(argv []string, prefix string) bool {
	prefix = strings.ToLower(prefix)
	for _, argument := range argv {
		if strings.HasPrefix(strings.ToLower(argument), prefix) {
			return true
		}
	}
	return false
}

func sqlUnboundedDeletePrerequisite(facts actionfacts.Facts) bool {
	return sqlMutationPrerequisite(facts, sqlMutationUnboundedDelete)
}

func sqlSchemaDestroyPrerequisite(facts actionfacts.Facts) bool {
	return sqlMutationPrerequisite(facts, sqlMutationSchemaDestroy)
}

func kubernetesNamespaceDeletePrerequisite(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		resource, targets, _, ok := staticKubernetesDelete(command)
		if ok && hasAnyArgFold([]string{resource}, "namespace", "namespaces", "ns") &&
			len(targets) != 0 {
			return true
		}
	}
	return false
}

func kubernetesBulkDeletePrerequisite(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		resource, _, all, ok := staticKubernetesDelete(command)
		if !ok || !all {
			continue
		}
		if hasAnyArgFold(
			[]string{resource},
			"all", "pod", "pods", "deployment", "deployments",
			"statefulset", "statefulsets", "daemonset", "daemonsets",
			"job", "jobs", "cronjob", "cronjobs", "service", "services",
		) {
			return true
		}
	}
	return false
}

func staticKubernetesDelete(command actionfacts.CommandFact) (string, []string, bool, bool) {
	if !reconImpactExecutingOwned(command) ||
		!oneOfFold(command.Program, "kubectl", "oc") ||
		!hasOperation(command, actionfacts.OperationDelete) {
		return "", nil, false, false
	}
	deleteIndex := workloadSubcommandIndex(command.Argv)
	if deleteIndex < 0 {
		return "", nil, false, false
	}
	valueOptions := map[string]bool{
		"-n": true, "--namespace": true, "--context": true,
		"--kubeconfig": true, "-f": true, "--filename": true,
		"-l": true, "--selector": true, "--field-selector": true,
		"--grace-period": true, "--timeout": true, "--cascade": true,
		"--dry-run": true, "-o": true, "--output": true,
	}
	all := false
	var positionals []string
	for index := deleteIndex + 1; index < len(command.Argv); index++ {
		argument := command.Argv[index]
		if argument == "--all" {
			all = true
			continue
		}
		key, value, joined := strings.Cut(argument, "=")
		if valueOptions[key] {
			if !joined {
				index++
				if index >= len(command.Argv) {
					return "", nil, false, false
				}
				value = command.Argv[index]
			}
			if key == "--dry-run" && !strings.EqualFold(value, "none") {
				return "", nil, false, false
			}
			continue
		}
		if strings.HasPrefix(argument, "-") {
			continue
		}
		if !staticProtectiveOperand(argument) {
			return "", nil, false, false
		}
		positionals = append(positionals, argument)
	}
	if len(positionals) == 0 {
		return "", nil, false, false
	}
	return positionals[0], positionals[1:], all, true
}

func workloadSubcommandIndex(argv []string) int {
	globalValues := map[string]bool{
		"--as": true, "--as-group": true, "--cache-dir": true,
		"--certificate-authority": true, "--client-certificate": true,
		"--client-key": true, "--cluster": true, "--context": true,
		"--kubeconfig": true, "--kuberc": true, "-n": true,
		"--namespace": true, "--profile": true, "--profile-output": true,
		"--proxy-url": true, "--request-timeout": true, "-s": true,
		"--server": true, "--tls-server-name": true, "--token": true,
		"--user": true, "-v": true, "--vmodule": true,
	}
	for index := 1; index < len(argv); index++ {
		argument := argv[index]
		if argument == "--" {
			index++
			if index < len(argv) && strings.EqualFold(argv[index], "delete") {
				return index
			}
			return -1
		}
		if argument == "-" || !strings.HasPrefix(argument, "-") {
			if strings.EqualFold(argument, "delete") {
				return index
			}
			return -1
		}
		key, _, joined := strings.Cut(argument, "=")
		if globalValues[key] && !joined {
			index++
			if index >= len(argv) {
				return -1
			}
		}
	}
	return -1
}

func infrastructureAsCodeFullDestroyPrerequisite(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		if !reconImpactExecutingOwned(command) ||
			!hasOperation(command, actionfacts.OperationDelete) ||
			!oneOfFold(command.Program, "terraform", "tofu", "pulumi") {
			continue
		}
		targeted := false
		for index, argument := range command.Argv {
			lowered := strings.ToLower(argument)
			if strings.HasPrefix(lowered, "-target=") ||
				strings.HasPrefix(lowered, "--target=") ||
				(lowered == "--target" && index+1 < len(command.Argv)) {
				targeted = true
				break
			}
		}
		if !targeted {
			return true
		}
	}
	return false
}

func staticProtectiveOperand(value string) bool {
	return value != "" &&
		!strings.ContainsAny(value, "$`\r\n") &&
		!strings.Contains(value, "$(") &&
		!strings.Contains(value, "${")
}

type sqlMutationKind uint8

const (
	sqlMutationUnboundedDelete sqlMutationKind = iota + 1
	sqlMutationSchemaDestroy
)

func sqlMutationPrerequisite(facts actionfacts.Facts, wanted sqlMutationKind) bool {
	for _, command := range facts.Commands {
		if !reconImpactExecutingOwned(command) {
			continue
		}
		queries, determinate := staticSQLQueries(command)
		if !determinate {
			continue
		}
		for _, query := range queries {
			mutations, ok := classifyStaticSQLMutations(query)
			if !ok {
				continue
			}
			for _, mutation := range mutations {
				if mutation == wanted {
					return true
				}
			}
		}
	}
	return false
}

func staticSQLQueries(command actionfacts.CommandFact) ([]string, bool) {
	program := strings.ToLower(command.Program)
	var shortOptions, longOptions []string
	switch program {
	case "psql":
		shortOptions, longOptions = []string{"-c"}, []string{"--command"}
	case "mysql", "mariadb":
		shortOptions, longOptions = []string{"-e"}, []string{"--execute"}
	case "sqlcmd":
		shortOptions = []string{"-q", "-Q"}
	case "snowsql":
		shortOptions, longOptions = []string{"-q"}, []string{"--query"}
	default:
		return nil, false
	}

	var queries []string
	for index := 1; index < len(command.Argv); index++ {
		argument := command.Argv[index]
		matched := false
		for _, option := range shortOptions {
			if argument == option {
				if index+1 >= len(command.Argv) || command.Argv[index+1] == "" {
					return nil, false
				}
				queries = append(queries, command.Argv[index+1])
				index++
				matched = true
				break
			}
		}
		if matched {
			continue
		}
		for _, option := range longOptions {
			prefix := option + "="
			if strings.HasPrefix(argument, prefix) {
				query := argument[len(prefix):]
				if query == "" {
					return nil, false
				}
				queries = append(queries, query)
				matched = true
				break
			}
			if argument == option {
				if index+1 >= len(command.Argv) || command.Argv[index+1] == "" {
					return nil, false
				}
				queries = append(queries, command.Argv[index+1])
				index++
				matched = true
				break
			}
		}
	}
	return queries, len(queries) != 0
}

func classifyStaticSQLMutations(query string) ([]sqlMutationKind, bool) {
	sanitized, ok := stripSQLLiteralsAndComments(query)
	if !ok {
		return nil, false
	}
	var mutations []sqlMutationKind
	var pending []sqlMutationKind
	inTransaction := false
	for _, statement := range strings.Split(sanitized, ";") {
		tokens := sqlKeywordTokens(statement)
		if len(tokens) == 0 {
			continue
		}
		if tokens[0] == "BEGIN" ||
			(len(tokens) > 1 && tokens[0] == "START" && tokens[1] == "TRANSACTION") {
			if inTransaction {
				return nil, false
			}
			inTransaction = true
			pending = nil
			continue
		}
		if tokens[0] == "ROLLBACK" {
			if inTransaction {
				inTransaction = false
				pending = nil
			}
			continue
		}
		if tokens[0] == "COMMIT" {
			if inTransaction {
				inTransaction = false
				mutations = append(mutations, pending...)
				pending = nil
			}
			continue
		}
		statementMutations := classifyStaticSQLStatement(tokens)
		if inTransaction {
			pending = append(pending, statementMutations...)
		} else {
			mutations = append(mutations, statementMutations...)
		}
	}
	if inTransaction {
		return nil, false
	}
	return mutations, true
}

func classifyStaticSQLStatement(tokens []string) []sqlMutationKind {
	var mutations []sqlMutationKind
	if len(tokens) == 0 {
		return nil
	}
	if tokens[0] == "DROP" && len(tokens) > 1 &&
		(tokens[1] == "DATABASE" || tokens[1] == "SCHEMA") {
		return []sqlMutationKind{sqlMutationSchemaDestroy}
	}
	if tokens[0] == "TRUNCATE" {
		return []sqlMutationKind{sqlMutationSchemaDestroy}
	}
	deleteIndex := -1
	for index, token := range tokens {
		if token == "DELETE" && index+1 < len(tokens) && tokens[index+1] == "FROM" {
			deleteIndex = index
			break
		}
	}
	if deleteIndex < 0 {
		return nil
	}
	if tokens[0] == "EXPLAIN" && !containsSQLToken(tokens[:deleteIndex], "ANALYZE") {
		return nil
	}
	if !containsSQLToken(tokens[deleteIndex+2:], "WHERE") {
		mutations = append(mutations, sqlMutationUnboundedDelete)
	}
	return mutations
}

func containsSQLToken(tokens []string, expected string) bool {
	for _, token := range tokens {
		if token == expected {
			return true
		}
	}
	return false
}

func sqlKeywordTokens(statement string) []string {
	return strings.FieldsFunc(strings.ToUpper(statement), func(r rune) bool {
		return !unicode.IsLetter(r) && r != '_'
	})
}

// stripSQLLiteralsAndComments keeps only executable SQL syntax. Quoted values,
// quoted identifiers, and comments are replaced with spaces so examples such
// as SELECT 'DELETE FROM users' never become policy evidence. Unterminated or
// nested constructs are indeterminate and therefore cannot authorize a block.
func stripSQLLiteralsAndComments(query string) (string, bool) {
	var out strings.Builder
	for index := 0; index < len(query); {
		switch {
		case query[index] == '\'':
			index++
			closed := false
			for index < len(query) {
				if query[index] != '\'' {
					index++
					continue
				}
				if index+1 < len(query) && query[index+1] == '\'' {
					index += 2
					continue
				}
				index++
				closed = true
				break
			}
			if !closed {
				return "", false
			}
			out.WriteByte(' ')
		case query[index] == '"' || query[index] == '`':
			quote := query[index]
			index++
			closed := false
			for index < len(query) {
				if query[index] != quote {
					index++
					continue
				}
				if index+1 < len(query) && query[index+1] == quote {
					index += 2
					continue
				}
				index++
				closed = true
				break
			}
			if !closed {
				return "", false
			}
			out.WriteByte(' ')
		case query[index] == '[':
			end := strings.IndexByte(query[index+1:], ']')
			if end < 0 {
				return "", false
			}
			index += end + 2
			out.WriteByte(' ')
		case index+1 < len(query) && query[index:index+2] == "--":
			index += 2
			for index < len(query) && query[index] != '\n' && query[index] != '\r' {
				index++
			}
			out.WriteByte(' ')
		case index+1 < len(query) && query[index:index+2] == "/*":
			end := strings.Index(query[index+2:], "*/")
			if end < 0 || strings.Contains(query[index+2:index+2+end], "/*") {
				return "", false
			}
			index += end + 4
			out.WriteByte(' ')
		case query[index] == '$':
			end := strings.IndexByte(query[index+1:], '$')
			if end < 0 {
				out.WriteByte(query[index])
				index++
				continue
			}
			tagEnd := index + end + 2
			tag := query[index:tagEnd]
			validTag := true
			for _, r := range tag[1 : len(tag)-1] {
				if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' {
					validTag = false
					break
				}
			}
			if !validTag {
				out.WriteByte(query[index])
				index++
				continue
			}
			closeOffset := strings.Index(query[tagEnd:], tag)
			if closeOffset < 0 {
				return "", false
			}
			index = tagEnd + closeOffset + len(tag)
			out.WriteByte(' ')
		default:
			out.WriteByte(query[index])
			index++
		}
	}
	return out.String(), true
}
