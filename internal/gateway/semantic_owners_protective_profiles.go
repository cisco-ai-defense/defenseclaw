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

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

const (
	semanticCloudBulkDataDeleteExpression         = `f.commands.exists(c, c.argv_complete && ((c.program == 'aws' && (('s3' in c.argv && 'rm' in c.argv && '--recursive' in c.argv) || ('s3api' in c.argv && 'delete-objects' in c.argv))) || (c.program == 'gcloud' && 'storage' in c.argv && 'rm' in c.argv && (('--recursive' in c.argv) || ('-r' in c.argv))) || (c.program == 'az' && 'storage' in c.argv && 'delete-batch' in c.argv)))`
	semanticCloudResourceDeleteExpression         = `f.commands.exists(c, c.argv_complete && ((c.program == 'aws' && ('delete' in c.argv || 'delete-bucket' in c.argv || 'delete-db-instance' in c.argv || 'delete-table' in c.argv || 'delete-stack' in c.argv || 'terminate-instances' in c.argv || 'delete-cluster' in c.argv)) || (c.program == 'gcloud' && 'delete' in c.argv) || (c.program == 'az' && 'delete' in c.argv)))`
	semanticCloudObservedResourceDeleteExpression = `f.tool in ['aws.cloudtrail_event', 'azure.activity_event']`
	semanticSQLUnboundedDeleteExpression          = semanticSQLDestructiveMutationExpression
	semanticSQLSchemaDestroyExpression            = semanticSQLUnboundedDeleteExpression
	semanticKubernetesNamespaceDeleteExpression   = `f.commands.exists(c, c.argv_complete && c.program in ['kubectl', 'oc'] && 'delete' in c.argv && (('namespace' in c.argv) || ('namespaces' in c.argv) || ('ns' in c.argv)))`
	semanticKubernetesBulkDeleteExpression        = `f.commands.exists(c, c.argv_complete && c.program in ['kubectl', 'oc'] && 'delete' in c.argv && '--all' in c.argv)`
	semanticIaCFullDestroyExpression              = `f.commands.exists(c, c.argv_complete && c.program in ['terraform', 'tofu', 'pulumi'] && (('destroy' in c.argv) || ('-destroy' in c.argv)))`
)

var semanticProtectiveProfileOwners = map[string]semanticOwner{
	"integrity.kernel_control_bind_override": {
		prerequisite:     actionfacts.ExactPOSIXKernelControlBindOverride,
		suppressFallback: authoritativeSemanticSafeNegative,
		alertOnly:        true,
	},
	"impact.protected_kernel_control_bind_override": {
		prerequisite:     actionfacts.ExactPOSIXKernelControlBindOverride,
		suppressFallback: authoritativeSemanticSafeNegative,
	},
	"impact.cloud_bulk_data_delete": {
		prerequisite:     cloudBulkDataDeletePrerequisite,
		suppressFallback: authoritativeSemanticSafeNegative,
	},
	"impact.cloud_resource_delete": {
		prerequisite:     cloudResourceDeletePrerequisite,
		suppressFallback: authoritativeSemanticSafeNegative,
	},
	"impact.cloud_observed_resource_delete": {
		prerequisite:     cloudObservedResourceDeletePrerequisite,
		suppressFallback: authoritativeSemanticSafeNegative,
		// Provider audit events report completed operations after the fact. Strict
		// and an explicitly assigned protected-cloud pack may surface them, but a
		// post-action observation can never authorize synchronous denial.
		alertOnly: true,
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
	for _, mutation := range actionfacts.ExactCloudResourceMutations(facts) {
		if mutation.Provider == "aws" && mutation.Service == "s3" && mutation.Recursive {
			return true
		}
	}
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
	for _, mutation := range actionfacts.ExactCloudResourceMutations(facts) {
		if mutation.Operation == actionfacts.CloudResourceDeleteDisk ||
			mutation.Operation == actionfacts.CloudResourceDeleteIAMBinding {
			return true
		}
	}
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

func cloudObservedResourceDeletePrerequisite(facts actionfacts.Facts) bool {
	for _, mutation := range actionfacts.ExactCloudResourceMutations(facts) {
		if !mutation.Observed {
			continue
		}
		if mutation.Operation == actionfacts.CloudResourceDeleteDisk ||
			mutation.Operation == actionfacts.CloudResourceDeleteIAMBinding {
			return true
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
	for _, mutation := range actionfacts.ExactSQLMutations(facts) {
		if mutation.Operation == actionfacts.SQLMutationDeleteUnbounded {
			return true
		}
	}
	return false
}

func sqlSchemaDestroyPrerequisite(facts actionfacts.Facts) bool {
	for _, mutation := range actionfacts.ExactSQLMutations(facts) {
		switch mutation.Operation {
		case actionfacts.SQLMutationTruncate, actionfacts.SQLMutationDropSchema,
			actionfacts.SQLMutationDropDatabase:
			return true
		}
	}
	return false
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
