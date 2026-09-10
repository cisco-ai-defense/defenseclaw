// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semantic"
)

func TestEmailPIIContextSeparatesRecordsFromOperationalAddresses(t *testing.T) {
	tests := []struct {
		name  string
		text  string
		email string
		want  bool
	}{
		{"customer record", "Customer Email: lindsey51@example.net", "lindsey51@example.net", true},
		{"contact record", "For questions, contact odiaz@example.net.", "odiaz@example.net", true},
		{"structured record", `{"email":"ajohnson@example.org"}`, "ajohnson@example.org", true},
		{"ssh login", `Log into "ubuntu@ec2-10-0-0-1.compute.amazonaws.com" using a key`, "ubuntu@ec2-10-0-0-1.compute.amazonaws.com", false},
		{"scp locator", `Copy files to "user@remote.machine:/tmp/newdir"`, "user@remote.machine", false},
		{"git ssh host alias", `git clone git@github.com-cisco-aispg:cisco-aispg/augur-dsl.git`, "git@github.com", false},
		{"numeric remote host", `Copy from "pi@192.168.1.PI"`, "pi@192.168.1.PI", false},
		{"email command", `Send email with attachment to "backup@email.com"`, "backup@email.com", false},
		{"literal search", `Find files containing string literal 'spammer@spammy.com'`, "spammer@spammy.com", false},
		{"schema example", `A common format is {"email":"user@example.com"}`, "user@example.com", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			start := strings.Index(test.text, test.email)
			if start < 0 {
				t.Fatal("test email is absent")
			}
			if got := credibleEmailContext(test.text, test.email, start, start+len(test.email)); got != test.want {
				t.Fatalf("credibleEmailContext()=%t, want %t", got, test.want)
			}
		})
	}
}

func TestProtectiveProfileExpressionsCompile(t *testing.T) {
	t.Parallel()
	compiler, err := semantic.NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	for ruleID, expression := range map[string]string{
		"impact.cloud_bulk_data_delete":      semanticCloudBulkDataDeleteExpression,
		"impact.cloud_resource_delete":       semanticCloudResourceDeleteExpression,
		"impact.sql_unbounded_delete":        semanticSQLUnboundedDeleteExpression,
		"impact.sql_schema_destroy":          semanticSQLSchemaDestroyExpression,
		"impact.kubernetes_namespace_delete": semanticKubernetesNamespaceDeleteExpression,
		"impact.kubernetes_bulk_delete":      semanticKubernetesBulkDeleteExpression,
		"impact.iac_full_destroy":            semanticIaCFullDestroyExpression,
	} {
		if _, code := compiler.Compile(expression); code != semantic.CompileOK {
			t.Errorf("%s compile code = %q", ruleID, code)
		}
	}
}

func TestCloudProductionProtectionProfileBoundaries(t *testing.T) {
	connector := activateUseCaseProfile(t, "cloud-production-protection")
	tests := []struct {
		name    string
		command string
		ruleID  string
		want    bool
	}{
		{"aws recursive object delete", "aws s3 rm s3://production-data --recursive", "impact.cloud_bulk_data_delete", true},
		{"aws object batch delete", "aws s3api delete-objects --bucket production-data --delete file://objects.json", "impact.cloud_bulk_data_delete", true},
		{"gcloud recursive object delete", "gcloud storage rm --recursive 'gs://production-data/**'", "impact.cloud_bulk_data_delete", true},
		{"azure blob batch delete", "az storage blob delete-batch --account-name production --source records", "impact.cloud_bulk_data_delete", true},
		{"aws database delete", "aws rds delete-db-instance --db-instance-identifier production", "impact.cloud_resource_delete", true},
		{"gcloud project delete", "gcloud projects delete production-project --quiet", "impact.cloud_resource_delete", true},
		{"azure resource group delete", "az group delete --name production --yes", "impact.cloud_resource_delete", true},
		{"single aws object", "aws s3 rm s3://production-data/old.log", "impact.cloud_bulk_data_delete", false},
		{"aws recursive dry run", "aws s3 rm s3://production-data --recursive --dryrun", "impact.cloud_bulk_data_delete", false},
		{"aws list", "aws s3 ls s3://production-data", "impact.cloud_bulk_data_delete", false},
		{"aws delete help", "aws rds delete-db-instance help", "impact.cloud_resource_delete", false},
		{"aws describe database", "aws rds describe-db-instances --db-instance-identifier production", "impact.cloud_resource_delete", false},
		{"quoted example", "printf '%s\\n' 'aws s3 rm s3://production-data --recursive'", "impact.cloud_bulk_data_delete", false},
		{"dynamic target", "aws s3 rm \"$TARGET\" --recursive", "impact.cloud_bulk_data_delete", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := EvaluateDeterministicAction(
				context.Background(),
				actionfacts.Input{Tool: "shell", Command: test.command},
				test.command,
				connector,
				"default",
			)
			matched := slices.Contains(got.RuleIDs, test.ruleID)
			if matched != test.want {
				t.Fatalf("rules=%v action=%q route=%q parse=%q, want %s match=%t", got.RuleIDs, got.Action, got.Route, got.ParseStatus, test.ruleID, test.want)
			}
			if test.want && got.Action != "block" {
				t.Fatalf("action=%q findings=%+v, want block", got.Action, got.Findings)
			}
		})
	}
}

func TestDatabaseDestructionProtectionProfileBoundaries(t *testing.T) {
	connector := activateUseCaseProfile(t, "database-destruction-protection")
	tests := []struct {
		name    string
		command string
		ruleID  string
		want    bool
	}{
		{"postgres unbounded delete", "psql -c 'DELETE FROM customers;'", "impact.sql_unbounded_delete", true},
		{"joined short option remains unsupported", "psql '-cDELETE FROM customers;'", "impact.sql_unbounded_delete", false},
		{"mysql unbounded delete", "mysql --execute='DELETE FROM audit_log' app", "impact.sql_unbounded_delete", true},
		{"mysql ssl option with value", "mysql --ssl-mode REQUIRED -e 'DELETE FROM audit_log' app", "impact.sql_unbounded_delete", true},
		{"sql server drop database", `sqlcmd -Q "DROP DATABASE production"`, "impact.sql_schema_destroy", true},
		{"warehouse truncate", "snowsql -q 'TRUNCATE TABLE production.events'", "impact.sql_schema_destroy", true},
		{"warehouse output option with value", "snowsql -o output_format=csv -q 'TRUNCATE TABLE production.events'", "impact.sql_schema_destroy", true},
		{"postgres drop schema", "psql --command='DROP SCHEMA production CASCADE'", "impact.sql_schema_destroy", true},
		{"bounded delete", "psql -c 'DELETE FROM customers WHERE id = 7;'", "impact.sql_unbounded_delete", false},
		{"delete in string", `psql -c "SELECT 'DELETE FROM customers';"`, "impact.sql_unbounded_delete", false},
		{"delete in comment", "mysql -e '-- DELETE FROM customers\\nSELECT 1'", "impact.sql_unbounded_delete", false},
		{"explain without analyze", "psql -c 'EXPLAIN DELETE FROM customers;'", "impact.sql_unbounded_delete", false},
		{"explicit rollback", "psql -c 'BEGIN; DELETE FROM customers; ROLLBACK;'", "impact.sql_unbounded_delete", false},
		{"explicit commit", "psql -c 'BEGIN; DELETE FROM customers; COMMIT;'", "impact.sql_unbounded_delete", true},
		{"delete after rollback", "psql -c 'BEGIN; DELETE FROM customers; ROLLBACK; DELETE FROM audit_log;'", "impact.sql_unbounded_delete", true},
		{"incomplete transaction abstains", "psql -c 'BEGIN; DELETE FROM customers;'", "impact.sql_unbounded_delete", false},
		{"ordinary drop table migration", "psql -c 'DROP TABLE obsolete_records;'", "impact.sql_schema_destroy", false},
		{"case-sensitive unrelated psql option", "psql -C title", "impact.sql_unbounded_delete", false},
		{"unsupported input file remains non-authoritative", "psql --file migration.sql -c 'DELETE FROM customers;'", "impact.sql_unbounded_delete", false},
		{"quoted example", `printf '%s\\n' "psql -c 'DELETE FROM customers;'"`, "impact.sql_unbounded_delete", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := EvaluateDeterministicAction(
				context.Background(),
				actionfacts.Input{Tool: "shell", Command: test.command},
				test.command,
				connector,
				"default",
			)
			matched := slices.Contains(got.RuleIDs, test.ruleID)
			if matched != test.want {
				t.Fatalf("rules=%v action=%q route=%q parse=%q, want %s match=%t", got.RuleIDs, got.Action, got.Route, got.ParseStatus, test.ruleID, test.want)
			}
			if test.want && got.Action != "block" {
				t.Fatalf("action=%q findings=%+v, want block", got.Action, got.Findings)
			}
		})
	}
}

func TestPrivacyHighAssuranceProfileBlocksSelectedPIIOnly(t *testing.T) {
	connector := activateUseCaseProfile(t, "privacy-high-assurance")
	for _, test := range []struct {
		name, content, ruleID string
	}{
		{"hyphenated SSN", "customer ssn: 731-42-8065", "ENT-BULK-SSN"},
		{"space-delimited SSN", "customer ssn: 731 42 8065", "ENT-BULK-SSN"},
		{"alphanumeric MRN", "patient MRN-182572", "ENT-MEDICAL-RECORD"},
		{"ISO date of birth", "Date of Birth: 1970-05-07", "ENT-DOB-PATTERN"},
		{"born-on date of birth", "The patient was born on 1970-05-07", "ENT-DOB-PATTERN"},
		{"labeled email", "Email: patient@example.com", "ENT-EMAIL-BULK"},
		{"labeled formatted phone", "Phone: +44 20 7946 0958", "ENT-US-PHONE"},
		{"labeled private-label card", "Credit Card Number: 3529044259647174", "PII-CARD-LABELED"},
	} {
		t.Run(test.name, func(t *testing.T) {
			positive := ScanAllRulesForConnector(connector, test.content, "message")
			if HighestSeverity(positive) != "CRITICAL" ||
				guardrailFallbackActionForProfile(HighestSeverity(positive), "default") != "block" {
				t.Fatalf("PII findings = %+v, want a CRITICAL blocking finding", positive)
			}
			positiveIDs := make([]string, 0, len(positive))
			for _, finding := range positive {
				positiveIDs = append(positiveIDs, finding.RuleID)
			}
			if !slices.Contains(positiveIDs, test.ruleID) {
				t.Fatalf("PII findings = %+v, want %s", positive, test.ruleID)
			}
		})
	}
	negative := ScanAllRulesForConnector(
		connector,
		"contact build-bot@example.com for the test fixture",
		"message",
	)
	negativeIDs := make([]string, 0, len(negative))
	for _, finding := range negative {
		negativeIDs = append(negativeIDs, finding.RuleID)
	}
	if slices.Contains(negativeIDs, "ENT-EMAIL-BULK") || HighestSeverity(negative) == "CRITICAL" {
		t.Fatalf("loose email pattern must not block in the high-assurance pack: %+v", negative)
	}
	for _, content := range []string{
		"The form includes a medical record number field.",
		"Authorize medical record disclosure for insurance purposes.",
		"Date of birth format is YYYY-MM-DD.",
		"Email format: name@example.com",
		"Phone format: +1 212-555-0100",
		"The credit card number field contains 16 digits.",
		"contact build-bot@example.com for the test fixture",
	} {
		findings := ScanAllRulesForConnector(connector, content, "message")
		if HighestSeverity(findings) == "CRITICAL" {
			t.Fatalf("schema or documentation text must not block: %q findings=%+v", content, findings)
		}
	}
	pack, err := guardrail.LoadRulePack(useCaseProfileDir("privacy-high-assurance"))
	if err != nil {
		t.Fatal(err)
	}
	if pack.Summary().EnabledRuleCount != 13 {
		t.Fatalf("privacy profile enabled rule count = %d, want 13", pack.Summary().EnabledRuleCount)
	}
}

func TestKubernetesProductionProtectionProfileBoundaries(t *testing.T) {
	connector := activateUseCaseProfile(t, "kubernetes-production-protection")
	for _, test := range []struct {
		name, command, ruleID string
		want                  bool
	}{
		{"namespace delete", "kubectl delete namespace production", "impact.kubernetes_namespace_delete", true},
		{"namespace named delete", "kubectl --namespace delete delete namespace production", "impact.kubernetes_namespace_delete", true},
		{"oc namespace delete", "oc delete ns production", "impact.kubernetes_namespace_delete", true},
		{"all workloads", "kubectl -n production delete all --all", "impact.kubernetes_bulk_delete", true},
		{"all pods", "kubectl delete pods --all --namespace production", "impact.kubernetes_bulk_delete", true},
		{"single pod", "kubectl -n production delete pod api-7", "impact.kubernetes_bulk_delete", false},
		{"manifest delete", "kubectl delete -f obsolete.yaml", "impact.kubernetes_bulk_delete", false},
		{"dry run", "kubectl delete namespace production --dry-run=server", "impact.kubernetes_namespace_delete", false},
		{"help", "kubectl delete --help", "impact.kubernetes_namespace_delete", false},
		{"dynamic namespace", "kubectl delete namespace \"$TARGET\"", "impact.kubernetes_namespace_delete", false},
		{"quoted example", "printf '%s\\n' 'kubectl delete namespace production'", "impact.kubernetes_namespace_delete", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := EvaluateDeterministicAction(context.Background(), actionfacts.Input{Tool: "shell", Command: test.command}, test.command, connector, "default")
			if matched := slices.Contains(got.RuleIDs, test.ruleID); matched != test.want {
				t.Fatalf("rules=%v action=%q route=%q parse=%q, want %s match=%t", got.RuleIDs, got.Action, got.Route, got.ParseStatus, test.ruleID, test.want)
			}
			if test.want && got.Action != "block" {
				t.Fatalf("action=%q findings=%+v, want block", got.Action, got.Findings)
			}
		})
	}
}

func TestInfrastructureDestructionProtectionProfileBoundaries(t *testing.T) {
	connector := activateUseCaseProfile(t, "infrastructure-destruction-protection")
	for _, test := range []struct {
		name, command string
		want          bool
	}{
		{"terraform destroy", "terraform destroy -auto-approve", true},
		{"tofu apply destroy", "tofu apply -destroy -auto-approve", true},
		{"pulumi destroy", "pulumi destroy --yes --stack production", true},
		{"terraform plan", "terraform plan -destroy", false},
		{"targeted terraform destroy", "terraform destroy -target=aws_instance.legacy", false},
		{"targeted pulumi destroy", "pulumi destroy --target urn:pulumi:prod::app::fixture", false},
		{"pulumi preview", "pulumi destroy --preview-only --stack production", false},
		{"terraform apply", "terraform apply production.tfplan", false},
		{"quoted example", "printf '%s\\n' 'terraform destroy -auto-approve'", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := EvaluateDeterministicAction(context.Background(), actionfacts.Input{Tool: "shell", Command: test.command}, test.command, connector, "default")
			if matched := slices.Contains(got.RuleIDs, "impact.iac_full_destroy"); matched != test.want {
				t.Fatalf("rules=%v action=%q route=%q parse=%q, want match=%t", got.RuleIDs, got.Action, got.Route, got.ParseStatus, test.want)
			}
			if test.want && got.Action != "block" {
				t.Fatalf("action=%q findings=%+v, want block", got.Action, got.Findings)
			}
		})
	}
}

func activateUseCaseProfile(t *testing.T, name string) string {
	t.Helper()
	connector := "use-case-" + name
	pack, err := guardrail.LoadRulePack(useCaseProfileDir(name))
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	if err := ApplyConnectorRulePackOverrides(connector, pack); err != nil {
		t.Fatalf("activate %s: %v", name, err)
	}
	t.Cleanup(func() { RemoveConnectorRulePackOverrides(connector) })
	return connector
}

func useCaseProfileDir(name string) string {
	return filepath.Join("..", "..", "policies", "guardrail-use-cases", name)
}
