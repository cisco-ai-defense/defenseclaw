// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestExactCloudAuditControlDestruction(t *testing.T) {
	tests := []struct {
		name    string
		command string
		dialect Dialect
		want    bool
	}{
		{name: "aws stop logging", command: "aws cloudtrail stop-logging --name production-trail --region us-east-1", want: true},
		{name: "aws delete trail powershell", command: "aws cloudtrail delete-trail --name production-trail --region us-gov-west-1", dialect: DialectPowerShell, want: true},
		{name: "aws reversed exact options", command: "aws cloudtrail delete-trail --region eu-west-2 --name audit.primary", want: true},
		{name: "gcp delete audit activity", command: "gcloud logging logs delete projects/security-prod-123/logs/cloudaudit.googleapis.com%2Factivity --quiet", want: true},
		{name: "aws describe", command: "aws cloudtrail describe-trails --region us-east-1"},
		{name: "aws status", command: "aws cloudtrail get-trail-status --name production-trail --region us-east-1"},
		{name: "aws start restore", command: "aws cloudtrail start-logging --name production-trail --region us-east-1"},
		{name: "aws update administration", command: "aws cloudtrail update-trail --name production-trail --region us-east-1"},
		{name: "aws source placeholder", command: "aws cloudtrail stop-logging --name #{cloudtrail_name} --region #{region}"},
		{name: "aws dynamic name", command: `aws cloudtrail delete-trail --name "$TRAIL" --region us-east-1`},
		{name: "aws dynamic region", command: `aws cloudtrail delete-trail --name production-trail --region "${AWS_REGION}"`},
		{name: "aws missing region", command: "aws cloudtrail delete-trail --name production-trail"},
		{name: "aws extra profile", command: "aws cloudtrail delete-trail --name production-trail --region us-east-1 --profile production"},
		{name: "aws joined option", command: "aws cloudtrail delete-trail --name=production-trail --region=us-east-1"},
		{name: "aws help", command: "aws cloudtrail delete-trail help"},
		{name: "aws extra command", command: "aws cloudtrail delete-trail --name production-trail --region us-east-1\nwhoami"},
		{name: "aws conditional", command: "test -f /tmp/ready && aws cloudtrail delete-trail --name production-trail --region us-east-1"},
		{name: "aws pipeline", command: "aws cloudtrail delete-trail --name production-trail --region us-east-1 | tee /tmp/result"},
		{name: "aws wrapper", command: "sh -c 'aws cloudtrail delete-trail --name production-trail --region us-east-1'"},
		{name: "gcp ordinary log delete", command: "gcloud logging logs delete projects/security-prod-123/logs/application --quiet"},
		{name: "gcp audit read", command: "gcloud logging read 'logName=cloudaudit.googleapis.com%2Factivity' --project security-prod-123"},
		{name: "gcp missing quiet", command: "gcloud logging logs delete projects/security-prod-123/logs/cloudaudit.googleapis.com%2Factivity"},
		{name: "gcp project placeholder", command: "gcloud logging logs delete projects/#{project-id}/logs/cloudaudit.googleapis.com%2Factivity --quiet"},
		{name: "gcp dynamic project", command: `gcloud logging logs delete "projects/$PROJECT/logs/cloudaudit.googleapis.com%2Factivity" --quiet`},
		{name: "gcp setup plus delete", command: "gcloud config set project security-prod-123\ngcloud logging logs delete projects/security-prod-123/logs/cloudaudit.googleapis.com%2Factivity --quiet"},
		{name: "azure unsupported", command: "az monitor diagnostic-settings delete --name audit --resource /subscriptions/000/resourceGroups/core"},
		{name: "documentation", command: `printf '%s\n' 'aws cloudtrail delete-trail --name production-trail --region us-east-1'`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dialect := test.dialect
			if dialect == "" {
				dialect = DialectPOSIX
			}
			facts := Analyze(Input{
				Tool: "shell", Command: test.command, CWD: "/repo", DialectHint: dialect,
			})
			if got := ExactCloudAuditControlDestruction(facts); got != test.want {
				t.Fatalf("proof=%t want=%t parse=%+v commands=%+v", got, test.want, facts.Parse, facts.Commands)
			}
			if test.want {
				command := facts.Commands[0]
				if !hasFactOperation(command, OperationDelete) ||
					!hasFactOperation(command, OperationConfigChange) ||
					!hasFactOperation(command, OperationPolicyBypass) {
					t.Fatalf("exact proof omitted operations: %+v", command)
				}
			}
		})
	}
}

func TestWindowsCloudCLINonMatchesRemainCompleteAndNonOwning(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
		dialect Dialect
	}{
		{name: "powershell aws describe", command: "aws cloudtrail describe-trails --region us-east-1", dialect: DialectPowerShell},
		{name: "powershell aws status", command: "aws cloudtrail get-trail-status --name production-trail --region us-east-1", dialect: DialectPowerShell},
		{name: "cmd gcloud read", command: `gcloud logging read "resource.type=gce_instance" --project security-prod-123`, dialect: DialectCMD},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{
				Tool: "shell", Command: test.command, CWD: `C:\repo`, DialectHint: test.dialect,
			})
			if !facts.Authoritative() || facts.Parse.Status != StatusComplete {
				t.Fatalf("unrelated cloud CLI became partial: parse=%+v commands=%+v", facts.Parse, facts.Commands)
			}
			if ExactCloudAuditControlDestruction(facts) {
				t.Fatalf("unrelated cloud CLI matched destruction proof: %+v", facts)
			}
			for _, command := range facts.Commands {
				if hasFactOperation(command, OperationDelete) ||
					hasFactOperation(command, OperationPolicyBypass) {
					t.Fatalf("unrelated cloud CLI gained destructive semantics: %+v", command)
				}
			}
		})
	}
}
