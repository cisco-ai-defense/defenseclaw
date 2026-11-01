// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/accountjoin"
)

func TestGatewayReadsCredential(t *testing.T) {
	for name, want := range map[string]bool{
		accountjoin.SecretName: false, accountjoin.NextSecretName: false,
		"ai-defense-api-key": true, "judge-key": true, "account-join-key-old": true,
	} {
		if got := GatewayReadsCredential(name); got != want {
			t.Errorf("%s: %v, want %v", name, got, want)
		}
	}
}

// rel-1-0-6:GAP-0301: the Windows installer's ACL pass names the same
// credentials as GatewayReadsCredential and gives them the administrator
// descriptor the Go store writes.
func TestTheInstallerKeepsTheAccountJoinSecretsFromTheGateway(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "packaging", "windows", "DefenseClawEnterprise.psm1"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	start := strings.Index(text, "function Get-DefenseClawStandaloneSecretFileSddl {")
	end := strings.Index(text[start+1:], "\nfunction ")
	if start < 0 || end < 0 {
		t.Fatal("Get-DefenseClawStandaloneSecretFileSddl not found")
	}
	body := text[start : start+1+end]
	for _, name := range []string{accountjoin.SecretName, accountjoin.NextSecretName} {
		if !strings.Contains(body, "$Name -ceq '"+name+"'") {
			t.Errorf("the installer does not name %s", name)
		}
	}
	if !strings.Contains(body, "return 'O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)'") {
		t.Error("the installer's account join descriptor is not LocalSystem and Administrators only")
	}
	if !strings.Contains(text, "-Name $item.Name") {
		t.Error("Set-DefenseClawStandaloneSecretsAcls does not pass the credential name")
	}
}
