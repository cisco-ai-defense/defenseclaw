// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package budgetstore

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/accountjoin"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/routingadmin"
)

// CredentialVersion is the device credential format.
const CredentialVersion = 1

// Credential is one device's budget store credential: what the
// administrator issues (budget-store device issue) and MDM installs as the
// device's protected credential. It names only that device's users and
// groups, and holds no tenant-wide secret.
type Credential struct {
	Version int    `json:"v"`
	Device  string `json:"device"`
	Secret  []byte `json:"secret"`
	// Users are the device's users: their verified SID or UPN as the device
	// sees them, and their fleet id.
	Users []CredentialUser `json:"users"`
	// Keys map the device's local charge keys of named-user, group and named
	// connector budgets to their fleet form.
	Keys map[string]string `json:"keys,omitempty"`
	// UserBudgets are the * user budgets the credential was issued for
	// (user:<id>:*:<user id>); a * budget added to the bundle later counts
	// on the device until the device is issued again.
	UserBudgets []string `json:"user_budgets,omitempty"`
	// ConnectorBudgets are the * connector budgets (connector:<id>:<name>).
	ConnectorBudgets []string `json:"connector_budgets,omitempty"`
}

// CredentialUser is one user a device may charge and read.
type CredentialUser struct {
	SID string `json:"sid,omitempty"`
	UPN string `json:"upn,omitempty"`
	ID  string `json:"id"`
}

// Encode returns the credential as the protected credential value.
func (c Credential) Encode() string {
	data, _ := json.Marshal(c)
	return base64.StdEncoding.EncodeToString(data)
}

// DecodeCredential parses a protected credential value.
func DecodeCredential(value string) (Credential, error) {
	var c Credential
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil || json.Unmarshal(data, &c) != nil {
		return Credential{}, errors.New("budget store device credential is damaged")
	}
	if c.Version != CredentialVersion || !ValidDevice(c.Device) || len(c.Secret) != SecretBytes {
		return Credential{}, errors.New("budget store device credential is not a version 1 credential")
	}
	for _, u := range c.Users {
		if !strings.HasPrefix(u.ID, "u") || (u.SID == "" && u.UPN == "") {
			return Credential{}, errors.New("budget store device credential has a malformed user")
		}
	}
	for _, id := range append(append([]string(nil), c.UserBudgets...), c.ConnectorBudgets...) {
		if !ValidKey("user:" + id + ":x") {
			return Credential{}, errors.New("budget store device credential has a malformed budget id")
		}
	}
	for local, fleet := range c.Keys {
		if !ValidKey(local) || !ValidKey(fleet) {
			return Credential{}, errors.New("budget store device credential has a malformed key")
		}
	}
	return c, nil
}

// Key returns the device's signing key.
func (c Credential) Key() (DeviceKey, error) { return NewDeviceKey(c.Device, c.Secret) }

// IssueInput is what the administrator names for one device.
type IssueInput struct {
	Budgets []config.RoutingBudget
	// Users are UPNs (name@domain) or SIDs (S-1-...) of the device's users.
	Users []string
	// Groups are the groups those users are in, as the budgets name them.
	Groups []string
	CapUSD float64
}

// Issue makes a new device credential and its store record with the subject
// key of the tenant secret (administrator workstation only).
func Issue(subject SubjectKey, in IssueInput) (Credential, DeviceRecord, error) {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return Credential{}, DeviceRecord{}, err
	}
	cred := Credential{Version: CredentialVersion, Device: "d" + hex.EncodeToString(raw[:]), Secret: make([]byte, SecretBytes), Keys: map[string]string{}}
	if _, err := rand.Read(cred.Secret); err != nil {
		return Credential{}, DeviceRecord{}, err
	}
	if math.IsNaN(in.CapUSD) || math.IsInf(in.CapUSD, 0) || in.CapUSD < 0 || in.CapUSD > maxUSD {
		return Credential{}, DeviceRecord{}, errors.New("--cap-usd must be 0 (the store default) to 10000000")
	}
	for _, b := range in.Budgets {
		if b.Scope == config.RoutingBudgetScopeUser && b.Subject == config.RoutingBudgetSubjectAll {
			cred.UserBudgets = append(cred.UserBudgets, b.ID)
		}
	}
	allowed := map[string]bool{}
	for _, entry := range in.Users {
		entry = strings.TrimSpace(entry)
		account := accountjoin.Account{UPN: entry}
		if strings.HasPrefix(strings.ToUpper(entry), "S-1-") {
			account = accountjoin.Account{SID: entry}
		}
		canonical, err := accountjoin.Canonical(account)
		if err != nil {
			return Credential{}, DeviceRecord{}, errors.New("a --user is neither a UPN (name@domain) nor a SID (S-1-...)")
		}
		user := CredentialUser{SID: account.SID, UPN: account.UPN, ID: "u" + subject.Hash("account:"+canonical)}
		cred.Users = append(cred.Users, user)
		for _, b := range in.Budgets {
			switch {
			case b.Scope == config.RoutingBudgetScopeUser && b.Subject == config.RoutingBudgetSubjectAll:
				allowed["user:"+b.ID+":*:"+user.ID] = true
			case b.Scope == config.RoutingBudgetScopeUser && sameAccount(b.Subject, entry):
				fleet := "user:" + b.ID + ":=" + subject.Hash(b.Subject)
				cred.Keys["user:"+b.ID+":="+routingadmin.LocalSubjectHash(b.Subject)] = fleet
				allowed[fleet] = true
			}
		}
	}
	for _, group := range in.Groups {
		group = strings.TrimSpace(group)
		for _, b := range in.Budgets {
			if b.Scope == config.RoutingBudgetScopeGroup && strings.EqualFold(b.Subject, group) {
				fleet := "group:" + b.ID + ":" + subject.Hash(b.Subject)
				cred.Keys["group:"+b.ID+":"+routingadmin.LocalSubjectHash(b.Subject)] = fleet
				allowed[fleet] = true
			}
		}
	}
	for _, b := range in.Budgets {
		if b.Scope != config.RoutingBudgetScopeConnector {
			continue
		}
		if b.Subject == config.RoutingBudgetSubjectAll {
			cred.ConnectorBudgets = append(cred.ConnectorBudgets, b.ID)
			continue
		}
		key := "connector:" + b.ID + ":" + config.NormalizeConnectorName(b.Subject)
		cred.Keys[key] = key
		allowed[key] = true
	}
	keys := make([]string, 0, len(allowed))
	for k := range allowed {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	rec := DeviceRecord{ID: cred.Device, Secret: append([]byte(nil), cred.Secret...), Keys: keys,
		ConnectorBudgets: append([]string(nil), cred.ConnectorBudgets...), CapUSD: in.CapUSD}
	return cred, rec, nil
}

// sameAccount reports whether a users entry names the account entry (the
// same UPN or SID, case-insensitively).
func sameAccount(budgetSubject, entry string) bool {
	return strings.EqualFold(strings.TrimSpace(budgetSubject), strings.TrimSpace(entry))
}
