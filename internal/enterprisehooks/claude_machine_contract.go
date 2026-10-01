// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// claudeHookContractOrder returns a Claude hook contract's position in the
// contract table (oldest first), or -1.
func claudeHookContractOrder(contractID string) int {
	contractID = strings.TrimSpace(contractID)
	for index, contract := range connector.KnownHookContracts("claudecode") {
		if contract.ContractID == contractID {
			return index
		}
	}
	return -1
}

// WindowsStandaloneClaudeMachinePolicyContract returns the hook contract a
// standalone Windows deployment renders its single machine-wide Claude policy
// from: the oldest contract among the manifest's enabled claudecode rows. A
// row's agent version is a claim its user controls; rendering the shared body
// from each row's own version let one user switch the hook contract for every
// user, and made rows on different contracts rewrite the body in turn. The
// oldest contract is valid for every enrolled client. It changes with the
// enrolled set, and rises as enrolled users upgrade; it never falls because
// an enrolled user downgrades, since a known row never follows a change to
// an older contract (claudeMachineContractLowered). Empty when no enabled
// row resolves to a known contract.
func WindowsStandaloneClaudeMachinePolicyContract(manifest Manifest) string {
	contracts := connector.KnownHookContracts("claudecode")
	best := -1
	for _, target := range manifest.Targets {
		if !target.IsEnabled() || !strings.EqualFold(strings.TrimSpace(target.Connector), "claudecode") {
			continue
		}
		resolution := connector.ResolveHookContract("claudecode", target.AgentVersion)
		if resolution.Status != connector.HookCompatibilityKnown {
			continue
		}
		if index := claudeHookContractOrder(resolution.Contract.ContractID); index >= 0 && (best < 0 || index < best) {
			best = index
		}
	}
	if best < 0 {
		return ""
	}
	return contracts[best].ContractID
}

// claudeMachinePolicySetup returns the setup the machine-wide Claude policy
// body is rendered and verified from. rowSetup carries the row's resolved
// HookContractID. Without a deployment-wide contract, or outside a
// standalone process, the row's own contract is used unchanged; the chosen
// contract is never newer than the row's own.
func claudeMachinePolicySetup(rowSetup connector.SetupOpts, machineContractID string, standalone bool) connector.SetupOpts {
	machineContractID = strings.TrimSpace(machineContractID)
	if !standalone || machineContractID == "" {
		return rowSetup
	}
	machine := claudeHookContractOrder(machineContractID)
	row := claudeHookContractOrder(rowSetup.HookContractID)
	if machine < 0 || row < 0 || machine > row {
		return rowSetup
	}
	policy := rowSetup
	policy.HookContractID = machineContractID
	return policy
}

// claudeMachineContractLowered explains why a known Claude Code row must not
// follow its user's change from version from to version to: to resolves to
// an older hook contract than from. The standalone Windows deployment renders
// the one machine-wide Claude policy from the oldest enrolled contract, so a
// row that followed the change would move every user's policy to the older
// contract, which lacks hooks the newer one has. Empty when the change may
// be followed: another connector, a contract that is the same or newer, or
// a from version with no known contract.
func claudeMachineContractLowered(connectorName, from, to string) string {
	if !strings.EqualFold(strings.TrimSpace(connectorName), "claudecode") {
		return ""
	}
	current := connector.ResolveHookContract("claudecode", from)
	next := connector.ResolveHookContract("claudecode", to)
	if current.Status != connector.HookCompatibilityKnown || next.Status != connector.HookCompatibilityKnown {
		return ""
	}
	currentOrder := claudeHookContractOrder(current.Contract.ContractID)
	nextOrder := claudeHookContractOrder(next.Contract.ContractID)
	if currentOrder < 0 || nextOrder < 0 || nextOrder >= currentOrder {
		return ""
	}
	return fmt.Sprintf(
		"version %s has an older hook contract (%s) than the enrolled %s (%s), and the one machine-wide Claude Code policy every user shares is rendered from the oldest enrolled contract",
		strings.TrimSpace(to), next.Contract.ContractID, strings.TrimSpace(from), current.Contract.ContractID,
	)
}
