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

package actionfacts

// curlSequentialPrefixProof is a parser-owned witness that earlier sequential
// curl transfer groups start before a later lazy setup failure. The zero
// value is not a proof. Coverage cannot be minted from a caller-supplied
// boolean: only proveCurlSequentialTransferPrefix can attach the nonce.
type curlSequentialPrefixProof struct {
	commandID int64
	maxGroup  int
	nonce     *curlSequentialPrefixNonce
}

type curlSequentialPrefixNonce struct{}

func newCurlSequentialPrefixProof(commandID int64, maxGroup int) curlSequentialPrefixProof {
	if maxGroup < 0 {
		return curlSequentialPrefixProof{}
	}
	return curlSequentialPrefixProof{
		commandID: commandID,
		maxGroup:  maxGroup,
		nonce:     &curlSequentialPrefixNonce{},
	}
}

func (p curlSequentialPrefixProof) ok() bool {
	return p.nonce != nil && p.maxGroup >= 0
}

func (p curlSequentialPrefixProof) covers(group int) bool {
	return p.ok() && group >= 0 && group <= p.maxGroup
}

// proveCurlSequentialTransferPrefix reports the last --next group that will
// start after argv/eager validation. Later lazy setup failures do not close
// an already proved sequential prefix. Parallel mode, eager later-group
// failures, redirects, wrappers, and incomplete envelopes yield the zero
// proof. The result never makes Facts.Authoritative() true.
func proveCurlSequentialTransferPrefix(
	command CommandFact,
	parsed curlArgvParse,
) curlSequentialPrefixProof {
	if !curlSequentialPrefixEnvelopeValid(command) {
		return curlSequentialPrefixProof{}
	}
	nullConfigOnly := staticCurlPOSIXNullConfigOnly(command, parsed)
	if (!parsed.Complete && !nullConfigOnly) || parsed.Preview ||
		parsed.EmptyTransferGroup ||
		!parsed.hasValidOptionValues() || len(parsed.Targets) == 0 ||
		!curlRangeOptionsValid(parsed) ||
		!staticCurlFeatureDependentPositiveOptionsValid(parsed) {
		return curlSequentialPrefixProof{}
	}
	if !staticCurlFTPEagerPreparseValid(command, parsed) {
		return curlSequentialPrefixProof{}
	}
	if !staticCurlFTPParallelSetupValid(command, parsed) {
		return curlSequentialPrefixProof{}
	}
	maxGroup := curlSequentialSetupValidPrefixGroup(command, parsed)
	if maxGroup < 0 {
		return curlSequentialPrefixProof{}
	}
	return newCurlSequentialPrefixProof(command.ID, maxGroup)
}

func curlSequentialPrefixEnvelopeValid(command CommandFact) bool {
	return (command.Dialect == DialectPOSIX || command.Dialect == DialectArgv) &&
		command.Effect == EffectExecute &&
		command.ParentCommandID == 0 &&
		len(command.Wrappers) == 0 &&
		len(command.Redirects) == 0 &&
		command.ArgvComplete &&
		len(command.Argv) != 0 &&
		command.Executable == command.Argv[0] &&
		len(command.Arguments) == len(command.Argv) &&
		exactCaseSensitivePOSIXProgram(&command, "curl")
}

func curlSequentialSetupValidPrefixGroup(
	command CommandFact,
	parsed curlArgvParse,
) int {
	groups := make(map[int]struct{})
	maximumGroup := 0
	for _, target := range parsed.Targets {
		groups[target.Group] = struct{}{}
		maximumGroup = max(maximumGroup, target.Group)
	}
	maxCovered := -1
	for group := 0; group <= maximumGroup; group++ {
		if _, present := groups[group]; !present {
			continue
		}
		if !staticCurlFTPGroupSetupValid(command, parsed, group) {
			break
		}
		maxCovered = group
	}
	return maxCovered
}
