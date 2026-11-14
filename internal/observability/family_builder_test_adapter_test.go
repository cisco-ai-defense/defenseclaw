// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package observability

// generatedLogFamilyContract and buildGeneratedLog were the production entry
// for handwritten log families before the generated wrappers moved to
// buildGeneratedResolvedLog. Only the kernel tests still drive a family
// through them, so they live here, with the tests (#1442 dead-code pass).
type generatedLogFamilyContract interface {
	familyDescriptor
	schemaDerivedLogFamilyContract
}

func (builder *FamilyBuilder) buildGeneratedLog(
	descriptor generatedLogFamilyContract,
	input familyLogBuildInput,
) (Record, error) {
	if !builder.ready() || nilInterface(descriptor) {
		return Record{}, familyBuildFailure(FamilyBuildInvalidDependency)
	}
	contract := cloneFamilyDescriptorContract(descriptor.familyDescriptorContract())
	if err := validateFamilyDescriptor(contract, familySignalLog); err != nil {
		return Record{}, err
	}
	resolvedIdentity := descriptor.schemaDerivedLogIdentity()
	if resolvedIdentity != contract.identity || resolvedIdentity.Signal != SignalLogs {
		return Record{}, familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
	return builder.buildResolvedGeneratedLog(
		contract,
		resolveGeneratedLogMandatory(descriptor.schemaDerivedLogMandatory()),
		input,
	)
}
