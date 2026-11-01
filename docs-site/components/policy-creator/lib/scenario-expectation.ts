// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

import type { Policy, Scenario } from '../types';

/**
 * The verdict a bundled scenario expects under the preset a policy is
 * based on. A scenario's expectedVerdict is the Balanced (default)
 * outcome; expectedByPreset names where Strict or Permissive decide
 * differently on purpose (rel-1-0-4 GAP-0209).
 */
export function expectedVerdictFor(
  scenario: Pick<Scenario, 'expectedVerdict' | 'expectedByPreset'>,
  preset: Policy['basedOn'],
): string {
  return scenario.expectedByPreset?.[preset] ?? scenario.expectedVerdict;
}

/** Whether the preset's expectation differs from the Balanced one. */
export function presetDiverges(scenario: Pick<Scenario, 'expectedByPreset'>, preset: Policy['basedOn']): boolean {
  return scenario.expectedByPreset?.[preset] != null;
}
