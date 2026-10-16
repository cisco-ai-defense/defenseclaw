// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

import type { Policy } from '../types';

export type GuardrailModeChoice = 'keep-host-mode' | 'observe' | 'action';

export const GUARDRAIL_MODE_CHOICES: Array<{ value: GuardrailModeChoice; label: string }> = [
  { value: 'keep-host-mode', label: 'keep host mode' },
  { value: 'observe', label: 'observe' },
  { value: 'action', label: 'action' },
];

export function getGuardrailModeChoice(guardrail: Policy['guardrail']): GuardrailModeChoice {
  return guardrail.mode ?? 'keep-host-mode';
}

export function setGuardrailModeChoice(
  guardrail: Policy['guardrail'],
  choice: GuardrailModeChoice,
): Policy['guardrail'] {
  const next = { ...guardrail };
  if (choice === 'keep-host-mode') {
    delete next.mode;
  } else {
    next.mode = choice;
  }
  return next;
}
