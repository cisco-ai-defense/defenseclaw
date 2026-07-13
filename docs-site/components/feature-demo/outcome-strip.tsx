'use client';

import { Ban, CheckCircle2, Clock3, Eye, RadioTower } from 'lucide-react';
import { motion, useReducedMotion } from 'motion/react';
import type { ScenarioOutcome, ScenarioStep } from './types';

function OutcomeIcon({ kind }: { kind: ScenarioOutcome['kind'] }) {
  if (kind === 'block' || kind === 'quarantine' || kind === 'disable') return <Ban aria-hidden />;
  if (kind === 'pause' || kind === 'review') return <Clock3 aria-hidden />;
  if (kind === 'observe' || kind === 'audit') return <Eye aria-hidden />;
  if (kind === 'export') return <RadioTower aria-hidden />;
  return <CheckCircle2 aria-hidden />;
}

export function OutcomeStrip({
  outcome,
  step,
}: {
  outcome?: ScenarioOutcome;
  step: ScenarioStep;
}) {
  const kind = outcome?.kind ?? 'observe';
  const prefersReducedMotion = useReducedMotion();

  return (
    <motion.div
      key={outcome?.id ?? step.id}
      className={`scenario-outcome scenario-outcome-${kind}`}
      initial={prefersReducedMotion ? false : { opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: prefersReducedMotion ? 0 : 0.2, ease: 'easeOut' }}
      aria-live="polite"
    >
      <div className="scenario-outcome-verdict">
        <span className="scenario-outcome-kicker">Decision</span>
        <strong><OutcomeIcon kind={kind} />{outcome?.label ?? 'Evaluating evidence'}</strong>
      </div>
      <div>
        <span className="scenario-outcome-kicker">Reason</span>
        <p>{outcome?.reason ?? step.description}</p>
      </div>
      <div>
        <span className="scenario-outcome-kicker">Action</span>
        <p>{outcome?.action ?? 'Continue guided analysis'}</p>
      </div>
    </motion.div>
  );
}
