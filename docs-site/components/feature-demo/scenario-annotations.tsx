'use client';

import { motion } from 'motion/react';
import type { ScenarioTone } from './types';

export function ScenarioAnnotations({
  tone,
  annotationCount,
  stepId,
}: {
  tone: ScenarioTone;
  annotationCount: number;
  stepId: string;
}) {
  if (annotationCount === 0) return null;

  return (
    <svg className="scenario-connectors" viewBox="0 0 1000 520" preserveAspectRatio="none" aria-hidden>
      <motion.path
        key={stepId}
        className={`scenario-connector scenario-tone-${tone}`}
        d="M 565 242 C 655 242, 634 144, 720 144 L 760 144"
        initial={{ pathLength: 0, opacity: 0 }}
        animate={{ pathLength: 1, opacity: 1 }}
        transition={{ duration: 0.5, ease: 'easeInOut' }}
      />
      <circle className={`scenario-connector-dot scenario-tone-${tone}`} cx="565" cy="242" r="4" />
      <circle className={`scenario-connector-dot scenario-tone-${tone}`} cx="760" cy="144" r="4" />
    </svg>
  );
}
