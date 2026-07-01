'use client';

import { AlertTriangle, CheckCircle2, CircleDot, ScanSearch } from 'lucide-react';
import { motion, useReducedMotion } from 'motion/react';
import type { EvidenceItem } from './types';

function EvidenceIcon({ tone }: { tone: EvidenceItem['tone'] }) {
  if (tone === 'danger' || tone === 'warning') return <AlertTriangle aria-hidden />;
  if (tone === 'success') return <CheckCircle2 aria-hidden />;
  if (tone === 'info') return <ScanSearch aria-hidden />;
  return <CircleDot aria-hidden />;
}

export function EvidenceRail({
  items,
  stepId,
}: {
  items: EvidenceItem[];
  stepId: string;
}) {
  const prefersReducedMotion = useReducedMotion();

  return (
    <aside className="scenario-evidence" aria-label="Active evidence" aria-live="polite">
      <div className="scenario-evidence-heading">
        <span>Evidence</span>
        <span>{String(items.length).padStart(2, '0')}</span>
      </div>
      <motion.div
        key={stepId}
        className="scenario-evidence-list"
        initial={prefersReducedMotion ? false : { opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: prefersReducedMotion ? 0 : 0.18, ease: 'easeOut' }}
      >
        {items.map((item, index) => (
          <motion.article
            key={item.id}
            className={`scenario-evidence-item scenario-tone-${item.tone}`}
            initial={prefersReducedMotion ? false : { opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{
              duration: prefersReducedMotion ? 0 : 0.2,
              delay: prefersReducedMotion ? 0 : index * 0.035,
              ease: 'easeOut',
            }}
          >
            <div className="scenario-evidence-label">
              <span className="scenario-annotation-number" aria-hidden>{index + 1}</span>
              <EvidenceIcon tone={item.tone} />
              {item.label}
            </div>
            <p className="scenario-evidence-value">{item.value}</p>
            {item.detail ? <p className="scenario-evidence-detail">{item.detail}</p> : null}
          </motion.article>
        ))}
      </motion.div>
    </aside>
  );
}
