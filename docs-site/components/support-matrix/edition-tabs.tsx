'use client';

import { useId, useRef, useState, type KeyboardEvent, type ReactNode } from 'react';
import styles from './support-matrix.module.css';

interface EditionTabsProps {
  oss: ReactNode;
  enterprise: ReactNode;
  label?: string;
}

const TABS = [
  { id: 'oss', label: 'Open source' },
  { id: 'enterprise', label: 'Enterprise' },
] as const;

// Open source / Enterprise switch. Both panels are server-rendered; the
// inactive one is hidden, so the page reads the same without JavaScript
// (open source shows by default).
export function EditionTabs({ oss, enterprise, label = 'Edition' }: EditionTabsProps) {
  const [active, setActive] = useState<(typeof TABS)[number]['id']>('oss');
  const base = useId();
  const refs = useRef<(HTMLButtonElement | null)[]>([]);

  function onKeyDown(event: KeyboardEvent<HTMLButtonElement>, index: number) {
    if (event.key !== 'ArrowRight' && event.key !== 'ArrowLeft') return;
    event.preventDefault();
    const next = (index + (event.key === 'ArrowRight' ? 1 : TABS.length - 1)) % TABS.length;
    setActive(TABS[next].id);
    refs.current[next]?.focus();
  }

  return (
    <div>
      <div role="tablist" aria-label={label} className={styles.tabs}>
        {TABS.map((tab, index) => (
          <button
            key={tab.id}
            ref={(node) => {
              refs.current[index] = node;
            }}
            id={`${base}-${tab.id}-tab`}
            type="button"
            role="tab"
            aria-selected={active === tab.id}
            aria-controls={`${base}-${tab.id}-panel`}
            tabIndex={active === tab.id ? 0 : -1}
            className={styles.tab}
            onClick={() => setActive(tab.id)}
            onKeyDown={(event) => onKeyDown(event, index)}
          >
            {tab.label}
          </button>
        ))}
      </div>
      <div
        role="tabpanel"
        id={`${base}-oss-panel`}
        aria-labelledby={`${base}-oss-tab`}
        hidden={active !== 'oss'}
      >
        {oss}
      </div>
      <div
        role="tabpanel"
        id={`${base}-enterprise-panel`}
        aria-labelledby={`${base}-enterprise-tab`}
        hidden={active !== 'enterprise'}
      >
        {enterprise}
      </div>
    </div>
  );
}
