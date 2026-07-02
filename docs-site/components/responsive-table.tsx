'use client';

import type { ComponentProps } from 'react';
import { useScrollable } from '@/hooks/use-scrollable';

export function ResponsiveTable({
  'aria-label': ariaLabel = 'Scrollable data table',
  ...props
}: ComponentProps<'table'>) {
  const { ref: regionRef, scrollable } = useScrollable<HTMLDivElement>();

  return (
    <div
      ref={regionRef}
      className="relative my-6 overflow-auto prose-no-margin"
      role={scrollable ? 'region' : undefined}
      aria-label={scrollable ? ariaLabel : undefined}
      tabIndex={scrollable ? 0 : undefined}
    >
      <table {...props} />
    </div>
  );
}
