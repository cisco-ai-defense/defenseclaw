'use client';

import type { ComponentProps } from 'react';
import { useScrollable } from '@/hooks/use-scrollable';

// A wide table scrolls sideways inside its own box. When it does, the box
// becomes a keyboard-focusable group (not a landmark, so many tables on one
// page don't trip axe's landmark-unique rule), edge shadows show there is
// more to the side, and a one-line hint matches the diagram scroll hint.
export function ResponsiveTable({
  'aria-label': ariaLabel = 'Table, scrolls sideways',
  ...props
}: ComponentProps<'table'>) {
  const { ref: regionRef, scrollable } = useScrollable<HTMLDivElement>();

  return (
    <div className="responsive-table my-6" data-scrollable={scrollable ? 'true' : undefined}>
      {scrollable ? (
        <p className="responsive-table-hint" aria-hidden>
          Scroll sideways to see every column.
        </p>
      ) : null}
      <div
        ref={regionRef}
        className="relative overflow-auto prose-no-margin dc-scroll-cue"
        role={scrollable ? 'group' : undefined}
        aria-label={scrollable ? ariaLabel : undefined}
        tabIndex={scrollable ? 0 : undefined}
      >
        <table {...props} />
      </div>
    </div>
  );
}
