'use client';

import { CodeBlock, Pre } from 'fumadocs-ui/components/codeblock';
import { type ComponentProps, useLayoutEffect, useRef } from 'react';

// Fumadocs' code block, with three docs-wide fixes:
// - The scroll viewport is a focusable, labelled group rather than an
//   unnamed `region` landmark. Every code block used to add a landmark with
//   the same (empty) name, which axe reports as landmark-unique on every page.
//   Fumadocs hard-codes the role after the props it passes through, so it is
//   corrected once on mount.
// - No 600px height cap: long recipes read top to bottom with the page
//   instead of inside a second scroll box.
// - Untitled blocks keep a right gutter for the copy button (global.css), so
//   the button never covers the end of the first line.
export function DocsCodeBlock({ children, ...props }: ComponentProps<'pre'> & { title?: string }) {
  const ref = useRef<HTMLElement>(null);
  const label = typeof props.title === 'string' && props.title ? `Code: ${props.title}` : 'Code example';

  useLayoutEffect(() => {
    const viewport = ref.current?.querySelector<HTMLElement>(':scope > .fd-scroll-container');
    if (!viewport) return;
    viewport.setAttribute('role', 'group');
    viewport.setAttribute('aria-label', label);
  }, [label]);

  return (
    <CodeBlock
      ref={ref}
      {...(props as ComponentProps<typeof CodeBlock>)}
      viewportProps={{ className: 'max-h-none dc-scroll-cue' }}
    >
      <Pre>{children}</Pre>
    </CodeBlock>
  );
}
