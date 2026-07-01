'use client';

import { useEffect, useRef, useState, type ComponentProps } from 'react';

export function ResponsiveTable({
  'aria-label': ariaLabel = 'Scrollable data table',
  ...props
}: ComponentProps<'table'>) {
  const regionRef = useRef<HTMLDivElement>(null);
  const [scrollable, setScrollable] = useState(false);

  useEffect(() => {
    const region = regionRef.current;
    if (!region) return;

    const update = () => {
      setScrollable(region.scrollWidth > region.clientWidth + 1);
    };
    update();

    const observer = new ResizeObserver(update);
    observer.observe(region);
    return () => observer.disconnect();
  }, []);

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
