'use client';

import {
  ScrollProgress,
  ScrollProgressProvider,
} from '@/components/animate-ui/primitives/animate/scroll-progress';

export function SiteScrollProgress({ children }: { children: React.ReactNode }) {
  return (
    <ScrollProgressProvider
      global
      direction="vertical"
      transition={{ stiffness: 260, damping: 42, bounce: 0 }}
    >
      <ScrollProgress
        aria-hidden
        className="site-scroll-progress"
        mode="scaleX"
        style={{ transformOrigin: '0 50%' }}
      />
      {children}
    </ScrollProgressProvider>
  );
}
