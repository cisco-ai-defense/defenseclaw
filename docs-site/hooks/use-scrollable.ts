'use client';

import { useEffect, useRef, useState } from 'react';

export function useScrollable<T extends HTMLElement>() {
  const ref = useRef<T | null>(null);
  const [scrollable, setScrollable] = useState(false);

  useEffect(() => {
    const element = ref.current;
    if (!element) return;

    const update = () => setScrollable(element.scrollWidth > element.clientWidth + 1);
    update();
    const observer = new ResizeObserver(update);
    observer.observe(element);
    const mutationObserver = new MutationObserver(update);
    mutationObserver.observe(element, {
      childList: true,
      subtree: true,
      characterData: true,
    });
    return () => {
      observer.disconnect();
      mutationObserver.disconnect();
    };
  }, []);

  return { ref, scrollable };
}
