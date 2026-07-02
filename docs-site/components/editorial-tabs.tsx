'use client';

import * as TabsPrimitive from '@radix-ui/react-tabs';
import {
  Children,
  cloneElement,
  isValidElement,
  type ComponentProps,
  type ReactElement,
  type ReactNode,
} from 'react';
import { cn } from '@/lib/utils';

function safeValue(value: string) {
  const slug = value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/(^-|-$)/g, '');
  let hash = 0;
  for (const character of value) hash = (hash * 31 + character.charCodeAt(0)) >>> 0;
  return `${slug || 'tab'}-${hash.toString(36)}`;
}

function uniqueValues(items: string[]) {
  const counts = new Map<string, number>();
  return items.map((item) => {
    const base = safeValue(item);
    const count = counts.get(base) ?? 0;
    counts.set(base, count + 1);
    return count === 0 ? base : `${base}-${count + 1}`;
  });
}

type RootProps = Omit<
  ComponentProps<typeof TabsPrimitive.Root>,
  'defaultValue' | 'value' | 'onValueChange'
> & {
  items?: string[];
  defaultIndex?: number;
  defaultValue?: string;
  label?: ReactNode;
};

export function EditorialTabs({
  items = [],
  defaultIndex = 0,
  defaultValue,
  label,
  className,
  children,
  ...props
}: RootProps) {
  const values = uniqueValues(items);
  const requestedIndex = defaultValue === undefined ? defaultIndex : items.indexOf(defaultValue);
  const initialValue = values[requestedIndex >= 0 ? requestedIndex : defaultIndex] ?? safeValue('tab');
  const valueOccurrences = new Map<string, number>();
  const resolvedChildren = Children.map(children, (child) => {
    if (!isValidElement<TabProps>(child) || child.type !== EditorialTab) return child;
    const occurrence = valueOccurrences.get(child.props.value) ?? 0;
    valueOccurrences.set(child.props.value, occurrence + 1);
    const matchingIndices = items.flatMap((item, index) => item === child.props.value ? [index] : []);
    const itemIndex = matchingIndices[occurrence];
    const resolvedValue = itemIndex === undefined ? safeValue(child.props.value) : values[itemIndex];
    return cloneElement(child as ReactElement<TabProps>, { resolvedValue });
  });

  return (
    <TabsPrimitive.Root
      {...props}
      defaultValue={initialValue}
      className={cn('editorial-tabs flex flex-col overflow-hidden border bg-fd-secondary my-4', className)}
    >
      <TabsPrimitive.List
        aria-label={typeof label === 'string' ? label : 'Documentation examples'}
        className="flex gap-3.5 overflow-x-auto px-4 text-fd-secondary-foreground not-prose"
      >
        {label ? <span className="me-auto my-auto text-sm font-medium">{label}</span> : null}
        {items.map((item, index) => (
          <TabsPrimitive.Trigger
            key={values[index]}
            value={values[index]}
            className="inline-flex items-center gap-2 whitespace-nowrap border-b border-transparent py-2 text-sm font-medium text-fd-muted-foreground transition-colors hover:text-fd-accent-foreground focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-fd-ring data-[state=active]:border-fd-primary data-[state=active]:text-fd-primary"
          >
            {item}
          </TabsPrimitive.Trigger>
        ))}
      </TabsPrimitive.List>
      {resolvedChildren}
    </TabsPrimitive.Root>
  );
}

type TabProps = Omit<ComponentProps<typeof TabsPrimitive.Content>, 'value'> & {
  value: string;
  resolvedValue?: string;
};

export function EditorialTab({ value, resolvedValue, className, children, ...props }: TabProps) {
  return (
    <TabsPrimitive.Content
      {...props}
      value={resolvedValue ?? safeValue(value)}
      forceMount
      className={cn('bg-fd-background p-4 text-[0.9375rem] outline-none prose-no-margin data-[state=inactive]:hidden [&>figure:only-child]:-m-4 [&>figure:only-child]:border-none', className)}
    >
      {children}
    </TabsPrimitive.Content>
  );
}
