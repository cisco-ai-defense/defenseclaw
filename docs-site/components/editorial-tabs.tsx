'use client';

import * as TabsPrimitive from '@radix-ui/react-tabs';
import type { ComponentProps, ReactNode } from 'react';

function safeValue(value: string) {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/(^-|-$)/g, '');
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
  const initialValue = safeValue(defaultValue ?? items[defaultIndex] ?? 'tab');

  return (
    <TabsPrimitive.Root
      {...props}
      defaultValue={initialValue}
      className={`editorial-tabs flex flex-col overflow-hidden border bg-fd-secondary my-4${className ? ` ${className}` : ''}`}
    >
      <TabsPrimitive.List
        aria-label={typeof label === 'string' ? label : 'Documentation examples'}
        className="flex gap-3.5 overflow-x-auto px-4 text-fd-secondary-foreground not-prose"
      >
        {label ? <span className="me-auto my-auto text-sm font-medium">{label}</span> : null}
        {items.map((item) => (
          <TabsPrimitive.Trigger
            key={item}
            value={safeValue(item)}
            className="inline-flex items-center gap-2 whitespace-nowrap border-b border-transparent py-2 text-sm font-medium text-fd-muted-foreground transition-colors hover:text-fd-accent-foreground focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-fd-ring data-[state=active]:border-fd-primary data-[state=active]:text-fd-primary"
          >
            {item}
          </TabsPrimitive.Trigger>
        ))}
      </TabsPrimitive.List>
      {children}
    </TabsPrimitive.Root>
  );
}

type TabProps = Omit<ComponentProps<typeof TabsPrimitive.Content>, 'value'> & {
  value: string;
};

export function EditorialTab({ value, className, children, ...props }: TabProps) {
  return (
    <TabsPrimitive.Content
      {...props}
      value={safeValue(value)}
      forceMount
      className={`bg-fd-background p-4 text-[0.9375rem] outline-none prose-no-margin data-[state=inactive]:hidden [&>figure:only-child]:-m-4 [&>figure:only-child]:border-none${className ? ` ${className}` : ''}`}
    >
      {children}
    </TabsPrimitive.Content>
  );
}
