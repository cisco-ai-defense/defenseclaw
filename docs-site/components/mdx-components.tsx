import defaultMdxComponents from 'fumadocs-ui/mdx';
import { Step, Steps } from 'fumadocs-ui/components/steps';
import { Accordion, Accordions } from 'fumadocs-ui/components/accordion';
import { Callout as FumadocsCallout } from 'fumadocs-ui/components/callout';
import { File, Folder, Files } from 'fumadocs-ui/components/files';
import { Card as FumadocsCard, Cards as FumadocsCards } from 'fumadocs-ui/components/card';
import { Banner } from 'fumadocs-ui/components/banner';
import { TypeTable } from 'fumadocs-ui/components/type-table';
import type { MDXComponents } from 'mdx/types';
import { Flow, Node, Edge, Sequence, Message } from '@/components/diagram';
import { CapabilityMatrix, HookEventsList } from '@/components/capability-matrix';
import { CommandGenerator } from '@/components/command-generator';
import PolicyCreator from '@/components/policy-creator';
import { RecipeCatalog } from '@/components/policy-creator/recipe-catalog';
import { Video } from '@/components/video';
import { TerminalAnimation } from '@/components/terminal-animation';
import { DefenseClawDemo } from '@/components/feature-demo';
import { EditorialTab as Tab, EditorialTabs as Tabs } from '@/components/editorial-tabs';
import { ResponsiveTable } from '@/components/responsive-table';
import { ConnectorCatalog } from '@/components/connector-catalog';
import { ConnectorLabel } from '@/components/connector-brand';
import type { ComponentProps } from 'react';
import { cn } from '@/lib/utils';

function Callout(props: ComponentProps<typeof FumadocsCallout>) {
  return <FumadocsCallout {...props} className={cn('editorial-callout', props.className)} />;
}

function Cards(props: ComponentProps<typeof FumadocsCards>) {
  return <FumadocsCards {...props} className={cn('editorial-cards', props.className)} />;
}

function Card(props: ComponentProps<typeof FumadocsCard>) {
  return <FumadocsCard {...props} className={cn('editorial-card', props.className)} />;
}

function MdxInput(props: ComponentProps<'input'>) {
  if (props.type === 'checkbox') {
    return (
      <input
        {...props}
        aria-label={props['aria-label'] ?? (props.checked ? 'Completed checklist item' : 'Incomplete checklist item')}
      />
    );
  }
  return <input {...props} />;
}

// Single registry for the components that MDX pages can reference
// without a per-file import. Keeping this list short and curated
// keeps the docs surface coherent — every page reaches for the same
// vocabulary (Steps, Tabs, Files, Callouts, Cards, Accordions,
// TypeTables, Flow/Sequence diagrams, the CapabilityMatrix).
export const mdxComponents: MDXComponents = {
  ...defaultMdxComponents,
  table: ResponsiveTable,
  input: MdxInput,
  Tab,
  Tabs,
  Step,
  Steps,
  Accordion,
  Accordions,
  Callout,
  File,
  Folder,
  Files,
  Card,
  Cards,
  Banner,
  TypeTable,
  Flow,
  Node,
  Edge,
  Sequence,
  Message,
  CapabilityMatrix,
  HookEventsList,
  CommandGenerator,
  PolicyCreator,
  RecipeCatalog,
  Video,
  TerminalAnimation,
  DefenseClawDemo,
  ConnectorCatalog,
  ConnectorLabel,
};
