import defaultMdxComponents from 'fumadocs-ui/mdx';
import { Step, Steps } from 'fumadocs-ui/components/steps';
import { Accordion, Accordions } from 'fumadocs-ui/components/accordion';
import { Callout as FumadocsCallout } from 'fumadocs-ui/components/callout';
import { File, Folder, Files } from 'fumadocs-ui/components/files';
import { Card as FumadocsCard, Cards as FumadocsCards } from 'fumadocs-ui/components/card';
import { Banner } from 'fumadocs-ui/components/banner';
import { TypeTable as FumadocsTypeTable } from 'fumadocs-ui/components/type-table';
import Link from 'fumadocs-core/link';
import type { MDXComponents } from 'mdx/types';
import { Flow, Node, Edge, Zone, Sequence, Message } from '@/components/diagram';
import { CapabilityMatrix, HookEventsList, SandboxHarnessTable } from '@/components/capability-matrix';
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
import { DocsCodeBlock } from '@/components/code-block';

function Callout(props: ComponentProps<typeof FumadocsCallout>) {
  return <FumadocsCallout {...props} className={cn('editorial-callout', props.className)} />;
}

function Cards(props: ComponentProps<typeof FumadocsCards>) {
  return <FumadocsCards {...props} className={cn('editorial-cards', props.className)} />;
}

// Same markup as Fumadocs' Card, except the title is not an <h3>. Cards are
// link lists; as headings they broke the outline wherever cards come before
// the page's first <h2> (axe heading-order).
function Card({ icon, title, description, children, className, ...props }: ComponentProps<typeof FumadocsCard>) {
  const body = (
    <>
      {icon ? (
        <div className="not-prose mb-2 w-fit shadow-md rounded-lg border bg-fd-muted p-1.5 text-fd-muted-foreground [&_svg]:size-4">
          {icon}
        </div>
      ) : null}
      <p className="editorial-card-title not-prose mb-1! mt-0! text-sm font-medium">{title}</p>
      {description ? <p className="my-0! text-sm text-fd-muted-foreground">{description}</p> : null}
      <div className="text-sm text-fd-muted-foreground prose-no-margin empty:hidden">{children}</div>
    </>
  );
  const classes = cn(
    'block rounded-xl border bg-fd-card p-4 text-fd-card-foreground transition-colors @max-lg:col-span-full',
    props.href && 'hover:bg-fd-accent/80',
    'editorial-card',
    className,
  );
  if (props.href) {
    return (
      <Link {...(props as ComponentProps<typeof Link>)} data-card className={classes}>
        {body}
      </Link>
    );
  }
  return (
    <div {...(props as ComponentProps<'div'>)} data-card className={classes}>
      {body}
    </div>
  );
}

// Every TypeTable on the site lists CLI flags, subcommands or values, not
// optional props, so Fumadocs' trailing "?" (shown when `required` is unset)
// read as part of the flag name, for example `--mode?`.
function TypeTable({ type, ...props }: ComponentProps<typeof FumadocsTypeTable>) {
  const shown = Object.fromEntries(
    Object.entries(type).map(([name, item]) => [name, { required: true, ...item }]),
  );
  return <FumadocsTypeTable {...props} type={shown} />;
}

// Inline code: short chips such as `--json` stay on one line instead of
// breaking at a hyphen, and long paths or URLs may wrap anywhere instead of
// overflowing a phone screen (global.css). Code inside <pre> has element
// children, so it is left alone.
function InlineCode(props: ComponentProps<'code'>) {
  const text = props.children;
  if (typeof text !== 'string' || text.includes('\n')) return <code {...props} />;
  return <code {...props} data-inline={text.length <= 32 ? 'short' : 'long'} />;
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
  pre: DocsCodeBlock,
  code: InlineCode,
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
  Zone,
  Sequence,
  Message,
  CapabilityMatrix,
  HookEventsList,
  SandboxHarnessTable,
  CommandGenerator,
  PolicyCreator,
  RecipeCatalog,
  Video,
  TerminalAnimation,
  DefenseClawDemo,
  ConnectorCatalog,
  ConnectorLabel,
};
