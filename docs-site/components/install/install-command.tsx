'use client';

import { Check, Copy } from 'lucide-react';
import { Fragment, useEffect, useRef, useState, type CSSProperties } from 'react';
import { cn } from '@/lib/utils';
import styles from './install.module.css';

interface InstallCommandProps {
  command: string;
  /** Accessible name of the copy button, e.g. "Copy the macOS install command". */
  copyLabel?: string;
  size?: 'lg' | 'md';
  /** Shell prompt shown before the command; not copied. */
  prompt?: string;
  className?: string;
}

async function copyText(text: string) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const area = document.createElement('textarea');
    area.value = text;
    area.setAttribute('readonly', '');
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.appendChild(area);
    area.select();
    const ok = document.execCommand('copy');
    area.remove();
    return ok;
  }
}

// Break long URLs after each slash so a one-liner wraps at path boundaries
// instead of scrolling or splitting mid-word.
function renderToken(token: string, index: number) {
  if (/^https?:\/\//.test(token)) {
    const parts = token.split('/');
    return (
      <span key={index} className={styles.tokUrl}>
        {parts.map((part, i) => (
          <Fragment key={i}>
            <span className={styles.nowrap}>{part}{i < parts.length - 1 ? '/' : null}</span>
            {i < parts.length - 1 && i > 1 ? <wbr /> : null}
          </Fragment>
        ))}
      </span>
    );
  }
  if (token === '|') return <span key={index} className={styles.tokPipe}>|</span>;
  if (token.startsWith('-')) return <span key={index} className={cn(styles.tokFlag, styles.nowrap)}>{token}</span>;
  if (index === 0) return <span key={index} className={cn(styles.tokCmd, styles.nowrap)}>{token}</span>;
  return <span key={index} className={styles.nowrap}>{token}</span>;
}

export function InstallCommand({ command, copyLabel, size = 'md', prompt, className }: InstallCommandProps) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(timer.current), []);

  const tokens = command.split(' ');

  return (
    <div className={cn(styles.command, size === 'lg' && styles.commandLg, className)}>
      <code
        className={styles.commandText}
        style={{ '--prompt-w': prompt ? `${prompt.length + 1}ch` : '0ch' } as CSSProperties}
      >
        {prompt ? <span aria-hidden className={styles.prompt}>{prompt}</span> : null}
        {tokens.map((token, index) => (
          <Fragment key={index}>
            {index > 0 ? ' ' : null}
            {renderToken(token, index)}
          </Fragment>
        ))}
      </code>
      <button
        type="button"
        className={styles.copy}
        aria-label={copied ? 'Copied' : (copyLabel ?? 'Copy command')}
        onClick={async () => {
          if (await copyText(command)) {
            setCopied(true);
            window.clearTimeout(timer.current);
            timer.current = window.setTimeout(() => setCopied(false), 1800);
          }
        }}
      >
        {copied ? <Check aria-hidden /> : <Copy aria-hidden />}
        <span className={styles.copyText}>{copied ? 'Copied' : 'Copy'}</span>
      </button>
      <span className={styles.srOnly} aria-live="polite">{copied ? 'Command copied to the clipboard' : ''}</span>
    </div>
  );
}
