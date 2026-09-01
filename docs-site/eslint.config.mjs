import { defineConfig, globalIgnores } from 'eslint/config';
import nextVitals from 'eslint-config-next/core-web-vitals';
import nextTypeScript from 'eslint-config-next/typescript';

export default defineConfig([
  ...nextVitals,
  ...nextTypeScript,
  {
    rules: {
      // These rules expose existing migration debt in the current component
      // library. Keep it visible without making the initial ESLint CLI gate
      // unusable; all other recommended and Core Web Vitals errors still fail.
      '@next/next/no-html-link-for-pages': 'warn',
      'prefer-const': 'warn',
      'react-hooks/set-state-in-effect': 'warn',
      'react-hooks/static-components': 'warn',
      'react/no-children-prop': 'warn',
      'react/no-unescaped-entities': 'warn',
    },
  },
  globalIgnores([
    '.next/**',
    '.source/**',
    'out/**',
    'build/**',
    'next-env.d.ts',
  ]),
]);
