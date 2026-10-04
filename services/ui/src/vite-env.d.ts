/// <reference types="vite/client" />

// Extend Vite's environment variable types
interface ImportMetaEnv {
  readonly VITE_AUTO_REFRESH_ON_ERROR?: string
  // Add more env variables here as needed
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}

// Declare CSS modules
declare module "*.css" {
  const content: Record<string, string>
  export default content
}

// Declare CSS side-effect imports
declare module "*.css" {
  const css: string
  export default css
}
