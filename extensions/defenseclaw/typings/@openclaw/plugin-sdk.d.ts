declare module "@openclaw/plugin-sdk" {
  interface PluginApi {
    on(event: string, handler: (...args: any[]) => void | Promise<void>): void;
  }

  interface CommandArg {
    name: string;
    description?: string;
    required?: boolean;
  }

  interface CommandDef {
    description: string;
    args?: CommandArg[];
    handler: (ctx: { args: Record<string, unknown> }) => Promise<{ text: string }> | { text: string };
  }

  interface ServiceDef {
    start: () => Promise<{ stop: () => void }>;
  }

  interface PluginContext {
    api: PluginApi;
    registerService(name: string, def: ServiceDef): void;
    registerCommand(name: string, def: CommandDef): void;
  }

  type PluginEntry = (ctx: PluginContext) => void;

  export function definePluginEntry(fn: (ctx: PluginContext) => void): PluginEntry;
}
