import type { Trace } from './guard.js';

/** The slice of the MCP SDK `Client` GuardPulse wraps. */
export interface McpClientLike {
  callTool(params: { name: string; arguments?: Record<string, unknown> }, ...rest: never[]): Promise<unknown>;
  listTools?(...args: never[]): Promise<{ tools: Array<{ name: string; description?: string; inputSchema?: unknown }> }>;
}

/**
 * Wraps an MCP client so every `callTool` goes through the trace (and can be blocked), and every
 * `listTools` is recorded for the Security Autopilot to spot changed tool definitions.
 */
export function guardMcpClient<C extends McpClientLike>(client: C, trace: Trace, opts: { server?: string } = {}): C {
  const server = opts.server ?? 'mcp';
  return new Proxy(client, {
    get(target, prop, receiver) {
      const value = Reflect.get(target, prop, receiver);
      if (prop === 'callTool') {
        return (params: { name: string; arguments?: Record<string, unknown> }, ...rest: never[]) =>
          trace.tool(params.name, params.arguments ?? {}, () => target.callTool(params, ...rest));
      }
      if (prop === 'listTools' && typeof value === 'function') {
        return async (...args: never[]) => {
          const res = await target.listTools!(...args);
          await trace.event('mcp.tools/list', {
            server,
            tools: res.tools.map(({ name, description, inputSchema }) => ({ name, description, inputSchema })),
          });
          return res;
        };
      }
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
}
