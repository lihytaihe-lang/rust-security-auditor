import { resolve } from "node:path";

export function resolveWorkspacePath(workspacePath?: string): string {
  return resolve(workspacePath ?? process.cwd());
}

