import { realpathSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

export function resolveWorkspacePath(workspacePath?: string): string {
  return resolve(workspacePath ?? process.cwd());
}

/**
 * True when `moduleUrl` is the entry point Node was started with.
 *
 * Symbolic links must be resolved on both sides: npm installs a bin as a
 * symlink in `node_modules/.bin`, so `process.argv[1]` is the link while
 * `import.meta.url` is the real file. Comparing them without realpath makes an
 * installed executable start up and exit without doing anything.
 */
export function isEntryPointModule(moduleUrl: string): boolean {
  const entry = process.argv[1];
  if (entry === undefined) return false;

  const modulePath = fileURLToPath(moduleUrl);

  try {
    return realpathSync(entry) === realpathSync(modulePath);
  } catch {
    return resolve(entry) === modulePath;
  }
}

