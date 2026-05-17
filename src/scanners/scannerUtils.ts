import { readdir, readFile } from "node:fs/promises";
import { basename, join, relative, sep } from "node:path";

const ignoredDirectoryNames = new Set([
  ".git",
  ".hg",
  ".svn",
  ".idea",
  ".vscode",
  "dist",
  "node_modules",
  "target"
]);

export async function collectWorkspaceFiles(rootPath: string): Promise<string[]> {
  const files: string[] = [];
  await collect(rootPath, files);
  files.sort((left, right) => left.localeCompare(right));
  return files;
}

export async function readTextLines(absolutePath: string): Promise<string[]> {
  const text = await readFile(absolutePath, "utf8");
  return text.split(/\r?\n/);
}

export function toRelativeFile(rootPath: string, absolutePath: string): string {
  const path = relative(rootPath, absolutePath);
  return path.split(sep).join("/");
}

export function firstMeaningfulLine(lines: readonly string[]): number {
  const index = lines.findIndex((line) => line.trim().length > 0);
  return index === -1 ? 1 : index + 1;
}

export function isCommentOnlyLine(line: string): boolean {
  const trimmed = line.trim();
  return (
    trimmed.length === 0 ||
    trimmed.startsWith("//") ||
    trimmed.startsWith("///") ||
    trimmed.startsWith("//!") ||
    trimmed.startsWith("#") ||
    trimmed.startsWith("/*") ||
    trimmed.startsWith("*")
  );
}

export function quotedTomlStrings(value: string): string[] {
  return [...value.matchAll(/"([^"]+)"/g)].map((match) => match[1]).filter((item): item is string => item !== undefined);
}

export function isCargoTomlPath(path: string): boolean {
  return basename(path) === "Cargo.toml";
}

export function isCargoLockPath(path: string): boolean {
  return basename(path) === "Cargo.lock";
}

export function isBuildScriptPath(path: string): boolean {
  return basename(path) === "build.rs";
}

export function isRustSourcePath(path: string): boolean {
  return path.endsWith(".rs");
}

async function collect(directory: string, files: string[]): Promise<void> {
  const entries = await readdir(directory, { withFileTypes: true });

  for (const entry of entries) {
    const absolutePath = join(directory, entry.name);

    if (entry.isDirectory()) {
      if (!ignoredDirectoryNames.has(entry.name)) {
        await collect(absolutePath, files);
      }
      continue;
    }

    if (entry.isFile()) {
      files.push(absolutePath);
    }
  }
}
