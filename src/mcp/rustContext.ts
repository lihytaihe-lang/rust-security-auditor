import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { GitDiffFile } from "../git/index.js";
import type { RustFunctionContext, UnsafeSiteContext } from "./types.js";

export interface RustLineContext {
  functionContext?: RustFunctionContext | undefined;
  unsafeSite?: UnsafeSiteContext | undefined;
}

export interface RustFileContext {
  file: string;
  functions: RustFunctionContext[];
  unsafeSites: UnsafeSiteContext[];
}

export async function extractRustContextForDiffFiles(
  projectPath: string,
  diffFiles: readonly GitDiffFile[]
): Promise<Map<string, RustFileContext>> {
  const contexts = new Map<string, RustFileContext>();
  const rustFiles = [...new Set(diffFiles.map((file) => file.filePath).filter((file) => file.endsWith(".rs")))];

  await Promise.all(
    rustFiles.map(async (file) => {
      try {
        const source = await readFile(join(projectPath, file), "utf8");
        contexts.set(file, extractRustFileContext(file, source.split(/\r?\n/)));
      } catch {
        // Deleted or unreadable files can still appear in a diff; skip context rather than failing review.
      }
    })
  );

  return contexts;
}

export async function extractRustContextForProjectFiles(
  projectPath: string,
  files: readonly string[]
): Promise<Map<string, RustFileContext>> {
  const contexts = new Map<string, RustFileContext>();
  const rustFiles = [...new Set(files.filter((file) => file.endsWith(".rs")))];

  await Promise.all(
    rustFiles.map(async (file) => {
      try {
        const source = await readFile(join(projectPath, file), "utf8");
        contexts.set(file, extractRustFileContext(file, source.split(/\r?\n/)));
      } catch {
        // Non-diff audit reports can still be useful without function/site context.
      }
    })
  );

  return contexts;
}

export function contextForLine(context: RustFileContext | undefined, line: number | undefined): RustLineContext {
  if (context === undefined || line === undefined) return {};

  const functionContext = findFunctionForLine(context.functions, line);
  const unsafeSite = findUnsafeSiteForLine(context.unsafeSites, line);
  const result: RustLineContext = {};

  if (functionContext !== undefined) {
    result.functionContext = functionContext;
  }

  if (unsafeSite !== undefined) {
    result.unsafeSite = unsafeSite;
  }

  return result;
}

function extractRustFileContext(file: string, lines: readonly string[]): RustFileContext {
  const functions = extractFunctions(lines);
  const unsafeSites = extractUnsafeSites(lines, functions);

  return {
    file,
    functions,
    unsafeSites
  };
}

function extractFunctions(lines: readonly string[]): RustFunctionContext[] {
  const functions: RustFunctionContext[] = [];
  const functionPattern =
    /^\s*(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+"[^"]+"\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\b/;

  lines.forEach((line, index) => {
    const match = functionPattern.exec(line);
    const name = match?.[1];
    if (name === undefined) return;

    const range = braceRangeFromLine(lines, index);
    const context: RustFunctionContext = {
      name,
      startLine: index + 1
    };

    if (range.endLine !== undefined) {
      context.endLine = range.endLine;
    }

    functions.push(context);
  });

  return functions;
}

function extractUnsafeSites(lines: readonly string[], functions: readonly RustFunctionContext[]): UnsafeSiteContext[] {
  const sites: UnsafeSiteContext[] = [];

  lines.forEach((line, index) => {
    const lineNumber = index + 1;

    if (/\bunsafe\s*\{/.test(line)) {
      sites.push(unsafeSite("unsafe_block", lineNumber, braceRangeFromLine(lines, index), functions));
    }

    if (/\bunsafe\s+(?:extern\s+"[^"]+"\s+)?fn\b/.test(line)) {
      sites.push(unsafeSite("unsafe_fn", lineNumber, braceRangeFromLine(lines, index), functions));
    }

    if (/\bunsafe\s+impl\b/.test(line)) {
      sites.push(unsafeSite("unsafe_impl", lineNumber, braceRangeFromLine(lines, index), functions));
    }

    if (/\bextern\s+"C"/.test(line)) {
      sites.push(unsafeSite("extern_c", lineNumber, braceRangeFromLine(lines, index), functions));
    }
  });

  return sites;
}

function unsafeSite(
  kind: UnsafeSiteContext["kind"],
  startLine: number,
  range: { endLine?: number | undefined },
  functions: readonly RustFunctionContext[]
): UnsafeSiteContext {
  const functionContext = findFunctionForLine(functions, startLine);
  const site: UnsafeSiteContext = {
    kind,
    startLine
  };

  if (range.endLine !== undefined) {
    site.endLine = range.endLine;
  }

  if (functionContext !== undefined) {
    site.functionName = functionContext.name;
  }

  return site;
}

function braceRangeFromLine(
  lines: readonly string[],
  startIndex: number
): { endLine?: number | undefined } {
  let foundOpeningBrace = false;
  let depth = 0;

  for (let index = startIndex; index < lines.length; index += 1) {
    const line = stripBraceNoise(lines[index] ?? "");

    for (const char of line) {
      if (char === "{") {
        foundOpeningBrace = true;
        depth += 1;
      } else if (char === "}" && foundOpeningBrace) {
        depth -= 1;
      }
    }

    if (foundOpeningBrace && depth <= 0) {
      return { endLine: index + 1 };
    }
  }

  return {};
}

function stripBraceNoise(line: string): string {
  let result = "";
  let inString = false;
  let inChar = false;
  let escaped = false;

  for (let index = 0; index < line.length; index += 1) {
    const char = line[index] ?? "";
    const next = line[index + 1];

    if (!inString && !inChar && char === "/" && next === "/") {
      break;
    }

    if (escaped) {
      escaped = false;
      continue;
    }

    if ((inString || inChar) && char === "\\") {
      escaped = true;
      continue;
    }

    if (!inChar && char === "\"") {
      inString = !inString;
      continue;
    }

    if (!inString && char === "'") {
      inChar = !inChar;
      continue;
    }

    if (!inString && !inChar) {
      result += char;
    }
  }

  return result;
}

function findFunctionForLine(
  functions: readonly RustFunctionContext[],
  line: number
): RustFunctionContext | undefined {
  return functions
    .filter((item) => item.startLine <= line && (item.endLine === undefined || item.endLine >= line))
    .sort((left, right) => right.startLine - left.startLine)[0];
}

function findUnsafeSiteForLine(
  sites: readonly UnsafeSiteContext[],
  line: number
): UnsafeSiteContext | undefined {
  return sites
    .filter((item) => item.startLine <= line && (item.endLine === undefined || item.endLine >= line))
    .sort((left, right) => unsafeSiteSpan(left) - unsafeSiteSpan(right))[0];
}

function unsafeSiteSpan(site: UnsafeSiteContext): number {
  return (site.endLine ?? site.startLine) - site.startLine;
}
