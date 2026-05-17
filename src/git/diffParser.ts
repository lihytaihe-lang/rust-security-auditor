import { isAbsolute, posix } from "node:path";

export type DiffLineKind = "added" | "removed" | "context";

export interface GitDiffHunk {
  oldStart: number;
  oldLines: number;
  newStart: number;
  newLines: number;
  addedLines: number[];
  removedLines: number[];
  contextLines: number[];
  contextRange: [number, number];
}

export interface GitDiffFile {
  filePath: string;
  oldPath?: string;
  newPath?: string;
  hunks: GitDiffHunk[];
}

export interface ParsedGitDiff {
  files: GitDiffFile[];
}

interface MutableGitDiffFile {
  filePath?: string;
  oldPath?: string;
  newPath?: string;
  hunks: GitDiffHunk[];
}

interface HunkState {
  hunk: GitDiffHunk;
  oldLine: number;
  newLine: number;
}

const hunkHeaderPattern = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/;

export function parseUnifiedDiff(input: string): ParsedGitDiff {
  const files: MutableGitDiffFile[] = [];
  let currentFile: MutableGitDiffFile | undefined;
  let currentHunk: HunkState | undefined;

  for (const line of input.split(/\r?\n/)) {
    if (line.startsWith("diff --git ")) {
      currentFile = createFileFromDiffHeader(line);
      files.push(currentFile);
      currentHunk = undefined;
      continue;
    }

    if (currentHunk !== undefined && isHunkBodyLine(line)) {
      applyHunkLine(currentHunk, line);
      continue;
    }

    if (line.startsWith("--- ")) {
      currentFile ??= pushFile(files);
      const oldPath = normalizeGitDiffPath(line.slice(4));
      if (oldPath !== undefined) {
        currentFile.oldPath = oldPath;
        currentFile.filePath ??= oldPath;
      } else {
        delete currentFile.oldPath;
      }
      currentHunk = undefined;
      continue;
    }

    if (line.startsWith("+++ ")) {
      currentFile ??= pushFile(files);
      const newPath = normalizeGitDiffPath(line.slice(4));
      if (newPath !== undefined) {
        currentFile.newPath = newPath;
        currentFile.filePath = newPath;
      } else if (currentFile.oldPath !== undefined) {
        delete currentFile.newPath;
        currentFile.filePath = currentFile.oldPath;
      }
      currentHunk = undefined;
      continue;
    }

    const hunkHeader = parseHunkHeader(line);
    if (hunkHeader !== undefined) {
      currentFile ??= pushFile(files);
      currentFile.hunks.push(hunkHeader);
      currentHunk = {
        hunk: hunkHeader,
        oldLine: hunkHeader.oldStart,
        newLine: hunkHeader.newStart
      };
    }
  }

  return {
    files: files
      .map(finalizeFile)
      .filter((file): file is GitDiffFile => file !== undefined)
  };
}

export function normalizeGitDiffPath(rawPath: string): string | undefined {
  let path = stripHeaderMetadata(rawPath.trim());

  if (path === "/dev/null" || path.length === 0) {
    return undefined;
  }

  path = unquoteGitPath(path);

  if (path.startsWith("a/") || path.startsWith("b/")) {
    path = path.slice(2);
  }

  const normalized = posix.normalize(path.replaceAll("\\", "/"));

  if (
    normalized === "." ||
    normalized === ".." ||
    normalized.startsWith("../") ||
    posix.isAbsolute(normalized) ||
    isAbsolute(path)
  ) {
    return undefined;
  }

  return normalized;
}

function createFileFromDiffHeader(line: string): MutableGitDiffFile {
  const [oldPath, newPath] = parseDiffHeaderPaths(line);
  const file: MutableGitDiffFile = {
    hunks: []
  };

  if (oldPath !== undefined) {
    file.oldPath = oldPath;
  }

  if (newPath !== undefined) {
    file.newPath = newPath;
  }

  const filePath = newPath ?? oldPath;
  if (filePath !== undefined) {
    file.filePath = filePath;
  }
  return file;
}

function parseDiffHeaderPaths(line: string): [string | undefined, string | undefined] {
  const rest = line.slice("diff --git ".length);
  const tokens = splitGitPathTokens(rest);

  return [
    tokens[0] === undefined ? undefined : normalizeGitDiffPath(tokens[0]),
    tokens[1] === undefined ? undefined : normalizeGitDiffPath(tokens[1])
  ];
}

function splitGitPathTokens(input: string): string[] {
  const tokens: string[] = [];
  let index = 0;

  while (index < input.length) {
    while (input[index] === " ") index += 1;
    if (index >= input.length) break;

    if (input[index] === "\"") {
      const quoted = readQuotedToken(input, index);
      tokens.push(quoted.token);
      index = quoted.nextIndex;
      continue;
    }

    const nextSpace = input.indexOf(" ", index);
    if (nextSpace === -1) {
      tokens.push(input.slice(index));
      break;
    }

    tokens.push(input.slice(index, nextSpace));
    index = nextSpace + 1;
  }

  return tokens;
}

function readQuotedToken(input: string, startIndex: number): { token: string; nextIndex: number } {
  let escaped = false;

  for (let index = startIndex + 1; index < input.length; index += 1) {
    const char = input[index];

    if (escaped) {
      escaped = false;
      continue;
    }

    if (char === "\\") {
      escaped = true;
      continue;
    }

    if (char === "\"") {
      return {
        token: input.slice(startIndex, index + 1),
        nextIndex: index + 1
      };
    }
  }

  return {
    token: input.slice(startIndex),
    nextIndex: input.length
  };
}

function parseHunkHeader(line: string): GitDiffHunk | undefined {
  const match = hunkHeaderPattern.exec(line);
  if (match === null) return undefined;

  const oldStart = Number.parseInt(match[1] ?? "0", 10);
  const oldLines = Number.parseInt(match[2] ?? "1", 10);
  const newStart = Number.parseInt(match[3] ?? "0", 10);
  const newLines = Number.parseInt(match[4] ?? "1", 10);
  const newEnd = newLines === 0 ? newStart : newStart + newLines - 1;

  return {
    oldStart,
    oldLines,
    newStart,
    newLines,
    addedLines: [],
    removedLines: [],
    contextLines: [],
    contextRange: [newStart, newEnd]
  };
}

function applyHunkLine(state: HunkState, line: string): void {
  const kind = line[0];

  switch (kind) {
    case "+":
      state.hunk.addedLines.push(state.newLine);
      state.newLine += 1;
      return;
    case "-":
      state.hunk.removedLines.push(state.oldLine);
      state.oldLine += 1;
      return;
    case " ":
      state.hunk.contextLines.push(state.newLine);
      state.oldLine += 1;
      state.newLine += 1;
      return;
    case "\\":
      return;
    default:
      return;
  }
}

function isHunkBodyLine(line: string): boolean {
  return line.startsWith("+") || line.startsWith("-") || line.startsWith(" ") || line.startsWith("\\");
}

function pushFile(files: MutableGitDiffFile[]): MutableGitDiffFile {
  const file: MutableGitDiffFile = {
    hunks: []
  };
  files.push(file);
  return file;
}

function finalizeFile(file: MutableGitDiffFile): GitDiffFile | undefined {
  const filePath = file.filePath ?? file.newPath ?? file.oldPath;
  if (filePath === undefined) return undefined;

  const finalized: GitDiffFile = {
    filePath,
    hunks: file.hunks
  };

  if (file.oldPath !== undefined) {
    finalized.oldPath = file.oldPath;
  }

  if (file.newPath !== undefined) {
    finalized.newPath = file.newPath;
  }

  return finalized;
}

function stripHeaderMetadata(value: string): string {
  if (value.startsWith("\"")) {
    return value;
  }

  const tabIndex = value.indexOf("\t");
  return tabIndex === -1 ? value : value.slice(0, tabIndex);
}

function unquoteGitPath(value: string): string {
  if (!value.startsWith("\"") || !value.endsWith("\"")) {
    return value;
  }

  try {
    const parsed = JSON.parse(value) as unknown;
    if (typeof parsed === "string") return parsed;
  } catch {
    // Fall back to a conservative unescape for Git-style quoted path headers.
  }

  return value.slice(1, -1).replaceAll("\\\"", "\"").replaceAll("\\\\", "\\");
}
