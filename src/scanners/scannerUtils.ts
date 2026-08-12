import { constants, type Dir, type Stats } from "node:fs";
import { lstat, open, opendir, realpath, stat, type FileHandle } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { StringDecoder } from "node:string_decoder";

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

/** Files larger than this are skipped; generated or vendored blobs are not review material. */
export const defaultMaxFileBytes = 2 * 1024 * 1024;

/** Upper bound on discovered files, so a mistargeted path cannot stall the MCP client. */
export const defaultMaxFiles = 50_000;

/** Directory-only trees must not bypass the discovery work limit. */
export const defaultMaxDirectories = defaultMaxFiles;

/** Total source bytes available to one MCP tool call. */
export const defaultMaxTotalBytes = 32 * 1024 * 1024;

/** Bounded reads prevent a large diff from opening every source file at once. */
export const defaultMaxReadConcurrency = 8;

export type ScanInputType = "rust" | "cargo_toml" | "cargo_lock" | "cargo_config" | "build_script";
export type ScanStage = "discovery" | "unsafe_scan" | "dependency_scan" | "source_risk_scan" | "suppression" | "rust_context" | "diff_selection";
export type ScanCoverageReason =
  | "file_too_large"
  | "file_limit"
  | "total_byte_limit"
  | "symbolic_link"
  | "outside_workspace"
  | "read_failed"
  | "stat_failed"
  | "discovery_truncated"
  | "context_failed"
  | "missing_current_input"
  | "lexical_incomplete";

export interface ScanCoverageEntry {
  status: "complete" | "incomplete" | "not_applicable";
  file: string;
  inputType: ScanInputType;
  stage: ScanStage;
  reason?: ScanCoverageReason;
  message: string;
  relevantToDiff?: boolean;
}

export interface ScanCoverage {
  complete: boolean;
  entries: ScanCoverageEntry[];
}

export interface SafeSourceReaderOptions {
  maxFileBytes?: number;
  maxFiles?: number;
  maxTotalBytes?: number;
  maxConcurrency?: number;
}

/**
 * Per-tool-call source snapshot. Every scanner, suppression lookup, and Rust
 * context extraction must use this capability instead of opening a path on its
 * own. It refuses symlinks and out-of-root paths, caps file/byte budgets, and
 * reuses the first successfully read content for internal consistency.
 */
export class SafeSourceReader {
  readonly rootPath: string;
  readonly maxFileBytes: number;
  readonly maxFiles: number;
  readonly maxTotalBytes: number;
  readonly maxConcurrency: number;
  private readonly cache = new Map<string, Promise<string[] | undefined>>();
  private readonly coverageEntries = new Map<string, ScanCoverageEntry>();
  private activeReads = 0;
  private maxObservedConcurrentReads = 0;
  private readonly waiters: Array<() => void> = [];
  private readFileCount = 0;
  private readByteCount = 0;

  constructor(rootPath: string, options: SafeSourceReaderOptions = {}) {
    this.rootPath = resolve(rootPath);
    this.maxFileBytes = options.maxFileBytes ?? defaultMaxFileBytes;
    this.maxFiles = options.maxFiles ?? defaultMaxFiles;
    this.maxTotalBytes = options.maxTotalBytes ?? defaultMaxTotalBytes;
    this.maxConcurrency = options.maxConcurrency ?? defaultMaxReadConcurrency;
  }

  async readTextLines(
    absolutePath: string,
    file: string,
    inputType: ScanInputType,
    stage: ScanStage
  ): Promise<string[] | undefined> {
    const resolvedPath = resolve(absolutePath);
    const normalizedFile = normalizeCoverageFile(file);

    if (!isPathWithin(this.rootPath, resolvedPath)) {
      this.recordIncomplete(normalizedFile, inputType, stage, "outside_workspace", "Path is outside the requested project root.");
      return undefined;
    }

    const cached = this.cache.get(resolvedPath);
    if (cached !== undefined) return await cached;

    const pending = this.withReadSlot(async () => await this.readOnce(resolvedPath, normalizedFile, inputType, stage));
    this.cache.set(resolvedPath, pending);
    return await pending;
  }

  recordIncomplete(
    file: string,
    inputType: ScanInputType,
    stage: ScanStage,
    reason: ScanCoverageReason,
    message: string,
    relevantToDiff?: boolean
  ): void {
    const normalizedFile = normalizeCoverageFile(file);
    const existing = this.coverageEntries.get(normalizedFile);
    const isRelevantToDiff = relevantToDiff ?? existing?.relevantToDiff;
    this.coverageEntries.set(normalizedFile, {
      status: "incomplete",
      file: normalizedFile,
      inputType,
      stage,
      reason,
      message,
      ...(isRelevantToDiff === undefined ? {} : { relevantToDiff: isRelevantToDiff })
    });
  }

  recordNotApplicable(file: string, inputType: ScanInputType, stage: ScanStage, message: string): void {
    const normalizedFile = normalizeCoverageFile(file);
    this.coverageEntries.set(normalizedFile, {
      status: "not_applicable",
      file: normalizedFile,
      inputType,
      stage,
      message
    });
  }

  markRelevantToDiff(file: string): void {
    const normalizedFile = normalizeCoverageFile(file);
    const current = this.coverageEntries.get(normalizedFile);
    if (current !== undefined) {
      this.coverageEntries.set(normalizedFile, { ...current, relevantToDiff: true });
    }
  }

  coverage(): ScanCoverage {
    const entries = [...this.coverageEntries.values()].sort((left, right) => left.file.localeCompare(right.file));
    return {
      complete: entries.every((entry) => entry.status !== "incomplete"),
      entries
    };
  }

  /** Observable only for deterministic regression tests of the resource budget. */
  readStats(): { openedFiles: number; maxObservedConcurrency: number } {
    return { openedFiles: this.readFileCount, maxObservedConcurrency: this.maxObservedConcurrentReads };
  }

  private async readOnce(
    absolutePath: string,
    file: string,
    inputType: ScanInputType,
    stage: ScanStage
  ): Promise<string[] | undefined> {
    const rootRealPath = await this.resolveRootPath(file, inputType, stage);
    if (rootRealPath === undefined) return undefined;

    const initialPathState = await inspectPath(this.rootPath, rootRealPath, absolutePath);
    if (initialPathState !== "verified") {
      this.recordPathState(file, inputType, stage, initialPathState);
      return undefined;
    }

    let stats;
    try {
      stats = await lstat(absolutePath);
    } catch {
      this.recordIncomplete(file, inputType, stage, "stat_failed", "Unable to stat an expected scan input.");
      return undefined;
    }

    if (stats.isSymbolicLink()) {
      this.recordIncomplete(file, inputType, stage, "symbolic_link", "Symbolic links are not followed during source scanning.");
      return undefined;
    }

    if (!stats.isFile()) {
      this.recordIncomplete(file, inputType, stage, "read_failed", "Expected scan input is not a regular file.");
      return undefined;
    }

    if (stats.size > this.maxFileBytes) {
      this.recordIncomplete(file, inputType, stage, "file_too_large", `File exceeds the ${this.maxFileBytes}-byte scan limit.`);
      return undefined;
    }

    let handle;
    try {
      handle = await open(absolutePath, constants.O_RDONLY | constants.O_NOFOLLOW);
      const openedStats = await handle.stat();
      if (!openedStats.isFile()) {
        this.recordIncomplete(file, inputType, stage, "read_failed", "Opened scan input is not a regular file.");
        return undefined;
      }

      const openedPathState = await inspectPath(this.rootPath, rootRealPath, absolutePath, openedStats);
      if (openedPathState !== "verified") {
        this.recordPathState(file, inputType, stage, openedPathState);
        return undefined;
      }

      if (openedStats.size > this.maxFileBytes) {
        this.recordIncomplete(file, inputType, stage, "file_too_large", `File exceeds the ${this.maxFileBytes}-byte scan limit.`);
        return undefined;
      }

      if (this.readFileCount >= this.maxFiles) {
        this.recordIncomplete(file, inputType, stage, "file_limit", `Read budget reached ${this.maxFiles} files.`);
        return undefined;
      }

      if (this.readByteCount + openedStats.size > this.maxTotalBytes) {
        this.recordIncomplete(file, inputType, stage, "total_byte_limit", `Read budget exceeds ${this.maxTotalBytes} bytes.`);
        return undefined;
      }

      this.readFileCount += 1;
      this.readByteCount += openedStats.size;

      const text = await readUtf8Exactly(handle, openedStats.size);
      if (text === undefined) {
        this.recordIncomplete(file, inputType, stage, "read_failed", "Scan input changed or ended before its verified length could be read.");
        return undefined;
      }

      const finalPathState = await inspectPath(this.rootPath, rootRealPath, absolutePath, openedStats);
      if (finalPathState !== "verified") {
        this.recordPathState(file, inputType, stage, finalPathState);
        return undefined;
      }

      // A later context read may supply useful text, but must never erase an
      // earlier incomplete record that keeps a current-diff decision fail-closed.
      if (this.coverageEntries.get(file)?.status !== "incomplete") {
        this.coverageEntries.set(file, {
          status: "complete",
          file,
          inputType,
          stage,
          message: "Read through the shared bounded source reader."
        });
      }
      return text.split(/\r?\n/);
    } catch {
      this.recordIncomplete(file, inputType, stage, "read_failed", "Unable to read scan input through the bounded source reader.");
      return undefined;
    } finally {
      await handle?.close();
    }
  }

  private async resolveRootPath(
    file: string,
    inputType: ScanInputType,
    stage: ScanStage
  ): Promise<string | undefined> {
    try {
      const initialStats = await lstat(this.rootPath);
      if (initialStats.isSymbolicLink()) {
        this.recordIncomplete(file, inputType, stage, "symbolic_link", "The requested project root is a symbolic link and cannot anchor safe source scanning.");
        return undefined;
      }

      const resolvedRootPath = await realpath(this.rootPath);
      if ((await lstat(this.rootPath)).isSymbolicLink()) {
        this.recordIncomplete(file, inputType, stage, "symbolic_link", "The requested project root changed to a symbolic link during safe source setup.");
        return undefined;
      }
      return resolvedRootPath;
    } catch {
      this.recordIncomplete(file, inputType, stage, "read_failed", "Unable to resolve the requested project root for safe source scanning.");
      return undefined;
    }
  }

  private recordPathState(
    file: string,
    inputType: ScanInputType,
    stage: ScanStage,
    state: Exclude<PathState, "verified">
  ): void {
    if (state === "symbolic_link") {
      this.recordIncomplete(file, inputType, stage, state, "Symbolic links are not followed during source scanning.");
      return;
    }
    if (state === "outside_workspace") {
      this.recordIncomplete(file, inputType, stage, state, "Resolved scan input is outside the requested project root.");
      return;
    }
    this.recordIncomplete(file, inputType, stage, state, "Scan input changed while its safe path was being verified.");
  }

  private async withReadSlot<T>(action: () => Promise<T>): Promise<T> {
    if (this.activeReads >= this.maxConcurrency) {
      await new Promise<void>((resolveWaiter) => this.waiters.push(resolveWaiter));
    }
    this.activeReads += 1;
    this.maxObservedConcurrentReads = Math.max(this.maxObservedConcurrentReads, this.activeReads);
    try {
      return await action();
    } finally {
      this.activeReads -= 1;
      this.waiters.shift()?.();
    }
  }
}

type PathState = "verified" | "symbolic_link" | "outside_workspace" | "read_failed";

/**
 * A pathname is never a capability: each component can be replaced after a
 * prior check. Verify both its canonical containment and, after open, that the
 * pathname still resolves to the same file descriptor before returning bytes.
 */
async function inspectPath(
  rootPath: string,
  rootRealPath: string,
  absolutePath: string,
  openedStats?: Stats
): Promise<PathState> {
  try {
    if (await hasSymbolicLinkComponent(rootPath, absolutePath)) return "symbolic_link";

    const resolvedPath = await realpath(absolutePath);
    if (!isPathWithin(rootRealPath, resolvedPath)) return "outside_workspace";

    if (openedStats === undefined) return "verified";

    const currentStats = await stat(resolvedPath);
    return sameFile(openedStats, currentStats) ? "verified" : "read_failed";
  } catch {
    return "read_failed";
  }
}

async function hasSymbolicLinkComponent(rootPath: string, absolutePath: string): Promise<boolean> {
  const relativePath = relative(rootPath, absolutePath);
  if (relativePath.length === 0 || !isPathWithin(rootPath, absolutePath)) return false;

  let currentPath = rootPath;
  for (const component of relativePath.split(sep)) {
    currentPath = join(currentPath, component);
    if ((await lstat(currentPath)).isSymbolicLink()) return true;
  }
  return false;
}

function sameFile(left: Stats, right: Stats): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

/** Reads no more than the verified descriptor length and preserves UTF-8 across chunks. */
async function readUtf8Exactly(handle: FileHandle, byteLength: number): Promise<string | undefined> {
  if (byteLength === 0) return "";

  const buffer = Buffer.alloc(Math.min(byteLength, 64 * 1024));
  const decoder = new StringDecoder("utf8");
  let position = 0;
  let text = "";

  while (position < byteLength) {
    const { bytesRead } = await handle.read(buffer, 0, Math.min(buffer.length, byteLength - position), position);
    if (bytesRead === 0) return undefined;
    text += decoder.write(buffer.subarray(0, bytesRead));
    position += bytesRead;
  }

  return `${text}${decoder.end()}`;
}

export interface WorkspaceFileScanOptions {
  maxFileBytes?: number;
  maxFiles?: number;
}

export interface WorkspaceFileScan {
  files: string[];
  warnings: string[];
}

export async function collectWorkspaceFiles(
  rootPath: string,
  options: WorkspaceFileScanOptions = {},
  sourceReader?: SafeSourceReader
): Promise<WorkspaceFileScan> {
  const maxFileBytes = options.maxFileBytes ?? defaultMaxFileBytes;
  const maxFiles = options.maxFiles ?? defaultMaxFiles;
  const state: CollectState = {
    files: [],
    maxFileBytes,
    maxFiles,
    maxDirectories: defaultMaxDirectories,
    visitedDirectories: 0,
    skippedLargeFiles: 0,
    skippedSymlinks: 0,
    unreadableDirectories: 0,
    truncated: false
  };

  const resolvedRootPath = sourceReader?.rootPath ?? resolve(rootPath);
  const rootRealPath = await resolveDiscoveryRoot(resolvedRootPath);
  if (rootRealPath === undefined) {
    recordDiscoveryDirectoryFailure(state, sourceReader, resolvedRootPath, resolvedRootPath, "read_failed");
  } else {
    await collect(resolvedRootPath, state, sourceReader, resolvedRootPath, rootRealPath);
  }
  state.files.sort((left, right) => left.localeCompare(right));

  const warnings: string[] = [];

  if (state.truncated) {
    warnings.push(
      `Workspace discovery stopped at the ${maxFiles}-file or ${defaultMaxDirectories}-directory limit; scan results are incomplete. Point the scan at a narrower directory.`
    );
  }

  if (state.skippedLargeFiles > 0) {
    warnings.push(
      `${state.skippedLargeFiles} file(s) larger than ${Math.round(maxFileBytes / 1024)} KiB were skipped and not scanned.`
    );
  }

  if (state.skippedSymlinks > 0) {
    warnings.push(
      `${state.skippedSymlinks} symbolic link(s) were not followed; linked code outside the project was not scanned.`
    );
  }

  if (state.unreadableDirectories > 0) {
    warnings.push(`${state.unreadableDirectories} directory/directories could not be read and were skipped.`);
  }

  return { files: state.files, warnings };
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

/**
 * Removes a TOML `#` comment, ignoring `#` characters inside quoted strings so
 * that values such as a git URL fragment survive.
 */
export function stripTomlComment(line: string): string {
  let inString = false;
  let quote = "";

  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];

    if (inString) {
      if (char === "\\") {
        index += 1;
        continue;
      }
      if (char === quote) inString = false;
      continue;
    }

    if (char === '"' || char === "'") {
      inString = true;
      quote = char;
      continue;
    }

    if (char === "#") {
      return line.slice(0, index);
    }
  }

  return line;
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

/** Matches `.cargo/config.toml` and the legacy extension-less `.cargo/config`. */
export function isCargoConfigPath(path: string): boolean {
  const name = basename(path);
  if (name !== "config.toml" && name !== "config") return false;
  return basename(dirname(path)) === ".cargo";
}

interface CollectState {
  files: string[];
  maxFileBytes: number;
  maxFiles: number;
  maxDirectories: number;
  visitedDirectories: number;
  skippedLargeFiles: number;
  skippedSymlinks: number;
  unreadableDirectories: number;
  truncated: boolean;
}

async function collect(
  directory: string,
  state: CollectState,
  sourceReader: SafeSourceReader | undefined,
  rootPath: string,
  rootRealPath: string
): Promise<void> {
  if (state.truncated) return;

  if (state.visitedDirectories >= state.maxDirectories) {
    state.truncated = true;
    sourceReader?.recordIncomplete(
      discoveryCoverageFile(rootPath, directory),
      "rust",
      "discovery",
      "discovery_truncated",
      `Directory discovery reached the ${state.maxDirectories}-directory limit.`
    );
    return;
  }

  const initialState = await verifyDiscoveryDirectory(rootPath, rootRealPath, directory);
  if (initialState !== "verified") {
    recordDiscoveryDirectoryFailure(state, sourceReader, rootPath, directory, initialState);
    return;
  }

  let directoryHandle: Dir | undefined;
  try {
    directoryHandle = await opendir(directory);
    state.visitedDirectories += 1;

    // opendir() resolves the path a second time. Check that exact path before
    // consuming entries so a link swap cannot turn this into external traversal.
    const openedState = await verifyDiscoveryDirectory(rootPath, rootRealPath, directory);
    if (openedState !== "verified") {
      recordDiscoveryDirectoryFailure(state, sourceReader, rootPath, directory, openedState);
      return;
    }

    for await (const entry of directoryHandle) {
      if (state.truncated) return;

      const absolutePath = join(directory, entry.name);

      if (entry.isSymbolicLink()) {
        state.skippedSymlinks += 1;
        sourceReader?.recordIncomplete(toRelativeFile(rootPath, absolutePath), inputTypeForPath(absolutePath), "discovery", "symbolic_link", "Symbolic links are not followed during discovery.");
        continue;
      }

      if (entry.isDirectory()) {
        if (!ignoredDirectoryNames.has(entry.name)) {
          await collect(absolutePath, state, sourceReader, rootPath, rootRealPath);
        }
        continue;
      }

      if (!entry.isFile()) continue;

      if (!(await isWithinSizeLimit(absolutePath, state, sourceReader))) continue;

      if (state.files.length >= state.maxFiles) {
        state.truncated = true;
        sourceReader?.recordIncomplete(toRelativeFile(rootPath, absolutePath), inputTypeForPath(absolutePath), "discovery", "discovery_truncated", `File discovery reached the ${state.maxFiles}-file limit.`);
        return;
      }

      state.files.push(absolutePath);
    }

    const finalState = await verifyDiscoveryDirectory(rootPath, rootRealPath, directory);
    if (finalState !== "verified") {
      recordDiscoveryDirectoryFailure(state, sourceReader, rootPath, directory, finalState);
    }
  } catch {
    recordDiscoveryDirectoryFailure(state, sourceReader, rootPath, directory, "read_failed");
  } finally {
    await directoryHandle?.close().catch(() => undefined);
  }
}

async function isWithinSizeLimit(absolutePath: string, state: CollectState, sourceReader: SafeSourceReader | undefined): Promise<boolean> {
  // Only files the scanners actually read need a size check.
  if (
    !isRustSourcePath(absolutePath) &&
    !isCargoTomlPath(absolutePath) &&
    !isCargoLockPath(absolutePath) &&
    !isCargoConfigPath(absolutePath)
  ) {
    return true;
  }

  try {
    const stats = await lstat(absolutePath);
    if (stats.isSymbolicLink()) {
      state.skippedSymlinks += 1;
      sourceReader?.recordIncomplete(toRelativeFile(rootDirectory(state, sourceReader), absolutePath), inputTypeForPath(absolutePath), "discovery", "symbolic_link", "Symbolic links are not followed during discovery.");
      return false;
    }
    if (stats.size > state.maxFileBytes) {
      state.skippedLargeFiles += 1;
      sourceReader?.recordIncomplete(toRelativeFile(rootDirectory(state, sourceReader), absolutePath), inputTypeForPath(absolutePath), "discovery", "file_too_large", `File exceeds the ${state.maxFileBytes}-byte discovery limit.`);
      return false;
    }
  } catch {
    sourceReader?.recordIncomplete(toRelativeFile(rootDirectory(state, sourceReader), absolutePath), inputTypeForPath(absolutePath), "discovery", "stat_failed", "Unable to stat file during discovery.");
    return false;
  }

  return true;
}

async function resolveDiscoveryRoot(rootPath: string): Promise<string | undefined> {
  try {
    const initialStats = await lstat(rootPath);
    if (initialStats.isSymbolicLink() || !initialStats.isDirectory()) return undefined;
    const rootRealPath = await realpath(rootPath);
    const finalStats = await lstat(rootPath);
    return finalStats.isSymbolicLink() || !finalStats.isDirectory() ? undefined : rootRealPath;
  } catch {
    return undefined;
  }
}

async function verifyDiscoveryDirectory(rootPath: string, rootRealPath: string, directory: string): Promise<PathState> {
  const pathState = await inspectPath(rootPath, rootRealPath, directory);
  if (pathState !== "verified") return pathState;

  try {
    return (await lstat(directory)).isDirectory() ? "verified" : "read_failed";
  } catch {
    return "read_failed";
  }
}

function recordDiscoveryDirectoryFailure(
  state: CollectState,
  sourceReader: SafeSourceReader | undefined,
  rootPath: string,
  directory: string,
  pathState: Exclude<PathState, "verified">
): void {
  if (pathState === "symbolic_link") {
    state.skippedSymlinks += 1;
    sourceReader?.recordIncomplete(
      discoveryCoverageFile(rootPath, directory),
      "rust",
      "discovery",
      "symbolic_link",
      "Symbolic links are not followed during discovery."
    );
    return;
  }

  state.unreadableDirectories += 1;
  const reason = pathState === "outside_workspace" ? "outside_workspace" : "read_failed";
  const message =
    pathState === "outside_workspace"
      ? "Resolved discovery directory is outside the requested project root."
      : "Unable to enumerate directory during discovery.";
  sourceReader?.recordIncomplete(discoveryCoverageFile(rootPath, directory), "rust", "discovery", reason, message);
}

function discoveryCoverageFile(rootPath: string, directory: string): string {
  const file = toRelativeFile(rootPath, directory);
  return file.length === 0 ? "." : file;
}

function isPathWithin(rootPath: string, candidate: string): boolean {
  const relativePath = relative(rootPath, candidate);
  return relativePath.length === 0 || (!relativePath.startsWith(`..${sep}`) && relativePath !== ".." && !isAbsolute(relativePath));
}

function normalizeCoverageFile(file: string): string {
  return file.split(sep).join("/");
}

function inputTypeForPath(path: string): ScanInputType {
  if (isCargoTomlPath(path)) return "cargo_toml";
  if (isCargoLockPath(path)) return "cargo_lock";
  if (isCargoConfigPath(path)) return "cargo_config";
  if (isBuildScriptPath(path)) return "build_script";
  return "rust";
}

function rootDirectory(_state: CollectState, sourceReader: SafeSourceReader | undefined): string {
  return sourceReader?.rootPath ?? ".";
}
