import { posix } from "node:path";
import { classifyRustSourceFile, type RustTargetKind } from "./cargoTargets.js";
import type { ScannerContext, ScannerResult, SecurityScanner } from "./types.js";
import {
  collectWorkspaceFiles,
  firstMeaningfulLine,
  isBuildScriptPath,
  isCargoConfigPath,
  isCargoLockPath,
  isCargoTomlPath,
  isRustSourcePath,
  quotedTomlStrings,
  SafeSourceReader,
  type ScanCoverage,
  toRelativeFile
} from "./scannerUtils.js";

export interface ProjectFile {
  file: string;
  absolutePath: string;
  line: number;
}

export interface RustSourceFile extends ProjectFile {
  /** How Cargo reaches this file, or that it reaches it at all. */
  targetKind: RustTargetKind;
  /** Workspace-relative directory of the owning manifest; `""` is the root. */
  crateDirectory: string | undefined;
}

export interface RustTargetSummary {
  shipped: number;
  buildScript: number;
  development: number;
  unreferenced: number;
}

export interface WorkspaceManifest extends ProjectFile {
  members: string[];
}

export interface RustProject {
  workspacePath: string;
  isRustProject: boolean;
  cargoTomlFiles: ProjectFile[];
  cargoLockFiles: ProjectFile[];
  cargoConfigFiles: ProjectFile[];
  buildScripts: ProjectFile[];
  rustSourceFiles: RustSourceFile[];
  workspaceManifests: WorkspaceManifest[];
  /** Counts per Cargo target kind, so an exclusion is always reportable. */
  rustTargetSummary: RustTargetSummary;
  /** Discovery-time limits that were hit, such as skipped symlinks or oversized files. */
  discoveryWarnings: string[];
  /** Per-tool-call bounded source capability, intentionally not serialized into reports. */
  sourceReader: SafeSourceReader;
  scanCoverage: ScanCoverage;
}

export interface ProjectScannerResult extends ScannerResult {
  project: RustProject;
}

export class ProjectScanner implements SecurityScanner<ScannerContext> {
  readonly name = "ProjectScanner";

  async scan(options: ScannerContext): Promise<ProjectScannerResult> {
    const project = await discoverRustProject(options.workspacePath, options.sourceReader);
    const warnings = [
      ...(project.isRustProject ? [] : [`No Cargo.toml files found under ${options.workspacePath}`]),
      ...project.discoveryWarnings,
      ...describeSkippedRustTargets(project.rustTargetSummary, options.includeNonShippedSources === true)
    ];

    return {
      project,
      findings: [],
      warnings,
      scanCoverage: project.sourceReader.coverage()
    };
  }
}

export async function discoverRustProject(workspacePath: string, existingReader?: SafeSourceReader): Promise<RustProject> {
  const sourceReader = existingReader ?? new SafeSourceReader(workspacePath);
  const { files, warnings } = await collectWorkspaceFiles(workspacePath, {}, sourceReader);
  const cargoTomlFiles: ProjectFile[] = [];
  const cargoLockFiles: ProjectFile[] = [];
  const cargoConfigFiles: ProjectFile[] = [];
  const buildScripts: ProjectFile[] = [];
  const discoveredRustFiles: ProjectFile[] = [];
  const workspaceManifests: WorkspaceManifest[] = [];

  for (const absolutePath of files) {
    const file = toRelativeFile(workspacePath, absolutePath);

    if (isCargoTomlPath(absolutePath)) {
      const lines = await sourceReader.readTextLines(absolutePath, file, "cargo_toml", "discovery");
      cargoTomlFiles.push({ file, absolutePath, line: 1 });
      if (lines !== undefined) {
        const workspace = workspaceManifest(file, absolutePath, lines);
        if (workspace !== undefined) {
          workspaceManifests.push(workspace);
        }
      }
      continue;
    }

    if (isCargoLockPath(absolutePath)) {
      cargoLockFiles.push({ file, absolutePath, line: 1 });
      continue;
    }

    if (isCargoConfigPath(absolutePath)) {
      cargoConfigFiles.push({ file, absolutePath, line: 1 });
      continue;
    }

    if (isBuildScriptPath(absolutePath)) {
      const lines = await sourceReader.readTextLines(absolutePath, file, "build_script", "discovery");
      buildScripts.push({ file, absolutePath, line: firstMeaningfulLine(lines ?? []) });
    }

    if (isRustSourcePath(absolutePath)) {
      discoveredRustFiles.push({ file, absolutePath, line: 1 });
    }
  }

  // Classification needs every manifest, so it runs after discovery rather than
  // inside the loop: a manifest can sort after the sources it owns.
  const manifestDirectories = new Set(
    cargoTomlFiles.map((manifest) => {
      const directory = posix.dirname(manifest.file);
      return directory === "." ? "" : directory;
    })
  );
  const rustSourceFiles: RustSourceFile[] = discoveredRustFiles.map((source) => ({
    ...source,
    ...classifyRustSourceFile(source.file, manifestDirectories)
  }));

  return {
    workspacePath,
    isRustProject: cargoTomlFiles.length > 0,
    cargoTomlFiles,
    cargoLockFiles,
    cargoConfigFiles,
    buildScripts,
    rustSourceFiles,
    rustTargetSummary: summarizeRustTargets(rustSourceFiles),
    workspaceManifests,
    discoveryWarnings: warnings,
    sourceReader,
    scanCoverage: sourceReader.coverage()
  };
}

function workspaceManifest(
  file: string,
  absolutePath: string,
  lines: readonly string[]
): WorkspaceManifest | undefined {
  const workspaceIndex = lines.findIndex((line) => /^\s*\[workspace\]\s*$/.test(line));
  if (workspaceIndex === -1) return undefined;

  const workspaceLines = lines.slice(workspaceIndex + 1, nextSectionIndex(lines, workspaceIndex + 1));
  const members: string[] = [];
  let collectingMembers = false;

  for (const line of workspaceLines) {
    const trimmed = line.trim();

    if (/^members\s*=/.test(trimmed)) {
      members.push(...quotedTomlStrings(trimmed));
      collectingMembers = trimmed.includes("[") && !trimmed.includes("]");
      continue;
    }

    if (collectingMembers) {
      members.push(...quotedTomlStrings(trimmed));
      if (trimmed.includes("]")) {
        collectingMembers = false;
      }
    }
  }

  return {
    file,
    absolutePath,
    line: workspaceIndex + 1,
    members
  };
}

function nextSectionIndex(lines: readonly string[], startIndex: number): number {
  const index = lines.findIndex((line, currentIndex) => currentIndex >= startIndex && /^\s*\[[^\]]+\]\s*$/.test(line));
  return index === -1 ? lines.length : index;
}

export function summarizeRustTargets(files: readonly RustSourceFile[]): RustTargetSummary {
  return {
    shipped: files.filter((file) => file.targetKind === "shipped").length,
    buildScript: files.filter((file) => file.targetKind === "build_script").length,
    development: files.filter((file) => file.targetKind === "development").length,
    unreferenced: files.filter((file) => file.targetKind === "unreferenced").length
  };
}

/**
 * A skipped file must never be invisible. When the scan is limited to what
 * Cargo builds, the report states how many files were left out and why, so a
 * lower finding count is explained rather than merely smaller.
 */
export function describeSkippedRustTargets(summary: RustTargetSummary, includeNonShipped: boolean): string[] {
  const skipped = summary.development + summary.unreferenced;
  if (includeNonShipped || skipped === 0) return [];

  const parts = [
    summary.development === 0 ? undefined : `${summary.development} test/benchmark/example target file(s)`,
    summary.unreferenced === 0 ? undefined : `${summary.unreferenced} file(s) no Cargo target reaches`
  ].filter((part): part is string => part !== undefined);

  // Phrased as an exclusion rather than as what was scanned, because each tool
  // reads a different subset of the Cargo-built files.
  return [
    `Excluded ${skipped} Rust file(s) from source scanning: ${parts.join(", ")}. Set includeNonShippedSources to include them.`
  ];
}
