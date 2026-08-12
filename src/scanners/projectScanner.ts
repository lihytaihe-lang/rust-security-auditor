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
  rustSourceFiles: ProjectFile[];
  workspaceManifests: WorkspaceManifest[];
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
      ...project.discoveryWarnings
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
  const rustSourceFiles: ProjectFile[] = [];
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
      rustSourceFiles.push({ file, absolutePath, line: 1 });
    }
  }

  return {
    workspacePath,
    isRustProject: cargoTomlFiles.length > 0,
    cargoTomlFiles,
    cargoLockFiles,
    cargoConfigFiles,
    buildScripts,
    rustSourceFiles,
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
