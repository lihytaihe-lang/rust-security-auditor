import type { Finding } from "../reports/schemas.js";
import { createScannerFinding, lineEvidence } from "./findingUtils.js";
import { discoverRustProject, type RustProject } from "./projectScanner.js";
import { finalizeScannerResult } from "./resultUtils.js";
import { isImportLine, maskRustSource } from "./rustLexer.js";
import type { RuleId } from "./rules.js";
import { firstMeaningfulLine, stripTomlComment } from "./scannerUtils.js";
import type { ScannerContext, ScannerResult, SecurityScanner } from "./types.js";

export interface DependencyScannerContext extends ScannerContext {
  project?: RustProject;
}

export class DependencyScanner implements SecurityScanner<DependencyScannerContext> {
  readonly name = "DependencyScanner";

  async scan(options: DependencyScannerContext): Promise<ScannerResult> {
    const project = options.project ?? (await discoverRustProject(options.workspacePath, options.sourceReader));
    const findings: Finding[] = [];

    for (const manifest of project.cargoTomlFiles) {
      const lines = await project.sourceReader.readTextLines(manifest.absolutePath, manifest.file, "cargo_toml", "dependency_scan");
      if (lines === undefined) continue;
      findings.push(...scanManifestLines(manifest.file, lines));
    }

    for (const lockfile of project.cargoLockFiles) {
      const lines = await project.sourceReader.readTextLines(lockfile.absolutePath, lockfile.file, "cargo_lock", "dependency_scan");
      if (lines === undefined) continue;
      lines.forEach((line, index) => {
        if (/^\s*source\s*=\s*"git\+/.test(line)) {
          findings.push(createSimpleFinding("RSA-DEP-LOCK-GIT", lockfile.file, index + 1, line));
        }
      });
    }

    for (const config of project.cargoConfigFiles) {
      const lines = await project.sourceReader.readTextLines(config.absolutePath, config.file, "cargo_config", "dependency_scan");
      if (lines === undefined) continue;
      findings.push(...scanCargoConfigLines(config.file, lines));
    }

    for (const buildScript of project.buildScripts) {
      const lines = await project.sourceReader.readTextLines(buildScript.absolutePath, buildScript.file, "build_script", "dependency_scan");
      if (lines === undefined) continue;
      findings.push(...scanBuildScriptLines(buildScript.file, lines));
    }

    return await finalizeScannerResult(options.workspacePath, findings, [], {
      includeSuppressed: options.includeSuppressed === true,
      sourceReader: project.sourceReader
    });
  }
}

export function scanCargoManifestText(file: string, source: string): Finding[] {
  return scanManifestLines(file, source.split(/\r?\n/));
}

export function scanCargoLockText(file: string, source: string): Finding[] {
  const findings: Finding[] = [];

  source.split(/\r?\n/).forEach((line, index) => {
    if (/^\s*source\s*=\s*"git\+/.test(line)) {
      findings.push(createSimpleFinding("RSA-DEP-LOCK-GIT", file, index + 1, line));
    }
  });

  return findings;
}

export function scanCargoConfigText(file: string, source: string): Finding[] {
  return scanCargoConfigLines(file, source.split(/\r?\n/));
}

export function scanBuildScriptText(file: string, source: string): Finding[] {
  return scanBuildScriptLines(file, source.split(/\r?\n/));
}

function scanManifestLines(file: string, lines: readonly string[]): Finding[] {
  const findings: Finding[] = [];
  let section = "";

  lines.forEach((line, index) => {
    const code = stripTomlComment(line);
    if (code.trim().length === 0) return;

    const nextSection = parseTomlSection(code);
    if (nextSection !== undefined) {
      section = nextSection;
      if (isBuildDependencySection(section)) {
        findings.push(createSimpleFinding("RSA-DEP-BUILD-DEPENDENCIES", file, index + 1, line));
      }
      return;
    }

    findings.push(...findManifestLineFindings(file, index + 1, code, line, section));
  });

  return findings;
}

function scanCargoConfigLines(file: string, lines: readonly string[]): Finding[] {
  const findings: Finding[] = [];
  let section = "";

  lines.forEach((line, index) => {
    const code = stripTomlComment(line);
    if (code.trim().length === 0) return;

    const nextSection = parseTomlSection(code);
    if (nextSection !== undefined) {
      section = nextSection;
      return;
    }

    if (/^\s*replace-with\s*=/.test(code) && /^source(?:\.|$)/.test(section)) {
      findings.push(createSimpleFinding("RSA-CARGO-SOURCE-REPLACEMENT", file, index + 1, line));
    }

    if (/^\s*runner\s*=/.test(code)) {
      findings.push(createSimpleFinding("RSA-CARGO-RUNNER", file, index + 1, line));
    }
  });

  return findings;
}

function scanBuildScriptLines(file: string, lines: readonly string[]): Finding[] {
  const findings: Finding[] = [buildScriptFinding(file, firstMeaningfulLine(lines), lines)];
  const masked = maskRustSource(lines);

  masked.withoutLiterals.forEach((codeLine, index) => {
    const commentFreeLine = masked.withoutComments[index] ?? codeLine;

    if (isImportLine(codeLine)) return;

    if (/\bCommand::new\s*\(/.test(codeLine) || /\bsh\s+-c\b|\bcmd\s+\/C\b/.test(commentFreeLine)) {
      findings.push(createSimpleFinding("RSA-BUILD-COMMAND", file, index + 1, lines[index] ?? codeLine));
    }
  });

  return findings;
}

function findManifestLineFindings(
  file: string,
  lineNumber: number,
  code: string,
  sourceLine: string,
  section: string
): Finding[] {
  const findings: Finding[] = [];
  const dependencySection = isDependencySection(section);

  if (dependencySection && /\bgit\s*=/.test(code)) {
    findings.push(createSimpleFinding("RSA-DEP-GIT", file, lineNumber, sourceLine));
  }

  if (dependencySection && /\bpath\s*=/.test(code)) {
    findings.push(createSimpleFinding("RSA-DEP-PATH", file, lineNumber, sourceLine));
  }

  if (/\bproc-macro\s*=\s*true\b/.test(code)) {
    findings.push(createSimpleFinding("RSA-DEP-PROC-MACRO", file, lineNumber, sourceLine));
  }

  if (dependencySection && unboundedVersionRequirement(code) !== undefined) {
    findings.push(createSimpleFinding("RSA-DEP-VERSION-UNBOUNDED", file, lineNumber, sourceLine));
  }

  return findings;
}

/** Keys inside a dependency table whose string value is not a version requirement. */
const nonVersionDependencyKeys = new Set([
  "git",
  "path",
  "branch",
  "tag",
  "rev",
  "package",
  "registry",
  "registry-index",
  "features",
  "default-features",
  "default_features",
  "optional",
  "workspace"
]);

export function unboundedVersionRequirement(code: string): string | undefined {
  const explicit = /\bversion\s*=\s*"([^"]*)"/.exec(code);
  if (explicit?.[1] !== undefined) {
    return isUnboundedRequirement(explicit[1]) ? explicit[1] : undefined;
  }

  const simple = /^\s*([A-Za-z0-9_.-]+)\s*=\s*"([^"]*)"\s*$/.exec(code);
  const key = simple?.[1];
  const value = simple?.[2];
  if (key === undefined || value === undefined || nonVersionDependencyKeys.has(key)) {
    return undefined;
  }

  return isUnboundedRequirement(value) ? value : undefined;
}

function isUnboundedRequirement(requirement: string): boolean {
  const value = requirement.trim();
  if (value.length === 0) return true;
  if (value.includes("*")) return true;

  // A comparator with no upper bound, such as ">=1.0". A comma means the
  // requirement has a second comparator and is treated as bounded.
  return /^>=?[^,]*$/.test(value);
}

function buildScriptFinding(file: string, lineNumber: number, lines: readonly string[]): Finding {
  const evidenceLine = lines[lineNumber - 1] ?? "build.rs";

  return createScannerFinding({
    ruleId: "RSA-BUILD-SCRIPT",
    file,
    line: lineNumber,
    evidence: [lineEvidence(lineNumber, evidenceLine)]
  });
}

function createSimpleFinding(ruleId: RuleId, file: string, lineNumber: number, line: string): Finding {
  return createScannerFinding({
    ruleId,
    file,
    line: lineNumber,
    evidence: [lineEvidence(lineNumber, line)]
  });
}

function parseTomlSection(line: string): string | undefined {
  const match = /^\s*\[([^\]]+)\]\s*$/.exec(line);
  return match?.[1]?.trim();
}

function isDependencySection(section: string): boolean {
  return (
    section === "dependencies" ||
    section === "dev-dependencies" ||
    section === "build-dependencies" ||
    /^dependencies\./.test(section) ||
    /^dev-dependencies\./.test(section) ||
    /^build-dependencies\./.test(section) ||
    /^workspace\.dependencies/.test(section) ||
    /^target\..+\.dependencies$/.test(section) ||
    /^target\..+\.dev-dependencies$/.test(section) ||
    /^target\..+\.build-dependencies$/.test(section)
  );
}

function isBuildDependencySection(section: string): boolean {
  return section === "build-dependencies" || /^target\..+\.build-dependencies$/.test(section);
}
