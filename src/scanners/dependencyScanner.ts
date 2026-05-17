import type { Finding } from "../reports/schemas.js";
import { createScannerFinding, lineEvidence } from "./findingUtils.js";
import { discoverRustProject, type RustProject } from "./projectScanner.js";
import { finalizeScannerResult } from "./resultUtils.js";
import type { RuleId } from "./rules.js";
import { firstMeaningfulLine, isCommentOnlyLine, readTextLines } from "./scannerUtils.js";
import type { ScannerContext, ScannerResult, SecurityScanner } from "./types.js";

export interface DependencyScannerContext extends ScannerContext {
  project?: RustProject;
}

export class DependencyScanner implements SecurityScanner<DependencyScannerContext> {
  readonly name = "DependencyScanner";

  async scan(options: DependencyScannerContext): Promise<ScannerResult> {
    const project = options.project ?? (await discoverRustProject(options.workspacePath));
    const findings: Finding[] = [];

    for (const manifest of project.cargoTomlFiles) {
      const lines = await readTextLines(manifest.absolutePath);
      let section = "";

      lines.forEach((line, index) => {
        if (isCommentOnlyLine(line)) return;

        const nextSection = parseTomlSection(line);
        if (nextSection !== undefined) {
          section = nextSection;
          if (isBuildDependencySection(section)) {
            findings.push(createSimpleFinding("RSA-DEP-BUILD-DEPENDENCIES", manifest.file, index + 1, line));
          }
          return;
        }

        findings.push(...findManifestLineFindings(manifest.file, index + 1, line, section));
      });
    }

    for (const lockfile of project.cargoLockFiles) {
      const lines = await readTextLines(lockfile.absolutePath);
      lines.forEach((line, index) => {
        if (/^\s*source\s*=\s*"git\+/.test(line)) {
          findings.push(createSimpleFinding("RSA-DEP-LOCK-GIT", lockfile.file, index + 1, line));
        }
      });
    }

    for (const buildScript of project.buildScripts) {
      const lines = await readTextLines(buildScript.absolutePath);
      findings.push(buildScriptFinding(buildScript.file, firstMeaningfulLine(lines), lines));

      lines.forEach((line, index) => {
        if (isCommentOnlyLine(line)) return;
        if (/\bCommand::new\s*\(|\bsh\s+-c\b|\bcmd\s+\/C\b|\bCommand::new\s*\(\s*["'](?:sh|cmd)["']/.test(line)) {
          findings.push(createSimpleFinding("RSA-BUILD-COMMAND", buildScript.file, index + 1, line));
        }
      });
    }

    return await finalizeScannerResult(options.workspacePath, findings, [], {
      includeSuppressed: options.includeSuppressed === true
    });
  }
}

export function scanCargoManifestText(file: string, source: string): Finding[] {
  const findings: Finding[] = [];
  let section = "";

  source.split(/\r?\n/).forEach((line, index) => {
    if (isCommentOnlyLine(line)) return;

    const nextSection = parseTomlSection(line);
    if (nextSection !== undefined) {
      section = nextSection;
      if (isBuildDependencySection(section)) {
        findings.push(createSimpleFinding("RSA-DEP-BUILD-DEPENDENCIES", file, index + 1, line));
      }
      return;
    }

    findings.push(...findManifestLineFindings(file, index + 1, line, section));
  });

  return findings;
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

export function scanBuildScriptText(file: string, source: string): Finding[] {
  const findings: Finding[] = [];
  const lines = source.split(/\r?\n/);

  findings.push(buildScriptFinding(file, firstMeaningfulLine(lines), lines));

  lines.forEach((line, index) => {
    if (isCommentOnlyLine(line)) return;
    if (/\bCommand::new\s*\(|\bsh\s+-c\b|\bcmd\s+\/C\b|\bCommand::new\s*\(\s*["'](?:sh|cmd)["']/.test(line)) {
      findings.push(createSimpleFinding("RSA-BUILD-COMMAND", file, index + 1, line));
    }
  });

  return findings;
}

function findManifestLineFindings(file: string, lineNumber: number, line: string, section: string): Finding[] {
  const findings: Finding[] = [];
  const dependencySection = isDependencySection(section);

  if (dependencySection && /\bgit\s*=/.test(line)) {
    findings.push(createSimpleFinding("RSA-DEP-GIT", file, lineNumber, line));
  }

  if (dependencySection && /\bpath\s*=/.test(line)) {
    findings.push(createSimpleFinding("RSA-DEP-PATH", file, lineNumber, line));
  }

  if (/\bproc-macro\s*=\s*true\b/.test(line)) {
    findings.push(createSimpleFinding("RSA-DEP-PROC-MACRO", file, lineNumber, line));
  }

  return findings;
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
    /^target\..+\.dependencies$/.test(section) ||
    /^target\..+\.dev-dependencies$/.test(section) ||
    /^target\..+\.build-dependencies$/.test(section)
  );
}

function isBuildDependencySection(section: string): boolean {
  return section === "build-dependencies" || /^target\..+\.build-dependencies$/.test(section);
}
