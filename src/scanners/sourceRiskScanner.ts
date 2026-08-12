import type { Finding } from "../reports/schemas.js";
import { createScannerFinding, lineEvidence } from "./findingUtils.js";
import { discoverRustProject, type RustProject } from "./projectScanner.js";
import { finalizeScannerResult } from "./resultUtils.js";
import { findTestCodeLines, isImportLine, maskRustSource } from "./rustLexer.js";
import { isBuildScriptPath } from "./scannerUtils.js";
import type { ScannerContext, ScannerResult, SecurityScanner } from "./types.js";

export interface SourceRiskScannerContext extends ScannerContext {
  project?: RustProject;
}

/**
 * Risk signals in shipped Rust source that are not about unsafe or Cargo
 * metadata. Build scripts are excluded because build-time process execution is
 * already covered by RSA-BUILD-COMMAND.
 */
export class SourceRiskScanner implements SecurityScanner<SourceRiskScannerContext> {
  readonly name = "SourceRiskScanner";

  async scan(options: SourceRiskScannerContext): Promise<ScannerResult> {
    const project = options.project ?? (await discoverRustProject(options.workspacePath, options.sourceReader));
    const findings: Finding[] = [];

    for (const sourceFile of project.rustSourceFiles) {
      if (isBuildScriptPath(sourceFile.absolutePath)) continue;

      const lines = await project.sourceReader.readTextLines(sourceFile.absolutePath, sourceFile.file, "rust", "source_risk_scan");
      if (lines === undefined) continue;
      const masked = maskRustSource(lines);
      if (!masked.isComplete) {
        project.sourceReader.recordIncomplete(
          sourceFile.file,
          "rust",
          "source_risk_scan",
          "lexical_incomplete",
          `Rust lexical analysis is incomplete (${masked.limitation ?? "unknown limitation"}); test-only severity reductions were disabled.`
        );
      }
      findings.push(...scanSourceRiskLines(sourceFile.file, lines, masked));
    }

    return await finalizeScannerResult(options.workspacePath, findings, [], {
      includeSuppressed: options.includeSuppressed === true,
      sourceReader: project.sourceReader
    });
  }
}

export function scanSourceRiskText(file: string, source: string): Finding[] {
  return scanSourceRiskLines(file, source.split(/\r?\n/));
}

function scanSourceRiskLines(file: string, lines: readonly string[], masked = maskRustSource(lines)): Finding[] {
  const testLines = findTestCodeLines(masked.withoutLiterals, masked.isComplete);
  const findings: Finding[] = [];

  masked.withoutLiterals.forEach((codeLine, index) => {
    if (codeLine.trim().length === 0) return;
    if (isImportLine(codeLine)) return;
    if (!/\bCommand::new\s*\(/.test(codeLine)) return;

    const lineNumber = index + 1;
    const inTestCode = testLines.has(lineNumber);

    findings.push(
      createScannerFinding({
        ruleId: "RSA-EXEC-COMMAND",
        file,
        line: lineNumber,
        evidence: [lineEvidence(lineNumber, lines[index] ?? codeLine)],
        ...(inTestCode
          ? {
              severity: "low" as const,
              falsePositiveNotes:
                "Located in #[cfg(test)] code, so severity is reduced; test-only code does not ship."
            }
          : {})
      })
    );
  });

  return findings;
}
