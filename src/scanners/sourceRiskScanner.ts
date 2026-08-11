import type { Finding } from "../reports/schemas.js";
import { createScannerFinding, lineEvidence } from "./findingUtils.js";
import { discoverRustProject, type RustProject } from "./projectScanner.js";
import { finalizeScannerResult } from "./resultUtils.js";
import { findTestCodeLines, isImportLine, maskRustSource } from "./rustLexer.js";
import { isBuildScriptPath, readTextLines } from "./scannerUtils.js";
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
    const project = options.project ?? (await discoverRustProject(options.workspacePath));
    const findings: Finding[] = [];

    for (const sourceFile of project.rustSourceFiles) {
      if (isBuildScriptPath(sourceFile.absolutePath)) continue;

      const lines = await readTextLines(sourceFile.absolutePath);
      findings.push(...scanSourceRiskLines(sourceFile.file, lines));
    }

    return await finalizeScannerResult(options.workspacePath, findings, [], {
      includeSuppressed: options.includeSuppressed === true
    });
  }
}

export function scanSourceRiskText(file: string, source: string): Finding[] {
  return scanSourceRiskLines(file, source.split(/\r?\n/));
}

function scanSourceRiskLines(file: string, lines: readonly string[]): Finding[] {
  const masked = maskRustSource(lines);
  const testLines = findTestCodeLines(masked.withoutLiterals);
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
