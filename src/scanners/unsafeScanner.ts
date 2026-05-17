import type { Finding } from "../reports/schemas.js";
import { createScannerFinding, lineEvidence } from "./findingUtils.js";
import { discoverRustProject, type RustProject } from "./projectScanner.js";
import { finalizeScannerResult } from "./resultUtils.js";
import type { RuleId } from "./rules.js";
import { isCommentOnlyLine, readTextLines } from "./scannerUtils.js";
import type { ScannerContext, ScannerResult, SecurityScanner } from "./types.js";

export interface UnsafeScannerContext extends ScannerContext {
  project?: RustProject;
}

export class UnsafeScanner implements SecurityScanner<UnsafeScannerContext> {
  readonly name = "UnsafeScanner";

  async scan(options: UnsafeScannerContext): Promise<ScannerResult> {
    const project = options.project ?? (await discoverRustProject(options.workspacePath));
    const findings: Finding[] = [];

    for (const sourceFile of project.rustSourceFiles) {
      const lines = await readTextLines(sourceFile.absolutePath);

      lines.forEach((line, index) => {
        if (isCommentOnlyLine(line)) return;

        const lineNumber = index + 1;
        findings.push(...findUnsafeLineFindings(sourceFile.file, lineNumber, line, lines, index));
      });
    }

    return await finalizeScannerResult(options.workspacePath, findings, [], {
      includeSuppressed: options.includeSuppressed === true
    });
  }
}

function findUnsafeLineFindings(
  file: string,
  lineNumber: number,
  line: string,
  lines: readonly string[],
  lineIndex: number
): Finding[] {
  const findings: Finding[] = [];

  if (/\bunsafe\s+impl\b[^{}\n;]*\bSend\b/.test(line)) {
    findings.push(createSimpleFinding("RSA-UNSAFE-IMPL-SEND", file, lineNumber, line));
  }

  if (/\bunsafe\s+impl\b[^{}\n;]*\bSync\b/.test(line)) {
    findings.push(createSimpleFinding("RSA-UNSAFE-IMPL-SYNC", file, lineNumber, line));
  }

  if (/\bunsafe\s+(?:extern\s+"C"\s+)?fn\b/.test(line)) {
    findings.push(createSimpleFinding("RSA-UNSAFE-FN", file, lineNumber, line));
  }

  if (/\bextern\s+"C"/.test(line)) {
    findings.push(createSimpleFinding("RSA-FFI-EXTERN-C", file, lineNumber, line));
  }

  if (/\bunsafe\s*\{/.test(line)) {
    findings.push(createUnsafeBlockFinding(file, lineNumber, line, lines, lineIndex));
  }

  if (/\b(?:std::mem::|mem::)?transmute\s*(?:::<[^>]+>)?\(/.test(line)) {
    findings.push(createSimpleFinding("RSA-UNSAFE-TRANSMUTE", file, lineNumber, line));
  }

  if (/\bMaybeUninit\b/.test(line)) {
    findings.push(createSimpleFinding("RSA-UNSAFE-MAYBEUNINIT", file, lineNumber, line));
  }

  if (/\bfrom_raw_parts(?:_mut)?\s*\(/.test(line)) {
    findings.push(createSimpleFinding("RSA-UNSAFE-FROM-RAW-PARTS", file, lineNumber, line));
  }

  if (/(?:\.|\b)set_len\s*\(/.test(line)) {
    findings.push(createSimpleFinding("RSA-UNSAFE-SET-LEN", file, lineNumber, line));
  }

  if (/\bBox::from_raw\s*\(/.test(line)) {
    findings.push(createSimpleFinding("RSA-UNSAFE-BOX-FROM-RAW", file, lineNumber, line));
  }

  return findings;
}

function createSimpleFinding(ruleId: RuleId, file: string, lineNumber: number, line: string): Finding {
  return createScannerFinding({
    ruleId,
    file,
    line: lineNumber,
    evidence: [lineEvidence(lineNumber, line)]
  });
}

function createUnsafeBlockFinding(
  file: string,
  lineNumber: number,
  line: string,
  lines: readonly string[],
  lineIndex: number
): Finding {
  const safetyComment = findNearbySafetyComment(lines, lineIndex);
  const evidence = [lineEvidence(lineNumber, line)];

  if (safetyComment !== undefined) {
    evidence.push(lineEvidence(safetyComment.line, safetyComment.text));
  }

  return createScannerFinding({
    ruleId: "RSA-UNSAFE-BLOCK",
    file,
    line: lineNumber,
    evidence,
    confidence: safetyComment === undefined ? "high" : "medium",
    ...(safetyComment === undefined
      ? {}
      : {
          falsePositiveNotes: `Nearby Safety comment detected on line ${safetyComment.line}; keep the finding for invariant review.`
        })
  });
}

function findNearbySafetyComment(
  lines: readonly string[],
  lineIndex: number
): { line: number; text: string } | undefined {
  const startIndex = Math.max(0, lineIndex - 3);

  for (let index = lineIndex; index >= startIndex; index -= 1) {
    const text = lines[index] ?? "";
    if (/\bSAFETY\s*:|\bSafety\s*:/.test(text)) {
      return { line: index + 1, text };
    }
  }

  return undefined;
}
