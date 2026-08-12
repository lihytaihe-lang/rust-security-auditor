import type { Finding } from "../reports/schemas.js";
import { createScannerFinding, lineEvidence } from "./findingUtils.js";
import { discoverRustProject, type RustProject } from "./projectScanner.js";
import { finalizeScannerResult } from "./resultUtils.js";
import { findTestCodeLines, maskRustSource } from "./rustLexer.js";
import type { RuleId } from "./rules.js";
import type { ScannerContext, ScannerResult, SecurityScanner } from "./types.js";

export interface UnsafeScannerContext extends ScannerContext {
  project?: RustProject;
}

export class UnsafeScanner implements SecurityScanner<UnsafeScannerContext> {
  readonly name = "UnsafeScanner";

  async scan(options: UnsafeScannerContext): Promise<ScannerResult> {
    const project = options.project ?? (await discoverRustProject(options.workspacePath, options.sourceReader));
    const findings: Finding[] = [];

    for (const sourceFile of project.rustSourceFiles) {
      const lines = await project.sourceReader.readTextLines(sourceFile.absolutePath, sourceFile.file, "rust", "unsafe_scan");
      if (lines === undefined) continue;
      const masked = maskRustSource(lines);
      if (!masked.isComplete) {
        project.sourceReader.recordIncomplete(
          sourceFile.file,
          "rust",
          "unsafe_scan",
          "lexical_incomplete",
          `Rust lexical analysis is incomplete (${masked.limitation ?? "unknown limitation"}); test-only severity reductions were disabled.`
        );
      }
      findings.push(...scanUnsafeRustLines(sourceFile.file, lines, masked));
    }

    return await finalizeScannerResult(options.workspacePath, findings, [], {
      includeSuppressed: options.includeSuppressed === true,
      sourceReader: project.sourceReader
    });
  }
}

export function scanUnsafeRustText(file: string, source: string): Finding[] {
  return scanUnsafeRustLines(file, source.split(/\r?\n/));
}

function scanUnsafeRustLines(file: string, lines: readonly string[], masked = maskRustSource(lines)): Finding[] {
  const testLines = findTestCodeLines(masked.withoutLiterals, masked.isComplete);
  const findings: Finding[] = [];

  masked.withoutLiterals.forEach((codeLine, index) => {
    if (codeLine.trim().length === 0) return;

    findings.push(
      ...findUnsafeLineFindings({
        file,
        lineNumber: index + 1,
        codeLine,
        sourceLine: lines[index] ?? codeLine,
        commentFreeLine: masked.withoutComments[index] ?? codeLine,
        sourceLines: lines,
        commentLines: masked.commentsOnly,
        lineIndex: index,
        inTestCode: testLines.has(index + 1)
      })
    );
  });

  return findings;
}

interface UnsafeLineContext {
  file: string;
  lineNumber: number;
  /** Comments and literals masked out; use for most pattern matching. */
  codeLine: string;
  /** Original source text; use for evidence and comment-based signals. */
  sourceLine: string;
  /** Comments masked out but literals preserved; use for ABI strings. */
  commentFreeLine: string;
  sourceLines: readonly string[];
  /** Only confirmed comments; use for comment-based security semantics. */
  commentLines: readonly string[];
  lineIndex: number;
  inTestCode: boolean;
}

function findUnsafeLineFindings(context: UnsafeLineContext): Finding[] {
  const { codeLine, commentFreeLine } = context;
  const findings: Finding[] = [];

  if (/\bunsafe\s+impl\b[^{}\n;]*\bSend\b/.test(codeLine)) {
    findings.push(simpleFinding(context, "RSA-UNSAFE-IMPL-SEND"));
  }

  if (/\bunsafe\s+impl\b[^{}\n;]*\bSync\b/.test(codeLine)) {
    findings.push(simpleFinding(context, "RSA-UNSAFE-IMPL-SYNC"));
  }

  if (/\bunsafe\s+(?:extern\s+"[^"]*"\s+)?fn\b/.test(commentFreeLine)) {
    findings.push(simpleFinding(context, "RSA-UNSAFE-FN"));
  }

  if (/\bextern\s+"C(?:-unwind)?"/.test(commentFreeLine)) {
    findings.push(simpleFinding(context, "RSA-FFI-EXTERN-C"));
  }

  if (/\bunsafe\s*\{/.test(codeLine)) {
    findings.push(unsafeBlockFinding(context));
  }

  if (/\b(?:std::mem::|core::mem::|mem::)?transmute(?:_copy)?\s*(?:::<[^>]*>)?\s*\(/.test(codeLine)) {
    findings.push(simpleFinding(context, "RSA-UNSAFE-TRANSMUTE"));
  }

  if (/\bMaybeUninit\b/.test(codeLine)) {
    findings.push(simpleFinding(context, "RSA-UNSAFE-MAYBEUNINIT"));
  }

  if (/\bfrom_raw_parts(?:_mut)?\s*\(/.test(codeLine)) {
    findings.push(simpleFinding(context, "RSA-UNSAFE-FROM-RAW-PARTS"));
  }

  if (/(?:\.|\b)set_len\s*\(/.test(codeLine)) {
    findings.push(simpleFinding(context, "RSA-UNSAFE-SET-LEN"));
  }

  if (/\bBox::from_raw\s*\(/.test(codeLine)) {
    findings.push(simpleFinding(context, "RSA-UNSAFE-BOX-FROM-RAW"));
  }

  if (/\bget_unchecked(?:_mut)?\s*\(/.test(codeLine)) {
    findings.push(simpleFinding(context, "RSA-UNSAFE-GET-UNCHECKED"));
  }

  if (/\b(?!get_unchecked(?:_mut)?\s*\()\w+_unchecked(?:_mut)?\s*\(/.test(codeLine)) {
    findings.push(simpleFinding(context, "RSA-UNSAFE-UNCHECKED-CALL"));
  }

  if (/\bstatic\s+mut\s+[A-Za-z_]/.test(codeLine)) {
    findings.push(simpleFinding(context, "RSA-UNSAFE-STATIC-MUT"));
  }

  if (
    /\b(?:copy_nonoverlapping|write_bytes|write_volatile|read_volatile|read_unaligned|write_unaligned)\s*\(/.test(
      codeLine
    ) ||
    /\bptr::(?:copy|read|write)\s*\(/.test(codeLine)
  ) {
    findings.push(simpleFinding(context, "RSA-UNSAFE-RAW-PTR-ACCESS"));
  }

  if (/\bCStr::from_ptr\s*\(|\bCString::from_raw\s*\(/.test(codeLine)) {
    findings.push(simpleFinding(context, "RSA-FFI-CSTR-FROM-PTR"));
  }

  return findings;
}

function simpleFinding(context: UnsafeLineContext, ruleId: RuleId): Finding {
  return createScannerFinding({
    ruleId,
    file: context.file,
    line: context.lineNumber,
    evidence: [lineEvidence(context.lineNumber, context.sourceLine)],
    ...testCodeOverrides(context)
  });
}

function unsafeBlockFinding(context: UnsafeLineContext): Finding {
  const safetyComment = findNearbySafetyComment(context.commentLines, context.lineIndex);
  const evidence = [lineEvidence(context.lineNumber, context.sourceLine)];
  const testOverrides = testCodeOverrides(context);

  if (safetyComment !== undefined) {
    evidence.push(lineEvidence(safetyComment.line, safetyComment.text));
  }

  const notes = [
    safetyComment === undefined
      ? undefined
      : `Nearby Safety comment detected on line ${safetyComment.line}; keep the finding for invariant review.`,
    testOverrides.falsePositiveNotes
  ].filter((note): note is string => note !== undefined);

  return createScannerFinding({
    ruleId: "RSA-UNSAFE-BLOCK",
    file: context.file,
    line: context.lineNumber,
    evidence,
    ...testOverrides,
    confidence: safetyComment === undefined ? "high" : "medium",
    ...(notes.length === 0 ? {} : { falsePositiveNotes: notes.join(" ") })
  });
}

/**
 * Findings inside `#[cfg(test)]` code are still worth reporting, but they do
 * not ship, so they should not drive a release gate or block a diff.
 */
function testCodeOverrides(context: UnsafeLineContext): {
  severity?: "low";
  falsePositiveNotes?: string;
} {
  if (!context.inTestCode) return {};

  return {
    severity: "low",
    falsePositiveNotes: "Located in #[cfg(test)] code, so severity is reduced; test-only code does not ship."
  };
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
