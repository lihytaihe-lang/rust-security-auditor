import { join } from "node:path";
import type { Confidence, Finding, Severity } from "../reports/schemas.js";
import { SafeSourceReader } from "./scannerUtils.js";
import { maskRustSource } from "./rustLexer.js";
import {
  isGlobalIgnoreToken,
  isSuppressionExpired,
  parseSuppressionDirective,
  suppressionMarker,
  type ParsedSuppressionDirective
} from "./suppressions.js";
import type { ScannerResult, SuppressedFinding } from "./types.js";

const severityRank: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1
};

const confidenceRank: Record<Confidence, number> = {
  high: 3,
  medium: 2,
  low: 1
};

export async function finalizeScannerResult(
  workspacePath: string,
  findings: readonly Finding[],
  warnings: readonly string[] = [],
  options: { includeSuppressed?: boolean; sourceReader?: SafeSourceReader } = {}
): Promise<ScannerResult> {
  const uniqueFindings = dedupeFindings(findings);
  const sourceReader = options.sourceReader ?? new SafeSourceReader(workspacePath);
  const { findings: unsuppressedFindings, suppressedFindings } = await applySuppressions(workspacePath, uniqueFindings, sourceReader);
  const suppressedCount = countActiveSuppressions(suppressedFindings);
  const expiredSuppressionCount = countExpiredSuppressions(suppressedFindings);
  const invalidSuppressionCount = countInvalidSuppressions(suppressedFindings);
  const deprecatedMarkerCount = countDeprecatedMarkerSuppressions(suppressedFindings);
  const finalWarnings = [...warnings];

  if (suppressedCount > 0) {
    finalWarnings.push(`${suppressedCount} finding(s) suppressed by inline accepted-risk directives.`);
  }

  if (expiredSuppressionCount > 0) {
    finalWarnings.push(`${expiredSuppressionCount} expired accepted-risk suppression directive(s) were ignored; findings are shown again.`);
  }

  if (invalidSuppressionCount > 0) {
    finalWarnings.push(`${invalidSuppressionCount} invalid accepted-risk suppression directive(s) were ignored; use an exact rule id and a '-- reason'.`);
  }

  if (deprecatedMarkerCount > 0) {
    finalWarnings.push(
      `${deprecatedMarkerCount} suppression comment(s) use the deprecated 'rustsec-auditor:' marker; rename them to '${suppressionMarker}:'.`
    );
  }

  return {
    findings: sortFindings(options.includeSuppressed === true ? uniqueFindings : unsuppressedFindings),
    warnings: finalWarnings,
    suppressedCount,
    expiredSuppressionCount,
    invalidSuppressionCount,
    suppressedFindings,
    scanCoverage: sourceReader.coverage()
  };
}

export function countActiveSuppressions(suppressions: readonly SuppressedFinding[]): number {
  return suppressions.filter((suppression) => suppression.isValid && !suppression.isExpired).length;
}

export function countExpiredSuppressions(suppressions: readonly SuppressedFinding[]): number {
  return suppressions.filter((suppression) => suppression.isExpired).length;
}

export function countInvalidSuppressions(suppressions: readonly SuppressedFinding[]): number {
  return suppressions.filter((suppression) => !suppression.isValid).length;
}

export function countDeprecatedMarkerSuppressions(suppressions: readonly SuppressedFinding[]): number {
  return suppressions.filter((suppression) => suppression.usesDeprecatedMarker === true).length;
}

export function dedupeFindings(findings: readonly Finding[]): Finding[] {
  const seen = new Set<string>();
  const deduped: Finding[] = [];

  for (const finding of findings) {
    const key = `${finding.file}:${finding.startLine ?? 0}:${finding.ruleId}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(finding);
  }

  return deduped;
}

export function sortFindings(findings: readonly Finding[]): Finding[] {
  return [...findings].sort((left, right) => {
    const severityDelta = severityRank[right.severity] - severityRank[left.severity];
    if (severityDelta !== 0) return severityDelta;

    const confidenceDelta = confidenceRank[right.confidence] - confidenceRank[left.confidence];
    if (confidenceDelta !== 0) return confidenceDelta;

    const fileDelta = left.file.localeCompare(right.file);
    if (fileDelta !== 0) return fileDelta;

    return (left.startLine ?? 0) - (right.startLine ?? 0);
  });
}

async function applySuppressions(
  workspacePath: string,
  findings: readonly Finding[],
  sourceReader: SafeSourceReader
): Promise<{ findings: Finding[]; suppressedFindings: SuppressedFinding[] }> {
  const commentCache = new Map<string, Promise<readonly string[] | undefined>>();
  const unsuppressed: Finding[] = [];
  const suppressedFindings: SuppressedFinding[] = [];

  for (const finding of findings) {
    const startLine = finding.startLine;
    if (startLine === undefined) {
      unsuppressed.push(finding);
      continue;
    }

    const commentLines = await cachedCommentLines(workspacePath, finding.file, commentCache, sourceReader);
    if (commentLines === undefined) {
      unsuppressed.push(finding);
      continue;
    }
    const suppression = findSuppression(commentLines, startLine, finding);

    if (suppression === undefined) {
      unsuppressed.push(finding);
      continue;
    }

    suppressedFindings.push(suppression.record);

    if (!suppression.isActive) {
      unsuppressed.push(finding);
    }
  }

  return { findings: unsuppressed, suppressedFindings };
}

/**
 * Suppression lookup needs the comment-only view of a source file. Both the
 * read and the lexing are cached per file.
 *
 * Lexing per finding instead of per file makes a scan quadratic in the size of
 * a single file: a 274 KiB file holding 6,000 findings was lexed 6,000 times
 * and took 69 seconds. The per-file size cap does not bound that, because the
 * cost is findings x lines rather than bytes.
 */
async function cachedCommentLines(
  workspacePath: string,
  file: string,
  commentCache: Map<string, Promise<readonly string[] | undefined>>,
  sourceReader: SafeSourceReader
): Promise<readonly string[] | undefined> {
  const cached = commentCache.get(file);
  if (cached !== undefined) return await cached;

  const next = sourceReader
    .readTextLines(join(workspacePath, file), file, "rust", "suppression")
    .then((lines) => (lines === undefined ? undefined : maskRustSource(lines).commentsOnly));
  commentCache.set(file, next);
  return await next;
}

function findSuppression(
  lines: readonly string[],
  lineNumber: number,
  finding: Finding
): { record: SuppressedFinding; isActive: boolean } | undefined {
  const start = Math.max(1, lineNumber - 3);
  const end = Math.min(lines.length, lineNumber);
  let globalIgnoreCandidate: { record: SuppressedFinding; isActive: boolean } | undefined;

  for (let current = end; current >= start; current -= 1) {
    const text = lines[current - 1] ?? "";
    const suppression = parseSuppressionDirective(text);
    if (suppression === undefined) continue;

    if (isGlobalIgnoreToken(suppression.ruleId)) {
      globalIgnoreCandidate ??= createSuppressionMatch(finding, current, suppression);
      continue;
    }

    if (suppression.ruleId === finding.ruleId) {
      return createSuppressionMatch(finding, current, suppression);
    }
  }

  return globalIgnoreCandidate;
}

function createSuppressionMatch(
  finding: Finding,
  directiveLine: number,
  suppression: ParsedSuppressionDirective,
  extraInvalidReasons: readonly string[] = []
): { record: SuppressedFinding; isActive: boolean } {
  const invalidReasons = [...suppression.invalidReasons, ...extraInvalidReasons];
  const isValid = invalidReasons.length === 0;
  const isExpired = isSuppressionExpired(suppression.until);
  const record: SuppressedFinding = {
    ruleId: finding.ruleId,
    file: finding.file,
    line: finding.startLine ?? directiveLine,
    directiveLine,
    reason: suppression.reason,
    isExpired,
    isValid,
    rawComment: suppression.rawComment
  };

  if (suppression.usesDeprecatedMarker) record.usesDeprecatedMarker = true;
  if (suppression.owner !== undefined) record.owner = suppression.owner;
  if (suppression.ticket !== undefined) record.ticket = suppression.ticket;
  if (suppression.until !== undefined) record.until = suppression.until;
  if (!isValid) record.invalidSuppression = invalidReasons.join(" ");

  return {
    record,
    isActive: isValid && !isExpired
  };
}
