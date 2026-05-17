import { join } from "node:path";
import type { Confidence, Finding, Severity } from "../reports/schemas.js";
import { readTextLines } from "./scannerUtils.js";
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
  options: { includeSuppressed?: boolean } = {}
): Promise<ScannerResult> {
  const uniqueFindings = dedupeFindings(findings);
  const { findings: unsuppressedFindings, suppressedFindings } = await applySuppressions(workspacePath, uniqueFindings);
  const finalWarnings = [...warnings];

  if (suppressedFindings.length > 0) {
    finalWarnings.push(`${suppressedFindings.length} finding(s) suppressed by rustsec-auditor inline directives.`);
  }

  return {
    findings: sortFindings(options.includeSuppressed === true ? uniqueFindings : unsuppressedFindings),
    warnings: finalWarnings,
    suppressedCount: suppressedFindings.length,
    suppressedFindings
  };
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
  findings: readonly Finding[]
): Promise<{ findings: Finding[]; suppressedFindings: SuppressedFinding[] }> {
  const lineCache = new Map<string, Promise<string[]>>();
  const unsuppressed: Finding[] = [];
  const suppressedFindings: SuppressedFinding[] = [];

  for (const finding of findings) {
    const startLine = finding.startLine;
    if (startLine === undefined) {
      unsuppressed.push(finding);
      continue;
    }

    const lines = await cachedLines(workspacePath, finding.file, lineCache);
    const suppression = findSuppression(lines, startLine, finding.ruleId);

    if (suppression === undefined) {
      unsuppressed.push(finding);
      continue;
    }

    suppressedFindings.push({
      ruleId: finding.ruleId,
      file: finding.file,
      line: startLine,
      reason: suppression.reason,
      directiveLine: suppression.line
    });
  }

  return { findings: unsuppressed, suppressedFindings };
}

async function cachedLines(
  workspacePath: string,
  file: string,
  lineCache: Map<string, Promise<string[]>>
): Promise<string[]> {
  const cached = lineCache.get(file);
  if (cached !== undefined) return await cached;

  const next = readTextLines(join(workspacePath, file)).catch(() => []);
  lineCache.set(file, next);
  return await next;
}

function findSuppression(
  lines: readonly string[],
  lineNumber: number,
  ruleId: string
): { line: number; reason: string } | undefined {
  const start = Math.max(1, lineNumber - 3);
  const end = Math.min(lines.length, lineNumber);

  for (let current = end; current >= start; current -= 1) {
    const text = lines[current - 1] ?? "";
    const suppression = parseSuppressionDirective(text);
    if (suppression === undefined) continue;

    if (
      suppression.ruleId === ruleId ||
      suppression.ruleId === "*" ||
      suppression.ruleId.toLowerCase() === "all"
    ) {
      return { line: current, reason: suppression.reason };
    }
  }

  return undefined;
}

function parseSuppressionDirective(line: string): { ruleId: string; reason: string } | undefined {
  const match = /rustsec-auditor:\s*ignore\s+([A-Za-z0-9*_-]+)(?:\s+(.+))?/i.exec(line);
  if (match === null || match[1] === undefined) return undefined;

  return {
    ruleId: match[1],
    reason: match[2]?.trim() ?? "No reason provided"
  };
}
