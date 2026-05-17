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
  const suppressedCount = countActiveSuppressions(suppressedFindings);
  const expiredSuppressionCount = countExpiredSuppressions(suppressedFindings);
  const invalidSuppressionCount = countInvalidSuppressions(suppressedFindings);
  const finalWarnings = [...warnings];

  if (suppressedCount > 0) {
    finalWarnings.push(`${suppressedCount} finding(s) suppressed by rustsec-auditor inline directives.`);
  }

  if (expiredSuppressionCount > 0) {
    finalWarnings.push(`${expiredSuppressionCount} expired rustsec-auditor suppression directive(s) were ignored; findings are shown again.`);
  }

  if (invalidSuppressionCount > 0) {
    finalWarnings.push(`${invalidSuppressionCount} invalid rustsec-auditor suppression directive(s) were ignored; use an exact rule id and a '-- reason'.`);
  }

  return {
    findings: sortFindings(options.includeSuppressed === true ? uniqueFindings : unsuppressedFindings),
    warnings: finalWarnings,
    suppressedCount,
    expiredSuppressionCount,
    invalidSuppressionCount,
    suppressedFindings
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
    const suppression = findSuppression(lines, startLine, finding);

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
      globalIgnoreCandidate ??= createSuppressionMatch(finding, current, suppression, [
        "Global rustsec-auditor ignore directives are not supported; suppress a specific rule id instead."
      ]);
      continue;
    }

    if (suppression.ruleId === finding.ruleId) {
      return createSuppressionMatch(finding, current, suppression);
    }
  }

  return globalIgnoreCandidate;
}

interface ParsedSuppressionDirective {
  ruleId: string;
  reason: string;
  owner?: string;
  ticket?: string;
  until?: string;
  rawComment: string;
  invalidReasons: string[];
}

function parseSuppressionDirective(line: string): ParsedSuppressionDirective | undefined {
  const match = /rustsec-auditor:\s*ignore\s+(\S+)(.*)$/i.exec(line);
  if (match === null || match[1] === undefined) return undefined;

  const ruleId = match[1].trim();
  const remainder = match[2]?.trim() ?? "";
  const delimiterIndex = remainder.indexOf("--");
  const metadataText = delimiterIndex === -1 ? remainder : remainder.slice(0, delimiterIndex).trim();
  const reason = delimiterIndex === -1 ? "" : remainder.slice(delimiterIndex + 2).trim();
  const invalidReasons: string[] = [];
  const metadata: Pick<ParsedSuppressionDirective, "owner" | "ticket" | "until"> = {};

  if (reason.length === 0) {
    invalidReasons.push("Suppression reason is required after '--'.");
  }

  if (!isGlobalIgnoreToken(ruleId) && !/^[A-Za-z0-9_-]+$/.test(ruleId)) {
    invalidReasons.push("Suppression rule id must be a concrete rule id.");
  }

  for (const token of metadataText.length === 0 ? [] : metadataText.split(/\s+/)) {
    if (token.startsWith("owner=")) {
      const owner = token.slice("owner=".length).trim();
      if (owner.length === 0) {
        invalidReasons.push("Suppression owner must be non-empty when provided.");
      } else {
        metadata.owner = owner;
      }
      continue;
    }

    if (token.startsWith("ticket=")) {
      const ticket = token.slice("ticket=".length).trim();
      if (ticket.length === 0) {
        invalidReasons.push("Suppression ticket must be non-empty when provided.");
      } else {
        metadata.ticket = ticket;
      }
      continue;
    }

    if (token.startsWith("until=")) {
      const until = token.slice("until=".length).trim();
      if (!isValidIsoDate(until)) {
        invalidReasons.push("Suppression until must use YYYY-MM-DD.");
      } else {
        metadata.until = until;
      }
      continue;
    }

    invalidReasons.push(`Unsupported suppression metadata '${token}'.`);
  }

  return {
    ruleId,
    reason,
    rawComment: line.trim(),
    invalidReasons,
    ...metadata
  };
}

function createSuppressionMatch(
  finding: Finding,
  directiveLine: number,
  suppression: ParsedSuppressionDirective,
  extraInvalidReasons: readonly string[] = []
): { record: SuppressedFinding; isActive: boolean } {
  const invalidReasons = [...suppression.invalidReasons, ...extraInvalidReasons];
  const isValid = invalidReasons.length === 0;
  const isExpired = suppression.until === undefined ? false : isPastDate(suppression.until);
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

  if (suppression.owner !== undefined) record.owner = suppression.owner;
  if (suppression.ticket !== undefined) record.ticket = suppression.ticket;
  if (suppression.until !== undefined) record.until = suppression.until;
  if (!isValid) record.invalidSuppression = invalidReasons.join(" ");

  return {
    record,
    isActive: isValid && !isExpired
  };
}

function isGlobalIgnoreToken(ruleId: string): boolean {
  return ruleId === "*" || ruleId.toLowerCase() === "all";
}

function isValidIsoDate(value: string): boolean {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (match === null) return false;

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const date = new Date(Date.UTC(year, month - 1, day));

  return date.getUTCFullYear() === year && date.getUTCMonth() === month - 1 && date.getUTCDate() === day;
}

function isPastDate(value: string): boolean {
  return value < todayIsoDate();
}

function todayIsoDate(): string {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, "0");
  const day = String(now.getDate()).padStart(2, "0");

  return `${year}-${month}-${day}`;
}
