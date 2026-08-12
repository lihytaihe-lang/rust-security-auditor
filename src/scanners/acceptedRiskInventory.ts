import { discoverRustProject } from "./projectScanner.js";
import { maskRustSource } from "./rustLexer.js";
import type { SafeSourceReader, ScanCoverage } from "./scannerUtils.js";
import { isSuppressionExpired, parseSuppressionDirective } from "./suppressions.js";

export interface AcceptedRiskInventoryOptions {
  workspacePath: string;
  includeExpired: boolean;
  includeInvalid: boolean;
  /** Optional shared reader when inventory participates in a broader scan. */
  sourceReader?: SafeSourceReader;
}

export interface AcceptedRiskInventoryEntry {
  ruleId: string;
  file: string;
  line: number;
  reason: string;
  owner?: string | undefined;
  ticket?: string | undefined;
  until?: string | undefined;
  isExpired: boolean;
  isValid: boolean;
  rawComment: string;
  invalidSuppression?: string | undefined;
}

export interface AcceptedRiskInventorySummary {
  acceptedRiskCount: number;
  expiredCount: number;
  invalidCount: number;
  byRuleId: Record<string, number>;
  byOwner: Record<string, number>;
}

export interface AcceptedRiskInventoryResult {
  summary: AcceptedRiskInventorySummary;
  acceptedRisks: AcceptedRiskInventoryEntry[];
  /** Inventory results are partial whenever this is incomplete; callers must surface it. */
  scanCoverage: ScanCoverage;
}

export async function listAcceptedRiskInventory(
  options: AcceptedRiskInventoryOptions
): Promise<AcceptedRiskInventoryResult> {
  const project = await discoverRustProject(options.workspacePath, options.sourceReader);
  const discoveredRisks: AcceptedRiskInventoryEntry[] = [];

  for (const sourceFile of project.rustSourceFiles) {
      const lines = await project.sourceReader.readTextLines(sourceFile.absolutePath, sourceFile.file, "rust", "suppression");
      if (lines === undefined) continue;
      const commentsOnly = maskRustSource(lines).commentsOnly;

      for (let index = 0; index < lines.length; index += 1) {
      const rawLine = commentsOnly[index] ?? "";
      const directive = parseSuppressionDirective(rawLine);
      if (directive === undefined) continue;

      const isExpired = isSuppressionExpired(directive.until);
      const isValid = directive.invalidReasons.length === 0;
      const entry: AcceptedRiskInventoryEntry = {
        ruleId: directive.ruleId,
        file: sourceFile.file,
        line: index + 1,
        reason: directive.reason,
        isExpired,
        isValid,
        rawComment: directive.rawComment
      };

      if (directive.owner !== undefined) entry.owner = directive.owner;
      if (directive.ticket !== undefined) entry.ticket = directive.ticket;
      if (directive.until !== undefined) entry.until = directive.until;
      if (!isValid) entry.invalidSuppression = directive.invalidReasons.join(" ");

      discoveredRisks.push(entry);
    }
  }

  const acceptedRisks = discoveredRisks.filter((risk) =>
    risk.isValid ? !risk.isExpired || options.includeExpired : options.includeInvalid
  );

  acceptedRisks.sort((left, right) => {
    const fileDelta = left.file.localeCompare(right.file);
    if (fileDelta !== 0) return fileDelta;
    return left.line - right.line;
  });

  return {
    summary: summarizeAcceptedRisks(acceptedRisks),
    acceptedRisks,
    scanCoverage: project.sourceReader.coverage()
  };
}

function summarizeAcceptedRisks(
  acceptedRisks: readonly AcceptedRiskInventoryEntry[]
): AcceptedRiskInventorySummary {
  const byRuleId: Record<string, number> = {};
  const byOwner: Record<string, number> = {};

  for (const risk of acceptedRisks) {
    byRuleId[risk.ruleId] = (byRuleId[risk.ruleId] ?? 0) + 1;
    const owner = risk.owner ?? "(missing)";
    byOwner[owner] = (byOwner[owner] ?? 0) + 1;
  }

  return {
    acceptedRiskCount: acceptedRisks.filter((risk) => risk.isValid && !risk.isExpired).length,
    expiredCount: acceptedRisks.filter((risk) => risk.isExpired).length,
    invalidCount: acceptedRisks.filter((risk) => !risk.isValid).length,
    byRuleId: sortCountRecord(byRuleId),
    byOwner: sortCountRecord(byOwner)
  };
}

function sortCountRecord(record: Record<string, number>): Record<string, number> {
  return Object.fromEntries(Object.entries(record).sort(([left], [right]) => left.localeCompare(right)));
}
