import { createHash } from "node:crypto";
import type { Confidence, Finding, Severity } from "../reports/schemas.js";
import { getRuleMetadata, type RuleId } from "./rules.js";

interface ScannerFindingInput {
  ruleId: RuleId;
  file: string;
  line: number;
  evidence: readonly string[];
  severity?: Severity;
  confidence?: Confidence;
  riskScenario?: string;
  suggestedFix?: string;
  suggestedTests?: readonly string[];
  falsePositiveNotes?: string;
  references?: readonly string[];
}

export function createScannerFinding(input: ScannerFindingInput): Finding {
  const rule = getRuleMetadata(input.ruleId);
  const finding: Finding = {
    id: stableFindingId(input.ruleId, input.file, input.line),
    ruleId: input.ruleId,
    title: rule.title,
    severity: input.severity ?? rule.severity,
    confidence: input.confidence ?? rule.confidence,
    category: rule.category,
    file: input.file,
    startLine: input.line,
    evidence: [...input.evidence],
    whyItMatters: rule.whyItMatters,
    riskScenario: input.riskScenario ?? rule.riskScenario,
    suggestedFix: input.suggestedFix ?? rule.remediation
  };

  const suggestedTests = input.suggestedTests ?? rule.suggestedTests;
  if (suggestedTests !== undefined) {
    finding.suggestedTests = [...suggestedTests];
  }

  if (input.falsePositiveNotes !== undefined) {
    finding.falsePositiveNotes = input.falsePositiveNotes;
  }

  if (input.references !== undefined) {
    finding.references = [...input.references];
  }

  return finding;
}

export function lineEvidence(lineNumber: number, lineText: string): string {
  return `Line ${lineNumber}: ${lineText.trim()}`;
}

function stableFindingId(ruleId: string, file: string, line: number): string {
  const digest = createHash("sha1").update(`${ruleId}:${file}:${line}`).digest("hex").slice(0, 8).toUpperCase();
  return `${ruleId}-${digest}`;
}
