export const schemaVersion = "0.2.0" as const;

export const severities = ["info", "low", "medium", "high", "critical"] as const;
export type Severity = (typeof severities)[number];

export const confidences = ["low", "medium", "high"] as const;
export type Confidence = (typeof confidences)[number];

export const categories = [
  "unsafe",
  "ffi",
  "dependency",
  "supply_chain",
  "command_execution",
  "filesystem",
  "input_boundary",
  "concurrency",
  "secret",
  "panic_dos",
  "manual_review"
] as const;
export type Category = (typeof categories)[number];

export const releaseGateResults = [
  "PASS",
  "PASS_WITH_WARNINGS",
  "NEEDS_FIX_BEFORE_RELEASE",
  "MANUAL_SECURITY_REVIEW_REQUIRED"
] as const;
export type ReleaseGateResult = (typeof releaseGateResults)[number];

export interface Finding {
  id: string;
  ruleId: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  category: Category;
  file: string;
  startLine?: number;
  endLine?: number;
  evidence: string[];
  whyItMatters: string;
  riskScenario: string;
  suggestedFix: string;
  suggestedTests?: string[];
  falsePositiveNotes?: string;
  references?: string[];
}

export interface AuditReportInput {
  findings: readonly Finding[];
  result?: ReleaseGateResult;
  title?: string;
  scope?: string;
  generatedAt?: string;
  summaryNotes?: readonly string[];
  releaseGateRecommendation?: string;
}

export interface ReportSummary {
  result: ReleaseGateResult;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  manualReview: number;
}

export class FindingSchemaError extends Error {
  readonly issues: readonly string[];

  constructor(issues: readonly string[]) {
    super(`Invalid finding: ${issues.join("; ")}`);
    this.name = "FindingSchemaError";
    this.issues = issues;
  }
}

type UnknownRecord = Record<string, unknown>;

export function isSeverity(value: unknown): value is Severity {
  return isOneOf(value, severities);
}

export function isConfidence(value: unknown): value is Confidence {
  return isOneOf(value, confidences);
}

export function isCategory(value: unknown): value is Category {
  return isOneOf(value, categories);
}

export function isReleaseGateResult(value: unknown): value is ReleaseGateResult {
  return isOneOf(value, releaseGateResults);
}

export function validateFinding(input: unknown): Finding {
  if (!isRecord(input)) {
    throw new FindingSchemaError(["finding must be an object"]);
  }

  const issues: string[] = [];
  const id = requiredString(input, "id", issues);
  const ruleId = requiredString(input, "ruleId", issues);
  const title = requiredString(input, "title", issues);
  const severity = enumValue(input, "severity", isSeverity, issues);
  const confidence = enumValue(input, "confidence", isConfidence, issues);
  const category = enumValue(input, "category", isCategory, issues);
  const file = requiredString(input, "file", issues);
  const evidence = requiredStringArray(input, "evidence", issues);
  const whyItMatters = requiredString(input, "whyItMatters", issues);
  const riskScenario = requiredString(input, "riskScenario", issues);
  const suggestedFix = requiredString(input, "suggestedFix", issues);
  const startLine = optionalPositiveInteger(input, "startLine", issues);
  const endLine = optionalPositiveInteger(input, "endLine", issues);
  const suggestedTests = optionalStringArray(input, "suggestedTests", issues);
  const falsePositiveNotes = optionalString(input, "falsePositiveNotes", issues);
  const references = optionalStringArray(input, "references", issues);

  if (evidence.length === 0) {
    issues.push("evidence must contain at least one item");
  }

  if (startLine !== undefined && endLine !== undefined && endLine < startLine) {
    issues.push("endLine must be greater than or equal to startLine");
  }

  if (issues.length > 0) {
    throw new FindingSchemaError(issues);
  }

  const finding: Finding = {
    id,
    ruleId,
    title,
    severity,
    confidence,
    category,
    file,
    evidence,
    whyItMatters,
    riskScenario,
    suggestedFix
  };

  if (startLine !== undefined) finding.startLine = startLine;
  if (endLine !== undefined) finding.endLine = endLine;
  if (suggestedTests !== undefined) finding.suggestedTests = suggestedTests;
  if (falsePositiveNotes !== undefined) finding.falsePositiveNotes = falsePositiveNotes;
  if (references !== undefined) finding.references = references;

  return finding;
}

export function validateFindings(findings: readonly unknown[]): Finding[] {
  return findings.map((finding) => validateFinding(finding));
}

export function isManualReviewFinding(finding: Finding): boolean {
  return finding.category === "manual_review" || finding.confidence === "low";
}

export function summarizeFindings(
  findings: readonly Finding[],
  explicitResult?: ReleaseGateResult
): ReportSummary {
  const summary: ReportSummary = {
    result: explicitResult ?? inferReleaseGate(findings),
    total: findings.length,
    critical: countSeverity(findings, "critical"),
    high: countSeverity(findings, "high"),
    medium: countSeverity(findings, "medium"),
    low: countSeverity(findings, "low"),
    info: countSeverity(findings, "info"),
    manualReview: findings.filter(isManualReviewFinding).length
  };

  return summary;
}

export function inferReleaseGate(findings: readonly Finding[]): ReleaseGateResult {
  if (findings.some((finding) => finding.severity === "critical" || finding.severity === "high")) {
    return "NEEDS_FIX_BEFORE_RELEASE";
  }

  if (findings.some(isManualReviewFinding)) {
    return "MANUAL_SECURITY_REVIEW_REQUIRED";
  }

  if (findings.some((finding) => finding.severity === "medium" || finding.severity === "low")) {
    return "PASS_WITH_WARNINGS";
  }

  return "PASS";
}

function countSeverity(findings: readonly Finding[], severity: Severity): number {
  return findings.filter((finding) => finding.severity === severity).length;
}

function isOneOf<const T extends readonly string[]>(value: unknown, values: T): value is T[number] {
  return typeof value === "string" && values.includes(value as T[number]);
}

function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requiredString(record: UnknownRecord, field: string, issues: string[]): string {
  const value = record[field];
  if (typeof value !== "string" || value.trim().length === 0) {
    issues.push(`${field} must be a non-empty string`);
    return "";
  }

  return value;
}

function optionalString(record: UnknownRecord, field: string, issues: string[]): string | undefined {
  const value = record[field];
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.trim().length === 0) {
    issues.push(`${field} must be a non-empty string when provided`);
    return undefined;
  }

  return value;
}

function requiredStringArray(record: UnknownRecord, field: string, issues: string[]): string[] {
  const value = record[field];
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string" || item.trim().length === 0)) {
    issues.push(`${field} must be an array of non-empty strings`);
    return [];
  }

  return [...value];
}

function optionalStringArray(record: UnknownRecord, field: string, issues: string[]): string[] | undefined {
  const value = record[field];
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string" || item.trim().length === 0)) {
    issues.push(`${field} must be an array of non-empty strings when provided`);
    return undefined;
  }

  return [...value];
}

function optionalPositiveInteger(record: UnknownRecord, field: string, issues: string[]): number | undefined {
  const value = record[field];
  if (value === undefined) return undefined;
  if (typeof value !== "number" || !Number.isInteger(value) || value <= 0) {
    issues.push(`${field} must be a positive integer when provided`);
    return undefined;
  }

  return value;
}

function enumValue<T extends string>(
  record: UnknownRecord,
  field: string,
  predicate: (value: unknown) => value is T,
  issues: string[]
): T {
  const value = record[field];
  if (!predicate(value)) {
    issues.push(`${field} has an unsupported value`);
    return "" as T;
  }

  return value;
}
