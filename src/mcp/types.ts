import type { Category, Finding, Severity } from "../reports/schemas.js";

export const mcpToolNames = [
  "rust_audit_project",
  "rust_audit_unsafe",
  "rust_audit_dependencies",
  "rust_review_current_diff"
] as const;

export type McpToolName = (typeof mcpToolNames)[number];
export type OutputFormat = "json" | "markdown";
export type RiskLevel = "pass" | "warning" | "needs_attention" | "high_risk";

export interface RustAuditProjectInput {
  projectPath: string;
  outputFormat?: OutputFormat | undefined;
  includeSuppressed?: boolean | undefined;
}

export interface RustAuditUnsafeInput {
  projectPath: string;
  includeDocumentedUnsafe?: boolean | undefined;
  outputFormat?: OutputFormat | undefined;
}

export interface RustAuditDependenciesInput {
  projectPath: string;
  outputFormat?: OutputFormat | undefined;
}

export interface RustReviewCurrentDiffInput {
  projectPath: string;
  baseRef?: string | undefined;
  headRef?: string | undefined;
  outputFormat?: OutputFormat | undefined;
}

export type RustAuditToolInput =
  | RustAuditProjectInput
  | RustAuditUnsafeInput
  | RustAuditDependenciesInput
  | RustReviewCurrentDiffInput;

export interface McpAuditSummary {
  findingCount: number;
  suppressedCount: number;
  severityCounts: Record<Severity, number>;
  categoryCounts: Record<Category, number>;
  riskLevel: RiskLevel;
}

export interface McpAuditError {
  code: string;
  message: string;
}

export interface McpAuditToolOutput {
  tool: McpToolName;
  projectPath: string;
  summary: McpAuditSummary;
  findings: Finding[];
  reportMarkdown?: string;
  warnings?: string[];
  diffAffectedFiles?: string[];
  error?: McpAuditError;
}
