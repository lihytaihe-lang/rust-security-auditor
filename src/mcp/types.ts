import type { Category, Finding, Severity } from "../reports/schemas.js";
import type { GitDiffFile } from "../git/index.js";
import type { SuppressedFinding } from "../scanners/types.js";

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
  staged?: boolean | undefined;
  includePreExisting?: boolean | undefined;
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
  introducedFindingCount?: number | undefined;
  nearChangedFindingCount?: number | undefined;
  preExistingFindingCount?: number | undefined;
  blockingCount?: number | undefined;
  manualReviewCount?: number | undefined;
  nonBlockingCount?: number | undefined;
}

export interface McpAuditError {
  code: string;
  message: string;
}

export type DiffRelation =
  | "introduced_by_diff"
  | "near_changed_lines"
  | "pre_existing_in_changed_file"
  | "unrelated";

export interface FindingDiffContext {
  relation: Exclude<DiffRelation, "unrelated">;
  nearestChangedLine?: number | undefined;
  distance?: number | undefined;
}

export interface DiffAwareFinding {
  finding: Finding;
  diffContext: FindingDiffContext;
  actionability?: FindingActionability | undefined;
  suppression?: SuppressedFinding | undefined;
}

export type DiffReviewMode = "working_tree" | "staged" | "range";
export type ReviewDecisionStatus = "pass" | "needs_attention" | "block";
export type RecommendedAction = "fix_before_commit" | "manual_review" | "monitor" | "suppress_if_accepted";

export interface ReviewDecision {
  status: ReviewDecisionStatus;
  reason: string;
  blockingFindingIds: string[];
  needsManualReviewFindingIds: string[];
  safeToCommit: boolean;
}

export interface FindingActionability {
  recommendedAction: RecommendedAction;
  canCodexFix: boolean;
  suggestedFixPrompt: string;
  suppressionSuggestion?: string | undefined;
}

export interface SuppressionSummary {
  suppressedCount: number;
  expiredSuppressionCount: number;
  invalidSuppressionCount: number;
}

export interface DiffReviewSummaryMetrics {
  introducedFindingCount: number;
  nearChangedFindingCount: number;
  preExistingFindingCount: number;
  blockingCount: number;
  manualReviewCount: number;
  nonBlockingCount: number;
}

export interface DiffReviewDetails {
  mode: DiffReviewMode;
  changedLineWindow: number;
  includePreExisting: boolean;
  includedRelations: FindingDiffContext["relation"][];
  relationCounts: Record<Exclude<DiffRelation, "unrelated">, number>;
  hiddenPreExistingCount: number;
  conclusion: "Safe to proceed" | "Needs attention" | "Block before commit";
}

export interface McpAuditToolOutput {
  tool: McpToolName;
  projectPath: string;
  summary: McpAuditSummary;
  findings: Finding[];
  reportMarkdown?: string;
  warnings?: string[];
  diffAffectedFiles?: string[];
  diff?: {
    files: GitDiffFile[];
  };
  diffReview?: DiffReviewDetails;
  reviewDecision?: ReviewDecision;
  enrichedFindings?: DiffAwareFinding[];
  suppressedFindings?: SuppressedFinding[];
  suppressionSummary?: SuppressionSummary;
  error?: McpAuditError;
}
