import type { Category, Finding, Severity } from "../reports/schemas.js";
import type { GitDiffFile } from "../git/index.js";
import type { SuppressedFinding } from "../scanners/types.js";

export const mcpToolNames = [
  "rust_audit_project",
  "rust_audit_unsafe",
  "rust_audit_dependencies",
  "rust_review_current_diff",
  "rust_list_accepted_risks"
] as const;

export type McpToolName = (typeof mcpToolNames)[number];
export type OutputFormat = "json" | "markdown";
export type PathMode = "relative" | "absolute";
export type DiffReportMode = "full" | "compact";
export type RiskLevel = "pass" | "warning" | "needs_attention" | "high_risk";

export interface RustAuditProjectInput {
  projectPath: string;
  outputFormat?: OutputFormat | undefined;
  pathMode?: PathMode | undefined;
  includeSuppressed?: boolean | undefined;
}

export interface RustAuditUnsafeInput {
  projectPath: string;
  includeDocumentedUnsafe?: boolean | undefined;
  outputFormat?: OutputFormat | undefined;
  pathMode?: PathMode | undefined;
}

export interface RustAuditDependenciesInput {
  projectPath: string;
  outputFormat?: OutputFormat | undefined;
  pathMode?: PathMode | undefined;
}

export interface RustReviewCurrentDiffInput {
  projectPath: string;
  baseRef?: string | undefined;
  headRef?: string | undefined;
  staged?: boolean | undefined;
  includePreExisting?: boolean | undefined;
  nearChangedLineWindow?: number | undefined;
  outputFormat?: OutputFormat | undefined;
  pathMode?: PathMode | undefined;
  reportMode?: DiffReportMode | undefined;
}

export interface RustListAcceptedRisksInput {
  projectPath: string;
  includeExpired: boolean;
  includeInvalid: boolean;
  outputFormat: OutputFormat;
  pathMode?: PathMode | undefined;
}

export type RustAuditToolInput =
  | RustAuditProjectInput
  | RustAuditUnsafeInput
  | RustAuditDependenciesInput
  | RustReviewCurrentDiffInput
  | RustListAcceptedRisksInput;

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
  functionName?: string | undefined;
  functionStartLine?: number | undefined;
  functionEndLine?: number | undefined;
  nearestChangedFunctionName?: string | undefined;
  nearestChangedFunctionStartLine?: number | undefined;
  nearestChangedFunctionEndLine?: number | undefined;
  sameFunctionAsNearestChange?: boolean | undefined;
  unsafeSite?: UnsafeSiteContext | undefined;
  nearestChangedUnsafeSite?: UnsafeSiteContext | undefined;
  sameUnsafeSiteAsNearestChange?: boolean | undefined;
  contextAssessment?: DiffContextAssessment | undefined;
  contextNote?: string | undefined;
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
export type DiffContextAssessment = "same_function_or_unsafe_site" | "different_function_or_unsafe_site" | "unknown";
export type UnsafeSiteKind = "unsafe_block" | "unsafe_fn" | "unsafe_impl" | "extern_c";

export interface RustFunctionContext {
  name: string;
  startLine: number;
  endLine?: number | undefined;
}

export interface UnsafeSiteContext {
  kind: UnsafeSiteKind;
  startLine: number;
  endLine?: number | undefined;
  functionName?: string | undefined;
}

export interface ReviewFindingGroup {
  id: string;
  title: string;
  file: string;
  startLine?: number | undefined;
  endLine?: number | undefined;
  functionName?: string | undefined;
  unsafeSite?: UnsafeSiteContext | undefined;
  relation: FindingDiffContext["relation"] | "mixed";
  findingIds: string[];
  ruleIds: string[];
}

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

export interface AcceptedRiskInventorySummary {
  acceptedRiskCount: number;
  expiredCount: number;
  invalidCount: number;
  byRuleId: Record<string, number>;
  byOwner: Record<string, number>;
}

export interface AcceptedRisk {
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

export interface DiffReviewSummaryMetrics {
  introducedFindingCount: number;
  nearChangedFindingCount: number;
  preExistingFindingCount: number;
  hiddenNearChangedFindingCount: number;
  unsafeSiteGroupCount: number;
  blockingCount: number;
  manualReviewCount: number;
  nonBlockingCount: number;
}

export interface DiffReviewDetails {
  mode: DiffReviewMode;
  changedLineWindow: number;
  reportMode: DiffReportMode;
  pathMode: PathMode;
  includePreExisting: boolean;
  includedRelations: FindingDiffContext["relation"][];
  relationCounts: Record<Exclude<DiffRelation, "unrelated">, number>;
  hiddenPreExistingCount: number;
  hiddenNearChangedCount: number;
  unsafeSiteGroupCount: number;
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
  reviewGroups?: ReviewFindingGroup[];
  suppressedFindings?: SuppressedFinding[];
  suppressionSummary?: SuppressionSummary;
  error?: McpAuditError;
}

export interface AcceptedRiskInventoryToolOutput {
  tool: "rust_list_accepted_risks";
  projectPath: string;
  summary: AcceptedRiskInventorySummary;
  acceptedRisks: AcceptedRisk[];
  reportMarkdown?: string | undefined;
  error?: McpAuditError | undefined;
}

export type McpToolOutput = McpAuditToolOutput | AcceptedRiskInventoryToolOutput;
