import type { Confidence, Finding, Severity } from "../reports/index.js";
import type { ScanCoverageEntry } from "../scanners/scannerUtils.js";
import type {
  DiffAwareFinding,
  DiffReviewSummaryMetrics,
  FindingActionability,
  FindingDiffContext,
  RecommendedAction,
  ReviewDecision
} from "./types.js";

export interface DiffReviewPolicyOptions {
  includePreExisting?: boolean | undefined;
  reportMode?: "compact" | "full" | undefined;
  incompleteCoverage?: readonly ScanCoverageEntry[] | undefined;
}

export function shouldDisplayDiffFinding(
  item: DiffAwareFinding,
  includePreExisting: boolean,
  reportMode: "compact" | "full" = "compact"
): boolean {
  if (item.suppression?.isExpired === true || item.suppression?.isValid === false) {
    return true;
  }

  if (reportMode === "full" && item.diffContext.relation !== "pre_existing_in_changed_file") {
    return true;
  }

  switch (item.diffContext.relation) {
    case "introduced_by_diff":
      return true;
    case "same_unsafe_site_context":
      return isRelevantContextFinding(item);
    case "same_function_context":
      return isRelevantContextFinding(item);
    case "nearby_legacy_context":
      return includePreExisting && isRelevantContextFinding(item);
    case "unrelated_nearby":
      return false;
    case "pre_existing_in_changed_file":
      return includePreExisting;
  }
}

function isRelevantContextFinding(item: DiffAwareFinding): boolean {
  return isAtLeastSeverity(item.finding.severity, "medium") && isMediumOrHighConfidence(item.finding.confidence);
}

export function withDiffReviewActionability(
  findings: readonly DiffAwareFinding[],
  options: DiffReviewPolicyOptions = {}
): DiffAwareFinding[] {
  return findings.map((item) => ({
    ...item,
    actionability: actionabilityForDiffFinding(item, options)
  }));
}

export function actionabilityForDiffFinding(
  item: DiffAwareFinding,
  options: DiffReviewPolicyOptions = {}
): FindingActionability {
  const recommendedAction = recommendedActionForDiffFinding(item, options);
  const actionability: FindingActionability = {
    recommendedAction,
    canCodexFix: canCodexFixFinding(item, recommendedAction),
    suggestedFixPrompt: suggestedFixPrompt(item, recommendedAction)
  };

  if (recommendedAction === "suppress_if_accepted") {
    actionability.suppressionSuggestion = suppressionSuggestion(item.finding);
  }

  return actionability;
}

export function inferReviewDecision(
  findings: readonly DiffAwareFinding[],
  options: DiffReviewPolicyOptions = {}
): ReviewDecision {
  const actionableFindings = withDiffReviewActionability(findings, options);
  const blockingFindingIds = actionableFindings
    .filter((item) => item.actionability?.recommendedAction === "fix_before_commit")
    .map((item) => item.finding.id);
  const needsManualReviewFindingIds = actionableFindings
    .filter(
      (item) =>
        item.actionability?.recommendedAction === "manual_review" ||
        item.actionability?.recommendedAction === "suppress_if_accepted"
    )
    .map((item) => item.finding.id);

  const incompleteCoverage = options.incompleteCoverage ?? [];
  // Incomplete coverage can only make a verdict stricter, never softer. Ranking
  // it above the blocking check downgraded `block` to `needs_attention` exactly
  // when the scan was least trustworthy, so the coverage reason is appended to
  // whatever verdict the findings already justify.
  const coverageNote =
    incompleteCoverage.length === 0
      ? ""
      : ` Required current-diff inputs were also not fully scanned: ${incompleteCoverage
          .map((entry) => `${entry.file} (${entry.reason ?? "incomplete"})`)
          .join(", ")}.`;

  if (blockingFindingIds.length > 0) {
    return {
      status: "block",
      reason: `The reviewed diff introduced high or critical security review signals with medium/high pattern-detection confidence.${coverageNote}`,
      blockingFindingIds,
      needsManualReviewFindingIds,
      safeToCommit: false
    };
  }

  if (needsManualReviewFindingIds.length > 0) {
    return {
      status: "needs_attention",
      reason: `No hard blockers were found, but introduced findings or directly related same-function/same-unsafe-site context need human review before commit.${coverageNote}`,
      blockingFindingIds,
      needsManualReviewFindingIds,
      safeToCommit: false
    };
  }

  if (incompleteCoverage.length > 0) {
    return {
      status: "needs_attention",
      reason: `Required current-diff inputs were not fully scanned: ${incompleteCoverage
        .map((entry) => `${entry.file} (${entry.reason ?? "incomplete"})`)
        .join(", ")}.`,
      blockingFindingIds,
      needsManualReviewFindingIds,
      safeToCommit: false
    };
  }

  return {
    status: "pass",
    reason:
      findings.length === 0
        ? "No introduced or directly related security review signals were reported for the reviewed diff."
        : "Only non-blocking legacy or low-risk context was reported for the reviewed diff.",
    blockingFindingIds,
    needsManualReviewFindingIds,
    safeToCommit: true
  };
}

export function summarizeDiffReviewMetrics(input: {
  allFindings: readonly DiffAwareFinding[];
  visibleFindings: readonly DiffAwareFinding[];
  reviewDecision: ReviewDecision;
  hiddenNearChangedCount: number;
  unsafeSiteGroupCount: number;
}): DiffReviewSummaryMetrics {
  const blocking = new Set(input.reviewDecision.blockingFindingIds);
  const manualReview = new Set(input.reviewDecision.needsManualReviewFindingIds);

  return {
    introducedFindingCount: countRelation(input.allFindings, "introduced_by_diff"),
    nearChangedFindingCount: countContextRelations(input.visibleFindings),
    sameUnsafeSiteContextFindingCount: countRelation(input.allFindings, "same_unsafe_site_context"),
    sameFunctionContextFindingCount: countRelation(input.allFindings, "same_function_context"),
    nearbyLegacyContextFindingCount: countRelation(input.allFindings, "nearby_legacy_context"),
    unrelatedNearbyFindingCount: countRelation(input.allFindings, "unrelated_nearby"),
    preExistingFindingCount: countRelation(input.allFindings, "pre_existing_in_changed_file"),
    hiddenNearChangedFindingCount: input.hiddenNearChangedCount,
    unsafeSiteGroupCount: input.unsafeSiteGroupCount,
    blockingCount: blocking.size,
    manualReviewCount: manualReview.size,
    nonBlockingCount: input.visibleFindings.filter(
      (item) => !blocking.has(item.finding.id) && !manualReview.has(item.finding.id)
    ).length
  };
}

export function conclusionFromReviewDecision(decision: ReviewDecision): "Safe to proceed" | "Needs attention" | "Block before commit" {
  switch (decision.status) {
    case "block":
      return "Block before commit";
    case "needs_attention":
      return "Needs attention";
    case "pass":
      return "Safe to proceed";
  }
}

function recommendedActionForDiffFinding(
  item: DiffAwareFinding,
  options: DiffReviewPolicyOptions
): RecommendedAction {
  if (item.suppression?.isExpired === true || item.suppression?.isValid === false) {
    return "manual_review";
  }

  if (isBlockingDiffFinding(item)) {
    return "fix_before_commit";
  }

  if (isLegacyNearbyContext(item) && options.includePreExisting !== true) {
    return "monitor";
  }

  if (item.finding.confidence === "low") {
    return "suppress_if_accepted";
  }

  switch (item.diffContext.relation) {
    case "introduced_by_diff":
      return isAtLeastSeverity(item.finding.severity, "medium") ? "manual_review" : "monitor";
    case "same_unsafe_site_context":
      return isAtLeastSeverity(item.finding.severity, "medium") ? "manual_review" : "monitor";
    case "same_function_context":
      return isAtLeastSeverity(item.finding.severity, "medium") && isMediumOrHighConfidence(item.finding.confidence)
        ? "manual_review"
        : "monitor";
    case "nearby_legacy_context":
      return options.includePreExisting === true && isAtLeastSeverity(item.finding.severity, "medium")
        ? "manual_review"
        : "monitor";
    case "unrelated_nearby":
      return "monitor";
    case "pre_existing_in_changed_file":
      return isAtLeastSeverity(item.finding.severity, "medium") ? "manual_review" : "suppress_if_accepted";
  }
}

function isBlockingDiffFinding(item: DiffAwareFinding): boolean {
  if (!isMediumOrHighConfidence(item.finding.confidence)) {
    return false;
  }

  if (!isAtLeastSeverity(item.finding.severity, "high")) {
    return false;
  }

  return item.diffContext.relation === "introduced_by_diff";
}

function canCodexFixFinding(item: DiffAwareFinding, recommendedAction: RecommendedAction): boolean {
  return (
    recommendedAction === "fix_before_commit" &&
    item.finding.confidence !== "low" &&
    (item.diffContext.relation === "introduced_by_diff" ||
      item.diffContext.relation === "same_unsafe_site_context")
  );
}

function isLegacyNearbyContext(item: DiffAwareFinding): boolean {
  return item.diffContext.relation === "nearby_legacy_context" || item.diffContext.relation === "unrelated_nearby";
}

function isMediumOrHighConfidence(confidence: Confidence): boolean {
  return confidence === "medium" || confidence === "high";
}

function isAtLeastSeverity(severity: Severity, threshold: Severity): boolean {
  return severityRank(severity) >= severityRank(threshold);
}

function severityRank(severity: Severity): number {
  switch (severity) {
    case "info":
      return 0;
    case "low":
      return 1;
    case "medium":
      return 2;
    case "high":
      return 3;
    case "critical":
      return 4;
  }
}

function countRelation(findings: readonly DiffAwareFinding[], relation: FindingDiffContext["relation"]): number {
  return findings.filter((item) => item.diffContext.relation === relation).length;
}

function countContextRelations(findings: readonly DiffAwareFinding[]): number {
  return findings.filter(
    (item) =>
      item.diffContext.relation === "same_unsafe_site_context" ||
      item.diffContext.relation === "same_function_context" ||
      item.diffContext.relation === "nearby_legacy_context" ||
      item.diffContext.relation === "unrelated_nearby"
  ).length;
}

function suggestedFixPrompt(item: DiffAwareFinding, recommendedAction: RecommendedAction): string {
  const finding = item.finding;
  const location = formatFindingLocation(finding);
  const functionPhrase =
    item.diffContext.functionName === undefined ? "" : ` inside function ${item.diffContext.functionName}`;
  const changedContext = formatChangedLineContext(item);
  const relation = relationPhrase(item);
  const ruleFix = sentenceToLowercase(finding.suggestedFix);

  if (item.diffContext.relation === "nearby_legacy_context" || item.diffContext.relation === "unrelated_nearby") {
    return `Legacy context near the current diff: ${finding.ruleId} at ${location}${functionPhrase}. Review separately; do not treat this as a required fix for the current diff.`;
  }

  if (item.diffContext.relation === "same_function_context") {
    return `Please manually confirm ${finding.ruleId} at ${location}${functionPhrase}. ${relation}${changedContext} This is pre-existing context in the same function as the current diff; first decide whether the changed code can affect this invariant before proposing a fix.`;
  }

  if (finding.confidence === "low") {
    return `Please review low-confidence ${finding.ruleId} at ${location}${functionPhrase}. ${relation}${changedContext} Do not modify code yet; first confirm whether the finding is real, then explain the safest fix or document why the risk is accepted.`;
  }

  switch (recommendedAction) {
    case "fix_before_commit":
      return `Please review ${finding.ruleId} at ${location}${functionPhrase}. ${relation}${changedContext} First explain the safety invariant and repair strategy, then ${ruleFix}`;
    case "manual_review":
      return `Please review ${finding.ruleId} at ${location}${functionPhrase}. ${relation}${changedContext} First explain whether the reported invariant is real, then propose the smallest safe fix if it is valid: ${finding.suggestedFix}`;
    case "monitor":
      return `Please inspect ${finding.ruleId} at ${location}${functionPhrase}. ${relation}${changedContext} Treat this as a non-blocking context note unless project policy requires a fix; if fixing, first explain the invariant and then apply: ${finding.suggestedFix}`;
    case "suppress_if_accepted":
      return `Please manually confirm ${finding.ruleId} at ${location}${functionPhrase}. ${relation}${changedContext} If the risk is intentional, document the acceptance with a rust-security-auditor suppression comment that includes a clear reason, owner, and ticket.`;
  }
}

function relationPhrase(item: DiffAwareFinding): string {
  switch (item.diffContext.relation) {
    case "introduced_by_diff":
      return "This finding appears introduced by the current diff.";
    case "same_unsafe_site_context":
      return "This finding is pre-existing context in the same unsafe site touched by the current diff.";
    case "same_function_context":
      return "This finding is pre-existing context in the same function touched by the current diff.";
    case "nearby_legacy_context":
      return "This finding is nearby legacy context, not part of the changed function or unsafe site.";
    case "unrelated_nearby":
      return "This finding is only line-near the current diff and has no confirmed function or unsafe-site tie.";
    case "pre_existing_in_changed_file":
      return "This finding appears pre-existing in a file touched by the current diff.";
  }
}

function formatChangedLineContext(item: DiffAwareFinding): string {
  const parts: string[] = [];

  if (item.diffContext.nearestChangedLine !== undefined) {
    parts.push(`nearest changed line ${item.diffContext.nearestChangedLine}`);
  }

  if (item.diffContext.nearestChangedFunctionName !== undefined) {
    parts.push(`changed-line function ${item.diffContext.nearestChangedFunctionName}`);
  }

  if (item.diffContext.contextAssessment === "unknown" && item.diffContext.relation === "unrelated_nearby") {
    parts.push("function/site match unknown");
  }

  if (parts.length === 0) return "";

  return ` Context: ${parts.join(", ")}.`;
}

function suppressionSuggestion(finding: Finding): string {
  return `// rust-security-auditor: ignore ${finding.ruleId} -- explain why this risk is acceptable`;
}

function formatFindingLocation(finding: Finding): string {
  if (finding.startLine === undefined) {
    return finding.file;
  }

  if (finding.endLine !== undefined && finding.endLine !== finding.startLine) {
    return `${finding.file}:${finding.startLine}-${finding.endLine}`;
  }

  return `${finding.file}:${finding.startLine}`;
}

function sentenceToLowercase(value: string): string {
  const trimmed = value.trim();
  return `${trimmed.slice(0, 1).toLowerCase()}${trimmed.slice(1)}`;
}
