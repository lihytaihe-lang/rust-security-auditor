import type { Confidence, Finding, Severity } from "../reports/index.js";
import type {
  DiffAwareFinding,
  DiffReviewSummaryMetrics,
  FindingActionability,
  FindingDiffContext,
  RecommendedAction,
  ReviewDecision
} from "./types.js";

export function shouldDisplayDiffFinding(item: DiffAwareFinding, includePreExisting: boolean): boolean {
  if (item.suppression?.isExpired === true || item.suppression?.isValid === false) {
    return true;
  }

  switch (item.diffContext.relation) {
    case "introduced_by_diff":
      return true;
    case "near_changed_lines":
      return isAtLeastSeverity(item.finding.severity, "medium") && isMediumOrHighConfidence(item.finding.confidence);
    case "pre_existing_in_changed_file":
      return includePreExisting;
  }
}

export function withDiffReviewActionability(findings: readonly DiffAwareFinding[]): DiffAwareFinding[] {
  return findings.map((item) => ({
    ...item,
    actionability: actionabilityForDiffFinding(item)
  }));
}

export function actionabilityForDiffFinding(item: DiffAwareFinding): FindingActionability {
  const recommendedAction = recommendedActionForDiffFinding(item);
  const actionability: FindingActionability = {
    recommendedAction,
    canCodexFix: recommendedAction === "fix_before_commit" && item.finding.confidence !== "low",
    suggestedFixPrompt: suggestedFixPrompt(item, recommendedAction)
  };

  if (recommendedAction === "suppress_if_accepted") {
    actionability.suppressionSuggestion = suppressionSuggestion(item.finding);
  }

  return actionability;
}

export function inferReviewDecision(findings: readonly DiffAwareFinding[]): ReviewDecision {
  const actionableFindings = withDiffReviewActionability(findings);
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

  if (blockingFindingIds.length > 0) {
    return {
      status: "block",
      reason:
        "The reviewed diff has high or critical security findings with enough confidence to block before commit.",
      blockingFindingIds,
      needsManualReviewFindingIds,
      safeToCommit: false
    };
  }

  if (needsManualReviewFindingIds.length > 0) {
    return {
      status: "needs_attention",
      reason:
        "No hard blockers were found, but the diff has medium-severity, nearby, or low-confidence findings that need human review before commit.",
      blockingFindingIds,
      needsManualReviewFindingIds,
      safeToCommit: false
    };
  }

  return {
    status: "pass",
    reason:
      findings.length === 0
        ? "No introduced or nearby security findings were reported for the reviewed diff."
        : "Only non-blocking findings were reported for the reviewed diff.",
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
    nearChangedFindingCount: countRelation(input.visibleFindings, "near_changed_lines"),
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

function recommendedActionForDiffFinding(item: DiffAwareFinding): RecommendedAction {
  if (item.suppression?.isExpired === true || item.suppression?.isValid === false) {
    return "manual_review";
  }

  if (isBlockingDiffFinding(item)) {
    return "fix_before_commit";
  }

  if (item.finding.confidence === "low") {
    return "suppress_if_accepted";
  }

  if (isNearChangedDifferentContext(item)) {
    return "monitor";
  }

  if (item.diffContext.relation === "pre_existing_in_changed_file") {
    return isAtLeastSeverity(item.finding.severity, "medium") ? "manual_review" : "suppress_if_accepted";
  }

  if (isAtLeastSeverity(item.finding.severity, "medium")) {
    return "manual_review";
  }

  return "monitor";
}

function isBlockingDiffFinding(item: DiffAwareFinding): boolean {
  if (!isMediumOrHighConfidence(item.finding.confidence)) {
    return false;
  }

  if (!isAtLeastSeverity(item.finding.severity, "high")) {
    return false;
  }

  if (item.diffContext.relation === "introduced_by_diff") {
    return true;
  }

  if (isNearChangedDifferentContext(item)) {
    return false;
  }

  return (
    item.diffContext.relation === "near_changed_lines" &&
    item.diffContext.contextAssessment === "same_function_or_unsafe_site" &&
    item.finding.confidence === "high"
  );
}

function isNearChangedDifferentContext(item: DiffAwareFinding): boolean {
  return (
    item.diffContext.relation === "near_changed_lines" &&
    item.diffContext.contextAssessment === "different_function_or_unsafe_site"
  );
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

function suggestedFixPrompt(item: DiffAwareFinding, recommendedAction: RecommendedAction): string {
  const finding = item.finding;
  const location = formatFindingLocation(finding);
  const functionPhrase =
    item.diffContext.functionName === undefined ? "" : ` inside function ${item.diffContext.functionName}`;
  const changedContext = formatChangedLineContext(item);
  const relation = relationPhrase(item);
  const ruleFix = sentenceToLowercase(finding.suggestedFix);

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
      return `Please manually confirm ${finding.ruleId} at ${location}${functionPhrase}. ${relation}${changedContext} If the risk is intentional, document the acceptance with a rustsec-auditor suppression comment that includes a clear reason, owner, and ticket.`;
  }
}

function relationPhrase(item: DiffAwareFinding): string {
  switch (item.diffContext.relation) {
    case "introduced_by_diff":
      return "This finding appears introduced by the current diff.";
    case "near_changed_lines":
      return "This finding is near changed code, not necessarily introduced by the current diff.";
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

  if (item.diffContext.contextAssessment === "unknown" && item.diffContext.relation === "near_changed_lines") {
    parts.push("function/site match unknown");
  }

  if (parts.length === 0) return "";

  return ` Context: ${parts.join(", ")}.`;
}

function suppressionSuggestion(finding: Finding): string {
  return `// rustsec-auditor: ignore ${finding.ruleId} -- explain why this risk is acceptable`;
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
