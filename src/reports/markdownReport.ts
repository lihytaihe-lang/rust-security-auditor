import {
  type AuditReportInput,
  type Finding,
  type Severity,
  isManualReviewFinding,
  summarizeFindings,
  validateFindings
} from "./schemas.js";

const severityOrder: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

export function renderMarkdownReport(input: AuditReportInput): string {
  const findings = validateFindings([...input.findings]);
  const summary = summarizeFindings(findings, input.result);
  const manualReviewFindings = findings.filter(isManualReviewFinding);
  const regularFindings = findings.filter((finding) => !isManualReviewFinding(finding));
  const lines: string[] = [
    `# ${input.title ?? "Rust Security Audit Report"}`,
    "",
    "## Summary",
    "",
    `- Result: ${summary.result}`,
    `- Critical: ${summary.critical}`,
    `- High: ${summary.high}`,
    `- Medium: ${summary.medium}`,
    `- Low: ${summary.low}`,
    `- Info: ${summary.info}`,
    `- Manual Review: ${summary.manualReview}`
  ];

  if (input.scope !== undefined) {
    lines.push(`- Scope: ${input.scope}`);
  }

  if (input.summaryNotes !== undefined && input.summaryNotes.length > 0) {
    lines.push("", "## Notes", "");
    for (const note of input.summaryNotes) {
      lines.push(`- ${note}`);
    }
  }

  for (const severity of severityOrder) {
    const group = regularFindings.filter((finding) => finding.severity === severity);
    lines.push("", `## ${sectionTitle(severity)}`, "");

    if (group.length === 0) {
      lines.push(`No ${severity} risk findings.`);
      continue;
    }

    for (const finding of group) {
      lines.push(...formatFinding(finding), "");
    }
  }

  lines.push("", "## Needs Manual Review", "");

  if (manualReviewFindings.length === 0) {
    lines.push("No manual review items.");
  } else {
    for (const finding of manualReviewFindings) {
      lines.push(...formatFinding(finding), "");
    }
  }

  lines.push(
    "",
    "## Pre-Release Recommendation",
    "",
    input.releaseGateRecommendation ?? defaultReleaseGateRecommendation(summary.result)
  );

  return `${lines.join("\n").replace(/\n{3,}/g, "\n\n").trimEnd()}\n`;
}

function formatFinding(finding: Finding): string[] {
  const lines = [
    `### ${finding.id}: ${finding.title}`,
    "",
    `- Severity: ${titleCase(finding.severity)}`,
    `- Confidence: ${titleCase(finding.confidence)}`,
    `- Category: ${finding.category}`,
    `- Rule: ${finding.ruleId}`,
    `- Location: \`${formatLocation(finding)}\``,
    "",
    "#### Evidence",
    "",
    ...finding.evidence.map((item) => `- ${item}`),
    "",
    "#### Why it matters",
    "",
    finding.whyItMatters,
    "",
    "#### Risk scenario",
    "",
    finding.riskScenario,
    "",
    "#### Suggested fix",
    "",
    finding.suggestedFix
  ];

  if (finding.suggestedTests !== undefined && finding.suggestedTests.length > 0) {
    lines.push("", "#### Suggested tests", "", ...finding.suggestedTests.map((item) => `- ${item}`));
  }

  if (finding.falsePositiveNotes !== undefined) {
    lines.push("", "#### False positive notes", "", finding.falsePositiveNotes);
  }

  if (finding.references !== undefined && finding.references.length > 0) {
    lines.push("", "#### References", "", ...finding.references.map((item) => `- ${item}`));
  }

  return lines;
}

function formatLocation(finding: Finding): string {
  if (finding.startLine === undefined) {
    return finding.file;
  }

  if (finding.endLine !== undefined && finding.endLine !== finding.startLine) {
    return `${finding.file}:${finding.startLine}-${finding.endLine}`;
  }

  return `${finding.file}:${finding.startLine}`;
}

function sectionTitle(severity: Severity): string {
  switch (severity) {
    case "critical":
      return "Critical Risk Findings";
    case "high":
      return "High Risk Findings";
    case "medium":
      return "Medium Risk Findings";
    case "low":
      return "Low Risk Findings";
    case "info":
      return "Informational Findings";
  }
}

function titleCase(value: string): string {
  return `${value.slice(0, 1).toUpperCase()}${value.slice(1)}`;
}

function defaultReleaseGateRecommendation(result: string): string {
  switch (result) {
    case "PASS":
      return "No security findings were reported by the configured checks.";
    case "PASS_WITH_WARNINGS":
      return "Review warnings before merge; no current finding blocks release.";
    case "NEEDS_FIX_BEFORE_RELEASE":
      return "Fix high or critical security findings before release or merge.";
    case "MANUAL_SECURITY_REVIEW_REQUIRED":
      return "Complete manual security review before release.";
    default:
      return "Review the report before release.";
  }
}
