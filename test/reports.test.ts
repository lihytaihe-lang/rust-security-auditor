import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  type Finding,
  FindingSchemaError,
  renderJsonReport,
  renderMarkdownReport,
  summarizeFindings,
  validateFinding
} from "../src/reports/index.js";

const commandFinding: Finding = {
  id: "RSA-001",
  ruleId: "RSA-BUILD-COMMAND",
  title: "Command execution reaches external input",
  severity: "high",
  confidence: "high",
  category: "command_execution",
  file: "src/runner.rs",
  startLine: 42,
  evidence: ["Command::new receives a user-controlled binary name."],
  whyItMatters: "External control over command execution can cross a privilege boundary.",
  riskScenario: "An attacker supplies a malicious executable name and gains code execution.",
  suggestedFix: "Use an allowlist of commands and pass untrusted values only as validated arguments.",
  suggestedTests: ["Reject command names outside the allowlist."]
};

describe("finding schema", () => {
  it("accepts a complete finding", () => {
    assert.deepEqual(validateFinding(commandFinding), commandFinding);
  });

  it("rejects findings without evidence", () => {
    assert.throws(
      () => validateFinding({ ...commandFinding, evidence: [] }),
      (error) => error instanceof FindingSchemaError && error.issues.includes("evidence must contain at least one item")
    );
  });

  it("rejects findings without ruleId", () => {
    const { ruleId: _ruleId, ...withoutRuleId } = commandFinding;

    assert.throws(
      () => validateFinding(withoutRuleId),
      (error) => error instanceof FindingSchemaError && error.issues.includes("ruleId must be a non-empty string")
    );
  });

  it("summarizes severity and pre-release counts", () => {
    const summary = summarizeFindings([
      commandFinding,
      {
        ...commandFinding,
        id: "RSA-002",
        severity: "medium",
        confidence: "low",
        category: "manual_review"
      }
    ]);

    assert.equal(summary.result, "NEEDS_FIX_BEFORE_RELEASE");
    assert.equal(summary.high, 1);
    assert.equal(summary.medium, 1);
    assert.equal(summary.manualReview, 1);
  });
});

describe("reporters", () => {
  it("renders markdown with stable security sections", () => {
    const markdown = renderMarkdownReport({ findings: [commandFinding], generatedAt: "2026-05-16T00:00:00.000Z" });

    assert.match(markdown, /# Rust Security Audit Report/);
    assert.match(markdown, /## High Risk Findings/);
    assert.match(markdown, /### RSA-001: Command execution reaches external input/);
    assert.match(markdown, /- Rule: RSA-BUILD-COMMAND/);
    assert.match(markdown, /- Location: `src\/runner.rs:42`/);
    assert.match(markdown, /## Needs Manual Review/);
  });

  it("renders json with schema version and summary", () => {
    const parsed = JSON.parse(
      renderJsonReport({ findings: [commandFinding], generatedAt: "2026-05-16T00:00:00.000Z" })
    ) as { schemaVersion: string; summary: { high: number }; findings: Finding[] };

    assert.equal(parsed.schemaVersion, "0.2.0");
    assert.equal(parsed.summary.high, 1);
    assert.equal(parsed.findings[0]?.id, "RSA-001");
    assert.equal(parsed.findings[0]?.ruleId, "RSA-BUILD-COMMAND");
  });
});
