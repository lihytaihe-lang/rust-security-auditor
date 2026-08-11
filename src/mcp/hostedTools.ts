import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import * as z from "zod/v4";
import {
  categories,
  severities,
  type Category,
  type Finding,
  type Severity
} from "../reports/index.js";
import {
  scanBuildScriptText,
  scanCargoLockText,
  scanCargoManifestText
} from "../scanners/dependencyScanner.js";
import { dedupeFindings, sortFindings } from "../scanners/resultUtils.js";
import { isSuppressionExpired, parseSuppressionDirective } from "../scanners/suppressions.js";
import { scanUnsafeRustText } from "../scanners/unsafeScanner.js";
import {
  acceptedRiskSuppressionFixture,
  dependencyManifestFixture,
  fixtureDiffReviewFixture,
  getHostedFixture,
  isHostedFixtureId,
  unsafeUsageFixture,
  withHostedDiffFixture,
  type HostedFixtureId
} from "./hostedFixtures.js";
import { rustReviewCurrentDiff } from "./tools.js";
import type {
  AcceptedRisk,
  McpAuditError,
  McpAuditSummary,
  ReviewDecision,
  RiskLevel
} from "./types.js";

export const hostedMcpToolNames = [
  "rust_audit_unsafe",
  "rust_audit_dependencies",
  "rust_list_accepted_risks",
  "rust_review_current_diff"
] as const;

export type HostedMcpToolName = (typeof hostedMcpToolNames)[number];
export type HostedSourceKind = "fixture" | "pasted_snippet" | "public_demo_metadata";

export interface HostedFinding {
  id: string;
  ruleId: string;
  title: string;
  severity: Severity;
  confidence: "low" | "medium" | "high";
  category: Category;
  file: string;
  startLine?: number | undefined;
  endLine?: number | undefined;
  evidenceSnippets: string[];
  limitations: string[];
  suggestedNextSteps: string[];
}

export interface HostedMcpToolOutput {
  tool: HostedMcpToolName;
  sourceKind: HostedSourceKind;
  fixture_id?: string | undefined;
  markdownSummary: string;
  riskLevel: RiskLevel;
  summary: Record<string, unknown>;
  findings: HostedFinding[];
  evidenceSnippets: string[];
  limitations: string[];
  suggestedNextSteps: string[];
  confidenceNote: string;
  privacy: {
    inputPolicy: string;
    doesNotReadLocalProjects: true;
    doesNotAcceptPrivateRepoTokens: true;
    doesNotPersistSource: true;
    loggingPolicy: string;
  };
  acceptedRisks?: AcceptedRisk[] | undefined;
  reviewDecision?: ReviewDecision | undefined;
  error?: McpAuditError | undefined;
}

type UnknownRecord = Record<string, unknown>;

const maxPastedSourceChars = 12_000;
const maxTotalInputChars = 24_000;
const confidenceNote = "confidence is pattern-detection confidence, not exploitability confidence";
const inputPolicy = "Only fixture_id, short pasted snippets, and public demo metadata are accepted.";
const defaultLimitations = [
  "Hosted MCP spike only scans bundled demo fixtures or explicitly pasted short snippets.",
  "It does not read local project paths, private repositories, repository tokens, or absolute paths.",
  "The scanner is heuristic static pattern detection, not full data-flow analysis, exploitability analysis, formal verification, or a complete security audit.",
  "Confidence means pattern-detection confidence, not exploitability confidence."
];
const readOnlyAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false
};

const riskLevelSchema = z.enum(["pass", "warning", "needs_attention", "high_risk"]);
const hostedToolNameSchema = z.enum(hostedMcpToolNames);
const sourceKindSchema = z.enum(["fixture", "pasted_snippet", "public_demo_metadata"]);
const publicDemoMetadataSchema = z
  .object({
    label: z.string().optional(),
    scenario: z.string().optional(),
    source_url: z.string().optional()
  })
  .passthrough();

const hostedBaseInputSchema = z
  .object({
    fixture_id: z.string().optional(),
    public_demo_metadata: publicDemoMetadataSchema.optional()
  })
  .passthrough();

const hostedUnsafeInputSchema = hostedBaseInputSchema.extend({
  snippet: z.string().optional(),
  pasted_snippet: z.string().optional()
});

const hostedDependencyInputSchema = hostedBaseInputSchema.extend({
  cargo_toml_snippet: z.string().optional(),
  cargo_lock_snippet: z.string().optional(),
  build_rs_snippet: z.string().optional()
});

const hostedAcceptedRiskInputSchema = hostedBaseInputSchema.extend({
  suppression_snippet: z.string().optional(),
  include_expired: z.boolean().optional(),
  include_invalid: z.boolean().optional()
});

const hostedDiffInputSchema = hostedBaseInputSchema.extend({
  diff_snippet: z.string().optional()
});

export const hostedMcpOutputSchema = {
  tool: hostedToolNameSchema,
  sourceKind: sourceKindSchema,
  fixture_id: z.string().optional(),
  markdownSummary: z.string(),
  riskLevel: riskLevelSchema,
  summary: z.object({ riskLevel: riskLevelSchema.optional(), findingCount: z.number().optional() }).passthrough(),
  findings: z.array(
    z
      .object({
        id: z.string(),
        ruleId: z.string(),
        title: z.string(),
        severity: z.enum(severities),
        confidence: z.enum(["low", "medium", "high"]),
        category: z.enum(categories),
        file: z.string(),
        startLine: z.number().optional(),
        endLine: z.number().optional(),
        evidenceSnippets: z.array(z.string()),
        limitations: z.array(z.string()),
        suggestedNextSteps: z.array(z.string())
      })
      .passthrough()
  ),
  evidenceSnippets: z.array(z.string()),
  limitations: z.array(z.string()),
  suggestedNextSteps: z.array(z.string()),
  confidenceNote: z.string(),
  privacy: z
    .object({
      inputPolicy: z.string(),
      doesNotReadLocalProjects: z.literal(true),
      doesNotAcceptPrivateRepoTokens: z.literal(true),
      doesNotPersistSource: z.literal(true),
      loggingPolicy: z.string()
    })
    .passthrough(),
  acceptedRisks: z.array(z.unknown()).optional(),
  reviewDecision: z.unknown().optional(),
  error: z.object({ code: z.string(), message: z.string() }).optional()
};

export function createHostedRustSecurityAuditorMcpServer(): McpServer {
  const server = new McpServer({
    name: "rust-security-auditor-hosted-demo",
    version: "0.1.1-stage2"
  });

  server.registerTool(
    "rust_audit_unsafe",
    {
      title: "Audit hosted demo unsafe Rust",
      description:
        "Fixture-safe hosted demo tool. Audits the unsafe_usage fixture or a short pasted Rust snippet for unsafe/FFI review signals. Does not accept project paths, private repository tokens, or full private repositories.",
      annotations: readOnlyAnnotations,
      inputSchema: hostedUnsafeInputSchema,
      outputSchema: hostedMcpOutputSchema
    },
    async (input) => toCallToolResult(await hostedRustAuditUnsafe(input))
  );

  server.registerTool(
    "rust_audit_dependencies",
    {
      title: "Audit hosted demo Cargo metadata",
      description:
        "Fixture-safe hosted demo tool. Audits the dependency_manifest fixture or short pasted Cargo/build snippets for supply-chain review signals. It does not query vulnerability databases and does not accept private repository tokens.",
      annotations: readOnlyAnnotations,
      inputSchema: hostedDependencyInputSchema,
      outputSchema: hostedMcpOutputSchema
    },
    async (input) => toCallToolResult(await hostedRustAuditDependencies(input))
  );

  server.registerTool(
    "rust_list_accepted_risks",
    {
      title: "List hosted demo accepted risks",
      description:
        "Fixture-safe hosted demo tool. Lists accepted-risk suppressions from the accepted_risk_suppression fixture or a short pasted suppression snippet. Does not read local project files.",
      annotations: readOnlyAnnotations,
      inputSchema: hostedAcceptedRiskInputSchema,
      outputSchema: hostedMcpOutputSchema
    },
    async (input) => toCallToolResult(await hostedRustListAcceptedRisks(input))
  );

  server.registerTool(
    "rust_review_current_diff",
    {
      title: "Review hosted demo Rust diff",
      description:
        "Fixture-only hosted demo tool. Reviews the fixture_diff demo diff and refuses pasted diffs, local paths, and private repository data. Use the local stdio MCP tool for real private working-tree review.",
      annotations: readOnlyAnnotations,
      inputSchema: hostedDiffInputSchema,
      outputSchema: hostedMcpOutputSchema
    },
    async (input) => toCallToolResult(await hostedRustReviewCurrentDiff(input))
  );

  return server;
}

export async function hostedRustAuditUnsafe(input: unknown): Promise<HostedMcpToolOutput> {
  const guard = validateHostedInput("rust_audit_unsafe", input);
  if (guard !== undefined) return guard;

  try {
    const record = asRecord(input);
    const pastedSnippet = getOptionalString(record, "snippet") ?? getOptionalString(record, "pasted_snippet");

    if (pastedSnippet !== undefined) {
      const findings = prepareFindings(scanUnsafeRustText("snippet.rs", pastedSnippet));
      return buildHostedFindingOutput({
        tool: "rust_audit_unsafe",
        sourceKind: "pasted_snippet",
        title: "Rust Unsafe Audit Hosted Demo",
        sourceLabel: "pasted snippet",
        summary: summarizeFindings(findings, 0),
        findings,
        limitations: ["Pasted snippets lack full project context, Cargo feature context, and surrounding call graph context."],
        suggestedNextSteps: unsafeNextSteps(findings)
      });
    }

    const fixtureId = resolveFixtureId("rust_audit_unsafe", record, ["unsafe_usage"], unsafeUsageFixture.id);
    if (typeof fixtureId !== "string") return fixtureId;

    const fixture = getHostedFixture(fixtureId);
    const source = fixture.files["src/lib.rs"] ?? "";
    const findings = prepareFindings(scanUnsafeRustText("src/lib.rs", source));

    return buildHostedFindingOutput({
      tool: "rust_audit_unsafe",
      sourceKind: "fixture",
      fixtureId,
      title: "Rust Unsafe Audit Hosted Demo",
      sourceLabel: `fixture_id=${fixtureId}`,
      summary: summarizeFindings(findings, 0),
      findings,
      limitations: [`Fixture: ${fixture.description}`],
      suggestedNextSteps: unsafeNextSteps(findings)
    });
  } catch (error) {
    return hostedErrorOutput("rust_audit_unsafe", "HOSTED_UNSAFE_FAILED", sanitizeErrorMessage(error));
  }
}

export async function hostedRustAuditDependencies(input: unknown): Promise<HostedMcpToolOutput> {
  const guard = validateHostedInput("rust_audit_dependencies", input);
  if (guard !== undefined) return guard;

  try {
    const record = asRecord(input);
    const pastedCargoToml = getOptionalString(record, "cargo_toml_snippet");
    const pastedCargoLock = getOptionalString(record, "cargo_lock_snippet");
    const pastedBuildRs = getOptionalString(record, "build_rs_snippet");

    if (pastedCargoToml !== undefined || pastedCargoLock !== undefined || pastedBuildRs !== undefined) {
      const findings = prepareFindings([
        ...(pastedCargoToml === undefined ? [] : scanCargoManifestText("Cargo.toml", pastedCargoToml)),
        ...(pastedCargoLock === undefined ? [] : scanCargoLockText("Cargo.lock", pastedCargoLock)),
        ...(pastedBuildRs === undefined ? [] : scanBuildScriptText("build.rs", pastedBuildRs))
      ]);

      return buildHostedFindingOutput({
        tool: "rust_audit_dependencies",
        sourceKind: "pasted_snippet",
        title: "Rust Dependency Audit Hosted Demo",
        sourceLabel: "pasted Cargo/build snippets",
        summary: summarizeFindings(findings, 0),
        findings,
        limitations: [
          "Pasted dependency snippets lack full workspace, feature resolution, transitive dependency, and registry context.",
          "This tool does not query vulnerability databases; run cargo audit or a RustSec-compatible database check separately."
        ],
        suggestedNextSteps: dependencyNextSteps(findings)
      });
    }

    const fixtureId = resolveFixtureId(
      "rust_audit_dependencies",
      record,
      ["dependency_manifest"],
      dependencyManifestFixture.id
    );
    if (typeof fixtureId !== "string") return fixtureId;

    const fixture = getHostedFixture(fixtureId);
    const findings = prepareFindings([
      ...scanCargoManifestText("Cargo.toml", fixture.files["Cargo.toml"] ?? ""),
      ...scanCargoLockText("Cargo.lock", fixture.files["Cargo.lock"] ?? ""),
      ...scanBuildScriptText("build.rs", fixture.files["build.rs"] ?? "")
    ]);

    return buildHostedFindingOutput({
      tool: "rust_audit_dependencies",
      sourceKind: "fixture",
      fixtureId,
      title: "Rust Dependency Audit Hosted Demo",
      sourceLabel: `fixture_id=${fixtureId}`,
      summary: summarizeFindings(findings, 0),
      findings,
      limitations: [
        `Fixture: ${fixture.description}`,
        "This tool does not query vulnerability databases; run cargo audit or a RustSec-compatible database check separately."
      ],
      suggestedNextSteps: dependencyNextSteps(findings)
    });
  } catch (error) {
    return hostedErrorOutput("rust_audit_dependencies", "HOSTED_DEPENDENCY_FAILED", sanitizeErrorMessage(error));
  }
}

export async function hostedRustListAcceptedRisks(input: unknown): Promise<HostedMcpToolOutput> {
  const guard = validateHostedInput("rust_list_accepted_risks", input);
  if (guard !== undefined) return guard;

  try {
    const record = asRecord(input);
    const includeExpired = getOptionalBoolean(record, "include_expired") ?? getOptionalBoolean(record, "includeExpired") ?? true;
    const includeInvalid = getOptionalBoolean(record, "include_invalid") ?? getOptionalBoolean(record, "includeInvalid") ?? true;
    const pastedSnippet = getOptionalString(record, "suppression_snippet");
    const fixtureId = pastedSnippet === undefined
      ? resolveFixtureId(
          "rust_list_accepted_risks",
          record,
          ["accepted_risk_suppression"],
          acceptedRiskSuppressionFixture.id
        )
      : undefined;

    if (fixtureId !== undefined && typeof fixtureId !== "string") return fixtureId;

    const source = pastedSnippet ?? getHostedFixture(fixtureId ?? "accepted_risk_suppression").files["src/lib.rs"] ?? "";
    const acceptedRisks = scanAcceptedRiskText("src/lib.rs", source, { includeExpired, includeInvalid });
    const summary = summarizeAcceptedRiskOutput(acceptedRisks);
    const findings = acceptedRisks.map(acceptedRiskToHostedFinding);
    const sourceKind: HostedSourceKind = pastedSnippet === undefined ? "fixture" : "pasted_snippet";
    const sourceLabel = pastedSnippet === undefined ? `fixture_id=${fixtureId ?? "accepted_risk_suppression"}` : "pasted suppression snippet";

    return buildHostedFindingOutput({
      tool: "rust_list_accepted_risks",
      sourceKind,
      fixtureId,
      title: "Rust Accepted Risk Inventory Hosted Demo",
      sourceLabel,
      summary,
      findings,
      limitations: [
        "Suppression inventory is based on accepted-risk suppression comments only; it does not prove that accepted risks are still justified.",
        "Owners, tickets, and dates in hosted fixtures are public demo metadata."
      ],
      suggestedNextSteps: acceptedRiskNextSteps(acceptedRisks),
      acceptedRisks
    });
  } catch (error) {
    return hostedErrorOutput("rust_list_accepted_risks", "HOSTED_ACCEPTED_RISK_FAILED", sanitizeErrorMessage(error));
  }
}

export async function hostedRustReviewCurrentDiff(input: unknown): Promise<HostedMcpToolOutput> {
  const guard = validateHostedInput("rust_review_current_diff", input);
  if (guard !== undefined) return guard;

  try {
    const record = asRecord(input);
    if (getOptionalString(record, "diff_snippet") !== undefined) {
      return hostedErrorOutput(
        "rust_review_current_diff",
        "FIXTURE_DIFF_ONLY",
        "Hosted rust_review_current_diff only accepts fixture_id=fixture_diff in this spike."
      );
    }

    const fixtureId = resolveFixtureId("rust_review_current_diff", record, ["fixture_diff"], fixtureDiffReviewFixture.id);
    if (typeof fixtureId !== "string") return fixtureId;

    return await withHostedDiffFixture(async (projectPath) => {
      const output = await rustReviewCurrentDiff({
        projectPath,
        outputFormat: "markdown",
        pathMode: "relative",
        reportMode: "compact"
      });
      const findings = prepareFindings(output.findings);
      const summary: Record<string, unknown> = {
        ...output.summary,
        reviewDecision: output.reviewDecision,
        diffAffectedFiles: output.diffAffectedFiles ?? [],
        parsedDiffFileCount: output.diff?.files.length ?? 0
      };

      return buildHostedFindingOutput({
        tool: "rust_review_current_diff",
        sourceKind: "fixture",
        fixtureId,
        title: "Rust Current Diff Review Hosted Demo",
        sourceLabel: `fixture_id=${fixtureId}`,
        summary,
        findings,
        limitations: [
          `Fixture: ${fixtureDiffReviewFixture.description}`,
          "Hosted diff review is fixture-only in this spike; it does not read a local git work tree or private repository.",
          ...(output.warnings ?? [])
        ],
        suggestedNextSteps: diffNextSteps(findings, output.reviewDecision),
        reviewDecision: output.reviewDecision
      });
    });
  } catch (error) {
    return hostedErrorOutput("rust_review_current_diff", "HOSTED_DIFF_FAILED", sanitizeErrorMessage(error));
  }
}

function toCallToolResult(output: HostedMcpToolOutput): CallToolResult {
  return {
    content: [
      {
        type: "text",
        text: output.markdownSummary
      }
    ],
    structuredContent: output as unknown as Record<string, unknown>,
    isError: output.error !== undefined
  };
}

function validateHostedInput(tool: HostedMcpToolName, input: unknown): HostedMcpToolOutput | undefined {
  if (!isRecord(input)) {
    return hostedErrorOutput(tool, "INVALID_INPUT", "Tool input must be a JSON object.");
  }

  const total = totalStringLength(input);
  if (total > maxTotalInputChars) {
    return hostedErrorOutput(tool, "OVERSIZED_SOURCE_INPUT", `Hosted inputs are limited to ${maxTotalInputChars} total characters.`);
  }

  const issue = findSensitiveInputIssue(input, []);
  if (issue !== undefined) {
    return hostedErrorOutput(tool, issue.code, issue.message);
  }

  return undefined;
}

function findSensitiveInputIssue(value: unknown, path: readonly string[]): McpAuditError | undefined {
  if (typeof value === "string") {
    if (value.length > maxPastedSourceChars) {
      return {
        code: "OVERSIZED_SOURCE_INPUT",
        message: `Hosted pasted source inputs are limited to ${maxPastedSourceChars} characters.`
      };
    }

    if (looksLikePrivateToken(value)) {
      return {
        code: "PRIVATE_TOKEN_NOT_ACCEPTED",
        message: "Hosted demo tools do not accept private repository tokens, API keys, bearer tokens, or secrets."
      };
    }

    if (looksLikeAbsolutePath(value)) {
      return {
        code: "ABSOLUTE_PATH_NOT_ACCEPTED",
        message: "Hosted demo tools do not accept absolute local filesystem paths."
      };
    }

    return undefined;
  }

  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      const issue = findSensitiveInputIssue(value[index], [...path, String(index)]);
      if (issue !== undefined) return issue;
    }
    return undefined;
  }

  if (!isRecord(value)) return undefined;

  for (const [key, nested] of Object.entries(value)) {
    const normalizedKey = key.replaceAll("-", "_").toLowerCase();

    if (isForbiddenPathKey(normalizedKey)) {
      return {
        code: "LOCAL_PATH_INPUT_NOT_ACCEPTED",
        message: "Hosted demo tools do not accept projectPath, project_path, local_path, or absolute path inputs."
      };
    }

    if (isForbiddenTokenKey(normalizedKey)) {
      return {
        code: "PRIVATE_TOKEN_NOT_ACCEPTED",
        message: "Hosted demo tools do not accept private repository tokens, API keys, bearer tokens, or secrets."
      };
    }

    if (isForbiddenRepositoryKey(normalizedKey)) {
      return {
        code: "PRIVATE_REPOSITORY_NOT_SUPPORTED",
        message: "Hosted demo tools do not accept repository URLs or private repository metadata in this spike."
      };
    }

    const issue = findSensitiveInputIssue(nested, [...path, key]);
    if (issue !== undefined) return issue;
  }

  return undefined;
}

function resolveFixtureId(
  tool: HostedMcpToolName,
  input: UnknownRecord,
  allowed: readonly HostedFixtureId[],
  fallback: HostedFixtureId
): HostedFixtureId | HostedMcpToolOutput {
  const rawFixtureId = getOptionalString(input, "fixture_id") ?? getOptionalString(input, "fixtureId") ?? fallback;

  if (!isHostedFixtureId(rawFixtureId) || !allowed.includes(rawFixtureId)) {
    return hostedErrorOutput(
      tool,
      "INVALID_FIXTURE_ID",
      `fixture_id must be one of: ${allowed.join(", ")}.`
    );
  }

  return rawFixtureId;
}

function buildHostedFindingOutput(input: {
  tool: HostedMcpToolName;
  sourceKind: HostedSourceKind;
  fixtureId?: string | undefined;
  title: string;
  sourceLabel: string;
  summary: McpAuditSummary | Record<string, unknown>;
  findings: readonly Finding[] | readonly HostedFinding[];
  limitations: readonly string[];
  suggestedNextSteps: readonly string[];
  acceptedRisks?: AcceptedRisk[] | undefined;
  reviewDecision?: ReviewDecision | undefined;
}): HostedMcpToolOutput {
  const hostedFindings = input.findings.map((finding) =>
    isHostedFinding(finding) ? finding : findingToHostedFinding(finding)
  );
  const riskLevel = normalizeRiskLevel(input.summary.riskLevel) ?? inferRiskLevelFromHostedFindings(hostedFindings);
  const summary = { ...input.summary };
  const limitations = uniqueStrings([...defaultLimitations, ...input.limitations.map(sanitizeText)]);
  const suggestedNextSteps = uniqueStrings([
    ...input.suggestedNextSteps.map(sanitizeText),
    "Use the local stdio MCP tools for real private project or working-tree review."
  ]);
  const output: HostedMcpToolOutput = {
    tool: input.tool,
    sourceKind: input.sourceKind,
    markdownSummary: renderHostedMarkdownSummary({
      title: input.title,
      tool: input.tool,
      sourceLabel: input.sourceLabel,
      riskLevel,
      findingCount: hostedFindings.length,
      findings: hostedFindings,
      limitations,
      suggestedNextSteps
    }),
    riskLevel,
    summary: {
      ...summary,
      riskLevel,
      findingCount: hostedFindings.length
    },
    findings: hostedFindings,
    evidenceSnippets: hostedFindings.flatMap((finding) => finding.evidenceSnippets).slice(0, 8),
    limitations,
    suggestedNextSteps,
    confidenceNote,
    privacy: hostedPrivacyPolicy()
  };

  if (input.fixtureId !== undefined) output.fixture_id = input.fixtureId;
  if (input.acceptedRisks !== undefined) output.acceptedRisks = input.acceptedRisks;
  if (input.reviewDecision !== undefined) output.reviewDecision = input.reviewDecision;

  return output;
}

function hostedErrorOutput(tool: HostedMcpToolName, code: string, message: string): HostedMcpToolOutput {
  const error: McpAuditError = {
    code,
    message: sanitizeText(message)
  };
  const limitations = uniqueStrings(defaultLimitations);
  const suggestedNextSteps = [
    "Retry with a supported fixture_id or a short non-sensitive pasted snippet.",
    "Use the local stdio MCP tools for real private project or working-tree review."
  ];

  return {
    tool,
    sourceKind: "fixture",
    markdownSummary: [
      `# ${tool} request rejected`,
      "",
      `- riskLevel: warning`,
      `- errorCode: ${error.code}`,
      `- message: ${error.message}`,
      `- Confidence: ${confidenceNote}`,
      "",
      "## Limitations",
      "",
      ...limitations.map((item) => `- ${item}`),
      "",
      "## Suggested next steps",
      "",
      ...suggestedNextSteps.map((item) => `- ${item}`)
    ].join("\n"),
    riskLevel: "warning",
    summary: {
      riskLevel: "warning",
      findingCount: 0,
      error
    },
    findings: [],
    evidenceSnippets: [],
    limitations,
    suggestedNextSteps,
    confidenceNote,
    privacy: hostedPrivacyPolicy(),
    error
  };
}

function renderHostedMarkdownSummary(input: {
  title: string;
  tool: HostedMcpToolName;
  sourceLabel: string;
  riskLevel: RiskLevel;
  findingCount: number;
  findings: readonly HostedFinding[];
  limitations: readonly string[];
  suggestedNextSteps: readonly string[];
}): string {
  const lines = [
    `# ${input.title}`,
    "",
    "## Summary",
    "",
    `- Tool: ${input.tool}`,
    `- Source: ${input.sourceLabel}`,
    `- Risk level: ${input.riskLevel}`,
    `- Findings: ${input.findingCount}`,
    `- Confidence: ${confidenceNote}`,
    "",
    "## Findings",
    ""
  ];

  if (input.findings.length === 0) {
    lines.push("- No fixture findings were detected.");
  } else {
    for (const finding of input.findings.slice(0, 6)) {
      const location = finding.startLine === undefined ? finding.file : `${finding.file}:${finding.startLine}`;
      const evidence = finding.evidenceSnippets[0] === undefined ? "" : ` Evidence: ${finding.evidenceSnippets[0]}`;
      lines.push(`- ${finding.severity} ${finding.ruleId} at ${location}: ${finding.title}.${evidence}`);
    }
  }

  lines.push(
    "",
    "## Limitations",
    "",
    ...input.limitations.slice(0, 8).map((item) => `- ${item}`),
    "",
    "## Suggested next steps",
    "",
    ...input.suggestedNextSteps.slice(0, 6).map((item) => `- ${item}`),
    ""
  );

  return `${lines.join("\n").trimEnd()}\n`;
}

function findingToHostedFinding(finding: Finding): HostedFinding {
  const suggestedNextSteps = uniqueStrings([
    finding.suggestedFix,
    ...(finding.suggestedTests ?? [])
  ]).map(sanitizeText);
  const hostedFinding: HostedFinding = {
    id: finding.id,
    ruleId: finding.ruleId,
    title: finding.title,
    severity: finding.severity,
    confidence: finding.confidence,
    category: finding.category,
    file: sanitizeRelativePath(finding.file),
    evidenceSnippets: finding.evidence.map(sanitizeText).slice(0, 3),
    limitations: [
      "Finding is generated by heuristic pattern detection and needs human review.",
      "Confidence is not exploitability confidence."
    ],
    suggestedNextSteps
  };

  if (finding.startLine !== undefined) hostedFinding.startLine = finding.startLine;
  if (finding.endLine !== undefined) hostedFinding.endLine = finding.endLine;

  return hostedFinding;
}

function acceptedRiskToHostedFinding(risk: AcceptedRisk): HostedFinding {
  const severity: Severity = !risk.isValid || risk.isExpired ? "medium" : "low";
  const nextSteps = [
    risk.isExpired ? "Re-review the expired accepted risk and either fix it or renew with a fresh owner/date." : undefined,
    !risk.isValid ? "Fix the suppression metadata; valid suppressions need a concrete rule id and a reason after '--'." : undefined,
    "Confirm the accepted risk still has an owner, rationale, and review ticket."
  ].filter((item): item is string => item !== undefined);
  const finding: HostedFinding = {
    id: `ACCEPTED-RISK-${risk.ruleId}-${risk.line}`,
    ruleId: risk.ruleId,
    title: risk.isExpired ? "Expired accepted risk suppression" : risk.isValid ? "Accepted risk suppression" : "Invalid accepted risk suppression",
    severity,
    confidence: "high",
    category: "manual_review",
    file: sanitizeRelativePath(risk.file),
    startLine: risk.line,
    evidenceSnippets: [sanitizeText(risk.rawComment)],
    limitations: [
      "Suppression inventory reports accepted-risk comments; it does not validate whether the acceptance is still appropriate.",
      "Confidence is not exploitability confidence."
    ],
    suggestedNextSteps: nextSteps
  };

  return finding;
}

function scanAcceptedRiskText(
  file: string,
  source: string,
  options: { includeExpired: boolean; includeInvalid: boolean }
): AcceptedRisk[] {
  const discoveredRisks: AcceptedRisk[] = [];

  source.split(/\r?\n/).forEach((line, index) => {
    const directive = parseSuppressionDirective(line);
    if (directive === undefined) return;

    const isExpired = isSuppressionExpired(directive.until);
    const isValid = directive.invalidReasons.length === 0;
    const risk: AcceptedRisk = {
      ruleId: directive.ruleId,
      file,
      line: index + 1,
      reason: directive.reason,
      isExpired,
      isValid,
      rawComment: directive.rawComment
    };

    if (directive.owner !== undefined) risk.owner = directive.owner;
    if (directive.ticket !== undefined) risk.ticket = directive.ticket;
    if (directive.until !== undefined) risk.until = directive.until;
    if (!isValid) risk.invalidSuppression = directive.invalidReasons.join(" ");

    discoveredRisks.push(risk);
  });

  return discoveredRisks.filter((risk) =>
    risk.isValid ? !risk.isExpired || options.includeExpired : options.includeInvalid
  );
}

function summarizeFindings(findings: readonly Finding[], suppressedCount: number): McpAuditSummary {
  const severityCounts = Object.fromEntries(severities.map((severity) => [severity, 0])) as Record<Severity, number>;
  const categoryCounts = Object.fromEntries(categories.map((category) => [category, 0])) as Record<Category, number>;

  for (const finding of findings) {
    severityCounts[finding.severity] += 1;
    categoryCounts[finding.category] += 1;
  }

  return {
    findingCount: findings.length,
    suppressedCount,
    severityCounts,
    categoryCounts,
    riskLevel: inferRiskLevelFromFindings(findings)
  };
}

function summarizeAcceptedRiskOutput(acceptedRisks: readonly AcceptedRisk[]): Record<string, unknown> {
  const findings = acceptedRisks.map(acceptedRiskToHostedFinding);
  const byRuleId = countBy(acceptedRisks.map((risk) => risk.ruleId));
  const byOwner = countBy(acceptedRisks.map((risk) => risk.owner ?? "(missing)"));

  return {
    findingCount: acceptedRisks.length,
    acceptedRiskCount: acceptedRisks.filter((risk) => risk.isValid && !risk.isExpired).length,
    expiredCount: acceptedRisks.filter((risk) => risk.isExpired).length,
    invalidCount: acceptedRisks.filter((risk) => !risk.isValid).length,
    byRuleId,
    byOwner,
    riskLevel: inferRiskLevelFromHostedFindings(findings)
  };
}

function prepareFindings(findings: readonly Finding[]): Finding[] {
  return sortFindings(dedupeFindings(findings));
}

function inferRiskLevelFromFindings(findings: readonly Finding[]): RiskLevel {
  if (findings.some((finding) => finding.severity === "critical" || finding.severity === "high")) return "high_risk";
  if (findings.some((finding) => finding.severity === "medium" || finding.category === "manual_review")) return "needs_attention";
  if (findings.length > 0) return "warning";
  return "pass";
}

function inferRiskLevelFromHostedFindings(findings: readonly HostedFinding[]): RiskLevel {
  if (findings.some((finding) => finding.severity === "critical" || finding.severity === "high")) return "high_risk";
  if (findings.some((finding) => finding.severity === "medium" || finding.category === "manual_review")) return "needs_attention";
  if (findings.length > 0) return "warning";
  return "pass";
}

function unsafeNextSteps(findings: readonly Finding[]): string[] {
  if (findings.length === 0) {
    return ["No unsafe fixture findings were detected; still review any real unsafe code locally before release."];
  }

  return uniqueStrings([
    "Review unsafe blocks and unsafe functions for pointer validity, aliasing, lifetime, ownership, and unwind invariants.",
    "Document Safety contracts next to each unsafe boundary.",
    ...findings.slice(0, 3).map((finding) => finding.suggestedFix)
  ]);
}

function dependencyNextSteps(findings: readonly Finding[]): string[] {
  if (findings.length === 0) {
    return ["No dependency fixture findings were detected; still run cargo audit or an equivalent RustSec check for real projects."];
  }

  return uniqueStrings([
    "Review git, path, build-dependency, proc-macro, and build.rs trust boundaries.",
    "Run cargo audit or a RustSec-compatible vulnerability database check separately.",
    ...findings.slice(0, 3).map((finding) => finding.suggestedFix)
  ]);
}

function acceptedRiskNextSteps(acceptedRisks: readonly AcceptedRisk[]): string[] {
  if (acceptedRisks.length === 0) {
    return ["No accepted-risk suppressions were found in the hosted demo input."];
  }

  return uniqueStrings([
    "Re-review expired and invalid suppressions first.",
    "Confirm each active accepted risk has a current owner, ticket, rationale, and review date.",
    "Prefer fixing the underlying finding when the acceptance no longer has a clear business or compatibility reason."
  ]);
}

function diffNextSteps(findings: readonly Finding[], reviewDecision: ReviewDecision | undefined): string[] {
  const decisionStep =
    reviewDecision?.status === "block"
      ? "Fix blocking introduced findings before committing."
      : reviewDecision?.status === "needs_attention"
        ? "Manually review introduced or same-context findings before committing."
        : "No blocking fixture findings were detected; keep using local diff review for real work.";

  return uniqueStrings([
    decisionStep,
    "For private code, run rust_review_current_diff through the local stdio MCP server instead of hosted MCP.",
    ...findings.slice(0, 3).map((finding) => finding.suggestedFix)
  ]);
}

function hostedPrivacyPolicy(): HostedMcpToolOutput["privacy"] {
  return {
    inputPolicy,
    doesNotReadLocalProjects: true,
    doesNotAcceptPrivateRepoTokens: true,
    doesNotPersistSource: true,
    loggingPolicy: "Do not log source snippets, diffs, absolute paths, private repo metadata, tokens, or secrets."
  };
}

function countBy(values: readonly string[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const value of values) {
    counts[value] = (counts[value] ?? 0) + 1;
  }
  return Object.fromEntries(Object.entries(counts).sort(([left], [right]) => left.localeCompare(right)));
}

function uniqueStrings(values: readonly string[]): string[] {
  return [...new Set(values.map(sanitizeText).filter((value) => value.trim().length > 0))];
}

function normalizeRiskLevel(value: unknown): RiskLevel | undefined {
  return value === "pass" || value === "warning" || value === "needs_attention" || value === "high_risk"
    ? value
    : undefined;
}

function isHostedFinding(value: Finding | HostedFinding): value is HostedFinding {
  return "evidenceSnippets" in value;
}

function getOptionalString(record: UnknownRecord, key: string): string | undefined {
  const value = record[key];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function getOptionalBoolean(record: UnknownRecord, key: string): boolean | undefined {
  const value = record[key];
  return typeof value === "boolean" ? value : undefined;
}

function asRecord(input: unknown): UnknownRecord {
  return isRecord(input) ? input : {};
}

function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function totalStringLength(value: unknown): number {
  if (typeof value === "string") return value.length;
  if (Array.isArray(value)) return value.reduce<number>((sum, item) => sum + totalStringLength(item), 0);
  if (!isRecord(value)) return 0;
  return Object.values(value).reduce<number>((sum, item) => sum + totalStringLength(item), 0);
}

function isForbiddenPathKey(key: string): boolean {
  return key === "projectpath" || key === "project_path" || key === "local_path" || key === "absolute_path" || key === "workspace_path";
}

function isForbiddenTokenKey(key: string): boolean {
  return key.includes("token") || key.includes("secret") || key === "authorization" || key === "password" || key === "api_key";
}

function isForbiddenRepositoryKey(key: string): boolean {
  return key === "repo_url" || key === "repository_url" || key === "private_repo" || key === "private_repository";
}

function looksLikePrivateToken(value: string): boolean {
  return (
    /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{16,}\b/.test(value) ||
    /\bgithub_pat_[A-Za-z0-9_]{20,}\b/.test(value) ||
    /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/.test(value) ||
    /\bBearer\s+[A-Za-z0-9._~+/=-]{16,}\b/i.test(value) ||
    /\bxox[baprs]-[A-Za-z0-9-]{16,}\b/.test(value)
  );
}

function looksLikeAbsolutePath(value: string): boolean {
  const trimmed = value.trim();
  return (
    /^\/(?:Users|Volumes|home|private|var|tmp|etc|opt|mnt|workspace)\//.test(trimmed) ||
    /(^|[\s"'=])\/(?:Users|Volumes|home|private|var|tmp|etc|opt|mnt|workspace)\//.test(value) ||
    /^[A-Za-z]:\\/.test(trimmed) ||
    /(^|[\s"'=])[A-Za-z]:\\/.test(value) ||
    /^\\\\/.test(trimmed)
  );
}

function sanitizeRelativePath(value: string): string {
  return sanitizeText(value).replaceAll("\\", "/").replace(/^.*<redacted-path>/, "<redacted-path>");
}

function sanitizeErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return sanitizeText(error.message);
  }

  return sanitizeText(String(error));
}

function sanitizeText(value: string): string {
  return value
    .replace(/\/(?:Users|Volumes|home|private|var|tmp|etc|opt|mnt|workspace)\/[^\s)'"`]+/g, "<redacted-path>")
    .replace(/[A-Za-z]:\\[^\s)'"`]+/g, "<redacted-path>")
    .replace(/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{8,}\b/g, "<redacted-token>")
    .replace(/\bgithub_pat_[A-Za-z0-9_]{8,}\b/g, "<redacted-token>")
    .replace(/\bsk-(?:proj-)?[A-Za-z0-9_-]{8,}\b/g, "<redacted-token>")
    .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]{8,}\b/gi, "Bearer <redacted-token>");
}
