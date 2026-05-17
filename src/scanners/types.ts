import type { Finding } from "../reports/schemas.js";

export interface ScannerContext {
  workspacePath: string;
  severityThreshold?: "info" | "low" | "medium" | "high";
  includeSuppressed?: boolean;
}

export interface ScannerResult {
  findings: Finding[];
  warnings: string[];
  suppressedCount?: number;
  suppressedFindings?: SuppressedFinding[];
}

export interface SuppressedFinding {
  ruleId: string;
  file: string;
  line: number;
  directiveLine: number;
  reason: string;
}

export interface SecurityScanner<TOptions extends ScannerContext = ScannerContext> {
  readonly name: string;
  scan(options: TOptions): Promise<ScannerResult>;
}
