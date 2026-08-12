import type { Finding } from "../reports/schemas.js";
import type { SafeSourceReader, ScanCoverage } from "./scannerUtils.js";

export interface ScannerContext {
  workspacePath: string;
  severityThreshold?: "info" | "low" | "medium" | "high";
  includeSuppressed?: boolean;
  /** Shared per-tool-call source capability. Internal callers should forward it. */
  sourceReader?: SafeSourceReader;
  /**
   * Include Rust files Cargo never compiles into the crate: test, benchmark,
   * and example targets, plus stray `.rs` files no target reaches. Off by
   * default; every skipped file is still counted and reported.
   */
  includeNonShippedSources?: boolean;
}

export interface ScannerResult {
  findings: Finding[];
  warnings: string[];
  suppressedCount?: number;
  expiredSuppressionCount?: number;
  invalidSuppressionCount?: number;
  suppressedFindings?: SuppressedFinding[];
  scanCoverage?: ScanCoverage;
}

export interface SuppressedFinding {
  ruleId: string;
  file: string;
  line: number;
  directiveLine: number;
  reason: string;
  owner?: string;
  ticket?: string;
  until?: string;
  isExpired: boolean;
  isValid: boolean;
  rawComment: string;
  invalidSuppression?: string;
  /** True when the comment used the deprecated `rustsec-auditor:` marker. */
  usesDeprecatedMarker?: boolean;
}

export interface SecurityScanner<TOptions extends ScannerContext = ScannerContext> {
  readonly name: string;
  scan(options: TOptions): Promise<ScannerResult>;
}
