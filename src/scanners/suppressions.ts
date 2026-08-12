/**
 * Canonical inline marker. `rustsec-auditor:` is still accepted so existing
 * suppression comments keep working, but it is deprecated: RustSec is an
 * unrelated project, and the old marker reads as an affiliation with it.
 */
export const suppressionMarker = "rust-security-auditor";
export const deprecatedSuppressionMarker = "rustsec-auditor";

export interface ParsedSuppressionDirective {
  ruleId: string;
  reason: string;
  owner?: string;
  ticket?: string;
  until?: string;
  rawComment: string;
  invalidReasons: string[];
  /** True when the comment used the deprecated `rustsec-auditor:` marker. */
  usesDeprecatedMarker: boolean;
}

export function parseSuppressionDirective(line: string): ParsedSuppressionDirective | undefined {
  const match = /(rust-security-auditor|rustsec-auditor):\s*ignore\s+(\S+)(.*)$/i.exec(line);
  if (match === null || match[2] === undefined) return undefined;

  const usesDeprecatedMarker = (match[1] ?? "").toLowerCase() === deprecatedSuppressionMarker;
  const ruleId = match[2].trim();
  const remainder = match[3]?.trim() ?? "";
  const delimiterIndex = remainder.indexOf("--");
  const metadataText = delimiterIndex === -1 ? remainder : remainder.slice(0, delimiterIndex).trim();
  const reason = delimiterIndex === -1 ? "" : remainder.slice(delimiterIndex + 2).trim();
  const invalidReasons: string[] = [];
  const metadata: Pick<ParsedSuppressionDirective, "owner" | "ticket" | "until"> = {};

  if (reason.length === 0) {
    invalidReasons.push("Suppression reason is required after '--'.");
  }

  if (isGlobalIgnoreToken(ruleId)) {
    invalidReasons.push("Global ignore directives are not supported; suppress a specific rule id instead.");
  } else if (!/^[A-Za-z0-9_-]+$/.test(ruleId)) {
    invalidReasons.push("Suppression rule id must be a concrete rule id.");
  }

  for (const token of metadataText.length === 0 ? [] : metadataText.split(/\s+/)) {
    if (token.startsWith("owner=")) {
      const owner = token.slice("owner=".length).trim();
      if (owner.length === 0) {
        invalidReasons.push("Suppression owner must be non-empty when provided.");
      } else {
        metadata.owner = owner;
      }
      continue;
    }

    if (token.startsWith("ticket=")) {
      const ticket = token.slice("ticket=".length).trim();
      if (ticket.length === 0) {
        invalidReasons.push("Suppression ticket must be non-empty when provided.");
      } else {
        metadata.ticket = ticket;
      }
      continue;
    }

    if (token.startsWith("until=")) {
      const until = token.slice("until=".length).trim();
      if (!isValidIsoDate(until)) {
        invalidReasons.push("Suppression until must use YYYY-MM-DD.");
      } else {
        metadata.until = until;
      }
      continue;
    }

    invalidReasons.push(`Unsupported suppression metadata '${token}'.`);
  }

  return {
    ruleId,
    reason,
    rawComment: line.trim(),
    invalidReasons,
    usesDeprecatedMarker,
    ...metadata
  };
}

export function isGlobalIgnoreToken(ruleId: string): boolean {
  return ruleId === "*" || ruleId.toLowerCase() === "all";
}

export function isSuppressionExpired(until: string | undefined): boolean {
  return until === undefined ? false : until < todayIsoDate();
}

function isValidIsoDate(value: string): boolean {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (match === null) return false;

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const date = new Date(Date.UTC(year, month - 1, day));

  return date.getUTCFullYear() === year && date.getUTCMonth() === month - 1 && date.getUTCDate() === day;
}

function todayIsoDate(): string {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, "0");
  const day = String(now.getDate()).padStart(2, "0");

  return `${year}-${month}-${day}`;
}
