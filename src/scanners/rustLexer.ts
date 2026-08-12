/**
 * Lightweight Rust lexical masking.
 *
 * The scanner kernel matches patterns line by line. Without lexical context, a
 * pattern inside a block comment, a doc example, or a string literal looks
 * exactly like real code. This module produces masked views of the source so
 * line-based rules keep their simplicity while ignoring non-code text.
 *
 * It is deliberately not a parser: it tracks only comment and literal state,
 * preserves line numbers, and preserves column offsets by replacing masked
 * characters with spaces.
 */

export interface MaskedRustSource {
  /** Comment bodies replaced by spaces; string and char literals kept intact. */
  withoutComments: string[];
  /** Comment bodies, string literals, and char literals all replaced by spaces. */
  withoutLiterals: string[];
  /** Only lexically confirmed Rust comments; code and literals are masked. */
  commentsOnly: string[];
  /** False when a literal or block comment was not closed before EOF. */
  isComplete: boolean;
  /** Stable explanation for conservative callers and scan coverage. */
  limitation?: "unterminated_block_comment" | "unterminated_literal";
}

type LexerState =
  | { kind: "code" }
  | { kind: "blockComment"; depth: number }
  | { kind: "string" }
  | { kind: "rawString"; hashes: number };

let maskInvocations = 0;

/**
 * Observable only for deterministic regression tests of lexing work. Lexing
 * must stay proportional to the number of files scanned; a caller that lexes
 * once per finding makes a scan quadratic in the size of a single file.
 */
export function maskRustSourceInvocations(): number {
  return maskInvocations;
}

/**
 * Masks comments and literals while preserving line count and column offsets.
 */
export function maskRustSource(lines: readonly string[]): MaskedRustSource {
  maskInvocations += 1;
  const withoutComments: string[] = [];
  const withoutLiterals: string[] = [];
  const commentsOnly: string[] = [];
  let state: LexerState = { kind: "code" };

  for (const line of lines) {
    let codeOnly = "";
    let literalsToo = "";
    let comments = "";
    let index = 0;

    const emit = (text: string, maskComment: boolean, maskLiteral: boolean) => {
      codeOnly += maskComment ? " ".repeat(text.length) : text;
      literalsToo += maskComment || maskLiteral ? " ".repeat(text.length) : text;
      comments += maskComment ? text : " ".repeat(text.length);
    };

    while (index < line.length) {
      const char = line[index] ?? "";
      const next = line[index + 1] ?? "";

      if (state.kind === "blockComment") {
        if (char === "*" && next === "/") {
          state = state.depth <= 1 ? { kind: "code" } : { kind: "blockComment", depth: state.depth - 1 };
          emit("*/", true, true);
          index += 2;
          continue;
        }

        if (char === "/" && next === "*") {
          state = { kind: "blockComment", depth: state.depth + 1 };
          emit("/*", true, true);
          index += 2;
          continue;
        }

        emit(char, true, true);
        index += 1;
        continue;
      }

      if (state.kind === "rawString") {
        if (char === '"' && closesRawString(line, index + 1, state.hashes)) {
          emit(line.slice(index, index + 1 + state.hashes), false, true);
          index += 1 + state.hashes;
          state = { kind: "code" };
          continue;
        }

        emit(char, false, true);
        index += 1;
        continue;
      }

      if (state.kind === "string") {
        if (char === "\\") {
          emit(line.slice(index, index + 2), false, true);
          index += 2;
          continue;
        }

        if (char === '"') {
          state = { kind: "code" };
        }

        emit(char, false, true);
        index += 1;
        continue;
      }

      if (char === "/" && next === "/") {
        emit(line.slice(index), true, true);
        break;
      }

      if (char === "/" && next === "*") {
        state = { kind: "blockComment", depth: 1 };
        emit("/*", true, true);
        index += 2;
        continue;
      }

      const rawStart = matchRawStringStart(line, index);
      if (rawStart !== undefined) {
        state = { kind: "rawString", hashes: rawStart.hashes };
        emit(line.slice(index, index + rawStart.length), false, true);
        index += rawStart.length;
        continue;
      }

      if (char === '"') {
        state = { kind: "string" };
        emit(char, false, true);
        index += 1;
        continue;
      }

      const charLiteralLength = matchCharLiteral(line, index);
      if (charLiteralLength !== undefined) {
        emit(line.slice(index, index + charLiteralLength), false, true);
        index += charLiteralLength;
        continue;
      }

      emit(char, false, false);
      index += 1;
    }

    withoutComments.push(codeOnly);
    withoutLiterals.push(literalsToo);
    commentsOnly.push(comments);
  }

  if (state.kind === "code") {
    return { withoutComments, withoutLiterals, commentsOnly, isComplete: true };
  }

  // We cannot prove where malformed source resumes code. Preserve comment
  // masking, but scan literal text conservatively instead of silently hiding a
  // potentially real token after an unterminated literal.
  if (state.kind !== "blockComment") {
    return {
      withoutComments,
      withoutLiterals: [...withoutComments],
      commentsOnly,
      isComplete: false,
      limitation: "unterminated_literal"
    };
  }

  return {
    withoutComments,
    withoutLiterals,
    commentsOnly,
    isComplete: false,
    limitation: "unterminated_block_comment"
  };
}

/**
 * Returns the 1-based line numbers that belong to `#[cfg(test)]` or `#[test]`
 * items, so test-only risk can be reported at a lower severity than production
 * code.
 */
export function findTestCodeLines(maskedLines: readonly string[], lexicalAnalysisComplete = true): Set<number> {
  if (!lexicalAnalysisComplete) return new Set();

  const testLines = new Set<number>();
  let depth = 0;
  let pendingAttribute = false;
  let itemDepth: number | undefined;

  maskedLines.forEach((line, index) => {
    const lineNumber = index + 1;

    if (!pendingAttribute && itemDepth === undefined && isTestAttribute(line)) {
      pendingAttribute = true;
    }

    if (pendingAttribute || itemDepth !== undefined) {
      testLines.add(lineNumber);
    }

    for (const char of line) {
      if (char === "{") {
        depth += 1;
        if (pendingAttribute) {
          pendingAttribute = false;
          itemDepth = depth - 1;
        }
        continue;
      }

      if (char === "}") {
        depth = Math.max(0, depth - 1);
        if (itemDepth !== undefined && depth <= itemDepth) {
          itemDepth = undefined;
        }
      }
    }

    // `#[cfg(test)] mod tests;` and similar item forms end without a block.
    if (pendingAttribute && /;\s*$/.test(line)) {
      pendingAttribute = false;
    }
  });

  return testLines;
}

/** `use` and `extern crate` lines name items; they never execute anything. */
export function isImportLine(line: string): boolean {
  return /^\s*(?:pub\s+(?:\([^)]*\)\s*)?)?(?:use|extern\s+crate)\b/.test(line);
}

function isTestAttribute(line: string): boolean {
  // Only Rust's exact built-in #[test] attribute proves an item is test-only.
  // A path ending in ::test can be any custom attribute macro and may compile
  // in production builds, so it must not lower a finding's severity.
  if (/#\s*\[\s*test\s*\]/.test(line)) return true;

  const cfg = /#\s*\[\s*cfg\s*\((.*)\)\s*\]/.exec(line);
  if (cfg?.[1] === undefined) return false;

  return definitelyRequiresTest(cfg[1]);
}

/**
 * A test-only downgrade is a proof obligation. `any(test, feature = ...)`,
 * `cfg_attr`, negation, and unknown cfg syntax may all compile production code
 * and must therefore remain production severity.
 */
function definitelyRequiresTest(condition: string): boolean {
  const trimmed = condition.trim();
  if (trimmed === "test") return true;

  const all = /^all\((.*)\)$/.exec(trimmed);
  if (all?.[1] === undefined) return false;

  return splitTopLevelArguments(all[1]).some((argument) => argument.trim() === "test");
}

function splitTopLevelArguments(value: string): string[] {
  const arguments_: string[] = [];
  let depth = 0;
  let start = 0;

  for (let index = 0; index < value.length; index += 1) {
    const char = value[index];
    if (char === "(") depth += 1;
    if (char === ")") depth = Math.max(0, depth - 1);
    if (char === "," && depth === 0) {
      arguments_.push(value.slice(start, index));
      start = index + 1;
    }
  }

  arguments_.push(value.slice(start));
  return arguments_;
}

function closesRawString(line: string, position: number, hashes: number): boolean {
  if (hashes === 0) return true;
  return line.slice(position, position + hashes) === "#".repeat(hashes);
}

function matchRawStringStart(line: string, index: number): { length: number; hashes: number } | undefined {
  const previous = index > 0 ? line[index - 1] ?? "" : "";
  if (/[A-Za-z0-9_]/.test(previous)) return undefined;

  const match = /^(?:br|rb|r)(#*)"/.exec(line.slice(index));
  if (match === null) return undefined;

  return { length: match[0].length, hashes: (match[1] ?? "").length };
}

function matchCharLiteral(line: string, index: number): number | undefined {
  if (line[index] !== "'") return undefined;

  const match = /^'(?:\\u\{[0-9a-fA-F]{1,6}\}|\\x[0-9a-fA-F]{2}|\\.|[^'\\])'/.exec(line.slice(index));
  return match === null ? undefined : match[0].length;
}
