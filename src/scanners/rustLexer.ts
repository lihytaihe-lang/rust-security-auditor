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
}

type LexerState =
  | { kind: "code" }
  | { kind: "blockComment"; depth: number }
  | { kind: "string" }
  | { kind: "rawString"; hashes: number };

/**
 * Masks comments and literals while preserving line count and column offsets.
 */
export function maskRustSource(lines: readonly string[]): MaskedRustSource {
  const withoutComments: string[] = [];
  const withoutLiterals: string[] = [];
  let state: LexerState = { kind: "code" };

  for (const line of lines) {
    let codeOnly = "";
    let literalsToo = "";
    let index = 0;

    const emit = (text: string, maskComment: boolean, maskLiteral: boolean) => {
      codeOnly += maskComment ? " ".repeat(text.length) : text;
      literalsToo += maskComment || maskLiteral ? " ".repeat(text.length) : text;
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

    // A plain string literal never spans lines; only raw strings and block
    // comments carry state across a newline.
    if (state.kind === "string") {
      state = { kind: "code" };
    }

    withoutComments.push(codeOnly);
    withoutLiterals.push(literalsToo);
  }

  return { withoutComments, withoutLiterals };
}

/**
 * Returns the 1-based line numbers that belong to `#[cfg(test)]` or `#[test]`
 * items, so test-only risk can be reported at a lower severity than production
 * code.
 */
export function findTestCodeLines(maskedLines: readonly string[]): Set<number> {
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
  if (/#\s*\[\s*(?:[\w:]+::)?test\s*\]/.test(line)) return true;

  const cfg = /#\s*\[\s*cfg(?:_attr)?\s*\((.*)\)\s*\]/.exec(line);
  if (cfg?.[1] === undefined) return false;

  return /(?:^|[(,\s])test(?:[),\s]|$)/.test(cfg[1]);
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
