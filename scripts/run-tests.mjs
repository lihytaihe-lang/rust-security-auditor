#!/usr/bin/env node
/**
 * Cross-platform test runner.
 *
 * `find | xargs` is not available on Windows shells, and `node --test <glob>`
 * needs a newer Node than this project's minimum. Collecting the files here
 * keeps `npm test` identical on Linux, macOS, and Windows.
 */
import { spawn } from "node:child_process";
import { readdir } from "node:fs/promises";
import { join, resolve } from "node:path";

const testRoot = resolve("dist/test");

async function collectTestFiles(directory) {
  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch {
    return [];
  }

  const files = [];
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await collectTestFiles(path)));
      continue;
    }
    if (entry.isFile() && entry.name.endsWith(".test.js")) {
      files.push(path);
    }
  }

  return files;
}

const testFiles = (await collectTestFiles(testRoot)).sort();

if (testFiles.length === 0) {
  console.error(`No compiled test files found under ${testRoot}. Run "npm run build" first.`);
  process.exit(1);
}

const child = spawn(process.execPath, ["--test", ...testFiles], { stdio: "inherit" });
child.on("close", (code, signal) => {
  process.exit(signal !== null ? 1 : code ?? 1);
});
