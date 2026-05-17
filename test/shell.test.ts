import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { ShellCommandError, formatCommand, runShellCommand, runShellCommandOrThrow } from "../src/utils/shell.js";

describe("shell command wrapper", () => {
  it("captures stdout for a successful command", async () => {
    const result = await runShellCommand(process.execPath, ["-e", "console.log('ok')"]);

    assert.equal(result.exitCode, 0);
    assert.equal(result.stdout.trim(), "ok");
    assert.equal(result.stderr, "");
    assert.equal(result.timedOut, false);
  });

  it("throws with result details when requested", async () => {
    await assert.rejects(
      () => runShellCommandOrThrow(process.execPath, ["-e", "process.exit(7)"]),
      (error) => error instanceof ShellCommandError && error.result.exitCode === 7
    );
  });

  it("formats commands without invoking a shell", () => {
    assert.equal(formatCommand("cargo", ["metadata", "--format-version", "1"]), "cargo metadata --format-version 1");
    assert.equal(formatCommand("echo", ["hello world"]), "echo 'hello world'");
  });
});

