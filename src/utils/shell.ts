import { spawn } from "node:child_process";

export interface ShellCommandOptions {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  timeoutMs?: number;
  input?: string;
  maxBufferBytes?: number;
}

export interface ShellCommandResult {
  command: string;
  args: readonly string[];
  cwd: string;
  stdout: string;
  stderr: string;
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  durationMs: number;
  timedOut: boolean;
  truncated: boolean;
  error?: string;
}

export class ShellCommandError extends Error {
  readonly result: ShellCommandResult;

  constructor(result: ShellCommandResult) {
    super(`Command failed: ${formatCommand(result.command, result.args)} (${describeExit(result)})`);
    this.name = "ShellCommandError";
    this.result = result;
  }
}

export async function runShellCommand(
  command: string,
  args: readonly string[] = [],
  options: ShellCommandOptions = {}
): Promise<ShellCommandResult> {
  const cwd = options.cwd ?? process.cwd();
  const timeoutMs = options.timeoutMs ?? 30_000;
  const maxBufferBytes = options.maxBufferBytes ?? 10 * 1024 * 1024;
  const startedAt = Date.now();
  let stdout = "";
  let stderr = "";
  let stdoutBytes = 0;
  let stderrBytes = 0;
  let timedOut = false;
  let truncated = false;

  return await new Promise<ShellCommandResult>((resolve) => {
    const child = spawn(command, [...args], {
      cwd,
      env: { ...process.env, ...options.env },
      shell: false,
      stdio: ["pipe", "pipe", "pipe"]
    });

    let settled = false;
    const timeout = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
    }, timeoutMs);

    const settle = (result: Omit<ShellCommandResult, "durationMs" | "timedOut" | "truncated">) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      resolve({
        ...result,
        durationMs: Date.now() - startedAt,
        timedOut,
        truncated
      });
    };

    child.stdout.on("data", (chunk: Buffer) => {
      const next = appendBounded(stdout, stdoutBytes, chunk, maxBufferBytes);
      stdout = next.value;
      stdoutBytes = next.bytes;
      truncated = truncated || next.truncated;
      if (next.truncated) child.kill("SIGTERM");
    });

    child.stderr.on("data", (chunk: Buffer) => {
      const next = appendBounded(stderr, stderrBytes, chunk, maxBufferBytes);
      stderr = next.value;
      stderrBytes = next.bytes;
      truncated = truncated || next.truncated;
      if (next.truncated) child.kill("SIGTERM");
    });

    child.on("error", (error) => {
      settle({
        command,
        args,
        cwd,
        stdout,
        stderr,
        exitCode: null,
        signal: null,
        error: error.message
      });
    });

    child.on("close", (exitCode, signal) => {
      settle({
        command,
        args,
        cwd,
        stdout,
        stderr,
        exitCode,
        signal
      });
    });

    if (options.input !== undefined) {
      child.stdin.write(options.input);
    }

    child.stdin.end();
  });
}

export async function runShellCommandOrThrow(
  command: string,
  args: readonly string[] = [],
  options: ShellCommandOptions = {}
): Promise<ShellCommandResult> {
  const result = await runShellCommand(command, args, options);
  if (result.exitCode !== 0) {
    throw new ShellCommandError(result);
  }

  return result;
}

export function formatCommand(command: string, args: readonly string[] = []): string {
  return [command, ...args].map(quoteShellPart).join(" ");
}

function appendBounded(
  current: string,
  currentBytes: number,
  chunk: Buffer,
  maxBufferBytes: number
): { value: string; bytes: number; truncated: boolean } {
  const nextBytes = currentBytes + chunk.byteLength;
  if (nextBytes > maxBufferBytes) {
    return {
      value: `${current}\n[output truncated after ${maxBufferBytes} bytes]\n`,
      bytes: currentBytes,
      truncated: true
    };
  }

  return {
    value: current + chunk.toString("utf8"),
    bytes: nextBytes,
    truncated: false
  };
}

function quoteShellPart(value: string): string {
  if (/^[A-Za-z0-9_./:=@+-]+$/.test(value)) {
    return value;
  }

  return `'${value.replaceAll("'", "'\\''")}'`;
}

function describeExit(result: ShellCommandResult): string {
  if (result.error !== undefined) return result.error;
  if (result.timedOut) return "timed out";
  if (result.signal !== null) return `signal ${result.signal}`;
  return `exit ${result.exitCode}`;
}

