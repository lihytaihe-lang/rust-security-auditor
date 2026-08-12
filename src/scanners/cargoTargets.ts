import { posix } from "node:path";

/**
 * How a `.rs` file relates to the Cargo targets of the crate that owns it.
 *
 * Cargo compiles only what a target reaches: `src/` for the library and
 * binaries, `build.rs` at the manifest root, and the `tests/`, `benches/`, and
 * `examples/` directories. A `.rs` file anywhere else in a crate directory is
 * never built — it is sample input, a vendored snapshot, or scratch material.
 * Auditing it reports risk in code that cannot run.
 */
export type RustTargetKind = "shipped" | "build_script" | "development" | "unreferenced";

/** Target kinds that end up in what the crate actually builds and ships. */
export const shippedTargetKinds: readonly RustTargetKind[] = ["shipped", "build_script"];

export function isShippedTargetKind(kind: RustTargetKind): boolean {
  return shippedTargetKinds.includes(kind);
}

export function describeTargetKind(kind: RustTargetKind): string {
  switch (kind) {
    case "shipped":
      return "crate source";
    case "build_script":
      return "build script";
    case "development":
      return "test, benchmark, or example target";
    case "unreferenced":
      return "not reachable from any Cargo target";
  }
}

/**
 * Classifies a workspace-relative Rust file against the nearest ancestor
 * manifest directory.
 *
 * `manifestDirectories` holds workspace-relative directory paths that contain a
 * `Cargo.toml`, with the workspace root itself represented as `""`.
 */
export function classifyRustSourceFile(
  file: string,
  manifestDirectories: ReadonlySet<string>
): { targetKind: RustTargetKind; crateDirectory: string | undefined } {
  const crateDirectory = nearestManifestDirectory(file, manifestDirectories);
  if (crateDirectory === undefined) {
    return { targetKind: "unreferenced", crateDirectory: undefined };
  }

  const relative = crateDirectory === "" ? file : file.slice(crateDirectory.length + 1);
  const [head] = relative.split("/");

  if (relative === "build.rs") return { targetKind: "build_script", crateDirectory };
  if (head === "src") return { targetKind: "shipped", crateDirectory };
  if (head === "tests" || head === "benches" || head === "examples") {
    return { targetKind: "development", crateDirectory };
  }

  return { targetKind: "unreferenced", crateDirectory };
}

function nearestManifestDirectory(file: string, manifestDirectories: ReadonlySet<string>): string | undefined {
  let directory = posix.dirname(file);

  while (true) {
    const candidate = directory === "." ? "" : directory;
    if (manifestDirectories.has(candidate)) return candidate;
    if (candidate === "") return undefined;
    directory = posix.dirname(directory);
  }
}
