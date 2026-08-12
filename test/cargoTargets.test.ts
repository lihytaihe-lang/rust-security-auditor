import assert from "node:assert/strict";
import { resolve } from "node:path";
import { describe, it } from "node:test";
import { classifyRustSourceFile, describeSkippedRustTargets, discoverRustProject, scanRustProject } from "../src/scanners/index.js";

const fixturePath = resolve("test/fixtures/non-shipped-sources");

function kindOf(file: string, manifests: readonly string[]): string {
  return classifyRustSourceFile(file, new Set(manifests)).targetKind;
}

describe("cargo target classification", () => {
  it("separates what Cargo builds from what it never reaches", () => {
    const root = [""];

    assert.equal(kindOf("src/lib.rs", root), "shipped");
    assert.equal(kindOf("src/deep/nested/mod.rs", root), "shipped");
    assert.equal(kindOf("build.rs", root), "build_script");
    assert.equal(kindOf("tests/integration.rs", root), "development");
    assert.equal(kindOf("benches/bench.rs", root), "development");
    assert.equal(kindOf("examples/demo.rs", root), "development");

    // A `.rs` file no target reaches: benchmark input, a vendored snapshot, or
    // scratch material. Cargo never compiles it.
    assert.equal(kindOf("scratch/notes.rs", root), "unreferenced");
    assert.equal(kindOf("benchmarks/haystacks/code/rust-library.rs", root), "unreferenced");
  });

  it("attributes a file to its nearest manifest, not the workspace root", () => {
    const manifests = ["", "crates/inner"];

    assert.equal(kindOf("crates/inner/src/lib.rs", manifests), "shipped");
    assert.equal(kindOf("crates/inner/tests/it.rs", manifests), "development");
    assert.equal(kindOf("crates/inner/build.rs", manifests), "build_script");
    // `src` belongs to the inner crate, so this path is not the root's src.
    assert.equal(kindOf("crates/other/notes.rs", manifests), "unreferenced");
  });

  it("marks a file with no owning manifest as unreferenced", () => {
    assert.equal(classifyRustSourceFile("loose/file.rs", new Set(["crates/a"])).targetKind, "unreferenced");
    assert.equal(classifyRustSourceFile("loose/file.rs", new Set(["crates/a"])).crateDirectory, undefined);
  });

  it("describes a skip only when files were actually skipped", () => {
    assert.deepEqual(describeSkippedRustTargets({ shipped: 3, buildScript: 1, development: 0, unreferenced: 0 }, false), []);
    assert.deepEqual(describeSkippedRustTargets({ shipped: 3, buildScript: 1, development: 2, unreferenced: 4 }, true), []);

    const [message] = describeSkippedRustTargets(
      { shipped: 3, buildScript: 1, development: 2, unreferenced: 4 },
      false
    );
    assert.match(message ?? "", /Excluded 6 Rust file\(s\) from source scanning/);
    assert.match(message ?? "", /2 test\/benchmark\/example target file\(s\)/);
    assert.match(message ?? "", /4 file\(s\) no Cargo target reaches/);
  });
});

describe("scan scope", () => {
  it("classifies every discovered Rust file in the fixture", async () => {
    const project = await discoverRustProject(fixturePath);

    assert.deepEqual(project.rustTargetSummary, {
      shipped: 1,
      buildScript: 1,
      development: 3,
      unreferenced: 1
    });
  });

  it("audits only what Cargo builds and says what it skipped", async () => {
    const scan = await scanRustProject({ workspacePath: fixturePath });
    const files = [...new Set(scan.findings.map((finding) => finding.file))].sort();

    assert.deepEqual(files, ["build.rs", "src/lib.rs"]);
    assert.ok(
      scan.warnings.some((warning) => /Excluded 4 Rust file\(s\) from source scanning: 3 test\/benchmark\/example target file\(s\), 1 file\(s\) no Cargo target reaches/.test(warning)),
      `expected a skip report, got: ${JSON.stringify(scan.warnings)}`
    );
  });

  it("scans the skipped files on request and then reports no skip", async () => {
    const scan = await scanRustProject({ workspacePath: fixturePath, includeNonShippedSources: true });
    const files = [...new Set(scan.findings.map((finding) => finding.file))].sort();

    assert.deepEqual(files, [
      "benches/bench.rs",
      "build.rs",
      "examples/demo.rs",
      "scratch/notes.rs",
      "src/lib.rs",
      "tests/integration.rs"
    ]);
    assert.equal(scan.warnings.some((warning) => warning.includes("skipped")), false);
  });
});
