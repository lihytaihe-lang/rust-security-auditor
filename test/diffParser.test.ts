import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { parseUnifiedDiff } from "../src/git/index.js";

describe("unified diff parser", () => {
  it("parses git file paths, hunk headers, added lines, removed lines, and context lines", () => {
    const diff = parseUnifiedDiff(`diff --git a/src/main.rs b/src/main.rs
index 1111111..2222222 100644
--- a/src/main.rs
+++ b/src/main.rs
@@ -10,6 +10,8 @@ fn main() {
 context before
-old risk
+new risk
+another risk
 context after
@@ -30,2 +32,2 @@ fn helper() {
-removed one
+added one
 context
`);

    assert.equal(diff.files.length, 1);
    assert.equal(diff.files[0]?.filePath, "src/main.rs");
    assert.equal(diff.files[0]?.oldPath, "src/main.rs");
    assert.equal(diff.files[0]?.newPath, "src/main.rs");
    assert.equal(diff.files[0]?.hunks.length, 2);

    const first = diff.files[0]?.hunks[0];
    assert.ok(first);
    assert.equal(first.oldStart, 10);
    assert.equal(first.oldLines, 6);
    assert.equal(first.newStart, 10);
    assert.equal(first.newLines, 8);
    assert.deepEqual(first.addedLines, [11, 12]);
    assert.deepEqual(first.removedLines, [11]);
    assert.deepEqual(first.contextLines, [10, 13]);
    assert.deepEqual(first.contextRange, [10, 17]);

    const second = diff.files[0]?.hunks[1];
    assert.ok(second);
    assert.deepEqual(second.addedLines, [32]);
    assert.deepEqual(second.removedLines, [30]);
    assert.deepEqual(second.contextLines, [33]);
  });

  it("uses the new path for added files", () => {
    const diff = parseUnifiedDiff(`diff --git a/src/new.rs b/src/new.rs
new file mode 100644
index 0000000..3333333
--- /dev/null
+++ b/src/new.rs
@@ -0,0 +1,2 @@
+pub unsafe fn new_risk(ptr: *const u8) -> u8 {
+    unsafe { *ptr }
`);

    assert.equal(diff.files[0]?.filePath, "src/new.rs");
    assert.equal(diff.files[0]?.oldPath, undefined);
    assert.equal(diff.files[0]?.newPath, "src/new.rs");
    assert.deepEqual(diff.files[0]?.hunks[0]?.addedLines, [1, 2]);
    assert.deepEqual(diff.files[0]?.hunks[0]?.removedLines, []);
    assert.deepEqual(diff.files[0]?.hunks[0]?.contextRange, [1, 2]);
  });
});
