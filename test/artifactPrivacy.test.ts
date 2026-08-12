import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { findArtifactPathLeaks, sanitizeArtifactValue } from "../src/release/artifactPrivacy.js";

// The repository root is synthetic on purpose: a test about not leaking local
// paths must not publish the maintainer's own directory layout.
const syntheticRepositoryRoot = "/home/example/workspace/auditor-checkout";

describe("artifact privacy", () => {
  it("sanitizes common absolute POSIX, Windows, UNC, and JSON-escaped path values before serialization", () => {
    const source = {
      posix: `${syntheticRepositoryRoot}/test/fixture`,
      posixTempRoot: "/tmp",
      posixTemp: "/tmp/private-rust-project/Cargo.toml",
      posixRoot: "/root/private-rust-project/Cargo.toml",
      posixService: "/srv/acme-rust/report.json",
      windows: "C:\\Users\\alice\\private-project\\src\\lib.rs",
      windowsDriveRoot: "D:\\secret",
      unc: "\\\\server\\share\\private-project\\src\\lib.rs",
      nested: ["/Users/alice/private-project/Cargo.toml"],
      url: "https://example.com/releases/rust-security-auditor"
    };
    const raw = JSON.stringify(source);
    const sanitized = sanitizeArtifactValue(source, [syntheticRepositoryRoot]);
    const serialized = JSON.stringify(sanitized);

    assert.deepEqual(findArtifactPathLeaks(raw, [syntheticRepositoryRoot]), [
      "posix_path",
      "repository_path",
      "unc_path",
      "windows_path"
    ]);
    assert.equal(findArtifactPathLeaks(serialized, [syntheticRepositoryRoot]).length, 0);
    assert.match(serialized, /<repo>|<local-path>/);
    assert.doesNotMatch(serialized, /alice|server|auditor-checkout|private-rust-project|acme-rust|secret/);
    assert.equal((sanitized as { url: string }).url, source.url);
    assert.deepEqual(findArtifactPathLeaks("#!/usr/bin/env node\n", []), []);
  });
});
