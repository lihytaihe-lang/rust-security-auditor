import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { findArtifactPathLeaks, sanitizeArtifactValue } from "../src/release/artifactPrivacy.js";

describe("artifact privacy", () => {
  it("sanitizes common absolute POSIX, Windows, UNC, and JSON-escaped path values before serialization", () => {
    const source = {
      posix: "/Volumes/GF/kaiyuan/rust-security-auditor/test/fixture",
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
    const sanitized = sanitizeArtifactValue(source, ["/Volumes/GF/kaiyuan/rust-security-auditor"]);
    const serialized = JSON.stringify(sanitized);

    assert.deepEqual(findArtifactPathLeaks(raw, ["/Volumes/GF/kaiyuan/rust-security-auditor"]), [
      "posix_path",
      "repository_path",
      "unc_path",
      "windows_path"
    ]);
    assert.equal(findArtifactPathLeaks(serialized, ["/Volumes/GF/kaiyuan/rust-security-auditor"]).length, 0);
    assert.match(serialized, /<repo>|<local-path>/);
    assert.doesNotMatch(serialized, /alice|server|kaiyuan|private-rust-project|acme-rust|secret/);
    assert.equal((sanitized as { url: string }).url, source.url);
    assert.deepEqual(findArtifactPathLeaks("#!/usr/bin/env node\n", []), []);
  });
});
