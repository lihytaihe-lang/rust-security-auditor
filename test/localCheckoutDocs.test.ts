import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, it } from "node:test";

const checkoutServer = "/absolute/path/to/rust-security-auditor/dist/src/mcp/server.js";
const translations = ["README.md", "README.zh-CN.md"] as const;

async function readTranslations(): Promise<Map<string, string>> {
  const contents = await Promise.all(translations.map((file) => readFile(resolve(file), "utf8")));
  return new Map(translations.map((file, index) => [file, contents[index] ?? ""]));
}

describe("local checkout installation references", () => {
  it("makes the built checkout server the primary client command", async () => {
    const [clientReferenceText, codexReferenceText] = await Promise.all([
      readFile(resolve("examples/mcp-client-config.json"), "utf8"),
      readFile(resolve("examples/codex-plugin-config.json"), "utf8")
    ]);
    const clientReference = JSON.parse(clientReferenceText) as Record<string, unknown>;
    const codexReference = JSON.parse(codexReferenceText) as Record<string, unknown>;

    // Every translation has to carry runnable instructions, not just the one a
    // maintainer happens to edit.
    for (const [file, readme] of await readTranslations()) {
      assert.match(readme, /npm ci\s*\n\s*npm run build/, `${file} lost the build step`);
      assert.match(
        readme,
        new RegExp(`node ${checkoutServer.replaceAll("/", "\\/")}`),
        `${file} lost the checkout server command`
      );
    }

    assert.equal(clientReference.primaryLocalCheckoutServer, checkoutServer);
    assert.deepEqual(clientReference.primaryLaunch, {
      command: "node",
      args: [checkoutServer]
    });
    assert.match(JSON.stringify(codexReference), /command = \\"node\\"/);
    assert.match(JSON.stringify(codexReference), /dist\/src\/mcp\/server\.js/);
  });

  it("keeps the translations linked to each other and structurally aligned", async () => {
    const readmes = await readTranslations();
    const english = readmes.get("README.md") ?? "";
    const chinese = readmes.get("README.zh-CN.md") ?? "";

    assert.match(english, /\[简体中文\]\(README\.zh-CN\.md\)/);
    assert.match(chinese, /\[English\]\(README\.md\)/);

    // A rule id or tool name added to one translation and not the other is the
    // usual way bilingual docs drift apart.
    const identifiers = (text: string) =>
      new Set(text.match(/RSA-[A-Z-]+|rust_(?:audit|review|list)_[a-z_]+/g) ?? []);
    const englishIdentifiers = identifiers(english);
    const chineseIdentifiers = identifiers(chinese);

    assert.deepEqual(
      [...englishIdentifiers].filter((id) => !chineseIdentifiers.has(id)).sort(),
      [],
      "README.zh-CN.md is missing identifiers documented in README.md"
    );
    assert.deepEqual(
      [...chineseIdentifiers].filter((id) => !englishIdentifiers.has(id)).sort(),
      [],
      "README.md is missing identifiers documented in README.zh-CN.md"
    );
  });
});
