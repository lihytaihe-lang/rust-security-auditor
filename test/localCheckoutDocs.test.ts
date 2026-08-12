import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, it } from "node:test";

const checkoutServer = "/absolute/path/to/rust-security-auditor/dist/src/mcp/server.js";

describe("local checkout installation references", () => {
  it("makes the built checkout server the primary client command", async () => {
    const [readme, clientReferenceText, codexReferenceText] = await Promise.all([
      readFile(resolve("README.md"), "utf8"),
      readFile(resolve("examples/mcp-client-config.json"), "utf8"),
      readFile(resolve("examples/codex-plugin-config.json"), "utf8")
    ]);
    const clientReference = JSON.parse(clientReferenceText) as Record<string, unknown>;
    const codexReference = JSON.parse(codexReferenceText) as Record<string, unknown>;

    assert.match(readme, /npm ci\s*\n\s*npm run build/);
    assert.match(readme, new RegExp(`node ${checkoutServer.replaceAll("/", "\\/")}`));
    assert.equal(clientReference.primaryLocalCheckoutServer, checkoutServer);
    assert.deepEqual(clientReference.primaryLaunch, {
      command: "node",
      args: [checkoutServer]
    });
    assert.match(JSON.stringify(codexReference), /command = \\"node\\"/);
    assert.match(JSON.stringify(codexReference), /dist\/src\/mcp\/server\.js/);
  });
});
