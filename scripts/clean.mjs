#!/usr/bin/env node
/**
 * Removes build output.
 *
 * `rm -rf` is not available on Windows shells, and tsc leaves orphaned output
 * behind when a source file is renamed or deleted -- which means `npm test`
 * would keep running a compiled test whose source no longer exists.
 */
import { rm } from "node:fs/promises";
import { resolve } from "node:path";

await rm(resolve("dist"), { recursive: true, force: true });
