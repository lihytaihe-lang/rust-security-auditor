/**
 * Single source of truth for the version reported over MCP.
 *
 * Kept in sync with package.json by a test, so an installed server never
 * advertises a version that does not match the package it came from.
 */
export const serverVersion = "0.1.4";
