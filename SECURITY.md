# Security Policy

## Reporting Security Issues

Please do not open a public issue for vulnerabilities in Rust Security Auditor itself.

Until a project-specific private advisory channel is configured, report suspected security issues by opening a minimal public issue that says a private security report is needed, without exploit details, private code, credentials, tokens, or sensitive paths. A maintainer can then arrange a private disclosure channel.

## Tool Scope

Rust Security Auditor is a heuristic static review tool. It helps focus local Rust security review, but it does not guarantee that it will find every vulnerability.

It does not perform full AST, data-flow, control-flow, or taint analysis. It is not formal verification, symbolic execution, supply-chain attestation, or a replacement for human security review.

## Local-First Design

The project is designed to run locally as an MCP server for Codex or another MCP client. Do not upload sensitive code to external services just to use this project. The MCP server scans local paths passed by the client and is not intended to be exposed as a public network service.

## Handling Sensitive Code

- Use local fixtures or redacted snippets when filing public issues.
- Do not attach proprietary repositories, customer code, credentials, access tokens, private keys, or internal paths.
- If a finding appears to involve sensitive project code, share only the smallest sanitized reproduction needed to discuss scanner behavior.
