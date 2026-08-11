# Security Policy

## Reporting a Vulnerability in This Tool

Report privately through GitHub's private vulnerability reporting:

1. Open the [Security tab](https://github.com/lihytaihe-lang/rust-security-auditor/security) of this repository.
2. Choose **Report a vulnerability**.
3. Describe the issue, the affected version, and a minimal reproduction.

Please do not open a public issue for a suspected vulnerability, and do not include private code, credentials, tokens, or internal paths in the report.

Expect an initial response within 7 days. If a fix is warranted, it ships in a patch release and the advisory is published once users have had a chance to upgrade.

If private vulnerability reporting is unavailable to you, open a public issue that only states a private security report is needed, with no exploit details, and a maintainer will arrange a channel.

## Supported Versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |
| Older previews | No |

This is a pre-1.0 preview: fixes land on the latest 0.1.x release rather than being backported.

## What Counts as a Vulnerability Here

In scope:

- Path handling that lets a tool call read outside the `projectPath` it was given.
- Argument handling that lets tool input reach a shell or inject `git` flags.
- Any code path that sends scanned source, paths, or environment data off the machine.
- Denial of service from untrusted repository contents, such as unbounded memory use while scanning.

Out of scope:

- A missed finding (false negative) or a noisy finding (false positive). Those are correctness bugs; please open a normal issue with a minimal fixture.
- Vulnerabilities in the Rust project you point the scanner at. Report those to that project.

## Tool Scope and Limits

Rust Security Auditor is a heuristic static review tool. It helps focus local Rust security review, but it does not guarantee that it will find every vulnerability.

It does not perform full AST, data-flow, control-flow, or taint analysis, and it does not check dependency versions against the [RustSec advisory database](https://rustsec.org). It is not formal verification, symbolic execution, supply-chain attestation, or a replacement for human security review. Run `cargo audit` or `cargo deny` alongside it for known-vulnerability coverage.

## Local-First Design

The project runs locally as an MCP server. It reads local paths passed by the MCP client, does not upload repositories or scanned code, and is not intended to be exposed as a public network service.

The hosted MCP prototype under `src/mcp/hostedServer.ts` is a fixture-only experiment. It serves built-in fixtures rather than local project files, and it validates `Host` and `Origin` headers against localhost by default. Do not expose it publicly.

## Handling Sensitive Code

- Use local fixtures or redacted snippets when filing public issues.
- Do not attach proprietary repositories, customer code, credentials, access tokens, private keys, or internal paths.
- If a finding involves sensitive project code, share only the smallest sanitized reproduction needed to discuss scanner behavior.
