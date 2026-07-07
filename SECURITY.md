# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities privately using [GitHub security
advisories](https://github.com/mcrescenzo/opencode-goals/security/advisories/new)
on this repository. Do not open a public issue for a suspected vulnerability.

Include a minimal reproduction, the affected version or commit, and the
expected versus actual behavior. You should receive an acknowledgement and,
once the report is triaged, an estimated timeline for a fix.

Use GitHub Issues for public support requests, ordinary bugs, and feature
proposals once sensitive details have been removed:

<https://github.com/mcrescenzo/opencode-goals/issues>

Do **not** post secrets, credentials, private logs, exploit details, sensitive
vulnerability details, or private workspace data in a public issue or report.
`/goal` relays bounded transcript, tool, and diff evidence to hidden model
calls; redaction of that evidence is best-effort, not a security boundary — if
you find a way to bypass it, that is a security report.

## Supported versions

The first public release line is `0.1.x`. It targets Node.js `>=20.11.0` and
the current/latest opencode runtime checked during release preparation.

Security fixes, if needed, will be released on the latest `0.1.x` line until a
newer public support policy is published.
