**OWNER SECURITY-FIRST DIRECTIVE (10-30-2026): SECURITY IS PRIORITY #1.** For every task, repository, agent, PR, CI workflow, and release, security takes precedence over features, speed, performance, cost, convenience, Rust migration, and backlog closure. Triage vulnerabilities, exposed secrets, privacy/access risks, supply-chain threats, CI/release integrity, and recovery hazards first. Never bypass security checks, required reviews, least privilege, privacy boundaries, or safe rollback to finish other work. Block unsafe merges, publication, deployments, and false security-issue closures. Preserve stricter local rules; this policy does not authorize destructive operations or public disclosure of private findings.

# Repository agent instructions

## Canonical guidebook (active policy)

Before making substantive changes, retrieve and read the **complete** current `GUIDEBOOK.md` from the default branch of [Cucklord420/Toe-Tickling](https://github.com/Cucklord420/Toe-Tickling/blob/main/GUIDEBOOK.md). Record the policy revision actually read; do not treat a URL or stale snapshot as evidence of intake. The last reviewed checkpoint is [v1.2.1 at `38433af6`](https://github.com/Cucklord420/Toe-Tickling/blob/38433af6ab609c6b23b0863a0b093e57516e3e5e/GUIDEBOOK.md) (10-16-2026). The checkpoint is a fallback/review reference; check for later canonical changes before acting. Follow the guide within the actual platform instruction hierarchy and preserve stricter project-specific safety rules.

All **new executable code and tests must be Rust** (including automation and validators); existing non-Rust components remain until their behavior can be preserved and an authorized migration verified. Declarative files and documentation retain their appropriate formats. Inspect the real repository and tests, preserve licenses/privacy, use isolated reviewable branches, and do not claim unrun tests, live deployment, or guidebook adoption without observed evidence.

## Local constraints

Preserve upstream uYouPlus contributors' licenses, notices, and inherited iOS build logic. Do not add downloaded proprietary IPA/payloads or assume an iOS device/build runner is available. Validate any Rust input/URL port against the existing build-script behavior; do not remove the original build path without verified parity.
