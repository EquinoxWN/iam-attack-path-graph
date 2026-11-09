# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub:
**Security > Report a vulnerability** on this repository
(`https://github.com/EquinoxWN/iam-attack-path-graph/security/advisories/new`). Do not open a public issue.

Include what you found, how to reproduce it, and the impact you expect. You will get an answer
within 7 days. Fixes are released as soon as they are ready, and you are credited unless you ask
not to be.

## Supported versions

This project is pre-1.0. Only the latest commit on `main` receives fixes.

## Scope

- **In scope:** an evaluation that reports `allowed` or `implicit-deny` where AWS would decide
  otherwise, unsafe parsing of snapshot files (crashes, unbounded memory or time), and any path
  where collection could call a write API or leak credentials.
- **Out of scope:** vulnerabilities in AWS, boto3 or botocore themselves (report those upstream).

## Using it safely

- Give the collection role only `iam:GetAccountAuthorizationDetails`
  (`deploy/readonly-role/permissions-policy.json`) and require an external ID and MFA in its trust policy.
- A snapshot contains the account's full IAM configuration. Store it like any other security
  artifact and never commit it.
- All fixtures use invented names, AWS's documentation account ID and the marker `EXAMPLE-NOT-A-SECRET`.

## How this repository protects itself

- Every GitHub Action is pinned to a full commit SHA, and workflows run with read-only
  permissions and without persisted credentials.
- Dependabot update pull requests are paused (`open-pull-requests-limit: 0`) so the repository keeps a single `main` branch; dependencies are updated by hand and checked by the CI audit.
- CI runs lint, `mypy --strict`, tests and a known-vulnerability check (pip-audit) on every push and pull request.
