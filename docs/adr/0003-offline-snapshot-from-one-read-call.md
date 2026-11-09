# ADR 0003: Collect one read-only snapshot, evaluate offline

- **Status:** Accepted

## Context

The tool needs every user, group, role, policy (all versions' defaults), boundary and trust
policy. It could call `ListUsers`, `ListAttachedUserPolicies`, `GetPolicyVersion` and so on per
entity (hundreds or thousands of calls, each needing its own permission), use the IAM policy
simulator, or make the single paginated call `GetAccountAuthorizationDetails`, which returns all
of it.

## Decision

The read-only role is granted exactly `iam:GetAccountAuthorizationDetails` on `*`
(`deploy/readonly-role/permissions-policy.json`); its trust policy requires a named principal,
an external ID and MFA. The response is stored as a JSON snapshot in the API's own format and all
analysis runs offline on it. The same format comes from `aws iam get-account-authorization-details`,
so the tool also works without boto3.

## Consequences

- One permission to review and one API call to rate-limit; a test proves with the tool's own
  evaluator that the role cannot call any catalog action or write anything.
- Snapshots can be diffed, archived and analysed in CI without cloud credentials.
- The call returns IAM only: SCPs (Organizations), S3 bucket and KMS key policies need further
  read calls later; they are documented non-goals for M1.
- The snapshot holds the account's full IAM configuration, which is sensitive: the README says to
  store it like any other security artifact.
