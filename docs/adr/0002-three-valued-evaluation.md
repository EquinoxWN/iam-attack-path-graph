# ADR 0002: Three-valued evaluation with "conditional" instead of guessing

- **Status:** Accepted

## Context

An offline snapshot does not know the request context: whether MFA was used, the source IP, the
region, the tags on the target resource. Many real policies depend on exactly these keys
(`Bool aws:MultiFactorAuthPresent`, `IpAddress aws:SourceIp`, `StringEquals aws:RequestedRegion`).
A two-valued evaluator must pick a default: treating unknown as false hides MFA-gated `iam:*`
(an escalation risk), treating it as true reports denies as allows.

## Decision

Every check returns TRUE, FALSE or UNKNOWN (Kleene logic: FALSE wins an AND, TRUE wins an OR).
The final decision is `allowed`, `explicit-deny`, `implicit-deny` or `conditional`, and a
`conditional` answer carries the reasons (which key, which statement, "only some resources").
Callers that know more pass a context (`--context key=value`), or declare it complete
(`--complete-context`) so missing keys count as absent, as in a real request.

## Consequences

- Reports never claim `allowed` for something that needs MFA or a specific resource; the lab
  account's carol (`iam:*` with MFA) and erin (`iam:CreateAccessKey` on her own user only) show
  as `conditional` with the reason.
- M2's graph has to handle conditional edges (weight or label them) instead of a plain yes/no.
- More code than a boolean evaluator: absent-versus-unknown keys, `IfExists`, `ForAllValues` and
  `ForAnyValue` each need explicit tests (they have them).
