# RFC 0001: iam-attack-path-graph design

- **Status:** Accepted for M1 (M2 and M3 sections are the plan)
- **Author:** EquinoxWN
- **Created:** 2026-11-09

## Problem (Define)

In an AWS account, privilege escalation rarely needs an exploit: a user who can call
`iam:PassRole` plus `lambda:CreateFunction`, or `iam:CreatePolicyVersion` on a policy attached to
themselves, can become an administrator with ordinary API calls. Finding those principals by
reading policies by hand does not scale: one principal's permissions come from inline policies,
attached managed policies, every group it belongs to, a permissions boundary, wildcards in actions
and resources, `NotAction`/`NotResource`, explicit denies, conditions and policy variables.

The first step, and the scope of M1, is a correct answer to "what can this principal do?" for
every user and role in an account, computed offline from a read-only snapshot, so that M2 can turn
the answers into graph edges.

**Users:** cloud security engineers and platform teams who own an AWS account and want to know
which identities can escalate before an attacker or an auditor finds out.

### Critical-to-quality measures

| CTQ | Target | How it is checked |
|---|---|---|
| Explicit deny always wins | 0 cases where a matching deny is not `explicit-deny` | unit tests plus 300 randomized policies (adding deny-all always gives `explicit-deny`) |
| No guessing | anything that depends on unknown request data is `conditional`, never `allowed` | tests for unknown condition keys, unresolved policy variables, resource-scoped allows, unsupported operators |
| Collection is read-only | the role grants `iam:GetAccountAuthorizationDetails` and nothing else | the shipped policy is evaluated by the tool itself: every catalog action and five write actions are `implicit-deny` |
| Bounded input | snapshot, document, statement and value sizes capped; no regex on untrusted patterns | limit tests; wildcard matcher compared with a regex reference on 5,000 random pairs and a hostile pattern |
| Throughput | a 1,500-principal account evaluated in under 5 s on a laptop | `iamgraph bench` (measured: 0.81 s) |

## Goals

- M1: read users, roles, groups, managed and inline policies, boundaries and trust policies through
  a read-only role (or from the output of `aws iam get-account-authorization-details`).
- M1: evaluate effective permissions per principal, handling wildcards, `Not*` elements, explicit
  denies, permissions boundaries, conditions and policy variables, with an explanation of which
  statements decided each answer.
- M2: principals become graph nodes, escalation methods become edges; shortest path to admin and
  blast radius per principal.
- M3: each path reported with the exact permissions behind it and a least-privilege Terraform fix;
  a deliberately vulnerable lab account built and torn down with Terraform, compared with PMapper.

## Non-goals

- Service control policies, resource control policies, session policies and cross-account
  resource-based policies (single account, identity side only in M1).
- Running attacks: the tool only reads IAM metadata and reasons about it offline.
- A hosted service; it is a command-line tool and a library.

## Design

```
read-only role --GetAccountAuthorizationDetails--> snapshot.json (atomic write)
snapshot.json --parse + validate--> Snapshot (principals with PolicySet: identity docs + boundary)
Principal + Request(action, resource, Context) --evaluate--> Decision + matched statements + reasons
Principal x catalog (33 actions) + ANY --report--> admin status, escalation actions, scoped resources
```

- **Collection (`collect.py`).** `sts:AssumeRole` into the read-only role (15-minute session,
  optional external ID), then the paginated `GetAccountAuthorizationDetails`. botocore timeouts
  (5 s connect, 30 s read) and `standard` retries with 5 attempts; at most 500 pages. The document
  is parsed before it is written, so an invalid snapshot never replaces a good one, and the write is
  a temp file plus `os.replace`.
- **Parsing (`policy.py`, `snapshot.py`).** Policies may be objects, JSON strings or URL-encoded
  JSON (the raw API form). Unknown statement elements, wrong types and oversized documents raise
  errors that name the location. Managed policies use their default version. An attached policy
  missing from the snapshot is a warning, not a silent drop.
- **Three-valued evaluation (`tristate.py`, `evaluator.py`, `conditions.py`).** Every check is
  TRUE, FALSE or UNKNOWN. The request context says which condition keys are known; the principal's
  own keys (`aws:username`, `aws:PrincipalArn`, `aws:PrincipalTag/*`, ...) are filled in. Decisions:
  `explicit-deny` if any deny is TRUE; `implicit-deny` if no allow can be TRUE (including the
  boundary); `allowed` if an allow is TRUE and no deny is possible; otherwise `conditional`, with
  the reasons. The request resource and action may be `*`, meaning "all of them": that is how
  "allowed on every resource" and "is administrator" are asked.
- **Wildcards (`wildcard.py`).** A two-pointer matcher, O(pattern x text), case-insensitive for
  actions and case-sensitive for resources, so a hostile pattern in a snapshot cannot cause
  catastrophic regex backtracking.
- **Catalog (`catalog.py`).** 29 escalation actions from the publicly documented IAM escalation
  methods plus 4 data-access actions. M1 reports which a principal holds; M2 turns them into edges.

## Alternatives considered

| Option | Why not |
|---|---|
| Call the AWS IAM policy simulator (`iam:SimulatePrincipalPolicy`) for every principal and action | Exact for what it covers, but it needs extra permissions on the live account, makes thousands of rate-limited API calls per run, and cannot be re-run offline or in CI on a stored snapshot. The offline evaluator keeps the collection role to one read call. |
| Two-valued evaluation that treats unknown conditions as false (or as true) | False under-reports risk (an MFA-gated `iam:*` would vanish); true over-reports and hides real denies. Three values with reasons keeps both visible; see ADR 0002. |
| Reuse PMapper's evaluator as a library | PMapper is the M3 baseline; reusing its code would make the comparison circular. It also pulls in its own graph model; M1 needs only the evaluator. |
| Use `fnmatch`/regex for wildcards | Simple, but `fnmatch` treats `[` specially and regex translation backtracks badly on patterns such as `*a*a*a...b`. |

## Measurement plan (Measure, Analyze, Improve, Control)

- **Measure:** `make test` (pass counts per file), `iamgraph bench` on seeded synthetic accounts
  (1,500 and 7,000 principals), and the decisions on the hand-written lab account
  (`examples/lab-snapshot.json`), recorded in `docs/results/m1.md`.
- **Analyze:** each lab principal has an expected answer written before the code ran; mismatches
  were treated as defects and root-caused (see results).
- **Improve / Control:** CI runs lint, `mypy --strict`, the tests, the lab summary and the
  benchmark as annotations, and `pip-audit` on every push; the hand mutations in
  `docs/quality/2026-11-01.md` show the tests fail when core rules are broken.
- **M3 proof:** an attack-path diagram from a read-only user to admin in the lab account, and the
  one-line fix that breaks it.

## Milestones

- **M1 (done):** read-only collection and effective-permission evaluation, as above.
- **M2:** principals become graph nodes; edges are ways to gain another identity (assume role,
  pass role to Lambda or EC2, create access keys, edit a policy); shortest path to admin and blast
  radius of every principal.
- **M3:** each path reported with its exact permissions and a least-privilege Terraform fix; a
  vulnerable lab account built and torn down with Terraform, validated against PMapper.

## Risks and open questions

- The evaluator follows AWS's documentation, not AWS's code. Differences are possible for rarely
  used operators and edge cases; M3 compares with PMapper and the IAM policy simulator on the lab
  account.
- `${*}`, `${?}` and `${$}` escapes become wildcards rather than literal characters (a resource
  containing a literal `*` is rare); this can only widen a match.
- Without SCPs and resource policies an `allowed` result can be stricter in reality (an SCP may
  deny it) and an `implicit-deny` can be wrong for cross-account resource policies; both are
  documented non-goals for M1.
