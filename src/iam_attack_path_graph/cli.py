"""`iamgraph`: collect a snapshot, then query effective permissions offline."""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Sequence
from pathlib import Path

from . import collect as collect_mod
from . import effective, synthetic, trust
from .context import Context
from .evaluator import ANY, RequestError
from .snapshot import SnapshotError, load_snapshot, parse_snapshot


def _positive(text: str) -> int:
    """argparse type: an integer from 1 to 100,000."""
    value = int(text)
    if not 1 <= value <= 100_000:
        raise argparse.ArgumentTypeError("must be between 1 and 100000")
    return value


def _context(pairs: Sequence[str], complete: bool) -> Context:
    """Parse repeated key=value options into a Context."""
    values: dict[str, list[str]] = {}
    for pair in pairs:
        key, sep, value = pair.partition("=")
        if not sep or not key:
            raise argparse.ArgumentTypeError(f"--context needs key=value, got {pair!r}")
        values.setdefault(key, []).append(value)
    return Context({k: tuple(v) for k, v in values.items()}, complete=complete)


def _cmd_collect(args: argparse.Namespace) -> int:
    """Live collection through the read-only role."""
    client = collect_mod.iam_client(args.role_arn, args.external_id)
    document = collect_mod.fetch(client)
    snap = parse_snapshot(document)
    collect_mod.write_atomic(args.out, document)
    print(
        f"wrote {args.out}: {len(snap.principals)} principals, {len(snap.managed_policies)} managed policies"
    )
    for w in snap.warnings:
        print(f"warning: {w}", file=sys.stderr)
    return 0


def _cmd_perms(args: argparse.Namespace) -> int:
    """Effective permissions for one or all principals."""
    snap = load_snapshot(args.snapshot)
    for w in snap.warnings:
        print(f"warning: {w}", file=sys.stderr)
    actions = args.actions.split(",") if args.actions else list(effective.CATALOG)
    principals = [snap.find(args.principal)] if args.principal else None
    reports = (
        [effective.report(p, actions) for p in principals]
        if principals
        else effective.report_all(snap, actions)
    )
    if args.json:
        out = {
            "account": snap.account_id,
            "collected_at": snap.collected_at,
            "summary": dict(effective.summary(reports)),
            "principals": [r.to_dict() for r in reports],
        }
        print(json.dumps(out, indent=2))
        return 0
    for r in reports:
        esc = r.escalation_actions()
        shown = "all" if len(esc) == len(effective.ESCALATION) else ",".join(esc) or "-"
        print(f"{r.kind:4} {r.name:20} admin={r.admin.value:13} escalation={shown}")
    s = effective.summary(reports)
    print(
        f"\n{s['principals']} principals, {s['admins']} admins, "
        f"{s['conditional_admins']} conditional admins, "
        f"{s['with_escalation_actions']} hold escalation actions"
    )
    return 0


def _cmd_check(args: argparse.Namespace) -> int:
    """One request for one principal, with the statements behind the decision."""
    snap = load_snapshot(args.snapshot)
    principal = snap.find(args.principal)
    ev = effective.check(
        principal, args.action, args.resource, _context(args.context, args.complete_context)
    )
    print(f"{principal.arn} {args.action} on {args.resource}: {ev.decision.value}")
    for m in ev.matches:
        print(f"  {m.effect:5} {m.applies.value:7} {m.policy} statement {m.sid or m.index}")
    for r in ev.reasons:
        print(f"  because: {r}")
    return 0


def _cmd_trust(args: argparse.Namespace) -> int:
    """Who each role's trust policy lets in."""
    snap = load_snapshot(args.snapshot)
    roles = (
        [snap.find(args.role)]
        if args.role
        else [p for p in snap.principals.values() if p.kind == "role"]
    )
    for role in sorted(roles, key=lambda p: p.arn):
        for g in trust.trusted(role):
            cond = " (with conditions)" if g.conditional else ""
            print(f"{role.name}: {g.principal_type} {g.principal}{cond}")
    return 0


def _cmd_bench(args: argparse.Namespace) -> int:
    """Time parsing and evaluation on a seeded synthetic account."""
    document = synthetic.account(args.users, args.roles, seed=args.seed)
    t0 = time.perf_counter()
    snap = parse_snapshot(document)
    t1 = time.perf_counter()
    reports = effective.report_all(snap)
    t2 = time.perf_counter()
    evaluations = len(reports) * (len(effective.CATALOG) + 1)
    print(
        json.dumps(
            {
                "principals": len(reports),
                "catalog_actions": len(effective.CATALOG),
                "evaluations": evaluations,
                "parse_seconds": round(t1 - t0, 4),
                "evaluate_seconds": round(t2 - t1, 4),
                "evaluations_per_second": round(evaluations / max(t2 - t1, 1e-9)),
                **effective.summary(reports),
            },
            indent=2,
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    """The argument parser."""
    parser = argparse.ArgumentParser(prog="iamgraph", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("collect", help="read IAM through the read-only role into a snapshot file")
    p.add_argument("--role-arn", help="read-only role to assume (default: current credentials)")
    p.add_argument("--external-id", help="external ID required by the role's trust policy")
    p.add_argument("--out", type=Path, required=True, help="snapshot file to write")
    p.set_defaults(func=_cmd_collect)

    p = sub.add_parser("perms", help="effective permissions per principal")
    p.add_argument("snapshot", type=Path)
    p.add_argument("--principal", help="name or ARN (default: all)")
    p.add_argument("--actions", help="comma-separated actions (default: the built-in catalog)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.set_defaults(func=_cmd_perms)

    p = sub.add_parser("check", help="decide one request for one principal")
    p.add_argument("snapshot", type=Path)
    p.add_argument("--principal", required=True)
    p.add_argument("--action", required=True)
    p.add_argument("--resource", default=ANY, help="resource ARN (default: every resource)")
    p.add_argument("--context", action="append", default=[], metavar="KEY=VALUE")
    p.add_argument(
        "--complete-context",
        action="store_true",
        help="keys not given with --context are absent from the request (default: unknown)",
    )
    p.set_defaults(func=_cmd_check)

    p = sub.add_parser("trust", help="who each role's trust policy lets in")
    p.add_argument("snapshot", type=Path)
    p.add_argument("--role", help="name or ARN (default: all roles)")
    p.set_defaults(func=_cmd_trust)

    p = sub.add_parser("bench", help="time evaluation on a seeded synthetic account")
    p.add_argument("--users", type=_positive, default=1000)
    p.add_argument("--roles", type=_positive, default=500)
    p.add_argument("--seed", type=int, default=7)
    p.set_defaults(func=_cmd_bench)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point; errors print one line and exit 2."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except argparse.ArgumentTypeError as exc:
        parser.error(str(exc))
    except (SnapshotError, RequestError, collect_mod.CollectError) as exc:
        print(f"iamgraph: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
