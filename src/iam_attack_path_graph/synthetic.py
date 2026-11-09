"""Seeded synthetic accounts in GetAccountAuthorizationDetails form, for benchmarks and tests.

Every name and ID is invented; the account ID is AWS's documentation example 123456789012.
"""

from __future__ import annotations

import random
from typing import Any

ACCOUNT = "123456789012"

TEMPLATES: dict[str, dict[str, Any]] = {
    "Admin": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
    "ReadOnly": {
        "Statement": [
            {"Effect": "Allow", "Action": ["*:Get*", "*:List*", "*:Describe*"], "Resource": "*"}
        ]
    },
    "PowerUser": {
        "Statement": [
            {"Effect": "Allow", "NotAction": ["iam:*", "organizations:*"], "Resource": "*"},
            {
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": f"arn:aws:iam::{ACCOUNT}:role/app-*",
            },
        ]
    },
    "S3Home": {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": "arn:aws:s3:::home-bucket/${aws:username}/*",
            }
        ]
    },
    "MfaIam": {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:*",
                "Resource": "*",
                "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
            }
        ]
    },
    "DenyKeys": {
        "Statement": [
            {
                "Effect": "Deny",
                "Action": ["iam:CreateAccessKey", "iam:CreateLoginProfile"],
                "Resource": "*",
            }
        ]
    },
    "LambdaDeploy": {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["lambda:CreateFunction", "lambda:InvokeFunction"],
                "Resource": "*",
            },
            {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"},
        ]
    },
}


def _policy(name: str) -> dict[str, Any]:
    """A customer-managed policy entry for one template."""
    return {
        "PolicyName": name,
        "Arn": f"arn:aws:iam::{ACCOUNT}:policy/{name}",
        "DefaultVersionId": "v1",
        "PolicyVersionList": [
            {
                "VersionId": "v1",
                "IsDefaultVersion": True,
                "Document": {"Version": "2012-10-17", **TEMPLATES[name]},
            }
        ],
    }


def _attach(rng: random.Random, k: int) -> list[dict[str, str]]:
    """k distinct random template attachments."""
    names = rng.sample(sorted(TEMPLATES), k)
    return [{"PolicyName": n, "PolicyArn": f"arn:aws:iam::{ACCOUNT}:policy/{n}"} for n in names]


def account(users: int, roles: int, groups: int = 5, seed: int = 7) -> dict[str, Any]:
    """A synthetic account with the given number of users, roles and groups."""
    if users < 0 or roles < 0 or groups < 1:
        raise ValueError("users and roles must be >= 0 and groups >= 1")
    rng = random.Random(seed)
    group_names = [f"team-{i}" for i in range(groups)]
    doc: dict[str, Any] = {
        "Policies": [_policy(n) for n in sorted(TEMPLATES)],
        "GroupDetailList": [
            {
                "GroupName": g,
                "GroupId": f"AGPAEXAMPLE{i:09d}",
                "Arn": f"arn:aws:iam::{ACCOUNT}:group/{g}",
                "GroupPolicyList": [],
                "AttachedManagedPolicies": _attach(rng, 1),
            }
            for i, g in enumerate(group_names)
        ],
        "UserDetailList": [],
        "RoleDetailList": [],
    }
    for i in range(users):
        name = f"user-{i:05d}"
        doc["UserDetailList"].append(
            {
                "UserName": name,
                "UserId": f"AIDAEXAMPLE{i:09d}",
                "Arn": f"arn:aws:iam::{ACCOUNT}:user/{name}",
                "GroupList": rng.sample(group_names, rng.randint(0, min(2, groups))),
                "AttachedManagedPolicies": _attach(rng, rng.randint(0, 2)),
                "UserPolicyList": [],
            }
        )
    for i in range(roles):
        name = f"app-{i:05d}"
        doc["RoleDetailList"].append(
            {
                "RoleName": name,
                "RoleId": f"AROAEXAMPLE{i:09d}",
                "Arn": f"arn:aws:iam::{ACCOUNT}:role/{name}",
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                },
                "AttachedManagedPolicies": _attach(rng, rng.randint(1, 2)),
                "RolePolicyList": [],
            }
        )
    return doc
