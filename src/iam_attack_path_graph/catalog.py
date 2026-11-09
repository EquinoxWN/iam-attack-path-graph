"""Actions whose effective permission matters for privilege escalation and data access.

The escalation actions are the ones used by publicly documented IAM privilege-escalation
methods (Rhino Security Labs' list, as also modelled by PMapper): they let a principal change
its own or another identity's permissions, mint credentials, or run code as another role.
M2 turns them into graph edges; M1 reports, for each principal, whether it holds them.
"""

from __future__ import annotations

from typing import Final

ESCALATION: Final[dict[str, str]] = {
    "iam:CreatePolicyVersion": "replace a managed policy's text with a new default version",
    "iam:SetDefaultPolicyVersion": "switch a managed policy to a more permissive old version",
    "iam:AttachUserPolicy": "attach any managed policy (for example AdministratorAccess) to a user",
    "iam:AttachGroupPolicy": "attach any managed policy to a group",
    "iam:AttachRolePolicy": "attach any managed policy to a role",
    "iam:PutUserPolicy": "write an inline policy on a user",
    "iam:PutGroupPolicy": "write an inline policy on a group",
    "iam:PutRolePolicy": "write an inline policy on a role",
    "iam:AddUserToGroup": "join a more privileged group",
    "iam:CreateAccessKey": "mint access keys for another user",
    "iam:CreateLoginProfile": "set a console password for another user",
    "iam:UpdateLoginProfile": "change another user's console password",
    "iam:UpdateAssumeRolePolicy": "edit a role's trust policy to let yourself assume it",
    "iam:PassRole": "hand a role to a service (Lambda, EC2, Glue, CloudFormation) that runs as it",
    "iam:DeleteUserPermissionsBoundary": "remove the boundary that limits a user",
    "iam:DeleteRolePermissionsBoundary": "remove the boundary that limits a role",
    "iam:PutUserPermissionsBoundary": "replace a user's boundary with a wider one",
    "iam:PutRolePermissionsBoundary": "replace a role's boundary with a wider one",
    "sts:AssumeRole": "become another role (if its trust policy allows it)",
    "lambda:CreateFunction": "create a function that runs as a passed role",
    "lambda:UpdateFunctionCode": "change the code of a function that runs as a privileged role",
    "lambda:InvokeFunction": "run a function created with a passed role",
    "lambda:CreateEventSourceMapping": "trigger a function without invoke permission",
    "ec2:RunInstances": "start an instance with a passed instance profile",
    "glue:CreateDevEndpoint": "start a Glue endpoint with a passed role",
    "glue:UpdateDevEndpoint": "add an SSH key to a Glue endpoint that runs as a role",
    "cloudformation:CreateStack": "create resources as a passed role",
    "ssm:SendCommand": "run commands on an instance and use its role",
    "ssm:StartSession": "open a shell on an instance and use its role",
}

DATA_ACCESS: Final[dict[str, str]] = {
    "s3:GetObject": "read objects",
    "secretsmanager:GetSecretValue": "read secrets",
    "ssm:GetParameter": "read parameters (often secrets)",
    "kms:Decrypt": "decrypt data",
}

CATALOG: Final[dict[str, str]] = {**ESCALATION, **DATA_ACCESS}
