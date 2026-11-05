"""Operator commands. Run inside the API container: python -m app.ops <command> --help"""

from __future__ import annotations

import argparse
import asyncio

from sqlalchemy import or_, select

from app import alerts
from app.database import async_session_factory
from app.models import ApiToken, Membership, Organization, Role, User
from app.security import now_utc
from app.services import BASELINE_PERMISSIONS, audit, cap_scopes, ensure_bootstrap

PRIVILEGED_SCOPES = {"*", "admin:*", "token:*"}


async def set_bootstrap_owner(email: str) -> str:
    async with async_session_factory() as db:
        org = await ensure_bootstrap(db)
        user = (await db.execute(select(User).where(User.email == email.strip().lower()))).scalar_one_or_none()
        if not user:
            raise SystemExit(f"No account with email {email}")
        owner_role = (await db.execute(select(Role).where(Role.org_id == org.id, Role.name == "owner"))).scalar_one()
        membership = (
            await db.execute(select(Membership).where(Membership.org_id == org.id, Membership.user_id == user.id))
        ).scalar_one_or_none()
        if membership:
            membership.role_id = owner_role.id
            membership.status = "active"
        else:
            membership = Membership(org_id=org.id, user_id=user.id, role_id=owner_role.id, status="active")
            db.add(membership)
        await db.flush()
        await audit(
            db,
            "org.owner.bootstrap",
            org_id=org.id,
            target_type="membership",
            target_id=membership.id,
            details={"via": "operator", "email": user.email},
        )
        await db.commit()
    await asyncio.gather(*alerts._pending)
    return f"{user.email} is now an owner of {org.slug}"


async def overscoped_tokens(revoke: bool = False) -> list[dict]:
    """Active API tokens whose stored scopes exceed what their owner's role allows today.

    Owned tokens are revoked with --revoke. Tokens without an owner (service, project) have no role
    to compare against, so those holding *, admin:* or token:* are listed for manual review only."""
    findings: list[dict] = []
    async with async_session_factory() as db:
        now = now_utc()
        tokens = await db.execute(
            select(ApiToken)
            .where(ApiToken.revoked_at.is_(None), or_(ApiToken.expires_at.is_(None), ApiToken.expires_at > now))
            .order_by(ApiToken.created_at.asc())
        )
        for token in tokens.scalars():
            scopes = list(token.scopes or [])
            owner = await db.get(User, token.user_id) if token.user_id else None
            org = await db.get(Organization, token.org_id) if token.org_id else None
            if token.user_id:
                permissions: list[str] = BASELINE_PERMISSIONS if not token.org_id else []
                if token.org_id:
                    role = await db.execute(
                        select(Role.permissions)
                        .join(Membership, Membership.role_id == Role.id)
                        .where(
                            Membership.user_id == token.user_id,
                            Membership.org_id == token.org_id,
                            Membership.status == "active",
                        )
                    )
                    permissions = role.scalar_one_or_none() or []
                if not owner or owner.disabled:
                    permissions = []
                allowed = set(cap_scopes(scopes, permissions))
                excess = [scope for scope in scopes if scope not in allowed]
                action = "revoke"
            else:
                excess = [scope for scope in scopes if scope in PRIVILEGED_SCOPES]
                action = "review"
            if not excess:
                continue
            findings.append(
                {
                    "id": token.id,
                    "token_type": token.token_type,
                    "hint": token.token_hint,
                    "org": org.slug if org else None,
                    "owner": owner.email if owner else None,
                    "scopes": scopes,
                    "excess": excess,
                    "action": action,
                }
            )
            if revoke and action == "revoke":
                token.revoked_at = now
                await audit(
                    db,
                    "token.revoke",
                    org_id=token.org_id,
                    target_type="token",
                    target_id=token.id,
                    details={"reason": "scopes_exceed_role", "via": "operator", "excess": excess},
                )
        await db.commit()
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m app.ops", description="GateKeeper operator commands")
    commands = parser.add_subparsers(dest="command", required=True)
    bootstrap_owner = commands.add_parser("bootstrap-owner", help="make an existing account owner of the bootstrap org")
    bootstrap_owner.add_argument("--email", required=True)
    overscoped = commands.add_parser(
        "overscoped-tokens", help="list (and with --revoke, revoke) API tokens whose scopes exceed the owner's role"
    )
    overscoped.add_argument("--revoke", action="store_true", help="revoke owned tokens; unowned ones stay for review")
    args = parser.parse_args()
    if args.command == "bootstrap-owner":
        print(asyncio.run(set_bootstrap_owner(args.email)))
    elif args.command == "overscoped-tokens":
        for item in asyncio.run(overscoped_tokens(revoke=args.revoke)):
            print(
                f"{item['action']}{'d' if args.revoke and item['action'] == 'revoke' else ''}\t{item['id']}\t"
                f"{item['token_type']}\t...{item['hint']}\torg={item['org']}\towner={item['owner']}\t"
                f"excess={','.join(item['excess'])}"
            )


if __name__ == "__main__":
    main()
