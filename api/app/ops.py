"""Operator commands. Run inside the API container: python -m app.ops <command> --help"""

from __future__ import annotations

import argparse
import asyncio

from sqlalchemy import select

from app import alerts
from app.database import async_session_factory
from app.models import Membership, Role, User
from app.services import audit, ensure_bootstrap


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


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m app.ops", description="GateKeeper operator commands")
    commands = parser.add_subparsers(dest="command", required=True)
    bootstrap_owner = commands.add_parser("bootstrap-owner", help="make an existing account owner of the bootstrap org")
    bootstrap_owner.add_argument("--email", required=True)
    args = parser.parse_args()
    if args.command == "bootstrap-owner":
        print(asyncio.run(set_bootstrap_owner(args.email)))


if __name__ == "__main__":
    main()
