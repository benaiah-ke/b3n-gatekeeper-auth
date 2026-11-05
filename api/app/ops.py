"""Operator commands. Run inside the API container: python -m app.ops <command> --help"""

from __future__ import annotations

import argparse
import asyncio
from datetime import datetime

from sqlalchemy import func, or_, select

from app import alerts
from app.config import settings
from app.database import async_session_factory
from app.models import (
    ApiToken,
    AuditEvent,
    AuthClient,
    Invitation,
    Membership,
    OAuthGrant,
    Organization,
    RefreshToken,
    Role,
    Session,
    User,
)
from app.security import now_utc
from app.services import (
    ALERT_DETAIL_KEYS,
    BASELINE_PERMISSIONS,
    DEFAULT_ORG_ROLES,
    audit,
    cap_scopes,
    ensure_bootstrap,
)

PRIVILEGED_SCOPES = {"*", "admin:*", "token:*"}
# Audit actions that change who can do what: roles, clients, memberships and owners.
CHANGE_ACTION_PREFIXES = ("role.", "client.", "user.membership.", "user.provision", "invitation.", "scim.", "org.")


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


async def overscoped_tokens(
    revoke: bool = False, ids: list[str] | None = None, exclude_users: list[str] | None = None
) -> list[dict]:
    """Active API tokens whose stored scopes exceed what their owner's role allows today.

    Owned tokens are revoked with --revoke. Tokens without an owner (service, project) have no role
    to compare against, so those holding *, admin:* or token:* are listed for manual review only.
    ids limits the run to those token ids; exclude_users skips tokens owned by those emails or user ids."""
    findings: list[dict] = []
    excluded = {item.strip().lower() for item in exclude_users or []}
    async with async_session_factory() as db:
        now = now_utc()
        query = select(ApiToken).where(
            ApiToken.revoked_at.is_(None), or_(ApiToken.expires_at.is_(None), ApiToken.expires_at > now)
        )
        if ids:
            query = query.where(ApiToken.id.in_(ids))
        tokens = await db.execute(query.order_by(ApiToken.created_at.asc()))
        for token in tokens.scalars():
            scopes = list(token.scopes or [])
            owner = await db.get(User, token.user_id) if token.user_id else None
            if owner and {owner.id.lower(), owner.email.lower()} & excluded:
                continue
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


def _when(value: datetime | None) -> str | None:
    return value.isoformat(sep=" ", timespec="seconds") if value else None


async def incident_sweep(since: datetime) -> dict[str, list[dict]]:
    """Read-only listing for incident review: accounts created since `since` and everything they can reach,
    plus clients, roles and invitations that deserve a second look. Never prints secrets or hashes."""
    flagged_audiences = settings.reserved_audience_set | settings.gatekeeper_audience_set
    default_roles = {name: sorted(permissions) for name, permissions in DEFAULT_ORG_ROLES}
    async with async_session_factory() as db:
        now = now_utc()
        emails = dict((await db.execute(select(User.id, User.email))).all())
        slugs = dict((await db.execute(select(Organization.id, Organization.slug))).all())
        accounts = list(
            (await db.execute(select(User).where(User.created_at >= since).order_by(User.created_at))).scalars()
        )
        account_ids = [user.id for user in accounts]
        memberships = (
            await db.execute(
                select(Membership, Role.name)
                .join(Role, Role.id == Membership.role_id)
                .where(Membership.user_id.in_(account_ids))
            )
        ).all()
        owned_org_ids = sorted({row[0].org_id for row in memberships if row[1] == "owner"})
        clients = [
            client
            for client in (await db.execute(select(AuthClient).order_by(AuthClient.created_at))).scalars()
            if client.org_id in owned_org_ids
            or client.created_at >= since
            or not client.audiences
            or flagged_audiences.intersection(client.audiences or [])
            or PRIVILEGED_SCOPES.intersection(client.scopes or [])
            or client.verified_at
        ]
        tokens = (
            await db.execute(
                select(ApiToken)
                .where(
                    or_(
                        ApiToken.user_id.in_(account_ids),
                        ApiToken.org_id.in_(owned_org_ids),
                        ApiToken.created_at >= since,
                    )
                )
                .order_by(ApiToken.created_at)
            )
        ).scalars()
        invitations = (
            await db.execute(
                select(Invitation, Role.name)
                .join(Role, Role.id == Invitation.role_id)
                .where(
                    Invitation.accepted_at.is_(None), Invitation.revoked_at.is_(None), Invitation.expires_at > now
                )
                .order_by(Invitation.created_at)
            )
        ).all()
        grants = (
            await db.execute(
                select(OAuthGrant, AuthClient.client_id)
                .join(AuthClient, AuthClient.id == OAuthGrant.client_id)
                .where(
                    OAuthGrant.revoked_at.is_(None),
                    or_(
                        OAuthGrant.user_id.in_(account_ids),
                        OAuthGrant.org_id.in_(owned_org_ids),
                        OAuthGrant.created_at >= since,
                    ),
                )
                .order_by(OAuthGrant.created_at)
            )
        ).all()
        roles = [
            role
            for role in (await db.execute(select(Role).order_by(Role.created_at))).scalars()
            if default_roles.get(role.name) != sorted(role.permissions or [])
        ]
        live_refresh = (
            select(func.count(RefreshToken.id))
            .where(
                RefreshToken.session_id == Session.id,
                RefreshToken.revoked_at.is_(None),
                RefreshToken.used_at.is_(None),
                RefreshToken.expires_at > now,
            )
            .scalar_subquery()
        )
        sessions = (
            await db.execute(
                select(Session, live_refresh)
                .where(
                    Session.revoked_at.is_(None),
                    Session.expires_at > now,
                    or_(Session.user_id.in_(account_ids), Session.created_at >= since),
                )
                .order_by(Session.created_at)
            )
        ).all()
        changes = (
            await db.execute(
                select(AuditEvent)
                .where(
                    AuditEvent.created_at >= since,
                    or_(*[AuditEvent.action.startswith(prefix) for prefix in CHANGE_ACTION_PREFIXES]),
                )
                .order_by(AuditEvent.created_at)
            )
        ).scalars()
        return {
            "accounts": [
                {
                    "id": user.id,
                    "email": user.email,
                    "created": _when(user.created_at),
                    "disabled": user.disabled,
                    "verified": user.email_verified,
                }
                for user in accounts
            ],
            "memberships": [
                {
                    "user": emails.get(row[0].user_id),
                    "org": slugs.get(row[0].org_id),
                    "role": row[1],
                    "status": row[0].status,
                }
                for row in memberships
            ],
            "owned_orgs": [{"id": org_id, "slug": slugs.get(org_id)} for org_id in owned_org_ids],
            "clients": [
                {
                    "client_id": client.client_id,
                    "name": client.name,
                    "org": slugs.get(client.org_id),
                    "audiences": client.audiences or [],
                    "scopes": client.scopes or [],
                    "verified": bool(client.verified_at),
                    "public": client.public,
                    "enabled": client.enabled,
                    "created": _when(client.created_at),
                }
                for client in clients
            ],
            "api_tokens": [
                {
                    "id": token.id,
                    "type": token.token_type,
                    "hint": token.token_hint,
                    "org": slugs.get(token.org_id),
                    "owner": emails.get(token.user_id),
                    "scopes": token.scopes or [],
                    "audiences": token.audiences or [],
                    "created": _when(token.created_at),
                    "state": "revoked"
                    if token.revoked_at
                    else ("expired" if token.expires_at and token.expires_at <= now else "active"),
                }
                for token in tokens
            ],
            "invitations": [
                {
                    "id": row[0].id,
                    "email": row[0].email,
                    "org": slugs.get(row[0].org_id),
                    "role": row[1],
                    "invited_by": emails.get(row[0].invited_by_user_id),
                    "expires": _when(row[0].expires_at),
                }
                for row in invitations
            ],
            "oauth_grants": [
                {
                    "id": row[0].id,
                    "user": emails.get(row[0].user_id),
                    "client_id": row[1],
                    "org": slugs.get(row[0].org_id),
                    "audience": row[0].audience,
                    "scopes": row[0].scopes or [],
                }
                for row in grants
            ],
            "roles": [
                {"id": role.id, "org": slugs.get(role.org_id), "name": role.name, "permissions": role.permissions or []}
                for role in roles
            ],
            "sessions": [
                {
                    "id": row[0].id,
                    "user": emails.get(row[0].user_id),
                    "org": slugs.get(row[0].org_id),
                    "ip": row[0].ip_address,
                    "amr": row[0].amr or [],
                    "scopes": row[0].scopes or [],
                    "created": _when(row[0].created_at),
                    "live_refresh_tokens": row[1],
                }
                for row in sessions
            ],
            "audit_events": [
                {
                    "time": _when(event.created_at),
                    "action": event.action,
                    "actor": emails.get(event.actor_user_id),
                    "org": slugs.get(event.org_id),
                    "target": f"{event.target_type or '-'}:{event.target_id or '-'}",
                    "ip": event.ip_address,
                    # Only the alert allowlist, so no secret ever reaches the terminal.
                    **{key: (event.details or {})[key] for key in ALERT_DETAIL_KEYS if (event.details or {}).get(key)},
                }
                for event in changes
            ],
        }


def _cell(value: object) -> str:
    return ",".join(map(str, value)) if isinstance(value, list) else str(value)


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m app.ops", description="GateKeeper operator commands")
    commands = parser.add_subparsers(dest="command", required=True)
    bootstrap_owner = commands.add_parser("bootstrap-owner", help="make an existing account owner of the bootstrap org")
    bootstrap_owner.add_argument("--email", required=True)
    overscoped = commands.add_parser(
        "overscoped-tokens", help="list (and with --revoke, revoke) API tokens whose scopes exceed the owner's role"
    )
    overscoped.add_argument("--revoke", action="store_true", help="revoke owned tokens; unowned ones stay for review")
    overscoped.add_argument("--id", action="append", dest="ids", help="only this token id (repeatable)")
    overscoped.add_argument(
        "--exclude-user", action="append", dest="exclude_users", help="skip tokens owned by this email or id"
    )
    sweep = commands.add_parser("incident-sweep", help="read-only listing of what accounts created since a date reach")
    sweep.add_argument("--since", required=True, type=datetime.fromisoformat, help="UTC date or time, e.g. 2026-11-03")
    args = parser.parse_args()
    if args.command == "bootstrap-owner":
        print(asyncio.run(set_bootstrap_owner(args.email)))
    elif args.command == "overscoped-tokens":
        for item in asyncio.run(overscoped_tokens(args.revoke, args.ids, args.exclude_users)):
            print(
                f"{item['action']}{'d' if args.revoke and item['action'] == 'revoke' else ''}\t{item['id']}\t"
                f"{item['token_type']}\t...{item['hint']}\torg={item['org']}\towner={item['owner']}\t"
                f"excess={','.join(item['excess'])}"
            )
    elif args.command == "incident-sweep":
        for section, rows in asyncio.run(incident_sweep(args.since)).items():
            print(f"## {section} ({len(rows)})")
            for row in rows:
                print("\t".join(f"{key}={_cell(value)}" for key, value in row.items()))


if __name__ == "__main__":
    main()
