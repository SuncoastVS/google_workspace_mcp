"""Identity handling when the server runs with protocol-level OAuth 2.1.

Drives the real AuthInfoMiddleware and service-decorator auth context through a
real FastMCP HTTP app (stateless, as deployed) with a static token verifier
standing in for Google, so no network or human sign-in is needed.

The property under test: the identity a tool sees is the one carried by THIS
request's verified token, never one left behind by an earlier request that used
the same (client-chosen) mcp-session-id.
"""

import contextlib

import httpx
import pytest
from fastmcp import FastMCP
from fastmcp.server.auth.providers.jwt import StaticTokenVerifier

from auth.auth_info_middleware import AuthInfoMiddleware
from auth.oauth21_session_store import set_auth_provider
from auth.service_decorator import _extract_oauth21_user_email, _get_auth_context
from core import config as core_config

SCOPES = ["openid", "https://www.googleapis.com/auth/userinfo.email"]
TOKENS = {
    "tok-alice": {"client_id": "t", "scopes": SCOPES, "email": "alice@suncoast.studio"},
    "tok-bob": {"client_id": "t", "scopes": SCOPES, "email": "bob@suncoast.studio"},
    "tok-mallory": {"client_id": "t", "scopes": SCOPES, "email": "mallory@example.org"},
    "tok-noemail": {"client_id": "t", "scopes": SCOPES},
}
pytestmark = pytest.mark.asyncio

HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}


@contextlib.asynccontextmanager
async def identity_client(monkeypatch):
    monkeypatch.setenv("WORKSPACE_MCP_ALLOWED_EMAILS", "@suncoast.studio")
    previous_mode = core_config.get_transport_mode()
    core_config.set_transport_mode("streamable-http")

    verifier = StaticTokenVerifier(tokens=TOKENS)
    set_auth_provider(verifier)
    mcp = FastMCP(name="identity-test", auth=verifier)
    mcp.add_middleware(AuthInfoMiddleware())

    @mcp.tool()
    async def whoami() -> str:
        user, via, _ = await _get_auth_context("whoami")
        # Same step the service decorator takes in OAuth 2.1 mode.
        user = _extract_oauth21_user_email(user, "whoami")
        return f"{user}|{via}"

    app = mcp.http_app(path="/mcp", stateless_http=True)
    try:
        async with app.router.lifespan_context(app):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://test"
            ) as c:
                yield c
    finally:
        set_auth_provider(None)
        core_config.set_transport_mode(previous_mode)


async def whoami(client, token=None, session=None):
    headers = dict(HEADERS)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if session:
        headers["mcp-session-id"] = session
    return await client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "whoami", "arguments": {}},
        },
    )


async def test_no_bearer_is_401(monkeypatch):
    async with identity_client(monkeypatch) as client:
        assert (await whoami(client)).status_code == 401


async def test_garbage_bearer_is_401(monkeypatch):
    async with identity_client(monkeypatch) as client:
        assert (await whoami(client, "not-a-token")).status_code == 401


async def test_caller_acts_as_the_token_owner(monkeypatch):
    async with identity_client(monkeypatch) as client:
        resp = await whoami(client, "tok-alice", "s1")
        assert resp.status_code == 200
        assert "alice@suncoast.studio|fastmcp_oauth" in resp.text


async def test_second_user_on_the_same_session_id_is_not_the_first(monkeypatch):
    async with identity_client(monkeypatch) as client:
        await whoami(client, "tok-alice", "shared")
        resp = await whoami(client, "tok-bob", "shared")
        assert "bob@suncoast.studio|fastmcp_oauth" in resp.text
        assert "alice@suncoast.studio" not in resp.text


async def test_token_without_an_email_never_inherits_an_earlier_identity(monkeypatch):
    """A valid token that names no account must not become whoever used the
    session id before it, for session-scoped state or session binding alike."""
    async with identity_client(monkeypatch) as client:
        await whoami(client, "tok-alice", "shared")
        resp = await whoami(client, "tok-noemail", "shared")
        assert "alice@suncoast.studio" not in resp.text
        assert '"isError":true' in resp.text


async def test_token_without_an_email_is_rejected_on_a_fresh_session(monkeypatch):
    async with identity_client(monkeypatch) as client:
        resp = await whoami(client, "tok-noemail", "fresh")
        assert '"isError":true' in resp.text


async def test_allowlist_still_rejects_other_domains(monkeypatch):
    async with identity_client(monkeypatch) as client:
        resp = await whoami(client, "tok-mallory", "s2")
        assert "not authorized" in resp.text
        assert "mallory@example.org|" not in resp.text
