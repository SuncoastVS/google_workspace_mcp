"""Coverage for the optional OAuth email allowlist.

The server itself has no notion of who is permitted to authenticate: whoever
completes the OAuth flow gets a credential. That is safe only while the Google
OAuth app is Internal, because Google refuses every non-org account before the
callback is ever reached. These tests cover the gate that has to exist before
the app is published externally.
"""

import pytest
from google.oauth2.credentials import Credentials

from auth.allowlist import EmailNotAllowedError, enforce_email_allowed, is_email_allowed
from auth.google_auth import handle_auth_callback

ENV_VAR = "WORKSPACE_MCP_ALLOWED_EMAILS"


# --- the allowlist itself -------------------------------------------------


def test_unset_allows_everyone(monkeypatch):
    """Upstream behaviour and local development both depend on this default."""
    monkeypatch.delenv(ENV_VAR, raising=False)
    assert is_email_allowed("anyone@example.com")
    assert is_email_allowed("sean@suncoast.studio")


def test_empty_or_whitespace_allows_everyone(monkeypatch):
    monkeypatch.setenv(ENV_VAR, "   ")
    assert is_email_allowed("anyone@example.com")


def test_exact_address_entries(monkeypatch):
    monkeypatch.setenv(ENV_VAR, "sean@suncoast.studio,travis@suncoast.studio")
    assert is_email_allowed("sean@suncoast.studio")
    assert is_email_allowed("travis@suncoast.studio")
    assert not is_email_allowed("someone@suncoast.studio")
    assert not is_email_allowed("attacker@gmail.com")


def test_domain_entries_allow_the_whole_domain(monkeypatch):
    monkeypatch.setenv(ENV_VAR, "@suncoast.studio")
    assert is_email_allowed("anyone@suncoast.studio")
    assert not is_email_allowed("anyone@gmail.com")


def test_bare_domain_entry_is_treated_as_a_domain(monkeypatch):
    """`suncoast.studio` and `@suncoast.studio` must not mean different things."""
    monkeypatch.setenv(ENV_VAR, "suncoast.studio")
    assert is_email_allowed("anyone@suncoast.studio")
    assert not is_email_allowed("anyone@gmail.com")


def test_matching_ignores_case_and_surrounding_whitespace(monkeypatch):
    monkeypatch.setenv(ENV_VAR, "  Sean@Suncoast.Studio ,  @RecruitTune.ai  ")
    assert is_email_allowed("SEAN@suncoast.studio")
    assert is_email_allowed("sean@recruittune.AI")
    assert not is_email_allowed("sean@gmail.com")


def test_mixed_address_and_domain_entries(monkeypatch):
    monkeypatch.setenv(ENV_VAR, "@suncoast.studio,seandotsonfl@gmail.com")
    assert is_email_allowed("will@suncoast.studio")
    assert is_email_allowed("seandotsonfl@gmail.com")
    assert not is_email_allowed("someone.else@gmail.com")


@pytest.mark.parametrize("value", [None, "", "   ", "not-an-email"])
def test_unusable_email_is_denied_when_an_allowlist_is_set(monkeypatch, value):
    """Fail closed: an identity we cannot read is not an identity we permit."""
    monkeypatch.setenv(ENV_VAR, "@suncoast.studio")
    assert not is_email_allowed(value)


def test_enforce_raises_for_denied_and_is_quiet_for_allowed(monkeypatch):
    monkeypatch.setenv(ENV_VAR, "@suncoast.studio")
    enforce_email_allowed("will@suncoast.studio")
    with pytest.raises(EmailNotAllowedError):
        enforce_email_allowed("attacker@gmail.com")


def test_denial_message_does_not_leak_the_allowlist(monkeypatch):
    """The error reaches an unauthenticated caller, so it must not enumerate us."""
    monkeypatch.setenv(ENV_VAR, "@suncoast.studio,travis@suncoast.studio")
    with pytest.raises(EmailNotAllowedError) as excinfo:
        enforce_email_allowed("attacker@gmail.com")
    message = str(excinfo.value)
    assert "suncoast.studio" not in message
    assert "travis" not in message


# --- the OAuth callback ---------------------------------------------------


class _DummyFlow:
    def __init__(self, credentials):
        self.credentials = credentials

    def fetch_token(self, authorization_response):  # noqa: ARG002
        return None


class _DummyOAuthStore:
    def __init__(self):
        self.stored_sessions = []

    def validate_and_consume_oauth_state(self, state, session_id=None):  # noqa: ARG002
        return {"session_id": session_id, "code_verifier": "verifier"}

    def get_credentials_by_mcp_session(self, mcp_session_id):  # noqa: ARG002
        return None

    def store_session(self, **kwargs):
        self.stored_sessions.append(kwargs)


class _DummyCredentialStore:
    def __init__(self):
        self.saved_credentials = None
        self.saved_email = None

    def get_credential(self, user_email):  # noqa: ARG002
        return None

    def store_credential(self, user_email, credentials):
        self.saved_email = user_email
        self.saved_credentials = credentials
        return True


def _make_credentials():
    return Credentials(
        token="access-token",
        refresh_token="refresh-token",
        token_uri="https://oauth2.googleapis.com/token",
        client_id="client-id",
        client_secret="client-secret",
        scopes=["scope.a"],
    )


def _wire_callback(monkeypatch, email, oauth_store, credential_store):
    monkeypatch.setattr(
        "auth.google_auth.create_oauth_flow",
        lambda **kwargs: _DummyFlow(_make_credentials()),  # noqa: ARG005
    )
    monkeypatch.setattr(
        "auth.google_auth.get_oauth21_session_store", lambda: oauth_store
    )
    monkeypatch.setattr(
        "auth.google_auth.get_credential_store", lambda: credential_store
    )
    monkeypatch.setattr(
        "auth.google_auth.get_user_info",
        lambda credentials: {"email": email},  # noqa: ARG005
    )
    monkeypatch.setattr(
        "auth.google_auth.save_credentials_to_session", lambda *args: None
    )


def test_callback_rejects_a_denied_address_and_stores_nothing(monkeypatch):
    """The whole point: no credential may reach disk for a denied identity."""
    monkeypatch.setenv(ENV_VAR, "@suncoast.studio")
    oauth_store = _DummyOAuthStore()
    credential_store = _DummyCredentialStore()
    _wire_callback(monkeypatch, "attacker@gmail.com", oauth_store, credential_store)

    with pytest.raises(EmailNotAllowedError):
        handle_auth_callback(
            scopes=["scope.a"],
            authorization_response="https://example.com/oauth2callback?state=abc&code=xyz",
            redirect_uri="https://example.com/oauth2callback",
        )

    assert credential_store.saved_credentials is None
    assert credential_store.saved_email is None
    assert oauth_store.stored_sessions == []


def test_callback_allows_a_permitted_address(monkeypatch):
    monkeypatch.setenv(ENV_VAR, "@suncoast.studio")
    oauth_store = _DummyOAuthStore()
    credential_store = _DummyCredentialStore()
    _wire_callback(monkeypatch, "will@suncoast.studio", oauth_store, credential_store)

    user_email, credentials = handle_auth_callback(
        scopes=["scope.a"],
        authorization_response="https://example.com/oauth2callback?state=abc&code=xyz",
        redirect_uri="https://example.com/oauth2callback",
    )

    assert user_email == "will@suncoast.studio"
    assert credentials.refresh_token == "refresh-token"
    assert credential_store.saved_email == "will@suncoast.studio"
    assert len(oauth_store.stored_sessions) == 1


def test_callback_unchanged_when_no_allowlist_is_configured(monkeypatch):
    """Existing deployments must behave exactly as they do today."""
    monkeypatch.delenv(ENV_VAR, raising=False)
    oauth_store = _DummyOAuthStore()
    credential_store = _DummyCredentialStore()
    _wire_callback(monkeypatch, "anyone@example.com", oauth_store, credential_store)

    user_email, _ = handle_auth_callback(
        scopes=["scope.a"],
        authorization_response="https://example.com/oauth2callback?state=abc&code=xyz",
        redirect_uri="https://example.com/oauth2callback",
    )

    assert user_email == "anyone@example.com"
    assert credential_store.saved_email == "anyone@example.com"


# --- the OAuth 2.1 / bearer path ------------------------------------------
#
# Not enabled on the deployed server today (the pod sets no MCP_ENABLE_OAUTH21),
# but it is the documented multi-user path, so turning it on later must not
# silently drop the gate.


class _FakeFastMCPContext:
    def __init__(self, session_id):
        self.session_id = session_id
        self.state = {}

    async def set_state(self, key, value, serializable=True):  # noqa: ARG002
        self.state[key] = value

    async def get_state(self, key):
        return self.state.get(key)


class _FakeMiddlewareContext:
    def __init__(self, session_id="mcp-session-1"):
        self.fastmcp_context = _FakeFastMCPContext(session_id)


class _SessionBindingStore:
    def __init__(self, email):
        self._email = email

    def get_user_by_mcp_session(self, mcp_session_id):  # noqa: ARG002
        return self._email


def _wire_session_binding(monkeypatch, email):
    """Drive the MCP-session-binding branch and neutralise the earlier ones."""
    monkeypatch.setattr(
        "auth.auth_info_middleware.get_access_token", lambda: None, raising=False
    )
    monkeypatch.setattr(
        "auth.auth_info_middleware.get_http_headers", lambda: {}, raising=False
    )
    monkeypatch.setattr(
        "auth.oauth21_session_store.get_oauth21_session_store",
        lambda: _SessionBindingStore(email),
    )


@pytest.mark.asyncio
async def test_bearer_path_rejects_a_denied_address(monkeypatch):
    from auth.auth_info_middleware import AuthInfoMiddleware

    monkeypatch.setenv(ENV_VAR, "@suncoast.studio")
    _wire_session_binding(monkeypatch, "attacker@gmail.com")

    context = _FakeMiddlewareContext()
    with pytest.raises(EmailNotAllowedError):
        await AuthInfoMiddleware()._process_request_for_auth(context)

    # Nothing downstream may still read this caller as authenticated.
    assert not context.fastmcp_context.state.get("authenticated_user_email")


@pytest.mark.asyncio
async def test_bearer_path_allows_a_permitted_address(monkeypatch):
    from auth.auth_info_middleware import AuthInfoMiddleware

    monkeypatch.setenv(ENV_VAR, "@suncoast.studio")
    _wire_session_binding(monkeypatch, "will@suncoast.studio")

    context = _FakeMiddlewareContext()
    await AuthInfoMiddleware()._process_request_for_auth(context)

    assert (
        context.fastmcp_context.state.get("authenticated_user_email")
        == "will@suncoast.studio"
    )


@pytest.mark.asyncio
async def test_bearer_path_unchanged_when_no_allowlist_is_configured(monkeypatch):
    from auth.auth_info_middleware import AuthInfoMiddleware

    monkeypatch.delenv(ENV_VAR, raising=False)
    _wire_session_binding(monkeypatch, "anyone@example.com")

    context = _FakeMiddlewareContext()
    await AuthInfoMiddleware()._process_request_for_auth(context)

    assert (
        context.fastmcp_context.state.get("authenticated_user_email")
        == "anyone@example.com"
    )
