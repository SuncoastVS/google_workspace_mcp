"""Optional allowlist of the identities permitted to authenticate.

The server has no notion of who may use it: whoever completes the OAuth flow
gets a credential, with every scope the deployment requests. That is safe only
while the Google OAuth app is configured Internal, because Google then refuses
every account outside the owning Workspace before the callback is ever reached.
Publishing the app externally removes that gate, so this replaces it.

`WORKSPACE_MCP_ALLOWED_EMAILS` is a comma-separated list. Unset or empty means
allow everyone, which is upstream's behaviour and what local development
expects. Each entry is either a full address (`someone@example.com`) or a
domain (`@example.com`, or the bare `example.com`) allowing every address at
that domain. Matching ignores case and surrounding whitespace.

The variable is read on every call rather than cached at import, so retuning
the list is a ConfigMap edit plus a restart and never a rebuild.
"""

import logging
import os
from typing import List, Optional

logger = logging.getLogger(__name__)

ALLOWED_EMAILS_ENV_VAR = "WORKSPACE_MCP_ALLOWED_EMAILS"


class EmailNotAllowedError(Exception):
    """Raised when an identity is not permitted to authenticate.

    The message deliberately omits the configured allowlist: this surfaces to
    an unauthenticated caller, and naming who IS permitted would hand an
    attacker a roster of accounts to go after instead.
    """


def allowed_entries() -> List[str]:
    """The configured entries, normalised. Empty means no allowlist is in force."""
    raw = os.getenv(ALLOWED_EMAILS_ENV_VAR) or ""
    return [entry.strip().lower() for entry in raw.split(",") if entry.strip()]


def is_email_allowed(email: Optional[str]) -> bool:
    entries = allowed_entries()
    if not entries:
        return True

    # Fail closed. With an allowlist in force, an identity we cannot read is
    # not an identity we can permit.
    if not email or not email.strip():
        return False

    candidate = email.strip().lower()
    if "@" not in candidate:
        return False
    domain = candidate.rsplit("@", 1)[1]
    if not domain:
        return False

    for entry in entries:
        if "@" in entry:
            # `@example.com` is a domain rule; anything else is a full address.
            if entry.startswith("@"):
                if domain == entry[1:]:
                    return True
            elif candidate == entry:
                return True
        elif domain == entry:
            # A bare `example.com` means the same as `@example.com`; treating it
            # as an address instead would silently match nothing.
            return True

    return False


def enforce_email_allowed(email: Optional[str]) -> None:
    """Raise EmailNotAllowedError unless `email` is permitted."""
    if is_email_allowed(email):
        return
    logger.warning(
        "Rejected authentication for %s: not present in %s",
        email or "<no email>",
        ALLOWED_EMAILS_ENV_VAR,
    )
    raise EmailNotAllowedError("This account is not authorized to use this server.")
