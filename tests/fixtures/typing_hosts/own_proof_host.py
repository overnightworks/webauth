"""A host that proves who someone is itself: no OpenID Connect block, a session it opens.

Every part is typed against the public ports and entry points. CI checks this file with a pinned
pyright against the built wheel, so an export a host cannot import fails the build instead of the
host's next upgrade.
"""

from __future__ import annotations

from fastapi import FastAPI, Request, Response
from oidc_host import (
    a_host_configures_without_local_credentials,
    a_host_renewal_transaction,
    a_host_sign_in_transaction,
)

from webauth.policies import CsrfPolicy, SecurityHeadersPolicy, default_content_security_policy
from webauth.ports import SessionTransaction, SignInTransaction
from webauth.proxies import TrustedProxies
from webauth.sessions import end_session, open_session
from webauth.web_auth import WebAuth, WebAuthSettings, WebAuthStores


def an_own_proof_host_composes_its_auth(front: TrustedProxies) -> WebAuth:
    sign_in: SignInTransaction = a_host_sign_in_transaction
    sessions: SessionTransaction = a_host_renewal_transaction
    return WebAuth.build(
        WebAuthSettings(
            config=a_host_configures_without_local_credentials(),
            max_sessions=3,
            security_headers=SecurityHeadersPolicy(
                content_security_policy=default_content_security_policy(),
            ),
            csrf_origin=CsrfPolicy(),
        ),
        oidc=None,
        stores=WebAuthStores(sign_in=sign_in, sessions=sessions),
        front=front,
    )


def an_own_proof_host_installs_its_auth(app: FastAPI, auth: WebAuth) -> None:
    auth.install(app, bearer=None)


def an_own_proof_host_opens_the_session_of_a_proven_account(
    request: Request, response: Response, account_id: str
) -> str:
    return open_session(request, response, account_id)


def an_own_proof_host_ends_the_session_of_the_request(
    request: Request, response: Response
) -> str | None:
    return end_session(request, response)
