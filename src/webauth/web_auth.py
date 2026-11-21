"""A host's whole auth from one settings object: built before its routes, installed after the last.

``WebAuth.build`` checks every early value and builds the relying party, the configuration and
the admission the host's routes take; ``auth.install(app, bearer=...)`` composes the library's
middleware in its one order, the sign-in routes and the readers' handle on the app. Neither reads
the environment or calls the issuer. ``web_auth_front`` serves several built apps behind one
client-address writer and one request line.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from logline import RequestLineMiddleware
from starlette.middleware import Middleware

from webauth._validation import require_positive_whole_number
from webauth.admission import NoAdmins
from webauth.config import _install_web_auth_config
from webauth.dependencies import _publish_installed_sessions
from webauth.https_client import fetch_key_set_over_https
from webauth.middleware.bearer_gate import BearerGate, _install_resource_metadata
from webauth.middleware.client_address import _ClientAddressMiddleware
from webauth.middleware.stack import _install_web_auth_middleware
from webauth.oidc import OidcRelyingParty
from webauth.oidc_transport import post_token_request_over_https
from webauth.proxies import TrustedProxies
from webauth.sign_in_routes import (
    _install_sign_in_routes,
    _require_logout_path_with_page_text,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from fastapi import FastAPI, Request, Response
    from starlette.types import ASGIApp

    from webauth.admission import AdmissionConfig
    from webauth.config import WebAuthConfig
    from webauth.middleware import SessionGate
    from webauth.oidc import OidcClientConfig, TokenRequestPost
    from webauth.policies import BodySizePolicy, CsrfPolicy, RateLimitPolicy, SecurityHeadersPolicy
    from webauth.ports import SessionTransaction, SignInTransaction
    from webauth.sign_in_routes import LogoutPageText, SignInPaths, SignInRefusal

__all__ = [
    "IssuerCalls",
    "ServedBehind",
    "SignInPages",
    "WebAuth",
    "WebAuthSettingError",
    "WebAuthSettings",
    "WebAuthStores",
    "web_auth_front",
]


class WebAuthSettingError(ValueError):
    """A value the host handed to the composition call is refused.

    The message names the field and never the value.
    """


def _refuse(field: str, problem: str) -> WebAuthSettingError:
    return WebAuthSettingError(f"{field} {problem}")


class ServedBehind(Enum):
    """The front an app is built for when it has none of its own.

    ``SHARED_FRONT``: one ``web_auth_front`` stands outside this app and every other app behind
    the same router, so the install places neither the client-address writer nor the request
    line.
    """

    SHARED_FRONT = "shared-front"


def web_auth_front(app: ASGIApp, *, trusted_proxies: TrustedProxies) -> ASGIApp:
    """Wrap ``app``, usually a router of several apps built with ``SHARED_FRONT``, in its front.

    The request line of logline is outermost and the client-address writer sits inside it, so the
    router's own answers and every child's lines carry the client ``trusted_proxies`` resolve.
    Serve every app built with ``SHARED_FRONT`` only through one such front; an app without it
    fails on its first request.
    """
    if not isinstance(trusted_proxies, TrustedProxies):
        raise _refuse("trusted_proxies", "must be TrustedProxies")
    return RequestLineMiddleware(_ClientAddressMiddleware(app, trusted_proxies=trusted_proxies))


@dataclass(frozen=True, kw_only=True)
class WebAuthSettings:
    """The deployment facts of one app's auth, filled from the host's own environment.

    ``client`` is the host's ``OidcClientConfig``, discovered at startup or built by hand.
    ``keeps_id_token`` has no default: ``True`` stores the ID token as the logout hint, ``False``
    none. ``max_sessions`` is ``None`` for no cap, else a positive whole number of sessions per
    account. ``body_size`` and ``rate_limit`` name the library's defaults when ``None``.
    """

    config: WebAuthConfig
    client: OidcClientConfig
    sign_in_paths: SignInPaths
    keeps_id_token: bool
    max_sessions: int | None
    security_headers: SecurityHeadersPolicy
    csrf_origin: CsrfPolicy
    body_size: BodySizePolicy | None = None
    rate_limit: RateLimitPolicy | None = None


@dataclass(frozen=True, kw_only=True)
class WebAuthStores:
    """The host's two transactions, over the same session data.

    ``sign_in`` serializes one sign-in; ``sessions`` is the entry ``current_user`` and
    ``authenticate_websocket`` read the session in.
    """

    sign_in: SignInTransaction
    sessions: SessionTransaction


@dataclass(frozen=True, kw_only=True)
class SignInPages:
    """What the host shows around the sign-in routes.

    ``refused`` answers a callback that ended without a session. ``logout_page_text`` is
    ``None`` exactly when ``settings.sign_in_paths.logout`` is. ``ui_language`` names the
    language tag sent as ``ui_locales`` to the issuer, ``None`` sends none.
    """

    refused: Callable[[Request, SignInRefusal], Response]
    logout_page_text: Callable[[Request], LogoutPageText] | None
    ui_language: Callable[[Request], str | None]


@dataclass(frozen=True, kw_only=True)
class IssuerCalls:
    """The relying party's three outbound dependencies; the defaults are the HTTPS ones."""

    post_token_request: TokenRequestPost = post_token_request_over_https
    fetch_key_set: Callable[[str], bytes] = fetch_key_set_over_https
    monotonic_clock: Callable[[], float] = time.monotonic


def _require_middleware_slot(field: str, entries: Sequence[Middleware]) -> None:
    if not isinstance(entries, tuple) or not all(
        isinstance(entry, Middleware) for entry in entries
    ):
        raise _refuse(field, "must be a tuple of starlette.middleware.Middleware")


def _require_early_values(
    settings: WebAuthSettings,
    *,
    groups: AdmissionConfig,
    pages: SignInPages,
    front: TrustedProxies | ServedBehind,
    outside: Sequence[Middleware],
    inside: Sequence[Middleware],
) -> None:
    if groups.bound_issuer != settings.client.issuer:
        raise _refuse("groups.bound_issuer", "must be the issuer of settings.client")
    if settings.max_sessions is not None:
        try:
            require_positive_whole_number("max_sessions", settings.max_sessions, unit="sessions")
        except ValueError:
            raise _refuse(
                "settings.max_sessions",
                "must be a positive whole number of sessions or None",
            ) from None
    if not isinstance(settings.keeps_id_token, bool):
        raise _refuse("settings.keeps_id_token", "must be True or False")
    try:
        _require_logout_path_with_page_text(settings.sign_in_paths, pages.logout_page_text)
    except ValueError:
        raise _refuse(
            "pages.logout_page_text",
            "must be given exactly when settings.sign_in_paths.logout is",
        ) from None
    if not isinstance(front, TrustedProxies | ServedBehind):
        raise _refuse("front", "must be TrustedProxies or ServedBehind.SHARED_FRONT")
    _require_middleware_slot("outside", outside)
    _require_middleware_slot("inside", inside)


def _answer_ahead_of_the_routes_of_the_host(app: FastAPI, routes_of_the_host: int) -> None:
    """Move the routes added after the host's first ``routes_of_the_host`` to the front.

    The router answers with the first route that matches, so a host's catch-all registered
    before the install would otherwise take the sign-in start, the callback and the resource
    metadata.
    """
    routes = app.router.routes
    own = routes[routes_of_the_host:]
    del routes[routes_of_the_host:]
    routes[:0] = own


class _Permit:
    """What only ``WebAuth.build`` holds, so that ``WebAuth(...)`` is no way to make one."""


_PERMIT = _Permit()


class WebAuth:
    """The built auth of one app: ``build`` it before the routes, ``install`` it after the last.

    The handle exposes ``relying_party``, ``config`` and ``admission`` for the host's routes.
    Until ``install`` has put it on the app, the first request that asks a reader for it raises
    ``RuntimeError``. A handle installs on one app, once: several apps behind one router are
    each built and installed once.
    """

    def __init__(
        self,
        permit: _Permit,
        *,
        settings: WebAuthSettings,
        stores: WebAuthStores,
        groups: AdmissionConfig,
        pages: SignInPages,
        front: TrustedProxies | ServedBehind,
        gate: SessionGate | None,
        outside: Sequence[Middleware],
        inside: Sequence[Middleware],
        relying_party: OidcRelyingParty,
    ) -> None:
        if permit is not _PERMIT:
            raise TypeError("WebAuth is made by WebAuth.build, never by its constructor.")
        self._settings = settings
        self._stores = stores
        self._groups = groups
        self._pages = pages
        self._front = front
        self._gate = gate
        self._outside = tuple(outside)
        self._inside = tuple(inside)
        self._relying_party = relying_party
        self._installed = False

    @classmethod
    def build(
        cls,
        settings: WebAuthSettings,
        *,
        stores: WebAuthStores,
        groups: AdmissionConfig,
        pages: SignInPages,
        front: TrustedProxies | ServedBehind,
        gate: SessionGate | None = None,
        outside: Sequence[Middleware] = (),
        inside: Sequence[Middleware] = (),
        issuer_calls: IssuerCalls | None = None,
    ) -> WebAuth:
        """Check every early value and build the relying party; no outbound call, no environment.

        ``outside`` and ``inside`` are tuples of Starlette ``Middleware`` records, outermost
        first. ``ValueError`` (a ``WebAuthSettingError``) names the field of a refused value.
        """
        _require_early_values(
            settings,
            groups=groups,
            pages=pages,
            front=front,
            outside=outside,
            inside=inside,
        )
        calls = issuer_calls or IssuerCalls()
        relying_party = OidcRelyingParty(
            settings.client,
            post_token_request=calls.post_token_request,
            fetch_key_set=calls.fetch_key_set,
            wall_clock=settings.config.wall_clock,
            monotonic_clock=calls.monotonic_clock,
        )
        return cls(
            _PERMIT,
            settings=settings,
            stores=stores,
            groups=groups,
            pages=pages,
            front=front,
            gate=gate,
            outside=outside,
            inside=inside,
            relying_party=relying_party,
        )

    @property
    def relying_party(self) -> OidcRelyingParty:
        return self._relying_party

    @property
    def config(self) -> WebAuthConfig:
        return self._settings.config

    @property
    def admission(self) -> AdmissionConfig:
        return self._groups

    def install(self, app: FastAPI, *, bearer: BearerGate | None) -> None:
        """Place the stack, the sign-in routes and the sessions entry the readers open on ``app``.

        Call it after the last route of the host.

        Outermost first: logline's request line and the client-address writer, both only when
        ``front`` is ``TrustedProxies`` (``SHARED_FRONT`` leaves them to ``web_auth_front``),
        ``outside``, the library's stack, ``inside``. A ``bearer`` that is no ``BearerGate`` or
        does not fit the early values raises a ``WebAuthSettingError``; a second install of the
        handle, on any app, or an app that already carries library middleware, raises
        ``RuntimeError``. Both are refused before the app changes. The sign-in routes and the
        resource metadata route answer ahead of every route the host added before.
        """
        if self._installed:
            raise RuntimeError(
                "This WebAuth is installed on an app already; build one WebAuth for each app.",
            )
        self._require_a_bearer_that_fits(bearer)
        settings = self._settings
        resource = None if bearer is None else bearer.resource
        _install_web_auth_middleware(
            app,
            sign_in_paths=settings.sign_in_paths,
            security_headers=settings.security_headers,
            csrf_origin=settings.csrf_origin,
            body_size=settings.body_size,
            rate_limit=settings.rate_limit,
            bearer_gate=bearer,
            session_gate=self._gate,
            trusted_proxies=self._front if isinstance(self._front, TrustedProxies) else None,
            outside=self._outside,
            inside=self._inside,
            relying_party=self._relying_party,
            admission=self._groups,
            sign_in=self._stores.sign_in,
            sessions=self._stores.sessions,
        )
        self._installed = True
        _install_web_auth_config(app, settings.config)
        _publish_installed_sessions(app, self._stores.sessions)
        routes_of_the_host = len(app.router.routes)
        _install_sign_in_routes(
            app,
            paths=settings.sign_in_paths,
            relying_party=self._relying_party,
            admission=self._groups,
            transaction=self._stores.sign_in,
            refused=self._pages.refused,
            keeps_id_token=settings.keeps_id_token,
            max_sessions=settings.max_sessions,
            logout_page_text=self._pages.logout_page_text,
            ui_language=self._pages.ui_language,
        )
        if resource is not None:
            _install_resource_metadata(app, resource, issuer=settings.client.issuer)
        _answer_ahead_of_the_routes_of_the_host(app, routes_of_the_host)

    def _require_a_bearer_that_fits(self, bearer: BearerGate | None) -> None:
        if bearer is None:
            return
        if not isinstance(bearer, BearerGate):
            raise _refuse("bearer", "must be a BearerGate or None")
        if bearer.machine_paths is not None and isinstance(self._groups.admin_group, NoAdmins):
            raise _refuse(
                "bearer.machine_paths",
                "needs groups with an admin group: no token could pass there",
            )
