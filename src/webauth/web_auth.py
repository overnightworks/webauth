"""A host's whole auth from one settings object: built before its routes, installed after the last.

``WebAuth.build`` checks every early value and builds the configuration and, for a host on an
OpenID Connect provider (its ``OidcSignIn``), the relying party and the admission the host's
routes take; ``auth.install(app, bearer=...)`` composes the library's middleware in its one
order, the sign-in routes of such a host and the readers' handle on the app. A host built with
``oidc=None`` proves who someone is itself and opens its sessions with ``webauth.sessions``.
Neither call reads the environment or calls the issuer. ``web_auth_front`` serves several built
apps behind one client-address writer and one request line.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from starlette.middleware import Middleware

from webauth._outage import _tracked_transactions
from webauth._validation import require_positive_whole_number
from webauth.admission import NoAdmins
from webauth.config import _install_web_auth, _InstalledWebAuth
from webauth.https_client import fetch_key_set_over_https
from webauth.middleware.bearer_gate import BearerGate, _install_resource_metadata
from webauth.middleware.client_address import _front_entries
from webauth.middleware.stack import _HandleBinding, _install_web_auth_middleware, _OidcBinding
from webauth.oidc import OidcRelyingParty
from webauth.oidc_transport import post_token_request_over_https
from webauth.proxies import TrustedProxies
from webauth.sign_in_routes import (
    _install_sign_in_routes,
    _require_logout_path_with_page_text,
)

if TYPE_CHECKING:
    from collections.abc import Callable

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
    "OidcSignIn",
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
    for entry in reversed(_front_entries(trusted_proxies)):
        app = entry.cls(app, *entry.args, **entry.kwargs)
    return app


@dataclass(frozen=True, kw_only=True)
class WebAuthSettings:
    """The deployment facts of one app's auth, filled from the host's own environment.

    ``max_sessions`` is ``None`` for no cap, else a positive whole number of sessions per
    account. ``body_size`` and ``rate_limit`` name the library's defaults when ``None``.
    """

    config: WebAuthConfig
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
    ``None`` exactly when ``oidc.sign_in_paths.logout`` is. ``ui_language`` names the
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


@dataclass(frozen=True, kw_only=True)
class OidcSignIn:
    """What a host on an OpenID Connect provider hands ``WebAuth.build`` as ``oidc``.

    ``client`` is the host's ``OidcClientConfig``, discovered at startup or built by hand.
    ``keeps_id_token`` has no default: ``True`` stores the ID token as the logout hint, ``False``
    none. ``groups`` is the admission, ``pages`` what the host shows around the sign-in routes.
    ``issuer_calls`` is ``None`` for the HTTPS calls.
    """

    client: OidcClientConfig
    sign_in_paths: SignInPaths
    keeps_id_token: bool
    groups: AdmissionConfig
    pages: SignInPages
    issuer_calls: IssuerCalls | None = None


def _require_middleware_slot(field: str, entries: tuple[Middleware, ...]) -> None:
    if not isinstance(entries, tuple) or not all(
        isinstance(entry, Middleware) for entry in entries
    ):
        raise _refuse(field, "must be a tuple of starlette.middleware.Middleware")


def _require_early_values(
    settings: WebAuthSettings,
    *,
    oidc: OidcSignIn | None,
    front: TrustedProxies | ServedBehind,
    outside: tuple[Middleware, ...],
    inside: tuple[Middleware, ...],
) -> None:
    if oidc is not None:
        _require_early_oidc_values(oidc)
    if settings.max_sessions is not None:
        try:
            require_positive_whole_number("max_sessions", settings.max_sessions, unit="sessions")
        except ValueError:
            raise _refuse(
                "settings.max_sessions",
                "must be a positive whole number of sessions or None",
            ) from None
    if not isinstance(front, TrustedProxies | ServedBehind):
        raise _refuse("front", "must be TrustedProxies or ServedBehind.SHARED_FRONT")
    _require_middleware_slot("outside", outside)
    _require_middleware_slot("inside", inside)


def _require_early_oidc_values(oidc: OidcSignIn) -> None:
    if not isinstance(oidc, OidcSignIn):
        raise _refuse("oidc", "must be an OidcSignIn or None")
    if oidc.groups.bound_issuer != oidc.client.issuer:
        raise _refuse("oidc.groups.bound_issuer", "must be the issuer of oidc.client")
    if not isinstance(oidc.keeps_id_token, bool):
        raise _refuse("oidc.keeps_id_token", "must be True or False")
    try:
        _require_logout_path_with_page_text(oidc.sign_in_paths, oidc.pages.logout_page_text)
    except ValueError:
        raise _refuse(
            "oidc.pages.logout_page_text",
            "must be given exactly when oidc.sign_in_paths.logout is",
        ) from None


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


@dataclass(frozen=True)
class _BuiltOidc:
    """The host's ``OidcSignIn`` and the relying party built from it."""

    sign_in: OidcSignIn
    relying_party: OidcRelyingParty


class _Permit:
    """What only ``WebAuth.build`` holds, so that ``WebAuth(...)`` is no way to make one."""


_PERMIT = _Permit()


class WebAuth:
    """The built auth of one app: ``build`` it before the routes, ``install`` it after the last.

    The handle exposes ``config`` and, on a host built with an ``OidcSignIn``, ``relying_party``
    and ``admission`` for the host's routes; without one they raise ``RuntimeError``. Until
    ``install`` has put it on the app, the first request that asks a reader for it raises
    ``RuntimeError``. A handle installs on one app, once: several apps behind one router are
    each built and installed once.
    """

    def __init__(
        self,
        permit: _Permit,
        *,
        settings: WebAuthSettings,
        stores: WebAuthStores,
        front: TrustedProxies | ServedBehind,
        gate: SessionGate | None,
        outside: tuple[Middleware, ...],
        inside: tuple[Middleware, ...],
        oidc: _BuiltOidc | None,
    ) -> None:
        if permit is not _PERMIT:
            raise TypeError("WebAuth is made by WebAuth.build, never by its constructor.")
        self._settings = settings
        self._stores = stores
        self._front = front
        self._gate = gate
        self._outside = tuple(outside)
        self._inside = tuple(inside)
        self._oidc = oidc
        self._installed = False

    @classmethod
    def build(
        cls,
        settings: WebAuthSettings,
        *,
        oidc: OidcSignIn | None,
        stores: WebAuthStores,
        front: TrustedProxies | ServedBehind,
        gate: SessionGate | None = None,
        outside: tuple[Middleware, ...] = (),
        inside: tuple[Middleware, ...] = (),
    ) -> WebAuth:
        """Check every early value and, with ``oidc``, build the relying party; no outbound call,
        no environment.

        ``oidc`` has no default: an ``OidcSignIn``, or ``None`` for an app the operator ruled off
        the provider, which builds no relying party and mounts no sign-in route. ``outside`` and
        ``inside`` are tuples of Starlette ``Middleware`` records, outermost first. ``ValueError``
        (a ``WebAuthSettingError``) names the field of a refused value.
        """
        _require_early_values(settings, oidc=oidc, front=front, outside=outside, inside=inside)
        return cls(
            _PERMIT,
            settings=settings,
            stores=stores,
            front=front,
            gate=gate,
            outside=outside,
            inside=inside,
            oidc=None
            if oidc is None
            else _BuiltOidc(oidc, _relying_party_of(oidc, settings.config)),
        )

    @property
    def relying_party(self) -> OidcRelyingParty:
        if self._oidc is None:
            raise _without_oidc("relying_party")
        return self._oidc.relying_party

    @property
    def config(self) -> WebAuthConfig:
        return self._settings.config

    @property
    def admission(self) -> AdmissionConfig:
        if self._oidc is None:
            raise _without_oidc("admission")
        return self._oidc.sign_in.groups

    def install(self, app: FastAPI, *, bearer: BearerGate | None) -> None:
        """Place the stack, the sign-in routes and the sessions entry the readers open on ``app``.

        Call it after the last route of the host.

        Outermost first: logline's request line and the client-address writer, both only when
        ``front`` is ``TrustedProxies`` (``SHARED_FRONT`` leaves them to ``web_auth_front``),
        ``outside``, the library's stack, ``inside``. A ``bearer`` that is no ``BearerGate``,
        does not fit the early values or is given to a handle built with ``oidc=None`` raises a
        ``WebAuthSettingError``; a second install of the handle, on any app, or an app that already
        carries another ``WebAuth``'s stack, raises ``RuntimeError``. Both are refused before the
        app changes. Without OpenID Connect the install registers no route and derives no rule:
        the routes and policies are the host's. With it, the sign-in routes and the resource
        metadata route answer ahead of every route the host added before.
        """
        if self._installed:
            raise RuntimeError(
                "This WebAuth is installed on an app already; build one WebAuth for each app.",
            )
        self._require_a_bearer_that_fits(bearer)
        settings = self._settings
        sign_in, sessions = _tracked_transactions(self._stores.sign_in, self._stores.sessions)
        built = self._oidc
        _install_web_auth_middleware(
            app,
            security_headers=settings.security_headers,
            csrf_origin=settings.csrf_origin,
            body_size=settings.body_size,
            rate_limit=settings.rate_limit,
            session_gate=self._gate,
            trusted_proxies=self._front if isinstance(self._front, TrustedProxies) else None,
            outside=self._outside,
            inside=self._inside,
            binding=_HandleBinding(
                sessions=sessions,
                oidc=None
                if built is None
                else _OidcBinding(
                    sign_in_paths=built.sign_in.sign_in_paths,
                    relying_party=built.relying_party,
                    admission=built.sign_in.groups,
                    sign_in=sign_in,
                    bearer_gate=bearer,
                ),
            ),
        )
        self._installed = True
        _install_web_auth(
            app,
            _InstalledWebAuth(
                config=settings.config,
                sessions=sessions,
                sign_in=sign_in,
                max_sessions=settings.max_sessions,
                uses_oidc=built is not None,
            ),
        )
        if built is not None:
            self._install_oidc_routes(app, built, sign_in, bearer)

    def _install_oidc_routes(
        self,
        app: FastAPI,
        built: _BuiltOidc,
        sign_in: SignInTransaction,
        bearer: BearerGate | None,
    ) -> None:
        oidc = built.sign_in
        routes_of_the_host = len(app.router.routes)
        _install_sign_in_routes(
            app,
            paths=oidc.sign_in_paths,
            relying_party=built.relying_party,
            admission=oidc.groups,
            transaction=sign_in,
            refused=oidc.pages.refused,
            keeps_id_token=oidc.keeps_id_token,
            logout_page_text=oidc.pages.logout_page_text,
            ui_language=oidc.pages.ui_language,
        )
        if bearer is not None and bearer.resource is not None:
            _install_resource_metadata(app, bearer.resource, issuer=oidc.client.issuer)
        _answer_ahead_of_the_routes_of_the_host(app, routes_of_the_host)

    def _require_a_bearer_that_fits(self, bearer: BearerGate | None) -> None:
        if bearer is None:
            return
        if not isinstance(bearer, BearerGate):
            raise _refuse("bearer", "must be a BearerGate or None")
        if self._oidc is None:
            raise _refuse("bearer", "needs oidc: a bearer gate verifies with the relying party")
        if bearer.machine_paths is not None and isinstance(
            self._oidc.sign_in.groups.admin_group, NoAdmins
        ):
            raise _refuse(
                "bearer.machine_paths",
                "needs groups with an admin group: no token could pass there",
            )


def _relying_party_of(oidc: OidcSignIn, config: WebAuthConfig) -> OidcRelyingParty:
    calls = oidc.issuer_calls or IssuerCalls()
    return OidcRelyingParty(
        oidc.client,
        post_token_request=calls.post_token_request,
        fetch_key_set=calls.fetch_key_set,
        wall_clock=config.wall_clock,
        monotonic_clock=calls.monotonic_clock,
    )


def _without_oidc(name: str) -> RuntimeError:
    return RuntimeError(f"{name} is not available: this WebAuth was built with oidc=None.")
