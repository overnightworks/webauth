"""A host's whole auth from one settings object: built before its routes, installed after the last.

``WebAuth.build`` checks every early value and builds the relying party, the configuration and
the admission the host's routes take; ``auth.install(app, bearer=...)`` composes the library's
middleware in its one order, the sign-in routes and the readers' handle on the app. Neither reads
the environment or calls the issuer.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from starlette.middleware import Middleware

from webauth._validation import require_positive_whole_number
from webauth.config import install_web_auth_config
from webauth.dependencies import _has_installed_web_auth, _publish_installed_web_auth
from webauth.https_client import fetch_key_set_over_https
from webauth.middleware.bearer_gate import install_resource_metadata
from webauth.middleware.stack import _install_slotted_web_auth_middleware
from webauth.oidc import OidcRelyingParty
from webauth.oidc_transport import post_token_request_over_https
from webauth.proxies import TrustedProxies
from webauth.sign_in_routes import install_sign_in_routes

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from fastapi import FastAPI, Request, Response

    from webauth.admission import AdmissionConfig
    from webauth.config import WebAuthConfig
    from webauth.jwt_verification import KeySetFetch, MonotonicClock
    from webauth.middleware import BearerGate, SessionGate
    from webauth.oidc import OidcClientConfig, TokenRequestPost
    from webauth.policies import BodySizePolicy, CsrfPolicy, RateLimitPolicy, SecurityHeadersPolicy
    from webauth.ports import SessionTransaction, SignInTransaction
    from webauth.sign_in_routes import LogoutPageText, SignInPaths, SignInRefusal

__all__ = [
    "IssuerCalls",
    "SignInPages",
    "WebAuth",
    "WebAuthSettingError",
    "WebAuthSettings",
    "WebAuthStores",
]


class WebAuthSettingError(ValueError):
    """A value the host handed to the composition call is refused.

    The message names the field and never the value.
    """


def _refuse(field: str, problem: str) -> WebAuthSettingError:
    return WebAuthSettingError(f"{field} {problem}")


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
    fetch_key_set: KeySetFetch = fetch_key_set_over_https
    monotonic_clock: MonotonicClock = time.monotonic


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
    front: TrustedProxies,
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
    if (settings.sign_in_paths.logout is None) != (pages.logout_page_text is None):
        raise _refuse(
            "pages.logout_page_text",
            "must be given exactly when settings.sign_in_paths.logout is",
        )
    if not isinstance(front, TrustedProxies):
        raise _refuse("front", "must be TrustedProxies")
    _require_middleware_slot("outside", outside)
    _require_middleware_slot("inside", inside)


class WebAuth:
    """The built auth of one app: ``build`` it before the routes, ``install`` it after the last.

    The handle exposes ``relying_party``, ``config`` and ``admission`` for the host's routes.
    Until ``install`` has put it on the app, the first request that asks a reader for it raises
    ``RuntimeError``.
    """

    def __init__(
        self,
        *,
        settings: WebAuthSettings,
        stores: WebAuthStores,
        groups: AdmissionConfig,
        pages: SignInPages,
        front: TrustedProxies,
        gate: SessionGate | None,
        outside: Sequence[Middleware],
        inside: Sequence[Middleware],
        relying_party: OidcRelyingParty,
    ) -> None:
        self._settings = settings
        self._stores = stores
        self._groups = groups
        self._pages = pages
        self._front = front
        self._gate = gate
        self._outside = tuple(outside)
        self._inside = tuple(inside)
        self._relying_party = relying_party

    @classmethod
    def build(
        cls,
        settings: WebAuthSettings,
        *,
        stores: WebAuthStores,
        groups: AdmissionConfig,
        pages: SignInPages,
        front: TrustedProxies,
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

    @property
    def stores(self) -> WebAuthStores:
        return self._stores

    def install(self, app: FastAPI, *, bearer: BearerGate | None) -> None:
        """Place the stack, the sign-in routes and this handle on ``app``, after its last route.

        Outermost first: logline's request line, the client-address writer, ``outside``, the
        library's stack, ``inside``. A ``bearer`` that does not fit the early values raises a
        ``WebAuthSettingError``; a second install, or an app that already carries library
        middleware, raises ``RuntimeError``. Both are refused before the app changes.
        """
        self._require_a_bearer_that_fits(bearer)
        if _has_installed_web_auth(app):
            raise RuntimeError("This application has an installed WebAuth already; install once.")
        settings = self._settings
        resource = None if bearer is None else bearer.resource
        gate = self._gate
        if gate is not None and resource is not None:
            gate = replace(gate, public=(*gate.public, resource.public_rule))
        _install_slotted_web_auth_middleware(
            app,
            sign_in_paths=settings.sign_in_paths,
            security_headers=settings.security_headers,
            csrf_origin=settings.csrf_origin,
            body_size=settings.body_size,
            rate_limit=settings.rate_limit,
            bearer_gate=bearer,
            session_gate=gate,
            front=self._front,
            outside=self._outside,
            inside=self._inside,
        )
        install_web_auth_config(app, settings.config)
        _publish_installed_web_auth(app, self)
        install_sign_in_routes(
            app,
            paths=settings.sign_in_paths,
            relying_party=lambda _request: self._relying_party,
            admission=self._groups,
            transaction=self._stores.sign_in,
            refused=self._pages.refused,
            keeps_id_token=settings.keeps_id_token,
            max_sessions=settings.max_sessions,
            logout_page_text=self._pages.logout_page_text,
            ui_language=self._pages.ui_language,
        )
        if resource is not None:
            install_resource_metadata(app, resource, issuer=settings.client.issuer)

    def _require_a_bearer_that_fits(self, bearer: BearerGate | None) -> None:
        if bearer is None:
            return
        if bearer.relying_party is not self._relying_party:
            raise _refuse("bearer.relying_party", "must be the relying_party of this WebAuth")
        if bearer.admission != self._groups:
            raise _refuse("bearer.admission", "must be the groups this WebAuth was built with")
