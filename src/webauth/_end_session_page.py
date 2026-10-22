"""The page that ends the issuer's session: one form posted to its end-session endpoint.

``EndSessionForm`` holds what the issuer receives. ``end_session_page`` answers
it as a ``no-store`` page that submits itself, and as a button when a script
cannot run, under a policy of its own that admits exactly that one script and
posts to the end-session and post-logout origins. The answer carries the
own-policy marker, so ``SecurityHeadersMiddleware`` leaves that policy and
``Cache-Control`` in place. The ID token hint is a ``SecretStr`` until it is
written into the page.
"""

from __future__ import annotations

import base64
import hashlib
import html
import urllib.parse
from dataclasses import dataclass
from typing import Final

from pydantic import SecretStr
from starlette.responses import Response

from webauth.policies import _OWN_POLICY_HEADER, _OWN_POLICY_HEADER_VALUE

__all__ = ["EndSessionForm", "end_session_page"]

_SUBMIT_SCRIPT: Final = "document.forms[0].submit()"
_SCRIPT_HASH: Final = base64.b64encode(hashlib.sha256(_SUBMIT_SCRIPT.encode()).digest()).decode()


@dataclass(frozen=True)
class EndSessionForm:
    """The fields of the form posted to ``end_session_endpoint``."""

    end_session_endpoint: str
    client_id: str
    post_logout_redirect_uri: str
    id_token_hint: SecretStr | None

    def hidden_fields(self) -> dict[str, str]:
        fields = {
            "client_id": self.client_id,
            "post_logout_redirect_uri": self.post_logout_redirect_uri,
        }
        if self.id_token_hint is not None:
            fields["id_token_hint"] = self.id_token_hint.get_secret_value()
        return fields


def end_session_page(form: EndSessionForm, *, button_label: str) -> Response:
    """The page that posts ``form`` and shows ``button_label`` where no script runs."""
    return Response(
        _markup(form, button_label),
        media_type="text/html",
        headers={
            "Cache-Control": "no-store",
            "Content-Security-Policy": _content_security_policy(form),
            _OWN_POLICY_HEADER: _OWN_POLICY_HEADER_VALUE,
        },
    )


def _markup(form: EndSessionForm, button_label: str) -> str:
    label = html.escape(button_label)
    inputs = "".join(
        f'<input type="hidden" name="{html.escape(name)}" value="{html.escape(value)}">'
        for name, value in form.hidden_fields().items()
    )
    return (
        '<!doctype html><html><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{label}</title></head><body>"
        f'<form method="post" action="{html.escape(form.end_session_endpoint)}">'
        f'{inputs}<button type="submit">{label}</button></form>'
        f"<script>{_SUBMIT_SCRIPT}</script></body></html>"
    )


def _content_security_policy(form: EndSessionForm) -> str:
    form_targets = dict.fromkeys(
        _origin(url) for url in (form.end_session_endpoint, form.post_logout_redirect_uri)
    )
    return "; ".join((
        "default-src 'none'",
        f"script-src 'sha256-{_SCRIPT_HASH}'",
        f"form-action {' '.join(form_targets)}",
        "base-uri 'none'",
        "frame-ancestors 'none'",
    ))


def _origin(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"
