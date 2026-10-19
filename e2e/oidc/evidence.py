"""What a run may keep: an allowlisted network log, a registry of every
credential the run touched, and the scan that keeps the evidence directory clean.

The network log is built from the browser's events field by field, so a field
this module does not know cannot reach the file. Masking keeps already-registered
values out of stdout and the table; a line that needed masking fails the run; the
final scan catches values registered later and deletes the file."""

from __future__ import annotations

import base64
import json
import re
import urllib.parse
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, TypedDict

from webauth.cookies import _is_pending_login_cookie_name, _pending_login_cookie_prefix

MIN_REGISTERED_VALUE_CHARS = 8
KEPT_HEADER_VALUES = frozenset({
    "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "content-type", "cache-control",
})
KEPT_SET_COOKIE_FLAGS = frozenset({"secure", "httponly"})
KEPT_SET_COOKIE_VALUES = {
    "samesite": re.compile(r"(?i)strict|lax|none"),
    "path": re.compile(r"/[\w/.\-]*"),
    "max-age": re.compile(r"-?\d+"),
    "expires": re.compile(r"[A-Za-z]{3}, \d\d[ \-][A-Za-z]{3}[ \-]\d{2,4} [\d:]{8} GMT"),
}
INVALID_ATTRIBUTE_VALUE = "(not a plain value)"
EVIDENCE_SUFFIXES = frozenset({".png", ".har", ".txt"})
CREDENTIAL_NAME_PARTS = ("secret", "credential", "password", "token", "key", "cert", "pem")
QUERY_IN_TEXT = re.compile(r"\?[^\s\"'<>]*")
HAR_VERSION = "1.2"



class HeaderPair(TypedDict):
    name: str
    value: str


class RequestTiming(TypedDict):
    startTime: float


HeaderPairs = Sequence[HeaderPair]


class RequestEvent(Protocol):
    """The part of a Playwright request the log reads."""

    @property
    def url(self) -> str: ...

    @property
    def method(self) -> str: ...

    @property
    def timing(self) -> RequestTiming: ...

    def headers_array(self) -> HeaderPairs: ...

    def response(self) -> Any: ...


@dataclass
class SecretRegistry:
    """Every credential value the run created or saw, by label."""

    values: dict[str, set[str]] = field(default_factory=dict)

    def add(self, label: str, value: str) -> None:
        if len(value) >= MIN_REGISTERED_VALUE_CHARS:
            self.values.setdefault(label, set()).add(value)

    def add_client_secret(self, client_id: str, secret: str) -> None:
        """The secret as it is, and as ``client_secret_basic`` sends it: base64 of the
        form-encoded ``client_id:secret`` (RFC 6749 section 2.3.1, RFC 7617)."""
        self.add("client secret", secret)
        credentials = f"{urllib.parse.quote_plus(client_id)}:{urllib.parse.quote_plus(secret)}"
        header_form = base64.b64encode(credentials.encode()).decode()
        self.add("client secret (client_secret_basic)", header_form)

    def masked(self, text: str) -> str:
        """The text with every registered value, in any encoding, replaced by its label;
        the longest form first, so one value never hides inside another's label."""
        for form, label in self._forms_longest_first():
            text = text.replace(form, f"[registered secret: {label}]")
        return text

    def labels_in(self, content: bytes) -> list[str]:
        """The labels of every registered value that appears in the content."""
        return sorted(
            label
            for label, forms in self.forms_by_label().items()
            if any(form in content for form in forms)
        )

    def _forms_longest_first(self) -> list[tuple[str, str]]:
        pairs = [
            (form.decode(), label)
            for label, forms in self.forms_by_label().items()
            for form in forms
        ]
        return sorted(pairs, key=lambda pair: len(pair[0]), reverse=True)

    def forms_by_label(self) -> dict[str, set[bytes]]:
        """Each value as raw, URL-encoded and form-encoded bytes."""
        return {
            label: {
                form.encode()
                for value in values
                for form in (
                    value, urllib.parse.quote(value, safe=""), urllib.parse.quote_plus(value)
                )
            }
            for label, values in self.values.items()
        }


@dataclass(frozen=True)
class Contamination:
    file: str
    label: str


def without_query_values(text: str) -> str:
    """Free text with every query string cut, for messages that may quote a URL."""
    return QUERY_IN_TEXT.sub("?...", text)


def sanitized_url(url: str) -> tuple[str, list[str]]:
    """``scheme://host[:port]/path`` and the names of the query parameters; no
    userinfo and no path parameters survive."""
    parts = urllib.parse.urlsplit(url)
    names = [name for name, _ in urllib.parse.parse_qsl(parts.query, keep_blank_values=True)]
    host = f"[{parts.hostname}]" if ":" in (parts.hostname or "") else parts.hostname or ""
    port = f":{parts.port}" if parts.port else ""
    path = "/".join(segment.partition(";")[0] for segment in parts.path.split("/"))
    return f"{parts.scheme}://{host}{port}{path}", names


def recorded_cookie_name(name: str) -> str:
    """A pending-login cookie's name ends in a digest of the login's state;
    the log keeps the shape only."""
    if _is_pending_login_cookie_name(name, secure=True):
        return f"{_pending_login_cookie_prefix(secure=True)}*"
    return name


class NetworkLog:
    """Collects requests as they happen and turns them into HAR entries on demand."""

    def __init__(self, registry: SecretRegistry) -> None:
        self._registry = registry
        self._pending: list[RequestEvent] = []
        self._entries: list[dict[str, Any]] = []

    def watch(self, request: RequestEvent) -> None:
        self._pending.append(request)

    def collect(self) -> None:
        """Turn what has been watched into entries; the browser must still be open."""
        for request in self._pending:
            self._entries.append(self._entry(request))
        self._pending.clear()

    def write(self, path: Path) -> None:
        document = {
            "log": {
                "version": HAR_VERSION,
                "creator": {"name": "webauth e2e/oidc", "version": "1"},
                "entries": self._entries,
            }
        }
        path.write_text(json.dumps(document, indent=1))

    def _entry(self, request: RequestEvent) -> dict[str, Any]:
        response = request.response()
        url, query_names = sanitized_url(request.url)
        request_headers = request.headers_array()
        response_headers = response.headers_array() if response else []
        self._register_set_cookie_values(response_headers)
        started = request.timing["startTime"] / 1000
        return {
            "startedDateTime": datetime.fromtimestamp(started, UTC).isoformat(),
            "time": 0,
            "request": {
                "method": request.method,
                "url": url,
                "httpVersion": "",
                "cookies": [
                    {"name": recorded_cookie_name(name), "value": ""}
                    for name in cookie_names(request_headers)
                ],
                "headers": _headers(request_headers),
                "queryString": [{"name": name, "value": ""} for name in query_names],
                "headersSize": -1,
                "bodySize": -1,
            },
            "response": {
                "status": response.status if response else 0,
                "statusText": "",
                "httpVersion": "",
                "cookies": _set_cookies(response_headers),
                "headers": _headers(response_headers),
                "content": {"size": -1, "mimeType": ""},
                "redirectURL": _redirect_target(response_headers, request.url),
                "headersSize": -1,
                "bodySize": -1,
            },
            "cache": {},
            "timings": {"send": 0, "wait": 0, "receive": 0},
        }

    def _register_set_cookie_values(self, headers: HeaderPairs) -> None:
        for header in headers:
            if header["name"].lower() == "set-cookie":
                for line in header["value"].splitlines():
                    name, _, rest = line.partition("=")
                    label = f"cookie {recorded_cookie_name(name)}"
                    self._registry.add(label, rest.split(";", 1)[0])


def _headers(headers: HeaderPairs) -> list[dict[str, str]]:
    return [
        {
            "name": header["name"],
            "value": header["value"] if header["name"].lower() in KEPT_HEADER_VALUES else "",
        }
        for header in headers
    ]


def cookie_names(request_headers: HeaderPairs) -> list[str]:
    return [
        pair.split("=", 1)[0].strip()
        for header in request_headers if header["name"].lower() == "cookie"
        for pair in header["value"].split(";") if pair.strip()
    ]


def _set_cookies(response_headers: HeaderPairs) -> list[dict[str, Any]]:
    cookies = []
    for header in response_headers:
        if header["name"].lower() != "set-cookie":
            continue
        for line in header["value"].splitlines():
            name_and_value, *attributes = line.split(";")
            name = name_and_value.split("=", 1)[0].strip()
            cookie: dict[str, Any] = {"name": recorded_cookie_name(name), "value": ""}
            for attribute in attributes:
                key, _, value = attribute.strip().partition("=")
                key = key.lower()
                if key in KEPT_SET_COOKIE_FLAGS:
                    cookie[key] = True
                elif key in KEPT_SET_COOKIE_VALUES:
                    plain = KEPT_SET_COOKIE_VALUES[key].fullmatch(value) is not None
                    cookie[key] = value if plain else INVALID_ATTRIBUTE_VALUE
            cookies.append(cookie)
    return cookies


def _redirect_target(response_headers: HeaderPairs, request_url: str) -> str:
    for header in response_headers:
        if header["name"].lower() == "location":
            url, _ = sanitized_url(urllib.parse.urljoin(request_url, header["value"]))
            return url
    return ""


def scan_evidence(evidence_dir: Path, registry: SecretRegistry) -> list[Contamination]:
    """Every registered value found in a retained file, and every file that is
    not an allowed kind of evidence; names the file and the label, never the value."""
    findings = []
    for path in sorted(evidence_dir.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(evidence_dir).as_posix()
        if path.suffix not in EVIDENCE_SUFFIXES or any(
            part in path.name.lower() for part in CREDENTIAL_NAME_PARTS
        ):
            findings.append(Contamination(relative, "file kind"))
        content = path.read_bytes()
        findings.extend(
            Contamination(relative, label) for label in registry.labels_in(content)
        )
    return findings


def delete_contaminated(evidence_dir: Path, findings: list[Contamination]) -> None:
    for relative in {finding.file for finding in findings}:
        (evidence_dir / relative).unlink(missing_ok=True)
