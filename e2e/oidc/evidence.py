"""What a run may keep: an allowlisted network log, a registry of every
credential the run touched, and the scan that keeps the evidence directory clean.

The network log is built from the browser's events field by field, so a field
this module does not know cannot reach the file. Nothing here redacts."""

from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

MIN_REGISTERED_VALUE_CHARS = 8
KEPT_HEADER_VALUES = frozenset({
    "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "content-type", "cache-control",
})
KEPT_SET_COOKIE_FLAGS = frozenset({"secure", "httponly"})
KEPT_SET_COOKIE_VALUES = frozenset({"samesite", "path", "max-age", "expires"})
EVIDENCE_SUFFIXES = frozenset({".png", ".har", ".txt"})
CREDENTIAL_NAME_PARTS = ("secret", "credential", "password", "token", "key", "cert", "pem")
QUERY_IN_TEXT = re.compile(r"\?[^\s\"'<>]*")
HAR_VERSION = "1.2"


class RequestEvent(Protocol):
    """The part of a Playwright request the log reads."""

    url: str
    method: str
    timing: dict[str, float]

    def headers_array(self) -> list[dict[str, str]]: ...

    def response(self) -> Any: ...


@dataclass
class SecretRegistry:
    """Every credential value the run created or saw, by label."""

    values: dict[str, set[str]] = field(default_factory=dict)

    def add(self, label: str, value: str) -> None:
        if len(value) >= MIN_REGISTERED_VALUE_CHARS:
            self.values.setdefault(label, set()).add(value)

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
    """``scheme://host/path`` and the names of the query parameters."""
    parts = urllib.parse.urlsplit(url)
    names = [name for name, _ in urllib.parse.parse_qsl(parts.query, keep_blank_values=True)]
    return f"{parts.scheme}://{parts.netloc}{parts.path}", names


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
        started = request.timing.get("startTime", 0) / 1000
        return {
            "startedDateTime": datetime.fromtimestamp(started, timezone.utc).isoformat(),
            "time": 0,
            "request": {
                "method": request.method,
                "url": url,
                "httpVersion": "",
                "cookies": [{"name": name, "value": ""} for name in _cookie_names(request_headers)],
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

    def _register_set_cookie_values(self, headers: list[dict[str, str]]) -> None:
        for header in headers:
            if header["name"].lower() == "set-cookie":
                name, _, rest = header["value"].partition("=")
                self._registry.add(f"cookie {name}", rest.split(";", 1)[0])


def _headers(headers: list[dict[str, str]]) -> list[dict[str, str]]:
    return [
        {
            "name": header["name"],
            "value": header["value"] if header["name"].lower() in KEPT_HEADER_VALUES else "",
        }
        for header in headers
    ]


def _cookie_names(request_headers: list[dict[str, str]]) -> list[str]:
    return [
        pair.split("=", 1)[0].strip()
        for header in request_headers if header["name"].lower() == "cookie"
        for pair in header["value"].split(";") if pair.strip()
    ]


def _set_cookies(response_headers: list[dict[str, str]]) -> list[dict[str, Any]]:
    cookies = []
    for header in response_headers:
        if header["name"].lower() != "set-cookie":
            continue
        name_and_value, *attributes = header["value"].split(";")
        cookie: dict[str, Any] = {"name": name_and_value.split("=", 1)[0].strip(), "value": ""}
        for attribute in attributes:
            key, _, value = attribute.strip().partition("=")
            key = key.lower()
            if key in KEPT_SET_COOKIE_FLAGS:
                cookie[key] = True
            elif key in KEPT_SET_COOKIE_VALUES:
                cookie[key] = value
        cookies.append(cookie)
    return cookies


def _redirect_target(response_headers: list[dict[str, str]], request_url: str) -> str:
    for header in response_headers:
        if header["name"].lower() == "location":
            url, _ = sanitized_url(urllib.parse.urljoin(request_url, header["value"]))
            return url
    return ""


def scan_evidence(evidence_dir: Path, registry: SecretRegistry) -> list[Contamination]:
    """Every registered value found in a retained file, and every file that is
    not an allowed kind of evidence; names the file and the label, never the value."""
    forms_by_label = registry.forms_by_label()
    findings = []
    for path in sorted(evidence_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix not in EVIDENCE_SUFFIXES or any(
            part in path.name.lower() for part in CREDENTIAL_NAME_PARTS
        ):
            findings.append(Contamination(path.name, "file kind"))
        content = path.read_bytes()
        findings.extend(
            Contamination(path.name, label)
            for label, forms in forms_by_label.items()
            if any(form in content for form in forms)
        )
    return findings


def delete_contaminated(evidence_dir: Path, findings: list[Contamination]) -> None:
    for name in {finding.file for finding in findings}:
        (evidence_dir / name).unlink(missing_ok=True)
