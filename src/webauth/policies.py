"""What the host application decides about its own requests.

The library owns the mechanism — one budget class per request, one CSRF
verdict, one body limit, one set of response headers — and knows nothing
about which paths a particular deployment serves. Each policy below carries
those answers as data: the application builds it at startup and hands it to
the middleware that reads it, so no middleware reaches for a settings
singleton or an application module of its own.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum, StrEnum, auto
from typing import Final

__all__ = [
    "DEFAULT_PERMISSIONS_POLICY",
    "BodySizePolicy",
    "BodySizeRule",
    "CacheControlRule",
    "CspDirective",
    "CsrfPolicy",
    "PathRules",
    "PathShape",
    "RateLimitBudget",
    "RateLimitClass",
    "RateLimitPolicy",
    "SecurityHeadersPolicy",
    "default_content_security_policy",
]


@dataclass(frozen=True)
class PathShape:
    """A path recognised by how it begins and how it ends."""

    starts_with: str
    ends_with: str

    def matches(self, path: str) -> bool:
        return path.startswith(self.starts_with) and path.endswith(self.ends_with)


@dataclass(frozen=True)
class PathRules:
    """The paths a rule selects, named exactly or by shape."""

    exact: frozenset[str] = frozenset()
    prefixes: tuple[str, ...] = ()
    shapes: tuple[PathShape, ...] = ()
    patterns: tuple[re.Pattern[str], ...] = ()

    def matches(self, path: str) -> bool:
        return (
            path in self.exact
            or path.startswith(self.prefixes)
            or any(shape.matches(path) for shape in self.shapes)
            or any(pattern.match(path) for pattern in self.patterns)
        )


class RateLimitClass(Enum):
    """The budget a request spends from, decided once per request."""

    API = auto()
    MEDIA = auto()
    STREAM = auto()


@dataclass(frozen=True)
class RateLimitBudget:
    """How many requests one class grants an address within its window."""

    max_requests: int
    window_seconds: int


@dataclass(frozen=True)
class RateLimitPolicy:
    """Which paths belong to which budget class, and how large each budget is.

    Separate classes exist so one traffic pattern cannot starve another
    arriving from the same address: range-served media and stream openings
    are ordinary use at rates that would look like abuse on an API budget.
    """

    budgets: Mapping[RateLimitClass, RateLimitBudget]
    exempt: PathRules = PathRules()
    media: PathRules = PathRules()
    stream: PathRules = PathRules()

    def __post_init__(self) -> None:
        unbudgeted = [
            rate_limit_class.name
            for rate_limit_class in RateLimitClass
            if rate_limit_class not in self.budgets
        ]
        if unbudgeted:
            raise ValueError(
                "Every rate-limit class needs a budget, or a request classified "
                f"into one would go unlimited; missing: {', '.join(unbudgeted)}.",
            )

    def is_exempt(self, path: str) -> bool:
        return self.exempt.matches(path)

    def classify(self, path: str) -> RateLimitClass:
        """The one class ``path`` spends from.

        A path no rule claims spends from the API budget — fail closed, so an
        unrecognised route cannot slip through unlimited.
        """
        if self.media.matches(path):
            return RateLimitClass.MEDIA
        if self.stream.matches(path):
            return RateLimitClass.STREAM
        return RateLimitClass.API

    def budget(self, rate_limit_class: RateLimitClass) -> RateLimitBudget:
        return self.budgets[rate_limit_class]


@dataclass(frozen=True)
class CsrfPolicy:
    """Which requests must prove they were made from this site.

    Leaving ``protected`` at its default (``None``) is the fail-closed shape:
    every state-changing request is checked, and ``exempt`` carves out the
    prefixes that carry no session and no token — a sessionless webhook, say.
    Naming an explicit ``PathRules`` in ``protected`` switches to the older
    fail-open shape, matched only against the paths it lists. That shape
    cannot carry an ``exempt`` rule: a non-empty exemption is refused at
    construction, rather than silently failing to change the listed paths.

    A path may be exempt from the token check and still owe a same-origin
    check: a login carries no session yet, so it has no token to submit, but
    a foreign page must not be able to submit it either.
    """

    protected: PathRules | None = None
    exempt: PathRules = PathRules()
    token_exempt: PathRules = PathRules()

    def __post_init__(self) -> None:
        if self.protected is not None and any((
            self.exempt.exact,
            self.exempt.prefixes,
            self.exempt.shapes,
            self.exempt.patterns,
        )):
            raise ValueError(
                "CsrfPolicy cannot combine explicit protected rules with exempt rules.",
            )

    def _is_protected(self, path: str) -> bool:
        if self.protected is None:
            return not self.exempt.matches(path)
        return self.protected.matches(path)

    def requires_same_origin(self, path: str) -> bool:
        return self._is_protected(path)

    def requires_token(self, path: str) -> bool:
        return self._is_protected(path) and not self.token_exempt.matches(path)

    def token_exemptions_outside_origin_check(self, token_policy: CsrfPolicy) -> tuple[str, ...]:
        """The ``token_policy`` exemptions this policy's origin check does not fully cover.

        A token exemption is safe only where the origin check still runs, so
        the decision is conservative and errs toward "uncovered":

        - an exact exemption is covered when ``requires_same_origin`` holds for it;
        - a prefix exemption is covered only when every path below it requires
          the origin check. With the default ``protected`` that means no
          ``exempt`` rule can match at or below the prefix: no exact path
          beginning with it, no prefix overlapping it either way, no shape whose
          start overlaps it, and no pattern at all (unverifiable). With explicit
          ``protected`` rules it means some protected prefix begins the
          exemption prefix; an exact protected path never covers a prefix;
        - a shape or pattern exemption cannot be enumerated and is always
          uncovered.
        """
        token_exempt = token_policy.token_exempt
        uncovered = [
            path for path in sorted(token_exempt.exact)
            if not self.requires_same_origin(path)
        ]
        uncovered += [
            prefix for prefix in token_exempt.prefixes
            if not self._covers_every_path_under(prefix)
        ]
        uncovered += [f"{rule!r}" for rule in (*token_exempt.shapes, *token_exempt.patterns)]
        return tuple(uncovered)

    def _covers_every_path_under(self, prefix: str) -> bool:
        if self.protected is not None:
            return any(prefix.startswith(q) for q in self.protected.prefixes)
        exempt = self.exempt
        return not (
            exempt.matches(prefix)
            or exempt.patterns
            or any(path.startswith(prefix) for path in exempt.exact)
            or any(q.startswith(prefix) for q in exempt.prefixes)
            or any(
                shape.starts_with.startswith(prefix) or prefix.startswith(shape.starts_with)
                for shape in exempt.shapes
            )
        )


@dataclass(frozen=True)
class BodySizeRule:
    """Routes whose request body may be larger than the default, and by how much."""

    paths: PathRules
    max_bytes: int
    methods: frozenset[str] | None = None
    """The methods the larger budget applies to; ``None`` means every method."""

    def applies_to(self, path: str, method: str) -> bool:
        if self.methods is not None and method.upper() not in self.methods:
            return False
        return self.paths.matches(path)


@dataclass(frozen=True)
class BodySizePolicy:
    """How large a request body may be, by default and on the routes that differ."""

    default_max_bytes: int
    rules: tuple[BodySizeRule, ...] = ()
    start_send_seconds: float = 10.0
    """How long a response start may take to reach the server before the request fails."""

    def __post_init__(self) -> None:
        if not 0 < self.start_send_seconds < math.inf:
            raise ValueError("start_send_seconds must be positive and finite.")

    def max_bytes(self, path: str, method: str) -> int:
        """The budget for this request; the first matching rule wins."""
        for rule in self.rules:
            if rule.applies_to(path, method):
                return rule.max_bytes
        return self.default_max_bytes


@dataclass(frozen=True)
class CacheControlRule:
    """The ``Cache-Control`` value the paths it names are answered with."""

    paths: PathRules
    value: str


DEFAULT_PERMISSIONS_POLICY: Final = "camera=(), microphone=(), geolocation=()"


@dataclass(frozen=True)
class SecurityHeadersPolicy:
    """The policy headers every response carries out of this deployment."""

    content_security_policy: str
    cache_control_rules: tuple[CacheControlRule, ...] = ()
    permissions_policy: str = DEFAULT_PERMISSIONS_POLICY

    def __post_init__(self) -> None:
        if "\r" in self.permissions_policy or "\n" in self.permissions_policy:
            raise ValueError(
                "permissions_policy cannot contain CR or LF: a header value with "
                "a line break breaks every response it is sent on.",
            )

    def cache_control(self, path: str) -> str | None:
        """What this path may be cached as; the first matching rule wins."""
        for rule in self.cache_control_rules:
            if rule.paths.matches(path):
                return rule.value
        return None


class CspDirective(StrEnum):
    """The directives a host may extend, in the order the default policy writes them."""

    SCRIPT_SRC = "script-src"
    STYLE_SRC = "style-src"
    CONNECT_SRC = "connect-src"
    IMG_SRC = "img-src"
    MEDIA_SRC = "media-src"
    FONT_SRC = "font-src"
    MANIFEST_SRC = "manifest-src"
    WORKER_SRC = "worker-src"
    FRAME_ANCESTORS = "frame-ancestors"
    FORM_ACTION = "form-action"


_TEXT_LIKE: Final = (str, bytes, bytearray, memoryview)
_SELF_KEYWORD: Final = "'self'"
_NONE_SOURCE: Final = "'none'"
_GRAMMAR_FLAGS: Final = re.ASCII | re.IGNORECASE
_DEFAULT_SOURCES: Final[Mapping[CspDirective, tuple[str, ...]]] = {
    CspDirective.SCRIPT_SRC: (_SELF_KEYWORD,),
    CspDirective.STYLE_SRC: (_SELF_KEYWORD,),
    CspDirective.CONNECT_SRC: (_SELF_KEYWORD,),
    CspDirective.IMG_SRC: (_SELF_KEYWORD, "data:", "blob:"),
    CspDirective.MEDIA_SRC: (_SELF_KEYWORD, "blob:"),
    CspDirective.FONT_SRC: (_SELF_KEYWORD,),
    CspDirective.MANIFEST_SRC: (_SELF_KEYWORD,),
    CspDirective.WORKER_SRC: (_SELF_KEYWORD,),
    CspDirective.FRAME_ANCESTORS: (_NONE_SOURCE,),
    CspDirective.FORM_ACTION: (_SELF_KEYWORD,),
}

_BASE64_VALUE: Final = r"[A-Za-z0-9+/\-_]+={0,2}"
_HASH_ALGORITHM: Final = r"sha(?:256|384|512)"
_HOST_LABEL: Final = r"[A-Za-z0-9\-]+"
_HOST: Final = rf"(?:\*|(?:\*\.)?{_HOST_LABEL}(?:\.{_HOST_LABEL})*\.?)"
_PORT: Final = r":(?:[0-9]+|\*)"
_PATH_CHAR: Final = r"(?:[\w\-.~!$&'()*+=:@]|%[0-9A-Fa-f]{2})"
_PATH: Final = rf"/(?:{_PATH_CHAR}+(?:/{_PATH_CHAR}*)*)?"
_SCHEME: Final = r"[A-Za-z][A-Za-z0-9+.\-]*"
_KEYWORDS: Final = (
    "self",
    "unsafe-inline",
    "unsafe-eval",
    "strict-dynamic",
    "unsafe-hashes",
    "report-sample",
    "unsafe-allow-redirects",
    "wasm-unsafe-eval",
)

_BARE_HASH: Final = re.compile(f"{_HASH_ALGORITHM}-{_BASE64_VALUE}", _GRAMMAR_FLAGS)
_KEYWORD_SOURCE: Final = re.compile(f"'(?:{'|'.join(_KEYWORDS)})'", _GRAMMAR_FLAGS)
_SELF_SOURCE: Final = re.compile(_SELF_KEYWORD, _GRAMMAR_FLAGS)
_NONCE_SOURCE: Final = re.compile(f"'nonce-{_BASE64_VALUE}'", _GRAMMAR_FLAGS)
_HASH_SOURCE: Final = re.compile(f"'{_HASH_ALGORITHM}-{_BASE64_VALUE}'", _GRAMMAR_FLAGS)
_SCHEME_SOURCE: Final = re.compile(f"{_SCHEME}:", _GRAMMAR_FLAGS)
_HOST_SOURCE: Final = re.compile(
    rf"(?:{_SCHEME}://)?{_HOST}(?:{_PORT})?(?:{_PATH})?",
    _GRAMMAR_FLAGS,
)
_SOURCE_GRAMMAR: Final = (
    _KEYWORD_SOURCE,
    _NONCE_SOURCE,
    _HASH_SOURCE,
    _SCHEME_SOURCE,
    _HOST_SOURCE,
)
_NAVIGATION_GRAMMAR: Final = (_SELF_SOURCE, _SCHEME_SOURCE, _HOST_SOURCE)
_SOURCE_SUBSET: Final = (
    "keyword sources "
    + ", ".join(f"'{keyword}'" for keyword in _KEYWORDS)
    + "; nonce and sha256, sha384, sha512 hash sources; scheme sources; host sources"
)
_NAVIGATION_SUBSET: Final = "'self', scheme sources and host sources"
_NAVIGATION_DIRECTIVES: Final = frozenset({CspDirective.FRAME_ANCESTORS, CspDirective.FORM_ACTION})
_FIXED_DIRECTIVES: Final = ("default-src 'none'", "base-uri 'self'")


def _require_source_list(owner: str, sources: object) -> Sequence[str]:
    if isinstance(sources, _TEXT_LIKE) or not isinstance(sources, Sequence):
        raise TypeError(
            f"{owner}: sources must be a sequence of str, not {type(sources).__name__}.",
        )
    for source in sources:
        if not isinstance(source, str):
            raise TypeError(f"{owner}: a source must be a str, not {type(source).__name__}.")
    return sources


def _validated_hash(script_hash: str) -> str:
    if not _BARE_HASH.fullmatch(script_hash):
        raise ValueError(
            f"{CspDirective.SCRIPT_SRC}: {script_hash!r} is not a bare sha256-, sha384- or "
            "sha512- hash with a base64 value.",
        )
    return f"'{script_hash}'"


def _validated_source(directive: CspDirective, source: str) -> str:
    is_navigation = directive in _NAVIGATION_DIRECTIVES
    grammar = _NAVIGATION_GRAMMAR if is_navigation else _SOURCE_GRAMMAR
    subset = _NAVIGATION_SUBSET if is_navigation else _SOURCE_SUBSET
    if not any(production.fullmatch(source) for production in grammar):
        raise ValueError(
            f"{directive}: {source!r} is not a source this library accepts; "
            f"the declared subset is {subset}.",
        )
    return source


def _validated_additions(
    added_sources: Mapping[CspDirective, Sequence[str]] | None,
) -> dict[CspDirective, tuple[str, ...]]:
    if added_sources is None:
        return {}
    if not isinstance(added_sources, Mapping):
        raise TypeError(f"added_sources must be a Mapping, not {type(added_sources).__name__}.")
    additions: dict[CspDirective, tuple[str, ...]] = {}
    for directive, sources in added_sources.items():
        if not isinstance(directive, CspDirective):
            raise TypeError(f"added_sources keys must be CspDirective members, not {directive!r}.")
        additions[directive] = tuple(
            _validated_source(directive, source)
            for source in _require_source_list(directive, sources)
        )
    return additions


def _source_list(
    directive: CspDirective,
    quoted_hashes: tuple[str, ...],
    additions: tuple[str, ...],
) -> str:
    defaults = _DEFAULT_SOURCES[directive]
    if additions and defaults == (_NONE_SOURCE,):
        defaults = ()
    hashes = quoted_hashes if directive is CspDirective.SCRIPT_SRC else ()
    return " ".join(dict.fromkeys((*defaults, *hashes, *additions)))


def default_content_security_policy(
    script_hashes: Sequence[str] = (),
    *,
    added_sources: Mapping[CspDirective, Sequence[str]] | None = None,
) -> str:
    """Nothing loads unless this origin serves it, and no page may frame it.

    Forms post only to this origin and a ``<base>`` may point only at it.

    The default holds no host fact. Inline scripts a build emits into its own
    document are admitted by bare hash (``sha256-<base64>``), which this function
    quotes. A host adds its own sources per directive in ``added_sources`` as
    complete source expressions: keywords, nonces and hashes in their quotes,
    hosts and schemes bare. A non-empty addition to ``frame-ancestors`` replaces
    its ``'none'``. A source outside the validated grammar is a ``ValueError``
    and a wrong type a ``TypeError``, raised before any policy is built.
    """
    quoted_hashes = tuple(
        _validated_hash(script_hash)
        for script_hash in _require_source_list(CspDirective.SCRIPT_SRC, script_hashes)
    )
    additions = _validated_additions(added_sources)
    directives = (
        f"{directive} {_source_list(directive, quoted_hashes, additions.get(directive, ()))}"
        for directive in CspDirective
    )
    return "; ".join((*_FIXED_DIRECTIVES, *directives))
