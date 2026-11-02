"""The resource scenarios of the bearer proof, 61 to 72.

The resource scenarios send agent tokens, whose only audience is the resource, to its entry point
``/mcp``; ``CHECK bearer-resource-tokens`` asserts ``aud`` and ``scope`` on a real one.

- 61 a known member of the MCP group: POST, no cookie, no ``Origin``, 200 with the user role.
- 62 a stored admin: 200 with the user role; no ``set_role`` (the ledger counts the accounts
  above the member role) and no event.
- 63 a known member of the login group outside the MCP group, the outsider and an unknown
  subject: 403 Access denied, the store untouched.
- 64 the agent token on ``/api/me``, a machine route and ``/admin``: 401, 401, the session's 401.
- 65 an app bearer and two audiences: 401; no scope: 403 ``insufficient_scope``.
- 66 no credential, and a fresh session cookie alone: 401 with the resource challenge.

Scenarios 67 to 72 send the same tokens to the resource's marked routes (``MARKED_ROUTES`` of
``host_app``):

- 67 the agent token on a marked ``GET`` and ``POST``: 200 with the user role, no cookie, no
  ``Origin``.
- 68 a stored admin on the marked route that reads ``admin_user``: the plain 403, no challenge.
- 69 no scope: 403 ``insufficient_scope``; two audiences: 401; each with a valid admin cookie.
- 70 an app bearer on the marked person path: admitted as today; one for another audience:
  today's person-path 401; on the other marked route it is ignored and the cookie decides.
- 71 no bearer: a cookie passes and a cross-origin cookie ``POST`` is refused.
- 72 the agent token on an unmarked method, ``HEAD``, a trailing slash, a longer path and ``..``:
  refused, no account.
"""

from __future__ import annotations

from typing import Any

from bearer_run import (
    EXPORT,
    HAL,
    ME,
    PERSON_CHALLENGE_INVALID_TOKEN,
    BearerRun,
    Call,
    as_list,
    assert_answer,
    assert_person_answer,
    claims_of,
    session_cookies,
)
from harness import reset_host
from host_app import RESOURCE_PATH, RESOURCE_SCOPE
from realm import ADMIN_NAME, OUTSIDER_NAME, RESOURCE_AUDIENCE_SCOPE, UNGROUPED_NAME, USER_NAME

AGENT_SCOPE = f"openid {RESOURCE_SCOPE}"
LEDGER = (
    "accounts", "account_events", "sessions", "session_transactions", "privileged_accounts",
)



# --- the resource scenarios: an agent's token at the entry point ---

def resource_challenge(run: BearerRun, error: str | None = None) -> str:
    metadata = f"{run.settings.app_origins[0]}/.well-known/oauth-protected-resource{RESOURCE_PATH}"
    challenge = f'Bearer resource_metadata="{metadata}", scope="{RESOURCE_SCOPE}"'
    return challenge if error is None else f'{challenge}, error="{error}"'


def ledger(run: BearerRun) -> tuple[Any, ...]:
    return tuple(run.state()[key] for key in LEDGER)


def agent_post(run: BearerRun, name: str, status: int) -> Any:
    answer = run.send(Call("POST", RESOURCE_PATH, run.tokens[name]))
    assert_person_answer(answer, status, None, "Access denied" if status == 403 else None)
    return answer.json() if status == 200 else None


def known_agent_is_admitted_as_a_person(run: BearerRun) -> str:
    before = ledger(run)
    person = {"id": claims_of(run.tokens["agent_user"])["sub"], "username": USER_NAME}
    assert agent_post(run, "agent_user", 200) == {**person, "role": "user"}
    assert ledger(run) == before, (before, ledger(run))
    return f"{USER_NAME}'s agent token, POST, no cookie, no Origin: 200 user; ledger {before}"


def stored_admin_is_admitted_with_the_person_role(run: BearerRun) -> str:
    reset_host(run.host)
    run.host_pages.pop(ADMIN_NAME, None)
    run.host_page(run.people["admin"])
    before = ledger(run)
    assert agent_post(run, "agent_admin", 200)["role"] == "user"
    assert ledger(run) == before, "the admission changed the stored admin or recorded an event"
    return f"{ADMIN_NAME}, a stored admin: 200 with role user; ledger unchanged {before}"


def no_group_and_unknown_subject_are_refused_plainly(run: BearerRun) -> str:
    before = ledger(run)
    agent_post(run, "agent_outsider", 403)
    assert ledger(run) == before, "the refused token touched the store"
    run.host_page(run.people["ungrouped"])
    before = ledger(run)
    agent_post(run, "agent_ungrouped", 403)
    assert ledger(run) == before, "a known member without the MCP group touched the store"
    reset_host(run.host)
    agent_post(run, "agent_user", 403)
    assert ledger(run) == (0, 0, 0, 0, 0), ledger(run)
    return (f"{UNGROUPED_NAME} (known, no MCP group), {OUTSIDER_NAME}, an unknown subject: "
            "403 Access denied, store untouched")


def the_agent_token_opens_no_other_path(run: BearerRun) -> str:
    token = run.tokens["agent_user"]
    me = run.send(Call("GET", ME, token))
    assert_person_answer(me, 401, PERSON_CHALLENGE_INVALID_TOKEN, "Invalid token")
    assert_answer(run.send(Call("GET", EXPORT, token)), 401, "invalid_token", "Invalid token")
    other = run.send(Call("GET", "/admin", token))
    assert_person_answer(other, 401, None, "Authentication required")
    assert ledger(run) == (0, 0, 0, 0, 0), ledger(run)
    return "the agent token on /api/me, E and /admin: 401, 401, the session's 401; accounts 0"


def tokens_the_resource_refuses(run: BearerRun) -> str:
    for name, status, error in (
        ("user", 401, "invalid_token"), ("audience_app", 401, "invalid_token"),
        ("agent_two_audiences", 401, "invalid_token"),
        ("agent_no_scope", 403, "insufficient_scope"),
    ):
        answer = run.send(Call("POST", RESOURCE_PATH, run.tokens[name]))
        assert_person_answer(answer, status, resource_challenge(run, error))
    return "app bearer, wrong audience, two audiences: 401; no scope: 403 insufficient_scope"


def no_credential_and_a_cookie_get_the_challenge(run: BearerRun) -> str:
    run.host_pages.pop(ADMIN_NAME, None)
    cookies = session_cookies(run.host_page(run.people["admin"]), run.settings.app_origins[0])
    before = run.state()["session_transactions"]
    for call in (Call("GET", RESOURCE_PATH), Call("POST", RESOURCE_PATH, cookies=cookies)):
        assert_person_answer(run.send(call), 401, resource_challenge(run))
    assert run.state()["session_transactions"] == before
    return "GET with nothing and POST with a cookie only: 401 with the resource challenge"


MARKED = "/notes/7"
MARKED_PERSON = "/api/notes/7"
ADMIN_ONLY = "/notes-admin"


def marked_route_admits_the_agent_capped(run: BearerRun) -> str:
    run.host_pages.pop(USER_NAME, None)
    run.host_page(run.people["user"])
    before = ledger(run)
    person = {"id": claims_of(run.tokens["agent_user"])["sub"], "username": USER_NAME}
    for method, path in (("GET", MARKED), ("POST", "/notes")):
        answer = run.send(Call(method, path, run.tokens["agent_user"]))
        assert_person_answer(answer, 200)
        assert answer.json() == {**person, "role": "user"}, answer.json()
    assert ledger(run) == before, (before, ledger(run))
    return f"{USER_NAME}'s agent token, GET and POST on marked routes, no cookie: 200 user"


def marked_route_admin_reader_is_the_plain_403(run: BearerRun) -> str:
    reset_host(run.host)
    run.host_pages.pop(ADMIN_NAME, None)
    run.host_page(run.people["admin"])
    before = ledger(run)
    answer = run.send(Call("GET", ADMIN_ONLY, run.tokens["agent_admin"]))
    assert_person_answer(answer, 403, None, "Admin access required")
    assert ledger(run) == before, "the admission changed the stored admin or recorded an event"
    return f"{ADMIN_NAME}, a stored admin, on the admin_user route: 403 without a challenge"


def marked_route_refusals_beside_a_cookie(run: BearerRun) -> str:
    run.host_pages.pop(ADMIN_NAME, None)
    cookies = session_cookies(run.host_page(run.people["admin"]), run.settings.app_origins[0])
    for name, status, error in (
        ("agent_no_scope", 403, "insufficient_scope"),
        ("agent_two_audiences", 401, "invalid_token"),
    ):
        answer = run.send(Call("GET", MARKED, run.tokens[name], cookies=cookies))
        assert_person_answer(answer, status, resource_challenge(run, error))
    return "no scope: 403 insufficient_scope; two audiences: 401; a valid cookie decides nothing"


def a_bearer_on_a_marked_route_is_not_the_resource_admission(run: BearerRun) -> str:
    app_answer = run.send(Call("GET", MARKED_PERSON, run.tokens["user"]))
    assert_person_answer(app_answer, 200)
    foreign = run.tokens["audience_app"]
    assert_person_answer(
        run.send(Call("GET", MARKED_PERSON, foreign)), 401, PERSON_CHALLENGE_INVALID_TOKEN,
    )
    cookies = session_cookies(run.host_page(run.people["admin"]), run.settings.app_origins[0])
    ignored = run.send(Call("GET", MARKED, foreign, cookies=cookies))
    assert_person_answer(ignored, 200)
    assert ignored.json()["role"] == "admin", ignored.json()
    return "an app bearer admitted as today; another audience: 401 on a person path, else ignored"


def a_marked_route_keeps_session_and_csrf_without_a_bearer(run: BearerRun) -> str:
    origin = run.settings.app_origins[0]
    cookies = session_cookies(run.host_page(run.people["admin"]), origin)
    assert_person_answer(run.send(Call("GET", MARKED, cookies=cookies)), 200)
    refused = run.send(Call(
        "POST", "/notes", cookies=cookies,
        headers={"Origin": "https://evil.example.test", "Sec-Fetch-Site": "cross-site"},
    ))
    assert refused.status_code == 403, refused.status_code
    return "a cookie passes on a marked route; a cross-origin cookie POST: 403"


def marked_route_refuses_the_agent_beyond_its_mark(run: BearerRun) -> str:
    reset_host(run.host)
    run.host_pages.pop(USER_NAME, None)
    run.host_page(run.people["user"])
    assert run.state()["accounts"] == 1, run.state()
    before = ledger(run)
    token = run.tokens["agent_user"]
    for method, path in (
        ("DELETE", MARKED), ("HEAD", MARKED), ("GET", f"{MARKED}/"), ("GET", f"{MARKED}/more"),
        ("GET", "/notes/%2e%2e"),
    ):
        answer = run.send(Call(method, path, token))
        assert answer.status_code in (401, 403), (method, path, answer.status_code)
        assert "resource_metadata" not in answer.headers.get("www-authenticate", ""), path
    assert ledger(run) == before, (before, ledger(run))
    return "the agent token beyond its mark (method, HEAD, slash, longer, ..): refused, unchanged"


def mint_agent_tokens(run: BearerRun) -> str:
    """Tokens for the resource; the first check reads ``aud`` and ``scope`` off a real one."""
    people = run.people
    audience = f"{run.settings.app_origins[0]}{RESOURCE_PATH}"
    for name, person, scope in (
        ("agent_user", people["user"], AGENT_SCOPE),
        ("agent_admin", people["admin"], AGENT_SCOPE),
        ("agent_outsider", people["outsider"], AGENT_SCOPE),
        ("agent_ungrouped", people["ungrouped"], AGENT_SCOPE),
        ("agent_two_audiences", people["user"], f"{AGENT_SCOPE} aud-d1-host"),
        ("agent_no_scope", people["user"], f"openid {RESOURCE_AUDIENCE_SCOPE}"),
    ):
        run.tokens[name] = run.mint(person, HAL, scope)["access_token"]
    claims = claims_of(run.tokens["agent_user"])
    assert as_list(claims["aud"]) == [audience], claims["aud"]
    assert RESOURCE_SCOPE in claims["scope"].split(), claims["scope"]
    return f"aud {audience!r} and scope {claims['scope']!r} on a real token"
