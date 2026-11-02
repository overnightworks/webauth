"""The resource scenarios of the bearer proof, 61 to 66.

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
