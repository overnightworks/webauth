"""The recipe of "Testing a host" in docs/host-contract.md, driven the way a host would."""

from __future__ import annotations

from http.cookies import SimpleCookie

from fastapi import Request, Response

from tests.support.oidc_login_host import after_signing_in, an_oidc_host
from tests.support.session_gate_arrangement import a_gated_app
from tests.support.webauth_arrangement import FakeUser, a_session
from webauth.cookies import issue_session_cookies
from webauth.middleware.session_gate import admitted_user

SAME_ORIGIN_FETCH = {"sec-fetch-site": "same-origin"}


def test_a_host_test_signs_a_person_in_without_an_issuer_from_its_own_store() -> None:
    """HOSTTEST-01, HOSTTEST-02, HOSTTEST-03: `issue_session_cookies` on a `Response` sets one
    cookie; copied into the client, it admits that person on a session path for a safe request
    and, with `Sec-Fetch-Site: same-origin`, for a state-changing one."""
    person = FakeUser(username="lena")
    host = a_gated_app(a_session(user=person))

    @host.app.post("/notes")
    def add_note(request: Request) -> dict[str, str]:
        user = admitted_user(request)
        assert user is not None
        return {"username": user.username}

    issued = Response()
    issue_session_cookies(issued, host.sessions.stored_record.id, host.config)
    set_cookies = issued.headers.getlist("set-cookie")
    [(name, morsel)] = SimpleCookie(set_cookies[0]).items()
    host.client.cookies.set(name, morsel.value)

    safe = host.client.get("/me", follow_redirects=False)
    changing = host.client.post("/notes", headers=SAME_ORIGIN_FETCH, follow_redirects=False)

    assert len(set_cookies) == 1
    assert (safe.status_code, safe.json()["username"]) == (200, person.username)
    assert (changing.status_code, changing.json()) == (200, {"username": person.username})


def test_a_host_test_drives_the_callback_route_through_its_own_stub_of_the_issuer() -> None:
    """HOSTTEST-04: a relying party given its own `post_token_request` and `fetch_key_set` signs
    a person in through the callback route, the stub receiving the code exchange."""
    host = after_signing_in(an_oidc_host())

    admitted = host.client.get("/me")

    assert len(host.issuer.requests) == 1
    assert admitted.status_code == 200
