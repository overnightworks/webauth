# How to test a host

For a host developer who tests a host built on webauth.

A test that needs a signed-in person needs no issuer. It creates the account and
a session inside the configured lifetime in the host's own store, calls
`issue_session_cookies(response, session_id, config)` from `webauth.cookies` on
a `Response` and copies the one cookie it sets into its client. A state-changing
request also sends `Sec-Fetch-Site: same-origin` ([CSRF origin](ARCHITECTURE.md#csrf-origin)).
When the client keeps the cookie's attributes and `cookie_secure` is on, use an
`https` base URL.

A test of a host that installs the sign-in routes and has its own logout route gives
`OidcRelyingParty` its own `post_token_request` (a `TokenRequestPost`, from
`webauth.oidc`) and `fetch_key_set` (a `KeySetFetch`, from
`webauth.jwt_verification`) instead of the HTTPS ones. The host owns that stub.

The sign-in flow itself is proven against a real issuer: `tests/e2e/oidc/` drives
Keycloak in a real browser and is webauth's own proof. A host proves its own
sign-in against an issuer of its choosing. webauth ships no fake issuer, because
one that mints tokens does not belong in every production install.
