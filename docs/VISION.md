# webauth vision

## What webauth is for

webauth takes authentication off every app. It is the OpenID Connect relying-party library that signs people in, keeps
their sessions, checks CSRF and origin, sets the security headers, admits machine callers on bearer routes, limits each
address's rate, raises audit events, and logs people out at the app and at the issuer. An app implements the ports,
wires the README's quick start and has nothing else to write.

Every app integrates it the same way, from the [README](../README.md) and the [host contract](host-contract.md), without
reading the library's code. A security fix lands once and reaches every app with the next tag.

It follows the standards it implements:

- OpenID Connect Core 1.0, RP-Initiated Logout 1.0 and Back-Channel Logout 1.0;
- OAuth 2.0 (RFC 6749) and its bearer tokens (RFC 6750);
- JSON Web Token (RFC 7519);
- Fetch Metadata for cross-site requests.

It is made by and for agents: every rule a machine can check is in the checks, the documents say what an agent cannot
derive from the code, and the code is clean enough that the next agent changes it without fear.

## Who uses it today

The operator, his apps, the services that admit an app acting as itself, and the agents that build and integrate them.
Every app integrates the same way: one app's need sets a shape for all of them, so all of them are asked.

## Deliberate non-goals

- No storage of its own: the host owns durable state through `webauth.ports`.
- No deployment of its own: the host pins the tag.
- No identity provider and no password login: it is a relying party of an OpenID Connect issuer.
- No compatibility layers: a public change breaks cleanly, marked **Breaking**, and leaves no old names, aliases or shims.
