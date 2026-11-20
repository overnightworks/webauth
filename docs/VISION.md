# webauth vision

## What webauth is for

webauth takes sign-in and its security off every app. It signs people in through their OpenID Connect provider, keeps
them signed in, and signs them out at the app and at the provider. It lets other programs call an app with credentials of
their own. Around that it guards every app the same way: it turns away requests that another site forged, has the browser
apply its protections, limits how often one address may try, and records what happened for a later security review. An
app tells it where to keep what must last, or takes the optional Postgres adapter for the session half, and has nothing else of its own to build.

A host builds its whole auth in one call from one typed settings object; it varies only its pages, its stores, its
groups and its own middleware, which it hands to webauth in named slots. Every app integrates it the same way, from its
documentation alone, without reading its code. A security fix is made once, and every app gets it by taking the next
release.

It follows OpenID Connect Core 1.0, Discovery 1.0, RP-Initiated Logout 1.0 and Back-Channel Logout 1.0, OAuth 2.0
(RFC 6749) with bearer tokens (RFC 6750), PKCE (RFC 7636), Token Exchange (RFC 8693) and Protected Resource Metadata
(RFC 9728), Authorization Server Issuer Identification (RFC 9207), JSON Web Token (RFC 7519) with JWT access
tokens (RFC 9068), and Fetch Metadata.

It is made by and for agents: every rule a machine can check is in the checks, the documents say what an agent cannot
derive from the code, and the code is clean enough that the next agent changes it without fear.

## Who uses it today

The operator, the people who sign in to his apps, the programs that call those apps on their own behalf, and the agents
that build and integrate them. One app's need shapes webauth for every app, so every app is asked.

## Deliberate non-goals

- No durable storage of its own: each app keeps its accounts, its audit and what else must last in its own database. The `postgres` extra is an optional adapter over the app's own database connection that covers the session half only; the single-process adapters (`webauth.single_process_stores`) keep accounts, sessions and the sign-in transaction in memory for a host that runs one worker and loses them on restart.
- No deployment of its own: each app chooses the release it runs.
- No identity provider and no password login: it relies on an OpenID Connect provider to say who someone is.
- No compatibility layers: a change that breaks its callers breaks cleanly, says so, and leaves nothing of the old form
  behind.
