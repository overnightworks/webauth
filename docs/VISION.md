# webauth vision

## What webauth is for

webauth takes sign-in and its security off every app. It signs people in through their OpenID Connect provider, keeps
them signed in, and signs them out at the app and at the provider. It lets other programs call an app with credentials of
their own. Around that it guards every app the same way: it turns away requests that another site forged, has the browser
apply its protections, limits how often one address may try, and records what happened for a later security review. An
app tells it where to keep what must last and has nothing else of its own to build.

Every app integrates it the same way, from its documentation alone, without reading its code. A security fix is made once
and reaches every app with the next release.

It follows OpenID Connect Core 1.0, RP-Initiated Logout 1.0 and Back-Channel Logout 1.0, OAuth 2.0 (RFC 6749) with bearer tokens (RFC 6750), JSON Web Token (RFC 7519) and Fetch Metadata.

It is made by and for agents: every rule a machine can check is in the checks, the documents say what an agent cannot
derive from the code, and the code is clean enough that the next agent changes it without fear.

## Who uses it today

The operator, the people who sign in to his apps, the programs that call those apps on their own behalf, and the agents
that build and integrate them. One app's need shapes webauth for all of them, so all of them are asked.

## Deliberate non-goals

- No storage of its own: each app keeps what must last.
- No deployment of its own: each app chooses the release it runs.
- No identity provider and no password login: it relies on an OpenID Connect provider to say who someone is.
- No compatibility layers: a change that breaks its callers breaks cleanly, says so, and leaves nothing of the old form
  behind.
