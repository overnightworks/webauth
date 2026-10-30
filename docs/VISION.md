# webauth vision

## The wish

> "eine auth library die mir alles abnimmt, damit ich sie in all meine repos easy wiederverwenden kann"

> "gemacht von und für agenten? sauber etc?"

A professional library: sign-in through the operator's Keycloak, sessions, CSRF and origin checks, security headers,
machine bearer routes and logout are taken off every app. It works the same in every app, so an agent integrates it from
the README and the host contract without reading the library's code. An app implements the ports, wires the README's quick
start and has nothing else to write; a security fix lands once and reaches every app with the next tag.

Made by and for agents: every rule a machine can check is in the checks, the documents say what an agent cannot derive
from the code, and the code is clean enough that the next agent changes it without fear.

## Who uses it today

The operator's apps (hopin, songmaker, presentator, and the next one), services that admit an app acting as itself (agent-runtime, whose manifest pins webauth), and the agents that build and integrate them.
Every app integrates the same way: one app's need sets a shape for all of them, so all of them are asked.

## Deliberate non-goals

- No storage of its own: the host owns durable state through `webauth.ports`.
- No deployment of its own: the host installs the tagged wheel.
- No identity provider and no password login: it is a relying party of an OpenID Connect issuer.
- No compatibility layers: a public change breaks cleanly, marked **Breaking**, and leaves no old names, aliases or shims.
