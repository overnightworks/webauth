# Security policy

## Reporting a vulnerability

Report it privately through GitHub: open the repository's **Security** tab,
choose **Advisories**, then **Report a vulnerability**
(<https://github.com/overnightworks/webauth/security/advisories/new>).

Please do not open a public issue or pull request for a vulnerability.

## Scope

What the library defends against, and what it trusts, is the README's [Security model](README.md#security-model).

## Supported versions

Only the latest minor release receives security fixes. By policy, the 0.14
line receives none: from 0.15.0 on, a fix ships in a patch of the latest minor
release or in the next minor. A host on 0.14.x moves to the OpenID Connect
login to receive fixes.

## What to expect

This is a one-person project. I aim to acknowledge a report within a week and
to tell you my assessment within a few weeks after that. I cannot promise a fix
date. Once a fix is released, the advisory is published and credits you if you
wish.
