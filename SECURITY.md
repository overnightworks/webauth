# Security policy

## Reporting a vulnerability

Report it privately through GitHub: open the repository's **Security** tab,
choose **Advisories**, then **Report a vulnerability**
(<https://github.com/overnightworks/webauth/security/advisories/new>).

Please do not open a public issue or pull request for a vulnerability.

## Supported versions

Only the latest minor release receives security fixes. The 0.14 line
receives none. A 0.14.x tag can still be pushed, but it can no longer be
released, because the release workflow releases only tags on commits of `main`,
and `main` carries 0.15.0 changes from this slice on. A host on 0.14.x moves to
the OpenID Connect release to receive fixes.

## What to expect

This is a one-person project. I aim to acknowledge a report within a week and
to tell you my assessment within a few weeks after that. I cannot promise a fix
date. Once a fix is released, the advisory is published and credits you if you
wish.
