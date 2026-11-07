"""The tokens of an autonomous agent's own client at a protected resource."""

from __future__ import annotations

from tests.support.oidc_arrangement import an_access_token
from webauth.middleware import ProtectedResource

AGENT_OWNER = "owner-account-1"
AGENT_NAME = "Mozart"
AGENT_CLIENT = "agent-mozart"


def an_agent_group_claims(resource: ProtectedResource, *groups: str) -> dict[str, object]:
    """The claims of an autonomous agent's own client's token for `resource`: its `azp` is no
    party of the resource, its groups hold the agent group and the resource's group, and it
    carries `agent_owner` and `agent_name`."""
    return {
        "aud": resource.url,
        "scope": resource.scope,
        "azp": AGENT_CLIENT,
        "groups": list(groups) or [resource.agent_group, resource.required_group],
        "agent_owner": AGENT_OWNER,
        "agent_name": AGENT_NAME,
    }


def an_agent_group_token(resource: ProtectedResource, *groups: str, **claims: object) -> str:
    """The token of an autonomous agent's own client; `claims` change or, with `ABSENT`,
    remove members of `an_agent_group_claims`."""
    return an_access_token(claims={**an_agent_group_claims(resource, *groups), **claims})
