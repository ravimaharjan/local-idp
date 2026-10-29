# local-idp

A local sandbox for learning and developing OAuth 2.0 and OpenID Connect authentication. It pairs an identity provider with a
small application that signs people in through it, so the whole flow can be run, inspected and changed on one machine without
depending on a hosted service such as Auth0, Okta or Keycloak.

## Objective

- Make the moving parts of OAuth 2.0 / OpenID Connect visible: sign-in, authorization codes, PKCE, access and refresh tokens,
  audiences and scopes, and how an application verifies a token.
- Provide a generic identity provider that any API or web application can use for OAuth2-based authentication during local
  development, rather than one tied to a single project.
- Offer a reference for how an application integrates with such a provider, to compare integration approaches and take the
  ideas to a production setup with a hosted provider.

This is a learning and development tool. It is not meant to be run in production.

## Projects

| Folder | What it is |
|---|---|
| [`idp/`](idp/README.md) | The identity provider: an OAuth 2.0 authorization server with OpenID Connect. |
| [`api/`](api/README.md) | A small todo application that uses the identity provider to sign people in. |

Each folder has its own README.
