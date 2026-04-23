
# v0.3.0

- feat: Single sign in is now configurable in one of three mode: always, never or onDemand (Previously was only onDemand) 
- feat: Added upstreamProvider resources and handling
- Add a 'style' attribut on OidcClient resource allowing visual layout configuration of login/logout page.
- feat: Add an 'enabled' (default: true) flag on oidcClient resource
- On authentication_code_flow, the request context is now saved in the session, instead of the browser.
- Update fosite library, sync with hydra tag 'v25.4.0'

# v0.2.2

- feat[helm]: Added support of 'haproxy' as ingress class
- fix: userinfo endpoint was not working. Fixed

# v0.2.1

- The JWKS base64 encoding was incorrect. Fixed.

# v0.2.0

- feat: Added `grant_types_supported` and `introspection_endpoint` in discovery URL response.
- fix: Access Token introspection was not working with a public client. Fixed.
- feat: Add support for JWT Access Token (helm values: `oidc.jwtAccessToken: true|false`).
- feat: Support of the Client credential flow.
- feat (BREAKING CHANGE): HashedSecret has been removed. A list of secrets can be provided instead, thus allowing secrets rotation.
- feat (BREAKING CHANGE): A multiTenant mode has been implemented. See 'OIDC Clients Configuration' chapter in the documentation.
- feat: kc hash subcommand has been modified.
- fix: 'aud' claim was not set in JWT Access Token: Fixed.

