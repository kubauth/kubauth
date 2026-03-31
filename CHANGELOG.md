

# v0.3.0

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

