
# v0.1.3

- feat: Added `grant_types_supported` and `introspection_endpoint` in discovery URL response
- fix: Access Token introspection was not working with a public client. Fixed.
- feat: Add support for JWT Access Token (helm values: `oidc.jwtAccessToken: true|false`  )
- feat: Support of the Client credential flow
- feat: HashedSecret has been removed. A list of secrets can be provided instead, thus allowing secrets rotation
- feat: kc hash subcommand has been modified