

# Upstream claims merge

Here is a proposal about how claims from an upstream provider are handled before being given back to fosite lib.

This processing occurs in the callback from the upstream provider.

Here are the fields of the UpstreamProvider spec relative to this operation 

```
apiVersion: kubauth.kubotal.io/v1alpha1
kind: UpstreamProvider
....
spec:
  ....
  useUserInfo: false    # If true, user info are merged with oidc claims
  claimRenamings:
  - oldName:
    newName:
    op: # copy or rename
  - oldName:
    newName:
    op: # copy or rename
  claimRemovals:
  - claim1
  - claim2

```

Note on claimRenamings:

- If newName already exists in the current set, it will be overridden.
- Renaming are performed in order.


And we will use this utility function for all merging of claims sources

```
// MergeMaps merge two maps and return a new one.
// Base from https://github.com/helm/helm/blob/v3.14.1/pkg/cli/values/options.go
// Second parameter map will override the first one
func MergeMaps(a, b map[string]interface{}, logger logr.logger) map[string]interface{} {
    ....
}
```

For this function, the following rules apply for a given key

- If both values are map[]interface{}, they are merged recursively
- If both value are []string, the resulting value is the de-duplicated concatenation of the values
- In all other case, the value from 'b' if not null is the resulting one.

The overall processing is the following:

- The base claim set is the OIDC claims set from the upstream provider.
- If `useUserInfo: true`, then userInfo is requested and the result is merged on top of the base claim
- Then, the set of `claimRenamings` is applied.
- The 'technical claims' are removed from the current set. Such claims are the one [here](https://openid.net/specs/openid-connect-core-1_0.html#IDToken). Only the `sub` claim is preserved.
  (NB: Anyway, theses claims will be overridden by the fosite library with the kubauth values)
- The claims from the `claimRemovals` list, if any, will be removed.
- Then request to the downStream provider(s) is issued, with the `sub` value as principal. And the result is merged on top of current value.
- Then hand is given back to fosite lib to return resulting claim set to the user.





# References


https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
https://openid.net/specs/openid-connect-core-1_0.html#IDToken

