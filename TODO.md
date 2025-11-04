# TODO

- User.spec.claims.groups is overwritten by GroupBinding. Merge instead
- Add the clientId in identity protocol, to record on each loginAttempt
- Missing automatic restart of kubauth on ldap and merge configMap change. Fixed ? To test. And add annotation for reloader (And test not too much reboot)
- Able to set oidc client secret as a k8s secret

--------------------------------------------------
# IN PROGRESS

- DOCUMENTATION
- Test/doc applications:
    - minio
    - harbor
    - argocd
    - zot

--------------------------------------------------
# ROADMAP

- apiserver: Use config file, to have an empty prefix on oidc group. (Maintains old method, for compatibility with older k8s version)

- DOC: Explain how to change page layout

- Implement in OKDP sandbox

- TESTING (Both unit and functional)

- A provider which handle password flow on another OIDC

- make kubelogin authcode-keyboard working. Or device-code. 
    May be a specific redirect-uri, which will be an indication to not redirect, but display code 

- cleanup scope/access_type with weboidc. (Implements a scope filter)

- Consent user front interface

- Token introspection handler

- A user front 
  - view/cancel sessions (Currently kc logout)
  - Change password

- Handle renewal token persistency (Store in db)

- An admin front end
  - User management
  - Session management
  - Last login view

- Implement BFA protection on oidc entry

- Authentication delegation to another idp (cf dex)

- internal cluster issuer

- Refactor helm chart to have several container of same type.

--------------------------------------------------
## DONE

- Renaming: kidtok -> kuboidc
- Implement issuer url as parameter
- Implement the user login (With hard coded users db)
- Implement client as K8s resources
- Use same hash for both user and client password validation
- Implement session as k8s resources
- Make JWT signature and global secret permanent
- Test with harbor
- Test with minio
- Package (helm/kubocd)
- Handle resources owner Password Credential Flow
- Handle and test PKCE
- tokenLifeSpan. Defined  by clientId and ensure ok for both access_token a,d id_token, in authorization code grant and password credentia grant
- Refactor OidcClient namespace mgmt (See studies)
- Test with k8s api server and setup a kubectl addon client for auth
- Port SKAS  merge module
- A module to log 'last login'
- helm: rbac for  ldap module (Access secret)
- helm: arrange to be deployed in the control plane
- kc logout: Option to avoid browser launch
- Test multi-nodes cluster
- helm: Remove replicaCount (hard code 1)
- kc audit login sort by date on operation. And set the sort critéria as first column
