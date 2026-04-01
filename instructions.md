
Reorganize the user interaction of /cmd/kubauth/cmd/oidc/oidcserver/handle-authorizer to have a specific url for the login page GET and POST.
Take care of the complete OIDC flow.

Add session management only on oauth2/login url. Use the github.com/alexedwards/scs library

Don't use the session to store the RawQuery. As we plan to use a stateful storage for session management, it is important to reduce the number of session PUT/GET operation
In the session, store the successful user authentication result in order to have a full SSO between several OIDC applications.

implement a new Codec for SessionManager, which store its data as a JSON string


Implement a SessionManager storage based on the kubernetes ressources SsoSession.kubauth.kubotal.io. 
Assume data stored in this session will be always of the form userdb.User, 
so you can match the resources fields with the ones in the data stored in session using Put()

There is a problem: The ssosession resources use the session token as name. But a resource name must ne RFC 1123 compliant. How to solve this.

Use a reversible scheme. And implement the All() interface

I don't like the idea to have several type of token sanitize method. We can forget about reversibility, as storing original token in annotation is OK. Simplify the code by using the same transformation in all cases


An optional field 'fullName' has been added in SsoSession resources and also in userdb.User struct. Handle the storage of this value

A required 'WebToken' field has been added in SsoSession resources. Use it to store the scs token, instead of using annotation.

Rename KubeSsoSessionStore to KubeSsoStore


Implement expired SsoSession cleanup, using same logic as scs.memstore.cleanup.
Implement this cleaner as a Runnable, to be set under the manager control, in oidc.go 

I have added a flags.cleanupPeriod configuration value. Use it and disable cleanup if value is 0

Rename SsoCleaner to KubeSsoCleaner and cleaner.go to kubessocleaner.go

Inject context in KubeSsoStore by implementing CtxStore and IterableCtxStore instead of Store and IterableStore

Complete the oidcserver.handleLogout function to retrieve and delete the corresponding SsoSession 


+++++++ Switch to claude-4, as seems better on html design

Complete the oidcserver.handleIndex function to display a page listing oidcClient in a user-friendly way.
Only oidcClient with a non null 'name' and 'entryUrl' attribute will be listed.
Each display entry will include 'name', 'description'. The 'name' attribute being a link on 'entryURL' value.
The page template will be in resources/templates/index.gohtml
Style will be the same as the resource/templates/login.gohtml. Put the css in a separate file

Arrange for index and login gohtml to share the same css file, without altering visual aspect of any

In index.gohtml, <div class="app-icon">, display the first letter if the displayName, in uppercase

Code has been manually modified.

in index page, sort entries by name and by entryUrl if name are same


in the login page, add a checkbox, with the label 'Remember me'. Checked by default.
If unchecked, then do not persist user


I got the following error:
{"time":"10:12:16.662","level":"ERROR","msg":"Failed to watch","logger":"controller-runtime/cache/UnhandledError","err":"failed to list *v1alpha1.OidcClient: oidcclients.kubauth.kubotal.io is forbidden: User │
│  \"system:serviceaccount:kubauth:kubauth\" cannot list resource \"oidcclients\" in API group \"kubauth.kubotal.io\" at the cluster scope","reflector":"pkg/mod/k8s.io/client-go@v0.33.0/tools/cache/reflector.g │
│ o:285","type":"*v1alpha1.OidcClient"}
The resource is namespaced, and I want to grant access to the controller on the namespace, not cluster width 


Modify the Dockerfile to have the base image (currently gcr.io/distroless/static:nonroot) configurable. Set the current value (gcr.io/distroless/static:nonroot) as default value.
Create a docker-ubuntu entry in the Makefile which build the image with ubuntu 22.04 instead of distroless

Implements the user info endpoint from the spec (https://openid.net/specs/openid-connect-basic-1_0.html#UserInfo) in cmd/kubauth/cmd/oidc/oidcserver/handle-user-info.go


Here is the beginning of the oidc server setup, in oidcserver.go.
```
func (s *OIDCServer) Setup(router *http.ServeMux, accessTokenLifespan time.Duration, refreshTokenLifespan time.Duration) {
	var err error
	// Generate RSA key for JWT signing
	s.privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate RSA key: %v", err))
	}
	s.keyID = uuid.NewString()

```
A key is generated to sign the JWT token. Problem is this key is generated on each restart.
Implements code read the key from a kubernetes secret. And to generate such secret if not existing.
Secret location is defined by jwtSigningKeySecretName and jwtSigningKeySecretNamespace flags parameters, already in place



The jwt token signing key is defined in OIDCServer, as
```
privateKey           *rsa.PrivateKey
keyID                string
```
Problem is the 'kid' field is missing in generated id_token header



Modify /kubauth/cmd/kubauth/cmd/oidc/fositepatch/flow_resource_owner.go to return an OIDC (jwt) token if openid is in requested scope


There is no id_token in the response.
I modify the code with the following:

```
	// Handle OpenID Connect ID token if openid scope is requested
	if request.GetGrantedScopes().Has("openid") {
		fmt.Printf("########### yes\n")
		idTokenLifespan := fosite.GetEffectiveLifespan(request.GetClient(), fosite.GrantTypePassword, fosite.IDToken, c.Config.GetIDTokenLifespan(ctx))
		request.GetSession().SetExpiresAt(fosite.IDToken, time.Now().UTC().Add(idTokenLifespan).Round(time.Second))
	} else {
		fmt.Printf("########### no\n")
	}
```

And a test prompt '########### no', meaning request.GetGrantedScopes().Has("openid") return false.

Here is my request:

```
curl --request POST   --url 'http://localhost:8101/oauth2/token'   --header 'content-type: application/x-www-form-urlencoded'   --data grant_type=password   --data 'username=ml'   --data 'password=lm'   --data 'scope=openid'   --data 'client_id=example-app'   --data 'client_secret=ZXhhbXBsZS1hcHAtc2VjcmV0'
```



Instead of using 'ResourceOwnerPasswordCredentialsGrantStorage.Authenticate', I want to user userdb.Authenticate and set the id_token with its value, as done in 'func (s *OIDCServer) newSession(user *userdb.User, clientId string) *openid.DefaultSession"


Got a panic in line 109. So, I have replaced c.userDb.Authenticate(username, password) by globalUserDb.Authenticate(username, password) and now it works.

But, I don't like global variable. Can we remove them.

You can explore fosite library at /Users/sa/dev/d1/git/fosite


Several manual change. Update your cache if any.

Seems current implementation does not handle PKCE. Could you fix this.

Got Token exchange failed: token request failed with status 400: {"error":"invalid_grant","error_description":"The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. The PKCE code challenge did not match the code verifier."}
This with a test client, with the following command: kc ui --pkce
The source code of the kc command is at the following location: /Users/sa/dev/d1/git/kc
May be the error is in the client


Write the README.md file for this OIDC server product. 
Main source of information for configuration and usage are the values.yaml file of the helm chart, and the kubernetes API.
You can also mention https://github.com/kubauth/kc for testing and generate hash for user's password and oidcclient secrets.


Modify the README.md: there is no helm chart repository. The helm chart is provided as OCI image: quay.io/kubauth/charts/kubauth:0.1.1-snapshot


---------
This project use the fosite library (https://github.com/ory/fosite.git )

Now, this library is not maintained anymore. It has been integrated in the hydra project (https://github.com/ory/hydra) under the 'fosite' path

Modify this project to use the updated fosite embedded in hydra


