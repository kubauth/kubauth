
Reorganize the user interaction of /cmd/kubauth/cmd/oidc/oidcserver/handle-authorizer to have a specific url for the login page GET and POST.
Take care of the complete OIDC flow.

Add session management only on oauth2/login url. Use the github.com/alexedwards/scs library

Don't use the session to store the RawQuery. As we plan to use a stateful storage for session management, it is important to reduce the number of session PUT/GET operation
In the session, store the successful user authentication result in order to have a full SSO between several OIDC applications.

implement a new Codec for SessionManager, which store its data as a JSON string


----

On login, request user to 'remember me', to activate SSO
Also, let choice for a permanent or browser based session.

Use a modified version of session storage, to check PUT/GET
Setup a K8S based session storage

